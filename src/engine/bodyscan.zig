//! The body-signature stage over one in-memory view of a file. Programs pinned to an offset go
//! through the anchored index of the file's partition and of type 0; every other program of the
//! file's target type (or type 0) runs through the verify VM's scanner. `.ndb` programs report
//! the first detection; logical subsig matches feed the sparse logical state, whose touched
//! signatures are evaluated at the end. This is the reference path: it needs no prefilter, so it
//! is what the prefilter stages (atoms, Bloom filters, atom tables) are checked against, and it
//! is what scans until they land. No heap allocation: logical state lives in worker scratch.
const std = @import("std");
const db = @import("../db/root.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");
const anchored = @import("../match/anchored.zig");
const lt = @import("../match/ldb_table.zig");
const logical = @import("../match/logical.zig");
const regex_pool = @import("../match/regex_pool.zig");
const yara_cond = @import("../match/yara_cond.zig");

/// Matches of one YARA regex string recorded per file before the count is reported as limited.
pub const max_regex_matches: u32 = 1024;
const limits_mod = @import("limits.zig");

pub const BodyIndex = struct {
    programs: ?prog.Programs = null,
    /// ANCHORED_INDEX per partition (target type).
    anchored: [15]?anchored.Index = @splat(null),
    ldb: ?lt.LdbTable = null,
    /// Regex programs (PCRE subsigs, .cdb filename regexes). Size each worker's zig-regex
    /// scratch with `regexes.capacity(..)` and hand it to its logical state.
    regexes: ?regex_pool.RegexPool = null,

    pub fn load(database: db.reader.Database) !BodyIndex {
        var index: BodyIndex = .{};
        if (database.section(.regex_pool, 0)) |section| index.regexes = try .init(section);
        const bytes = database.section(.subsig_prog, 0) orelse return index;
        index.programs = try .init(bytes);
        for (&index.anchored, 0..) |*slot, p| {
            if (database.section(.anchored_index, @intCast(p))) |section| slot.* = try .init(section, index.programs.?);
        }
        if (database.section(.ldb_table, 0)) |section| index.ldb = try .initWith(section, index.programs.?, index.regexes);
        if (database.section(.yara_cond, 0)) |section| {
            const table = index.ldb orelse return error.BadYaraTable;
            index.ldb.?.yara = try .init(section, table.records, if (index.regexes) |p| p.count() else 0);
        }
        return index;
    }
};

/// What is known about the file being scanned.
pub const File = struct {
    info: vm.FileInfo,
    /// ClamAV target type.
    target: u8 = 0,
    /// Immediate container type (`fmt.types.ClType`), 0 at the root.
    container: u16 = 0,
    intermediates: []const u16 = &.{},

    pub fn context(f: File) lt.FileContext {
        const executable = f.info.entry_point != null or f.info.sections.len > 0;
        return .{
            .target = f.target,
            .size = f.info.size,
            .entry_point = f.info.entry_point,
            .section_count = if (executable) f.info.sections.len else null,
            .container = f.container,
            .intermediates = f.intermediates,
        };
    }
};

pub const Detection = struct {
    /// Signature id; resolve the name through the hash index's sigmeta.
    sig: u32,
    /// Where the match lies (for a logical signature, where its last subsig hit lies).
    start: usize,
    end: usize,
};

pub const Verdict = union(enum) {
    clean,
    infected: Detection,
    /// No signature matched, but the verify budget ran out somewhere: not a clean result.
    limited: limits_mod.Event,
};

const Collector = struct {
    index: *const BodyIndex,
    programs: prog.Programs,
    state: ?*logical.State,
    ctx: lt.FileContext,
    hit: ?Detection = null,
    last: vm.Match = .{ .start = 0, .end = 0 },
    /// The logical state's spill arena filled up: reported as a limit.
    overflow: bool = false,

    fn take(c: *Collector, h: anchored.Hit) bool {
        const p = c.programs.get(h.prog);
        if (p.header.flags & prog.flag_ldb == 0) {
            c.hit = .{ .sig = p.header.sig, .start = h.match.start, .end = h.match.end };
            return false;
        }
        c.touch(p, h.match) catch {
            c.overflow = true;
            return false;
        };
        return true;
    }

    fn touch(c: *Collector, p: prog.Program, m: vm.Match) !void {
        const state = c.state orelse return;
        const table = c.index.ldb orelse return;
        if (p.header.sig >= table.records.len) return;
        c.last = m;
        try state.touch(table, c.ctx, p.header.sig, p.header.subsig, m.start);
    }

    /// The logical signature does not count matches and already has this subsig.
    fn settled(c: *Collector, p: prog.Program) bool {
        const state = c.state orelse return true;
        const table = c.index.ldb orelse return true;
        if (p.header.sig >= table.records.len) return true;
        const rec = table.records[p.header.sig];
        // Counting signatures need every match; byte compares need their triggers' starts.
        if (rec.flags & lt.flag_counts != 0 or rec.bc_count > 0) return false;
        return state.settled(p.header.sig, p.header.subsig);
    }
};

/// Scan `data`, the whole file. `budget` is per file. With `state` (reset by the caller between
/// files) logical signatures are evaluated too.
pub fn scanBuffer(index: *const BodyIndex, data: []const u8, file: File, budget: *vm.Budget, tracker: *limits_mod.Tracker, state: ?*logical.State) !Verdict {
    const progs = index.programs orelse return .clean;
    const target = file.target;
    const info = file.info;
    var c: Collector = .{ .index = index, .programs = progs, .state = state, .ctx = file.context() };
    // Signatures pinned to an offset: direct lookups through the file's partition and type 0.
    for ([_]u8{ target, 0 }, 0..) |part, n| {
        if (n == 1 and target == 0) break;
        const a = if (part < index.anchored.len) index.anchored[part] orelse continue else continue;
        anchored.scan(a, progs, data, info, budget, &c, Collector.take) catch break;
        if (c.hit) |d| return .{ .infected = d };
        if (c.overflow) break;
    }
    // Everything else is searched for.
    scan: for (0..progs.count()) |i| {
        const p = progs.get(i);
        if (anchored.isAnchored(p)) continue;
        if (p.header.target != 0 and p.header.target != target) continue;
        const is_ldb = p.header.flags & prog.flag_ldb != 0;
        if (is_ldb and c.settled(p)) continue;
        var scanner = vm.Scanner.init(p, data, info, budget);
        while (true) {
            const m = scanner.next() catch break :scan;
            const hit = m orelse break;
            if (!is_ldb) return .{ .infected = .{ .sig = p.header.sig, .start = hit.start, .end = hit.end } };
            c.touch(p, hit) catch {
                c.overflow = true;
                break :scan;
            };
            if (c.settled(p)) break;
        }
    }
    if (state) |st| if (index.ldb) |table| if (table.yara) |yara| {
        // YARA: regex strings are searched here (they have no verify program), and rules whose
        // condition can hold with no string matched get state so they are evaluated.
        for (yara.rules) |rule| {
            if (rule.flags & yara_cond.flag_always != 0) st.ensure(table, c.ctx, rule.ldb) catch {
                c.overflow = true;
            };
            for (yara.ruleStrings(rule), 0..) |str, i| {
                if (str.kind != yara_cond.kind_regex) continue;
                const scratch = st.regex_scratch orelse {
                    st.regex_limited = true;
                    continue;
                };
                const program = index.regexes.?.get(str.regex);
                var pos: usize = 0;
                var n: u32 = 0;
                while (pos <= data.len) {
                    const m = (program.findFrom(scratch, data, pos) catch {
                        st.regex_limited = true;
                        break;
                    }) orelse break;
                    if (n == max_regex_matches) {
                        tracker.note(.yara_matches);
                        break;
                    }
                    st.touch(table, c.ctx, rule.ldb, @intCast(i), m.start) catch {
                        c.overflow = true;
                        break;
                    };
                    n += 1;
                    // Every start position counts, as YARA counts matches.
                    pos = m.start + 1;
                }
            }
        }
    };
    if (state) |st| if (index.ldb) |table| {
        // Expressions that hold with no hits are evaluated for every file, as libclamav does.
        for (table.always) |i| st.ensure(table, c.ctx, i) catch {
            c.overflow = true;
        };
        var out: [1]u32 = undefined;
        const n = st.finalizeWith(table, data, info, &out);
        if (st.bc_out_of_bounds) tracker.note(.byte_compare_bounds);
        if (n == 0 and st.offsets_limited) {
            tracker.note(.yara_matches);
            return .{ .limited = .yara_matches };
        }
        if (n == 0 and st.regex_limited) {
            tracker.note(.regex_steps);
            return .{ .limited = .regex_steps };
        }
        if (n > 0) return .{ .infected = .{ .sig = table.records[out[0]].sig, .start = c.last.start, .end = c.last.end } };
    };
    if (c.overflow) {
        tracker.note(.logical_state);
        return .{ .limited = .logical_state };
    }
    if (budget.exhausted) {
        tracker.note(.verify_steps);
        return .{ .limited = .verify_steps };
    }
    return .clean;
}

test "compile .ndb signatures and detect them end to end" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const hashscan = @import("hashscan.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("test.ndb",
        \\Test.Body.Any-1-0:0:*:4558414d504c45{-8}5041594c4f4144
        \\Test.Body.Pe-2-0:1:EP+0:e8????????5dc3
        \\Test.Body.Html-3-0:3:*:3c736372697074
        \\
    );
    const summary = try c.write(io, tmp.dir, "body.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 3), summary.body_rules);

    const database = try db.reader.open(io, tmp.dir, "body.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    const names = try hashscan.HashIndex.load(database);
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    var budget: vm.Budget = .{};
    const doc = "header EXAMPLE...PAYLOAD trailer";
    const hit = try scanBuffer(&index, doc, .{ .info = .{ .size = doc.len } }, &budget, &tracker, null);
    try std.testing.expectEqualStrings("Test.Body.Any-1-0", try names.meta.?.name(hit.infected.sig, &name_buf));
    try std.testing.expectEqual(@as(usize, 7), hit.infected.start);

    // Target types partition: the HTML signature does not fire on a PE, nor the PE one off EP.
    budget.reset();
    const pe = "MZ<script>\xe8\x01\x02\x03\x04\x5d\xc3";
    try std.testing.expectEqual(Verdict.clean, try scanBuffer(&index, pe, .{ .info = .{ .size = pe.len, .entry_point = 3 }, .target = 1 }, &budget, &tracker, null));
    budget.reset();
    const at_ep = try scanBuffer(&index, pe, .{ .info = .{ .size = pe.len, .entry_point = 10 }, .target = 1 }, &budget, &tracker, null);
    try std.testing.expectEqualStrings("Test.Body.Pe-2-0", try names.meta.?.name(at_ep.infected.sig, &name_buf));
    budget.reset();
    try std.testing.expect(try scanBuffer(&index, pe, .{ .info = .{ .size = pe.len }, .target = 3 }, &budget, &tracker, null) == .infected);

    // A budget that runs out is a limit, not a clean verdict.
    var tiny: vm.Budget = .{ .per_verify = 1, .per_file = 1 };
    const many = "EXAMPLE EXAMPLE EXAMPLE";
    try std.testing.expectEqual(Verdict{ .limited = .verify_steps }, try scanBuffer(&index, many, .{ .info = .{ .size = many.len } }, &tiny, &tracker, null));
    try std.testing.expect(tracker.raised.contains(.verify_steps));
}

test "logical signatures end to end: counts, target descriptions, anchored subsigs" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const hashscan = @import("hashscan.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("test.ldb",
        \\Test.Logical.Pair-1-0;Target:0;0&1;6576616c28;756e6573636170652800::i
        \\Test.Logical.Count-2-0;Target:0;0>2&1=0;414141;5a5a5a
        \\Test.Logical.Pe-3-0;Target:1,FileSize:10-64;0&1;EP+0:e800;4d5a
        \\Test.Logical.Distinct-4-0;Target:7;(0|1|2)>1,2;6f6e65;74776f;746872656565
        \\Test.Logical.Bc-5-0;Target:0;0&1;4c454e3d;0(>>4#de3#>100)
        \\Test.Logical.Pcre-6-0;Target:0;0&1;3c736372697074;0/eval\s*\(\s*unescape/i
        \\Test.Logical.PcreCount-7-0;Target:0;1>1;46524147;0/frag[0-9]+/g
        \\Test.Logical.PcreSled-8-0;Target:0;0&1;534c4544;0/(?:\x90|\xcc){4,}/
        \\
    );
    _ = try c.write(io, tmp.dir, "ldb.zavdb", .{ .db_version = 1 });
    const database = try db.reader.open(io, tmp.dir, "ldb.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    const names = try hashscan.HashIndex.load(database);

    // Logical state comes from worker scratch; the heap is never used during scans.
    var scratch: [2 * 1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var state = try logical.State.init(fba.allocator());
    const regex = @import("regex");
    const capacity = index.regexes.?.capacity(256);
    const regex_mem = try fba.allocator().alignedAlloc(u8, .@"8", regex.Scratch.bytesNeeded(capacity));
    var regex_scratch = try regex.Scratch.initBuffer(regex_mem, capacity);
    regex_scratch.step_budget = 1 << 20;
    state.regex_scratch = &regex_scratch;
    const reserved = fba.end_index;
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    const Case = struct { []const u8, File, ?[]const u8 };
    const pe = "MZ\x90\x00....\xe8\x00\x00\x00";
    for ([_]Case{
        .{ "x=eval(UNESCAPE(\x00y)", .{ .info = .{ .size = 22 } }, "Test.Logical.Pair-1-0" },
        .{ "x=eval(y)", .{ .info = .{ .size = 9 } }, null },
        .{ "AAA AAA AAAA", .{ .info = .{ .size = 12 } }, "Test.Logical.Count-2-0" },
        .{ "AAA AAA", .{ .info = .{ .size = 7 } }, null },
        .{ "AAA AAA AAA ZZZ", .{ .info = .{ .size = 15 } }, null },
        .{ pe, .{ .info = .{ .size = pe.len, .entry_point = 8 }, .target = 1 }, "Test.Logical.Pe-3-0" },
        .{ pe, .{ .info = .{ .size = pe.len, .entry_point = 4 }, .target = 1 }, null },
        .{ pe, .{ .info = .{ .size = pe.len, .entry_point = 8 }, .target = 6 }, null },
        .{ "one two", .{ .info = .{ .size = 7 }, .target = 7 }, "Test.Logical.Distinct-4-0" },
        .{ "one one", .{ .info = .{ .size = 7 }, .target = 7 }, null },
        .{ "x LEN=512;", .{ .info = .{ .size = 10 } }, "Test.Logical.Bc-5-0" },
        .{ "x LEN=099;", .{ .info = .{ .size = 10 } }, null },
        .{ "x LEN=5", .{ .info = .{ .size = 7 } }, null },
        .{ "<script>EVAL ( Unescape('x')", .{ .info = .{ .size = 1 } }, "Test.Logical.Pcre-6-0" },
        .{ "<script>evaluate(unescape)", .{ .info = .{ .size = 1 } }, null },
        .{ "FRAG frag1 frag22", .{ .info = .{ .size = 1 } }, "Test.Logical.PcreCount-7-0" },
        .{ "FRAG frag1", .{ .info = .{ .size = 1 } }, null },
        .{ "SLED \x90\xcc\x90\x90!", .{ .info = .{ .size = 1 } }, "Test.Logical.PcreSled-8-0" },
        .{ "SLED \x90\xcc\x90!", .{ .info = .{ .size = 1 } }, null },
    }) |case| {
        state.reset();
        var budget: vm.Budget = .{};
        var file = case[1];
        file.info.size = case[0].len;
        const verdict = try scanBuffer(&index, case[0], file, &budget, &tracker, &state);
        if (case[2]) |want| {
            try std.testing.expectEqualStrings(want, try names.meta.?.name(verdict.infected.sig, &name_buf));
        } else try std.testing.expectEqual(Verdict.clean, verdict);
    }
    try std.testing.expectEqual(reserved, fba.end_index);
    // The last case's compare pointed past the end of the data: a bounds event, still no match.
    try std.testing.expect(tracker.raised.contains(.byte_compare_bounds));
}

test "YARA rules end to end: text, hex and regex strings, offsets, reads, always rules" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const hashscan = @import("hashscan.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("test.yar",
        \\rule Yara_Pe_Dropper {
        \\  strings:
        \\    $mz = { 4D 5A }
        \\    $s = "dropper" nocase
        \\    $u = /https?:\/\/[a-z]+\.invalid/
        \\  condition:
        \\    $mz at 0 and uint16(0) == 0x5A4D and $s and #u >= 2
        \\}
        \\rule Yara_Wide { strings: $w = "evil" wide condition: $w in (0..16) }
        \\rule Yara_Missing { strings: $a = "marker!" condition: uint8(0) == 0x41 and not $a }
        \\private rule Yara_Private { strings: $p = "private!" condition: $p }
        \\
    );
    const summary = try c.write(io, tmp.dir, "yara.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 4), summary.yara_rules);
    const database = try db.reader.open(io, tmp.dir, "yara.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    const names = try hashscan.HashIndex.load(database);

    var scratch: [2 * 1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var state = try logical.State.init(fba.allocator());
    const regex = @import("regex");
    const capacity = index.regexes.?.capacity(256);
    var regex_scratch = try regex.Scratch.initBuffer(try fba.allocator().alignedAlloc(u8, .@"8", regex.Scratch.bytesNeeded(capacity)), capacity);
    state.regex_scratch = &regex_scratch;
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    const Case = struct { []const u8, ?[]const u8 };
    for ([_]Case{
        .{ "MZ..DROPPER http://a.invalid and https://bb.invalid", "Yara_Pe_Dropper" },
        .{ "MZ..DROPPER http://a.invalid only one", null },
        .{ "xMZ.dropper http://a.invalid https://bb.invalid", null }, // MZ not at 0
        .{ "ab e\x00v\x00i\x00l\x00", "Yara_Wide" },
        .{ ".................e\x00v\x00i\x00l\x00", null }, // starts at 17, past the range
        .{ "A plain file", "Yara_Missing" }, // no string matched: evaluated because it can hold
        .{ "A file with marker!", null },
        .{ "a private! match is not reported", null },
    }) |case| {
        state.reset();
        var budget: vm.Budget = .{};
        const verdict = try scanBuffer(&index, case[0], .{ .info = .{ .size = case[0].len } }, &budget, &tracker, &state);
        if (case[1]) |want| {
            if (verdict != .infected) {
                std.debug.print("case: {s} gave {any}\n", .{ case[0], verdict });
                return error.TestUnexpectedResult;
            }
            std.testing.expectEqualStrings(want, try names.meta.?.name(verdict.infected.sig, &name_buf)) catch |err| {
                std.debug.print("case: {s}\n", .{case[0]});
                return err;
            };
        } else std.testing.expectEqual(Verdict.clean, verdict) catch |err| {
            std.debug.print("case: {s}\n", .{case[0]});
            return err;
        };
    }
}
