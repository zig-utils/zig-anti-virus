//! Sparse per-file logical-signature state (docs/DESIGN.md section 5, "Logical state").
//!
//! A database holds hundreds of thousands of logical subsigs but a file touches a handful, so
//! state is kept only for touched signatures: an 8192-slot open-addressing table of 16-byte
//! slots, a touched list that makes reset O(touched), and a pool of u16 counters handed out to
//! signatures whose expression compares counts. The target description is checked once, on a
//! signature's first touch; a signature that fails it is marked dead and ignores later hits.
//! When the table passes its load limit or the counter pool runs dry, entries spill into a list
//! in the state's own spill arena, reclaimed by `reset`: slower, and only a limit event (never a
//! silent miss) if even that fills. Nothing here touches the heap; every byte comes from the
//! scratch allocator handed to `init`, once, for the worker's lifetime.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const lt = @import("ldb_table.zig");
const vm = @import("verify_vm.zig");
const regex = @import("regex");

pub const slot_count: usize = 8192;
/// Entries the table takes before new signatures spill (75% load).
pub const table_limit: usize = slot_count / 4 * 3;
pub const counter_pool: usize = 32 * 1024;
/// Trigger match starts kept per (signature, trigger) for byte compares.
pub const bc_offsets_per_trigger: usize = 8;
pub const bc_pool: usize = 256;
/// Bytes for entries that spill past the table, the counter pool or the trigger pool.
pub const spill_bytes: usize = 256 * 1024;

pub const Slot = extern struct {
    mask: u64 = 0,
    ldb: u32 = 0,
    /// Index of the first of `nsub` counters in the pool, or `no_counters`.
    cnt_off: u16 = no_counters,
    dead: u8 = 0,
    used: u8 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Slot) == 16);
}

pub const no_counters: u16 = 0xffff;

/// Match starts of one byte-compare trigger subsig.
const TriggerOffsets = struct {
    ldb: u32,
    trigger: u8,
    n: u8 = 0,
    starts: [bc_offsets_per_trigger]u64 = undefined,
};

const Spilled = struct {
    ldb: u32,
    mask: u64 = 0,
    dead: bool,
    /// Counters for this entry (spill arena), empty when the expression has no counts.
    counts: []u16 = &.{},
};

pub const State = struct {
    spill_arena: std.heap.FixedBufferAllocator,
    slots: []Slot,
    touched: []u16,
    touched_len: usize = 0,
    counts: []u16,
    counts_used: usize = 0,
    spill: std.ArrayList(Spilled) = .empty,
    /// Byte-compare trigger offsets; rare, so a short list searched linearly, moving to the
    /// spill arena past `bc_pool`.
    triggers: std.ArrayList(TriggerOffsets),
    trigger_pool: []TriggerOffsets,
    /// Every match, or only the first.
    all_match: bool = false,
    /// A byte compare pointed outside the data during the last finalize.
    bc_out_of_bounds: bool = false,
    /// zig-regex matching state for PCRE subsigs, sized for the database's REGEX_POOL
    /// (`RegexPool.capacity`) and owned by the worker. Without it PCRE subsigs cannot run.
    regex_scratch: ?*regex.Scratch = null,
    /// A PCRE subsig could not be decided (step budget, or no scratch) during the last finalize.
    regex_limited: bool = false,

    /// Reserve the table, touched list, counter and trigger pools and the spill arena (about
    /// 500 KiB) from `scratch`. They live as long as the worker.
    pub fn init(scratch: std.mem.Allocator) !State {
        const slots = try scratch.alloc(Slot, slot_count);
        @memset(slots, .{});
        const pool = try scratch.alloc(TriggerOffsets, bc_pool);
        return .{
            .spill_arena = .init(try scratch.alloc(u8, spill_bytes)),
            .slots = slots,
            .touched = try scratch.alloc(u16, table_limit),
            .counts = try scratch.alloc(u16, counter_pool),
            .triggers = .initBuffer(pool),
            .trigger_pool = pool,
        };
    }

    /// Forget the last file. Costs one write per touched signature, whatever the database size.
    pub fn reset(s: *State) void {
        for (s.touched[0..s.touched_len]) |i| s.slots[i] = .{};
        s.touched_len = 0;
        s.counts_used = 0;
        s.spill = .empty;
        s.triggers = .initBuffer(s.trigger_pool);
        s.spill_arena.reset();
        s.bc_out_of_bounds = false;
        s.regex_limited = false;
    }

    fn recordTrigger(s: *State, table: lt.LdbTable, rec: lt.LdbRecord, ldb: u32, subsig: u16, start: u64) !void {
        for (table.byteCompares(rec)) |bc| {
            if (bc.trigger != subsig) continue;
            for (s.triggers.items) |*t| if (t.ldb == ldb and t.trigger == subsig) {
                if (t.n < bc_offsets_per_trigger) {
                    t.starts[t.n] = start;
                    t.n += 1;
                }
                return;
            };
            var t: TriggerOffsets = .{ .ldb = ldb, .trigger = @intCast(subsig), .n = 1 };
            t.starts[0] = start;
            if (s.triggers.items.len == s.triggers.capacity) {
                // The fixed pool is full: continue in a larger copy in the spill arena (the pool
                // itself is not the arena's, so the list must not try to resize it in place).
                const bigger = try s.spill_arena.allocator().alloc(TriggerOffsets, s.triggers.capacity * 2);
                @memcpy(bigger[0..s.triggers.items.len], s.triggers.items);
                s.triggers = .{ .items = bigger[0..s.triggers.items.len], .capacity = bigger.len };
            }
            s.triggers.appendAssumeCapacity(t);
            return;
        }
    }

    fn triggerStarts(s: *const State, ldb: u32, trigger: u8) []const u64 {
        for (s.triggers.items) |*t| if (t.ldb == ldb and t.trigger == trigger) return t.starts[0..t.n];
        return &.{};
    }

    fn hash(ldb: u32) usize {
        return @intCast((@as(u64, ldb) *% 0x9E37_79B9_7F4A_7C15) >> (64 - 13));
    }

    fn find(s: *State, ldb: u32) ?*Slot {
        var i = hash(ldb);
        while (true) : (i = (i + 1) & (slot_count - 1)) {
            const slot = &s.slots[i];
            if (slot.used == 0) return null;
            if (slot.ldb == ldb) return slot;
        }
    }

    fn findSpilled(s: *State, ldb: u32) ?*Spilled {
        for (s.spill.items) |*e| if (e.ldb == ldb) return e;
        return null;
    }

    /// Record a match of subsig `subsig` of logical signature `ldb` starting at `start`.
    pub fn touch(s: *State, table: lt.LdbTable, ctx: lt.FileContext, ldb: u32, subsig: u16, start: u64) !void {
        const rec = table.records[ldb];
        if (subsig >= rec.nsub) return;
        const bit = @as(u64, 1) << @intCast(subsig);
        if (s.find(ldb)) |slot| {
            if (slot.dead != 0) return;
            slot.mask |= bit;
            if (slot.cnt_off != no_counters) s.counts[slot.cnt_off + subsig] +|= 1;
            if (rec.bc_count > 0) try s.recordTrigger(table, rec, ldb, subsig, start);
            return;
        }
        if (s.findSpilled(ldb)) |e| {
            if (e.dead) return;
            e.mask |= bit;
            if (e.counts.len > 0) e.counts[subsig] +|= 1;
            if (rec.bc_count > 0) try s.recordTrigger(table, rec, ldb, subsig, start);
            return;
        }
        if (rec.bc_count > 0 and lt.tdbMatches(table.tdbs[ldb], ctx)) try s.recordTrigger(table, rec, ldb, subsig, start);
        // First touch: the target description decides whether the signature can match at all.
        const dead = !lt.tdbMatches(table.tdbs[ldb], ctx);
        const wants_counts = rec.flags & lt.flag_counts != 0 and !dead;
        if (s.touched_len < table_limit and (!wants_counts or s.counts_used + rec.nsub <= s.counts.len)) {
            var i = hash(ldb);
            while (s.slots[i].used != 0) i = (i + 1) & (slot_count - 1);
            var slot: Slot = .{ .ldb = ldb, .used = 1, .dead = @intFromBool(dead) };
            if (wants_counts) {
                slot.cnt_off = @intCast(s.counts_used);
                @memset(s.counts[s.counts_used..][0..rec.nsub], 0);
                s.counts_used += rec.nsub;
                s.counts[slot.cnt_off + subsig] = 1;
            }
            if (!dead) slot.mask = bit;
            s.slots[i] = slot;
            s.touched[s.touched_len] = @intCast(i);
            s.touched_len += 1;
            return;
        }
        // Spill: scratch memory, linear lookups.
        var e: Spilled = .{ .ldb = ldb, .dead = dead };
        if (wants_counts) {
            e.counts = try s.spill_arena.allocator().alloc(u16, rec.nsub);
            @memset(e.counts, 0);
            e.counts[subsig] = 1;
        }
        if (!dead) e.mask = bit;
        try s.spill.append(s.spill_arena.allocator(), e);
    }

    /// Whether subsig `subsig` of `ldb` has matched (or the signature is dead): the scan can
    /// skip further matches of it when its expression does not count.
    pub fn settled(s: *State, ldb: u32, subsig: u16) bool {
        const bit = @as(u64, 1) << @intCast(subsig);
        if (s.find(ldb)) |slot| return slot.dead != 0 or slot.mask & bit != 0;
        if (s.findSpilled(ldb)) |e| return e.dead or e.mask & bit != 0;
        return false;
    }

    fn countsOf(s: *State, table: lt.LdbTable, data: []const u8, info: vm.FileInfo, ldb: u32, rec: lt.LdbRecord, mask: u64, counters: ?[]const u16, out: *[ir.max_subsigs]u32) []const u32 {
        const nsub = rec.nsub;
        for (0..nsub) |i| {
            out[i] = if (counters) |c| c[i] else @intFromBool(mask & (@as(u64, 1) << @intCast(i)) != 0);
        }
        // Byte compares: how many trigger matches satisfy each one.
        for (table.byteCompares(rec)) |bc| {
            var hits: u32 = 0;
            for (s.triggerStarts(ldb, bc.trigger)) |start| {
                if (start > data.len) continue;
                switch (lt.evalByteCompare(bc, data, @intCast(start))) {
                    .yes => hits += 1,
                    .no => {},
                    .out_of_bounds => s.bc_out_of_bounds = true,
                }
            }
            out[bc.subsig] = if (counters != null) hits else @intFromBool(hits > 0);
        }
        // PCRE subsigs, in subsig order: each runs only when its trigger over the earlier
        // subsigs holds.
        for (table.pcreSubsigs(rec)) |pr| {
            out[pr.subsig] = 0;
            if (!lt.evalRpn(table.trigger(pr), out[0..pr.subsig])) continue;
            const hits = s.runPcre(table, pr, data, info);
            out[pr.subsig] = if (counters != null) hits else @intFromBool(hits > 0);
        }
        return out[0..nsub];
    }

    /// How many times a PCRE subsig matches under its offset and flags.
    fn runPcre(s: *State, table: lt.LdbTable, pr: lt.PcreRecord, data: []const u8, info: vm.FileInfo) u32 {
        const scratch = s.regex_scratch orelse {
            s.regex_limited = true;
            return 0;
        };
        const program = table.regexes.?.get(pr.regex);
        const off = pr.offset();
        var lo: usize = 0;
        var start_hi: usize = std.math.maxInt(usize);
        var input = data;
        if (off.kind != .any) {
            const w = vm.startWindow(off, info) orelse return 0;
            lo = @intCast(@min(w.lo, data.len));
            // Without `r` (rolling) the match is anchored to the offset window.
            if (!pr.flags.rolling) start_hi = @intCast(@min(w.hi, data.len));
            // `e`: the whole match lies inside offset..offset + maxshift.
            if (pr.flags.encompass) {
                input = data[0..@intCast(@min(data.len, w.lo +| off.shift))];
                start_hi = std.math.maxInt(usize);
            }
        }
        if (pr.flags.anchored) start_hi = lo;
        var hits: u32 = 0;
        var pos = lo;
        while (pos <= input.len) {
            const m = (program.findFrom(scratch, input, pos) catch {
                s.regex_limited = true;
                return hits;
            }) orelse break;
            if (m.start > start_hi) break;
            hits +|= 1;
            if (!pr.flags.global) break;
            pos = if (m.end > m.start) m.end else m.start + 1;
        }
        return hits;
    }

    /// Evaluate every touched, live signature over the file's `data` (byte compares read it).
    /// Matching record indices go into `out` (the first only, unless `all_match`); returns how
    /// many.
    pub fn finalize(s: *State, table: lt.LdbTable, data: []const u8, out: []u32) usize {
        return s.finalizeWith(table, data, .{ .size = data.len }, out);
    }

    /// `finalize` with the file's entry point and sections, which PCRE offsets resolve against.
    pub fn finalizeWith(s: *State, table: lt.LdbTable, data: []const u8, info: vm.FileInfo, out: []u32) usize {
        var n: usize = 0;
        var buf: [ir.max_subsigs]u32 = undefined;
        for (s.touched[0..s.touched_len]) |i| {
            const slot = s.slots[i];
            if (slot.dead != 0) continue;
            const rec = table.records[slot.ldb];
            const counters: ?[]const u16 = if (slot.cnt_off != no_counters) s.counts[slot.cnt_off..][0..rec.nsub] else null;
            if (lt.evalRpn(table.expr(rec), s.countsOf(table, data, info, slot.ldb, rec, slot.mask, counters, &buf))) {
                if (n == out.len) return n;
                out[n] = slot.ldb;
                n += 1;
                if (!s.all_match) return n;
            }
        }
        for (s.spill.items) |e| {
            if (e.dead) continue;
            const rec = table.records[e.ldb];
            const counters: ?[]const u16 = if (e.counts.len > 0) e.counts else null;
            if (lt.evalRpn(table.expr(rec), s.countsOf(table, data, info, e.ldb, rec, e.mask, counters, &buf))) {
                if (n == out.len) return n;
                out[n] = e.ldb;
                n += 1;
                if (!s.all_match) return n;
            }
        }
        return n;
    }
};

const testing = std.testing;
const ldb_parse = @import("../compile/ldb.zig");
const ldb_build = @import("../compile/ldb_build.zig");

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    table: lt.LdbTable,

    fn deinit(f: *Fixture) void {
        f.arena.deinit();
    }
};

fn fixture(lines: []const []const u8) !Fixture {
    var f: Fixture = .{ .arena = .init(testing.allocator), .table = undefined };
    errdefer f.arena.deinit();
    const a = f.arena.allocator();
    const rules = try a.alloc(ir.LogicalRule, lines.len);
    const entries = try a.alloc(ldb_build.Entry, lines.len);
    for (lines, rules, entries, 0..) |line, *r, *e, i| {
        var column: u32 = 0;
        r.* = try ldb_parse.parseLine(a, line, &column);
        e.* = .{ .rule = r, .sig = @intCast(100 + i), .prog_first = 0, .prog_count = 0 };
    }
    const bytes = try ldb_build.build(a, entries);
    const image = try a.alignedAlloc(u8, .@"8", bytes.len);
    @memcpy(image, bytes);
    f.table = try lt.LdbTable.init(image, null);
    return f;
}

test "touch, target descriptions, counts, finalize and an O(touched) reset" {
    var f = try fixture(&.{
        "A-1-0;Target:0;0&1;aa;bb", // 0
        "B-2-0;Target:1;0;aa", // 1: PE only
        "C-3-0;Target:0;0>2;aa", // 2: counts
        "D-4-0;Target:0,FileSize:10-20;0;aa", // 3
        "E-5-0;Target:0;(0|1)=2,2;aa;bb", // 4: counts and distinct
    });
    defer f.deinit();
    var mem: [1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var s = try State.init(fba.allocator());
    const after_init = fba.end_index;
    s.all_match = true;

    const ctx: lt.FileContext = .{ .target = 0, .size = 100 };
    try s.touch(f.table, ctx, 0, 0, 0);
    try s.touch(f.table, ctx, 1, 0, 0); // dead: wrong target
    try s.touch(f.table, ctx, 3, 0, 0); // dead: wrong size
    for (0..3) |_| try s.touch(f.table, ctx, 2, 0, 0);
    try s.touch(f.table, ctx, 4, 0, 0);
    try s.touch(f.table, ctx, 4, 1, 0);
    var out: [8]u32 = undefined;
    var n = s.finalize(f.table, "", &out);
    std.mem.sortUnstable(u32, out[0..n], {}, std.sort.asc(u32));
    try testing.expectEqualSlices(u32, &.{ 2, 4 }, out[0..n]); // 0 lacks subsig 1
    try testing.expect(s.settled(1, 0)); // dead counts as settled
    try testing.expect(!s.settled(0, 1));

    try s.touch(f.table, ctx, 0, 1, 0);
    try s.touch(f.table, ctx, 4, 0, 0); // three matches now: =2 fails
    n = s.finalize(f.table, "", &out);
    std.mem.sortUnstable(u32, out[0..n], {}, std.sort.asc(u32));
    try testing.expectEqualSlices(u32, &.{ 0, 2 }, out[0..n]);
    s.all_match = false;
    try testing.expectEqual(@as(usize, 1), s.finalize(f.table, "", &out));

    // Reset clears exactly the touched slots; no allocation happened in any of this.
    try testing.expectEqual(@as(usize, 5), s.touched_len);
    s.reset();
    try testing.expectEqual(@as(usize, 0), s.touched_len);
    for (s.slots) |slot| try testing.expectEqual(@as(u8, 0), slot.used);
    try testing.expectEqual(after_init, fba.end_index);
    try testing.expectEqual(@as(usize, 0), s.finalize(f.table, "", &out));
}

test "past the table limit entries spill into scratch and still evaluate" {
    // table_limit + 10 distinct signatures, each "0>0" over one subsig (counts).
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const n_sigs = table_limit + 10;
    var column: u32 = 0;
    const r = try ldb_parse.parseLine(a.allocator(), "S-1-0;Target:0;0>0;aa", &column);
    const entries = try a.allocator().alloc(ldb_build.Entry, n_sigs);
    for (entries, 0..) |*e, i| e.* = .{ .rule = &r, .sig = @intCast(i), .prog_first = 0, .prog_count = 0 };
    const bytes = try ldb_build.build(a.allocator(), entries);
    const image = try a.allocator().alignedAlloc(u8, .@"8", bytes.len);
    @memcpy(image, bytes);
    const table = try lt.LdbTable.init(image, null);

    const mem = try testing.allocator.alloc(u8, 2 * 1024 * 1024);
    defer testing.allocator.free(mem);
    var fba: std.heap.FixedBufferAllocator = .init(mem);
    var s = try State.init(fba.allocator());
    s.all_match = true;
    for (0..n_sigs) |i| try s.touch(table, .{}, @intCast(i), 0, 0);
    try testing.expectEqual(@as(usize, 10), s.spill.items.len);
    const out = try a.allocator().alloc(u32, n_sigs);
    try testing.expectEqual(n_sigs, s.finalize(table, "", out));
    s.reset();
    fba.reset();
}

test "byte compares evaluate against recorded trigger starts" {
    var f = try fixture(&.{
        "BC-1-0;Target:0;0&1;aa;0(>>2#ib1#=0x7f)",
        "BC-2-0;Target:0;0>1&1;aa;0(>>1#d2#>50)",
    });
    defer f.deinit();
    var mem: [1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var s = try State.init(fba.allocator());
    s.all_match = true;
    const data = "aa\x7f.....a75";
    try s.touch(f.table, .{}, 0, 0, 0); // byte at 2 is 0x7f
    try s.touch(f.table, .{}, 1, 0, 8); // "75" at 9
    try s.touch(f.table, .{}, 1, 0, 0); // "\x7f." is not decimal
    var out: [4]u32 = undefined;
    var n = s.finalize(f.table, data, &out);
    std.mem.sortUnstable(u32, out[0..n], {}, std.sort.asc(u32));
    try testing.expectEqualSlices(u32, &.{ 0, 1 }, out[0..n]);
    try testing.expect(!s.bc_out_of_bounds);
    // A trigger near the end points past the data: no match, and the bounds event is set.
    s.reset();
    try s.touch(f.table, .{}, 0, 0, data.len - 1);
    n = s.finalize(f.table, data, &out);
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expect(s.bc_out_of_bounds);
}

test "pcre subsigs: triggers, offsets, rolling, encompass, anchored and global counts" {
    const regex_pool = @import("regex_pool.zig");
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const lines = [_][]const u8{
        "Exact-1-0;Target:0;0&1;aa;4:0/abc/", // 0: must start at 4
        "Rolling-2-0;Target:0;0&1;aa;4:0/abc/r", // 1: anywhere from 4 on
        "Window-3-0;Target:0;0&1;aa;4,4:0/abc/e", // 2: inside 4..8
        "Anchored-4-0;Target:0;0&1;aa;0/abc/A", // 3: at 0 only
        "Global-5-0;Target:0;0&1>1;aa;0/abc/g", // 4: more than one
        "Trigger-6-0;Target:0;0&1&2;aa;bb;1/abc/", // 5: runs only when bb hit
    };
    const rules = try a.alloc(ir.LogicalRule, lines.len);
    const entries = try a.alloc(@import("../compile/ldb_build.zig").Entry, lines.len);
    var blobs: std.ArrayList([]const u8) = .empty;
    for (lines, rules, entries, 0..) |line, *r, *e, i| {
        var column: u32 = 0;
        r.* = try ldb_parse.parseLine(a, line, &column);
        e.* = .{ .rule = r, .sig = @intCast(i), .prog_first = 0, .prog_count = 0, .regex_first = @intCast(blobs.items.len) };
        try @import("../compile/ldb_build.zig").pcrePrograms(r, &blobs, a);
    }
    const pool_bytes = try regex_pool.build(a, blobs.items);
    const pool_image = try a.alignedAlloc(u8, .@"8", pool_bytes.len);
    @memcpy(pool_image, pool_bytes);
    const pool = try regex_pool.RegexPool.init(pool_image);
    const bytes = try @import("../compile/ldb_build.zig").build(a, entries);
    const image = try a.alignedAlloc(u8, .@"8", bytes.len);
    @memcpy(image, bytes);
    const table = try lt.LdbTable.initWith(image, null, pool);

    var mem: [1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var s = try State.init(fba.allocator());
    const capacity = pool.capacity(64);
    var scratch = try regex.Scratch.initBuffer(try fba.allocator().alignedAlloc(u8, .@"8", regex.Scratch.bytesNeeded(capacity)), capacity);
    s.regex_scratch = &scratch;
    s.all_match = true;

    const Case = struct { []const u8, []const u32 };
    for ([_]Case{
        .{ "abc.abc", &.{ 0, 1, 2, 3, 4 } }, // abc at 0 (anchored) and at 4 (exact, window)
        .{ "aa..abc...", &.{ 0, 1, 2 } },
        .{ "aa...abc..", &.{ 1, 2 } },
        .{ "aa.....abc", &.{1} },
        .{ "aa bb abc", &.{ 1, 5 } },
    }) |c| {
        s.reset();
        for (0..lines.len) |l| try s.touch(table, .{}, @intCast(l), 0, 0);
        if (std.mem.indexOf(u8, c[0], "bb") != null) try s.touch(table, .{}, 5, 1, 0);
        var out: [8]u32 = undefined;
        const n = s.finalize(table, c[0], &out);
        std.mem.sortUnstable(u32, out[0..n], {}, std.sort.asc(u32));
        testing.expectEqualSlices(u32, c[1], out[0..n]) catch |err| {
            std.debug.print("case {s}\n", .{c[0]});
            return err;
        };
        try testing.expect(!s.regex_limited);
    }
    // Without a scratch a triggered PCRE cannot run: a limit, not a miss.
    s.reset();
    s.regex_scratch = null;
    try s.touch(table, .{}, 1, 0, 0);
    var out: [8]u32 = undefined;
    try testing.expectEqual(@as(usize, 0), s.finalize(table, "aa..abc", &out));
    try testing.expect(s.regex_limited);
}

test "a worst-case PCRE input stops at the step budget and is reported" {
    const regex_pool = @import("regex_pool.zig");
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var column: u32 = 0;
    const rule = try ldb_parse.parseLine(a, "Slow-1-0;Target:0;0&1;61;0/[ab]*[ab]*[ab]*[ab]*c/g", &column);
    var blobs: std.ArrayList([]const u8) = .empty;
    try @import("../compile/ldb_build.zig").pcrePrograms(&rule, &blobs, a);
    const pool_bytes = try regex_pool.build(a, blobs.items);
    const pool_image = try a.alignedAlloc(u8, .@"8", pool_bytes.len);
    @memcpy(pool_image, pool_bytes);
    const pool = try regex_pool.RegexPool.init(pool_image);
    const entries = [_]@import("../compile/ldb_build.zig").Entry{.{ .rule = &rule, .sig = 0, .prog_first = 0, .prog_count = 0 }};
    const bytes = try @import("../compile/ldb_build.zig").build(a, &entries);
    const image = try a.alignedAlloc(u8, .@"8", bytes.len);
    @memcpy(image, bytes);
    const table = try lt.LdbTable.initWith(image, null, pool);

    const data = try a.alloc(u8, 256 * 1024);
    @memset(data, 'a');
    var mem: [1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var s = try State.init(fba.allocator());
    const capacity = pool.capacity(16);
    var scratch = try regex.Scratch.initBuffer(try fba.allocator().alignedAlloc(u8, .@"8", regex.Scratch.bytesNeeded(capacity)), capacity);
    scratch.step_budget = 10_000;
    s.regex_scratch = &scratch;
    try s.touch(table, .{}, 0, 0, 0);
    var out: [1]u32 = undefined;
    try testing.expectEqual(@as(usize, 0), s.finalize(table, data, &out));
    try testing.expect(s.regex_limited);
    try testing.expect(scratch.steps <= 10_000);
}
