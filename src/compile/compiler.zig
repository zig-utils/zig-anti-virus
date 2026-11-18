//! The compile driver: signature sources in, one `.zavdb` out.
//!
//! Sources are added as named files (`main.hdb`, `local.ign2`, ...) or as a verified CVD/CLD whose
//! members are added the same way. Nothing is filtered until `write`, because `.ign2` lists can
//! arrive after the signatures they ignore. Every signature that does not make it into the database
//! is counted in the coverage report, which is written into the database too.
const std = @import("std");
const Io = std.Io;
const ir = @import("ir.zig");
const hashsig = @import("hashsig.zig");
const hexsig = @import("hexsig.zig");
const ndb = @import("ndb.zig");
const prog_build = @import("prog_build.zig");
const anchored_build = @import("anchored_build.zig");
const ldb = @import("ldb.zig");
const ldb_build = @import("ldb_build.zig");
const ldb_table = @import("../match/ldb_table.zig");
const prog = @import("../match/prog.zig");
const filters = @import("filters.zig");
const coverage_mod = @import("coverage.zig");
const hash_build = @import("hash_build.zig");
const cvd = @import("cvd.zig");
const mbazaar = @import("mbazaar.zig");
const builtin_rules = @import("builtin.zig");
const hashidx = @import("../match/hashidx.zig");
const writer = @import("../db/writer.zig");
const format = @import("../db/format.zig");

/// Allowlist tables use the fp_tables section kind: hot halves at the table variant, cold halves
/// at this offset plus the table variant.
pub const fp_cold_variant_offset: u16 = 16;

/// Database extensions zav recognises but does not compile yet; their lines are counted as skipped.
const later_formats = [_][]const u8{ "ndb", "ndu", "ldb", "ldu", "cdb", "ftm", "pdb", "gdb", "wdb", "idb", "crb", "cat", "yar", "yara", "cfg", "hwp", "ign" };

pub const Compiler = struct {
    gpa: std.mem.Allocator,
    /// Owns every source text; rules borrow from it.
    arena: std.heap.ArenaAllocator,
    rules: std.ArrayList(ir.HashRule) = .empty,
    bodies: std.ArrayList(ir.BodyRule) = .empty,
    logicals: std.ArrayList(ir.LogicalRule) = .empty,
    allow: std.ArrayList(ir.HashRule) = .empty,
    ignore_entries: std.ArrayList(filters.IgnoreEntry) = .empty,
    rejected: std.ArrayList(ir.Rejection) = .empty,
    coverage: coverage_mod.Coverage = .{},
    sources: format.Sources = .{},

    pub fn init(gpa: std.mem.Allocator) Compiler {
        return .{ .gpa = gpa, .arena = .init(gpa) };
    }

    pub fn deinit(c: *Compiler) void {
        c.rules.deinit(c.gpa);
        c.bodies.deinit(c.gpa);
        c.logicals.deinit(c.gpa);
        c.allow.deinit(c.gpa);
        c.ignore_entries.deinit(c.gpa);
        c.rejected.deinit(c.gpa);
        c.coverage.deinit(c.gpa);
        c.arena.deinit();
    }

    /// Add one signature file. `name` decides the format by extension; `text` is copied.
    pub fn addFile(c: *Compiler, name: []const u8, text: []const u8) !void {
        const arena = c.arena.allocator();
        const owned_name = try arena.dupe(u8, name);
        const owned = try arena.dupe(u8, text);
        const ext = extension(owned_name);

        if (hashsig.formatFor(ext)) |fmt| {
            try hashsig.parse(c.gpa, fmt, owned_name, owned, .{ .rules = &c.rules, .rejected = &c.rejected });
        } else if (std.mem.eql(u8, ext, "ndb") or std.mem.eql(u8, ext, "ndu")) {
            try ndb.parse(c.gpa, arena, owned_name, owned, ext[2] == 'u', .{ .rules = &c.bodies, .rejected = &c.rejected });
        } else if (std.mem.eql(u8, ext, "ldb") or std.mem.eql(u8, ext, "ldu")) {
            try ldb.parse(c.gpa, arena, owned_name, owned, ext[2] == 'u', .{ .rules = &c.logicals, .rejected = &c.rejected });
        } else if (filters.allowlistFormat(ext)) |fmt| {
            try hashsig.parse(c.gpa, fmt, owned_name, owned, .{ .rules = &c.allow, .rejected = &c.rejected });
        } else if (std.mem.eql(u8, ext, "ign2")) {
            try filters.parseIgnore(c.gpa, owned, &c.ignore_entries);
        } else if (std.mem.eql(u8, ext, "cbc")) {
            try c.coverage.skip(c.gpa, owned_name, .bytecode);
        } else if (std.mem.eql(u8, ext, "info") or std.mem.eql(u8, owned_name, "COPYING")) {
            // Container metadata, verified by the CVD reader.
        } else {
            // Known formats awaiting their parsers and unknown files are counted alike, per line.
            _ = isLaterFormat(ext);
            const reason: ir.Reason = .unsupported_database;
            var lines = std.mem.splitScalar(u8, owned, '\n');
            while (lines.next()) |line| {
                if (std.mem.trim(u8, line, " \r\t").len == 0) continue;
                try c.coverage.skip(c.gpa, owned_name, reason);
            }
        }
    }

    /// Add the signatures every database carries (EICAR).
    pub fn addBuiltin(c: *Compiler) !void {
        for (builtin_rules.rules()) |rule| try c.rules.append(c.gpa, rule);
    }

    /// Add a MalwareBazaar CSV export (opt-in feed).
    pub fn addMalwareBazaar(c: *Compiler, name: []const u8, text: []const u8, export_time: u64) !void {
        const arena = c.arena.allocator();
        try mbazaar.parse(c.gpa, arena, try arena.dupe(u8, name), try arena.dupe(u8, text), &c.rules, &c.rejected);
        c.sources.malwarebazaar = export_time;
    }

    /// Verify a CVD (or, with `allow_unverified`, a CLD) and add its members.
    pub fn addContainer(c: *Compiler, io: Io, dir: Io.Dir, sub_path: []const u8, options: cvd.VerifyOptions) !cvd.Header {
        const file = try dir.openFile(io, sub_path, .{});
        defer file.close(io);
        var header_bytes: [cvd.header_len]u8 = undefined;
        const n = try file.readPositionalAll(io, &header_bytes, 0);
        if (n != cvd.header_len) return error.Truncated;
        const header_copy = try c.arena.allocator().dupe(u8, &header_bytes);
        const header = try cvd.parseHeader(header_copy);

        var buf: [64 * 1024]u8 = undefined;
        {
            var r = file.reader(io, &buf);
            try r.seekTo(cvd.header_len);
            try cvd.verify(header, &r.interface, options);
        }
        var r = file.reader(io, &buf);
        try r.seekTo(cvd.header_len);
        var visitor: MemberVisitor = .{ .compiler = c };
        try cvd.walk(c.gpa, header, &r.interface, .{}, &visitor);

        const stem = std.fs.path.stem(sub_path);
        if (std.mem.startsWith(u8, stem, "main")) c.sources.clamav_main = header.version;
        if (std.mem.startsWith(u8, stem, "daily")) c.sources.clamav_daily = header.version;
        if (std.mem.startsWith(u8, stem, "bytecode")) c.sources.clamav_bytecode = header.version;
        return header;
    }

    const MemberVisitor = struct {
        compiler: *Compiler,

        pub fn member(v: *MemberVisitor, name: []const u8, size: u64, reader: *Io.Reader) !void {
            const text = try v.compiler.gpa.alloc(u8, @intCast(size));
            defer v.compiler.gpa.free(text);
            try reader.readSliceAll(text);
            try v.compiler.addFile(name, text);
        }
    };

    pub const Summary = struct {
        signatures: u32,
        hash_rules: u64,
        /// Body signatures compiled into verify programs.
        body_rules: u64,
        /// Logical signatures in LDB_TABLE.
        logical_rules: u64,
        /// Verify programs: one per variant after modifier expansion.
        programs: u64,
        allowlist_rules: u64,
        duplicates: u64,
    };

    /// Filter, build and write the database.
    pub fn write(c: *Compiler, io: Io, dir: Io.Dir, sub_path: []const u8, options: writer.Options) !Summary {
        var ignore = try filters.Ignore.init(c.gpa, c.ignore_entries.items);
        defer ignore.deinit(c.gpa);

        for (c.rejected.items) |r| try c.coverage.skip(c.gpa, r.source_name, r.reason);

        var kept: std.ArrayList(ir.HashRule) = .empty;
        defer kept.deinit(c.gpa);
        for (c.rules.items) |*rule| {
            if (filters.skipReason(rule, &ignore, filters.engine_flevel)) |reason| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), reason);
                continue;
            }
            try kept.append(c.gpa, rule.*);
            try c.coverage.include(c.gpa, @tagName(rule.source), 1);
        }

        // Body signatures: filter, expand modifiers into variants, and name them in the shared
        // signature id space.
        const arena = c.arena.allocator();
        var kept_bodies: std.ArrayList(ir.BodyRule) = .empty;
        defer kept_bodies.deinit(c.gpa);
        var body_variants: std.ArrayList([]hexsig.Variant) = .empty;
        defer body_variants.deinit(c.gpa);
        var names: std.ArrayList(hash_build.ExtraName) = .empty;
        defer names.deinit(c.gpa);
        for (c.bodies.items) |*rule| {
            if (filters.skipReasonFor(rule.name, rule.line, rule.flevel_min, rule.flevel_max, &ignore, filters.engine_flevel)) |reason| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), reason);
                continue;
            }
            const variants = hexsig.expand(arena, rule.subsig.pattern, rule.subsig.mods) catch |err| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), hexsig.reasonOf(err));
                continue;
            };
            try kept_bodies.append(c.gpa, rule.*);
            try body_variants.append(c.gpa, variants);
            try names.append(c.gpa, .{ .name = rule.name, .flags = rule.flags, .source = rule.source });
            try c.coverage.include(c.gpa, @tagName(rule.source), 1);
        }

        // Logical signatures: the same filters; every subsig must expand or the rule is dropped.
        var kept_logicals: std.ArrayList(*const ir.LogicalRule) = .empty;
        defer kept_logicals.deinit(c.gpa);
        var logical_variants: std.ArrayList([]const []hexsig.Variant) = .empty;
        defer logical_variants.deinit(c.gpa);
        logical: for (c.logicals.items) |*rule| {
            if (filters.skipReasonFor(rule.name, rule.line, rule.flevel_min, rule.flevel_max, &ignore, filters.engine_flevel)) |reason| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), reason);
                continue;
            }
            const per_subsig = try arena.alloc([]hexsig.Variant, rule.subsigs.len);
            for (rule.subsigs, per_subsig) |sub, *out| switch (sub) {
                .hex => |h| out.* = hexsig.expand(arena, h.pattern, h.mods) catch |err| {
                    try c.coverage.skip(c.gpa, @tagName(rule.source), hexsig.reasonOf(err));
                    continue :logical;
                },
                // Byte compares run at evaluation time and have no program.
                .byte_compare => out.* = &.{},
            };
            try kept_logicals.append(c.gpa, rule);
            try logical_variants.append(c.gpa, per_subsig);
            try names.append(c.gpa, .{ .name = rule.name, .flags = rule.flags, .source = rule.source });
            try c.coverage.include(c.gpa, @tagName(rule.source), 1);
        }

        var built = try hash_build.buildWithNames(c.gpa, kept.items, names.items);
        defer built.deinit();

        var inputs: std.ArrayList(prog_build.Input) = .empty;
        defer inputs.deinit(c.gpa);
        for (kept_bodies.items, body_variants.items, built.extra_sigs[0..kept_bodies.items.len]) |rule, variants, sig| {
            for (variants) |v| {
                var flags: u8 = 0;
                if (v.folded) flags |= prog.flag_folded;
                if (v.wide) flags |= prog.flag_wide;
                if (rule.subsig.mods.fullword) flags |= prog.flag_fullword;
                try inputs.append(c.gpa, .{ .pattern = v.pattern, .offset = rule.subsig.offset, .target = rule.target, .sig = sig, .flags = flags });
            }
        }
        var ldb_entries: std.ArrayList(ldb_build.Entry) = .empty;
        defer ldb_entries.deinit(c.gpa);
        const logical_sigs = built.extra_sigs[kept_bodies.items.len..];
        for (kept_logicals.items, logical_variants.items, logical_sigs, 0..) |rule, per_subsig, sig, record| {
            const first: u32 = @intCast(inputs.items.len);
            for (rule.subsigs, per_subsig, 0..) |sub, variants, i| {
                if (sub != .hex) continue;
                const h = sub.hex;
                for (variants) |v| {
                    var flags: u8 = prog.flag_ldb;
                    if (v.folded) flags |= prog.flag_folded;
                    if (v.wide) flags |= prog.flag_wide;
                    if (h.mods.fullword) flags |= prog.flag_fullword;
                    try inputs.append(c.gpa, .{ .pattern = v.pattern, .offset = h.offset, .target = rule.tdb.target, .sig = @intCast(record), .subsig = @intCast(i), .flags = flags });
                }
            }
            try ldb_entries.append(c.gpa, .{ .rule = rule, .sig = sig, .prog_first = first, .prog_count = @intCast(inputs.items.len - first) });
        }
        const ldb_raw = try ldb_build.build(c.gpa, ldb_entries.items);
        defer c.gpa.free(ldb_raw);

        const programs_raw = try prog_build.build(c.gpa, inputs.items);
        defer c.gpa.free(programs_raw);
        const programs = try c.gpa.alignedAlloc(u8, .@"4", programs_raw.len);
        defer c.gpa.free(programs);
        @memcpy(programs, programs_raw);

        // One anchored-offset index per partition, each proven to reach all of its programs.
        var anchored_sections: [ndb.max_target + 1]?[]u8 = @splat(null);
        defer for (anchored_sections) |a| if (a) |bytes| c.gpa.free(bytes);
        if (inputs.items.len > 0) {
            const progs = try prog.Programs.init(programs);
            for (&anchored_sections, 0..) |*slot, p| slot.* = try anchored_build.build(c.gpa, progs, @intCast(p));
        }
        var allow = try hash_build.build(c.gpa, c.allow.items);
        defer allow.deinit();

        var report: Io.Writer.Allocating = .init(c.gpa);
        defer report.deinit();
        try c.coverage.render(&report.writer);

        var sections: std.ArrayList(writer.Section) = .empty;
        defer sections.deinit(c.gpa);
        var buf: [32]writer.Section = undefined;
        try sections.appendSlice(c.gpa, built.sections(&buf));
        for (allow.hot, 0..) |hot, t| if (hot) |bytes| {
            try sections.append(c.gpa, .{ .kind = .fp_tables, .variant = @intCast(t), .bytes = bytes });
            try sections.append(c.gpa, .{ .kind = .fp_tables, .variant = fp_cold_variant_offset + @as(u16, @intCast(t)), .bytes = allow.cold[t].? });
        };
        if (inputs.items.len > 0) try sections.append(c.gpa, .{ .kind = .subsig_prog, .bytes = programs });
        if (ldb_entries.items.len > 0) try sections.append(c.gpa, .{ .kind = .ldb_table, .align_log2 = 12, .bytes = ldb_raw });
        for (anchored_sections, 0..) |a, p| if (a) |bytes| {
            try sections.append(c.gpa, .{ .kind = .anchored_index, .variant = @intCast(p), .partition = @intCast(p), .hot = true, .bytes = bytes });
        };
        try sections.append(c.gpa, .{ .kind = .coverage_report, .bytes = report.written() });

        var opts = options;
        opts.sources = c.sources;
        opts.sources.engine_flevel = filters.engine_flevel;
        try writer.write(io, dir, sub_path, sections.items, opts);
        return .{
            .signatures = built.signature_count,
            .hash_rules = kept.items.len,
            .body_rules = kept_bodies.items.len,
            .logical_rules = ldb_entries.items.len,
            .programs = inputs.items.len,
            .allowlist_rules = c.allow.items.len,
            .duplicates = built.duplicates,
        };
    }
};

fn extension(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "";
    return name[dot + 1 ..];
}

fn isLaterFormat(ext: []const u8) bool {
    for (later_formats) |f| if (std.mem.eql(u8, f, ext)) return true;
    return false;
}

test "compile files and a container, filter, and write a database" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const db = @import("../db/root.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "test.cld", .data = cvd.fixture_cld });

    var c = Compiler.init(gpa);
    defer c.deinit();
    _ = try c.addContainer(io, tmp.dir, "test.cld", .{ .kind = .cld, .allow_unverified = true });
    try c.addFile("local.hdb", "00112233445566778899aabbccddeeff:10:Local.Ignored-1-0\nbad line\n");
    try c.addFile("local.ign2", "Local.Ignored-1-0\n");
    try c.addFile("local.fp", "44d88612fea8a8f36de82e1278abb02f:68:Allow.Eicar\n");
    try c.addFile("main.ndb", "Eicar:0:*:58354f\nBroken:0:*:58(35\n");
    try c.addFile("main.pdb", "R:example.com\n");
    try c.addFile("main.ldb", "Logical.Test-1-0;Target:0;0&1;4142;4344::i\nLogical.Bad-2-0;Target:0;0=0;4142\n");
    const summary = try c.write(io, tmp.dir, "out.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 2), summary.hash_rules); // two from the container
    try std.testing.expectEqual(@as(u64, 1), summary.allowlist_rules);
    try std.testing.expectEqual(@as(u64, 1), summary.body_rules);
    try std.testing.expectEqual(@as(u64, 1), summary.logical_rules);
    try std.testing.expectEqual(@as(u64, 1 + 1 + 4), summary.programs); // ndb, then 1 + 4 nocase variants

    const opened = try db.reader.open(io, tmp.dir, "out.zavdb", .{ .allow_unsigned = true });
    defer opened.close();
    const report = opened.section(.coverage_report, 0).?;
    try std.testing.expect(std.mem.indexOf(u8, report, "hdb: 1 skipped (ignored)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "local.hdb: 1 skipped (field_count)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "ndb: 1 included") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "main.ndb: 1 skipped (hex_bad_alternation)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "main.pdb: 1 skipped (unsupported_database)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "main.ldb: 1 skipped (expr_true_without_hits)") != null);
    const progs = try prog.Programs.init(opened.section(.subsig_prog, 0).?);
    try std.testing.expectEqual(@as(usize, 6), progs.count());
    const logical = try ldb_table.LdbTable.init(opened.section(.ldb_table, 0).?, progs);
    try std.testing.expectEqual(@as(usize, 1), logical.records.len);
    try std.testing.expectEqual(@as(u32, 1), logical.records[0].prog_first);
    try std.testing.expectEqual(@as(u32, 5), logical.records[0].prog_count);

    // The ignored signature is not in the database; the container's EICAR is.
    const t = hashidx.tableVariant(.md5, .file);
    const table = try hashidx.Table.init(opened.section(.hash_hot, t).?, opened.section(.hash_cold, t).?);
    var ignored: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ignored, "00112233445566778899aabbccddeeff");
    try std.testing.expectEqual(@as(?u32, null), table.lookup(10, &ignored));
    var eicar: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&eicar, "44d88612fea8a8f36de82e1278abb02f");
    try std.testing.expect(table.lookup(68, &eicar) != null);

    // The allowlist is a full-digest table of its own.
    const fp = try hashidx.Table.init(opened.section(.fp_tables, t).?, opened.section(.fp_tables, fp_cold_variant_offset + t).?);
    try std.testing.expect(fp.lookup(68, &eicar) != null);
}
