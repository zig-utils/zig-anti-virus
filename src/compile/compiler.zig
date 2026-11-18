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
const filters = @import("filters.zig");
const coverage_mod = @import("coverage.zig");
const hash_build = @import("hash_build.zig");
const cvd = @import("cvd.zig");
const mbazaar = @import("mbazaar.zig");
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

        var built = try hash_build.build(c.gpa, kept.items);
        defer built.deinit();
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
        try sections.append(c.gpa, .{ .kind = .coverage_report, .bytes = report.written() });

        var opts = options;
        opts.sources = c.sources;
        opts.sources.engine_flevel = filters.engine_flevel;
        try writer.write(io, dir, sub_path, sections.items, opts);
        return .{
            .signatures = built.signature_count,
            .hash_rules = kept.items.len,
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
    try c.addFile("main.ndb", "Eicar:0:*:58354f\n");
    const summary = try c.write(io, tmp.dir, "out.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 2), summary.hash_rules); // two from the container
    try std.testing.expectEqual(@as(u64, 1), summary.allowlist_rules);

    const opened = try db.reader.open(io, tmp.dir, "out.zavdb", .{ .allow_unsigned = true });
    defer opened.close();
    const report = opened.section(.coverage_report, 0).?;
    try std.testing.expect(std.mem.indexOf(u8, report, "hdb: 1 skipped (ignored)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "local.hdb: 1 skipped (field_count)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "main.ndb: 1 skipped (unsupported_database)") != null);

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
