//! The hash stage of a scan: ask the need map which algorithms this file's size calls for, hash
//! only those in one pass over the source, then look each digest up. Files whose size no hash
//! signature has are never hashed. Works on any seekable or streaming source and allocates nothing.
const std = @import("std");
const Io = std.Io;
const db = @import("../db/root.zig");
const hashidx = @import("../match/hashidx.zig");
const ir = @import("../compile/ir.zig");
const source_mod = @import("source.zig");
const limits_mod = @import("limits.zig");
const pe = @import("../fmt/pe.zig");

/// The hash sections of an opened database, ready for lookups.
pub const HashIndex = struct {
    need: [3]?hashidx.NeedMap = @splat(null),
    tables: [9]?hashidx.Table = @splat(null),
    allow: [9]?hashidx.Table = @splat(null),
    meta: ?hashidx.SigMeta = null,
    /// Report PUA signatures (`hashidx.SigMeta.reported`). Off by default, as in clamscan.
    detect_pua: bool = false,

    pub fn load(database: db.reader.Database) !HashIndex {
        var index: HashIndex = .{};
        for (0..3) |scope| {
            if (database.section(.hash_need_map, @intCast(scope))) |bytes| index.need[scope] = try .init(bytes);
        }
        for (0..9) |t| {
            const v: u16 = @intCast(t);
            if (database.section(.hash_hot, v)) |hot| index.tables[t] = try .init(hot, database.section(.hash_cold, v) orelse return error.BadHashTable);
            if (database.section(.fp_tables, v)) |hot| index.allow[t] = try .init(hot, database.section(.fp_tables, 16 + v) orelse return error.BadHashTable);
        }
        if (database.section(.sigmeta, 0)) |records| index.meta = try .init(records, database.section(.name_pool, 0) orelse return error.BadSigMeta);
        return index;
    }
};

pub const Verdict = union(enum) {
    clean,
    /// Signature id; resolve the name with `HashIndex.meta`.
    infected: u32,
    /// A signature matched but an allowlist entry for the same file overrides it.
    allowed: u32,
    limited: limits_mod.Event,
};

/// Hash a whole-file source and look it up. `block` is caller scratch (64 KiB is plenty).
pub fn scanSource(io: Io, index: *const HashIndex, src: source_mod.Source, tracker: *limits_mod.Tracker, block: []u8) !Verdict {
    const size = src.len() orelse return error.UnknownSize;
    if (size < limits_mod.min_scan_size) return .clean;
    tracker.checkFileSize(size) catch return .{ .limited = .file_size };
    var file = FileHashes.init(index, size) orelse return .clean;
    while (file.bytes < size) {
        const n = try src.readAt(io, file.bytes, block);
        if (n == 0) break;
        tracker.addScanned(n) catch return .{ .limited = .scan_size };
        file.update(block[0..n]);
    }
    if (file.bytes != size) return error.SourceChanged;
    return file.finish(index);
}

/// The whole-file hash stage for callers that already deliver an object's bytes in chunks.
pub const FileHashes = struct {
    size: u64,
    bytes: u64 = 0,
    need: u8,
    md5: std.crypto.hash.Md5 = .init(.{}),
    sha1: std.crypto.hash.Sha1 = .init(.{}),
    sha256: std.crypto.hash.sha2.Sha256 = .init(.{}),

    pub fn init(index: *const HashIndex, size: u64) ?FileHashes {
        if (size < limits_mod.min_scan_size) return null;
        const map = index.need[@backingInt(ir.HashScope.file)] orelse return null;
        const need = map.mask(size);
        return if (need == 0) null else .{ .size = size, .need = need };
    }

    pub fn update(file: *FileHashes, chunk: []const u8) void {
        file.bytes += chunk.len;
        if (file.need & hashidx.need_md5 != 0) file.md5.update(chunk);
        if (file.need & hashidx.need_sha1 != 0) file.sha1.update(chunk);
        if (file.need & hashidx.need_sha256 != 0) file.sha256.update(chunk);
    }

    pub fn finish(file: *FileHashes, index: *const HashIndex) Verdict {
        if (file.bytes != file.size) return .clean;
        var md5: [16]u8 = undefined;
        var sha1: [20]u8 = undefined;
        var sha256: [32]u8 = undefined;
        if (file.need & hashidx.need_md5 != 0) file.md5.final(&md5);
        if (file.need & hashidx.need_sha1 != 0) file.sha1.final(&sha1);
        if (file.need & hashidx.need_sha256 != 0) file.sha256.final(&sha256);

        const digests = [_]struct { algo: ir.HashAlgo, bit: u8, bytes: []const u8 }{
            .{ .algo = .md5, .bit = hashidx.need_md5, .bytes = &md5 },
            .{ .algo = .sha1, .bit = hashidx.need_sha1, .bytes = &sha1 },
            .{ .algo = .sha256, .bit = hashidx.need_sha256, .bytes = &sha256 },
        };
        for (digests) |d| {
            if (file.need & d.bit == 0) continue;
            const table = index.tables[hashidx.tableVariant(d.algo, .file)] orelse continue;
            const sig = table.lookup(file.size, d.bytes) orelse continue;
            if (!hashidx.SigMeta.reported(index.meta, sig, index.detect_pua)) continue;
            // Check the whole-file allowlist only when a hash hit.
            for (digests) |a| {
                if (file.need & a.bit == 0) continue;
                if (index.allow[hashidx.tableVariant(a.algo, .file)]) |allow| {
                    if (allow.lookup(file.size, a.bytes) != null) return .{ .allowed = sig };
                }
            }
            return .{ .infected = sig };
        }
        return .clean;
    }
};

/// Section (.mdb/.msb) and import (.imp) hashes of a parsed PE. A section is hashed only when
/// the pe_section need map lists its stored raw size, and only with the algorithms that size
/// needs; the import hash is computed only when the pe_import map lists any size at all.
pub fn scanPe(io: Io, index: *const HashIndex, src: source_mod.Source, info: *const pe.Info, block: []u8) Verdict {
    if (index.need[@backingInt(ir.HashScope.pe_section)]) |map| {
        for (info.sections) |*s| {
            const need = map.mask(s.stored_raw_size);
            if (need == 0) continue;
            inline for (.{
                .{ ir.HashAlgo.md5, hashidx.need_md5, std.crypto.hash.Md5 },
                .{ ir.HashAlgo.sha1, hashidx.need_sha1, std.crypto.hash.Sha1 },
                .{ ir.HashAlgo.sha256, hashidx.need_sha256, std.crypto.hash.sha2.Sha256 },
            }) |a| if (need & a[1] != 0) {
                if (index.tables[hashidx.tableVariant(a[0], .pe_section)]) |table| {
                    if (pe.sectionDigest(io, src, s, a[2], block)) |d| {
                        if (table.lookup(s.stored_raw_size, &d)) |sig| if (hashidx.SigMeta.reported(index.meta, sig, index.detect_pua)) return .{ .infected = sig };
                    }
                }
            };
        }
    }
    if (index.tables[hashidx.tableVariant(.md5, .pe_import)]) |table| {
        if (pe.importHash(io, src, info)) |ih| {
            const listed = if (index.need[@backingInt(ir.HashScope.pe_import)]) |map| map.mask(ih.size) != 0 else true;
            if (listed) if (table.lookup(ih.size, &ih.md5)) |sig| if (hashidx.SigMeta.reported(index.meta, sig, index.detect_pua)) return .{ .infected = sig };
        }
    }
    return .clean;
}

test "section-hash and import-hash signatures detect a PE" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const fixtures = @import("../fmt/fixtures/fixtures.zig");
    const sample = fixtures.exes[0].bytes;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // .text is the 512 bytes at 0x200 (independent of the parser's section mapping).
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(sample[0x200..0x400], &md5, .{});
    var line_buf: [128]u8 = undefined;
    const mdb = try std.fmt.bufPrint(&line_buf, "512:{s}:Test.Section.Text\n", .{std.fmt.bytesToHex(md5, .lower)});
    var sections: [pe.max_sections]pe.Section = undefined;

    for ([_]struct { file: []const u8, text: []const u8, name: []const u8 }{
        .{ .file = "t.mdb", .text = mdb, .name = "Test.Section.Text" },
        // The ClamAV documentation's clam.exe import hash; the fixture imports the same two functions.
        .{ .file = "t.imp", .text = "98c88d882f01a3f6ac1e5f7dfd761624:39:Test.Import.Clam\n", .name = "Test.Import.Clam" },
    }) |case| {
        var c = Compiler.init(gpa);
        defer c.deinit();
        try c.addFile(case.file, case.text);
        _ = try c.write(io, tmp.dir, "pe.zavdb", .{ .db_version = 1 });
        const database = try db.reader.open(io, tmp.dir, "pe.zavdb", .{ .allow_unsigned = true });
        defer database.close();
        const index = try HashIndex.load(database);
        const info = try pe.parse(io, .{ .memory = sample }, &sections);
        var block: [4096]u8 = undefined;
        const v = scanPe(io, &index, .{ .memory = sample }, &info, &block);
        var name_buf: [64]u8 = undefined;
        try std.testing.expectEqualStrings(case.name, try index.meta.?.name(v.infected, &name_buf));
        // A PE without that section or import table stays clean.
        const other = fixtures.exes[4].bytes; // overlapping sections: .rdata reads .text bytes
        const other_info = try pe.parse(io, .{ .memory = other }, &sections);
        if (std.mem.eql(u8, case.file, "t.imp")) try std.testing.expectEqual(Verdict.clean, scanPe(io, &index, .{ .memory = other }, &other_info, &block));
    }
}

test "compile the built-in signatures and detect EICAR end to end" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const builtin_rules = @import("../compile/builtin.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addBuiltin();
    _ = try c.write(io, tmp.dir, "builtin.zavdb", .{ .db_version = 1 });

    const database = try db.reader.open(io, tmp.dir, "builtin.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try HashIndex.load(database);
    var block: [4096]u8 = undefined;
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    const hit = try scanSource(io, &index, .{ .memory = builtin_rules.eicar }, &tracker, &block);
    try std.testing.expectEqualStrings(builtin_rules.eicar_name, try index.meta.?.name(hit.infected, &name_buf));

    // One byte different: same size, no match. A different size is never hashed at all.
    var altered: [builtin_rules.eicar.len]u8 = builtin_rules.eicar.*;
    altered[0] = 'Y';
    try std.testing.expectEqual(Verdict.clean, try scanSource(io, &index, .{ .memory = &altered }, &tracker, &block));
    try std.testing.expectEqual(Verdict.clean, try scanSource(io, &index, .{ .memory = "hello" }, &tracker, &block));
    try std.testing.expectEqual(@as(u8, 0), index.need[0].?.mask(5));
}
