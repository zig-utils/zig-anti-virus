//! Guardian's YARA sources and TOML metadata. Setup-only allocations; scan format is unchanged.
const std = @import("std");
pub const bundle = @import("bundle.zig");
pub const metadata = @import("metadata.zig");
pub const Entry = bundle.Entry;
pub const Pack = bundle.Pack;
pub const max_rules = 4096;

/// Require one metadata file and at least one rule file per family; validate before compilation.
pub fn validate(arena: std.mem.Allocator, pack: Pack) !void {
    try bundle.validateEntries(pack.entries);
    if (pack.version == 0 or pack.version > std.math.maxInt(u32)) return error.InvalidPackVersion;
    for (pack.entries) |entry| {
        const slash = std.mem.indexOfScalar(u8, entry.path, '/').?;
        const family = entry.path[0 .. slash + 1];
        var meta: ?[]const u8 = null;
        var rules: usize = 0;
        for (pack.entries) |candidate| {
            if (!std.mem.startsWith(u8, candidate.path, family)) continue;
            if (std.mem.eql(u8, candidate.path[family.len..], "meta.toml")) {
                meta = candidate.bytes;
            } else rules += 1;
        }
        if (rules == 0 or meta == null) return error.InvalidPackFamily;
        if (std.mem.endsWith(u8, entry.path, "/meta.toml")) _ = try metadata.parse(arena, meta.?);
    }
}

/// Explicit local authoring path. Refuse symlinks and only inspect two directory levels.
/// Caller owns arena and source directory; no filesystem writes or archive extraction occur.
pub fn readDirectory(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, version: u64) !Pack {
    var entries: std.ArrayList(Entry) = .empty;
    var families = dir.iterate();
    var total: usize = 0;
    while (try families.next(io)) |family| {
        if (family.kind != .directory) {
            // Documentation may accompany a local pack; symlinks are never followed.
            if (family.kind == .sym_link) return error.InvalidPackPath;
            continue;
        }
        var sub = try dir.openDir(io, family.name, .{ .iterate = true, .follow_symlinks = false });
        defer sub.close(io);
        var files = sub.iterate();
        while (try files.next(io)) |file| {
            if (file.kind != .file) return error.InvalidPackPath;
            if (!std.mem.eql(u8, file.name, "meta.toml") and !std.mem.endsWith(u8, file.name, ".yar")) continue;
            const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ family.name, file.name });
            if (!bundle.validPath(path)) return error.InvalidPackPath;
            if (entries.items.len >= bundle.max_entries) return error.PackLimit;
            const limit: usize = if (std.mem.eql(u8, file.name, "meta.toml")) bundle.max_meta_bytes else bundle.max_rule_bytes;
            const source = try sub.openFile(io, file.name, .{ .follow_symlinks = false, .allow_directory = false });
            defer source.close(io);
            if ((try source.stat(io)).kind != .file) return error.InvalidPackPath;
            var buffer: [4096]u8 = undefined;
            var reader = source.reader(io, &buffer);
            const bytes = try reader.interface.allocRemaining(arena, .limited(limit + 1));
            total += @sizeOf(bundle.FileRecord) + path.len + bytes.len;
            if (total + 104 > bundle.max_bytes) return error.PackLimit;
            try entries.append(arena, .{ .path = path, .bytes = bytes });
        }
    }
    // Filesystem iteration is not a stable ordering. Reproducible pack bytes and signature ids.
    std.mem.sort(Entry, entries.items, {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.less);
    const pack: Pack = .{ .version = version, .entries = entries.items };
    try validate(arena, pack);
    return pack;
}

test {
    _ = bundle;
    _ = metadata;
    _ = @import("integration_test.zig");
}
