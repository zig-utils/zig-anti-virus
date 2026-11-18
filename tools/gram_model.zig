//! `zig build gram-model -- <out.bin> <corpus dir>...`: build the 4-gram frequency model atom
//! selection uses (src/compile/gram_model.zig) from benign corpus directories, as fetched by
//! `bun bench/fetch.ts B1`. Files are read in name order (the corpus names files by SHA-256),
//! so the same corpus always gives the same model.
const std = @import("std");
const zav = @import("zav");
const gm = zav.compile.gram_model;

pub const top_count = 32768;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) {
        std.debug.print("usage: gram-model <out.bin> <corpus dir>...\n", .{});
        std.process.exit(2);
    }
    var paths: std.ArrayList([]const u8) = .empty;
    defer {
        for (paths.items) |p| gpa.free(p);
        paths.deinit(gpa);
    }
    for (args[2..]) |dir_path| {
        var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .file) continue;
            try paths.append(gpa, try std.fs.path.join(gpa, &.{ dir_path, e.name }));
        }
    }
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    var b = try gm.Builder.init(gpa);
    defer b.deinit();
    for (0..2) |pass| {
        for (paths.items) |p| {
            const data = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 30));
            defer gpa.free(data);
            if (pass == 0) b.addSketch(data) else try b.addExact(data);
        }
        if (pass == 0) b.finishSketch(top_count * 16);
    }
    const bytes = try b.finish(gpa, top_count);
    defer gpa.free(bytes);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[1], .data = bytes });
    const m = try gm.Model.init(bytes);
    std.debug.print("{d} files, {d} grams, {d} top grams, floor {d}/8 bits, {d} bytes\n", .{ paths.items.len, m.total, m.top.len, m.floor, bytes.len });
}
