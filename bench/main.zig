//! `zig build bench -- <results.json>`: kernel micro-benchmarks with zig-bench. The end-to-end
//! harness against clamd (corpora, memory sampling) lands with P6.15.
const std = @import("std");
const bench = @import("bench");
const zav = @import("zav");

var io_global: std.Io = undefined;
var dir_global: std.Io.Dir = undefined;
var sink: u64 = 0;

/// Open and close a 200 MB database: header, signature and section-table checks only.
fn dbOpen() void {
    const db = zav.db.reader.open(io_global, dir_global, "bench.zavdb", .{ .allow_unsigned = true }) catch unreachable;
    sink +%= db.header().db_version;
    db.close();
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const out_path = if (args.len > 1) args[1] else "zig-out/bench.json";
    if (std.fs.path.dirname(out_path)) |dir| try std.Io.Dir.cwd().createDirPath(init.io, dir);

    io_global = init.io;
    try std.Io.Dir.cwd().createDirPath(init.io, "zig-out/bench-data");
    dir_global = try std.Io.Dir.cwd().openDir(init.io, "zig-out/bench-data", .{});
    defer dir_global.close(init.io);

    // A 200 MB database: one hot and one cold section, mostly zero bytes.
    const big = try init.gpa.alloc(u8, 200 * 1024 * 1024);
    defer init.gpa.free(big);
    @memset(big, 0);
    const sections = [_]zav.db.writer.Section{
        .{ .kind = .hash_hot, .hot = true, .bytes = big[0 .. 32 * 1024 * 1024] },
        .{ .kind = .hash_cold, .bytes = big[32 * 1024 * 1024 ..] },
    };
    try zav.db.writer.write(init.io, dir_global, "bench.zavdb", &sections, .{ .db_version = 1 });

    const before = privateDirtyKiB(init.io);
    const db = try zav.db.reader.open(init.io, dir_global, "bench.zavdb", .{ .allow_unsigned = true });
    const after = privateDirtyKiB(init.io);
    db.close();
    if (before != null and after != null)
        std.debug.print("db open: private dirty delta {d} KiB\n", .{after.? -| before.?});

    var suite = bench.BenchmarkSuite.init(init.gpa, init.io);
    defer suite.deinit();
    try suite.add("db open 200 MB (warm cache)", dbOpen);
    suite.setBaseline(out_path);
    try suite.run();
    std.mem.doNotOptimizeAway(sink);
}

/// Linux: Private_Dirty from /proc/self/smaps_rollup. Null elsewhere.
fn privateDirtyKiB(io: std.Io) ?u64 {
    var buf: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, "/proc/self/smaps_rollup", &buf) catch return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "Private_Dirty:")) continue;
        var parts = std.mem.tokenizeAny(u8, line["Private_Dirty:".len..], " kB\t");
        return std.fmt.parseInt(u64, parts.next() orelse return null, 10) catch null;
    }
    return null;
}
