//! `zig build bench -- <results.json>`: kernel micro-benchmarks with zig-bench. The end-to-end
//! harness against clamd (corpora, memory sampling) lands with P6.15.
const std = @import("std");
const bench = @import("bench");
const zav = @import("zav");

var io_global: std.Io = undefined;
var dir_global: std.Io.Dir = undefined;
var sink: u64 = 0;
var lookup_table: zav.match.hashidx.Table = undefined;
var lookup_probes: [4096][16]u8 = undefined;
var lookup_i: usize = 0;

/// One hash-index lookup in a 1M-entry MD5 table: a random digest at a populated size.
fn hashLookup() void {
    const d = &lookup_probes[lookup_i & 4095];
    lookup_i +%= 1;
    if (lookup_table.lookup(1000 + (lookup_i % 4096), d)) |sig| sink +%= sig;
}

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

    // A 1M-entry MD5 table spread over 4096 sizes.
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    const rules = try init.gpa.alloc(zav.compile.ir.HashRule, 1_000_000);
    defer init.gpa.free(rules);
    for (rules, 0..) |*r, i| {
        var digest: [32]u8 = @splat(0);
        random.bytes(digest[0..16]);
        r.* = .{ .algo = .md5, .scope = .file, .digest = digest, .size = 1000 + (i % 4096), .name = "Bench.Sig", .source = .hdb };
    }
    var built = try zav.compile.hash_build.build(init.gpa, rules);
    defer built.deinit();
    const t = zav.match.hashidx.tableVariant(.md5, .file);
    lookup_table = try .init(built.hot[t].?, built.cold[t].?);
    for (&lookup_probes) |*p| random.bytes(p);

    var suite = bench.BenchmarkSuite.init(init.gpa, init.io);
    defer suite.deinit();
    try suite.add("db open 200 MB (warm cache)", dbOpen);
    try suite.add("hash lookup, 1M MD5 entries", hashLookup);
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
