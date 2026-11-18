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

var anchored_index: zav.match.anchored.Index = undefined;
var anchored_programs: zav.match.prog.Programs = undefined;
var anchored_file: [4096]u8 = undefined;
var anchored_sections: [4]zav.match.verify_vm.Section = undefined;

fn countHit(n: *u64, hit: zav.match.anchored.Hit) bool {
    n.* +%= hit.prog;
    return true;
}

/// One file through an anchored index of 20k EP, absolute, EOF and section signatures (P4.07).
fn anchoredScan() void {
    var budget: zav.match.verify_vm.Budget = .{};
    const info: zav.match.verify_vm.FileInfo = .{ .size = anchored_file.len, .entry_point = 1024, .sections = &anchored_sections };
    zav.match.anchored.scan(anchored_index, anchored_programs, &anchored_file, info, &budget, &sink, countHit) catch unreachable;
}

fn buildAnchored(gpa: std.mem.Allocator, random: std.Random) !void {
    const zc = zav.compile;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    const a = arena.allocator();
    var inputs: std.ArrayList(zc.prog_build.Input) = .empty;
    const kinds = [_]zc.ir.Offset{
        .{ .kind = .entry_point, .a = 0 },
        .{ .kind = .entry_point, .a = 16 },
        .{ .kind = .absolute, .a = 0 },
        .{ .kind = .eof_minus, .a = 64 },
        .{ .kind = .section_start, .section = 1, .a = 0 },
        .{ .kind = .last_section, .a = 8 },
    };
    for (0..20_000) |i| {
        var hex: [16]u8 = undefined;
        var raw: [8]u8 = undefined;
        random.bytes(&raw);
        _ = std.fmt.bufPrint(&hex, "{x}", .{raw}) catch unreachable;
        var diag: zc.hexsig.Diag = .{};
        const off = kinds[i % kinds.len];
        try inputs.append(a, .{ .pattern = try zc.hexsig.parse(a, &hex, &diag), .target = 1, .offset = off, .sig = @intCast(i) });
    }
    // A few window signatures that are verified at every start of a 16-byte window.
    for (0..64) |i| {
        var diag: zc.hexsig.Diag = .{};
        try inputs.append(a, .{ .pattern = try zc.hexsig.parse(a, "e8????????5d", &diag), .target = 1, .offset = .{ .kind = .entry_point, .a = @intCast(i), .shift = 16 }, .sig = 0 });
    }
    const bytes = try zc.prog_build.build(a, inputs.items);
    const pimage = try a.alignedAlloc(u8, .@"4", bytes.len);
    @memcpy(pimage, bytes);
    anchored_programs = try .init(pimage);
    const section = (try zc.anchored_build.build(a, anchored_programs, 1)).?;
    const image = try a.alignedAlloc(u8, .@"4", section.len);
    @memcpy(image, section);
    anchored_index = try .init(image, anchored_programs);
    random.bytes(&anchored_file);
    anchored_sections = .{ .{ .offset = 512, .size = 1024 }, .{ .offset = 1536, .size = 1024 }, .{ .offset = 2560, .size = 512 }, .{ .offset = 3072, .size = 1024 } };
    // The arena lives for the whole run; the programs and index point into it.
}

var logical_tables: [2]zav.match.ldb_table.LdbTable = undefined;
var logical_state: zav.match.logical.State = undefined;
var logical_i: u32 = 0;

fn logicalFile(comptime which: usize) fn () void {
    return struct {
        /// 16 touched signatures, evaluation and the reset: one file's logical-state cost. The
        /// touched signatures come from the same first 1000 records in both tables, so the
        /// numbers differ only if the state's cost depended on the database size.
        fn run() void {
            const table = logical_tables[which];
            const n: u32 = 1000;
            for (0..16) |k| {
                const ldb: u32 = (logical_i +% @as(u32, @intCast(k)) *% 7919) % n;
                logical_state.touch(table, .{}, ldb, 0, 0) catch unreachable;
                logical_state.touch(table, .{}, ldb, 1, 0) catch unreachable;
            }
            logical_i +%= 1;
            var out: [4]u32 = undefined;
            sink +%= logical_state.finalize(table, "", &out);
            logical_state.reset();
        }
    }.run;
}

fn buildLogical(gpa: std.mem.Allocator) !void {
    const zc = zav.compile;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    const a = arena.allocator();
    var column: u32 = 0;
    const rule = try a.create(zc.ir.LogicalRule);
    rule.* = try zc.ldb.parseLine(a, "Bench.Logical-1-0;Target:0;(0|1)>1&2=0;aabb;ccdd;eeff", &column);
    for ([_]usize{ 1_000, 100_000 }, 0..) |count, t| {
        const entries = try a.alloc(zc.ldb_build.Entry, count);
        for (entries, 0..) |*e, i| e.* = .{ .rule = rule, .sig = @intCast(i), .prog_first = 0, .prog_count = 0 };
        const bytes = try zc.ldb_build.build(a, entries);
        const image = try a.alignedAlloc(u8, .@"8", bytes.len);
        @memcpy(image, bytes);
        logical_tables[t] = try .init(image, null);
    }
    logical_state = try .init(a);
    // The arena lives for the whole run.
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
    // `zig build bench -- <out.json> e7 [filter]`: only the decoder experiment
    // (docs/experiments/E7), optionally only the corpus files whose name contains `filter`.
    if (args.len > 2 and std.mem.eql(u8, args[2], "e7")) return decoderBenchmarks(init.io, init.gpa, if (args.len > 3) args[3] else "");
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

    hash_input = try init.gpa.alloc(u8, hash_input_len);
    defer init.gpa.free(hash_input);
    var hash_prng = std.Random.DefaultPrng.init(8);
    hash_prng.random().bytes(hash_input);
    try hashBenchmarks(init.io, &suite);
    try suite.add("hash lookup, 1M MD5 entries", hashLookup);
    try buildAnchored(init.gpa, random);
    try suite.add("anchored index, 20k signatures, one file", anchoredScan);
    try buildLogical(init.gpa);
    try suite.add("logical state, 16 touched, 1k-signature table", logicalFile(0));
    try suite.add("logical state, 16 touched, 100k-signature table", logicalFile(1));
    try normaliserBenchmarks(init.io, init.gpa, &suite);
    try prefilterBenchmarks(init.io, init.gpa, &suite);
    try decoderBenchmarks(init.io, init.gpa, "");
    suite.setBaseline(out_path);
    try suite.run();
    std.mem.doNotOptimizeAway(sink);
}

// Hashing (E8, docs/experiments/E8-hashers.md): MB/s per algorithm on every kernel variant this
// CPU can run, the fused pass, std.crypto built for the bench target, and the dispatch overhead.

const hash_input_len = 1024 * 1024;
var hash_input: []u8 = undefined;

fn HashBench(comptime kernels: *const zav.hash.Kernels, comptime algo: zav.hash.Algo) type {
    return struct {
        fn run() void {
            var h = zav.hash.hasher.Hasher(algo).initWith(kernels);
            h.update(hash_input);
            sink +%= h.finalResult()[0];
        }
    };
}

fn StdBench(comptime Std: type) type {
    return struct {
        fn run() void {
            var out: [Std.digest_length]u8 = undefined;
            Std.hash(hash_input, &out, .{});
            sink +%= out[0];
        }

        fn small() void {
            var out: [Std.digest_length]u8 = undefined;
            Std.hash(hash_input[0..64], &out, .{});
            sink +%= out[0];
        }
    };
}

fn fusedAll() void {
    var m = zav.hash.Multihash.init(.full, .{});
    m.update(hash_input);
    sink +%= m.final().sha256[0];
}

fn dispatchedSmall() void {
    sink +%= zav.hash.Sha256.hash(hash_input[0..64])[0];
}

fn detectFeatures() void {
    const f = zav.simd.arch.detect();
    sink +%= @intFromBool(f.x86_sha or f.aarch64_sha2);
}

/// Best-of-5 nanoseconds per call, each round running `f` for at least 100 ms.
fn nsPerCall(io: std.Io, f: *const fn () void) f64 {
    var best: f64 = std.math.inf(f64);
    for (0..5) |_| {
        var calls: u64 = 0;
        const start = std.Io.Clock.awake.now(io);
        var elapsed: i96 = 0;
        while (elapsed < 100 * std.time.ns_per_ms) {
            f();
            calls += 1;
            elapsed = start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds;
        }
        best = @min(best, @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(calls)));
    }
    return best;
}

fn mbps(io: std.Io, f: *const fn () void) f64 {
    return @as(f64, hash_input_len) / nsPerCall(io, f) * 1000.0;
}

fn hashBenchmarks(io: std.Io, suite: *bench.BenchmarkSuite) !void {
    const hash = zav.hash;
    const features = zav.simd.arch.detect();
    const all_kernels = comptime hash.dispatch.all ++ [_]hash.Kernels{hash.dispatch.portable};
    var brand_buf: [64]u8 = undefined;
    std.debug.print("hash: cpu {s}, {s}\n", .{ zav.simd.arch.brand(&brand_buf) orelse "unknown", @tagName(@import("builtin").os.tag) });
    std.debug.print("hash: active variant {s}; MB/s (10^6 bytes) over a 1 MiB buffer, best of 5\n", .{hash.dispatch.active().name});
    std.debug.print("hash: {s:<18} {s:>9} {s:>9} {s:>9}  hw sha1/sha256\n", .{ "variant", "md5", "sha1", "sha256" });
    inline for (all_kernels) |*k| {
        if (hash.dispatch.supports(features, k.requires)) {
            std.debug.print("hash: {s:<18} {d:>9.0} {d:>9.0} {d:>9.0}  {}/{}\n", .{
                k.name,
                mbps(io, HashBench(k, .md5).run),
                mbps(io, HashBench(k, .sha1).run),
                mbps(io, HashBench(k, .sha256).run),
                k.hwSha1(),
                k.hwSha256(),
            });
            inline for (comptime std.enums.values(hash.Algo)) |algo|
                try suite.add("hash " ++ @tagName(algo) ++ " 1 MiB " ++ k.name, HashBench(k, algo).run);
        } else std.debug.print("hash: {s:<18} skipped: this CPU cannot run it\n", .{k.name});
    }
    const Md5Std = StdBench(std.crypto.hash.Md5);
    const Sha1Std = StdBench(std.crypto.hash.Sha1);
    const Sha256Std = StdBench(std.crypto.hash.sha2.Sha256);
    std.debug.print("hash: {s:<18} {d:>9.0} {d:>9.0} {d:>9.0}\n", .{ "std (bench target)", mbps(io, Md5Std.run), mbps(io, Sha1Std.run), mbps(io, Sha256Std.run) });
    std.debug.print("hash: fused md5+sha1+sha256 (active) {d:.0} MB/s\n", .{mbps(io, fusedAll)});
    std.debug.print("hash: sha256 of 64 bytes: dispatched {d:.1} ns, std direct {d:.1} ns; feature detection {d:.0} ns\n", .{
        nsPerCall(io, dispatchedSmall), nsPerCall(io, Sha256Std.small), nsPerCall(io, detectFeatures),
    });
    try suite.add("hash fused md5+sha1+sha256 1 MiB", fusedAll);
    try suite.add("hash sha256 64 B dispatched", dispatchedSmall);
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

// Normalisers (P5.07, P5.08): MB/s over 1 MiB of generated markup and text.

var norm_html: []u8 = undefined;
var norm_text: []u8 = undefined;
var norm_out: [64 * 1024]u8 = undefined;

fn normDiscard(_: *anyopaque, bytes: []const u8) error{Stop}!void {
    sink +%= bytes.len;
}

fn htmlNormalize() void {
    var ctx: u8 = 0;
    const out: zav.fmt.html_norm.Output = .{ .ctx = &ctx, .write = normDiscard };
    const S = struct {
        var n: zav.fmt.html_norm.Normalizer = undefined;
    };
    S.n = .init(.{ .nocomment = out, .notags = out });
    S.n.feed(norm_html) catch unreachable;
    S.n.finish() catch unreachable;
}

fn textNormalize() void {
    var n: zav.fmt.text_norm.Normalizer = .{};
    var off: usize = 0;
    while (off < norm_text.len) : (off += norm_out.len) {
        const chunk = norm_text[off..@min(norm_text.len, off + norm_out.len)];
        sink +%= n.feed(chunk, &norm_out);
    }
}

fn normaliserBenchmarks(io: std.Io, gpa: std.mem.Allocator, suite: *bench.BenchmarkSuite) !void {
    const len = 1024 * 1024;
    norm_html = try gpa.alloc(u8, len);
    norm_text = try gpa.alloc(u8, len);
    const piece = "<DIV Class='Row'>  <A HREF=\"http://example.com/Path?a=1&amp;b=2\">Link &#x41;</A>\n<!-- note -->" ++
        "<script>var X = 1;</script> Some   Body TEXT with words\r\n";
    const words = "The Quick  Brown\tFox JUMPS over the lazy dog.\r\n";
    for (0..len) |i| {
        norm_html[i] = piece[i % piece.len];
        norm_text[i] = words[i % words.len];
    }
    std.debug.print("html normaliser: {d:.0} MB/s\n", .{@as(f64, len) / nsPerCall(io, htmlNormalize) * 1000.0});
    std.debug.print("text normaliser: {d:.0} MB/s\n", .{@as(f64, len) / nsPerCall(io, textNormalize) * 1000.0});
    try suite.add("html normaliser, 1 MiB", htmlNormalize);
    try suite.add("text normaliser, 1 MiB", textNormalize);
}

// E7 (docs/experiments/E7-decoders.md): decode throughput of std flate and zstd and our bzip2
// and xz over the corpus `bun bench/e7/run.ts` writes to zig-out/e7 (skipped when absent).

var e7_input: []const u8 = undefined;
var e7_plain_len: usize = 0;
var e7_out: [64 * 1024]u8 = undefined;
var e7_window: []u8 = undefined;
var e7_tt: []u32 = undefined;
var e7_tables: *zav.fmt.bzip2.Decoder.TablesType = undefined;
var e7_dict: []u8 = undefined;
var e7_probs: []u16 = undefined;
var e7_zbuf: []u8 = undefined;

/// The decoded corpus file, when the output should be checked (once per case, untimed).
var e7_expect: ?[]const u8 = null;

fn drainAll(r: *std.Io.Reader) usize {
    var n: usize = 0;
    while (true) {
        const got = zav.engine.container.readSome(r, &e7_out) catch break;
        if (e7_expect) |want| {
            if (n + got > want.len or !std.mem.eql(u8, want[n..][0..got], e7_out[0..got])) @panic("e7: decoded bytes differ from the corpus");
        }
        n += got;
    }
    return n;
}

fn e7Gzip() void {
    var in: std.Io.Reader = .fixed(e7_input);
    var d = zav.fmt.gzip.Decoder.init(&in, e7_window);
    if (drainAll(&d.interface) != e7_plain_len) @panic("e7: gzip length");
}

fn e7Bzip2() void {
    var in: std.Io.Reader = .fixed(e7_input);
    var d = zav.fmt.bzip2.Decoder.init(&in, e7_tt, e7_tables, &.{}) catch @panic("e7: bzip2 header");
    if (drainAll(&d.interface) != e7_plain_len) @panic("e7: bzip2 length");
}

fn e7Xz() void {
    var in: std.Io.Reader = .fixed(e7_input);
    var d = zav.fmt.xz.Decoder.init(&in, e7_dict, e7_probs, &.{}, &.{});
    if (drainAll(&d.interface) != e7_plain_len) @panic("e7: xz length");
}

fn e7Zstd() void {
    var in: std.Io.Reader = .fixed(e7_input);
    const s = zav.fmt.zstd.sizing(zav.fmt.zstd.frameWindow(e7_input, 8 << 20) catch unreachable);
    var d = zav.fmt.zstd.decode.Decoder.init(&in, e7_zbuf[0..s.buffer_len], s.window_len);
    if (drainAll(&d.interface) != e7_plain_len) @panic("e7: zstd length");
}

/// Best-of-5 MB/s of decompressed output, each round at least 300 ms.
fn e7Measure(io: std.Io, f: *const fn () void) f64 {
    var best: f64 = std.math.inf(f64);
    for (0..5) |_| {
        var calls: u64 = 0;
        const start = std.Io.Clock.awake.now(io);
        var elapsed: i96 = 0;
        while (elapsed < 300 * std.time.ns_per_ms) {
            f();
            calls += 1;
            elapsed = start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds;
        }
        best = @min(best, @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(calls)));
    }
    return @as(f64, @floatFromInt(e7_plain_len)) / best * 1000.0;
}

fn decoderBenchmarks(io: std.Io, gpa: std.mem.Allocator, filter: []const u8) !void {
    var dir = std.Io.Dir.cwd().openDir(io, "zig-out/e7", .{}) catch {
        std.debug.print("e7: no corpus in zig-out/e7 (run `bun bench/e7/run.ts`), skipped\n", .{});
        return;
    };
    defer dir.close(io);
    e7_window = try gpa.alloc(u8, zav.fmt.gzip.window_len);
    defer gpa.free(e7_window);
    e7_tt = try gpa.alloc(u32, 900_000);
    defer gpa.free(e7_tt);
    e7_tables = try gpa.create(zav.fmt.bzip2.Decoder.TablesType);
    defer gpa.destroy(e7_tables);
    e7_dict = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(e7_dict);
    e7_probs = try gpa.alloc(u16, zav.fmt.lzma.Lzma2.probs_len);
    defer gpa.free(e7_probs);
    e7_zbuf = try gpa.alloc(u8, zav.fmt.zstd.sizing(8 << 20).buffer_len);
    defer gpa.free(e7_zbuf);

    var results: std.ArrayList(u8) = .empty;
    defer results.deinit(gpa);
    try results.appendSlice(gpa, "[\n");
    const cases = [_]struct { file: []const u8, decoder: []const u8, f: *const fn () void }{
        .{ .file = "text.gz", .decoder = "zav inflate", .f = e7Gzip },
        .{ .file = "binary.gz", .decoder = "zav inflate", .f = e7Gzip },
        .{ .file = "text.zst", .decoder = "zav zstd", .f = e7Zstd },
        .{ .file = "binary.zst", .decoder = "zav zstd", .f = e7Zstd },
        .{ .file = "text.zst19", .decoder = "zav zstd", .f = e7Zstd },
        .{ .file = "binary.zst19", .decoder = "zav zstd", .f = e7Zstd },
        .{ .file = "text.bz2", .decoder = "zav bzip2", .f = e7Bzip2 },
        .{ .file = "binary.bz2", .decoder = "zav bzip2", .f = e7Bzip2 },
        .{ .file = "text.xz", .decoder = "zav xz/lzma2", .f = e7Xz },
        .{ .file = "binary.xz", .decoder = "zav xz/lzma2", .f = e7Xz },
    };
    var written: usize = 0;
    for (cases) |c| {
        if (std.mem.indexOf(u8, c.file, filter) == null) continue;
        const data = dir.readFileAlloc(io, c.file, gpa, .limited(1 << 30)) catch {
            std.debug.print("e7: {s} missing, skipped\n", .{c.file});
            continue;
        };
        defer gpa.free(data);
        e7_input = data;
        e7_plain_len = 16 * 1024 * 1024;
        // Check the output once against the raw corpus file, then time.
        const raw_name = c.file[0 .. std.mem.indexOfScalar(u8, c.file, '.') orelse c.file.len];
        const raw_path = try std.fmt.allocPrint(gpa, "{s}.raw", .{raw_name});
        defer gpa.free(raw_path);
        if (dir.readFileAlloc(io, raw_path, gpa, .limited(1 << 30))) |raw| {
            defer gpa.free(raw);
            e7_expect = raw;
            c.f();
            e7_expect = null;
        } else |_| {}
        const rate = e7Measure(io, c.f);
        std.debug.print("e7: {s:<14} {s:<20} {d:>6.0} MB/s\n", .{ c.file, c.decoder, rate });
        const line = try std.fmt.allocPrint(gpa, "{s}  {{\"file\": \"{s}\", \"decoder\": \"{s}\", \"mbps\": {d:.1}}}", .{ if (written > 0) ",\n" else "", c.file, c.decoder, rate });
        written += 1;
        defer gpa.free(line);
        try results.appendSlice(gpa, line);
    }
    try results.appendSlice(gpa, "\n]\n");
    // A filtered run is partial: keep the full results file.
    if (filter.len == 0) try dir.writeFile(io, .{ .sub_path = "zig-results.json", .data = results.items });
}

// Stage one per tier (P4.05) -----------------------------------------------------------------

const Tiered = struct {
    name: []const u8,
    /// Hex bodies of each generated atom: `len` random bytes, `count` of them.
    len: usize,
    count: usize,
};

/// Partitions of random atoms of one length each (11 and 7 bytes: the sampled stride-3 filter,
/// 5: stride 1 behind the gate, 3: a 3-gram tier D), plus the previous design's strides 8 and
/// 4 over 11- and 7-byte atoms for comparison.
var tier_parts: [5]zav.match.prefilter.Partition = undefined;
var tier_data: []u8 = &.{};
var tier_ring: [zav.match.prefilter.ring_len]zav.match.prefilter.Candidate = undefined;

fn buildTier(gpa: std.mem.Allocator, random: std.Random, lens: []const usize, count: usize, costs: zav.compile.atoms.Costs) !zav.match.prefilter.Partition {
    const zc = zav.compile;
    // Lives for the whole run: the partition points into it.
    var arena: std.heap.ArenaAllocator = .init(gpa);
    const a = arena.allocator();
    var inputs: std.ArrayList(zc.prog_build.Input) = .empty;
    for (0..count) |i| {
        const len = lens[i % lens.len];
        const raw = try a.alloc(u8, len);
        random.bytes(raw);
        const hex = try a.alloc(u8, 2 * len);
        _ = std.fmt.bufPrint(hex, "{x}", .{raw}) catch unreachable;
        var diag: zc.hexsig.Diag = .{};
        try inputs.append(a, .{ .pattern = try zc.hexsig.parse(a, hex, &diag), .sig = @intCast(i) });
    }
    const planned = try zc.atoms.plan(a, zc.gram_model.Model.default(), costs, inputs.items, &.{});
    var w = zc.prog_build.Writer.init(a, null);
    for (inputs.items, planned) |*in, pl| {
        in.atom = pl.atom(in.offset.kind);
        _ = try w.add(in.*);
    }
    const bytes = try w.finish();
    const image = try a.alignedAlloc(u8, .@"64", bytes.len);
    @memcpy(image, bytes);
    const progs = try zav.match.prog.Programs.init(image);
    const section = (try zc.prefilter_build.buildAll(a, progs, w.atoms.items, .{})).?;
    return (try zav.match.prefilter.loadAll(section, progs))[0].?;
}

fn Stage1Bench(comptime k: usize) type {
    return struct {
        fn run() void {
            var pos: usize = 0;
            var n: usize = 0;
            while (pos < tier_data.len) {
                const got, const next = zav.match.prefilter.stage1(&tier_parts[k], tier_data, pos, &tier_ring);
                n += got;
                pos = next;
            }
            sink +%= n;
        }
    };
}

fn prefilterBenchmarks(io: std.Io, gpa: std.mem.Allocator, suite: *bench.BenchmarkSuite) !void {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    const names = [_][]const u8{ "stride 3, 11-byte atoms", "stride 3, 7-byte atoms", "stride 1 gated, 5-byte", "tier D (3-gram, gated)", "strides 8+4 (before)" };
    const lens = [_][]const usize{ &.{11}, &.{7}, &.{5}, &.{3}, &.{ 11, 11, 11, 7 } };
    // 100k atoms per partition, about the PE partition's size.
    for (&tier_parts, lens, 0..) |*part, l, k| part.* = try buildTier(gpa, r, l, if (l[0] == 3) 2000 else 100_000, if (k == 4) .{ .sampled = &.{ 8, 4 } } else .{});
    tier_data = try gpa.alloc(u8, hash_input_len);
    r.bytes(tier_data);
    std.debug.print("stage 1: MB/s (10^6 bytes) per core over 1 MiB of random bytes, best of 5\n", .{});
    inline for (0..5) |k| {
        std.debug.print("stage 1: {s:<26} {d:>8.0}\n", .{ names[k], mbps(io, Stage1Bench(k).run) });
        try suite.add("stage 1 " ++ ([_][]const u8{ "s3 11B", "s3 7B", "s1 gated", "D", "s8+s4" })[k] ++ " 1 MiB", Stage1Bench(k).run);
    }
}
