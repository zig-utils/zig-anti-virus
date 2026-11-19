//! Prefilter census and measurements against a compiled database and benign corpora
//! (bench/corpus, fetched by `bun bench/fetch.ts`). Single-threaded: every rate is per core.
//!
//!   zig build prefilter -Doptimize=ReleaseFast -- census <db>
//!       partitions: filter sizes and loads, atom table sizes, programs by tier and target
//!   zig build prefilter -Doptimize=ReleaseFast -- scan <db> <dir>... [--reference] [--limit N]
//!       the body scan over every file: MB/s, candidates, probes and verifies per MB, detections
//!   zig build prefilter -Doptimize=ReleaseFast -- stages <db> <dir>...
//!       stage one alone, and stages one and two (no verify), per partition the files use
//!   zig build prefilter -Doptimize=ReleaseFast -- diff <db> <dir>... [--limit N]
//!       prefiltered against reference verdicts, file by file
//!   zig build prefilter -Doptimize=ReleaseFast -- deferral-diff <db> <no-defer-db> <dir>...
//!       compare first raw-body verdicts under both compiled prefilters, including limits
//!   zig build prefilter -Doptimize=ReleaseFast -- prefix <db> <dir>...
//!       E3: candidates per MB with 3-byte prefixes (ClamAV's Aho-Corasick depth) against atoms
const std = @import("std");
const zav = @import("zav");
const prog = zav.match.prog;
const pf = zav.match.prefilter;
const bodyscan = zav.engine.bodyscan;
const vm = zav.match.verify_vm;

/// `--partition N`: type every file as target N (E2 measures the PE partition over all of B1).
var force_partition: ?u8 = null;
/// `planted --record N`: only logical signature record N.
var planted_record: ?usize = null;
/// `worst --max-ms X`: exit 1 when an input takes longer than X ms per MB (the E4 pass line).
var worst_max_ms: f64 = std.math.inf(f64);
/// `--verify-per-kib N`: the verify count budget per KiB (vm.Budget.verify_per_kib) in `worst`.
var verify_per_kib: u64 = (vm.Budget{}).verify_per_kib;
/// `--rounds N`: best of N passes in `stages` (a loaded machine needs more than three), and of
/// N scans per file in `scan` (default 1 there).
var rounds: usize = 3;
var rounds_set = false;

const Corpus = struct {
    paths: std.ArrayList([]const u8) = .empty,
    bytes: u64 = 0,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) return usage();
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "compile")) return compileVariant(gpa, io, args[2..]);
    const database = try zav.db.reader.open(io, std.Io.Dir.cwd(), args[2], .{ .allow_unsigned = true });
    defer database.close();
    index_db = database;
    const index = try bodyscan.BodyIndex.load(database);
    if (std.mem.eql(u8, cmd, "deferral-diff")) {
        if (args.len < 5) return error.MissingDeferralInputs;
        return deferralDiff(gpa, arena, io, database, &index, args[3], args[4..]);
    }

    var dirs: std.ArrayList([]const u8) = .empty;
    var reference = false;
    var limit: usize = std.math.maxInt(usize);
    var i: usize = 3;
    force_partition = null;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--reference")) {
            reference = true;
        } else if (std.mem.eql(u8, args[i], "--rounds")) {
            i += 1;
            rounds = try std.fmt.parseInt(usize, args[i], 10);
            rounds_set = true;
        } else if (std.mem.eql(u8, args[i], "--verify-per-kib")) {
            i += 1;
            verify_per_kib = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--max-ms")) {
            i += 1;
            worst_max_ms = try std.fmt.parseFloat(f64, args[i]);
        } else if (std.mem.eql(u8, args[i], "--record")) {
            i += 1;
            planted_record = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--partition")) {
            i += 1;
            force_partition = try std.fmt.parseInt(u8, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--limit")) {
            i += 1;
            limit = try std.fmt.parseInt(usize, args[i], 10);
        } else try dirs.append(arena, args[i]);
    }
    var corpus: Corpus = .{};
    if (!std.mem.eql(u8, cmd, "show") and !std.mem.eql(u8, cmd, "rec") and !std.mem.eql(u8, cmd, "short") and !std.mem.eql(u8, cmd, "vmprog") and !std.mem.eql(u8, cmd, "planted") and !std.mem.eql(u8, cmd, "worst")) for (dirs.items) |d| try list(io, arena, d, &corpus, limit);

    if (std.mem.eql(u8, cmd, "census")) return census(database, index);
    if (std.mem.eql(u8, cmd, "short")) {
        if (dirs.items.len > 1) hot_key = @byteSwap(try std.fmt.parseInt(u16, dirs.items[1], 16));
        return shortAtoms(gpa, index, if (dirs.items.len > 0) try std.fmt.parseInt(u8, dirs.items[0], 10) else 1);
    }
    if (std.mem.eql(u8, cmd, "scan")) {
        if (!rounds_set) rounds = 1;
        return scan(gpa, io, index, corpus, if (reference) .reference else .auto);
    }
    if (std.mem.eql(u8, cmd, "stages")) return stages(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "diff")) return diff(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "prefix")) return prefix(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "top")) return top(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "grams")) return grams(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "kernel")) return kernelDiff(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "planted")) return planted(gpa, io, index, limit);
    if (std.mem.eql(u8, cmd, "worst")) return worst(gpa, io, index);
    if (std.mem.eql(u8, cmd, "vmprog")) {
        // vmprog <db> <prog> <file>: verify one program at every anchor occurrence, with one
        // memo for the whole file, and report steps and time.
        const k = try std.fmt.parseInt(usize, dirs.items[0], 10);
        const p = index.programs.?.get(k);
        const data = try std.Io.Dir.cwd().readFileAlloc(io, dirs.items[1], gpa, .limited(1 << 31));
        defer gpa.free(data);
        var budget: vm.Budget = .{ .per_file = 1 << 40, .per_verify = if (dirs.items.len > 2) try std.fmt.parseInt(u32, dirs.items[2], 10) else 4096 };
        var memo: vm.Memo = undefined;
        memo.prepare(p.header.part_count);
        const lit = p.pattern.bytes(p.pattern.ops[p.header.anchor_op]);
        var n: usize = 0;
        var hits: usize = 0;
        var exhausted: usize = 0;
        const t = now(io);
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, data, pos, lit)) |at| : (pos = at + 1) {
            if (at < p.header.anchor_delta) continue;
            n += 1;
            const w = vm.startWindow(p.offset(), .{ .size = data.len }).?;
            const before = budget.used;
            if (vm.verifyMemo(p, data, w, at - p.header.anchor_delta, &budget, &memo)) |m| {
                if (m != null) hits += 1;
            } else |_| exhausted += 1;
            if (n <= 5) std.debug.print("  candidate at {d}: {d} steps\n", .{ at, budget.used - before });
        }
        std.debug.print("{d} candidates, {d} matches, {d} exhausted, {d} steps, {d:.1} ms\n", .{ n, hits, exhausted, budget.used, @as(f64, @floatFromInt(nsSince(io, t))) / 1e6 });
        return;
    }
    if (std.mem.eql(u8, cmd, "rec")) {
        // rec <db> <record>: the programs of one logical signature.
        const rec = index.ldb.?.records[try std.fmt.parseInt(usize, dirs.items[0], 10)];
        var buf: [4096]u8 = undefined;
        for (rec.prog_first..rec.prog_first + rec.prog_count) |k| {
            const p = index.programs.?.get(k);
            var wr: std.Io.Writer = .fixed(&buf);
            zav.compile.hexsig.format(p.pattern, &wr) catch {};
            std.debug.print("prog {d} sub {d} t{d} flags {x} anchor op {d}: {s}\n", .{ k, p.header.subsig, p.header.target, p.header.flags, p.header.anchor_op, wr.buffered() });
        }
        return;
    }
    if (std.mem.eql(u8, cmd, "show")) {
        // show <db> <prog index>...: print programs.
        var buf: [4096]u8 = undefined;
        for (dirs.items) |a| {
            const k = try std.fmt.parseInt(usize, a, 10);
            const p = index.programs.?.get(k);
            var wr: std.Io.Writer = .fixed(&buf);
            zav.compile.hexsig.format(p.pattern, &wr) catch {};
            std.debug.print("prog {d}: {any}\n  {s}\n", .{ k, p.header, wr.buffered() });
        }
        return;
    }
    return usage();
}

/// compile <out.zavdb> <cvd>... [--prefix] [--no-defer] [--strides 8,4] [--gate-ns X]
/// [--penalty-scale X]: a database with atom selection varied, for E2 and E3 (prefix
/// selection; no deferral; other sampled strides; the gate cost; the stride penalties scaled).
fn compileVariant(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const tmp = try std.fmt.allocPrint(gpa, "{s}.spill", .{args[0]});
    defer gpa.free(tmp);
    try cwd.createDirPath(io, tmp);
    defer cwd.deleteTree(io, tmp) catch {};
    var spill_dir = try cwd.openDir(io, tmp, .{});
    defer spill_dir.close(io);
    var spill = zav.compile.spill.Spill.init(io, spill_dir);
    var c = zav.compile.compiler.Compiler.initOptions(gpa, .{ .spill = &spill });
    defer c.deinit();
    for (args[1..]) |a| if (std.mem.endsWith(u8, a, ".cvd")) try c.preloadIgnores(io, cwd, a, .{ .kind = .cvd, .allow_unverified = true });
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--prefix")) {
            c.atom_costs.prefix = true;
        } else if (std.mem.eql(u8, a, "--no-defer")) {
            c.atom_costs.no_defer = true;
        } else if (std.mem.eql(u8, a, "--max-chain")) {
            i += 1;
            c.crowd.max_chain = try std.fmt.parseInt(u32, args[i], 10);
            if (c.crowd.max_chain == 0) c.crowd.max_chain = std.math.maxInt(u32);
        } else if (std.mem.eql(u8, a, "--gate-ns")) {
            i += 1;
            c.atom_costs.gate_ns = try std.fmt.parseFloat(f64, args[i]);
        } else if (std.mem.eql(u8, a, "--strides")) {
            // --strides 8,4: the sampled strides windows may use (the previous design's tiers).
            i += 1;
            var picked: std.ArrayList(u8) = .empty;
            var it = std.mem.splitScalar(u8, args[i], ',');
            while (it.next()) |x| try picked.append(gpa, try std.fmt.parseInt(u8, x, 10));
            c.atom_costs.sampled = picked.items;
        } else if (std.mem.eql(u8, a, "--penalty-scale")) {
            i += 1;
            const k = try std.fmt.parseFloat(f64, args[i]);
            for (&c.atom_costs.stride_penalty) |*x| x.* *= k;
            c.atom_costs.q3_penalty *= k;
            c.atom_costs.q2_penalty *= k;
        }
    }
    for (args[1..]) |a| if (std.mem.endsWith(u8, a, ".cvd")) {
        _ = try c.addContainer(io, cwd, a, .{ .kind = .cvd, .allow_unverified = true });
    };
    try c.addBuiltin();
    const summary = try c.write(io, cwd, args[0], .{ .db_version = 1 });
    std.debug.print("{s}: {d} programs\n", .{ args[0], summary.programs });
    var buf: [1024]u8 = undefined;
    var w = std.debug.lockStderr(&buf).terminal().writer;
    defer std.debug.unlockStderr();
    try c.histogram.render(w);
    try w.flush();
}

fn usage() void {
    std.debug.print("usage: prefilter census|scan|stages|diff|prefix <db> [dir...] [--reference] [--limit N]\n", .{});
    std.debug.print("       prefilter deferral-diff <db> <no-defer-db> <dir>...\n", .{});
}

fn list(io: std.Io, arena: std.mem.Allocator, dir_path: []const u8, corpus: *Corpus, limit: usize) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |e| if (e.kind == .file) try names.append(arena, try arena.dupe(u8, e.name));
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    for (names.items[0..@min(names.items.len, limit)]) |n| {
        const p = try std.fs.path.join(arena, &.{ dir_path, n });
        const st = try std.Io.Dir.cwd().statFile(io, p, .{});
        corpus.bytes += st.size;
        try corpus.paths.append(arena, p);
    }
}

/// ClamAV target type from the first bytes (enough for benchmarks; the engine has the real
/// file-type pipeline).
fn targetOf(data: []const u8) u8 {
    if (force_partition) |p| return p;
    if (data.len >= 2 and data[0] == 'M' and data[1] == 'Z') return 1;
    if (data.len >= 4 and std.mem.eql(u8, data[0..4], "\x7fELF")) return 6;
    if (data.len >= 4) {
        const m = std.mem.readInt(u32, data[0..4], .little);
        if (m == 0xfeedface or m == 0xfeedfacf or m == 0xcafebabe or m == 0xbebafeca) return 9;
    }
    if (data.len >= 8 and std.mem.eql(u8, data[0..8], "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")) return 2;
    if (data.len >= 5 and std.mem.eql(u8, data[0..5], "%PDF-")) return 10;
    return 0;
}

fn now(io: std.Io) std.Io.Timestamp {
    return std.Io.Clock.awake.now(io);
}

fn nsSince(io: std.Io, t: std.Io.Timestamp) u64 {
    return @intCast(t.durationTo(now(io)).toNanoseconds());
}

const Worker = struct {
    scratch: []u8,
    fba: std.heap.FixedBufferAllocator,
    state: zav.match.logical.State,
    regex_scratch: zav.match.regex_pool.Scratch,
    scan: *bodyscan.Scratch,

    fn init(gpa: std.mem.Allocator, index: *const bodyscan.BodyIndex) !*Worker {
        const w = try gpa.create(Worker);
        errdefer gpa.destroy(w);
        w.scratch = try gpa.alloc(u8, 64 * 1024 * 1024);
        errdefer gpa.free(w.scratch);
        w.fba = .init(w.scratch);
        w.state = try .init(w.fba.allocator());
        w.scan = try w.fba.allocator().create(bodyscan.Scratch);
        if (index.regexes) |pool| {
            const mem = try w.fba.allocator().alignedAlloc(u8, .@"8", pool.scratchBytes(256));
            w.regex_scratch = try .initBuffer(mem, pool, 256);
            w.regex_scratch.setStepBudget(1 << 20);
            w.state.regex_scratch = &w.regex_scratch;
        }
        return w;
    }

    fn deinit(w: *Worker, gpa: std.mem.Allocator) void {
        gpa.free(w.scratch);
        gpa.destroy(w);
    }
};

fn scanOne(index: *const bodyscan.BodyIndex, w: *Worker, data: []const u8, mode: bodyscan.Mode, stats: ?*pf.Stats) !bodyscan.Verdict {
    return scanBody(index, w, data, .{ .info = .{ .size = data.len }, .target = targetOf(data) }, mode, stats);
}

fn scanBody(index: *const bodyscan.BodyIndex, w: *Worker, data: []const u8, file: bodyscan.File, mode: bodyscan.Mode, stats: ?*pf.Stats) !bodyscan.Verdict {
    w.state.reset();
    var budget: vm.Budget = .{};
    var tracker = zav.engine.limits.Tracker.init(.{});
    return bodyscan.scanBufferScratch(index, data, file, &budget, &tracker, &w.state, mode, stats, w.scan);
}

fn scan(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus, mode: bodyscan.Mode) !void {
    const w = try Worker.init(gpa, &index);
    var stats: pf.Stats = .{};
    var ns: u64 = 0;
    var infected: usize = 0;
    var limited: usize = 0;
    var slowest: struct { ns: u64 = 0, path: []const u8 = "", size: usize = 0 } = .{};
    var densest: struct { per_kib: f64 = 0, path: []const u8 = "", size: usize = 0 } = .{};
    var verifies_before: u64 = 0;
    var name_buf: [512]u8 = undefined;
    const names = try zav.engine.hashscan.HashIndex.load(index_db);
    // With --rounds N each file is scanned N times and its fastest scan counts (counters and
    // verdicts from the last).
    for (corpus.paths.items) |p| {
        const data = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31));
        defer gpa.free(data);
        var dt: u64 = std.math.maxInt(u64);
        var verdict: bodyscan.Verdict = undefined;
        for (0..rounds) |r| {
            const before = stats;
            const t = now(io);
            verdict = try scanOne(&index, w, data, mode, &stats);
            dt = @min(dt, nsSince(io, t));
            if (r + 1 < rounds) stats = before;
        }
        ns += dt;
        if (dt > slowest.ns) slowest = .{ .ns = dt, .path = p, .size = data.len };
        // Densest file by verifies and by verify steps per KiB (files of 4 KiB or more).
        if (data.len >= 4096) {
            const kib = @as(f64, @floatFromInt(data.len)) / 1024;
            const v = @as(f64, @floatFromInt(stats.verifies - verifies_before)) / kib;
            if (v > densest.per_kib) densest = .{ .per_kib = v, .path = p, .size = data.len };
        }
        verifies_before = stats.verifies;
        switch (verdict) {
            .clean => {},
            .infected => |d| {
                infected += 1;
                const name = if (names.meta) |m| m.name(d.sig, &name_buf) catch "?" else "?";
                std.debug.print("FOUND {s} {s}\n", .{ p, name });
            },
            .limited => |e| {
                limited += 1;
                std.debug.print("LIMITED {s} {t}\n", .{ p, e });
            },
        }
    }
    const mb = @as(f64, @floatFromInt(corpus.bytes)) / 1e6;
    const secs = @as(f64, @floatFromInt(ns)) / 1e9;
    std.debug.print("{d} files, {d:.1} MB, {d:.3} s, {d:.1} MB/s per core ({t}); {d} detected, {d} limited\n", .{ corpus.paths.items.len, mb, secs, mb / secs, mode, infected, limited });
    std.debug.print("per MB: {d:.1} candidates, {d:.1} probes, {d:.1} verifies, {d:.2} deferred programs searched\n", .{
        @as(f64, @floatFromInt(stats.candidates)) / mb,
        @as(f64, @floatFromInt(stats.probes)) / mb,
        @as(f64, @floatFromInt(stats.verifies)) / mb,
        @as(f64, @floatFromInt(stats.deferred)) / mb,
    });
    std.debug.print("deferred pass: {d} runs over {d} files, {d:.1} probes and {d:.1} verifies per MB\n", .{ stats.deferred_runs, corpus.paths.items.len, @as(f64, @floatFromInt(stats.deferred_probes)) / mb, @as(f64, @floatFromInt(stats.deferred_verifies)) / mb });
    for (stats.by_kind, [_][]const u8{ "stride 8", "stride 4", "stride 3", "stride 2", "stride 1", "3-gram", "2-gram" }) |k, name| {
        std.debug.print("  {s:<9} per MB: {d:>9.1} candidates {d:>9.1} probes {d:>8.1} verifies\n", .{ name, @as(f64, @floatFromInt(k.candidates)) / mb, @as(f64, @floatFromInt(k.probes)) / mb, @as(f64, @floatFromInt(k.verifies)) / mb });
    }
    std.debug.print("densest: {s} ({d} bytes) {d:.1} verifies per KiB\n", .{ densest.path, densest.size, densest.per_kib });
    std.debug.print("slowest: {s} ({d} bytes) {d:.2} ms\n", .{ slowest.path, slowest.size, @as(f64, @floatFromInt(slowest.ns)) / 1e6 });
}

var index_db: zav.db.reader.Database = undefined;

const CountSink = struct {
    n: u64 = 0,
    pub fn candidate(s: *CountSink, prog_index: u32, anchor_start: usize) bool {
        s.n +%= prog_index +% anchor_start;
        return true;
    }
};

fn stages(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus) !void {
    var datas: std.ArrayList([]u8) = .empty;
    defer {
        for (datas.items) |d| gpa.free(d);
        datas.deinit(gpa);
    }
    for (corpus.paths.items) |p| try datas.append(gpa, try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31)));
    var ring: [pf.ring_len]pf.Candidate = undefined;
    const mb = @as(f64, @floatFromInt(corpus.bytes)) / 1e6;
    // Keep every runnable variant's measurement; the dispatch winner alone cannot show
    // whether a portable binary improves with the CPU-specific objects.
    const Measurement = struct { best1: u64 = std.math.maxInt(u64), best12: u64 = std.math.maxInt(u64), cands: u64 = 0, stats: pf.Stats = .{} };
    var measurements: [8]Measurement = @splat(.{});
    var kbuf: [8]*const pf.Kernel = undefined;
    const kernels = pf.runnableKernels(&kbuf);
    for (kernels, measurements[0..kernels.len]) |kern, *m| {
        for (0..rounds) |_| {
            var t = now(io);
            m.cands = 0;
            for (datas.items) |d| {
                const part = index.partitionFor(targetOf(d)) orelse continue;
                var pos: usize = 0;
                while (pos < d.len) {
                    const n, const next = pf.stage1With(kern.run, part, d, pos, &ring);
                    m.cands += n;
                    pos = next;
                }
            }
            m.best1 = @min(m.best1, nsSince(io, t));
            t = now(io);
            const checksum = probeCorpus(&index, datas.items, kern, &ring, null);
            m.best12 = @min(m.best12, nsSince(io, t));
            std.mem.doNotOptimizeAway(checksum);
        }
        // Gather diagnostic counts separately so timed scans use the production path.
        _ = probeCorpus(&index, datas.items, kern, &ring, &m.stats);
    }
    var gate_pass: u64 = 0;
    var gate_pos: u64 = 0;
    for (datas.items) |d| {
        const part = index.partitionFor(targetOf(d)) orelse continue;
        if (part.gate.len == 0 or d.len < 2) continue;
        for (0..d.len - 1) |k| {
            const two = @as(u32, d[k]) | @as(u32, d[k + 1]) << 8;
            gate_pass += @intFromBool(part.gate[two] != 0);
        }
        gate_pos += d.len - 1;
    }
    // What a vector filter on one byte of the pair would pass: the gate's first and second bytes.
    var first_pass: u64 = 0;
    var second_pass: u64 = 0;
    var firsts: [256]bool = @splat(false);
    var seconds: [256]bool = @splat(false);
    for (datas.items) |d| {
        const part = index.partitionFor(targetOf(d)) orelse continue;
        if (part.gate.len == 0 or d.len < 2) continue;
        firsts = @splat(false);
        seconds = @splat(false);
        for (part.gate, 0..) |g, k| if (g != 0) {
            firsts[k & 0xff] = true;
            seconds[k >> 8] = true;
        };
        for (0..d.len - 1) |k| {
            first_pass += @intFromBool(firsts[d[k]]);
            second_pass += @intFromBool(seconds[d[k + 1]]);
        }
    }
    {
        // The gate keys that pass most often.
        const counts = try gpa.alloc(u64, 65536);
        defer gpa.free(counts);
        @memset(counts, 0);
        var gp: ?*const pf.Partition = null;
        for (datas.items) |d| {
            const part = index.partitionFor(targetOf(d)) orelse continue;
            gp = part;
            if (part.gate.len == 0 or d.len < 2) continue;
            for (0..d.len - 1) |k| {
                const two = @as(u32, d[k]) | @as(u32, d[k + 1]) << 8;
                if (part.gate[two] != 0) counts[two] += 1;
            }
        }
        for (0..12) |_| {
            const top_k = std.mem.indexOfMax(u64, counts);
            if (counts[top_k] == 0) break;
            std.debug.print("  gate key {x:0>2}{x:0>2} flags {d}: {d:.3}% of positions\n", .{ top_k & 0xff, top_k >> 8, gp.?.gate[top_k], 100 * @as(f64, @floatFromInt(counts[top_k])) / @as(f64, @floatFromInt(@max(gate_pos, 1))) });
            counts[top_k] = 0;
        }
    }
    var nf: usize = 0;
    var ns: usize = 0;
    for (firsts, seconds) |f, sec| {
        nf += @intFromBool(f);
        ns += @intFromBool(sec);
    }
    std.debug.print("gate: {d} first bytes pass {d:.1}%, {d} second bytes pass {d:.1}% (last file's partition)\n", .{ nf, 100 * @as(f64, @floatFromInt(first_pass)) / @as(f64, @floatFromInt(@max(gate_pos, 1))), ns, 100 * @as(f64, @floatFromInt(second_pass)) / @as(f64, @floatFromInt(@max(gate_pos, 1))) });
    std.debug.print("{d} files, {d:.1} MB, stride-one gate passes {d:.2}% of positions\n", .{ datas.items.len, mb, 100 * @as(f64, @floatFromInt(gate_pass)) / @as(f64, @floatFromInt(@max(gate_pos, 1))) });
    std.debug.print("best of {d} rounds; active kernel {s}\n", .{ rounds, pf.activeKernel().name });
    for (kernels, measurements[0..kernels.len]) |kern, m| {
        std.debug.print("stage 1 [{s}]:    {d:.1} MB/s per core, {d:.1} candidates per MB\n", .{ kern.name, mb / (@as(f64, @floatFromInt(m.best1)) / 1e9), @as(f64, @floatFromInt(m.cands)) / mb });
        std.debug.print("stages 1+2 [{s}]: {d:.1} MB/s per core, {d:.1} probes and {d:.1} verifies per MB\n", .{ kern.name, mb / (@as(f64, @floatFromInt(m.best12)) / 1e9), @as(f64, @floatFromInt(m.stats.probes)) / mb, @as(f64, @floatFromInt(m.stats.verifies)) / mb });
    }
}

fn probeCorpus(index: *const bodyscan.BodyIndex, datas: []const []u8, kern: *const pf.Kernel, ring: *[pf.ring_len]pf.Candidate, stats: ?*pf.Stats) u64 {
    var sink: CountSink = .{};
    for (datas) |data| {
        const part = index.partitionFor(targetOf(data)) orelse continue;
        var pos: usize = 0;
        while (pos < data.len) {
            const n, const next = pf.stage1With(kern.run, part, data, pos, ring);
            pos = next;
            if (stats) |s| s.candidates += n;
            _ = pf.stage2(part, data, ring[0..n], &sink, stats);
        }
    }
    return sink.n;
}

fn diff(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus) !void {
    const w = try Worker.init(gpa, &index);
    var mismatches: usize = 0;
    for (corpus.paths.items) |p| {
        const data = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31));
        defer gpa.free(data);
        const a = try scanOne(&index, w, data, .auto, null);
        const b = try scanOne(&index, w, data, .reference, null);
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) {
            mismatches += 1;
            std.debug.print("MISMATCH {s}: prefilter {any}, reference {any}\n", .{ p, a, b });
        }
    }
    std.debug.print("{d} files compared, {d} mismatches\n", .{ corpus.paths.items.len, mismatches });
}

fn deferralDiff(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, database: zav.db.reader.Database, index: *const bodyscan.BodyIndex, baseline_path: []const u8, dirs: []const []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const baseline_db = try zav.db.reader.open(io, cwd, baseline_path, .{ .allow_unsigned = true });
    defer baseline_db.close();
    const baseline = try bodyscan.BodyIndex.load(baseline_db);
    try checkDeferralPair(database, index, baseline_db, &baseline);

    var corpus: Corpus = .{};
    for (dirs) |dir| try list(io, arena, dir, &corpus, std.math.maxInt(usize));
    if (corpus.paths.items.len == 0) return error.EmptyCorpus;

    const classifier = try zav.engine.layerscan.Scanner.init(gpa, io);
    defer classifier.deinit();
    const enabled = try Worker.init(gpa, index);
    defer enabled.deinit(gpa);
    const disabled = try Worker.init(gpa, &baseline);
    defer disabled.deinit(gpa);
    var clean: usize = 0;
    var detected: usize = 0;
    var different: usize = 0;
    var limited: usize = 0;
    for (corpus.paths.items) |path| {
        const data = try cwd.readFileAlloc(io, path, gpa, .limited(1 << 31));
        defer gpa.free(data);
        const file = classifier.classify(data).file;
        const a = try scanBody(index, enabled, data, file, .auto, null);
        const b = try scanBody(&baseline, disabled, data, file, .auto, null);
        if (a == .limited or b == .limited) {
            limited += 1;
            std.debug.print("INCONCLUSIVE {s}: deferred {any}, non-deferred {any}\n", .{ std.fs.path.basename(path), a, b });
        } else if (a == .clean and b == .clean) {
            clean += 1;
        } else if (a == .infected and b == .infected and a.infected.sig == b.infected.sig) {
            detected += 1;
        } else {
            different += 1;
            std.debug.print("MISMATCH {s}: deferred {any}, non-deferred {any}\n", .{ std.fs.path.basename(path), a, b });
        }
    }
    std.debug.print("{d} files: {d} clean, {d} same first detection, {d} mismatched, {d} inconclusive\n", .{
        corpus.paths.items.len, clean, detected, different, limited,
    });
    if (different != 0 or limited != 0) return error.DeferralComparisonFailed;
}

/// Require matching signatures and allow differences in the atom plans and their reports.
fn checkDeferralPair(a: zav.db.reader.Database, enabled: *const bodyscan.BodyIndex, b: zav.db.reader.Database, disabled: *const bodyscan.BodyIndex) !void {
    if (!std.meta.eql(a.header().sources, b.header().sources)) return error.DifferentSignatureSources;
    for ([_]zav.db.reader.Database{ a, b }, [_]zav.db.reader.Database{ b, a }) |left, right| {
        for (left.sections()) |section| {
            switch (section.kind) {
                .prefilter, .atom_table, .coverage_report => continue,
                .subsig_prog => if (section.variant == 0) continue,
                else => {},
            }
            const x = left.section(section.kind, section.variant).?;
            const y = right.section(section.kind, section.variant) orelse return error.DifferentSignatureTables;
            if (!std.mem.eql(u8, x, y)) return error.DifferentSignatureTables;
        }
    }
    if (enabled.partitionFor(0) == null or disabled.partitionFor(0) == null) return error.MissingPrefilter;
    const x = enabled.programs orelse return error.MissingPrograms;
    const y = disabled.programs orelse return error.MissingPrograms;
    if (x.count() != y.count()) return error.DifferentPrograms;
    var deferred: usize = 0;
    for (0..x.count()) |i| {
        const p = x.get(i);
        const q = y.get(i);
        if (q.header.flags & prog.flag_deferred != 0) return error.BaselineHasDeferredPrograms;
        deferred += @intFromBool(p.header.flags & prog.flag_deferred != 0);
        var header = p.header;
        header.flags &= ~prog.flag_deferred;
        header.anchor_op = q.header.anchor_op;
        header.anchor_part = q.header.anchor_part;
        header.anchor_delta = q.header.anchor_delta;
        if (!std.meta.eql(header, q.header) or
            !std.mem.eql(u8, std.mem.sliceAsBytes(p.pattern.ops), std.mem.sliceAsBytes(q.pattern.ops)) or
            !std.mem.eql(u8, p.pattern.data, q.pattern.data)) return error.DifferentPrograms;
    }
    if (deferred == 0) return error.NoDeferredPrograms;
    std.debug.print("{d} equivalent verify programs, {d} deferred only in the first database\n", .{ x.count(), deferred });
}

fn prefix(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus) !void {
    // Every searched program (deferred ones too: prefix selection has no deferral) contributes
    // the first three bytes of its first literal, as ClamAV's Aho-Corasick depth-3 trie would.
    const progs = index.programs.?;
    const bitmap = try gpa.alloc(u64, (1 << 24) / 64);
    defer gpa.free(bitmap);
    @memset(bitmap, 0);
    var counted: usize = 0;
    for (0..progs.count()) |i| {
        const p = progs.get(i);
        if (p.header.off_kind != .any) continue;
        for (p.pattern.ops) |o| {
            if (o.code != .lit or o.len < 3) continue;
            const b = p.pattern.bytes(o);
            const g = @as(u32, b[0]) | @as(u32, b[1]) << 8 | @as(u32, b[2]) << 16;
            bitmap[g >> 6] |= @as(u64, 1) << @intCast(g & 63);
            counted += 1;
            break;
        }
    }
    var hits: u64 = 0;
    for (corpus.paths.items) |p| {
        const data = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31));
        defer gpa.free(data);
        if (data.len < 3) continue;
        for (0..data.len - 2) |k| {
            const g = @as(u32, data[k]) | @as(u32, data[k + 1]) << 8 | @as(u32, data[k + 2]) << 16;
            hits += (bitmap[g >> 6] >> @intCast(g & 63)) & 1;
        }
    }
    const mb = @as(f64, @floatFromInt(corpus.bytes)) / 1e6;
    std.debug.print("{d} programs with a 3-byte literal prefix; {d:.1} prefix candidates per MB\n", .{ counted, @as(f64, @floatFromInt(hits)) / mb });
}

/// The programs whose atoms reach the verifier most often, and the programs most often run
/// by the whole-buffer scanner (no atom, or deferred and not batched).
fn top(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus) !void {
    const progs = index.programs.?;
    const verifies = try gpa.alloc(u32, progs.count());
    defer gpa.free(verifies);
    @memset(verifies, 0);
    const scans = try gpa.alloc(u32, progs.count());
    defer gpa.free(scans);
    @memset(scans, 0);
    const w = try Worker.init(gpa, &index);
    const exhausted = try gpa.alloc(u32, progs.count());
    defer gpa.free(exhausted);
    @memset(exhausted, 0);
    var stats: pf.Stats = .{ .per_prog = verifies, .per_prog_scans = scans, .per_prog_exhausted = exhausted };
    for (corpus.paths.items) |p| {
        const data = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31));
        defer gpa.free(data);
        _ = try scanOne(&index, w, data, .auto, &stats);
    }
    std.debug.print("{d} verifies, {d} whole-buffer scans\n", .{ stats.verifies, stats.scans });
    for ([_][]const u32{ verifies, scans, exhausted }, 0..) |counts, which| {
        const order = try gpa.alloc(u32, progs.count());
        defer gpa.free(order);
        for (order, 0..) |*o, k| o.* = @intCast(k);
        std.mem.sortUnstable(u32, order, counts, struct {
            fn lt(c: []const u32, a: u32, b: u32) bool {
                return c[a] > c[b];
            }
        }.lt);
        std.debug.print("{s}\n", .{([_][]const u8{ "most verified atoms", "most scanned programs", "verify budget exhausted" })[which]});
        var buf: [160]u8 = undefined;
        for (order[0..25]) |k| {
            const n = counts[k];
            if (n == 0) break;
            const p = progs.get(k);
            var wr: std.Io.Writer = .fixed(&buf);
            zav.compile.hexsig.format(p.pattern, &wr) catch {};
            const deferred = p.header.flags & prog.flag_deferred != 0;
            std.debug.print("  {d:>7}  prog {d} sig {d}.{d} t={d}{s}: {s}\n", .{ n, k, p.header.sig, p.header.subsig, p.header.target, if (deferred) " deferred" else "", wr.buffered() });
        }
    }
}

/// The grams at stage-one candidates most often, per filter kind.
fn grams(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus) !void {
    var counts: std.AutoHashMapUnmanaged(u64, u32) = .empty;
    defer counts.deinit(gpa);
    var ring: [pf.ring_len]pf.Candidate = undefined;
    for (corpus.paths.items) |p| {
        const d = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31));
        defer gpa.free(d);
        const part = index.partitionFor(targetOf(d)) orelse continue;
        var pos: usize = 0;
        while (pos < d.len) {
            const n, const next = pf.stage1(part, d, pos, &ring);
            pos = next;
            for (ring[0..n]) |c| {
                if (c.pos + 4 > d.len) continue;
                const f = part.filters[c.filter];
                const key = @as(u64, pf.load4(d, c.pos)) | @as(u64, f.stride) << 32 | @as(u64, f.q) << 40;
                const e = try counts.getOrPut(gpa, key);
                if (!e.found_existing) e.value_ptr.* = 0;
                e.value_ptr.* += 1;
            }
        }
    }
    const Pair = struct { k: u64, n: u32 };
    var pairs: std.ArrayList(Pair) = .empty;
    defer pairs.deinit(gpa);
    var it = counts.iterator();
    while (it.next()) |e| try pairs.append(gpa, .{ .k = e.key_ptr.*, .n = e.value_ptr.* });
    std.mem.sortUnstable(Pair, pairs.items, {}, struct {
        fn lt(_: void, a: Pair, b: Pair) bool {
            return a.n > b.n;
        }
    }.lt);
    for (pairs.items[0..@min(40, pairs.items.len)]) |x| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, @truncate(x.k), .little);
        for (&b) |*c| if (c.* < 0x20 or c.* > 0x7e) {
            c.* = '.';
        };
        std.debug.print("  {d:>8}  stride {d} q {d}  {x:0>8} '{s}'\n", .{ x.n, (x.k >> 32) & 0xff, x.k >> 40, @as(u32, @truncate(x.k)), &b });
    }
}

/// The stage-one kernel against the scalar reference, file by file, plus as much random data.
fn kernelDiff(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus) !void {
    var ring: [pf.ring_len]pf.Candidate = undefined;
    var want: std.ArrayList(pf.Candidate) = .empty;
    defer want.deinit(gpa);
    var got: std.ArrayList(pf.Candidate) = .empty;
    defer got.deinit(gpa);
    var bytes: u64 = 0;
    var cands: u64 = 0;
    var prng = std.Random.DefaultPrng.init(1);
    const lt = struct {
        fn less(_: void, a: pf.Candidate, b: pf.Candidate) bool {
            return @as(u64, @bitCast(a)) < @as(u64, @bitCast(b));
        }
    }.less;
    for (0..2 * corpus.paths.items.len) |k| {
        const random_round = k >= corpus.paths.items.len;
        const p = corpus.paths.items[k % corpus.paths.items.len];
        const d = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31));
        defer gpa.free(d);
        if (random_round) prng.random().bytes(d);
        const part = index.partitionFor(targetOf(d)) orelse continue;
        want.clearRetainingCapacity();
        try pf.stage1Reference(part, d, &want, gpa);
        std.mem.sort(pf.Candidate, want.items, {}, lt);
        // Every CPU variant of the kernel this machine can run.
        var kbuf: [8]*const pf.Kernel = undefined;
        for (pf.runnableKernels(&kbuf)) |kern| {
            got.clearRetainingCapacity();
            var pos: usize = 0;
            while (pos < d.len) {
                const n, const next = pf.stage1With(kern.run, part, d, pos, &ring);
                try got.appendSlice(gpa, ring[0..n]);
                pos = next;
            }
            std.mem.sort(pf.Candidate, got.items, {}, lt);
            if (!std.mem.eql(u64, @ptrCast(want.items), @ptrCast(got.items))) {
                std.debug.print("MISMATCH {s}{s} ({s}): kernel {d}, reference {d}\n", .{ p, if (random_round) " (random)" else "", kern.name, got.items.len, want.items.len });
                var x: usize = 0;
                var y: usize = 0;
                while (x < got.items.len or y < want.items.len) {
                    const g: u64 = if (x < got.items.len) @bitCast(got.items[x]) else std.math.maxInt(u64);
                    const h: u64 = if (y < want.items.len) @bitCast(want.items[y]) else std.math.maxInt(u64);
                    if (g == h) {
                        x += 1;
                        y += 1;
                    } else if (g < h) {
                        const c = got.items[x];
                        std.debug.print("  kernel only: pos {d} filter {d} (stride {d} q {d}) len {d}\n", .{ c.pos, c.filter, part.filters[c.filter].stride, part.filters[c.filter].q, d.len });
                        x += 1;
                    } else {
                        const c = want.items[y];
                        std.debug.print("  reference only: pos {d} filter {d} (stride {d} q {d}) len {d}\n", .{ c.pos, c.filter, part.filters[c.filter].stride, part.filters[c.filter].q, d.len });
                        y += 1;
                    }
                }
                return error.KernelMismatch;
            }
        }
        bytes += d.len;
        cands += got.items.len;
    }
    var kbuf: [8]*const pf.Kernel = undefined;
    std.debug.print("kernel = reference for variants", .{});
    for (pf.runnableKernels(&kbuf)) |kern| std.debug.print(" {s}", .{kern.name});
    std.debug.print(" on {d} files and as many random buffers: {d:.1} MB, {d} candidates\n", .{ corpus.paths.items.len, @as(f64, @floatFromInt(bytes)) / 1e6, cands });
}

/// Logical signatures planted one per file, prefiltered (with deferral) against reference
/// verdicts: each hex subsig's first variant is synthesised (shortest gaps, first
/// alternatives) and the subsigs are concatenated with filler between them.
fn planted(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, limit: usize) !void {
    const progs = index.programs.?;
    const table = index.ldb.?;
    const w = try Worker.init(gpa, &index);
    var prng = std.Random.DefaultPrng.init(42);
    const r = prng.random();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    var tested: usize = 0;
    var detected_both: usize = 0;
    var deferred_rules: usize = 0;
    var inconclusive: usize = 0;
    var detected_prefilter_only_limited: usize = 0;
    var mismatches: usize = 0;
    var other_first: usize = 0;
    const n = @min(limit, table.records.len);
    const step = @max(1, table.records.len / n);
    var rec_i: usize = planted_record orelse 0;
    while (rec_i < table.records.len and tested < n) : (rec_i += step) {
        if (planted_record != null and tested > 0) break;
        const rec = table.records[rec_i];
        if (rec.prog_count == 0) continue;
        buf.clearRetainingCapacity();
        for (0..64) |_| try buf.append(gpa, ' ');
        var last_subsig: i32 = -1;
        var any_deferred = false;
        var target: u8 = 0;
        var pinned = false;
        for (rec.prog_first..rec.prog_first + rec.prog_count) |i| {
            const p = progs.get(i);
            if (@as(i32, p.header.subsig) == last_subsig) continue;
            last_subsig = p.header.subsig;
            target = p.header.target;
            if (p.header.off_kind != .any) pinned = true;
            any_deferred = any_deferred or p.header.flags & prog.flag_deferred != 0;
            try sample(gpa, &buf, p, r);
            for (0..16) |_| try buf.append(gpa, ' ');
        }
        if (pinned) continue;
        tested += 1;
        if (any_deferred) deferred_rules += 1;
        w.state.reset();
        var budget: vm.Budget = .{};
        var tracker = zav.engine.limits.Tracker.init(.{});
        const file: bodyscan.File = .{ .info = .{ .size = buf.items.len }, .target = target };
        const a = try bodyscan.scanBufferScratch(&index, buf.items, file, &budget, &tracker, &w.state, .auto, null, w.scan);
        w.state.reset();
        budget = .{};
        const b = try bodyscan.scanBufferScratch(&index, buf.items, file, &budget, &tracker, &w.state, .reference, null, w.scan);
        // The reference path searches every program, so its logical state can overflow
        // where the prefiltered one does not: such a file decides nothing.
        if (b == .limited) {
            inconclusive += 1;
            if (a == .infected) detected_prefilter_only_limited += 1;
            continue;
        }
        // Both detecting, but another signature first: a planted file can satisfy several
        // signatures of one family, and the two paths find matches in a different order.
        if (a == .infected and b == .infected and a.infected.sig != b.infected.sig) {
            other_first += 1;
            continue;
        }
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) {
            std.debug.print("MISMATCH record {d}: prefiltered {any}, reference {any}\n", .{ rec_i, a, b });
            // The file, for `top` and `vmprog`.
            var name_buf: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "planted-{d}.bin", .{rec_i});
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = name, .data = buf.items });
            mismatches += 1;
            continue;
        }
        if (a == .infected) detected_both += 1;
    }
    std.debug.print("{d} logical signatures planted ({d} with deferred subsigs): {d} mismatches, {d} detected by both ({d} reporting another signature of the file first), {d} where the reference ran out of logical state ({d} of them detected by the prefiltered path)\n", .{ tested, deferred_rules, mismatches, detected_both + other_first, other_first, inconclusive, detected_prefilter_only_limited });
    if (mismatches > 0) return error.Mismatch;
}

/// E4: worst-case inputs built from the database itself (so they are never committed; this is
/// their generator), 1 MiB each, scanned with the default budgets: time and verify steps per
/// MB, and the verdict (a budget that runs out must say so).
fn worst(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex) !void {
    const progs = index.programs.?;
    const w = try Worker.init(gpa, &index);
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    const size = 1 << 20;
    const Kind = enum { anchors, unbounded, subsigs, zeros_opcodes };
    var over: usize = 0;
    for (std.enums.values(Kind)) |kind| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        var i: usize = 0;
        var used: usize = 0;
        while (buf.items.len < size) : (i = (i + 7919) % progs.count()) {
            const p = progs.get(i);
            if (p.header.off_kind != .any or p.header.anchor_op == prog.no_anchor) continue;
            const ldb = p.header.flags & prog.flag_ldb != 0;
            switch (kind) {
                // Every program's anchor literal alone, back to back: the most candidates
                // that all fail in the verifier.
                .anchors => {
                    if (p.header.target > 1) continue;
                    const lit = p.pattern.bytes(p.pattern.ops[p.header.anchor_op]);
                    if (lit.len < 5) continue;
                    // The last byte changed: the atom still fires, the verifier fails.
                    try buf.appendSlice(gpa, lit[0 .. lit.len - 1]);
                    try buf.append(gpa, lit[lit.len - 1] ^ 0x55);
                },
                // Programs with an unbounded gap: everything but their last part, repeated,
                // so each candidate searches to the end of the data.
                .unbounded => {
                    if (p.header.part_count < 2 or p.header.target > 1) continue;
                    var part: usize = 0;
                    var unbounded = false;
                    for (p.pattern.ops) |o| if (o.code == .part_end and o.b == zav.compile.ir.unbounded) {
                        unbounded = true;
                    };
                    if (!unbounded) continue;
                    // Every part but the last.
                    var last_end: usize = 0;
                    for (p.pattern.ops, 0..) |o, k| if (o.code == .part_end) {
                        last_end = k;
                        part += 1;
                    };
                    const cut: prog.Program = .{ .header = p.header, .pattern = .{ .ops = p.pattern.ops[0..last_end], .data = p.pattern.data } };
                    try sample(gpa, &buf, cut, r);
                },
                // One subsig of many logical signatures, complete: every one touches state.
                .subsigs => {
                    if (!ldb or p.header.flags & prog.flag_deferred != 0 or p.header.target > 1) continue;
                    try sample(gpa, &buf, p, r);
                    // The last byte changed, so the subsig is verified and fails at its end.
                    buf.items[buf.items.len - 1] ^= 0x55;
                },
                // Zero padding and the short opcodes the tier-D body signatures start with.
                .zeros_opcodes => {
                    for (0..64) |_| try buf.appendSlice(gpa, &[_]u8{ 0, 0, 0, 0, 0xe8, 0x01, 0, 0, 0, 0x86, 0x01, 0x66, 0x88, 0x01, 0xff, 0xe9, 0x68, 0, 0, 0, 0, 0xff, 0x25 });
                    used += 1;
                    if (used > 1000) break;
                },
            }
        }
        const data = buf.items[0..@min(buf.items.len, size)];
        // Break every whole match the pieces happen to make, so the scan runs to the end:
        // overwrite each detection's bytes with noise until the file is clean.
        var broken: usize = 0;
        while (broken < 2000) : (broken += 1) {
            w.state.reset();
            var budget: vm.Budget = .{ .verify_per_kib = verify_per_kib };
            var tracker = zav.engine.limits.Tracker.init(.{});
            const v = try bodyscan.scanBufferScratch(&index, data, .{ .info = .{ .size = data.len }, .target = 1 }, &budget, &tracker, &w.state, .auto, null, w.scan);
            if (v != .infected) break;
            const d = v.infected;
            const lo = d.start -| 4;
            const hi = @min(data.len, @max(d.end, d.start + 1) + 4);
            r.bytes(data[lo..hi]);
        }
        var best: u64 = std.math.maxInt(u64);
        var steps: u64 = 0;
        var verdict: bodyscan.Verdict = .clean;
        var stats: pf.Stats = .{};
        for (0..3) |_| {
            w.state.reset();
            var budget: vm.Budget = .{ .verify_per_kib = verify_per_kib };
            var tracker = zav.engine.limits.Tracker.init(.{});
            stats = .{};
            const t = now(io);
            verdict = try bodyscan.scanBufferScratch(&index, data, .{ .info = .{ .size = data.len }, .target = 1 }, &budget, &tracker, &w.state, .auto, &stats, w.scan);
            best = @min(best, nsSince(io, t));
            steps = budget.used;
        }
        const mb = @as(f64, @floatFromInt(data.len)) / 1e6;
        if (verdict == .infected) {
            const names = try zav.engine.hashscan.HashIndex.load(index_db);
            var nb: [256]u8 = undefined;
            std.debug.print("  ({s} at {d})\n", .{ names.meta.?.name(verdict.infected.sig, &nb) catch "?", verdict.infected.start });
        }
        std.debug.print("  ({d} matches broken)\n", .{broken});
        const ms_per_mb = @as(f64, @floatFromInt(best)) / 1e6 / mb;
        var what_buf: [64]u8 = undefined;
        const what = switch (verdict) {
            .limited => |e| std.fmt.bufPrint(&what_buf, "limited ({t})", .{e}) catch "limited",
            else => @tagName(std.meta.activeTag(verdict)),
        };
        std.debug.print("{t:<14} {d:>7.2} ms/MB  {d:>9.0} steps/MB  {d:>8.0} verifies/MB  {d:>8.0} candidates/MB  {s}\n", .{
            kind,                                           ms_per_mb,
            @as(f64, @floatFromInt(steps)) / mb,            @as(f64, @floatFromInt(stats.verifies)) / mb,
            @as(f64, @floatFromInt(stats.candidates)) / mb, what,
        });
        if (ms_per_mb > worst_max_ms) over += 1;
    }
    if (over > 0) {
        std.debug.print("{d} inputs over the pass line of {d} ms/MB\n", .{ over, worst_max_ms });
        std.process.exit(1);
    }
}

fn sample(gpa: std.mem.Allocator, out: *std.ArrayList(u8), p: prog.Program, r: std.Random) !void {
    for (p.pattern.ops) |o| switch (o.code) {
        .lit => try out.appendSlice(gpa, p.pattern.bytes(o)),
        .masked => for (p.pattern.bytes(o), p.pattern.masks(o)) |v, m| {
            if (o.flags & zav.compile.ir.op_negate != 0) {
                try out.append(gpa, (v & m) ^ m ^ 0xff);
            } else try out.append(gpa, (r.int(u8) & ~m) | (v & m));
        },
        .gapf => for (0..o.a) |_| try out.append(gpa, 'x'),
        .alt => for (p.pattern.altOps(p.pattern.alternatives(o)[0])) |x| switch (x.code) {
            .lit, .masked => try out.appendSlice(gpa, p.pattern.bytes(x)),
            else => for (0..x.a) |_| try out.append(gpa, 'x'),
        },
        .nalt => for (0..o.b & 0xffff) |_| try out.append(gpa, 0xa5),
        .bound => try out.append(gpa, ' '),
        .part_end => for (0..o.a) |_| try out.append(gpa, 'x'),
        else => {},
    };
}

fn census(database: zav.db.reader.Database, index: bodyscan.BodyIndex) !void {
    if (database.section(.prefilter, 0)) |sec| std.debug.print("PREFILTER section: {d} bytes\n", .{sec.len});
    var buf: [4096]u8 = undefined;
    var w = std.debug.lockStderr(&buf).terminal().writer;
    defer std.debug.unlockStderr();
    try zav.match.prefilter.describe(&index.prefilters, w);
    // Anchored index groups by offset kind, and their list programs.
    for ([_]u8{ 0, 1 }) |part| if (index.anchored[part]) |ai| {
        var kinds: [8]u64 = @splat(0);
        var lists: [8]u64 = @splat(0);
        var keyed: [8]u64 = @splat(0);
        for (ai.groups) |g| {
            const k = @min(7, @backingInt(g.off_kind));
            kinds[k] += 1;
            lists[k] += g.list_count;
            keyed[k] += g.keyed_count;
        }
        try w.print("  anchored {d}: groups by kind {any}, list programs {any}, keyed {any}\n", .{ part, kinds, lists, keyed });
    };
    // Chain lengths of the shared atom table: every candidate walks its key's whole chain.
    if (index.partitionFor(1)) |part| {
        var hist: [8]u64 = @splat(0);
        var longest: usize = 0;
        var in_long: u64 = 0;
        for (part.slots) |sl| {
            if (sl.first == pf.empty_slot) continue;
            var k = sl.first;
            while (part.entries[k].flags & pf.entry_last == 0) k += 1;
            const len = k - sl.first + 1;
            longest = @max(longest, len);
            hist[@min(7, std.math.log2_int(usize, len))] += 1;
            if (len >= 64) in_long += len;
            if (len >= 5000) {
                var wb: [200]u8 = undefined;
                var wr: std.Io.Writer = .fixed(&wb);
                const p0 = index.programs.?.get(part.entries[sl.first].prog);
                zav.compile.hexsig.format(p0.pattern, &wr) catch {};
                try w.print("  key {x:0>8}: {d} entries, stride {d}, e.g. {s}\n", .{ @byteSwap(sl.key), len, part.entries[sl.first].stride, wr.buffered() });
                var lens: [32]u32 = @splat(0);
                var parts_one: usize = 0;
                for (part.entries[sl.first..][0..len], 0..) |e, ei| {
                    const pp = index.programs.?.get(e.prog);
                    lens[@min(31, pp.pattern.ops[pp.header.anchor_op].len)] += 1;
                    if (pp.header.part_count == 1 and pp.pattern.ops.len <= 2) parts_one += 1;
                    if (ei % 20000 == 7) {
                        var wb2: [200]u8 = undefined;
                        var wr2: std.Io.Writer = .fixed(&wb2);
                        zav.compile.hexsig.format(pp.pattern, &wr2) catch {};
                        try w.print("    {s} (sig {d}.{d} flags {x})\n", .{ wr2.buffered(), pp.header.sig, pp.header.subsig, pp.header.flags });
                    }
                }
                try w.print("    anchor literal lengths {any}; single-literal programs {d}\n", .{ lens, parts_one });
            }
        }
        try w.print("  chains: longest {d}; by length 1, 2-3, 4-7, ..., 128+: {any}; {d} entries in chains of 64 or more\n", .{ longest, hist, in_long });
    }
    try w.flush();
}

/// short <db> [target]: the stride-one atoms of one partition (its own target and type 0), by
/// gram length and anchor literal length, with sample patterns.
var hot_key: ?u16 = null;

fn shortAtoms(gpa: std.mem.Allocator, index: bodyscan.BodyIndex, target: u8) !void {
    const progs = index.programs.?;
    const part = index.partitionFor(target).?;
    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer seen.deinit(gpa);
    var hist: [5][17]u32 = @splat(@splat(0));
    var buf: [200]u8 = undefined;
    var shown: usize = 0;
    // Each entry's key, from the slots.
    const keys = try gpa.alloc(u32, part.entries.len);
    defer gpa.free(keys);
    for (part.slots) |sl| {
        if (sl.first == pf.empty_slot) continue;
        var k = sl.first;
        while (true) : (k += 1) {
            keys[k] = sl.key;
            if (part.entries[k].flags & pf.entry_last != 0) break;
        }
    }
    for (part.entries) |*ep| {
        const e = ep.*;
        if (e.stride != 1) continue;
        const t = e.flags >> pf.entry_target_shift;
        if (t != 0 and t != target) continue;
        if ((try seen.getOrPut(gpa, e.prog)).found_existing) continue;
        const p = progs.get(e.prog);
        const lit_len = p.pattern.ops[p.header.anchor_op].len;
        hist[e.q][@min(lit_len, 16)] += 1;
        const key_hot = if (hot_key) |hk| @as(u16, @truncate(keys[(@intFromPtr(ep) - @intFromPtr(part.entries.ptr)) / @sizeOf(pf.Entry)])) == hk else false;
        if (key_hot or (hot_key == null and shown < 400 and (e.prog % 7 == 0))) {
            shown += 1;
            var wr: std.Io.Writer = .fixed(&buf);
            zav.compile.hexsig.format(p.pattern, &wr) catch {};
            std.debug.print("q{d} lit{d} t{d} {s}\n", .{ e.q, lit_len, t, wr.buffered() });
        }
    }
    for (2..5) |qq| {
        std.debug.print("q={d}:", .{qq});
        for (hist[qq], 0..) |n, l| if (n > 0) std.debug.print(" lit{d}={d}", .{ l, n });
        std.debug.print("\n", .{});
    }
}
