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
//!   zig build prefilter -Doptimize=ReleaseFast -- prefix <db> <dir>...
//!       E3: candidates per MB with 3-byte prefixes (ClamAV's Aho-Corasick depth) against atoms
const std = @import("std");
const zav = @import("zav");
const prog = zav.match.prog;
const pf = zav.match.prefilter;
const bodyscan = zav.engine.bodyscan;
const vm = zav.match.verify_vm;

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

    var dirs: std.ArrayList([]const u8) = .empty;
    var reference = false;
    var limit: usize = std.math.maxInt(usize);
    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--reference")) {
            reference = true;
        } else if (std.mem.eql(u8, args[i], "--limit")) {
            i += 1;
            limit = try std.fmt.parseInt(usize, args[i], 10);
        } else try dirs.append(arena, args[i]);
    }
    var corpus: Corpus = .{};
    if (!std.mem.eql(u8, cmd, "show") and !std.mem.eql(u8, cmd, "vmprog") and !std.mem.eql(u8, cmd, "planted") and !std.mem.eql(u8, cmd, "worst")) for (dirs.items) |d| try list(io, arena, d, &corpus, limit);

    if (std.mem.eql(u8, cmd, "census")) return census(database, index);
    if (std.mem.eql(u8, cmd, "scan")) return scan(gpa, io, index, corpus, if (reference) .reference else .auto);
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

/// compile <out.zavdb> <cvd>... [--prefix] [--penalty-scale X]: a database with atom selection
/// varied, for E2 and E3 (prefix selection; the stride penalties scaled).
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
}

fn usage() void {
    std.debug.print("usage: prefilter census|scan|stages|diff|prefix <db> [dir...] [--reference] [--limit N]\n", .{});
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
    regex_scratch: zav.regex.Scratch,
    scan: *bodyscan.Scratch,

    fn init(gpa: std.mem.Allocator, index: *const bodyscan.BodyIndex) !*Worker {
        const w = try gpa.create(Worker);
        w.scratch = try gpa.alloc(u8, 64 * 1024 * 1024);
        w.fba = .init(w.scratch);
        w.state = try .init(w.fba.allocator());
        w.scan = try w.fba.allocator().create(bodyscan.Scratch);
        if (index.regexes) |pool| {
            const capacity = pool.capacity(256);
            const mem = try w.fba.allocator().alignedAlloc(u8, .@"8", zav.regex.Scratch.bytesNeeded(capacity));
            w.regex_scratch = try .initBuffer(mem, capacity);
            w.regex_scratch.step_budget = 1 << 20;
            w.state.regex_scratch = &w.regex_scratch;
        }
        return w;
    }
};

fn scanOne(index: *const bodyscan.BodyIndex, w: *Worker, data: []const u8, mode: bodyscan.Mode, stats: ?*pf.Stats) !bodyscan.Verdict {
    w.state.reset();
    var budget: vm.Budget = .{};
    var tracker = zav.engine.limits.Tracker.init(.{});
    return bodyscan.scanBufferScratch(index, data, .{ .info = .{ .size = data.len }, .target = targetOf(data) }, &budget, &tracker, &w.state, mode, stats, w.scan);
}

fn scan(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, corpus: Corpus, mode: bodyscan.Mode) !void {
    const w = try Worker.init(gpa, &index);
    var stats: pf.Stats = .{};
    var ns: u64 = 0;
    var infected: usize = 0;
    var limited: usize = 0;
    var slowest: struct { ns: u64 = 0, path: []const u8 = "", size: usize = 0 } = .{};
    var name_buf: [512]u8 = undefined;
    const names = try zav.engine.hashscan.HashIndex.load(index_db);
    for (corpus.paths.items) |p| {
        const data = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 31));
        defer gpa.free(data);
        const t = now(io);
        const verdict = try scanOne(&index, w, data, mode, &stats);
        const dt = nsSince(io, t);
        ns += dt;
        if (dt > slowest.ns) slowest = .{ .ns = dt, .path = p, .size = data.len };
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
    for (stats.by_kind, [_][]const u8{ "stride 8", "stride 4", "stride 1", "3-gram", "2-gram" }) |k, name| {
        std.debug.print("  {s:<9} per MB: {d:>9.1} candidates {d:>9.1} probes {d:>8.1} verifies\n", .{ name, @as(f64, @floatFromInt(k.candidates)) / mb, @as(f64, @floatFromInt(k.probes)) / mb, @as(f64, @floatFromInt(k.verifies)) / mb });
    }
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
    // Best of three passes each.
    var best1: u64 = std.math.maxInt(u64);
    var best12: u64 = std.math.maxInt(u64);
    var cands: u64 = 0;
    var stats: pf.Stats = .{};
    for (0..3) |round| {
        var t = now(io);
        cands = 0;
        for (datas.items) |d| {
            const part = index.partitionFor(targetOf(d)) orelse continue;
            var pos: usize = 0;
            while (pos < d.len) {
                const n, const next = pf.stage1(part, d, pos, &ring);
                cands += n;
                pos = next;
            }
        }
        best1 = @min(best1, nsSince(io, t));
        t = now(io);
        var sink: CountSink = .{};
        stats = .{};
        for (datas.items) |d| {
            const part = index.partitionFor(targetOf(d)) orelse continue;
            _ = pf.scan(part, d, &ring, &sink, &stats);
        }
        best12 = @min(best12, nsSince(io, t));
        std.mem.doNotOptimizeAway(sink.n);
        _ = round;
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
    std.debug.print("{d} files, {d:.1} MB, stride-one gate passes {d:.2}% of positions\n", .{ datas.items.len, mb, 100 * @as(f64, @floatFromInt(gate_pass)) / @as(f64, @floatFromInt(@max(gate_pos, 1))) });
    std.debug.print("stage 1:     {d:.1} MB/s per core, {d:.1} candidates per MB\n", .{ mb / (@as(f64, @floatFromInt(best1)) / 1e9), @as(f64, @floatFromInt(cands)) / mb });
    std.debug.print("stages 1+2:  {d:.1} MB/s per core, {d:.1} probes and {d:.1} verifies per MB\n", .{ mb / (@as(f64, @floatFromInt(best12)) / 1e9), @as(f64, @floatFromInt(stats.probes)) / mb, @as(f64, @floatFromInt(stats.verifies)) / mb });
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
        got.clearRetainingCapacity();
        try pf.stage1Reference(part, d, &want, gpa);
        var pos: usize = 0;
        while (pos < d.len) {
            const n, const next = pf.stage1(part, d, pos, &ring);
            try got.appendSlice(gpa, ring[0..n]);
            pos = next;
        }
        std.mem.sort(pf.Candidate, want.items, {}, lt);
        std.mem.sort(pf.Candidate, got.items, {}, lt);
        if (!std.mem.eql(u64, @ptrCast(want.items), @ptrCast(got.items))) {
            std.debug.print("MISMATCH {s}{s}: kernel {d}, reference {d}\n", .{ p, if (random_round) " (random)" else "", got.items.len, want.items.len });
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
        bytes += d.len;
        cands += got.items.len;
    }
    std.debug.print("kernel = reference on {d} files and as many random buffers: {d:.1} MB, {d} candidates\n", .{ corpus.paths.items.len, @as(f64, @floatFromInt(bytes)) / 1e6, cands });
}

/// Logical signatures planted one per file, prefiltered (with deferral) against reference
/// verdicts: each hex subsig's first variant is synthesised (shortest gaps, first
/// alternatives) and the subsigs are concatenated with filler between them.
fn planted(gpa: std.mem.Allocator, io: std.Io, index: bodyscan.BodyIndex, limit: usize) !void {
    _ = io;
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
    var rec_i: usize = 0;
    while (rec_i < table.records.len and tested < n) : (rec_i += step) {
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
            var budget: vm.Budget = .{};
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
            var budget: vm.Budget = .{};
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
        std.debug.print("{t:<14} {d:>7.2} ms/MB  {d:>9.0} steps/MB  {d:>8.0} verifies/MB  {d:>8.0} candidates/MB  {t}\n", .{
            kind,                                           @as(f64, @floatFromInt(best)) / 1e6 / mb,
            @as(f64, @floatFromInt(steps)) / mb,            @as(f64, @floatFromInt(stats.verifies)) / mb,
            @as(f64, @floatFromInt(stats.candidates)) / mb, std.meta.activeTag(verdict),
        });
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
    try w.flush();
}
