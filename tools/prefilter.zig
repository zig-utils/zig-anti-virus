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
    if (!std.mem.eql(u8, cmd, "show") and !std.mem.eql(u8, cmd, "vmprog")) for (dirs.items) |d| try list(io, arena, d, &corpus, limit);

    if (std.mem.eql(u8, cmd, "census")) return census(database, index);
    if (std.mem.eql(u8, cmd, "scan")) return scan(gpa, io, index, corpus, if (reference) .reference else .auto);
    if (std.mem.eql(u8, cmd, "stages")) return stages(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "diff")) return diff(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "prefix")) return prefix(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "top")) return top(gpa, io, index, corpus);
    if (std.mem.eql(u8, cmd, "grams")) return grams(gpa, io, index, corpus);
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

fn census(database: zav.db.reader.Database, index: bodyscan.BodyIndex) void {
    if (database.section(.prefilter, 0)) |s| std.debug.print("PREFILTER section: {d} bytes\n", .{s.len});
    for (index.prefilters, 0..) |slot, p| {
        const part = slot orelse continue;
        var filter_bytes: usize = 0;
        for (part.filters[0..part.filter_count]) |f| filter_bytes += f.sbbf.blocks.len * 32;
        const table_size = part.slots.len * @sizeOf(pf.Slot) + part.entries.len * @sizeOf(pf.Entry);
        std.debug.print("partition {d}: filters {d} bytes, atom table {d} bytes ({d} slots, {d} entries), {d} programs without an atom\n", .{ p, filter_bytes, table_size, part.slots.len, part.entries.len, part.short.len });
        var buf: [200]u8 = undefined;
        if (p == 1) for (part.short) |k| {
            var wr: std.Io.Writer = .fixed(&buf);
            zav.compile.hexsig.format(index.programs.?.get(k).pattern, &wr) catch {};
            std.debug.print("  no atom: prog {d} {s}\n", .{ k, wr.buffered() });
        };
        for (part.filters[0..part.filter_count]) |f| {
            std.debug.print("  stride {d} q {d}: {d} atoms, {d} grams, {d} blocks ({d} KiB), {d:.2} bits/gram, expected FPR {d:.4}%\n", .{
                f.stride,                                                                                    f.q,
                f.atoms,                                                                                     f.sbbf.num_keys,
                f.sbbf.blocks.len,                                                                           f.sbbf.blocks.len * 32 / 1024,
                @as(f64, @floatFromInt(f.sbbf.blocks.len * 256)) / @as(f64, @floatFromInt(f.sbbf.num_keys)), f.sbbf.expectedFalsePositiveRate() * 100,
            });
        }
    }
}
