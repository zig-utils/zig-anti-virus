//! The body-signature stage over one in-memory view of a file. Programs pinned to an offset go
//! through the anchored index of the file's partition and of type 0. Every other program is
//! searched: with a prefilter in the database (PREFILTER/ATOM_TABLE, match/prefilter.zig) its
//! atoms are found by stage one and two and only the candidates reach the verify VM, programs
//! with no atom run through the verify VM's scanner, and deferred logical subsigs run through
//! it only for signatures the first pass touched (compile/atoms.zig). Without a prefilter, or
//! in `.reference` mode, every program of the file's target type (or type 0) runs through the
//! scanner: the reference path the prefiltered one is checked against. `.ndb` programs report
//! the first detection; logical subsig matches feed the sparse logical state, whose touched
//! signatures are evaluated at the end. No heap allocation: logical state lives in worker
//! scratch and the candidate ring on the stack.
const std = @import("std");
const db = @import("../db/root.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");
const anchored = @import("../match/anchored.zig");
const lt = @import("../match/ldb_table.zig");
const logical = @import("../match/logical.zig");
const regex_pool = @import("../match/regex_pool.zig");
const yara_cond = @import("../match/yara_cond.zig");
const prefilter = @import("../match/prefilter.zig");

/// Matches of one YARA regex string recorded per file before the count is reported as limited.
pub const max_regex_matches: u32 = 1024;
const limits_mod = @import("limits.zig");

pub const BodyIndex = struct {
    programs: ?prog.Programs = null,
    /// ANCHORED_INDEX per partition (target type).
    anchored: [15]?anchored.Index = @splat(null),
    ldb: ?lt.LdbTable = null,
    /// Regex programs (PCRE subsigs, .cdb filename regexes). Size each worker's zig-regex
    /// scratch with `regexes.capacity(..)` and hand it to its logical state.
    regexes: ?regex_pool.RegexPool = null,
    /// PREFILTER and ATOM_TABLE per partition; partition 0 serves targets without their own.
    prefilters: [prefilter.partitions]?prefilter.Partition = @splat(null),

    /// The prefilter a file of `target` is scanned with, or null for the reference path.
    pub fn partitionFor(index: *const BodyIndex, target: u8) ?*const prefilter.Partition {
        if (target < index.prefilters.len) if (index.prefilters[target]) |*p| return p;
        if (index.prefilters[0]) |*p| return p;
        return null;
    }

    pub fn load(database: db.reader.Database) !BodyIndex {
        var index: BodyIndex = .{};
        if (database.section(.regex_pool, 0)) |section| index.regexes = try .init(section);
        // A database of YARA rules with only regex strings has no verify programs at all.
        if (database.section(.subsig_prog, 0)) |bytes| {
            index.programs = try .init(bytes);
            for (&index.anchored, 0..) |*slot, p| {
                if (database.section(.anchored_index, @intCast(p))) |section| slot.* = try .init(section, index.programs.?);
            }
        }
        if (index.programs) |progs| if (database.section(.prefilter, 0)) |section| {
            index.prefilters = try prefilter.loadAll(section, progs);
        };
        if (database.section(.ldb_table, 0)) |section| index.ldb = try .initWith(section, index.programs, index.regexes);
        if (database.section(.yara_cond, 0)) |section| {
            const table = index.ldb orelse return error.BadYaraTable;
            index.ldb.?.yara = try .init(section, table.records, if (index.regexes) |p| p.count() else 0);
        }
        return index;
    }
};

/// What is known about the file being scanned.
pub const File = struct {
    info: vm.FileInfo,
    /// ClamAV target type.
    target: u8 = 0,
    /// Immediate container type (`fmt.types.ClType`), 0 at the root.
    container: u16 = 0,
    intermediates: []const u16 = &.{},

    pub fn context(f: File) lt.FileContext {
        const executable = f.info.entry_point != null or f.info.sections.len > 0;
        return .{
            .target = f.target,
            .size = f.info.size,
            .entry_point = f.info.entry_point,
            .section_count = if (executable) f.info.sections.len else null,
            .container = f.container,
            .intermediates = f.intermediates,
        };
    }
};

pub const Detection = struct {
    /// Signature id; resolve the name through the hash index's sigmeta.
    sig: u32,
    /// Where the match lies (for a logical signature, where its last subsig hit lies).
    start: usize,
    end: usize,
};

pub const Verdict = union(enum) {
    clean,
    infected: Detection,
    /// No signature matched, but the verify budget ran out somewhere: not a clean result.
    limited: limits_mod.Event,
};

const Collector = struct {
    index: *const BodyIndex,
    programs: prog.Programs,
    state: ?*logical.State,
    ctx: lt.FileContext,
    hit: ?Detection = null,
    last: vm.Match = .{ .start = 0, .end = 0 },
    /// The logical state's spill arena filled up: reported as a limit.
    overflow: bool = false,

    fn take(c: *Collector, h: anchored.Hit) bool {
        const p = c.programs.get(h.prog);
        if (p.header.flags & prog.flag_ldb == 0) {
            c.hit = .{ .sig = p.header.sig, .start = h.match.start, .end = h.match.end };
            return false;
        }
        c.touch(p, h.match) catch {
            c.overflow = true;
            return false;
        };
        return true;
    }

    fn touch(c: *Collector, p: prog.Program, m: vm.Match) !void {
        const state = c.state orelse return;
        const table = c.index.ldb orelse return;
        if (p.header.sig >= table.records.len) return;
        c.last = m;
        try state.touch(table, c.ctx, p.header.sig, p.header.subsig, m.start);
    }

    /// The logical signature does not count matches and already has this subsig.
    fn settled(c: *Collector, p: prog.Program) bool {
        const state = c.state orelse return true;
        const table = c.index.ldb orelse return true;
        if (p.header.sig >= table.records.len) return true;
        const rec = table.records[p.header.sig];
        // Counting signatures need every match; byte compares need their triggers' starts.
        if (rec.flags & lt.flag_counts != 0 or rec.bc_count > 0) return false;
        return state.settled(p.header.sig, p.header.subsig);
    }
};

/// How the searched programs are found.
pub const Mode = enum {
    /// Through the prefilter when the database has one.
    auto,
    /// Every program through the verify VM's scanner.
    reference,
};

/// Scan `data`, the whole file. `budget` is per file. With `state` (reset by the caller between
/// files) logical signatures are evaluated too.
pub fn scanBuffer(index: *const BodyIndex, data: []const u8, file: File, budget: *vm.Budget, tracker: *limits_mod.Tracker, state: ?*logical.State) !Verdict {
    return scanBufferMode(index, data, file, budget, tracker, state, .auto, null);
}

/// What searching one program found.
const Searched = enum { more, detected, stop };

/// Run one program's scanner over the whole buffer (the reference path, programs without an
/// atom, deferred subsigs).
fn searchProgram(c: *Collector, p: prog.Program, data: []const u8, info: vm.FileInfo, budget: *vm.Budget) Searched {
    const is_ldb = p.header.flags & prog.flag_ldb != 0;
    if (is_ldb and c.settled(p)) return .more;
    var scanner = vm.Scanner.init(p, data, info, budget);
    while (true) {
        const m = scanner.next() catch return .stop;
        const hit = m orelse return .more;
        if (!is_ldb) {
            c.hit = .{ .sig = p.header.sig, .start = hit.start, .end = hit.end };
            return .detected;
        }
        c.touch(p, hit) catch {
            c.overflow = true;
            return .stop;
        };
        if (c.settled(p)) return .more;
    }
}

/// Stage three for prefilter candidates: the verify VM from the anchor part's start.
const Sink = struct {
    c: *Collector,
    data: []const u8,
    info: vm.FileInfo,
    budget: *vm.Budget,
    target: u8,
    /// The file's verify budget ran out.
    stopped: bool = false,
    /// Verify calls this file may make (`vm.Budget.verifyCap`).
    verify_cap: u64 = std.math.maxInt(u64),
    stats: ?*prefilter.Stats = null,
    /// What earlier candidates of the same multi-part program learned (verify_vm.Memo), so a
    /// common anchor part next to an unbounded gap stays linear over the file, as with the
    /// reference scanner: programs of up to `CompactMemo.parts` parts in a direct-mapped cache
    /// of compact entries, copied into `working` around each verify; longer ones in a few
    /// full memos.
    compact: []CompactMemo,
    working: *vm.Memo,
    memos: []vm.Memo,
    memo_progs: []u32,

    fn bigMemo(s: *Sink, prog_index: u32, part_count: usize) *vm.Memo {
        const i = prog_index % s.memos.len;
        if (s.memo_progs[i] != prog_index) {
            s.memo_progs[i] = prog_index;
            s.memos[i].prepare(part_count);
        }
        return &s.memos[i];
    }

    pub fn candidate(s: *Sink, prog_index: u32, anchor_start: usize) bool {
        const p = s.c.programs.get(prog_index);
        if (p.header.target != 0 and p.header.target != s.target) return true;
        const is_ldb = p.header.flags & prog.flag_ldb != 0;
        if (is_ldb and s.c.settled(p)) return true;
        const window = vm.startWindow(p.offset(), s.info) orelse return true;
        // Candidate density is bounded by a count, not only by steps: a verify that fails at
        // once costs no step budget to speak of.
        if (s.budget.verifies >= s.verify_cap) {
            s.budget.exhausted = true;
            s.budget.count_exhausted = true;
            s.stopped = true;
            return false;
        }
        s.budget.verifies += 1;
        const parts = p.header.part_count;
        var memo: *vm.Memo = s.working;
        var cached: ?*CompactMemo = null;
        if (parts == 1) {
            memo.prepare(1);
        } else if (parts <= CompactMemo.parts and s.compact.len > 0) {
            const e = &s.compact[prog_index % s.compact.len];
            if (e.prog != prog_index) {
                e.prog = prog_index;
                memo.prepare(parts);
            } else e.load(memo, parts);
            cached = e;
        } else memo = s.bigMemo(prog_index, parts);
        defer if (cached) |e| e.store(memo, parts);
        const got = vm.verifyMemo(p, s.data, window, anchor_start, s.budget, memo) catch {
            // One candidate ran out of its own budget: recorded, and the scan goes on, as the
            // reference scanner does. The file budget running out ends the search.
            if (s.budget.used >= s.budget.per_file) {
                s.stopped = true;
                return false;
            }
            if (s.stats) |st| if (st.per_prog_exhausted) |pp| {
                pp[prog_index] +|= 1;
            };
            return true;
        };
        const hit = got orelse return true;
        if (!is_ldb) {
            s.c.hit = .{ .sig = p.header.sig, .start = hit.start, .end = hit.end };
            return false;
        }
        s.c.touch(p, hit) catch {
            s.c.overflow = true;
            return false;
        };
        return true;
    }
};

/// Deferred programs searched together: one pass over the buffer tests, at every position, a
/// bitmap of the first two bytes of every pending atom, and on a hit probes a small table of
/// the atoms' 4-, 3- and 2-byte keys (case variants of a folded atom are separate keys),
/// instead of a pass per program. It lives in the worker's `Scratch` (or on the stack, about 84 KiB).
const Pending = struct {
    const slots = 4096;
    const max = slots / 2;
    const empty: u32 = 0xffff_ffff;
    /// Gate passes collected before they are probed.
    const pass_cap = 256;

    keys: [slots]u32,
    progs: [slots]u32,
    backs: [slots]u32,
    qs: [slots]u8,
    /// The anchor literal's bytes after the key, up to four more (`ext_lens`), compared before
    /// the verifier is called: deferred subsigs of one family share 4-byte prefixes (`558bec51`
    /// starts thousands of them), and without the next bytes each occurrence verifies them all.
    exts: [slots]u32,
    ext_lens: [slots]u8,
    nocase: [slots]bool,
    /// The first two bytes of every key: the test at every position.
    bits: [65536 / 64]u64,
    /// Per key length (2, 3, 4 bytes): a bit per 16-bit hash of the whole key, tested at the
    /// positions `bits` passes, so a common prefix costs a bit test rather than three table
    /// probes.
    full: [3][65536 / 64]u64,
    n: usize,

    fn clear(t: *Pending) void {
        @memset(&t.progs, empty);
        @memset(&t.bits, 0);
        for (&t.full) |*f| @memset(f, 0);
        t.n = 0;
    }

    /// A deferred program's key: the first (up to) four bytes of its anchor literal, the
    /// literal whose prefix atom selection found rarest (compile/atoms.zig `deferredAnchor`).
    /// Programs without a literal of two bytes use the scanner.
    fn keyOf(p: prog.Program) ?[]const u8 {
        const h = p.header;
        if (h.anchor_op == prog.no_anchor) return null;
        const lit = p.pattern.bytes(p.pattern.ops[h.anchor_op]);
        if (lit.len < 2) return null;
        return lit[0..@min(lit.len, 4)];
    }

    /// Room for every case variant of a key.
    fn fits(t: *const Pending) bool {
        return t.n + 16 <= max;
    }

    fn add(t: *Pending, p: prog.Program, index: u32) void {
        const h = p.header;
        const op = p.pattern.ops[h.anchor_op];
        const lit = keyOf(p).?;
        var key: [4]u8 = @splat(0);
        @memcpy(key[0..lit.len], lit);
        const q: u8 = @intCast(lit.len);
        const whole = p.pattern.bytes(op);
        const more = whole[lit.len..][0..@min(whole.len - lit.len, 4)];
        var ext_bytes: [4]u8 = @splat(0);
        const nocase = op.flags & @import("../compile/ir.zig").op_nocase != 0;
        for (more, 0..) |b, k| ext_bytes[k] = if (nocase) std.ascii.toLower(b) else b;
        const ext: Ext = .{ .bytes = std.mem.readInt(u32, &ext_bytes, .little), .len = @intCast(more.len), .nocase = nocase };
        if (!nocase) {
            t.put(std.mem.readInt(u32, &key, .little), q, index, h.anchor_delta, ext);
            return;
        }
        var it = @import("../compile/atoms.zig").Variants.init(&key);
        while (it.next()) |g| t.put(g, q, index, h.anchor_delta, ext);
    }

    const Ext = struct { bytes: u32, len: u8, nocase: bool };

    /// Whether the `len` bytes at `data[i..]` are the extension (lower-cased for a folded
    /// literal). Past the end of the data the verifier decides.
    inline fn extMatches(data: []const u8, i: usize, bytes: u32, len: u8, nocase: bool) bool {
        if (len == 0) return true;
        if (i + len > data.len) return true;
        var got: u32 = 0;
        for (0..len) |k| {
            const b = data[i + k];
            got |= @as(u32, if (nocase) std.ascii.toLower(b) else b) << @intCast(8 * k);
        }
        return got == bytes;
    }

    inline fn hash16(key: u32) u16 {
        return @truncate((key *% 0x9E37_79B1) >> 16);
    }

    inline fn has(bits: *const [65536 / 64]u64, k: u32) bool {
        return (bits[k >> 6] >> @intCast(k & 63)) & 1 != 0;
    }

    fn put(t: *Pending, key: u32, q: u8, index: u32, back: u32, ext: Ext) void {
        var s = prefilter.slotOf(key, slots);
        while (t.progs[s] != empty) s = (s + 1) & (slots - 1);
        t.keys[s] = key;
        t.qs[s] = q;
        t.progs[s] = index;
        t.backs[s] = back;
        t.exts[s] = ext.bytes;
        t.ext_lens[s] = ext.len;
        t.nocase[s] = ext.nocase;
        t.bits[(key & 0xffff) >> 6] |= @as(u64, 1) << @intCast(key & 63);
        const h = hash16(key);
        t.full[q - 2][h >> 6] |= @as(u64, 1) << @intCast(h & 63);
        t.n += 1;
    }

    fn run(t: *const Pending, data: []const u8, sink: *Sink) bool {
        if (data.len < 2) return true;
        if (sink.stats) |st| st.deferred_runs += 1;
        // Sixteen positions at a time: the bitmap tests append passing positions without a
        // branch, and a batch of them is probed at once.
        var passes: [pass_cap]u32 = undefined;
        var i: usize = 0;
        while (i + 17 <= data.len) {
            var np: usize = 0;
            const base = i;
            while (i + 17 <= data.len and np + 16 <= pass_cap) : (i += 16) {
                inline for (0..16) |j| {
                    const g2: u32 = std.mem.readInt(u16, data[i + j ..][0..2], .little);
                    passes[np] = @intCast(i + j - base);
                    np += @intFromBool(has(&t.bits, g2));
                }
            }
            for (passes[0..np]) |off| if (!t.probe(data, base + off, sink)) return false;
        }
        while (i + 2 <= data.len) : (i += 1) {
            const g2: u32 = std.mem.readInt(u16, data[i..][0..2], .little);
            if (!has(&t.bits, g2)) continue;
            if (!t.probe(data, i, sink)) return false;
        }
        return true;
    }

    /// The pending atoms whose key sits at `i`: each key length whose whole-key bit is set is
    /// looked up in the table.
    fn probe(t: *const Pending, data: []const u8, i: usize, sink: *Sink) bool {
        const g2: u32 = std.mem.readInt(u16, data[i..][0..2], .little);
        const g3: ?u32 = if (i + 3 <= data.len) g2 | @as(u32, data[i + 2]) << 16 else null;
        const g4: ?u32 = if (i + 4 <= data.len) prefilter.load4(data, i) else null;
        const keys = [3]?u32{ g2, g3, g4 };
        for (keys, 0..) |maybe, k| {
            const g = maybe orelse continue;
            if (!has(&t.full[k], hash16(g))) continue;
            if (sink.stats) |st| st.deferred_probes += 1;
            const q: u8 = @intCast(k + 2);
            var s = prefilter.slotOf(g, slots);
            while (t.progs[s] != empty) : (s = (s + 1) & (slots - 1)) {
                if (t.keys[s] != g or t.qs[s] != q or t.backs[s] > i) continue;
                if (!extMatches(data, i + q, t.exts[s], t.ext_lens[s], t.nocase[s])) continue;
                if (sink.stats) |st| st.deferred_verifies += 1;
                if (!sink.candidate(t.progs[s], i - t.backs[s])) return false;
            }
        }
        return true;
    }
};

/// A verify memo of a program with few parts, in file positions below 4 GiB (larger ones are
/// stored as unknown, which only costs a search).
const CompactMemo = struct {
    const parts = 16;
    const none: u32 = std.math.maxInt(u32);

    prog: u32,
    from: [parts]u32,
    upto: [parts]u32,
    stretch: [parts][4]u32,

    fn load(e: *const CompactMemo, m: *vm.Memo, n: usize) void {
        m.parts = n;
        for (0..n) |k| {
            m.dead_from[k] = if (e.from[k] == none) std.math.maxInt(usize) else e.from[k];
            m.dead_upto[k] = if (e.upto[k] == none) std.math.maxInt(usize) else e.upto[k];
            m.from_lo[k] = e.stretch[k][0];
            m.from_hi[k] = e.stretch[k][1];
            m.upto_lo[k] = e.stretch[k][2];
            m.upto_hi[k] = e.stretch[k][3];
        }
    }

    fn store(e: *CompactMemo, m: *const vm.Memo, n: usize) void {
        for (0..n) |k| {
            e.from[k] = std.math.cast(u32, m.dead_from[k]) orelse none;
            e.upto[k] = std.math.cast(u32, m.dead_upto[k]) orelse none;
            // A stretch past 4 GiB is dropped (stored empty): that only costs a search.
            const fits = m.from_hi[k] <= none and m.upto_hi[k] <= none;
            e.stretch[k] = if (fits) .{ @intCast(m.from_lo[k]), @intCast(m.from_hi[k]), @intCast(m.upto_lo[k]), @intCast(m.upto_hi[k]) } else @splat(0);
        }
    }
};

/// Per-worker memory for the prefiltered search (about 300 KiB): the candidate ring, the
/// deferred pass's table and the verify memo caches. Workers allocate one from their scratch
/// and pass it to `scanBufferScratch`; without one a smaller copy lives on the stack.
pub const Scratch = struct {
    pub const compact_slots = 1024;
    pub const memo_slots = 8;

    ring: [prefilter.ring_len]prefilter.Candidate,
    pending: Pending,
    compact: [compact_slots]CompactMemo,
    working: vm.Memo,
    memos: [memo_slots]vm.Memo,
    memo_progs: [memo_slots]u32,
};

/// The stack fallback when the caller has no `Scratch`.
const SmallScratch = struct {
    ring: [prefilter.ring_len]prefilter.Candidate,
    pending: Pending,
    working: vm.Memo,
    memos: [2]vm.Memo,
    memo_progs: [2]u32,
};

/// `scanBuffer` with the search mode chosen, worker scratch, and prefilter counters for
/// benchmarks.
pub fn scanBufferMode(index: *const BodyIndex, data: []const u8, file: File, budget: *vm.Budget, tracker: *limits_mod.Tracker, state: ?*logical.State, mode: Mode, stats: ?*prefilter.Stats) !Verdict {
    return scanBufferScratch(index, data, file, budget, tracker, state, mode, stats, null);
}

pub fn scanBufferScratch(index: *const BodyIndex, data: []const u8, file: File, budget: *vm.Budget, tracker: *limits_mod.Tracker, state: ?*logical.State, mode: Mode, stats: ?*prefilter.Stats, worker: ?*Scratch) !Verdict {
    if (index.programs == null and index.ldb == null) return .clean;
    const progs = index.programs orelse prog.Programs.empty;
    const target = file.target;
    const info = file.info;
    var c: Collector = .{ .index = index, .programs = progs, .state = state, .ctx = file.context() };
    // Signatures pinned to an offset: direct lookups through the file's partition and type 0.
    for ([_]u8{ target, 0 }, 0..) |part, n| {
        if (n == 1 and target == 0) break;
        const a = if (part < index.anchored.len) index.anchored[part] orelse continue else continue;
        anchored.scan(a, progs, data, info, budget, &c, Collector.take) catch break;
        if (c.hit) |d| return .{ .infected = d };
        if (c.overflow) break;
    }
    const part: ?*const prefilter.Partition = if (mode == .auto) index.partitionFor(target) else null;
    if (part) |pf| search: {
        // Stages one and two find candidates, the verify VM confirms them.
        var small: SmallScratch = undefined;
        var ring: *[prefilter.ring_len]prefilter.Candidate = &small.ring;
        var pending: *Pending = &small.pending;
        var memos: []vm.Memo = &small.memos;
        var memo_progs: []u32 = &small.memo_progs;
        var working: *vm.Memo = &small.working;
        var compact: []CompactMemo = &.{};
        if (worker) |sc| {
            ring = &sc.ring;
            pending = &sc.pending;
            memos = &sc.memos;
            memo_progs = &sc.memo_progs;
            working = &sc.working;
            compact = &sc.compact;
        }
        @memset(memo_progs, std.math.maxInt(u32));
        for (compact) |*e| e.prog = std.math.maxInt(u32);
        var sink: Sink = .{ .c = &c, .data = data, .info = info, .budget = budget, .target = target, .stats = stats, .compact = compact, .working = working, .memos = memos, .memo_progs = memo_progs, .verify_cap = budget.verifyCap(data.len) };
        _ = prefilter.scan(pf, data, ring, &sink, stats);
        if (c.hit) |d| return .{ .infected = d };
        if (sink.stopped or c.overflow) break :search;
        // Programs with no atom.
        for (pf.short) |i| {
            const p = progs.get(i);
            if (p.header.target != 0 and p.header.target != target) continue;
            if (stats) |s| {
                s.scans += 1;
                if (s.per_prog_scans) |pp| pp[i] +|= 1;
            }
            switch (searchProgram(&c, p, data, info, budget)) {
                .more => {},
                .detected => return .{ .infected = c.hit.? },
                .stop => break :search,
            }
        }
        // Deferred subsigs of the logical signatures the first pass touched: one of their
        // cover subsigs matched, so they are searched now, their atoms all in one pass.
        const st = state orelse break :search;
        const table = index.ldb orelse break :search;
        pending.n = 0;
        var pending_ready = false;
        var it = st.liveTouched();
        while (it.next()) |ldb| {
            if (ldb >= table.records.len) continue;
            const rec = table.records[ldb];
            for (rec.prog_first..rec.prog_first + rec.prog_count) |i| {
                const p = progs.get(i);
                if (p.header.flags & prog.flag_deferred == 0) continue;
                if (p.header.target != 0 and p.header.target != target) continue;
                if (c.settled(p)) continue;
                if (stats) |s| s.deferred += 1;
                if (Pending.keyOf(p) != null) {
                    // The table is cleared on first use: most files touch nothing deferred.
                    if (!pending_ready) {
                        pending.clear();
                        pending_ready = true;
                    }
                    if (!pending.fits()) {
                        if (!pending.run(data, &sink)) break :search;
                        pending.clear();
                    }
                    pending.add(p, @intCast(i));
                    continue;
                }
                if (stats) |s| {
                    s.scans += 1;
                    if (s.per_prog_scans) |pp| pp[i] +|= 1;
                }
                switch (searchProgram(&c, p, data, info, budget)) {
                    .more => {},
                    .detected => return .{ .infected = c.hit.? },
                    .stop => break :search,
                }
            }
        }
        if (pending.n > 0 and !pending.run(data, &sink)) break :search;
    } else {
        // The reference path: every program of the target is searched.
        for (0..progs.count()) |i| {
            const p = progs.get(i);
            if (anchored.isAnchored(p)) continue;
            if (p.header.target != 0 and p.header.target != target) continue;
            switch (searchProgram(&c, p, data, info, budget)) {
                .more => {},
                .detected => return .{ .infected = c.hit.? },
                .stop => break,
            }
        }
    }
    if (state) |st| if (index.ldb) |table| if (table.yara) |yara| {
        // YARA: regex strings are searched here (they have no verify program), and rules whose
        // condition can hold with no string matched get state so they are evaluated.
        for (yara.rules) |rule| {
            if (rule.flags & yara_cond.flag_always != 0) st.ensure(table, c.ctx, rule.ldb) catch {
                c.overflow = true;
            };
            for (yara.ruleStrings(rule), 0..) |str, i| {
                if (str.kind != yara_cond.kind_regex) continue;
                const scratch = st.regex_scratch orelse {
                    st.regex_limited = true;
                    continue;
                };
                const program = index.regexes.?.get(str.regex);
                var pos: usize = 0;
                var n: u32 = 0;
                while (pos <= data.len) {
                    const m = (program.findFrom(scratch, data, pos) catch {
                        st.regex_limited = true;
                        break;
                    }) orelse break;
                    if (n == max_regex_matches) {
                        tracker.note(.yara_matches);
                        break;
                    }
                    st.touch(table, c.ctx, rule.ldb, @intCast(i), m.start) catch {
                        c.overflow = true;
                        break;
                    };
                    n += 1;
                    // Every start position counts, as YARA counts matches.
                    pos = m.start + 1;
                }
            }
        }
    };
    if (state) |st| if (index.ldb) |table| {
        // Expressions that hold with no hits are evaluated for every file, as libclamav does.
        for (table.always) |i| st.ensure(table, c.ctx, i) catch {
            c.overflow = true;
        };
        var out: [1]u32 = undefined;
        const n = st.finalizeWith(table, data, info, &out);
        if (st.bc_out_of_bounds) tracker.note(.byte_compare_bounds);
        if (n == 0 and st.offsets_limited) {
            tracker.note(.yara_matches);
            return .{ .limited = .yara_matches };
        }
        if (n == 0 and st.regex_limited) {
            tracker.note(.regex_steps);
            return .{ .limited = .regex_steps };
        }
        if (n > 0) return .{ .infected = .{ .sig = table.records[out[0]].sig, .start = c.last.start, .end = c.last.end } };
    };
    if (c.overflow) {
        tracker.note(.logical_state);
        return .{ .limited = .logical_state };
    }
    if (budget.count_exhausted) {
        tracker.note(.verify_count);
        return .{ .limited = .verify_count };
    }
    if (budget.exhausted) {
        tracker.note(.verify_steps);
        return .{ .limited = .verify_steps };
    }
    return .clean;
}

test "compile .ndb signatures and detect them end to end" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const hashscan = @import("hashscan.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("test.ndb",
        \\Test.Body.Any-1-0:0:*:4558414d504c45{-8}5041594c4f4144
        \\Test.Body.Pe-2-0:1:EP+0:e8????????5dc3
        \\Test.Body.Html-3-0:3:*:3c736372697074
        \\
    );
    const summary = try c.write(io, tmp.dir, "body.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 3), summary.body_rules);

    const database = try db.reader.open(io, tmp.dir, "body.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    const names = try hashscan.HashIndex.load(database);
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    var budget: vm.Budget = .{};
    const doc = "header EXAMPLE...PAYLOAD trailer";
    const hit = try scanBuffer(&index, doc, .{ .info = .{ .size = doc.len } }, &budget, &tracker, null);
    try std.testing.expectEqualStrings("Test.Body.Any-1-0", try names.meta.?.name(hit.infected.sig, &name_buf));
    try std.testing.expectEqual(@as(usize, 7), hit.infected.start);

    // Target types partition: the HTML signature does not fire on a PE, nor the PE one off EP.
    budget.reset();
    const pe = "MZ<script>\xe8\x01\x02\x03\x04\x5d\xc3";
    try std.testing.expectEqual(Verdict.clean, try scanBuffer(&index, pe, .{ .info = .{ .size = pe.len, .entry_point = 3 }, .target = 1 }, &budget, &tracker, null));
    budget.reset();
    const at_ep = try scanBuffer(&index, pe, .{ .info = .{ .size = pe.len, .entry_point = 10 }, .target = 1 }, &budget, &tracker, null);
    try std.testing.expectEqualStrings("Test.Body.Pe-2-0", try names.meta.?.name(at_ep.infected.sig, &name_buf));
    budget.reset();
    try std.testing.expect(try scanBuffer(&index, pe, .{ .info = .{ .size = pe.len }, .target = 3 }, &budget, &tracker, null) == .infected);

    // A budget that runs out is a limit, not a clean verdict. Both literals occur (so a
    // candidate comes whichever one holds the atom), never within 8 bytes of each other.
    var tiny: vm.Budget = .{ .per_verify = 1, .per_file = 1 };
    const many = "PAYLOAD EXAMPLE..........PAYLOAD EXAMPLE..........PAYLOAD";
    try std.testing.expectEqual(Verdict{ .limited = .verify_steps }, try scanBuffer(&index, many, .{ .info = .{ .size = many.len } }, &tiny, &tracker, null));
    try std.testing.expect(tracker.raised.contains(.verify_steps));

    // So is a verify count that runs out (candidate density), with ample steps.
    var few: vm.Budget = .{ .verify_floor = 2, .verify_per_kib = 0 };
    try std.testing.expectEqual(Verdict{ .limited = .verify_count }, try scanBuffer(&index, many, .{ .info = .{ .size = many.len } }, &few, &tracker, null));
    try std.testing.expect(tracker.raised.contains(.verify_count));
    // A detection before the count runs out is still a detection.
    var two: vm.Budget = .{ .verify_floor = 2, .verify_per_kib = 0 };
    const found = try scanBuffer(&index, doc, .{ .info = .{ .size = doc.len } }, &two, &tracker, null);
    try std.testing.expect(found == .infected);
}

test "logical signatures end to end: counts, target descriptions, anchored subsigs" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const hashscan = @import("hashscan.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("test.ldb",
        \\Test.Logical.Pair-1-0;Target:0;0&1;6576616c28;756e6573636170652800::i
        \\Test.Logical.Count-2-0;Target:0;0>2&1=0;414141;5a5a5a
        \\Test.Logical.Pe-3-0;Target:1,FileSize:10-64;0&1;EP+0:e800;4d5a
        \\Test.Logical.Distinct-4-0;Target:7;(0|1|2)>1,2;6f6e65;74776f;746872656565
        \\Test.Logical.Bc-5-0;Target:0;0&1;4c454e3d;0(>>4#de3#>100)
        \\Test.Logical.Pcre-6-0;Target:0;0&1;3c736372697074;0/eval\s*\(\s*unescape/i
        \\Test.Logical.PcreCount-7-0;Target:0;1>1;46524147;0/frag[0-9]+/g
        \\Test.Logical.PcreSled-8-0;Target:0;0&1;534c4544;0/(?:\x90|\xcc){4,}/
        \\
    );
    _ = try c.write(io, tmp.dir, "ldb.zavdb", .{ .db_version = 1 });
    const database = try db.reader.open(io, tmp.dir, "ldb.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    const names = try hashscan.HashIndex.load(database);

    // Logical state comes from worker scratch; the heap is never used during scans.
    var scratch: [2 * 1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var state = try logical.State.init(fba.allocator());
    const pool = index.regexes.?;
    const regex_mem = try fba.allocator().alignedAlloc(u8, .@"8", pool.scratchBytes(256));
    var regex_scratch = try regex_pool.Scratch.initBuffer(regex_mem, pool, 256);
    regex_scratch.setStepBudget(1 << 20);
    state.regex_scratch = &regex_scratch;
    const reserved = fba.end_index;
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    const Case = struct { []const u8, File, ?[]const u8 };
    const pe = "MZ\x90\x00....\xe8\x00\x00\x00";
    for ([_]Case{
        .{ "x=eval(UNESCAPE(\x00y)", .{ .info = .{ .size = 22 } }, "Test.Logical.Pair-1-0" },
        .{ "x=eval(y)", .{ .info = .{ .size = 9 } }, null },
        .{ "AAA AAA AAAA", .{ .info = .{ .size = 12 } }, "Test.Logical.Count-2-0" },
        .{ "AAA AAA", .{ .info = .{ .size = 7 } }, null },
        .{ "AAA AAA AAA ZZZ", .{ .info = .{ .size = 15 } }, null },
        .{ pe, .{ .info = .{ .size = pe.len, .entry_point = 8 }, .target = 1 }, "Test.Logical.Pe-3-0" },
        .{ pe, .{ .info = .{ .size = pe.len, .entry_point = 4 }, .target = 1 }, null },
        .{ pe, .{ .info = .{ .size = pe.len, .entry_point = 8 }, .target = 6 }, null },
        .{ "one two", .{ .info = .{ .size = 7 }, .target = 7 }, "Test.Logical.Distinct-4-0" },
        .{ "one one", .{ .info = .{ .size = 7 }, .target = 7 }, null },
        .{ "x LEN=512;", .{ .info = .{ .size = 10 } }, "Test.Logical.Bc-5-0" },
        .{ "x LEN=099;", .{ .info = .{ .size = 10 } }, null },
        .{ "x LEN=5", .{ .info = .{ .size = 7 } }, null },
        .{ "<script>EVAL ( Unescape('x')", .{ .info = .{ .size = 1 } }, "Test.Logical.Pcre-6-0" },
        .{ "<script>evaluate(unescape)", .{ .info = .{ .size = 1 } }, null },
        .{ "FRAG frag1 frag22", .{ .info = .{ .size = 1 } }, "Test.Logical.PcreCount-7-0" },
        .{ "FRAG frag1", .{ .info = .{ .size = 1 } }, null },
        .{ "SLED \x90\xcc\x90\x90!", .{ .info = .{ .size = 1 } }, "Test.Logical.PcreSled-8-0" },
        .{ "SLED \x90\xcc\x90!", .{ .info = .{ .size = 1 } }, null },
    }) |case| {
        state.reset();
        var budget: vm.Budget = .{};
        var file = case[1];
        file.info.size = case[0].len;
        const verdict = try scanBuffer(&index, case[0], file, &budget, &tracker, &state);
        // The prefiltered search (with deferred subsigs) and the reference search agree.
        state.reset();
        var budget_ref: vm.Budget = .{};
        // (A logical detection's position is its last subsig match, which depends on the
        // order matches were found in; the verdict and the signature do not.)
        const ref = try scanBufferMode(&index, case[0], file, &budget_ref, &tracker, &state, .reference, null);
        const same = std.meta.activeTag(verdict) == std.meta.activeTag(ref) and (verdict != .infected or verdict.infected.sig == ref.infected.sig);
        if (!same) {
            std.debug.print("case {s}: prefilter {any}, reference {any}\n", .{ case[0], verdict, ref });
            return error.TestUnexpectedResult;
        }
        if (case[2]) |want| {
            try std.testing.expectEqualStrings(want, try names.meta.?.name(verdict.infected.sig, &name_buf));
        } else try std.testing.expectEqual(Verdict.clean, verdict);
    }
    try std.testing.expectEqual(reserved, fba.end_index);
    // The last case's compare pointed past the end of the data: a bounds event, still no match.
    try std.testing.expect(tracker.raised.contains(.byte_compare_bounds));
}

test "YARA rules end to end: text, hex and regex strings, offsets, reads, always rules" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const hashscan = @import("hashscan.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("test.yar",
        \\rule Yara_Pe_Dropper {
        \\  strings:
        \\    $mz = { 4D 5A }
        \\    $s = "dropper" nocase
        \\    $u = /https?:\/\/[a-z]+\.invalid/
        \\  condition:
        \\    $mz at 0 and uint16(0) == 0x5A4D and $s and #u >= 2
        \\}
        \\rule Yara_Wide { strings: $w = "evil" wide condition: $w in (0..16) }
        \\rule Yara_Missing { strings: $a = "marker!" condition: uint8(0) == 0x41 and not $a }
        \\private rule Yara_Private { strings: $p = "private!" condition: $p }
        \\
    );
    const summary = try c.write(io, tmp.dir, "yara.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 4), summary.yara_rules);
    const database = try db.reader.open(io, tmp.dir, "yara.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    const names = try hashscan.HashIndex.load(database);

    var scratch: [2 * 1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var state = try logical.State.init(fba.allocator());
    const pool = index.regexes.?;
    var regex_scratch = try regex_pool.Scratch.initBuffer(try fba.allocator().alignedAlloc(u8, .@"8", pool.scratchBytes(256)), pool, 256);
    state.regex_scratch = &regex_scratch;
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    const Case = struct { []const u8, ?[]const u8 };
    for ([_]Case{
        .{ "MZ..DROPPER http://a.invalid and https://bb.invalid", "Yara_Pe_Dropper" },
        .{ "MZ..DROPPER http://a.invalid only one", null },
        .{ "xMZ.dropper http://a.invalid https://bb.invalid", null }, // MZ not at 0
        .{ "ab e\x00v\x00i\x00l\x00", "Yara_Wide" },
        .{ ".................e\x00v\x00i\x00l\x00", null }, // starts at 17, past the range
        .{ "A plain file", "Yara_Missing" }, // no string matched: evaluated because it can hold
        .{ "A file with marker!", null },
        .{ "a private! match is not reported", null },
    }) |case| {
        state.reset();
        var budget: vm.Budget = .{};
        const verdict = try scanBuffer(&index, case[0], .{ .info = .{ .size = case[0].len } }, &budget, &tracker, &state);
        if (case[1]) |want| {
            if (verdict != .infected) {
                std.debug.print("case: {s} gave {any}\n", .{ case[0], verdict });
                return error.TestUnexpectedResult;
            }
            std.testing.expectEqualStrings(want, try names.meta.?.name(verdict.infected.sig, &name_buf)) catch |err| {
                std.debug.print("case: {s}\n", .{case[0]});
                return err;
            };
        } else std.testing.expectEqual(Verdict.clean, verdict) catch |err| {
            std.debug.print("case: {s}\n", .{case[0]});
            return err;
        };
    }
}

test "the prefiltered scan allocates nothing: worker memory comes from a counting allocator once" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("t.ndb", "T.A-1-0:0:*:13a7c95be2f1408d77e3b1aa\nT.C-2-0:0:*:c95be2f1\nT.D-3-0:0:*:ff25a4{3}00000000\n");
    try c.addFile("t.ldb", "T.L-4-0;Target:0;0&1;6576616c28756e65;6162\n");
    _ = try c.write(io, tmp.dir, "a.zavdb", .{ .db_version = 1 });
    const database = try db.reader.open(io, tmp.dir, "a.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    try std.testing.expect(index.prefilters[0] != null);

    const Counting = struct {
        parent: std.mem.Allocator,
        allocs: usize = 0,
        fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.allocs += 1;
            return self.parent.rawAlloc(len, a, ra);
        }
        fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.allocs += 1;
            return self.parent.rawResize(m, a, n, ra);
        }
        fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.allocs += 1;
            return self.parent.rawRemap(m, a, n, ra);
        }
        fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.parent.rawFree(m, a, ra);
        }
        fn allocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
        }
    };
    var counting: Counting = .{ .parent = gpa };
    const ca = counting.allocator();
    var arena: std.heap.ArenaAllocator = .init(ca);
    defer arena.deinit();
    var state = try logical.State.init(arena.allocator());
    const worker = try arena.allocator().create(Scratch);
    const before = counting.allocs;

    var prng = std.Random.DefaultPrng.init(3);
    var data: [1 << 16]u8 = undefined;
    var tracker = limits_mod.Tracker.init(.{});
    for (0..8) |round| {
        prng.random().bytes(&data);
        @memcpy(data[100..][0..12], "\x13\xa7\xc9\x5b\xe2\xf1\x40\x8d\x77\xe3\xb1\xaa");
        @memcpy(data[5000..][0..11], "eval(une ab");
        state.reset();
        var budget: vm.Budget = .{};
        const v = try scanBufferScratch(&index, &data, .{ .info = .{ .size = data.len } }, &budget, &tracker, &state, .auto, null, worker);
        if (round == 0) try std.testing.expect(v == .infected);
    }
    try std.testing.expectEqual(before, counting.allocs);
}
