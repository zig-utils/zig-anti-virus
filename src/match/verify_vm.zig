//! The verify VM: confirms a candidate against a whole subsignature program (docs/DESIGN.md 5).
//!
//! A candidate is a position where the program's anchor part starts. Parts before the anchor are
//! searched backwards and parts after it forwards, each inside the gap window its `part_end`
//! carries. Searching jumps between occurrences of a part's edge literal byte with memchr, and
//! stops early when trying a later position provably cannot help (a fixed-length part followed
//! by an unbounded gap). Every part attempt and every alternative tried costs a step; a step
//! budget per verify call and one per file bound the work any input can cause, and running out
//! is reported as a limit, never as a clean result.
//!
//! The VM works on one in-memory view of the data, keeps all state on the stack (no allocation)
//! and recurses at most once per part and once per branch point (both bounded by validation).
//!
//! Semantics, from ClamAV's body signature documentation: `*` spans any distance, each `{n-m}`
//! window applies between neighbouring parts independently, a match's start must fall in the
//! offset window (`offset` to `offset + maxshift`), `::f` needs a non-alphanumeric byte (or the
//! edge of the data) on both sides of the match.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const prog = @import("prog.zig");

/// A section of an executable, as file offsets.
pub const Section = struct {
    offset: u64,
    size: u64,
};

/// What offsets resolve against. Entry point and sections come from the format parsers.
pub const FileInfo = struct {
    size: u64,
    entry_point: ?u64 = null,
    sections: []const Section = &.{},
};

/// Where a match may start and how far it may reach.
pub const Window = struct {
    lo: u64,
    hi: u64,
    end_limit: u64,
};

/// The start window for an offset, or null when it cannot apply to this file (no entry point,
/// no such section, before the start of the file).
pub fn startWindow(off: ir.Offset, info: FileInfo) ?Window {
    const size = info.size;
    var base: i64 = 0;
    const end_limit = size;
    switch (off.kind) {
        .any => return .{ .lo = 0, .hi = size, .end_limit = size },
        .absolute => base = off.a,
        .eof_minus => base = @as(i64, @intCast(size)) - off.a,
        .entry_point => base = @as(i64, @intCast(info.entry_point orelse return null)) + off.a,
        .section_start, .section_entire => {
            if (off.section >= info.sections.len) return null;
            const s = info.sections[off.section];
            if (off.kind == .section_entire) {
                // libclamav lets a match start anywhere from the section's first byte to one
                // past its last, and run past its end (tests/differential/cases/ldb.case).
                if (s.size == 0 or s.offset >= size) return null;
                return .{ .lo = s.offset, .hi = @min(size, s.offset +| s.size), .end_limit = size };
            }
            base = @as(i64, @intCast(s.offset)) + off.a;
        },
        .last_section => {
            if (info.sections.len == 0) return null;
            base = @as(i64, @intCast(info.sections[info.sections.len - 1].offset)) + off.a;
        },
        _ => return null,
    }
    if (base < 0 or base > size) return null;
    const lo: u64 = @intCast(base);
    return .{ .lo = lo, .hi = @min(size, lo +| off.shift), .end_limit = end_limit };
}

pub const Budget = struct {
    /// Steps one verify call may take (the per-subsignature budget).
    per_verify: u32 = 4096,
    /// Steps all verify calls for one file may take together.
    per_file: u64 = 1 << 24,
    used: u64 = 0,
    /// Set when either budget ran out during this file.
    exhausted: bool = false,

    pub fn reset(b: *Budget) void {
        b.used = 0;
        b.exhausted = false;
    }
};

pub const Match = struct {
    start: usize,
    end: usize,
};

pub const Error = error{BudgetExhausted};

const Outcome = enum { here_fail, later_fail, ok };

const max_parts = prog.max_parts;
const unknown = std.math.maxInt(usize);

/// What earlier verify calls on the same data learned: part k matches nowhere at or after
/// `dead_from[k]`, and ends nowhere at or before `dead_upto[k]`. Whether a part's own ops match
/// at a position does not depend on the rest of the chain, so this stays true for every later
/// candidate and keeps unbounded-gap signatures linear over a file.
pub const Memo = struct {
    dead_from: [max_parts]usize = undefined,
    dead_upto: [max_parts]usize = undefined,
    /// Entries below this are initialised.
    parts: usize = 0,

    /// Forget everything and size the memo for a program with `part_count` parts. Only the
    /// entries in use are touched, so a one-part program pays nothing.
    pub fn prepare(m: *Memo, part_count: usize) void {
        @memset(m.dead_from[0..part_count], unknown);
        @memset(m.dead_upto[0..part_count], unknown);
        m.parts = part_count;
    }
};

const Vm = struct {
    pat: ir.Pattern,
    data: []const u8,
    flags: u8,
    window: Window,
    /// First op of each part; `part_first[part_count]` is one past the last op.
    part_first: [max_parts + 1]u16,
    /// Each part's ops consume a fixed number of bytes.
    part_fixed: [max_parts]bool,
    part_count: usize,
    steps: u32,
    budget: *Budget,
    memo: *Memo,
    start: usize = 0,
    end: usize = 0,

    fn init(p: prog.Program, data: []const u8, window: Window, budget: *Budget, memo: *Memo) Vm {
        var vm: Vm = .{
            .pat = p.pattern,
            .data = data,
            .flags = p.header.flags,
            .window = window,
            .part_first = undefined,
            .part_fixed = undefined,
            .part_count = p.header.part_count,
            .steps = budget.per_verify,
            .budget = budget,
            .memo = memo,
        };
        var part: usize = 0;
        vm.part_first[0] = 0;
        vm.part_fixed[0] = true;
        for (p.pattern.ops, 0..) |o, i| switch (o.code) {
            .part_end => {
                part += 1;
                vm.part_first[part] = @intCast(i + 1);
                vm.part_fixed[part] = true;
            },
            .alt => if (o.b & 0xffff != o.b >> 16) {
                vm.part_fixed[part] = false;
            },
            else => {},
        };
        vm.part_first[vm.part_count] = @intCast(p.pattern.ops.len + 1);
        return vm;
    }

    fn step(vm: *Vm) Error!void {
        if (vm.steps == 0 or vm.budget.used >= vm.budget.per_file) {
            vm.budget.exhausted = true;
            return error.BudgetExhausted;
        }
        vm.steps -= 1;
        vm.budget.used += 1;
    }

    /// Index of the op ending part k (its part_end), or ops.len for the last part.
    fn partEnd(vm: *const Vm, k: usize) usize {
        return vm.part_first[k + 1] - 1;
    }

    fn nocase(o: ir.Op) bool {
        return o.flags & ir.op_nocase != 0;
    }

    fn eqByte(a: u8, b: u8, fold: bool) bool {
        return a == b or (fold and std.ascii.toLower(a) == std.ascii.toLower(b));
    }

    /// A straight-line op (lit, masked, gapf) at `pos`: bytes consumed, or null.
    fn simple(vm: *const Vm, o: ir.Op, pos: usize) ?usize {
        const d = vm.data;
        switch (o.code) {
            .lit => {
                if (pos + o.len > d.len) return null;
                const want = vm.pat.bytes(o);
                const got = d[pos..][0..o.len];
                if (nocase(o)) {
                    for (want, got) |w, g| if (!eqByte(w, g, true)) return null;
                } else if (!std.mem.eql(u8, want, got)) return null;
                return o.len;
            },
            .masked => {
                if (pos + o.len > d.len) return null;
                const negate = o.flags & ir.op_negate != 0;
                for (vm.pat.bytes(o), vm.pat.masks(o), d[pos..][0..o.len]) |v, m, g| {
                    if (((g & m) == v) == negate) return null;
                }
                return o.len;
            },
            .gapf => return if (pos + o.a <= d.len) o.a else null,
            else => unreachable,
        }
    }

    /// One alternative at `pos`, all straight-line ops.
    fn alternative(vm: *const Vm, entry: ir.AltEntry, pos: usize, fold: bool) bool {
        var p = pos;
        for (vm.pat.altOps(entry)) |inner| {
            var o = inner;
            if (fold and o.code == .lit) o.flags |= ir.op_nocase;
            p += vm.simple(o, p) orelse return false;
        }
        return true;
    }

    fn isAlnum(b: u8) bool {
        return std.ascii.isAlphanumeric(b);
    }

    /// Bytes boundary anchor op `i` consumes ending (backwards) or starting (forwards) at `pos`,
    /// or null when it does not hold. Edge anchors are zero-width lookarounds.
    fn boundAt(vm: *const Vm, i: usize, pos: usize, backwards: bool) ?usize {
        const o = vm.pat.ops[i];
        const class: ir.Bound = @fromBackingInt(o.flags);
        const where = ir.boundPos(vm.pat.ops, i);
        if (where != .middle) return if (ir.boundOk(class, where, vm.data, pos)) 0 else null;
        if (backwards) {
            if (pos == 0) return null;
            return if (ir.boundOk(class, .middle, vm.data, pos - 1)) 1 else null;
        }
        return if (ir.boundOk(class, .middle, vm.data, pos)) 1 else null;
    }

    fn wordBefore(vm: *const Vm, pos: usize) bool {
        const d = vm.data;
        if (vm.flags & prog.flag_wide != 0) return pos >= 2 and d[pos - 1] == 0 and isAlnum(d[pos - 2]);
        return pos > 0 and isAlnum(d[pos - 1]);
    }

    fn wordAfter(vm: *const Vm, pos: usize) bool {
        const d = vm.data;
        if (vm.flags & prog.flag_wide != 0) return pos + 1 < d.len and d[pos + 1] == 0 and isAlnum(d[pos]);
        return pos < d.len and isAlnum(d[pos]);
    }

    // -- forwards ------------------------------------------------------------------------------

    /// Match part k's ops from op `i` at `pos`, then every later part.
    fn fwd(vm: *Vm, k: usize, i_start: usize, pos_start: usize) Error!Outcome {
        var i = i_start;
        var pos = pos_start;
        const end_op = vm.partEnd(k);
        while (i < end_op) : (i += 1) {
            const o = vm.pat.ops[i];
            switch (o.code) {
                .lit, .masked, .gapf => pos += vm.simple(o, pos) orelse return .here_fail,
                .nalt => {
                    const n = o.b & 0xffff;
                    if (pos + n > vm.data.len) return .here_fail;
                    for (vm.pat.alternatives(o)) |entry| {
                        if (vm.alternative(entry, pos, nocase(o))) return .here_fail;
                    }
                    pos += n;
                },
                .alt => {
                    var later = false;
                    for (vm.pat.alternatives(o)) |entry| {
                        if (pos + entry.byte_len > vm.data.len) continue;
                        try vm.step();
                        if (!vm.alternative(entry, pos, nocase(o))) continue;
                        switch (try vm.fwd(k, i + 1, pos + entry.byte_len)) {
                            .ok => return .ok,
                            .later_fail => later = true,
                            .here_fail => {},
                        }
                    }
                    return if (later) .later_fail else .here_fail;
                },
                .bound => pos += vm.boundAt(i, pos, false) orelse return .here_fail,
                else => unreachable,
            }
        }
        // Part k matched, ending at pos.
        if (k + 1 == vm.part_count) {
            if (pos > vm.window.end_limit) return .later_fail;
            if (vm.flags & prog.flag_fullword != 0 and vm.wordAfter(pos)) return .later_fail;
            vm.end = pos;
            return .ok;
        }
        const gap = vm.pat.ops[end_op];
        if (try vm.nextPart(k + 1, pos, gap)) return .ok;
        return .later_fail;
    }

    /// Search part k's start in `[from + gap.a, from + gap.b]`.
    fn nextPart(vm: *Vm, k: usize, from: usize, gap: ir.Op) Error!bool {
        const d = vm.data;
        if (gap.a > gap.b) return false;
        const lo = from +| gap.a;
        if (lo > d.len) return false;
        const hi = if (gap.b == ir.unbounded) d.len else @min(d.len, from +| gap.b);
        const first = vm.pat.ops[vm.part_first[k]];
        const greedy = vm.part_fixed[k] and k + 1 < vm.part_count and vm.pat.ops[vm.partEnd(k)].b == ir.unbounded;
        const to_end = hi == d.len;
        if (to_end and lo >= vm.memo.dead_from[k]) return false;
        var any_later = false;
        var q = lo;
        while (q <= hi) : (q += 1) {
            if (first.code == .lit and first.flags & ir.op_nocase == 0) {
                const byte = vm.pat.bytes(first)[0];
                q = std.mem.indexOfScalarPos(u8, d[0..@min(d.len, hi + 1)], q, byte) orelse break;
            }
            try vm.step();
            switch (try vm.fwd(k, vm.part_first[k], q)) {
                .ok => return true,
                .later_fail => {
                    if (greedy) return false;
                    any_later = true;
                },
                .here_fail => {},
            }
        }
        if (to_end and !any_later) vm.memo.dead_from[k] = @min(vm.memo.dead_from[k], lo);
        return false;
    }

    // -- backwards -----------------------------------------------------------------------------

    /// Match part k's ops backwards from op `i` (exclusive upper bound) ending at `pos`, then
    /// every earlier part.
    fn bwd(vm: *Vm, k: usize, i_end: usize, pos_end: usize) Error!Outcome {
        var i = i_end;
        var pos = pos_end;
        const first = vm.part_first[k];
        while (i > first) {
            i -= 1;
            const o = vm.pat.ops[i];
            switch (o.code) {
                .lit, .masked => {
                    if (pos < o.len) return .here_fail;
                    pos -= o.len;
                    _ = vm.simple(o, pos) orelse return .here_fail;
                },
                .gapf => {
                    if (pos < o.a) return .here_fail;
                    pos -= o.a;
                },
                .nalt => {
                    const n = o.b & 0xffff;
                    if (pos < n) return .here_fail;
                    pos -= n;
                    for (vm.pat.alternatives(o)) |entry| {
                        if (vm.alternative(entry, pos, nocase(o))) return .here_fail;
                    }
                },
                .alt => {
                    var later = false;
                    for (vm.pat.alternatives(o)) |entry| {
                        if (pos < entry.byte_len) continue;
                        try vm.step();
                        if (!vm.alternative(entry, pos - entry.byte_len, nocase(o))) continue;
                        switch (try vm.bwd(k, i, pos - entry.byte_len)) {
                            .ok => return .ok,
                            .later_fail => later = true,
                            .here_fail => {},
                        }
                    }
                    return if (later) .later_fail else .here_fail;
                },
                .bound => pos -= vm.boundAt(i, pos, true) orelse return .here_fail,
                else => unreachable,
            }
        }
        if (try vm.atPartStart(k, pos)) return .ok;
        return .later_fail;
    }

    /// Part k starts at `pos`: finish the chain towards the start of the match.
    fn atPartStart(vm: *Vm, k: usize, pos: usize) Error!bool {
        if (k == 0) {
            if (pos < vm.window.lo or pos > vm.window.hi) return false;
            if (vm.flags & prog.flag_fullword != 0 and vm.wordBefore(pos)) return false;
            vm.start = pos;
            return true;
        }
        const gap = vm.pat.ops[vm.partEnd(k - 1)];
        if (pos < gap.a or gap.a > gap.b) return false;
        const hi = pos - gap.a; // latest end of part k-1
        const lo = if (gap.b == ir.unbounded or gap.b > pos) 0 else pos - gap.b;
        const last = vm.pat.ops[vm.partEnd(k - 1) - 1];
        const greedy = vm.part_fixed[k - 1] and k - 1 > 0 and vm.pat.ops[vm.partEnd(k - 2)].b == ir.unbounded;
        const dead = &vm.memo.dead_upto[k - 1];
        if (lo == 0 and dead.* != unknown and hi <= dead.*) return false;
        var any_later = false;
        var e = hi;
        while (true) {
            if (last.code == .lit and last.flags & ir.op_nocase == 0) {
                // The part ends with a literal: jump to the previous occurrence of its last byte.
                const byte = vm.pat.bytes(last)[last.len - 1];
                // Ends lie in [lo, e], so the byte sits in [lo - 1, e - 1]; no part ends at 0.
                const base = if (lo == 0) 0 else lo - 1;
                const at = std.mem.lastIndexOfScalar(u8, vm.data[base..e], byte) orelse break;
                e = base + at + 1;
            }
            try vm.step();
            switch (try vm.bwd(k - 1, vm.partEnd(k - 1), e)) {
                .ok => return true,
                .later_fail => {
                    if (greedy) return false;
                    any_later = true;
                },
                .here_fail => {},
            }
            if (e == lo) break;
            e -= 1;
        }
        if (lo == 0 and !any_later) dead.* = if (dead.* == unknown) hi else @max(dead.*, hi);
        return false;
    }
};

/// Verify a candidate: the program's anchor part starting at `anchor_start`.
pub fn verify(p: prog.Program, data: []const u8, window: Window, anchor_start: usize, budget: *Budget) Error!?Match {
    var memo: Memo = .{};
    memo.prepare(p.header.part_count);
    return verifyMemo(p, data, window, anchor_start, budget, &memo);
}

/// `verify` sharing what earlier calls on the same program and data learned.
pub fn verifyMemo(p: prog.Program, data: []const u8, window: Window, anchor_start: usize, budget: *Budget, memo: *Memo) Error!?Match {
    if (anchor_start > data.len) return null;
    std.debug.assert(memo.parts == p.header.part_count);
    var vm = Vm.init(p, data, window, budget, memo);
    const a = p.header.anchor_part;
    try vm.step();
    if (!try vm.atPartStart(a, anchor_start)) return null;
    if (try vm.fwd(a, vm.part_first[a], anchor_start) != .ok) return null;
    return .{ .start = vm.start, .end = vm.end };
}

/// Every match of one program over `data`, in anchor order. Candidates come from memchr on the
/// anchor literal's first byte; a program with no anchor literal tries every position its
/// window allows. This is the reference path the prefilter stages must agree with.
pub const Scanner = struct {
    program: prog.Program,
    data: []const u8,
    window: ?Window,
    budget: *Budget,
    /// Next anchor-literal position to try.
    pos: usize = 0,
    memo: Memo = .{},

    pub fn init(p: prog.Program, data: []const u8, info: FileInfo, budget: *Budget) Scanner {
        var s: Scanner = .{ .program = p, .data = data, .window = startWindow(p.offset(), info), .budget = budget };
        s.memo.prepare(p.header.part_count);
        if (s.window) |w| {
            // The anchor part cannot start before the match does.
            if (p.header.anchor_part == 0) {
                const delta: u64 = if (p.header.anchor_op != prog.no_anchor) p.header.anchor_delta else 0;
                s.pos = @intCast(@min(data.len, w.lo + delta));
            }
        }
        return s;
    }

    pub fn next(s: *Scanner) Error!?Match {
        const w = s.window orelse return null;
        const h = s.program.header;
        const d = s.data;
        // With the anchor in part 0 the anchor must sit inside the start window.
        const bounded = h.anchor_part == 0;
        const limit: usize = if (bounded) @intCast(@min(d.len, w.hi +| (if (h.anchor_op == prog.no_anchor) 0 else h.anchor_delta))) else d.len;
        while (s.pos <= limit and s.pos < d.len + @intFromBool(h.anchor_op == prog.no_anchor)) {
            var anchor_start: usize = undefined;
            if (h.anchor_op != prog.no_anchor) {
                const o = s.program.pattern.ops[h.anchor_op];
                const at = if (o.flags & ir.op_nocase == 0)
                    std.mem.indexOfScalarPos(u8, d[0..@min(d.len, limit + 1)], s.pos, s.program.pattern.bytes(o)[0]) orelse return null
                else
                    s.pos;
                s.pos = at + 1;
                if (at < h.anchor_delta) continue;
                anchor_start = at - h.anchor_delta;
            } else {
                anchor_start = s.pos;
                s.pos += 1;
            }
            const got = verifyMemo(s.program, d, w, anchor_start, s.budget, &s.memo) catch |err| {
                // One candidate ran out of its own budget: it is recorded (budget.exhausted) and
                // the scan goes on. The file budget running out ends the scan.
                if (s.budget.used >= s.budget.per_file) return err;
                continue;
            };
            if (got) |m| return m;
        }
        return null;
    }
};

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

const testing = std.testing;
const hexsig = @import("../compile/hexsig.zig");
const prog_build = @import("../compile/prog_build.zig");

const Built = struct {
    arena: std.heap.ArenaAllocator,
    progs: prog.Programs,

    fn deinit(b: *Built) void {
        b.arena.deinit();
    }
};

fn compile(inputs: []const struct { body: []const u8, offset: ir.Offset = .{}, flags: u8 = 0, mods: ir.Modifiers = .{} }) !Built {
    var b: Built = .{ .arena = .init(testing.allocator), .progs = undefined };
    errdefer b.arena.deinit();
    const a = b.arena.allocator();
    var list: std.ArrayList(prog_build.Input) = .empty;
    for (inputs, 0..) |in, i| {
        var diag: hexsig.Diag = .{};
        const pat = try hexsig.parse(a, in.body, &diag);
        for (try hexsig.expand(a, pat, in.mods)) |v| {
            var flags = in.flags;
            if (v.folded) flags |= prog.flag_folded;
            try list.append(a, .{ .pattern = v.pattern, .offset = in.offset, .sig = @intCast(i), .flags = flags });
        }
    }
    const bytes = try prog_build.build(a, list.items);
    const aligned = try a.alignedAlloc(u8, .@"4", bytes.len);
    @memcpy(aligned, bytes);
    b.progs = try prog.Programs.init(aligned);
    return b;
}

/// First match of any program (variant) of the compiled body over `data`.
fn firstMatch(body: []const u8, mods: ir.Modifiers, flags: u8, offset: ir.Offset, info: FileInfo, data: []const u8) !?Match {
    var b = try compile(&.{.{ .body = body, .offset = offset, .flags = flags, .mods = mods }});
    defer b.deinit();
    var best: ?Match = null;
    for (0..b.progs.count()) |i| {
        var budget: Budget = .{};
        var s = Scanner.init(b.progs.get(i), data, info, &budget);
        if (try s.next()) |m| {
            if (best == null or m.start < best.?.start) best = m;
        }
    }
    return best;
}

fn matches(body: []const u8, data: []const u8) !bool {
    return (try firstMatch(body, .{}, 0, .{}, .{ .size = data.len }, data)) != null;
}

test "literals, nibbles and negations" {
    try testing.expect(try matches("414243", "xxABCxx"));
    try testing.expect(!try matches("414243", "xxABxCx"));
    try testing.expect(try matches("41??43", "A-C"));
    try testing.expect(try matches("414?43", "AOC"));
    try testing.expect(!try matches("414?43", "A C"));
    try testing.expect(try matches("41?343", "AsC"));
    try testing.expect(try matches("41~4243", "AxC"));
    try testing.expect(!try matches("41~4243", "ABC"));
    try testing.expect(try matches("41~4?43", "A C"));
    try testing.expect(!try matches("41~4?43", "AOC"));
    try testing.expect(try matches("41{3}45", "AbcdE"));
    try testing.expect(!try matches("41{3}45", "AbcE"));
}

test "part windows: star, ranges, exact and brackets" {
    try testing.expect(try matches("4142*4344", "AB.........CD"));
    try testing.expect(try matches("4142*4344", "ABCD"));
    try testing.expect(!try matches("4142*4344", "CD AB"));
    try testing.expect(try matches("4142{2-4}4344", "AB..CD"));
    try testing.expect(try matches("4142{2-4}4344", "AB....CD"));
    try testing.expect(!try matches("4142{2-4}4344", "AB.CD"));
    try testing.expect(!try matches("4142{2-4}4344", "AB.....CD"));
    try testing.expect(try matches("4142{-2}4344", "ABCD"));
    try testing.expect(!try matches("4142{-2}4344", "AB...CD"));
    try testing.expect(try matches("4142{3-}4344", "AB...CD"));
    try testing.expect(!try matches("4142{3-}4344", "AB..CD"));
    try testing.expect(try matches("41[1-2]4344", "A.CD"));
    try testing.expect(!try matches("41[1-2]4344", "ACD"));
    var long: [300]u8 = @splat('.');
    long[0] = 'A';
    long[1] = 'B';
    long[130] = 'C';
    long[131] = 'D';
    try testing.expect(try matches("4142{128}4344", &long));
    try testing.expect(!try matches("4142{129}4344", &long));
    // Each window applies independently between neighbours.
    try testing.expect(try matches("41{1-2}42{1-2}43", "A.B..C"));
    try testing.expect(!try matches("41{1-2}42{1-2}43", "A...B.C"));
}

test "backtracking over earlier occurrences and alternations" {
    // The first "AB" is too far from "CD"; the second one works.
    try testing.expect(try matches("4142{0-1}4344", "AB....ABxCD"));
    try testing.expect(try matches("41(42|4243)44", "ABCD"));
    try testing.expect(try matches("41(4243|42)43", "ABC"));
    try testing.expect(try matches("41(42|43)44", "ACD"));
    try testing.expect(!try matches("41(42|43)44", "AXD"));
    try testing.expect(try matches("41!(42|43)44", "AXD"));
    try testing.expect(!try matches("41!(42|43)44", "ABD"));
    try testing.expect(try matches("41!(4243|4445)46", "AXYF"));
    try testing.expect(!try matches("41!(4243|4445)46", "ABCF"));
    try testing.expect(try matches("41(4?|{2}5a)46", "AxyZF"));
    // Anchor in a later part, earlier parts found backwards.
    try testing.expect(try matches("41*42{2}434445464748", "A..xB..CDEFGH"));
    try testing.expect(!try matches("41*42{2}434445464748", "..xB..CDEFGHA"));
}

test "character classes" {
    // At the edges anchors are zero-width lookarounds with libclamav's byte sets; the start and
    // end of the data satisfy them. In the middle they consume one byte.
    try testing.expect(try matches("(B)41424344(B)", "ABCD"));
    try testing.expect(try matches("(B)41424344(B)", "x ABCD>"));
    try testing.expect(!try matches("(B)41424344(B)", "x ABCD."));
    try testing.expect(!try matches("(B)41424344(B)", "xABCD>"));
    try testing.expect(try matches("(B)41424344(B)", "x.ABCD\r"));
    try testing.expect(!try matches("(B)41424344(B)", "x\rABCD\r"));
    try testing.expect(try matches("41424344(L)", "ABCD\r\nE"));
    try testing.expect(!try matches("41424344(L)", "ABCD\rE"));
    try testing.expect(try matches("(L)41424344", "x\nABCD"));
    try testing.expect(!try matches("(L)41424344", "x\rABCD"));
    try testing.expect(try matches("41424344(L)45", "ABCD\nE"));
    try testing.expect(!try matches("41424344(L)45", "ABCD\r\nE"));
    try testing.expect(!try matches("41424344(L)45", "ABCD E"));
    try testing.expect(try matches("41424344(W)45", "ABCD-E"));
    try testing.expect(!try matches("41424344(W)45", "ABCDzE"));
    try testing.expect(try matches("41424344(B)45", "ABCD.E"));
    try testing.expect(!try matches("41424344(B)45", "ABCD,E"));
    // Zero-width at the edges: the match is the bytes between the boundaries.
    const m = (try firstMatch("(B)41424344(B)", .{}, 0, .{}, .{ .size = 7 }, "x ABCD ")).?;
    try testing.expectEqual(@as(usize, 2), m.start);
    try testing.expectEqual(@as(usize, 6), m.end);
}

test "modifiers: nocase, wide, ascii, fullword" {
    const Case = struct { []const u8, ir.Modifiers, u8, []const u8, bool };
    for ([_]Case{
        .{ "68656c6c6f", .{ .nocase = true }, 0, "say HeLLo", true },
        .{ "68656c6c6f", .{}, 0, "say HeLLo", false },
        .{ "6162636465666768", .{ .nocase = true }, 0, "xABCDefgHx", true }, // folded, not expanded
        .{ "616263", .{ .wide = true }, 0, "a\x00b\x00c\x00", true },
        .{ "616263", .{ .wide = true }, 0, "abc", false },
        .{ "616263", .{ .wide = true, .ascii = true }, 0, "abc", true },
        .{ "616263", .{}, prog.flag_fullword, "x abc.", true },
        .{ "616263", .{}, prog.flag_fullword, "xabc.", false },
        .{ "616263", .{}, prog.flag_fullword, "abc", true },
        .{ "616263", .{}, prog.flag_fullword, "abcd", false },
    }) |c| {
        const got = try firstMatch(c[0], c[1], c[2], .{}, .{ .size = c[3].len }, c[3]);
        try testing.expectEqual(c[4], got != null);
    }
    // Wide fullword checks the neighbouring 16-bit units.
    const wide_flags = prog.flag_fullword | prog.flag_wide;
    var b = try compile(&.{.{ .body = "610062006300", .flags = wide_flags }});
    defer b.deinit();
    var budget: Budget = .{};
    const data = "x\x00a\x00b\x00c\x00";
    var s = Scanner.init(b.progs.get(0), data, .{ .size = data.len }, &budget);
    try testing.expect(try s.next() == null);
    const ok = " \x00a\x00b\x00c\x00!\x00";
    s = Scanner.init(b.progs.get(0), ok, .{ .size = ok.len }, &budget);
    try testing.expect(try s.next() != null);
}

test "offset kinds resolve against the file" {
    const data = "MZ..ABCD....EFGH..XYZW";
    const info: FileInfo = .{ .size = data.len, .entry_point = 4, .sections = &.{ .{ .offset = 4, .size = 8 }, .{ .offset = 12, .size = 6 } } };
    const Case = struct { []const u8, ir.Offset, bool };
    for ([_]Case{
        .{ "41424344", .{ .kind = .absolute, .a = 4 }, true },
        .{ "41424344", .{ .kind = .absolute, .a = 3 }, false },
        .{ "41424344", .{ .kind = .absolute, .a = 2, .shift = 2 }, true },
        .{ "41424344", .{ .kind = .absolute, .a = 1, .shift = 2 }, false },
        .{ "58595a57", .{ .kind = .eof_minus, .a = 4 }, true },
        .{ "58595a57", .{ .kind = .eof_minus, .a = 5 }, false },
        .{ "41424344", .{ .kind = .entry_point, .a = 0 }, true },
        .{ "45464748", .{ .kind = .entry_point, .a = 8 }, true },
        .{ "4d5a", .{ .kind = .entry_point, .a = -4 }, true },
        .{ "45464748", .{ .kind = .section_start, .section = 1, .a = 0 }, true },
        .{ "45464748", .{ .kind = .section_start, .section = 2, .a = 0 }, false },
        .{ "45464748", .{ .kind = .last_section, .a = 0 }, true },
        .{ "4344", .{ .kind = .section_entire, .section = 0 }, true },
        // libclamav: a start up to one past the section's last byte, and the match may run on.
        .{ "4546", .{ .kind = .section_entire, .section = 0 }, true },
        .{ "4748", .{ .kind = .section_entire, .section = 0 }, false },
        .{ "47482e2e58", .{ .kind = .section_entire, .section = 1 }, true },
        .{ "4142*4546", .{ .kind = .absolute, .a = 4 }, true },
    }) |c| {
        const got = try firstMatch(c[0], .{}, 0, c[1], info, data);
        try testing.expectEqual(c[2], got != null);
    }
    // No entry point: EP signatures cannot apply.
    try testing.expect(try firstMatch("41424344", .{}, 0, .{ .kind = .entry_point }, .{ .size = data.len }, data) == null);
    // The reported match covers every part.
    const m = (try firstMatch("4142*4546", .{}, 0, .{}, info, data)).?;
    try testing.expectEqual(@as(usize, 4), m.start);
    try testing.expectEqual(@as(usize, 14), m.end);
}

test "scanner yields every occurrence" {
    var b = try compile(&.{.{ .body = "6161" }});
    defer b.deinit();
    var budget: Budget = .{};
    const data = "aaxaaa";
    var s = Scanner.init(b.progs.get(0), data, .{ .size = data.len }, &budget);
    var starts: [4]usize = undefined;
    var n: usize = 0;
    while (try s.next()) |m| : (n += 1) starts[n] = m.start;
    try testing.expectEqualSlices(usize, &.{ 0, 3, 4 }, starts[0..n]);
}

test "adversarial inputs stop at the budget and say so" {
    // Many '*' parts over data that has every byte but the last literal: exponential without
    // the budget. The greedy rule keeps the common case linear; the budget bounds the rest.
    var b = try compile(&.{.{ .body = "61{0-200}61{0-200}61{0-200}61{0-200}62" }});
    defer b.deinit();
    const data: [4096]u8 = @splat('a');
    var budget: Budget = .{ .per_verify = 1000, .per_file = 5000 };
    var s = Scanner.init(b.progs.get(0), &data, .{ .size = data.len }, &budget);
    try testing.expectError(error.BudgetExhausted, s.next());
    try testing.expect(budget.exhausted);
    try testing.expect(budget.used <= budget.per_file);

    // Unbounded gaps with fixed parts are linear thanks to the greedy rule: no limit hit.
    var g = try compile(&.{.{ .body = "6161*6161*6161*6162" }});
    defer g.deinit();
    var budget2: Budget = .{ .per_verify = 4096, .per_file = 1 << 20 };
    var s2 = Scanner.init(g.progs.get(0), &data, .{ .size = data.len }, &budget2);
    try testing.expect(try s2.next() == null);
    try testing.expect(!budget2.exhausted);
}
