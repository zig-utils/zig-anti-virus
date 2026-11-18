//! The stage-one kernel: sampled gram probes into a partition's split-block Bloom filters with
//! no loop-carried dependency (docs/DESIGN.md 5, P4.05).
//!
//! Sixteen positions at a time: one 32-byte load and a comptime shuffle into sixteen 4-byte
//! grams. The sampled filters (strides 8, 4, 3 and 2) hash the lanes their strides land on in
//! one vector and test them with scalar block loads; every test sets one bit of a mask and the
//! rare hits are appended to the candidate ring afterwards, so no test waits for the ring
//! position of the one before it. Stride 3 does not divide 16, so with it the loop steps 48
//! positions at a time, three loads whose sampled lanes differ.
//!
//! The stride-one filters (short atoms: 4-byte windows and tier D) would cost a block test per
//! byte, so a 64 KiB gate indexed by each position's first two bytes runs first, one byte load
//! per position, and the positions it passes are collected without a branch. They are tested
//! in one pass per batch, against the filters the gate names, without a branch on the names:
//! a pass costs a few block tests on filters that sit in L1, not two mispredicted branches.
//! Every filter of a partition shares one seed. A full ring (or the end of the data) returns
//! to the caller for stage two.
//!
//! The sampled filter set is fixed per partition, so the loop is specialised at comptime for
//! each combination of sampled strides present and for whether any stride-one filter exists.
const std = @import("std");
const regex = @import("regex");
const sbbf = regex.literals.sbbf;
const pf = @import("prefilter.zig");

const lanes = 16;
/// Gate passes collected before they are tested.
const pass_cap = 256;

/// Filter kinds, in the order `Idx` holds their indices.
const k_s8 = 0;
const k_s4 = 1;
const k_s3 = 2;
const k_s2 = 3;
const k_s1 = 4;
const k_q3 = 5;
const k_q2 = 6;
const kinds = 7;

/// The sampled strides present, and whether any gated filter is.
const Config = packed struct(u5) { s8: bool, s4: bool, s3: bool, s2: bool, gated: bool };
/// Filter index by kind.
const Idx = [kinds]u8;

fn kindOf(f: pf.Filter) usize {
    if (f.q == 3) return k_q3;
    if (f.q == 2) return k_q2;
    return switch (f.stride) {
        8 => k_s8,
        4 => k_s4,
        3 => k_s3,
        2 => k_s2,
        else => k_s1,
    };
}

pub fn run(part: *const pf.Partition, data: []const u8, start: usize, ring: *[pf.ring_len]pf.Candidate) struct { usize, usize } {
    var idx: Idx = @splat(0);
    var present: [kinds]bool = @splat(false);
    for (part.filters[0..part.filter_count], 0..) |f, i| {
        const k = kindOf(f);
        idx[k] = @intCast(i);
        present[k] = true;
    }
    const cfg: Config = .{ .s8 = present[k_s8], .s4 = present[k_s4], .s3 = present[k_s3], .s2 = present[k_s2], .gated = present[k_s1] or present[k_q3] or present[k_q2] };
    return switch (@as(u5, @bitCast(cfg))) {
        inline else => |bits| loop(@bitCast(bits), part, idx, present, data, start, ring),
    };
}

inline fn testBlock(blocks: []const sbbf.Block, h: u32) bool {
    const blk: @Vector(8, u32) = blocks[sbbf.blockIndex(h, @intCast(blocks.len))];
    const m = sbbf.masks(h);
    return @reduce(.Or, m & ~blk) == 0;
}

/// Blocks of a filter that may be absent: a single empty block, which no gram passes, so
/// absent gated filters cost a test and never a branch.
const no_blocks = [1]sbbf.Block{@splat(0)};

fn loop(comptime cfg: Config, part: *const pf.Partition, idx: Idx, present: [kinds]bool, data: []const u8, start: usize, ring: *[pf.ring_len]pf.Candidate) struct { usize, usize } {
    const seed = part.seed;
    var blocks: [kinds][]const sbbf.Block = undefined;
    for (&blocks, present, idx) |*b, p, x| b.* = if (p) part.filters[x].sbbf.blocks else &no_blocks;
    const gate = part.gate;
    const width = comptime stepWidth(cfg);
    const subs = width / lanes;
    // Per 16-position sub-step: the lanes hashed, and each sampled test's hashed lane and
    // filter kind.
    const plan = comptime blk: {
        var p: [subs]SubStep = undefined;
        for (&p, 0..) |*s, k| s.* = subStep(cfg, k);
        break :blk p;
    };
    var test_filter: [subs][max_tests]u8 = undefined;
    inline for (plan, 0..) |s, k| inline for (s.tests[0..s.count], 0..) |t, x| {
        test_filter[k][x] = idx[t.kind];
    };
    const tests_per_step = comptime blk: {
        var c: usize = 0;
        for (plan) |s| c += s.count;
        break :blk c;
    };
    const gated: usize = if (cfg.gated) @as(usize, @intFromBool(present[k_s1])) + @intFromBool(present[k_q3]) + @intFromBool(present[k_q2]) else 0;
    var n: usize = 0;
    var i = start;
    // An unaligned start (a resumed scalar run): one position at a time up to a step boundary.
    while (i % width != 0 and i < data.len and n + kinds <= pf.ring_len) : (i += 1) n = scalarAt(cfg, idx, present, seed, blocks, gate, data, i, ring, n);
    if (i % width == 0) {
        // Positions the gate passed, as offsets from `base`, tested once per batch.
        var passes: [pass_cap]u32 = undefined;
        while (true) {
            var np: usize = 0;
            const base = i;
            while (i + width + lanes <= data.len and n + tests_per_step + gated * (np + width) <= pf.ring_len and np + width <= pass_cap) : (i += width) {
                inline for (plan, 0..) |sub, k| {
                    const at = i + k * lanes;
                    if (comptime sub.count > 0) {
                        const v: @Vector(32, u8) = data[at..][0..32].*;
                        const bytes: @Vector(lanes * 4, u8) = @shuffle(u8, v, undefined, gram_mask);
                        const grams: @Vector(lanes, u32) = @bitCast(bytes);
                        const hashed = comptime sub.hashed[0..sub.hashed_count].*;
                        const hs: [hashed.len]u32 = sbbf.hash(@as(@Vector(hashed.len, u32), @shuffle(u32, grams, undefined, hashed)), seed);
                        var hit: u32 = 0;
                        inline for (sub.tests[0..sub.count], 0..) |t, x| hit |= @as(u32, @intFromBool(testBlock(blocks[t.kind], hs[t.h]))) << x;
                        while (hit != 0) : (hit &= hit - 1) {
                            const x = @ctz(hit);
                            ring[n] = .{ .pos = @intCast(at + sub.lane_of[x]), .filter = test_filter[k][x] };
                            n += 1;
                        }
                    }
                    // The gate, read with each position's two bytes straight from memory; the
                    // positions it passes are appended without a branch.
                    if (cfg.gated) inline for (0..lanes) |j| {
                        passes[np] = @intCast(at + j - base);
                        np += @intFromBool(gate[std.mem.readInt(u16, data[at + j ..][0..2], .little)] != 0);
                    };
                }
            }
            // The passed positions, each tested against every stride-one filter, kept where
            // its gate flags name the filter.
            if (cfg.gated) for (passes[0..np]) |off| {
                const p = base + off;
                const pos: u56 = @intCast(p);
                const g = pf.load4(data, p);
                const flags = gate[@as(u16, @truncate(g))];
                if (present[k_s1]) {
                    ring[n] = .{ .pos = pos, .filter = idx[k_s1] };
                    n += @intFromBool(flags & pf.gate_s1 != 0) & @intFromBool(testBlock(blocks[k_s1], sbbf.hash(g, seed)));
                }
                if (present[k_q3]) {
                    ring[n] = .{ .pos = pos, .filter = idx[k_q3] };
                    n += @intFromBool(flags & pf.gate_q3 != 0) & @intFromBool(testBlock(blocks[k_q3], sbbf.hash(g & 0xff_ffff, seed)));
                }
                if (present[k_q2]) {
                    ring[n] = .{ .pos = pos, .filter = idx[k_q2] };
                    n += @intFromBool(flags & pf.gate_q2 != 0) & @intFromBool(testBlock(blocks[k_q2], sbbf.hash(g & 0xffff, seed)));
                }
            };
            if (i + width + lanes > data.len) break;
            // The ring is nearly full: back to stage two.
            if (n + tests_per_step + gated * width > pf.ring_len) return .{ n, i };
        }
    }
    // The last positions: one at a time.
    while (i < data.len and n + kinds <= pf.ring_len) : (i += 1) n = scalarAt(cfg, idx, present, seed, blocks, gate, data, i, ring, n);
    return .{ n, i };
}

/// One position, the way the vector loop treats it: the sampled filters directly, the
/// stride-one ones only when the gate names them.
inline fn scalarAt(comptime cfg: Config, idx: Idx, present: [kinds]bool, seed: u32, blocks: [kinds][]const sbbf.Block, gate: []const u8, data: []const u8, i: usize, ring: *[pf.ring_len]pf.Candidate, n_in: usize) usize {
    var n = n_in;
    const pos: u56 = @intCast(i);
    const flags: u8 = if (cfg.gated and i + 2 <= data.len) gate[std.mem.readInt(u16, data[i..][0..2], .little)] else 0;
    if (present[k_q2] and flags & pf.gate_q2 != 0) {
        const g = @as(u32, data[i]) | @as(u32, data[i + 1]) << 8;
        ring[n] = .{ .pos = pos, .filter = idx[k_q2] };
        n += @intFromBool(testBlock(blocks[k_q2], sbbf.hash(g, seed)));
    }
    if (present[k_q3] and flags & pf.gate_q3 != 0 and i + 3 <= data.len) {
        const g = @as(u32, data[i]) | @as(u32, data[i + 1]) << 8 | @as(u32, data[i + 2]) << 16;
        ring[n] = .{ .pos = pos, .filter = idx[k_q3] };
        n += @intFromBool(testBlock(blocks[k_q3], sbbf.hash(g, seed)));
    }
    if (i + 4 > data.len) return n;
    const h = sbbf.hash(pf.load4(data, i), seed);
    inline for ([_]struct { on: bool, s: usize, k: usize }{
        .{ .on = cfg.s8, .s = 8, .k = k_s8 },
        .{ .on = cfg.s4, .s = 4, .k = k_s4 },
        .{ .on = cfg.s3, .s = 3, .k = k_s3 },
        .{ .on = cfg.s2, .s = 2, .k = k_s2 },
    }) |f| if (f.on and i % f.s == 0) {
        ring[n] = .{ .pos = pos, .filter = idx[f.k] };
        n += @intFromBool(testBlock(blocks[f.k], h));
    };
    if (present[k_s1] and flags & pf.gate_s1 != 0) {
        ring[n] = .{ .pos = pos, .filter = idx[k_s1] };
        n += @intFromBool(testBlock(blocks[k_s1], h));
    }
    return n;
}

/// Positions per vector step: 48 with stride 3 (the least multiple of 16 it divides), else 16.
fn stepWidth(comptime cfg: Config) usize {
    return if (cfg.s3) 48 else lanes;
}

const max_tests = 32;

const Test = struct { h: u8, kind: u8 };

/// What one 16-position sub-step of a vector step samples.
const SubStep = struct {
    /// Lanes hashed, in order.
    hashed: [lanes]i32 = undefined,
    hashed_count: usize = 0,
    tests: [max_tests]Test = undefined,
    /// The lane each test reads.
    lane_of: [max_tests]u8 = undefined,
    count: usize = 0,
};

/// Sub-step `k` covers positions `16k .. 16k + 15` of the step: every lane some sampled
/// stride lands on is hashed once and tested against each filter whose stride it is a
/// multiple of.
fn subStep(comptime cfg: Config, comptime k: usize) SubStep {
    var s: SubStep = .{};
    for (0..lanes) |j| {
        const p = k * lanes + j;
        var any = false;
        for ([_]struct { on: bool, st: usize, kind: u8 }{
            .{ .on = cfg.s8, .st = 8, .kind = k_s8 },
            .{ .on = cfg.s4, .st = 4, .kind = k_s4 },
            .{ .on = cfg.s3, .st = 3, .kind = k_s3 },
            .{ .on = cfg.s2, .st = 2, .kind = k_s2 },
        }) |f| if (f.on and p % f.st == 0) {
            if (!any) {
                s.hashed[s.hashed_count] = j;
                s.hashed_count += 1;
                any = true;
            }
            s.tests[s.count] = .{ .h = s.hashed_count - 1, .kind = f.kind };
            s.lane_of[s.count] = j;
            s.count += 1;
        };
    }
    return s;
}

/// Lane k of the shuffled vector holds bytes k..k+3 of the 32-byte load.
const gram_mask = blk: {
    var m: [lanes * 4]i32 = undefined;
    for (0..lanes) |k| {
        for (0..4) |j| m[k * 4 + j] = @intCast(k + j);
    }
    break :blk m;
};
