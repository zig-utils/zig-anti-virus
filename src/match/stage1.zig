//! The stage-one kernel: sampled gram probes into a partition's split-block Bloom filters with
//! no loop-carried dependency (docs/DESIGN.md 5, P4.05).
//!
//! Sixteen positions at a time: one 32-byte load and a comptime shuffle into sixteen 4-byte
//! grams. The sampled filters (strides 8 and 4) hash their four lanes in one vector and test
//! them with scalar block loads, writing every tested lane to the candidate ring and advancing
//! the count by the result, so they have no data-dependent branches. The stride-one filters
//! (short atoms of tiers C and D) would cost a block test per byte, so a 64 KiB gate indexed by
//! each position's first two bytes runs first, one byte load per lane, and only the lanes it
//! passes are hashed and tested, against only the filters the gate names. Every filter of a partition shares one seed. A full ring (or
//! the end of the data) returns to the caller for stage two.
//!
//! The filter set is fixed per partition, so the loop is specialised at comptime for each
//! combination of strides present (8, 4, 1 and the 3-gram and 2-gram filters).
const std = @import("std");
const regex = @import("regex");
const sbbf = regex.literals.sbbf;
const pf = @import("prefilter.zig");

const lanes = 16;
/// Ring slots one 16-position step can fill.
const per_step = 5 * lanes;

const Config = packed struct(u5) { s8: bool, s4: bool, s1: bool, q3: bool, q2: bool };

pub fn run(part: *const pf.Partition, data: []const u8, start: usize, ring: *[pf.ring_len]pf.Candidate) struct { usize, usize } {
    var idx: [5]u8 = @splat(0);
    var cfg: Config = .{ .s8 = false, .s4 = false, .s1 = false, .q3 = false, .q2 = false };
    for (part.filters[0..part.filter_count], 0..) |f, i| {
        if (f.q == 3) {
            cfg.q3 = true;
            idx[3] = @intCast(i);
        } else if (f.q == 2) {
            cfg.q2 = true;
            idx[4] = @intCast(i);
        } else switch (f.stride) {
            8 => {
                cfg.s8 = true;
                idx[0] = @intCast(i);
            },
            4 => {
                cfg.s4 = true;
                idx[1] = @intCast(i);
            },
            else => {
                cfg.s1 = true;
                idx[2] = @intCast(i);
            },
        }
    }
    return switch (@as(u5, @bitCast(cfg))) {
        inline else => |bits| loop(@bitCast(bits), part, idx, data, start, ring),
    };
}

inline fn testBlock(blocks: []const sbbf.Block, h: u32) bool {
    const blk: @Vector(8, u32) = blocks[sbbf.blockIndex(h, @intCast(blocks.len))];
    const m = sbbf.masks(h);
    return @reduce(.Or, m & ~blk) == 0;
}

fn loop(comptime cfg: Config, part: *const pf.Partition, idx: [5]u8, data: []const u8, start: usize, ring: *[pf.ring_len]pf.Candidate) struct { usize, usize } {
    const seed = part.seed;
    const b8 = if (cfg.s8) part.filters[idx[0]].sbbf.blocks else &.{};
    const b4 = if (cfg.s4) part.filters[idx[1]].sbbf.blocks else &.{};
    const b1 = if (cfg.s1) part.filters[idx[2]].sbbf.blocks else &.{};
    const b3 = if (cfg.q3) part.filters[idx[3]].sbbf.blocks else &.{};
    const b2 = if (cfg.q2) part.filters[idx[4]].sbbf.blocks else &.{};
    const gate = part.gate;
    var n: usize = 0;
    var i = start;
    // An unaligned start (a resumed scalar run): one position at a time up to a lane boundary.
    while (i % lanes != 0 and i < data.len and n + 5 <= pf.ring_len) : (i += 1) n = scalarAt(cfg, idx, seed, .{ b8, b4, b1, b3, b2 }, data, i, ring, n);
    if (i % lanes == 0) {
        while (i + 32 <= data.len and n + per_step <= pf.ring_len) : (i += lanes) {
            const v: @Vector(32, u8) = data[i..][0..32].*;
            const bytes: @Vector(lanes * 4, u8) = @shuffle(u8, v, undefined, gram_mask);
            const grams: @Vector(lanes, u32) = @bitCast(bytes);
            // Sampled filters: the lanes their strides land on, hashed together.
            if (cfg.s8 or cfg.s4) {
                const sampled: @Vector(4, u32) = @shuffle(u32, grams, undefined, [4]i32{ 0, 4, 8, 12 });
                const hs: [4]u32 = sbbf.hash(sampled, seed);
                inline for (0..4) |k| {
                    const pos: u56 = @intCast(i + 4 * k);
                    if (cfg.s8 and k % 2 == 0) {
                        ring[n] = .{ .pos = pos, .filter = idx[0] };
                        n += @intFromBool(testBlock(b8, hs[k]));
                    }
                    if (cfg.s4) {
                        ring[n] = .{ .pos = pos, .filter = idx[1] };
                        n += @intFromBool(testBlock(b4, hs[k]));
                    }
                }
            }
            // Stride-one filters, behind the gate: most positions start no stride-one gram.
            // The gate is read with the position's two bytes straight from memory, and the
            // positions it passes are appended without a branch, then tested.
            if (cfg.s1 or cfg.q3 or cfg.q2) {
                var passed: [lanes]u8 = undefined;
                var m: usize = 0;
                inline for (0..lanes) |j| {
                    passed[m] = j;
                    m += @intFromBool(gate[std.mem.readInt(u16, data[i + j ..][0..2], .little)] != 0);
                }
                const g: [lanes]u32 = grams;
                for (passed[0..m]) |j| {
                    const pos: u56 = @intCast(i + j);
                    const flags = gate[@as(u16, @truncate(g[j]))];
                    if (cfg.s1 and flags & pf.gate_s1 != 0) {
                        ring[n] = .{ .pos = pos, .filter = idx[2] };
                        n += @intFromBool(testBlock(b1, sbbf.hash(g[j], seed)));
                    }
                    if (cfg.q3 and flags & pf.gate_q3 != 0) {
                        ring[n] = .{ .pos = pos, .filter = idx[3] };
                        n += @intFromBool(testBlock(b3, sbbf.hash(g[j] & 0xff_ffff, seed)));
                    }
                    if (cfg.q2 and flags & pf.gate_q2 != 0) {
                        ring[n] = .{ .pos = pos, .filter = idx[4] };
                        n += @intFromBool(testBlock(b2, sbbf.hash(g[j] & 0xffff, seed)));
                    }
                }
            }
        }
        if (i + 32 <= data.len) return .{ n, i };
    }
    // The last positions: one at a time.
    while (i < data.len and n + 5 <= pf.ring_len) : (i += 1) n = scalarAt(cfg, idx, seed, .{ b8, b4, b1, b3, b2 }, data, i, ring, n);
    return .{ n, i };
}

inline fn scalarAt(comptime cfg: Config, idx: [5]u8, seed: u32, blocks: [5][]const sbbf.Block, data: []const u8, i: usize, ring: *[pf.ring_len]pf.Candidate, n_in: usize) usize {
    var n = n_in;
    const pos: u56 = @intCast(i);
    if (cfg.q2 and i + 2 <= data.len) {
        const g = @as(u32, data[i]) | @as(u32, data[i + 1]) << 8;
        ring[n] = .{ .pos = pos, .filter = idx[4] };
        n += @intFromBool(testBlock(blocks[4], sbbf.hash(g, seed)));
    }
    if (cfg.q3 and i + 3 <= data.len) {
        const g = @as(u32, data[i]) | @as(u32, data[i + 1]) << 8 | @as(u32, data[i + 2]) << 16;
        ring[n] = .{ .pos = pos, .filter = idx[3] };
        n += @intFromBool(testBlock(blocks[3], sbbf.hash(g, seed)));
    }
    if (i + 4 > data.len) return n;
    const h = sbbf.hash(pf.load4(data, i), seed);
    if (cfg.s8 and i % 8 == 0) {
        ring[n] = .{ .pos = pos, .filter = idx[0] };
        n += @intFromBool(testBlock(blocks[0], h));
    }
    if (cfg.s4 and i % 4 == 0) {
        ring[n] = .{ .pos = pos, .filter = idx[1] };
        n += @intFromBool(testBlock(blocks[1], h));
    }
    if (cfg.s1) {
        ring[n] = .{ .pos = pos, .filter = idx[2] };
        n += @intFromBool(testBlock(blocks[2], h));
    }
    return n;
}

/// Lane k of the shuffled vector holds bytes k..k+3 of the 32-byte load.
const gram_mask = blk: {
    var m: [lanes * 4]i32 = undefined;
    for (0..lanes) |k| {
        for (0..4) |j| m[k * 4 + j] = @intCast(k + j);
    }
    break :blk m;
};
