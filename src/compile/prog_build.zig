//! Serialises verify programs into a SUBSIG_PROG section (layout in match/prog.zig) and picks
//! each program's anchor: the longest literal whose distance from its part's start is fixed.
const std = @import("std");
const ir = @import("ir.zig");
const prog = @import("../match/prog.zig");

pub const Input = struct {
    pattern: ir.Pattern,
    offset: ir.Offset = .{},
    target: u8 = 0,
    sig: u32,
    subsig: u16 = 0,
    flags: u8 = 0,
};

pub const Anchor = struct { part: u8 = 0, op: u16 = prog.no_anchor, delta: u16 = prog.no_anchor };

/// The longest literal with a fixed distance from its part's start (the earliest on ties).
/// Programs with an offset are verified from where the match starts, so `part0_only` keeps
/// their anchor in the first part.
pub fn chooseAnchor(p: ir.Pattern, part0_only: bool) Anchor {
    var best: Anchor = .{};
    var best_len: u16 = 0;
    var part: usize = 0;
    var delta: ?u32 = 0;
    for (p.ops, 0..) |o, i| {
        switch (o.code) {
            .part_end => {
                if (part0_only) break;
                part += 1;
                delta = 0;
                continue;
            },
            .lit => if (delta) |d| if (o.len > best_len and d < prog.no_anchor) {
                best = .{ .part = @intCast(part), .op = @intCast(i), .delta = @intCast(d) };
                best_len = o.len;
            },
            else => {},
        }
        if (delta) |d| delta = switch (o.code) {
            .lit, .masked => d + o.len,
            .gapf => d + o.a,
            .nalt => d + (o.b & 0xffff),
            .alt => if (o.b & 0xffff == o.b >> 16) d + (o.b & 0xffff) else null,
            else => null,
        };
    }
    return best;
}

/// Shortest possible match length (saturating).
pub fn minLen(p: ir.Pattern) u32 {
    var n: u32 = 0;
    for (p.ops) |o| n +|= switch (o.code) {
        .lit, .masked => o.len,
        .gapf => o.a,
        .alt, .nalt => o.b & 0xffff,
        .part_end => o.a,
        else => 0,
    };
    return n;
}

/// The section bytes for `inputs`, in order: program i is input i.
pub fn build(gpa: std.mem.Allocator, inputs: []const Input) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const header: prog.SectionHeader = .{ .count = @intCast(inputs.len) };
    try out.appendSlice(gpa, std.mem.asBytes(&header));
    try out.appendNTimes(gpa, 0, inputs.len * 4);
    for (inputs, 0..) |in, i| {
        while (out.items.len % 4 != 0) try out.append(gpa, 0);
        std.mem.writeInt(u32, out.items[@sizeOf(prog.SectionHeader) + i * 4 ..][0..4], @intCast(out.items.len), .little);
        const anchor = chooseAnchor(in.pattern, in.offset.kind != .any);
        const h: prog.ProgHeader = .{
            .sig = in.sig,
            .subsig = in.subsig,
            .target = in.target,
            .flags = in.flags,
            .off_kind = in.offset.kind,
            .anchor_part = anchor.part,
            .off_section = in.offset.section,
            .off_a = in.offset.a,
            .off_shift = in.offset.shift,
            .op_count = @intCast(in.pattern.ops.len),
            .part_count = @intCast(in.pattern.partCount()),
            .data_len = @intCast(in.pattern.data.len),
            .min_len = minLen(in.pattern),
            .anchor_op = anchor.op,
            .anchor_delta = anchor.delta,
        };
        try out.appendSlice(gpa, std.mem.asBytes(&h));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(in.pattern.ops));
        try out.appendSlice(gpa, in.pattern.data);
    }
    return out.toOwnedSlice(gpa);
}

const testing = std.testing;
const hexsig = @import("hexsig.zig");

test "anchors prefer the longest fixed-distance literal" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diag: hexsig.Diag = .{};
    const p = try hexsig.parse(arena.allocator(), "aa??bbcc*dd(ee|ffff)112233445566", &diag);
    const a = chooseAnchor(p, false);
    // After the variable-length alternation the distance is unknown: "112233.." cannot anchor.
    try testing.expectEqual(@as(u8, 0), a.part);
    try testing.expectEqual(@as(u16, 2), a.op);
    try testing.expectEqual(@as(u16, 2), a.delta);
    const q = try hexsig.parse(arena.allocator(), "aa*bb(cc|dd)11223344", &diag);
    const b = chooseAnchor(q, false);
    try testing.expectEqual(@as(u8, 0), chooseAnchor(q, true).part);
    try testing.expectEqual(@as(u8, 1), b.part);
    try testing.expectEqual(@as(u16, 2), b.delta);
    try testing.expectEqual(@as(u32, 7), minLen(q));
}

test "built sections validate and read back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diag: hexsig.Diag = .{};
    const a = arena.allocator();
    const inputs = [_]Input{
        .{ .pattern = try hexsig.parse(a, "deadbeef", &diag), .sig = 7 },
        .{ .pattern = try hexsig.parse(a, "aa(bb|cc??)dd*ee{-3}ff(B)", &diag), .sig = 8, .target = 1, .offset = .{ .kind = .entry_point, .a = -4, .shift = 2 } },
    };
    const bytes = try build(testing.allocator, &inputs);
    defer testing.allocator.free(bytes);
    const aligned = try a.alignedAlloc(u8, .@"4", bytes.len);
    @memcpy(aligned, bytes);
    const progs = try prog.Programs.init(aligned);
    try testing.expectEqual(@as(usize, 2), progs.count());
    const p1 = progs.get(1);
    try testing.expectEqual(@as(u32, 8), p1.header.sig);
    try testing.expectEqual(@as(u16, 3), p1.header.part_count);
    try testing.expectEqual(@as(i32, -4), p1.offset().a);
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try hexsig.format(p1.pattern, &w);
    try testing.expectEqualStrings("aa(bb|cc??)dd*ee{-3}ff(B)", w.buffered());

    // Any single corrupted byte is either harmless or refused; never out of bounds.
    for (0..aligned.len) |i| {
        const saved = aligned[i];
        for ([_]u8{ 0xff, 0x00, 0x80 }) |v| {
            aligned[i] = v;
            if (prog.Programs.init(aligned)) |ps| {
                for (0..ps.count()) |j| _ = ps.get(j).pattern.ops.len;
            } else |_| {}
        }
        aligned[i] = saved;
    }
}
