//! Serialises verify programs into a SUBSIG_PROG section (layout in match/prog.zig) and picks
//! each program's anchor: the longest literal whose distance from its part's start is fixed.
const std = @import("std");
const ir = @import("ir.zig");
const prog = @import("../match/prog.zig");
const spill_mod = @import("spill.zig");

pub const Input = struct {
    pattern: ir.Pattern,
    offset: ir.Offset = .{},
    target: u8 = 0,
    sig: u32,
    subsig: u16 = 0,
    flags: u8 = 0,
    /// The anchor and prefilter atom compile/atoms.zig chose; null picks the longest literal.
    atom: ?Atom = null,
};

pub const Atom = struct { anchor: Anchor, spec: AtomSpec = .{} };

/// A program's prefilter atom: `stride + q - 1` bytes of its anchor literal from `off`, whose
/// `q`-byte grams the filter of that stride and gram length holds (strides 1, 4 and 8 with
/// 4-byte grams, stride 1 with 3- or 2-byte grams). `q` 0: none (pinned to an offset,
/// deferred, or no literal of two bytes). Kept beside SUBSIG_PROG, not in it: only the
/// compiler's prefilter builder reads it.
pub const AtomSpec = packed struct(u32) { off: u16 = 0, stride: u8 = 0, q: u8 = 0 };

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
            .bound => d + ir.boundWidth(p.ops, i),
            else => null,
        };
    }
    return best;
}

/// Shortest possible match length (saturating).
pub fn minLen(p: ir.Pattern) u32 {
    var n: u32 = 0;
    for (p.ops, 0..) |o, i| n +|= switch (o.code) {
        .lit, .masked => o.len,
        .gapf => o.a,
        .alt, .nalt => o.b & 0xffff,
        .part_end => o.a,
        .bound => ir.boundWidth(p.ops, i),
        else => 0,
    };
    return n;
}

/// The section bytes for `inputs`, in order: program i is input i.
pub fn build(gpa: std.mem.Allocator, inputs: []const Input) ![]u8 {
    var w = Writer.init(gpa, null);
    defer w.deinit();
    for (inputs) |in| _ = try w.add(in);
    const section = try w.finish();
    return gpa.dupe(u8, section);
}

/// One program as it is laid out in the section (header, ops, data).
fn header(in: Input) prog.ProgHeader {
    const anchor = if (in.atom) |a| a.anchor else chooseAnchor(in.pattern, in.offset.kind != .any);
    return .{
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
}

/// SUBSIG_PROG built one program at a time: bodies go to a (spill-backed) sink as they come, the
/// index stays on the heap, and `finish` puts header, index and bodies together.
pub const Writer = struct {
    gpa: std.mem.Allocator,
    spill: ?*spill_mod.Spill,
    /// Body offsets relative to the first body byte.
    index: std.ArrayList(u32) = .empty,
    /// The atom of each program, in program order.
    atoms: std.ArrayList(AtomSpec) = .empty,
    bodies: spill_mod.Sink,
    section: ?spill_mod.Sink = null,

    pub fn init(gpa: std.mem.Allocator, spill: ?*spill_mod.Spill) Writer {
        return .{ .gpa = gpa, .spill = spill, .bodies = .init(gpa, spill) };
    }

    pub fn deinit(w: *Writer) void {
        w.index.deinit(w.gpa);
        w.atoms.deinit(w.gpa);
        w.bodies.deinit();
        if (w.section) |*s| s.deinit();
        w.* = undefined;
    }

    pub fn count(w: *const Writer) u32 {
        return @intCast(w.index.items.len);
    }

    /// Append a program; returns its number.
    pub fn add(w: *Writer, in: Input) !u32 {
        const n = w.count();
        try w.bodies.alignTo(4);
        try w.index.append(w.gpa, @intCast(w.bodies.len));
        try w.atoms.append(w.gpa, if (in.atom) |a| a.spec else .{});
        var packed_buf: [@sizeOf(prog.PackedHeader) + @sizeOf(prog.PackedOffset)]u8 = undefined;
        try w.bodies.append(prog.pack(header(in), &packed_buf));
        try w.bodies.append(std.mem.sliceAsBytes(in.pattern.ops));
        try w.bodies.append(in.pattern.data);
        return n;
    }

    /// The finished section, 4-byte aligned, valid until `deinit`.
    pub fn finish(w: *Writer) ![]align(4) const u8 {
        const bodies = try w.bodies.finish();
        const base = @sizeOf(prog.SectionHeader) + w.index.items.len * 4;
        if (base + bodies.len > std.math.maxInt(u32)) return error.TooLarge;
        for (w.index.items) |*off| off.* += @intCast(base);
        var section = spill_mod.Sink.init(w.gpa, w.spill);
        errdefer section.deinit();
        const h: prog.SectionHeader = .{ .count = w.count() };
        try section.append(std.mem.asBytes(&h));
        try section.append(std.mem.sliceAsBytes(w.index.items));
        try section.append(bodies);
        w.section = section;
        // The bodies are copied; their spill file can go.
        w.bodies.deinit();
        w.bodies = .init(w.gpa, null);
        const bytes = try w.section.?.finish();
        std.debug.assert(@intFromPtr(bytes.ptr) % 4 == 0);
        return @alignCast(bytes);
    }
};

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

test "expanded optional alternations produce valid verify programs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{ "(6162|)", "6162*(6364|)", "(6162|)*6364", "6162*(6364|)*6566", "6162(6364|)" }) |body| {
        var diag: hexsig.Diag = .{};
        const pattern = try hexsig.parse(a, body, &diag);
        for (0..16) |bits| {
            const mods: ir.Modifiers = @bitCast(@as(u8, @intCast(bits)));
            const variants = try hexsig.expand(a, pattern, mods);
            for (variants) |variant| {
                const inputs = [_]Input{.{ .pattern = variant.pattern, .sig = 1 }};
                const bytes = try build(a, &inputs);
                const aligned = try a.alignedAlloc(u8, .@"4", bytes.len);
                @memcpy(aligned, bytes);
                _ = prog.Programs.init(aligned) catch |err| {
                    std.debug.print("invalid expanded program for {s} mods {}: {t}\n", .{ body, mods, err });
                    return err;
                };
            }
        }
    }
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
