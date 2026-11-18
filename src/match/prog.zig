//! The SUBSIG_PROG section: one verify program per subsignature variant (docs/DESIGN.md 3.4).
//!
//! Layout, little-endian and offset based:
//!
//!     SectionHeader (16 bytes)
//!     index: [count]u32   byte offset of each program from the section start (4-byte aligned)
//!     program: PackedHeader (24 bytes), PackedOffset (12 bytes, only when the program has an
//!              offset), [op_count]ir.Op (12 bytes each), [data_len]u8
//!
//! Version 2 stores headers packed: 85% of the 1.63 million programs of main and daily are a
//! single literal, so the old 40-byte header was the largest part of the section, and only 3.6%
//! have an offset. `Programs.get` decodes a program's header into `ProgHeader`.
//!
//! Ops and data are the hex-signature IR exactly as the compiler built it (compile/ir.zig).
//! `Programs.init` validates every program before any is used: every offset and length lands
//! inside the program, alternation tables are well formed, parts and branch points stay within
//! the verify VM's recursion bound. A corrupt section is refused, never half used.
const std = @import("std");
const ir = @import("../compile/ir.zig");

pub const SectionHeader = extern struct {
    magic: [4]u8 = "PROG".*,
    version: u32 = 2,
    count: u32,
    _reserved: u32 = 0,
};

/// Program flag bits.
pub const flag_fullword: u8 = 1 << 0;
/// Some ops compare case-insensitively (nocase that was not expanded into variants).
pub const flag_folded: u8 = 1 << 1;
/// Part of a logical signature: `sig` is the LDB_TABLE record, `subsig` the subsig index.
pub const flag_ldb: u8 = 1 << 2;
/// A `::w` variant: fullword boundaries are checked on 16-bit units.
pub const flag_wide: u8 = 1 << 3;
pub const known_flags: u8 = flag_fullword | flag_folded | flag_ldb | flag_wide;

pub const no_anchor: u16 = 0xffff;

pub const ProgHeader = extern struct {
    /// Signature id (sigmeta) for a body signature; LDB_TABLE record for a logical subsig.
    sig: u32,
    subsig: u16 = 0,
    /// ClamAV target type, which is also the partition.
    target: u8 = 0,
    flags: u8 = 0,
    off_kind: ir.OffsetKind = .any,
    /// The part holding the anchor literal.
    anchor_part: u8 = 0,
    off_section: u16 = 0,
    off_a: i32 = 0,
    off_shift: u32 = 0,
    op_count: u16,
    part_count: u16,
    data_len: u32,
    /// Shortest possible match, for offset windows near the end of the data.
    min_len: u32 = 0,
    /// Index of the anchor literal op, or `no_anchor`.
    anchor_op: u16 = no_anchor,
    /// Fixed byte distance from the anchor part's start to the anchor literal.
    anchor_delta: u16 = no_anchor,
    _reserved: u32 = 0,
};

/// The on-disk form of a header without its offset fields.
pub const PackedHeader = extern struct {
    sig: u32,
    subsig: u8,
    target: u8,
    flags: u8,
    off_kind: ir.OffsetKind,
    op_count: u16,
    part_count: u8,
    anchor_part: u8,
    data_len: u32,
    min_len: u32,
    anchor_op: u16,
    anchor_delta: u16,
};

/// The offset fields, stored only for programs whose `off_kind` is not `any`.
pub const PackedOffset = extern struct {
    off_section: u16,
    _pad: u16 = 0,
    off_a: i32,
    off_shift: u32,
};

comptime {
    std.debug.assert(@sizeOf(SectionHeader) == 16);
    std.debug.assert(@sizeOf(ProgHeader) == 40);
    std.debug.assert(@alignOf(ProgHeader) == 4);
    std.debug.assert(@sizeOf(PackedHeader) == 24);
    std.debug.assert(@sizeOf(PackedOffset) == 12);
}

/// The packed bytes of a header: 24, or 36 with an offset. `h` must fit (subsig and part count
/// below 256).
pub fn pack(h: ProgHeader, out: *[@sizeOf(PackedHeader) + @sizeOf(PackedOffset)]u8) []const u8 {
    const ph: PackedHeader = .{
        .sig = h.sig,
        .subsig = @intCast(h.subsig),
        .target = h.target,
        .flags = h.flags,
        .off_kind = h.off_kind,
        .op_count = h.op_count,
        .part_count = @intCast(h.part_count),
        .anchor_part = h.anchor_part,
        .data_len = h.data_len,
        .min_len = h.min_len,
        .anchor_op = h.anchor_op,
        .anchor_delta = h.anchor_delta,
    };
    out[0..@sizeOf(PackedHeader)].* = std.mem.toBytes(ph);
    if (h.off_kind == .any) return out[0..@sizeOf(PackedHeader)];
    const po: PackedOffset = .{ .off_section = h.off_section, .off_a = h.off_a, .off_shift = h.off_shift };
    out[@sizeOf(PackedHeader)..].* = std.mem.toBytes(po);
    return out;
}

fn headerLen(kind: ir.OffsetKind) usize {
    return @sizeOf(PackedHeader) + @as(usize, if (kind == .any) 0 else @sizeOf(PackedOffset));
}

/// Bounds the verify VM relies on for its recursion depth.
pub const max_parts: usize = 255;
pub const max_branches: usize = 64;

pub const Program = struct {
    /// Decoded from the packed form.
    header: ProgHeader,
    pattern: ir.Pattern,

    pub fn offset(p: Program) ir.Offset {
        return .{ .kind = p.header.off_kind, .a = p.header.off_a, .section = p.header.off_section, .shift = p.header.off_shift };
    }
};

pub const Programs = struct {
    bytes: []align(4) const u8,
    index: []const u32,

    pub const Error = error{BadProgram};

    /// No programs (a database whose signatures need none, such as regex-only YARA rules).
    pub const empty: Programs = .{ .bytes = &.{}, .index = &.{} };

    pub fn init(section: []const u8) Error!Programs {
        if (section.len < @sizeOf(SectionHeader) or @intFromPtr(section.ptr) % 4 != 0) return error.BadProgram;
        const bytes: []align(4) const u8 = @alignCast(section);
        const h: *const SectionHeader = @ptrCast(bytes.ptr);
        if (!std.mem.eql(u8, &h.magic, "PROG") or h.version != 2) return error.BadProgram;
        if (h.count > (bytes.len - @sizeOf(SectionHeader)) / 4) return error.BadProgram;
        const index_ptr: [*]const u32 = @ptrCast(@alignCast(bytes.ptr + @sizeOf(SectionHeader)));
        const progs: Programs = .{ .bytes = bytes, .index = index_ptr[0..h.count] };
        const body_start = @sizeOf(SectionHeader) + @as(usize, h.count) * 4;
        for (progs.index) |off| {
            if (off < body_start or off % 4 != 0) return error.BadProgram;
            _ = try progs.checked(off);
        }
        return progs;
    }

    pub fn count(progs: Programs) usize {
        return progs.index.len;
    }

    /// Program `i`; validated by `init`.
    pub fn get(progs: Programs, i: usize) Program {
        return progs.at(progs.index[i]);
    }

    fn at(progs: Programs, off: u32) Program {
        const ph: *const PackedHeader = @ptrCast(@alignCast(progs.bytes.ptr + off));
        var h: ProgHeader = .{
            .sig = ph.sig,
            .subsig = ph.subsig,
            .target = ph.target,
            .flags = ph.flags,
            .off_kind = ph.off_kind,
            .anchor_part = ph.anchor_part,
            .op_count = ph.op_count,
            .part_count = ph.part_count,
            .data_len = ph.data_len,
            .min_len = ph.min_len,
            .anchor_op = ph.anchor_op,
            .anchor_delta = ph.anchor_delta,
        };
        if (ph.off_kind != .any) {
            const po: *const PackedOffset = @ptrCast(@alignCast(progs.bytes.ptr + off + @sizeOf(PackedHeader)));
            h.off_section = po.off_section;
            h.off_a = po.off_a;
            h.off_shift = po.off_shift;
        }
        const ops_at = off + headerLen(ph.off_kind);
        const ops: [*]const ir.Op = @ptrCast(@alignCast(progs.bytes.ptr + ops_at));
        const data_at = ops_at + @as(usize, h.op_count) * @sizeOf(ir.Op);
        const data: []align(4) const u8 = @alignCast(progs.bytes[data_at..][0..h.data_len]);
        return .{ .header = h, .pattern = .{ .ops = ops[0..h.op_count], .data = data } };
    }

    fn checked(progs: Programs, off: u32) Error!Program {
        const len = progs.bytes.len;
        if (@as(usize, off) + @sizeOf(PackedHeader) > len) return error.BadProgram;
        const ph: *const PackedHeader = @ptrCast(@alignCast(progs.bytes.ptr + off));
        const end = @as(usize, off) + headerLen(ph.off_kind) + @as(usize, ph.op_count) * @sizeOf(ir.Op) + ph.data_len;
        if (end > len) return error.BadProgram;
        const p = progs.at(off);
        try validate(p);
        return p;
    }
};

/// Check one program's header and IR.
pub fn validate(p: Program) Programs.Error!void {
    const h = p.header;
    if (h.flags & ~known_flags != 0 or h.target > 14) return error.BadProgram;
    if (@backingInt(h.off_kind) > @backingInt(ir.OffsetKind.last_section)) return error.BadProgram;
    if (h.op_count == 0 or h.part_count == 0 or h.part_count > max_parts) return error.BadProgram;
    try validateOps(p.pattern, p.pattern.ops, false);
    var parts: usize = 1;
    var branches: usize = 0;
    var anchor_part: usize = 0;
    for (p.pattern.ops, 0..) |o, i| {
        switch (o.code) {
            .part_end => {
                if (i == 0 or i + 1 == p.pattern.ops.len or p.pattern.ops[i - 1].code == .part_end) return error.BadProgram;
                parts += 1;
            },
            .alt => branches += 1,
            else => {},
        }
        if (i == h.anchor_op) {
            if (o.code != .lit) return error.BadProgram;
            anchor_part = parts - 1;
        }
    }
    if (parts != h.part_count or branches > max_branches) return error.BadProgram;
    if (h.anchor_op != no_anchor) {
        if (h.anchor_op >= h.op_count or anchor_part != h.anchor_part or h.anchor_delta == no_anchor) return error.BadProgram;
    } else if (h.anchor_part >= parts) return error.BadProgram;
}

fn validateOps(p: ir.Pattern, ops: []const ir.Op, inside_alt: bool) Programs.Error!void {
    const data_len = p.data.len;
    for (ops) |o| switch (o.code) {
        .lit => {
            if (o.len == 0 or o.flags & ~ir.op_nocase != 0 or @as(usize, o.a) + o.len > data_len) return error.BadProgram;
        },
        .masked => {
            if (o.len == 0 or o.flags & ~ir.op_negate != 0 or @as(usize, o.a) + 2 * @as(usize, o.len) > data_len) return error.BadProgram;
            if (o.flags & ir.op_negate != 0 and (o.len != 1 or inside_alt)) return error.BadProgram;
        },
        .gapf => if (o.a == 0 or o.a >= ir.inline_gap_limit or o.flags != 0) return error.BadProgram,
        .bound => if (inside_alt or o.flags > @backingInt(ir.Bound.nonalnum)) return error.BadProgram,
        // A minimum above the maximum is a gap that never matches (libclamav loads `{3-1}`).
        .part_end => if (inside_alt or o.flags > @backingInt(ir.GapSyntax.bracket)) return error.BadProgram,
        .alt, .nalt => {
            if (inside_alt or o.len == 0 or o.flags & ~ir.op_nocase != 0) return error.BadProgram;
            if (o.a % 4 != 0 or @as(usize, o.a) + @as(usize, o.len) * @sizeOf(ir.AltEntry) > data_len) return error.BadProgram;
            var min_len: u32 = std.math.maxInt(u32);
            var max_len: u32 = 0;
            for (p.alternatives(o), 0..) |entry, k| {
                // An empty alternative makes the alternation optional (`(aabb|)`); libclamav
                // refuses it first, and negations never hold one.
                const empty_ok = k > 0 and o.code == .alt;
                if ((entry.op_count == 0 and !empty_ok) or entry.ops_off % 4 != 0) return error.BadProgram;
                if (@as(usize, entry.ops_off) + @as(usize, entry.op_count) * @sizeOf(ir.Op) > data_len) return error.BadProgram;
                const inner = p.altOps(entry);
                try validateOps(p, inner, true);
                var len: u32 = 0;
                for (inner) |x| {
                    len += switch (x.code) {
                        .lit, .masked => x.len,
                        .gapf => x.a,
                        else => unreachable,
                    };
                    if (o.code == .nalt and x.code != .lit) return error.BadProgram;
                }
                if (len != entry.byte_len or (len == 0 and !empty_ok)) return error.BadProgram;
                min_len = @min(min_len, len);
                max_len = @max(max_len, len);
            }
            if (o.b != (min_len | max_len << 16)) return error.BadProgram;
            if (o.code == .nalt and min_len != max_len) return error.BadProgram;
        },
        _ => return error.BadProgram,
    };
}
