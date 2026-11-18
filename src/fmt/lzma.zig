//! Streaming LZMA and LZMA2 decoders, written from the LZMA specification (Igor Pavlov,
//! lzma-specification.txt in the public-domain LZMA SDK) and the LZMA2 chunk layout from the
//! .xz file format specification.
//!
//! Zig std has LZMA and LZMA2, but its LZMA2 accumulates each chunk's whole output in a growing
//! heap buffer and ignores the dictionary size, so a hostile block can demand unbounded memory.
//! These decoders keep exactly one dictionary (a circular buffer sized by the caller, at most the
//! declared dictionary size) and decode straight into the consumer's buffer.
const std = @import("std");
const Io = std.Io;

pub const Error = error{ Corrupt, ReadFailed, EndOfStream };

pub const Props = struct {
    lc: u4 = 3,
    lp: u3 = 0,
    pb: u3 = 2,

    /// The packed properties byte: (pb * 5 + lp) * 9 + lc.
    pub fn decode(byte: u8) error{Corrupt}!Props {
        if (byte >= 9 * 5 * 5) return error.Corrupt;
        return .{ .lc = @intCast(byte % 9), .lp = @intCast((byte / 9) % 5), .pb = @intCast(byte / 45) };
    }

    pub fn probCount(p: Props) usize {
        return lit_base + (@as(usize, 0x300) << (@as(u5, p.lc) + p.lp));
    }
};

/// The circular dictionary: also the match window.
pub const Dict = struct {
    buf: []u8,
    pos: usize = 0,
    /// Bytes ever written since the last reset (saturating; distance checks use min(len, buf.len)).
    total: u64 = 0,

    pub fn reset(d: *Dict) void {
        d.pos = 0;
        d.total = 0;
    }

    inline fn put(d: *Dict, b: u8) void {
        d.buf[d.pos] = b;
        d.pos += 1;
        if (d.pos == d.buf.len) d.pos = 0;
        d.total += 1;
    }

    /// The byte `dist` back (1 = the last byte written).
    inline fn get(d: *const Dict, dist: usize) u8 {
        return d.buf[if (dist <= d.pos) d.pos - dist else d.buf.len + d.pos - dist];
    }

    inline fn has(d: *const Dict, dist: u64) bool {
        return dist <= d.total and dist <= d.buf.len;
    }
};

const RangeDecoder = struct {
    range: u32 = 0xFFFFFFFF,
    code: u32 = 0,
    /// Input bytes taken since init (LZMA2 checks chunk packed sizes with it).
    taken: u64 = 0,

    fn init(rc: *RangeDecoder, in: *Io.Reader) Error!void {
        const b = try in.takeArray(5);
        if (b[0] != 0) return error.Corrupt;
        rc.range = 0xFFFFFFFF;
        rc.code = std.mem.readInt(u32, b[1..5], .big);
        rc.taken = 5;
        if (rc.code == rc.range) return error.Corrupt;
    }

    inline fn normalize(rc: *RangeDecoder, in: *Io.Reader) Error!void {
        if (rc.range < (1 << 24)) {
            rc.range <<= 8;
            rc.code = (rc.code << 8) | try in.takeByte();
            rc.taken += 1;
        }
    }

    inline fn bit(rc: *RangeDecoder, in: *Io.Reader, prob: *u16) Error!u1 {
        const bound = (rc.range >> 11) * prob.*;
        var b: u1 = undefined;
        if (rc.code < bound) {
            rc.range = bound;
            prob.* += (2048 - prob.*) >> 5;
            b = 0;
        } else {
            rc.range -= bound;
            rc.code -= bound;
            prob.* -= prob.* >> 5;
            b = 1;
        }
        try rc.normalize(in);
        return b;
    }

    fn direct(rc: *RangeDecoder, in: *Io.Reader, n: u5) Error!u32 {
        var res: u32 = 0;
        for (0..n) |_| {
            rc.range >>= 1;
            rc.code -%= rc.range;
            const t: u32 = 0 -% (rc.code >> 31);
            rc.code +%= rc.range & t;
            if (rc.code == rc.range) return error.Corrupt;
            res = (res << 1) +% (t +% 1);
            try rc.normalize(in);
        }
        return res;
    }

    fn tree(rc: *RangeDecoder, in: *Io.Reader, probs: []u16, comptime bits: u5) Error!u32 {
        var m: u32 = 1;
        for (0..bits) |_| m = (m << 1) | try rc.bit(in, &probs[m]);
        return m - (@as(u32, 1) << bits);
    }

    fn reverse(rc: *RangeDecoder, in: *Io.Reader, probs: []u16, bits: u5) Error!u32 {
        var m: u32 = 1;
        var sym: u32 = 0;
        for (0..bits) |i| {
            const b = try rc.bit(in, &probs[m]);
            m = (m << 1) | b;
            sym |= @as(u32, b) << @intCast(i);
        }
        return sym;
    }
};

// Probability array layout (offsets into one []u16).
const n_states = 12;
const pos_states_max = 16;
const is_match = 0;
const is_rep = is_match + n_states * pos_states_max;
const is_rep_g0 = is_rep + n_states;
const is_rep_g1 = is_rep_g0 + n_states;
const is_rep_g2 = is_rep_g1 + n_states;
const is_rep0_long = is_rep_g2 + n_states;
const pos_slot = is_rep0_long + n_states * pos_states_max;
const spec_pos = pos_slot + 4 * 64;
const align_probs = spec_pos + 115;
const len_probs = align_probs + 16;
const len_size = 2 + pos_states_max * 8 * 2 + 256;
const rep_len_probs = len_probs + len_size;
const lit_base = rep_len_probs + len_size;

/// The LZMA symbol decoder. One instance decodes an LZMA stream or every chunk of an LZMA2
/// stream; the dictionary is shared state the caller owns.
pub const Lzma = struct {
    probs: []u16,
    props: Props,
    dict: *Dict,
    rc: RangeDecoder = .{},
    state: u8 = 0,
    reps: [4]u32 = @splat(0),
    /// A match cut short by a full output buffer.
    pending: u32 = 0,
    finished: bool = false,

    pub fn init(probs: []u16, props: Props, dict: *Dict) Lzma {
        var l: Lzma = .{ .probs = probs, .props = props, .dict = dict };
        l.resetState();
        return l;
    }

    pub fn resetState(l: *Lzma) void {
        @memset(l.probs[0..l.props.probCount()], 1024);
        l.state = 0;
        l.reps = @splat(0);
        l.pending = 0;
        l.finished = false;
    }

    fn lenDecode(l: *Lzma, in: *Io.Reader, base: usize, pos_state: usize) Error!u32 {
        const p = l.probs[base..][0..len_size];
        if (try l.rc.bit(in, &p[0]) == 0) return l.rc.tree(in, p[2 + pos_state * 8 ..][0..8], 3);
        if (try l.rc.bit(in, &p[1]) == 0) return 8 + try l.rc.tree(in, p[2 + pos_states_max * 8 + pos_state * 8 ..][0..8], 3);
        return 16 + try l.rc.tree(in, p[2 + pos_states_max * 16 ..][0..256], 8);
    }

    /// Decode into `dest`, producing at most `max_out` bytes. Returns the count; `finished` is set
    /// when the end marker is decoded.
    pub fn decode(l: *Lzma, in: *Io.Reader, dest: []u8, max_out: u64) Error!usize {
        const want: usize = @intCast(@min(dest.len, max_out));
        var i: usize = 0;
        const d = l.dict;
        const pb_mask = (@as(u32, 1) << l.props.pb) - 1;
        const lp_mask = (@as(u32, 1) << l.props.lp) - 1;
        const lc = l.props.lc;
        while (i < want) {
            if (l.pending > 0) {
                const dist = @as(usize, l.reps[0]) + 1;
                const n = @min(l.pending, want - i);
                for (0..n) |_| {
                    const b = d.get(dist);
                    d.put(b);
                    dest[i] = b;
                    i += 1;
                }
                l.pending -= @intCast(n);
                continue;
            }
            if (l.finished) break;
            const pos_state: usize = @intCast(d.total & pb_mask);
            const state = l.state;
            if (try l.rc.bit(in, &l.probs[is_match + @as(usize, state) * pos_states_max + pos_state]) == 0) {
                const prev: u32 = if (d.total > 0) d.get(1) else 0;
                const lit_state = ((@as(u32, @truncate(d.total)) & lp_mask) << lc) + (prev >> @intCast(8 - @as(u5, lc)));
                const probs = l.probs[lit_base + 0x300 * @as(usize, lit_state) ..][0..0x300];
                var sym: u32 = 1;
                if (state >= 7) {
                    if (!d.has(@as(u64, l.reps[0]) + 1)) return error.Corrupt;
                    var match_byte: u32 = d.get(@as(usize, l.reps[0]) + 1);
                    while (sym < 0x100) {
                        const match_bit = (match_byte >> 7) & 1;
                        match_byte <<= 1;
                        const b = try l.rc.bit(in, &probs[((1 + match_bit) << 8) + sym]);
                        sym = (sym << 1) | b;
                        if (match_bit != b) break;
                    }
                }
                while (sym < 0x100) sym = (sym << 1) | try l.rc.bit(in, &probs[sym]);
                const b: u8 = @truncate(sym);
                d.put(b);
                dest[i] = b;
                i += 1;
                l.state = if (state < 4) 0 else if (state < 10) state - 3 else state - 6;
                continue;
            }
            var len: u32 = undefined;
            if (try l.rc.bit(in, &l.probs[is_rep + state]) == 1) {
                if (d.total == 0) return error.Corrupt;
                if (try l.rc.bit(in, &l.probs[is_rep_g0 + state]) == 0) {
                    if (try l.rc.bit(in, &l.probs[is_rep0_long + @as(usize, state) * pos_states_max + pos_state]) == 0) {
                        if (!d.has(@as(u64, l.reps[0]) + 1)) return error.Corrupt;
                        l.state = if (state < 7) 9 else 11;
                        const b = d.get(@as(usize, l.reps[0]) + 1);
                        d.put(b);
                        dest[i] = b;
                        i += 1;
                        continue;
                    }
                } else {
                    var dist: u32 = undefined;
                    if (try l.rc.bit(in, &l.probs[is_rep_g1 + state]) == 0) {
                        dist = l.reps[1];
                    } else {
                        if (try l.rc.bit(in, &l.probs[is_rep_g2 + state]) == 0) {
                            dist = l.reps[2];
                        } else {
                            dist = l.reps[3];
                            l.reps[3] = l.reps[2];
                        }
                        l.reps[2] = l.reps[1];
                    }
                    l.reps[1] = l.reps[0];
                    l.reps[0] = dist;
                }
                len = try l.lenDecode(in, rep_len_probs, pos_state);
                l.state = if (state < 7) 8 else 11;
            } else {
                l.reps[3] = l.reps[2];
                l.reps[2] = l.reps[1];
                l.reps[1] = l.reps[0];
                len = try l.lenDecode(in, len_probs, pos_state);
                l.state = if (state < 7) 7 else 10;
                const len_state: usize = @min(len, 3);
                const slot = try l.rc.tree(in, l.probs[pos_slot + len_state * 64 ..][0..64], 6);
                var dist: u32 = slot;
                if (slot >= 4) {
                    const direct_bits: u5 = @intCast((slot >> 1) - 1);
                    dist = (2 | (slot & 1)) << direct_bits;
                    if (slot < 14) {
                        dist +%= try l.rc.reverse(in, l.probs[spec_pos + dist - slot ..], direct_bits);
                    } else {
                        dist +%= (try l.rc.direct(in, direct_bits - 4)) << 4;
                        dist +%= try l.rc.reverse(in, l.probs[align_probs..][0..16], 4);
                    }
                }
                l.reps[0] = dist;
                if (dist == 0xFFFFFFFF) {
                    l.finished = true;
                    break;
                }
            }
            if (!d.has(@as(u64, l.reps[0]) + 1)) return error.Corrupt;
            l.pending = len + 2;
        }
        return i;
    }
};

/// LZMA2: a sequence of LZMA and uncompressed chunks over one dictionary.
pub const Lzma2 = struct {
    lzma: Lzma,
    in: *Io.Reader,
    /// Bytes left in the current chunk, and whether it is an LZMA chunk.
    chunk_left: u32 = 0,
    packed_left: u32 = 0,
    lzma_chunk: bool = false,
    need_dict_reset: bool = true,
    need_props: bool = true,
    done: bool = false,
    /// Compressed bytes consumed since `reset` (xz block padding is computed from it).
    consumed: u64 = 0,
    err: ?Error = null,
    interface: Io.Reader,

    /// `probs` must hold `(Props{ .lc = 4 }).probCount()` entries (lc + lp is at most 4 in LZMA2).
    pub fn init(in: *Io.Reader, probs: []u16, dict: *Dict, buffer: []u8) Lzma2 {
        return .{
            .lzma = .{ .probs = probs, .props = .{}, .dict = dict },
            .in = in,
            .interface = .{ .vtable = @import("../engine/container.zig").fillVTable(Lzma2), .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    pub const probs_len = lit_base + (0x300 << 4);

    /// Dictionary size from the one-byte LZMA2 filter property.
    pub fn dictSize(prop: u8) error{Corrupt}!u64 {
        if (prop > 40) return error.Corrupt;
        if (prop == 40) return 0xFFFFFFFF;
        return @as(u64, 2 | (prop & 1)) << @intCast(prop / 2 + 11);
    }

    pub fn fill(z: *Lzma2, dest: []u8) Io.Reader.Error!usize {
        return z.decodeInto(dest) catch |e| switch (e) {
            error.ReadFailed => error.ReadFailed,
            else => {
                z.err = e;
                return error.ReadFailed;
            },
        };
    }

    /// Forget the previous block (xz starts each block with a fresh LZMA2 stream).
    pub fn reset(z: *Lzma2, in: *Io.Reader) void {
        z.in = in;
        z.chunk_left = 0;
        z.packed_left = 0;
        z.lzma_chunk = false;
        z.need_dict_reset = true;
        z.need_props = true;
        z.done = false;
        z.consumed = 0;
        z.err = null;
    }

    pub fn decodeInto(z: *Lzma2, dest: []u8) Error!usize {
        while (true) {
            if (z.chunk_left == 0) {
                if (z.lzma_chunk) {
                    if (z.lzma.rc.taken != z.packed_left) return error.Corrupt;
                    z.consumed += z.packed_left;
                }
                z.lzma_chunk = false;
                if (z.done) return 0;
                if (!try z.nextChunk()) {
                    z.done = true;
                    return 0;
                }
                continue;
            }
            if (z.lzma_chunk) {
                const n = try z.lzma.decode(z.in, dest, z.chunk_left);
                if (z.lzma.finished) return error.Corrupt; // LZMA2 chunks carry no end marker
                z.chunk_left -= @intCast(n);
                return n;
            }
            const n = @min(dest.len, z.chunk_left);
            try z.in.readSliceAll(dest[0..n]);
            z.consumed += n;
            for (dest[0..n]) |b| z.lzma.dict.put(b);
            z.chunk_left -= @intCast(n);
            return n;
        }
    }

    fn nextChunk(z: *Lzma2) Error!bool {
        const control = try z.in.takeByte();
        z.consumed += 1;
        if (control == 0) return false;
        if (control == 1 or control == 2) {
            if (control == 1) {
                z.lzma.dict.reset();
                z.need_dict_reset = false;
            } else if (z.need_dict_reset) return error.Corrupt;
            const size = try z.in.takeInt(u16, .big);
            z.consumed += 2;
            z.chunk_left = @as(u32, size) + 1;
            return true;
        }
        if (control < 0x80) return error.Corrupt;
        const usize_hi: u32 = control & 0x1f;
        const unpacked = (usize_hi << 16) + @as(u32, try z.in.takeInt(u16, .big)) + 1;
        const packed_size = @as(u32, try z.in.takeInt(u16, .big)) + 1;
        const mode = (control >> 5) & 3;
        z.consumed += if (mode >= 2) 5 else 4;
        if (mode == 3) {
            z.lzma.dict.reset();
            z.need_dict_reset = false;
        } else if (z.need_dict_reset) return error.Corrupt;
        if (mode >= 2) {
            const props = try Props.decode(try z.in.takeByte());
            if (@as(u5, props.lc) + props.lp > 4) return error.Corrupt;
            z.lzma.props = props;
            z.need_props = false;
        } else if (z.need_props) return error.Corrupt;
        if (mode >= 1) z.lzma.resetState();
        try z.lzma.rc.init(z.in);
        z.lzma.pending = 0;
        z.chunk_left = unpacked;
        z.packed_left = packed_size;
        z.lzma_chunk = true;
        return true;
    }
};

/// An LZMA stream in the "alone" layout used by .lzma files and zip method 14 (after zip's
/// 4-byte version header): a 5-byte properties header, optionally a 64-bit size, then data that
/// ends at `size` bytes or at the end marker.
pub const Alone = struct {
    lzma: Lzma,
    in: *Io.Reader,
    left: ?u64,
    err: ?Error = null,
    interface: Io.Reader,

    pub const Header = struct { props: Props, dict_size: u32 };

    pub fn parseHeader(bytes: *const [5]u8) error{Corrupt}!Header {
        return .{ .props = try Props.decode(bytes[0]), .dict_size = std.mem.readInt(u32, bytes[1..5], .little) };
    }

    /// The range coder starts reading immediately: `in` must be positioned at the coded data.
    pub fn init(in: *Io.Reader, header: Header, size: ?u64, probs: []u16, dict: *Dict, buffer: []u8) Error!Alone {
        var a: Alone = .{
            .lzma = .init(probs, header.props, dict),
            .in = in,
            .left = size,
            .interface = .{ .vtable = @import("../engine/container.zig").fillVTable(Alone), .buffer = buffer, .seek = 0, .end = 0 },
        };
        try a.lzma.rc.init(in);
        return a;
    }

    pub fn fill(a: *Alone, dest: []u8) Io.Reader.Error!usize {
        if (a.left) |l| if (l == 0) return 0;
        const n = a.lzma.decode(a.in, dest, a.left orelse std.math.maxInt(u64)) catch |e| switch (e) {
            error.ReadFailed => return error.ReadFailed,
            else => {
                a.err = e;
                return error.ReadFailed;
            },
        };
        if (a.left) |*l| l.* -= n;
        if (n == 0 and !a.lzma.finished) {
            a.err = error.Corrupt;
            return error.ReadFailed;
        }
        return n;
    }
};

const fixtures = @import("fixtures/fixtures.zig");

test "LZMA alone stream decodes to the reference bytes" {
    const gpa = std.testing.allocator;
    const v = fixtures.lzma_vectors[0];
    var in: Io.Reader = .fixed(v.compressed);
    const header = try Alone.parseHeader(try in.takeArray(5));
    const size = try in.takeInt(u64, .little);
    const probs = try gpa.alloc(u16, header.props.probCount());
    defer gpa.free(probs);
    const dict_buf = try gpa.alloc(u8, @min(header.dict_size, v.plain_len));
    defer gpa.free(dict_buf);
    var dict: Dict = .{ .buf = dict_buf };
    var buf: [1000]u8 = undefined;
    var a = try Alone.init(&in, header, if (size == std.math.maxInt(u64)) null else size, probs, &dict, &buf);
    var crc = std.hash.Crc32.init();
    var total: usize = 0;
    while (true) {
        const chunk = a.interface.peekGreedy(1) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return a.err.?,
        };
        crc.update(chunk);
        total += chunk.len;
        a.interface.toss(chunk.len);
    }
    try std.testing.expectEqual(v.plain_len, total);
    try std.testing.expectEqual(v.plain_crc, crc.final());
}

test "dictionary size property" {
    try std.testing.expectEqual(@as(u64, 4096), try Lzma2.dictSize(0));
    try std.testing.expectEqual(@as(u64, 6144), try Lzma2.dictSize(1));
    try std.testing.expectEqual(@as(u64, 8 << 20), try Lzma2.dictSize(22));
    try std.testing.expectError(error.Corrupt, Lzma2.dictSize(41));
}
