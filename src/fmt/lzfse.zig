//! LZFSE and LZVN decoding (Apple's compression formats, used by ULFO disk images), written from
//! the format as Apple's open-source reference documents it: a stream of blocks, each starting
//! with a magic: "bvx-" stored, "bvxn" LZVN, "bvx2" LZFSE with compressed frequency tables, and
//! "bvx$" ending the stream. ("bvx1", uncompressed tables, is not produced by the reference
//! encoder and is reported as unsupported.)
//!
//! LZFSE codes literals with four interleaved FSE states and (literal length, match length,
//! distance) triples with three more, reading both payloads backwards. Decoding is one-shot into
//! a caller buffer (a disk image chunk): every count, state and distance is checked against the
//! header and the output, so a hostile block fails with an error.
const std = @import("std");

pub const Error = error{ Truncated, Corrupt, Unsupported, OutputFull };

const l_syms = 20;
const m_syms = 20;
const d_syms = 64;
const lit_syms = 256;
const l_states = 64;
const m_states = 64;
const d_states = 256;
const lit_states = 1024;
pub const max_literals = 4 * 10000;
const max_matches = 10000;

fn baseTable(comptime extra: []const u8) [extra.len]u32 {
    var t: [extra.len]u32 = undefined;
    var v: u32 = 0;
    for (extra, 0..) |e, i| {
        t[i] = v;
        v += @as(u32, 1) << @intCast(e);
    }
    return t;
}

const l_extra = [l_syms]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8 };
const m_extra = [m_syms]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11 };
const d_extra: [d_syms]u8 = blk: {
    var t: [d_syms]u8 = undefined;
    for (&t, 0..) |*e, i| e.* = i >> 2;
    break :blk t;
};
const l_base = baseTable(&l_extra);
const m_base = baseTable(&m_extra);
const d_base = baseTable(&d_extra);

const Entry = struct { k: u8 = 0, symbol: u8 = 0, delta: i16 = 0 };
const ValueEntry = struct { total_bits: u8 = 0, value_bits: u8 = 0, delta: i16 = 0, vbase: u32 = 0 };

/// Decoder tables and the literal buffer: caller memory, about 60 KiB.
pub const Scratch = struct {
    lit: [lit_states]Entry = undefined,
    l: [l_states]ValueEntry = undefined,
    m: [m_states]ValueEntry = undefined,
    d: [d_states]ValueEntry = undefined,
    literals: [max_literals + 64]u8 = undefined,
};

/// Decode a whole stream into `dst`; the number of bytes produced.
pub fn decode(src: []const u8, dst: []u8, s: *Scratch) Error!usize {
    var in = src;
    var out: usize = 0;
    while (true) {
        if (in.len < 4) return error.Truncated;
        const magic = in[0..4];
        if (std.mem.eql(u8, magic, "bvx$")) return out;
        if (in.len < 8) return error.Truncated;
        const n_raw = std.mem.readInt(u32, in[4..8], .little);
        if (n_raw > dst.len - out) return error.OutputFull;
        if (std.mem.eql(u8, magic, "bvx-")) {
            if (in.len - 8 < n_raw) return error.Truncated;
            @memcpy(dst[out..][0..n_raw], in[8..][0..n_raw]);
            out += n_raw;
            in = in[8 + n_raw ..];
        } else if (std.mem.eql(u8, magic, "bvxn")) {
            if (in.len < 12) return error.Truncated;
            const n_payload = std.mem.readInt(u32, in[8..12], .little);
            if (in.len - 12 < n_payload) return error.Truncated;
            try lzvn(in[12..][0..n_payload], dst[0 .. out + n_raw], out);
            out += n_raw;
            in = in[12 + n_payload ..];
        } else if (std.mem.eql(u8, magic, "bvx2")) {
            const used = try block2(in, dst[0 .. out + n_raw], out, s);
            out += n_raw;
            in = in[used..];
        } else if (std.mem.eql(u8, magic, "bvx1")) {
            return error.Unsupported;
        } else return error.Corrupt;
    }
}

// ---------------------------------------------------------------------------------------------
// LZFSE (bvx2)

/// One v2 block; `dst[start..]` is its output (exactly filled). Returns the input bytes used.
fn block2(in: []const u8, dst: []u8, start: usize, s: *Scratch) Error!usize {
    // Magic, raw size and three packed 64-bit fields, then the frequency tables.
    if (in.len < 32) return error.Truncated;
    const f0 = std.mem.readInt(u64, in[8..16], .little);
    const f1 = std.mem.readInt(u64, in[16..24], .little);
    const f2 = std.mem.readInt(u64, in[24..32], .little);
    const n_literals: u32 = @intCast(f0 & 0xfffff);
    const n_lit_payload: u32 = @intCast((f0 >> 20) & 0xfffff);
    const n_matches: u32 = @intCast((f0 >> 40) & 0xfffff);
    const literal_bits: i32 = @as(i32, @intCast((f0 >> 60) & 7)) - 7;
    var lit_state: [4]u32 = undefined;
    for (&lit_state, 0..) |*st, i| st.* = @intCast((f1 >> @intCast(10 * i)) & 0x3ff);
    const n_lmd_payload: u32 = @intCast((f1 >> 40) & 0xfffff);
    const lmd_bits: i32 = @as(i32, @intCast((f1 >> 60) & 7)) - 7;
    const header_size: u32 = @truncate(f2);
    var l_state: u32 = @intCast((f2 >> 32) & 0x3ff);
    var m_state: u32 = @intCast((f2 >> 42) & 0x3ff);
    var d_state: u32 = @intCast((f2 >> 52) & 0x3ff);
    if (header_size < 32 or header_size > in.len) return error.Truncated;
    if (n_literals > max_literals or n_matches > max_matches) return error.Corrupt;
    if (l_state >= l_states or m_state >= m_states or d_state >= d_states) return error.Corrupt;
    for (lit_state) |st| if (st >= lit_states) return error.Corrupt;

    // Frequency tables: a variable-length code, bits taken least significant first.
    var freq: [l_syms + m_syms + d_syms + lit_syms]u16 = undefined;
    var hp: usize = 32;
    var accum: u32 = 0;
    var nbits: u6 = 0;
    for (&freq) |*f| {
        while (hp < header_size and nbits + 8 <= 32) {
            accum |= @as(u32, in[hp]) << @intCast(nbits);
            nbits += 8;
            hp += 1;
        }
        const code = freqValue(accum);
        if (code.bits > nbits) return error.Corrupt;
        f.* = code.value;
        accum = if (code.bits >= 32) 0 else accum >> @intCast(code.bits);
        nbits -= code.bits;
    }
    if (nbits >= 8 or hp != header_size) return error.Corrupt;
    const l_freq = freq[0..l_syms];
    const m_freq = freq[l_syms..][0..m_syms];
    const d_freq = freq[l_syms + m_syms ..][0..d_syms];
    const lit_freq = freq[l_syms + m_syms + d_syms ..][0..lit_syms];
    try initTable(lit_states, lit_freq, &s.lit);
    try initValueTable(l_states, l_freq, &l_extra, &l_base, &s.l);
    try initValueTable(m_states, m_freq, &m_extra, &m_base, &s.m);
    try initValueTable(d_states, d_freq, &d_extra, &d_base, &s.d);

    const payload = in[header_size..];
    if (payload.len < @as(u64, n_lit_payload) + n_lmd_payload) return error.Truncated;

    // Literals, four states interleaved, read backwards from the end of their payload.
    {
        var br = try BackReader.init(in[0 .. header_size + n_lit_payload], literal_bits);
        var i: u32 = 0;
        while (i < n_literals) : (i += 4) {
            try br.flush();
            inline for (0..4) |k| {
                const e = s.lit[lit_state[k]];
                lit_state[k] = @intCast(@as(i32, e.delta) + @as(i32, @intCast(br.pull(@intCast(e.k)))));
                if (lit_state[k] >= lit_states) return error.Corrupt;
                s.literals[i + k] = e.symbol;
            }
        }
    }

    // (L, M, D) triples.
    var br = try BackReader.init(in[0 .. header_size + n_lit_payload + n_lmd_payload], lmd_bits);
    var lit_pos: u32 = 0;
    var out = start;
    var dist: usize = 0;
    var i: u32 = 0;
    while (i < n_matches) : (i += 1) {
        try br.flush();
        const l = valueDecode(&l_state, &s.l, &br);
        const m = valueDecode(&m_state, &s.m, &br);
        const d = valueDecode(&d_state, &s.d, &br);
        if (l_state >= l_states or m_state >= m_states or d_state >= d_states) return error.Corrupt;
        if (d != 0) dist = d;
        if (l > n_literals - lit_pos or l > dst.len - out) return error.Corrupt;
        @memcpy(dst[out..][0..l], s.literals[lit_pos..][0..l]);
        lit_pos += l;
        out += l;
        if (m > dst.len - out) return error.Corrupt;
        if (m != 0) {
            if (dist == 0 or dist > out) return error.Corrupt;
            copyMatch(dst, out, dist, m);
            out += m;
        }
    }
    if (out != dst.len) return error.Corrupt;
    return header_size + n_lit_payload + n_lmd_payload;
}

const FreqCode = struct { value: u16, bits: u6 };

/// The frequency code: the low five bits select a 2, 3, 5, 8 or 14-bit code.
fn freqValue(bits: u32) FreqCode {
    const nbits_table = [32]u6{ 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14 };
    const value_table = [32]u16{ 0, 2, 1, 4, 0, 3, 1, 0, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 0, 0, 2, 1, 7, 0, 3, 1, 0 };
    const b = bits & 31;
    const n = nbits_table[b];
    return switch (n) {
        8 => .{ .value = @intCast(8 + ((bits >> 4) & 0xf)), .bits = 8 },
        14 => .{ .value = @intCast(24 + ((bits >> 4) & 0x3ff)), .bits = 14 },
        else => .{ .value = value_table[b], .bits = n },
    };
}

/// FSE states for each symbol, in symbol order: a state of symbol `i` with frequency `f` reads
/// `k` or `k - 1` bits, where `k` makes `f << k` land in [N, 2N).
fn initTable(comptime n: u32, freq: []const u16, t: *[n]Entry) Error!void {
    @memset(t, .{});
    var pos: u32 = 0;
    for (freq, 0..) |f_in, sym| {
        const f: u32 = f_in;
        if (f == 0) continue;
        if (f > n - pos) return error.Corrupt;
        const k: u32 = @clz(f) - @clz(n);
        const j0: u32 = ((2 * n) >> @intCast(k)) - f;
        for (0..f) |j32| {
            const j: u32 = @intCast(j32);
            t[pos + j] = if (j < j0)
                .{ .k = @intCast(k), .symbol = @intCast(sym), .delta = @intCast(@as(i32, @intCast((f + j) << @intCast(k))) - @as(i32, n)) }
            else
                .{ .k = @intCast(k - 1), .symbol = @intCast(sym), .delta = @intCast((j - j0) << @intCast(k - 1)) };
        }
        pos += f;
    }
}

fn initValueTable(comptime n: u32, freq: []const u16, extra: []const u8, base: []const u32, t: *[n]ValueEntry) Error!void {
    var plain: [n]Entry = undefined;
    try initTable(n, freq, &plain);
    for (t, plain) |*v, e| v.* = .{
        .total_bits = e.k + extra[e.symbol],
        .value_bits = extra[e.symbol],
        .delta = e.delta,
        .vbase = base[e.symbol],
    };
}

fn valueDecode(state: *u32, t: []const ValueEntry, br: *BackReader) u32 {
    const e = t[state.*];
    const bits = br.pull(@intCast(e.total_bits));
    state.* = @intCast(@as(i64, e.delta) + @as(i64, @intCast(bits >> @intCast(e.value_bits))));
    return e.vbase + @as(u32, @intCast(bits & ((@as(u64, 1) << @intCast(e.value_bits)) - 1)));
}

/// The FSE bit stream: read backwards from the end of a payload, 64-bit accumulator, bits pulled
/// from the top. `buf` runs from the start of the block to the end of the payload: refills read
/// ahead by up to 8 bytes and may reach into the bytes before the payload, which a valid stream
/// never pulls.
const BackReader = struct {
    buf: []const u8,
    pos: usize,
    accum: u64,
    nbits: u7,

    fn init(buf: []const u8, initial: i32) Error!BackReader {
        if (initial > 0 or initial < -7) return error.Corrupt;
        var r: BackReader = .{ .buf = buf, .pos = buf.len, .accum = 0, .nbits = 0 };
        if (initial != 0) {
            if (buf.len < 8) return error.Truncated;
            r.pos -= 8;
            r.accum = std.mem.readInt(u64, buf[r.pos..][0..8], .little);
            r.nbits = @intCast(64 + initial);
        } else {
            if (buf.len < 7) return error.Truncated;
            r.pos -= 7;
            var b: [8]u8 = @splat(0);
            @memcpy(b[0..7], buf[r.pos..][0..7]);
            r.accum = std.mem.readInt(u64, &b, .little);
            r.nbits = 56;
        }
        if (r.nbits < 56 or r.nbits >= 64 or (r.accum >> @intCast(r.nbits)) != 0) return error.Corrupt;
        return r;
    }

    /// Top up to at least 56 bits, a whole number of bytes at a time.
    fn flush(r: *BackReader) Error!void {
        const want: u7 = (63 - r.nbits) & ~@as(u7, 7);
        const bytes = want >> 3;
        if (bytes > r.pos) return error.Truncated;
        if (bytes == 0) return;
        r.pos -= bytes;
        var b: [8]u8 = @splat(0);
        @memcpy(b[0..bytes], r.buf[r.pos..][0..bytes]);
        const incoming = std.mem.readInt(u64, &b, .little);
        r.accum = (r.accum << @intCast(want)) | incoming;
        r.nbits += want;
    }

    fn pull(r: *BackReader, n: u7) u64 {
        if (n == 0) return 0;
        if (n > r.nbits) {
            // Corrupt data asked for more than the stream holds: yield zeros, the caller's
            // bounds checks reject what follows.
            r.nbits = 0;
            r.accum = 0;
            return 0;
        }
        r.nbits -= n;
        const v = r.accum >> @intCast(r.nbits);
        r.accum &= if (r.nbits == 0) 0 else (@as(u64, 1) << @intCast(r.nbits)) - 1;
        return v;
    }
};

fn copyMatch(dst: []u8, out: usize, dist: usize, len: usize) void {
    var i: usize = 0;
    while (i < len) : (i += 1) dst[out + i] = dst[out + i - dist];
}

// ---------------------------------------------------------------------------------------------
// LZVN (bvxn)

/// Decode an LZVN payload so that `dst[start..]` is exactly filled.
fn lzvn(src: []const u8, dst: []u8, start: usize) Error!void {
    var p: usize = 0;
    var out = start;
    var dist: usize = 0;
    while (true) {
        if (p >= src.len) return error.Truncated;
        const op = src[p];
        var lit: usize = 0;
        var len: usize = 0;
        var oplen: usize = 1;
        switch (op) {
            0x06 => break, // end of stream
            0x0e, 0x16 => {
                p += 1;
                continue;
            },
            0x1e, 0x26, 0x2e, 0x36, 0x3e, 0x70...0x7f, 0xd0...0xdf => return error.Corrupt,
            0xa0...0xbf => {
                // Medium distance: 101LLMMM DDDDDDMM DDDDDDDD.
                if (src.len - p < 3) return error.Truncated;
                lit = (op >> 3) & 3;
                len = ((@as(usize, op & 7) << 2) | (src[p + 1] & 3)) + 3;
                dist = (@as(usize, src[p + 2]) << 6) | (src[p + 1] >> 2);
                oplen = 3;
            },
            0xe0 => {
                if (src.len - p < 2) return error.Truncated;
                lit = @as(usize, src[p + 1]) + 16;
                oplen = 2;
            },
            0xe1...0xef => lit = op & 0x0f,
            0xf0 => {
                if (src.len - p < 2) return error.Truncated;
                len = @as(usize, src[p + 1]) + 16;
                oplen = 2;
            },
            0xf1...0xff => len = op & 0x0f,
            else => {
                lit = op >> 6;
                len = ((op >> 3) & 7) + 3;
                switch (op & 7) {
                    6 => {}, // previous distance
                    7 => {
                        if (src.len - p < 3) return error.Truncated;
                        dist = std.mem.readInt(u16, src[p + 1 ..][0..2], .little);
                        oplen = 3;
                    },
                    else => {
                        if (src.len - p < 2) return error.Truncated;
                        dist = (@as(usize, op & 7) << 8) | src[p + 1];
                        oplen = 2;
                    },
                }
            },
        }
        p += oplen;
        if (lit > 0) {
            if (lit > src.len - p) return error.Truncated;
            if (lit > dst.len - out) return error.Corrupt;
            @memcpy(dst[out..][0..lit], src[p..][0..lit]);
            p += lit;
            out += lit;
        }
        if (len > 0) {
            if (dist == 0 or dist > out or len > dst.len - out) return error.Corrupt;
            copyMatch(dst, out, dist, len);
            out += len;
        }
    }
    if (out != dst.len) return error.Corrupt;
}

test "fse tables cover every state exactly once" {
    var t: [64]Entry = undefined;
    var freq: [20]u16 = @splat(0);
    freq[0] = 40;
    freq[3] = 20;
    freq[19] = 4;
    try initTable(64, &freq, &t);
    // A symbol with frequency f covers f consecutive states, and the states it reaches next
    // span [0, 64).
    try std.testing.expectEqual(@as(u8, 0), t[39].symbol);
    try std.testing.expectEqual(@as(u8, 3), t[40].symbol);
    try std.testing.expectEqual(@as(u8, 19), t[63].symbol);
    freq[1] = 1;
    try std.testing.expectError(error.Corrupt, initTable(64, &freq, &t));
}

test "lzvn: literals, a match and the end marker" {
    // e3 "abc" (3 literals), then a small-distance match: L=0, M=3, D=3 (0b00000_000 0x03),
    // then end of stream.
    const src = [_]u8{ 0xe3, 'a', 'b', 'c', 0x00, 0x03, 0x06, 0, 0, 0, 0, 0, 0, 0 };
    var dst: [6]u8 = undefined;
    try lzvn(&src, &dst, 0);
    try std.testing.expectEqualStrings("abcabc", &dst);
}

test "reference vectors from Apple's encoder: LZVN, multi-block LZFSE and stored blocks" {
    const fixtures = @import("fixtures/fixtures.zig");
    const gpa = std.testing.allocator;
    const s = try gpa.create(Scratch);
    defer gpa.destroy(s);
    for (fixtures.lzfse_vectors) |v| {
        const out = try gpa.alloc(u8, v.plain_len + 16);
        defer gpa.free(out);
        const n = decode(v.compressed, out, s) catch |e| {
            std.debug.print("lzfse {s}: {t}\n", .{ v.name, e });
            return e;
        };
        try std.testing.expectEqual(v.plain_len, n);
        try std.testing.expectEqual(v.plain_crc, std.hash.Crc32.hash(out[0..n]));
        // Too small an output buffer is an error, not an overrun.
        if (n > 1) try std.testing.expectError(error.OutputFull, decode(v.compressed, out[0 .. n - 1], s));
    }
}

test "stored blocks and the end marker" {
    const src = "bvx-\x03\x00\x00\x00abcbvx-\x02\x00\x00\x00debvx$";
    var dst: [8]u8 = undefined;
    var s: Scratch = undefined;
    try std.testing.expectEqual(@as(usize, 5), try decode(src, &dst, &s));
    try std.testing.expectEqualStrings("abcde", dst[0..5]);
    try std.testing.expectError(error.Truncated, decode(src[0 .. src.len - 2], &dst, &s));
}
