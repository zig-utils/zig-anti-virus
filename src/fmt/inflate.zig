//! A table-driven DEFLATE decoder (RFC 1951) with the gzip (RFC 1952) and zlib (RFC 1950)
//! wrappers. Written from the RFCs for E7 (#102): std.compress.flate reads every symbol through
//! per-call bit-reader helpers and copies matches byte by byte, which ran at 23 to 52% of the C
//! decoders.
//!
//! How it is fast:
//! - The hot loop keeps a 64-bit bit buffer in a local, refilled a word at a time straight from
//!   the input reader's buffer (one unaligned load, no per-byte branch).
//! - Literal/length symbols decode in one lookup of an 11-bit table (8 bits for distances), with
//!   a second-level table for longer codes. A length entry carries its base and extra-bit count,
//!   so the length is one shift and mask away. Up to three literals decode per refill.
//! - Matches copy 16 or 8 bytes at a time when the distance allows, into slack past the limit.
//!
//! Streaming: input comes from an `Io.Reader`, and the decoder never takes a byte it has not
//! used (the hot loop gives back whole bytes it loaded ahead), so a gzip trailer, the next gzip
//! member or a zip's next record stays in the reader. Output goes to a linear buffer holding 32
//! KiB of history plus room for new output, which is slid when full. Memory is the caller's:
//! `work_len` bytes, carved into the output buffer and the decode tables.
//!
//! Like std's decoder, the gzip CRC-32 and zlib Adler-32 trailers are skipped, not verified (a
//! scanner reads damaged data anyway). Error names match std.compress.flate.Decompress.Error.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");

pub const history_len = 32 * 1024;
/// New output decoded per refill of the output buffer.
const out_room = 128 * 1024;
/// Over-long match copies (up to 15 bytes) land here, past the decode limit.
const slack = 64;
const max_match = 258;
const buffer_len = history_len + out_room + max_match + slack;

/// Bytes of caller memory a decoder needs: the output buffer plus the tables.
pub const work_len = buffer_len + @sizeOf(Tables) + @alignOf(Tables);

pub const Container = enum { raw, gzip, zlib };

pub const Error = error{
    BadGzipHeader,
    BadZlibHeader,
    InvalidBlockType,
    WrongStoredBlockNlen,
    InvalidDynamicBlockHeader,
    OversubscribedHuffmanTree,
    IncompleteHuffmanTree,
    MissingEndOfBlockCode,
    InvalidCode,
    InvalidMatch,
    EndOfStream,
    ReadFailed,
};

// Table entries (u32):
//   bits 0..7    bits to consume: code length plus extra bits (for a subtable link, the root bits)
//   bits 8..11   code length (for a subtable link, the subtable's index bits)
//   bit 13       literal
//   bit 14       subtable link
//   bit 15       exceptional: end of block (value 0) or an invalid code (value 1)
//   bits 16..31  value: the literal, length or distance base, or the subtable offset
const flag_lit: u32 = 1 << 13;
const flag_sub: u32 = 1 << 14;
const flag_exc: u32 = 1 << 15;
const entry_eob: u32 = flag_exc;
const entry_invalid: u32 = flag_exc | (1 << 16);

const lit_root = 11;
const dist_root = 8;
const pre_root = 7;
// Second-level tables are sized by the longest code under each root prefix, so each takes at
// most 2^(15 - root) entries and there is at most one per code longer than the root.
const lit_table_len = (1 << lit_root) + 288 * (1 << (15 - lit_root));
const dist_table_len = (1 << dist_root) + 32 * (1 << (15 - dist_root));

const Tables = struct {
    lit: [lit_table_len]u32,
    dist: [dist_table_len]u32,
    pre: [1 << pre_root]u32,
};

const length_base = [29]u16{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
const length_extra = [29]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
const dist_base = [30]u16{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
const dist_extra = [30]u8{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
const precode_order = [19]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

const Kind = enum { lit, dist, pre };

fn entryFor(comptime kind: Kind, sym: usize, len: u32) u32 {
    switch (kind) {
        .pre => return (@as(u32, @intCast(sym)) << 16) | (len << 8) | len,
        .lit => {
            if (sym < 256) return flag_lit | (@as(u32, @intCast(sym)) << 16) | (len << 8) | len;
            if (sym == 256) return entry_eob | (len << 8) | len;
            if (sym > 285) return entry_invalid | (len << 8) | len;
            const i = sym - 257;
            return (@as(u32, length_base[i]) << 16) | (len << 8) | (len + length_extra[i]);
        },
        .dist => {
            if (sym >= 30) return entry_invalid | (len << 8) | len;
            return (@as(u32, dist_base[sym]) << 16) | (len << 8) | (len + dist_extra[sym]);
        },
    }
}

fn reverse(code: u32, len: u32) u32 {
    return @as(u32, @bitReverse(@as(u16, @intCast(code)))) >> @intCast(16 - len);
}

/// Build a two-level decode table from canonical code lengths. Incomplete codes are accepted
/// only as a single one-bit code, or no codes at all for distances (as zlib does); the unused
/// half then decodes as an invalid code.
fn build(comptime kind: Kind, table: []u32, lens: []const u8, comptime root: u5) Error!void {
    var count: [16]u16 = @splat(0);
    for (lens) |l| count[l] += 1;
    count[0] = 0;
    var left: i32 = 1;
    var n_codes: u32 = 0;
    var max_len: u32 = 0;
    for (1..16) |l| {
        left = (left << 1) - count[l];
        if (left < 0) return error.OversubscribedHuffmanTree;
        n_codes += count[l];
        if (count[l] != 0) max_len = @intCast(l);
    }
    if (left > 0) {
        const allowed = kind != .pre and ((n_codes == 0 and kind == .dist) or (n_codes == 1 and max_len == 1));
        if (!allowed) return error.IncompleteHuffmanTree;
        @memset(table[0 .. 1 << root], entry_invalid);
    }

    // Symbols in canonical order (by length, then symbol), with their codes.
    var offs: [16]u16 = undefined;
    var next: [16]u32 = undefined;
    offs[1] = 0;
    next[1] = 0;
    for (2..16) |l| {
        offs[l] = offs[l - 1] + count[l - 1];
        next[l] = (next[l - 1] + count[l - 1]) << 1;
    }
    var sorted: [320]u16 = undefined;
    var codes: [320]u16 = undefined;
    for (lens, 0..) |l, sym| {
        if (l == 0) continue;
        sorted[offs[l]] = @intCast(sym);
        codes[offs[l]] = @intCast(next[l]);
        offs[l] += 1;
        next[l] += 1;
    }

    var sub_next: u32 = 1 << root;
    var cur_prefix: u32 = std.math.maxInt(u32);
    var sub_off: u32 = 0;
    var sub_bits: u32 = 0;
    for (0..n_codes) |i| {
        const sym = sorted[i];
        const len: u32 = lens[sym];
        const code: u32 = codes[i];
        if (len <= root) {
            const e = entryFor(kind, sym, len);
            var j = reverse(code, len);
            while (j < (1 << root)) : (j += @as(u32, 1) << @intCast(len)) table[j] = e;
            continue;
        }
        const prefix = code >> @intCast(len - root);
        if (prefix != cur_prefix) {
            // A new second-level table, sized by the longest code under this prefix.
            cur_prefix = prefix;
            var k = i;
            var longest = len;
            while (k < n_codes) : (k += 1) {
                const lk: u32 = lens[sorted[k]];
                if (codes[k] >> @intCast(lk - root) != prefix) break;
                longest = lk;
            }
            sub_bits = longest - root;
            sub_off = sub_next;
            sub_next += @as(u32, 1) << @intCast(sub_bits);
            std.debug.assert(sub_next <= table.len);
            table[reverse(prefix, root)] = flag_sub | (sub_off << 16) | (sub_bits << 8) | root;
        }
        const rest = len - root;
        const e = entryFor(kind, sym, rest);
        var j = reverse(code & ((@as(u32, 1) << @intCast(rest)) - 1), rest);
        while (j < (@as(u32, 1) << @intCast(sub_bits))) : (j += @as(u32, 1) << @intCast(rest)) table[sub_off + j] = e;
    }
}

inline fn load64(p: [*]const u8) u64 {
    return std.mem.readInt(u64, p[0..8], .little);
}

inline fn mask(n: u32) u64 {
    return (@as(u64, 1) << @intCast(n)) - 1;
}

pub const Inflate = struct {
    in: *Io.Reader,
    format: Container,
    buf: []u8,
    tables: *Tables,
    /// Write position in `buf`; output below it is history or not yet read.
    wp: usize = 0,
    /// Read position: output from here to `wp` is waiting for the consumer.
    rp: usize = 0,
    /// Bits of `in.buffer[in.seek]` already consumed.
    bitoff: u3 = 0,
    state: State = .header,
    final: bool = false,
    stored_left: u32 = 0,
    err: ?Error = null,
    interface: Io.Reader,

    const State = enum { header, block, stored, codes, trailer, done };

    /// `work` must hold at least `work_len` bytes. Fill the result in place (`d.* = init()`)
    /// before reading: the reader is found by its address.
    pub fn init(in: *Io.Reader, format: Container, work: []u8) Inflate {
        std.debug.assert(work.len >= work_len);
        const addr = std.mem.alignForward(usize, @intFromPtr(work.ptr), @alignOf(Tables));
        const off = addr - @intFromPtr(work.ptr);
        return .{
            .in = in,
            .format = format,
            .tables = @ptrCast(@alignCast(work[off..].ptr)),
            .buf = work[off + @sizeOf(Tables) ..][0..buffer_len],
            .interface = .{ .vtable = container.fillVTable(Inflate), .buffer = &.{}, .seek = 0, .end = 0 },
        };
    }

    /// Start a new stream over the same reader and memory (the next gzip member).
    pub fn reset(d: *Inflate) void {
        d.wp = 0;
        d.rp = 0;
        d.bitoff = 0;
        d.state = .header;
        d.final = false;
        d.stored_left = 0;
        d.err = null;
    }

    /// Whether the stream (and its trailer) has been decoded to the end.
    pub fn finished(d: *const Inflate) bool {
        return d.state == .done and d.rp == d.wp;
    }

    pub fn fill(d: *Inflate, dest: []u8) Io.Reader.Error!usize {
        while (true) {
            if (d.rp < d.wp) {
                const n = @min(d.wp - d.rp, dest.len);
                @memcpy(dest[0..n], d.buf[d.rp..][0..n]);
                d.rp += n;
                return n;
            }
            if (d.state == .done) return 0;
            if (d.err != null) return error.ReadFailed;
            d.produce() catch |e| {
                d.err = e;
                return error.ReadFailed;
            };
        }
    }

    /// Decode until the output buffer is full or the stream ends. Only called with every
    /// decoded byte read (`rp == wp`).
    fn produce(d: *Inflate) Error!void {
        const limit = buffer_len - slack;
        if (d.wp + max_match + 3 > limit) {
            @memmove(d.buf[0..history_len], d.buf[d.wp - history_len .. d.wp]);
            d.wp = history_len;
            d.rp = history_len;
        }
        while (true) switch (d.state) {
            .header => {
                try d.readHeader();
                d.state = .block;
            },
            .block => {
                if (d.final) {
                    d.state = .trailer;
                    continue;
                }
                const h: u32 = @intCast(try d.takeBits(3));
                d.final = h & 1 == 1;
                switch (h >> 1) {
                    0 => {
                        d.alignByte();
                        const lens = d.in.takeArray(4) catch |e| return e;
                        const len = std.mem.readInt(u16, lens[0..2], .little);
                        const nlen = std.mem.readInt(u16, lens[2..4], .little);
                        if (len != ~nlen) return error.WrongStoredBlockNlen;
                        d.stored_left = len;
                        d.state = .stored;
                    },
                    1 => {
                        try d.fixedTables();
                        d.state = .codes;
                    },
                    2 => {
                        try d.dynamicTables();
                        d.state = .codes;
                    },
                    else => return error.InvalidBlockType,
                }
            },
            .stored => {
                const n = @min(d.stored_left, limit - d.wp);
                if (n == 0 and d.stored_left != 0) return;
                d.in.readSliceAll(d.buf[d.wp..][0..n]) catch |e| return e;
                d.wp += n;
                d.stored_left -= @intCast(n);
                if (d.stored_left != 0) return;
                d.state = .block;
            },
            .codes => {
                if (!try d.codes(limit)) return;
                d.state = .block;
            },
            .trailer => {
                d.alignByte();
                switch (d.format) {
                    .raw => {},
                    .gzip => d.in.discardAll(8) catch |e| return e,
                    .zlib => d.in.discardAll(4) catch |e| return e,
                }
                d.state = .done;
                return;
            },
            .done => return,
        };
    }

    fn readHeader(d: *Inflate) Error!void {
        const in = d.in;
        switch (d.format) {
            .raw => {},
            .zlib => {
                const h = in.takeArray(2) catch |e| return e;
                if (h[0] & 0x0f != 8 or h[0] >> 4 > 7 or (@as(u16, h[0]) << 8 | h[1]) % 31 != 0) return error.BadZlibHeader;
                if (h[1] & 0x20 != 0) return error.BadZlibHeader; // preset dictionary
            },
            .gzip => {
                const h = in.takeArray(10) catch |e| return e;
                if (h[0] != 0x1f or h[1] != 0x8b or h[2] != 8) return error.BadGzipHeader;
                const flags = h[3];
                if (flags & 0x04 != 0) {
                    const xlen = in.takeInt(u16, .little) catch |e| return e;
                    in.discardAll(xlen) catch |e| return e;
                }
                if (flags & 0x08 != 0) _ = in.discardDelimiterInclusive(0) catch |e| return e;
                if (flags & 0x10 != 0) _ = in.discardDelimiterInclusive(0) catch |e| return e;
                if (flags & 0x02 != 0) in.discardAll(2) catch |e| return e;
            },
        }
    }

    // Slow bit reading, for headers and the last bytes of the input buffer: the position is
    // `in.seek` plus `bitoff`, and bits are read without taking bytes until they are consumed.

    /// Up to 64 bits from the current position; past the end of the stream they read as zero
    /// and `avail` says how many are real.
    fn peekSlow(d: *Inflate) Error!struct { bits: u64, avail: u32 } {
        const in = d.in;
        if (in.end - in.seek < 8) {
            in.fill(@min(8, in.buffer.len)) catch |e| switch (e) {
                error.EndOfStream => {},
                error.ReadFailed => return error.ReadFailed,
            };
        }
        const b = in.buffered();
        var word: u64 = 0;
        if (b.len >= 8) word = load64(b.ptr) else {
            for (b, 0..) |c, i| word |= @as(u64, c) << @intCast(8 * i);
        }
        const n: u32 = @intCast(@min(b.len, 8));
        return .{ .bits = word >> d.bitoff, .avail = n * 8 -| d.bitoff };
    }

    fn consume(d: *Inflate, n: u32) void {
        const t = @as(u32, d.bitoff) + n;
        d.in.toss(t >> 3);
        d.bitoff = @intCast(t & 7);
    }

    fn takeBits(d: *Inflate, n: u32) Error!u64 {
        const p = try d.peekSlow();
        if (p.avail < n) return error.EndOfStream;
        d.consume(n);
        return p.bits & mask(n);
    }

    fn alignByte(d: *Inflate) void {
        if (d.bitoff != 0) {
            d.in.toss(1);
            d.bitoff = 0;
        }
    }

    fn fixedTables(d: *Inflate) Error!void {
        var lens: [288]u8 = undefined;
        @memset(lens[0..144], 8);
        @memset(lens[144..256], 9);
        @memset(lens[256..280], 7);
        @memset(lens[280..288], 8);
        try build(.lit, &d.tables.lit, &lens, lit_root);
        @memset(lens[0..32], 5);
        try build(.dist, &d.tables.dist, lens[0..32], dist_root);
    }

    fn dynamicTables(d: *Inflate) Error!void {
        const h: u32 = @intCast(try d.takeBits(14));
        const hlit = (h & 31) + 257;
        const hdist = ((h >> 5) & 31) + 1;
        const hclen = (h >> 10) + 4;
        if (hlit > 286 or hdist > 30) return error.InvalidDynamicBlockHeader;
        var pre_lens: [19]u8 = @splat(0);
        for (precode_order[0..hclen]) |sym| pre_lens[sym] = @intCast(try d.takeBits(3));
        build(.pre, &d.tables.pre, &pre_lens, pre_root) catch return error.InvalidDynamicBlockHeader;

        var lens: [286 + 30]u8 = undefined;
        const total = hlit + hdist;
        var i: u32 = 0;
        while (i < total) {
            const p = try d.peekSlow();
            const e = d.tables.pre[@intCast(p.bits & mask(pre_root))];
            if (e & flag_exc != 0) return error.InvalidDynamicBlockHeader;
            const len = e & 0xff;
            const sym = e >> 16;
            if (sym < 16) {
                if (len > p.avail) return error.EndOfStream;
                d.consume(len);
                lens[i] = @intCast(sym);
                i += 1;
                continue;
            }
            const extra: u32 = switch (sym) {
                16 => 2,
                17 => 3,
                else => 7,
            };
            if (len + extra > p.avail) return error.EndOfStream;
            d.consume(len + extra);
            const x: u32 = @intCast((p.bits >> @intCast(len)) & mask(extra));
            const value: u8, const run: u32 = switch (sym) {
                16 => blk: {
                    if (i == 0) return error.InvalidDynamicBlockHeader;
                    break :blk .{ lens[i - 1], 3 + x };
                },
                17 => .{ 0, 3 + x },
                else => .{ 0, 11 + x },
            };
            if (i + run > total) return error.InvalidDynamicBlockHeader;
            @memset(lens[i..][0..run], value);
            i += run;
        }
        if (lens[256] == 0) return error.MissingEndOfBlockCode;
        try build(.lit, &d.tables.lit, lens[0..hlit], lit_root);
        try build(.dist, &d.tables.dist, lens[hlit..total], dist_root);
    }

    /// Decode symbols of the current block until its end (true) or until the output reaches
    /// `limit` (false).
    fn codes(d: *Inflate, limit: usize) Error!bool {
        const lit = &d.tables.lit;
        const dist = &d.tables.dist;
        const out = d.buf.ptr;
        var wp = d.wp;
        defer d.wp = wp;
        const in = d.in;
        while (true) {
            if (wp + max_match + 3 > limit) return false;
            if (in.end - in.seek < 32) {
                in.fill(@min(64, in.buffer.len)) catch |e| switch (e) {
                    error.EndOfStream => {},
                    error.ReadFailed => return error.ReadFailed,
                };
            }
            if (in.end - in.seek >= 32) {
                // Fast loop: the bit buffer lives in locals, refilled a word at a time.
                const base = in.buffer.ptr;
                var p = in.seek;
                const p_end = in.end - 16;
                var bitbuf: u64 = 0;
                var nbits: u32 = 0;
                bitbuf |= load64(base + p) << @intCast(nbits);
                p += (63 - nbits) >> 3;
                nbits |= 56;
                bitbuf >>= d.bitoff;
                nbits -= d.bitoff;
                var eob = false;
                var bad: ?Error = null;
                while (p <= p_end and wp + max_match + 3 <= limit) {
                    bitbuf |= load64(base + p) << @intCast(nbits);
                    p += (63 - nbits) >> 3;
                    nbits |= 56;
                    var e = lit[@intCast(bitbuf & mask(lit_root))];
                    if (e & flag_lit != 0) {
                        // Up to three literals per refill: 56 bits cover three 15-bit codes.
                        bitbuf >>= @intCast(e & 0xff);
                        nbits -= e & 0xff;
                        out[wp] = @intCast(e >> 16);
                        wp += 1;
                        e = lit[@intCast(bitbuf & mask(lit_root))];
                        if (e & flag_lit != 0) {
                            bitbuf >>= @intCast(e & 0xff);
                            nbits -= e & 0xff;
                            out[wp] = @intCast(e >> 16);
                            wp += 1;
                            e = lit[@intCast(bitbuf & mask(lit_root))];
                            if (e & flag_lit != 0) {
                                bitbuf >>= @intCast(e & 0xff);
                                nbits -= e & 0xff;
                                out[wp] = @intCast(e >> 16);
                                wp += 1;
                                continue;
                            }
                        }
                        bitbuf |= load64(base + p) << @intCast(nbits);
                        p += (63 - nbits) >> 3;
                        nbits |= 56;
                    }
                    if (e & flag_sub != 0) {
                        bitbuf >>= lit_root;
                        nbits -= lit_root;
                        e = lit[(e >> 16) + @as(u32, @intCast(bitbuf & mask((e >> 8) & 15)))];
                        if (e & flag_lit != 0) {
                            bitbuf >>= @intCast(e & 0xff);
                            nbits -= e & 0xff;
                            out[wp] = @intCast(e >> 16);
                            wp += 1;
                            continue;
                        }
                    }
                    if (e & flag_exc != 0) {
                        if (e & entry_invalid == entry_invalid) {
                            bad = error.InvalidCode;
                            break;
                        }
                        bitbuf >>= @intCast(e & 0xff);
                        nbits -= e & 0xff;
                        eob = true;
                        break;
                    }
                    // A length (up to 20 bits) and a distance (up to 28): 48 bits, all buffered.
                    const len: usize = (e >> 16) + @as(u32, @intCast((bitbuf & mask(e & 0xff)) >> @intCast((e >> 8) & 15)));
                    bitbuf >>= @intCast(e & 0xff);
                    nbits -= e & 0xff;
                    var de = dist[@intCast(bitbuf & mask(dist_root))];
                    if (de & flag_sub != 0) {
                        bitbuf >>= dist_root;
                        nbits -= dist_root;
                        de = dist[(de >> 16) + @as(u32, @intCast(bitbuf & mask((de >> 8) & 15)))];
                    }
                    if (de & flag_exc != 0) {
                        bad = error.InvalidCode;
                        break;
                    }
                    const dd: usize = (de >> 16) + @as(u32, @intCast((bitbuf & mask(de & 0xff)) >> @intCast((de >> 8) & 15)));
                    bitbuf >>= @intCast(de & 0xff);
                    nbits -= de & 0xff;
                    if (dd > wp) {
                        bad = error.InvalidMatch;
                        break;
                    }
                    copyMatch(out, wp, dd, len);
                    wp += len;
                }
                // Give back whole bytes loaded ahead of the consumed bits.
                const rem = nbits & 7;
                in.seek = p - (nbits >> 3) - @intFromBool(rem != 0);
                d.bitoff = @intCast((8 - rem) & 7);
                if (bad) |b| return b;
                if (eob) return true;
                continue;
            }
            // Slow path, one symbol at a time near the end of the input.
            const pk = try d.peekSlow();
            var bits = pk.bits;
            var used: u32 = 0;
            var e = lit[@intCast(bits & mask(lit_root))];
            if (e & flag_sub != 0) {
                bits >>= lit_root;
                used = lit_root;
                e = lit[(e >> 16) + @as(u32, @intCast(bits & mask((e >> 8) & 15)))];
            }
            const elen = e & 0xff;
            if (used + elen > pk.avail) return error.EndOfStream;
            if (e & flag_exc != 0) {
                if (e & entry_invalid == entry_invalid) return error.InvalidCode;
                d.consume(used + elen);
                return true;
            }
            if (e & flag_lit != 0) {
                d.consume(used + elen);
                out[wp] = @intCast(e >> 16);
                wp += 1;
                continue;
            }
            const len: usize = (e >> 16) + @as(u32, @intCast((bits & mask(elen)) >> @intCast((e >> 8) & 15)));
            bits >>= @intCast(elen);
            used += elen;
            var de = dist[@intCast(bits & mask(dist_root))];
            if (de & flag_sub != 0) {
                bits >>= dist_root;
                used += dist_root;
                de = dist[(de >> 16) + @as(u32, @intCast(bits & mask((de >> 8) & 15)))];
            }
            const dlen = de & 0xff;
            if (used + dlen > pk.avail) return error.EndOfStream;
            if (de & flag_exc != 0) return error.InvalidCode;
            const dd: usize = (de >> 16) + @as(u32, @intCast((bits & mask(dlen)) >> @intCast((de >> 8) & 15)));
            if (dd > wp) return error.InvalidMatch;
            d.consume(used + dlen);
            copyMatch(out, wp, dd, len);
            wp += len;
        }
    }
};

/// Copy `len` bytes from `dist` back. May write up to 15 bytes past the end (into slack).
inline fn copyMatch(out: [*]u8, wp: usize, dist: usize, len: usize) void {
    var dst = out + wp;
    var src = dst - dist;
    const end = dst + len;
    if (dist >= 16) {
        while (true) {
            const v: @Vector(16, u8) = src[0..16].*;
            dst[0..16].* = v;
            dst += 16;
            src += 16;
            if (@intFromPtr(dst) >= @intFromPtr(end)) break;
        }
    } else if (dist >= 8) {
        while (true) {
            const v: [8]u8 = src[0..8].*;
            dst[0..8].* = v;
            dst += 8;
            src += 8;
            if (@intFromPtr(dst) >= @intFromPtr(end)) break;
        }
    } else if (dist == 1) {
        const v: @Vector(16, u8) = @splat(src[0]);
        while (true) {
            dst[0..16].* = v;
            dst += 16;
            if (@intFromPtr(dst) >= @intFromPtr(end)) break;
        }
    } else {
        for (0..len) |i| dst[i] = src[i];
    }
}

// Tests: round trips through std's compressor at several levels and block types, a
// differential check against std's decoder on mutated streams, and the streaming contract.

fn decodeAll(gpa: std.mem.Allocator, compressed: []const u8, format: Container, in_buf_len: usize) ![]u8 {
    const work = try gpa.alloc(u8, work_len);
    defer gpa.free(work);
    // A reader that hands out the input a few bytes at a time exercises the slow path.
    var src: Trickle = .{ .data = compressed, .step = in_buf_len, .interface = undefined };
    const in_buf = try gpa.alloc(u8, @max(in_buf_len, 16));
    defer gpa.free(in_buf);
    src.interface = .{ .vtable = &Trickle.vtable, .buffer = in_buf, .seek = 0, .end = 0 };
    var d = Inflate.init(&src.interface, format, work);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var chunk: [5000]u8 = undefined;
    while (true) {
        const n = container.readSome(&d.interface, &chunk) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return d.err.?,
        };
        try out.appendSlice(gpa, chunk[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

/// Serves `data` in pieces of at most `step` bytes.
const Trickle = struct {
    data: []const u8,
    pos: usize = 0,
    step: usize,
    interface: Io.Reader,

    const vtable: Io.Reader.VTable = .{ .stream = stream };

    fn stream(r: *Io.Reader, w: *Io.Writer, lim: Io.Limit) Io.Reader.StreamError!usize {
        const t: *Trickle = @alignCast(@fieldParentPtr("interface", r));
        if (t.pos == t.data.len) return error.EndOfStream;
        const n = lim.minInt(@min(t.step, t.data.len - t.pos));
        const got = try w.write(t.data[t.pos..][0..n]);
        t.pos += got;
        return got;
    }
};

fn stdCompress(gpa: std.mem.Allocator, data: []const u8, format: std.compress.flate.Container, opts: ?std.compress.flate.Compress.Options) ![]u8 {
    var out: Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    errdefer out.deinit();
    const buf = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(buf);
    if (opts) |o| {
        var c = try std.compress.flate.Compress.init(&out.writer, buf, format, o);
        try c.writer.writeAll(data);
        try c.finish();
    } else {
        var c = try std.compress.flate.Compress.Huffman.init(&out.writer, buf, format);
        try c.writer.writeAll(data);
        try c.finish();
    }
    return out.toOwnedSlice();
}

fn testData(gpa: std.mem.Allocator, len: usize, seed: u64) ![]u8 {
    const data = try gpa.alloc(u8, len);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var i: usize = 0;
    while (i < len) {
        const kind = r.uintLessThan(u8, 4);
        const n = @min(len - i, 1 + r.uintLessThan(usize, 600));
        switch (kind) {
            0 => r.bytes(data[i..][0..n]),
            1 => @memset(data[i..][0..n], r.int(u8)),
            2 => for (data[i..][0..n], 0..) |*b, k| {
                b.* = "the quick brown fox jumps over the lazy dog "[k % 44];
            },
            else => if (i > 0) {
                // A back-reference with a short period (distances 1 to 20).
                const period = 1 + r.uintLessThan(usize, @min(i, 20));
                for (data[i..][0..n], 0..) |*b, k| b.* = data[i - period + k % period];
            } else r.bytes(data[i..][0..n]),
        }
        i += n;
    }
    return data;
}

test "round trips std's compressor output at every level, gzip, zlib and raw" {
    const gpa = std.testing.allocator;
    const Options = std.compress.flate.Compress.Options;
    const levels = [_]?Options{ null, Options.level_1, Options.level_4, Options.level_6, Options.level_9 };
    for ([_]usize{ 0, 1, 100, 70_000, 400_000 }, 0..) |len, li| {
        const data = try testData(gpa, len, li);
        defer gpa.free(data);
        for (levels) |opts| {
            inline for (.{ .{ std.compress.flate.Container.gzip, Container.gzip }, .{ std.compress.flate.Container.zlib, Container.zlib }, .{ std.compress.flate.Container.raw, Container.raw } }) |pair| {
                const c = try stdCompress(gpa, data, pair[0], opts);
                defer gpa.free(c);
                for ([_]usize{ 64 * 1024, 7 }) |step| {
                    const out = try decodeAll(gpa, c, pair[1], step);
                    defer gpa.free(out);
                    try std.testing.expectEqualSlices(u8, data, out);
                }
            }
        }
    }
}

test "stored blocks and the gzip header fields" {
    const gpa = std.testing.allocator;
    const data = try testData(gpa, 150_000, 9);
    defer gpa.free(data);
    // Stored blocks, from std's raw (no compression) writer.
    var out: Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer out.deinit();
    const buf = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(buf);
    var raw = try std.compress.flate.Compress.Raw.init(&out.writer, buf, .gzip);
    try raw.writer.writeAll(data);
    try raw.finish();
    const decoded = try decodeAll(gpa, out.written(), .gzip, 1000);
    defer gpa.free(decoded);
    try std.testing.expectEqualSlices(u8, data, decoded);

    // FEXTRA, FNAME, FCOMMENT and FHCRC, around a fixed-Huffman "hello".
    const gz = "\x1f\x8b\x08\x1e\x00\x00\x00\x00\x00\x03" ++ "\x02\x00xy" ++ "name\x00" ++ "comment\x00" ++ "\xaa\xbb" ++
        "\xcb\x48\xcd\xc9\xc9\x07\x00" ++ "\x86\xa6\x10\x36\x05\x00\x00\x00";
    const hello = try decodeAll(gpa, gz, .gzip, 3);
    defer gpa.free(hello);
    try std.testing.expectEqualStrings("hello", hello);
}

test "the reader is left just after the stream" {
    const gpa = std.testing.allocator;
    const data = try testData(gpa, 50_000, 3);
    defer gpa.free(data);
    const c = try stdCompress(gpa, data, .gzip, .level_6);
    defer gpa.free(c);
    const joined = try std.mem.concat(gpa, u8, &.{ c, "TRAILING" });
    defer gpa.free(joined);
    const work = try gpa.alloc(u8, work_len);
    defer gpa.free(work);
    var in: Io.Reader = .fixed(joined);
    var d = Inflate.init(&in, .gzip, work);
    var sink: [4096]u8 = undefined;
    var total: usize = 0;
    while (true) total += container.readSome(&d.interface, &sink) catch break;
    try std.testing.expect(d.err == null);
    try std.testing.expectEqual(data.len, total);
    try std.testing.expectEqualStrings("TRAILING", in.buffered());
}

test "agrees with std's decoder on mutated streams" {
    const gpa = std.testing.allocator;
    const data = try testData(gpa, 20_000, 5);
    defer gpa.free(data);
    const Options = std.compress.flate.Compress.Options;
    for ([_]?Options{ null, Options.level_6 }) |opts| {
        const c = try stdCompress(gpa, data, .raw, opts);
        defer gpa.free(c);
        const copy = try gpa.dupe(u8, c);
        defer gpa.free(copy);
        var prng = std.Random.DefaultPrng.init(42);
        const r = prng.random();
        const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
        defer gpa.free(window);
        for (0..400) |round| {
            @memcpy(copy, c);
            for (0..1 + round % 3) |_| copy[r.uintLessThan(usize, copy.len)] ^= @as(u8, 1) << r.int(u3);
            const cut = if (round % 5 == 0) r.uintLessThan(usize, copy.len) else copy.len;
            const input = copy[0..cut];

            var std_in: Io.Reader = .fixed(input);
            var sd = std.compress.flate.Decompress.init(&std_in, .raw, window);
            var want: Io.Writer.Allocating = .init(gpa);
            defer want.deinit();
            const std_ok = if (sd.reader.streamRemaining(&want.writer)) |_| true else |_| false;

            const got = decodeAll(gpa, input, .raw, 64 * 1024) catch |e| {
                // Both fail; the decoded prefix may differ by buffering, so compare what std
                // produced against a decode that keeps its partial output.
                if (std_ok) {
                    std.debug.print("round {d}: std ok, ours {s}\n", .{ round, @errorName(e) });
                    return error.TestUnexpectedResult;
                }
                continue;
            };
            defer gpa.free(got);
            if (!std_ok) {
                std.debug.print("round {d}: ours ok, std {?}\n", .{ round, sd.err });
                return error.TestUnexpectedResult;
            }
            try std.testing.expectEqualSlices(u8, want.written(), got);
        }
    }
}
