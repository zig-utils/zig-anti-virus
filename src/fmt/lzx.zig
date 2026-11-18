//! LZX decoding, written from the LZX data format as documented in [MS-PATCH] "LZX DELTA
//! Compression and Decompression" (whose base format is the cabinet LZX), section 2: verbatim,
//! aligned-offset and uncompressed blocks, the pretree-coded path lengths delta-coded against
//! the previous block, three repeated offsets, and the E8 call translation. Cabinet folders (one
//! frame per CFDATA block) and CHM content (with a reset interval) both use it.
//!
//! The decoder is frame-oriented: `frame(len)` produces the next `len` output bytes (32768 for
//! every frame but the last), then realigns the input to 16 bits as the format requires. Input
//! is a bit stream of 16-bit little-endian words read MSB first. Every length, offset and table
//! is checked; a malformed stream fails with an error, never reads outside its buffers.
const std = @import("std");
const Io = std.Io;

pub const frame_len: u32 = 32768;
pub const min_window_bits = 15;
pub const max_window_bits = 21;
const num_chars = 256;
const min_match = 2;
const max_match = 257;
const pretree_syms = 20;
const length_syms = 249;
const aligned_syms = 8;
pub const max_main_syms = num_chars + 50 * 8;

pub const Error = error{
    ReadFailed,
    /// The input ended more than a couple of padding words early.
    Truncated,
    BadBlockType,
    BadTree,
    BadMatch,
    BadBlockSize,
};

/// Position slots per window size (window bits 15 to 21).
fn positionSlots(bits: u5) u32 {
    return switch (bits) {
        15 => 30,
        16 => 32,
        17 => 34,
        18 => 36,
        19 => 38,
        20 => 42,
        else => 50,
    };
}

const extra_bits: [50]u5 = blk: {
    var t: [50]u5 = undefined;
    for (&t, 0..) |*e, i| e.* = if (i < 4) 0 else @min((i - 2) / 2, 17);
    break :blk t;
};

const position_base: [51]u32 = blk: {
    var t: [51]u32 = undefined;
    t[0] = 0;
    for (0..50) |i| t[i + 1] = t[i] + (@as(u32, 1) << extra_bits[i]);
    break :blk t;
};

/// A canonical Huffman decoder for up to `n` symbols with codes of at most 16 bits: a 10-bit
/// first-level table, then a bit-at-a-time walk over the code-length counts for longer codes.
pub fn Huffman(comptime n: usize) type {
    return struct {
        const Self = @This();
        const fast_bits = 10;
        lens: [n]u8 = @splat(0),
        count: [17]u16 = @splat(0),
        sorted: [n]u16 = undefined,
        /// symbol << 5 | length, or 0 when the code is longer than `fast_bits`.
        fast: [1 << fast_bits]u16 = @splat(0),
        empty: bool = true,

        /// Build from `lens`. An empty tree is valid (decoding from it is an error); otherwise
        /// the code must be complete, neither over- nor under-subscribed.
        pub fn build(h: *Self, used: usize) error{BadTree}!void {
            @memset(&h.count, 0);
            for (h.lens[0..used]) |l| {
                if (l > 16) return error.BadTree;
                h.count[l] += 1;
            }
            h.count[0] = 0;
            var left: i32 = 1;
            for (1..17) |l| {
                left <<= 1;
                left -= h.count[l];
                if (left < 0) return error.BadTree;
            }
            h.empty = left == 1 << 16;
            if (h.empty) return;
            if (left != 0) return error.BadTree;
            var offs: [17]u16 = undefined;
            offs[1] = 0;
            for (1..16) |l| offs[l + 1] = offs[l] + h.count[l];
            for (h.lens[0..used], 0..) |l, s| if (l != 0) {
                h.sorted[offs[l]] = @intCast(s);
                offs[l] += 1;
            };
            // Fast table: walk the canonical codes of length <= fast_bits.
            @memset(&h.fast, 0);
            var code: u32 = 0;
            var idx: usize = 0;
            for (1..17) |l| {
                for (0..h.count[l]) |_| {
                    if (l <= fast_bits) {
                        const sym = h.sorted[idx];
                        const shift: u5 = @intCast(fast_bits - l);
                        const first = code << shift;
                        const span = @as(u32, 1) << shift;
                        for (first..first + span) |k| h.fast[k] = @intCast((@as(u32, sym) << 5) | @as(u32, @intCast(l)));
                    }
                    code += 1;
                    idx += 1;
                }
                code <<= 1;
            }
        }

        pub fn decode(h: *const Self, br: *BitReader) Error!u16 {
            if (h.empty) return error.BadTree;
            try br.ensure(16);
            const peek = br.peek(16);
            const e = h.fast[peek >> (16 - fast_bits)];
            if (e != 0) {
                br.drop(@intCast(e & 31));
                return e >> 5;
            }
            // Longer than fast_bits: canonical decode, one bit at a time.
            var code: i32 = 0;
            var first: i32 = 0;
            var index: i32 = 0;
            for (1..17) |l| {
                code |= @intCast((peek >> @intCast(16 - l)) & 1);
                const c: i32 = h.count[l];
                if (code - c < first) {
                    br.drop(@intCast(l));
                    return h.sorted[@intCast(index + (code - first))];
                }
                index += c;
                first += c;
                first <<= 1;
                code <<= 1;
            }
            return error.BadTree;
        }
    };
}

/// 16-bit little-endian words, consumed most significant bit first. At most one word beyond
/// what a request needs is ever buffered, so the byte-aligned parts of the format (uncompressed
/// blocks) can take over exactly where the bits end.
pub const BitReader = struct {
    in: *Io.Reader,
    buf: u32 = 0,
    count: u6 = 0,
    /// Zero words supplied after the input ended (the format pads its last word).
    padding: u8 = 0,

    pub fn ensure(br: *BitReader, n: u6) Error!void {
        while (br.count < n) {
            const word: u32 = if (br.in.takeArray(2)) |b|
                std.mem.readInt(u16, b, .little)
            else |e| switch (e) {
                error.EndOfStream => blk: {
                    br.padding += 1;
                    if (br.padding > 2) return error.Truncated;
                    break :blk 0;
                },
                error.ReadFailed => return error.ReadFailed,
            };
            br.buf |= word << @intCast(16 - br.count);
            br.count += 16;
        }
    }

    pub fn peek(br: *const BitReader, n: u5) u32 {
        return br.buf >> @intCast(32 - @as(u6, n));
    }

    pub fn drop(br: *BitReader, n: u6) void {
        br.buf = if (n >= 32) 0 else br.buf << @intCast(n);
        br.count -= n;
    }

    pub fn bits(br: *BitReader, n: u5) Error!u32 {
        if (n == 0) return 0;
        try br.ensure(n);
        const v = br.peek(n);
        br.drop(n);
        return v;
    }

    /// Up to 24 bits, read in two parts as the format's own decoders do.
    pub fn bitsWide(br: *BitReader, n: u5) Error!u32 {
        if (n <= 16) return br.bits(n);
        const hi = try br.bits(n - 8);
        return (hi << 8) | try br.bits(8);
    }

    /// Drop to the next 16-bit boundary (the tail of the current word).
    pub fn alignWord(br: *BitReader) void {
        br.drop(br.count % 16);
    }

    /// Switch to byte mode for an uncompressed block: buffered bits are the tail of the current
    /// word (or, when aligned, one whole padding word follows and is skipped).
    fn toBytes(br: *BitReader) Error!void {
        if (br.count == 0) _ = br.in.takeArray(2) catch |e| return mapEnd(e);
        br.buf = 0;
        br.count = 0;
    }

    fn takeBytes(br: *BitReader, dest: []u8) Error!void {
        br.in.readSliceAll(dest) catch |e| return mapEnd(e);
    }

    fn mapEnd(e: Io.Reader.Error) Error {
        return switch (e) {
            error.EndOfStream => error.Truncated,
            error.ReadFailed => error.ReadFailed,
        };
    }
};

pub const Lzx = struct {
    br: BitReader,
    window: []u8,
    window_bits: u5,
    pos: u32 = 0,
    /// Window offset where the current frame begins.
    frame_start: u32 = 0,
    /// A frame shorter than 32768 bytes was the last.
    ended: bool = false,
    /// Output produced since the stream began (for offset checks and E8 positions).
    total: u64 = 0,
    frames: u32 = 0,
    /// Frames between state resets (CHM); 0 for none.
    reset_interval: u32 = 0,
    r: [3]u32 = .{ 1, 1, 1 },
    header_read: bool = false,
    e8_size: u32 = 0,
    block_type: u3 = 0,
    block_remaining: u32 = 0,
    /// An uncompressed block whose length is odd ends with a pad byte.
    block_odd: bool = false,
    main: *Huffman(max_main_syms),
    length: *Huffman(length_syms),
    aligned: Huffman(aligned_syms) = .{},
    pretree: Huffman(pretree_syms) = .{},
    main_syms: u32,
    /// The frame after E8 translation (the window keeps the untranslated bytes).
    e8_buf: *[frame_len]u8,

    pub const Tables = struct {
        main: Huffman(max_main_syms) = .{},
        length: Huffman(length_syms) = .{},
        e8: [frame_len]u8 = undefined,
    };

    pub fn windowLen(bits: u5) u32 {
        return @as(u32, 1) << bits;
    }

    /// `window` must be `windowLen(bits)` bytes; `tables` lives as long as the decoder.
    pub fn init(in: *Io.Reader, bits: u5, window: []u8, tables: *Tables, reset_interval: u32) Lzx {
        std.debug.assert(bits >= min_window_bits and bits <= max_window_bits);
        std.debug.assert(window.len == windowLen(bits));
        tables.* = .{};
        return .{
            .br = .{ .in = in },
            .window = window,
            .window_bits = bits,
            .main = &tables.main,
            .length = &tables.length,
            .main_syms = num_chars + positionSlots(bits) * 8,
            .e8_buf = &tables.e8,
            .reset_interval = reset_interval,
        };
    }

    fn resetState(d: *Lzx) void {
        d.r = .{ 1, 1, 1 };
        d.header_read = false;
        d.block_remaining = 0;
        d.block_type = 0;
        d.block_odd = false;
        @memset(&d.main.lens, 0);
        @memset(&d.length.lens, 0);
    }

    /// Decode the next frame of `len` bytes and return it. Every frame but the last of the
    /// stream is 32768 bytes; a shorter one ends the stream.
    pub fn frame(d: *Lzx, len: u32) Error![]const u8 {
        if (len == 0 or len > frame_len or d.ended) return error.BadBlockSize;
        if (len < frame_len) d.ended = true;
        if (d.reset_interval != 0 and d.frames % d.reset_interval == 0 and d.frames != 0) {
            if (d.block_remaining != 0) return error.BadBlockSize;
            d.resetState();
        }
        if (!d.header_read) {
            if (try d.br.bits(1) != 0) {
                const hi = try d.br.bits(16);
                d.e8_size = (hi << 16) | try d.br.bits(16);
            } else d.e8_size = 0;
            d.header_read = true;
        }
        // Frames sit on 32 KiB boundaries of the window, so one never wraps. A match may run
        // past a frame's end; those bytes are the start of the next frame.
        const start = d.frame_start;
        const end = start + len;
        while (d.pos < end) {
            if (d.block_remaining == 0) try d.readBlockHeader();
            try d.decodeRun(end);
        }
        if (d.block_type != 3) d.br.alignWord();
        d.frames += 1;
        d.total += len;
        const out = d.translate(d.window[start..end]);
        d.frame_start = end;
        if (end == d.window.len) {
            // A match never crosses the window's end (copyMatch), so nothing ran over.
            d.frame_start = 0;
            d.pos = 0;
        }
        return out;
    }

    fn translate(d: *Lzx, out: []const u8) []const u8 {
        if (d.e8_size == 0 or out.len <= 10 or d.frames > 32768) return out;
        const buf = d.e8_buf[0..out.len];
        @memcpy(buf, out);
        const base: i64 = @intCast(d.total - out.len);
        const size: i64 = d.e8_size;
        var i: usize = 0;
        while (i < out.len - 10) {
            if (buf[i] != 0xe8) {
                i += 1;
                continue;
            }
            const cur: i64 = base + @as(i64, @intCast(i));
            const abs: i64 = std.mem.readInt(i32, buf[i + 1 ..][0..4], .little);
            if (abs >= -cur and abs < size) {
                const rel: i64 = if (abs >= 0) abs - cur else abs + size;
                std.mem.writeInt(i32, buf[i + 1 ..][0..4], @truncate(rel), .little);
            }
            i += 5;
        }
        return buf;
    }

    fn readBlockHeader(d: *Lzx) Error!void {
        if (d.block_type == 3 and d.block_odd) {
            _ = d.br.in.takeByte() catch |e| return BitReader.mapEnd(e);
        }
        d.block_odd = false;
        d.block_type = @intCast(try d.br.bits(3));
        const hi = try d.br.bits(16);
        const size = (hi << 8) | try d.br.bits(8);
        if (size == 0) return error.BadBlockSize;
        d.block_remaining = size;
        switch (d.block_type) {
            1, 2 => {
                if (d.block_type == 2) {
                    for (&d.aligned.lens) |*l| l.* = @intCast(try d.br.bits(3));
                    try d.aligned.build(aligned_syms);
                }
                try d.readLengths(d.main.lens[0..num_chars]);
                try d.readLengths(d.main.lens[num_chars..d.main_syms]);
                try d.main.build(d.main_syms);
                try d.readLengths(d.length.lens[0..length_syms]);
                try d.length.build(length_syms);
            },
            3 => {
                try d.br.toBytes();
                var rs: [12]u8 = undefined;
                try d.br.takeBytes(&rs);
                for (&d.r, 0..) |*r, i| r.* = std.mem.readInt(u32, rs[i * 4 ..][0..4], .little);
                d.block_odd = size & 1 != 0;
            },
            else => return error.BadBlockType,
        }
    }

    /// Path lengths through a freshly read pretree, delta-coded against the previous values.
    fn readLengths(d: *Lzx, lens: []u8) Error!void {
        for (&d.pretree.lens) |*l| l.* = @intCast(try d.br.bits(4));
        try d.pretree.build(pretree_syms);
        var x: usize = 0;
        while (x < lens.len) {
            const z = try d.pretree.decode(&d.br);
            switch (z) {
                17, 18 => {
                    const run: usize = if (z == 17) 4 + try d.br.bits(4) else 20 + try d.br.bits(5);
                    if (run > lens.len - x) return error.BadTree;
                    @memset(lens[x..][0..run], 0);
                    x += run;
                },
                19 => {
                    const run: usize = 4 + try d.br.bits(1);
                    if (run > lens.len - x) return error.BadTree;
                    const sym = try d.pretree.decode(&d.br);
                    if (sym > 16) return error.BadTree;
                    const v: u8 = @intCast((@as(u32, lens[x]) + 17 - sym) % 17);
                    @memset(lens[x..][0..run], v);
                    x += run;
                },
                else => {
                    if (z > 16) return error.BadTree;
                    lens[x] = @intCast((@as(u32, lens[x]) + 17 - z) % 17);
                    x += 1;
                },
            }
        }
    }

    /// Decode symbols of the current block until the frame's end or the block's end.
    fn decodeRun(d: *Lzx, end: u32) Error!void {
        if (d.block_type == 3) {
            const n: u32 = @min(d.block_remaining, end - d.pos);
            try d.br.takeBytes(d.window[d.pos..][0..n]);
            d.pos += n;
            d.block_remaining -= n;
            return;
        }
        const aligned = d.block_type == 2;
        while (d.pos < end and d.block_remaining > 0) {
            const sym = try d.main.decode(&d.br);
            if (sym >= d.main_syms) return error.BadTree;
            if (sym < num_chars) {
                d.window[d.pos] = @intCast(sym);
                d.pos += 1;
                d.block_remaining -= 1;
                continue;
            }
            const m = sym - num_chars;
            var len: u32 = m & 7;
            if (len == 7) len += try d.length.decode(&d.br);
            len += min_match;
            const slot = m >> 3;
            var offset: u32 = undefined;
            switch (slot) {
                0 => offset = d.r[0],
                1 => {
                    offset = d.r[1];
                    d.r[1] = d.r[0];
                    d.r[0] = offset;
                },
                2 => {
                    offset = d.r[2];
                    d.r[2] = d.r[0];
                    d.r[0] = offset;
                },
                else => {
                    const extra = extra_bits[slot];
                    offset = position_base[slot] - 2;
                    if (aligned and extra >= 3) {
                        if (extra > 3) offset += try d.br.bitsWide(extra - 3) << 3;
                        offset += try d.aligned.decode(&d.br);
                    } else if (extra > 0) {
                        offset += try d.br.bitsWide(extra);
                    }
                    d.r[2] = d.r[1];
                    d.r[1] = d.r[0];
                    d.r[0] = offset;
                },
            }
            try d.copyMatch(offset, len);
        }
    }

    fn copyMatch(d: *Lzx, offset: u32, len: u32) Error!void {
        const win: u32 = @intCast(d.window.len);
        if (len > d.block_remaining) return error.BadMatch;
        if (d.pos + len > win) return error.BadMatch;
        // Only bytes already produced may be referenced.
        const produced: u64 = d.total + (d.pos - d.frame_start);
        if (offset == 0 or offset > win or offset > produced) return error.BadMatch;
        var src: u32 = if (offset <= d.pos) d.pos - offset else win - (offset - d.pos);
        var i: u32 = 0;
        while (i < len) : (i += 1) {
            d.window[d.pos + i] = d.window[src];
            src += 1;
            if (src == win) src = 0;
        }
        d.pos += len;
        d.block_remaining -= len;
    }
};

test "position tables" {
    try std.testing.expectEqual(@as(u32, 0), position_base[0]);
    try std.testing.expectEqual(@as(u32, 4), position_base[4]);
    try std.testing.expectEqual(@as(u32, 6), position_base[5]);
    try std.testing.expectEqual(@as(u5, 17), extra_bits[49]);
    try std.testing.expectEqual(@as(u32, 50), positionSlots(21));
}

test "huffman: complete, empty and over-subscribed codes" {
    var h: Huffman(4) = .{};
    h.lens = .{ 1, 2, 3, 3 };
    try h.build(4);
    var data = [_]u8{ 0b0110_1110, 0b1000_0000 }; // words are little-endian: 0x80 then 0x6e
    var r: Io.Reader = .fixed(&data);
    var br: BitReader = .{ .in = &r };
    // Bits 1000 0000 0110 1110: "10" -> 1, "0" -> 0, "0" ->0, ...
    try std.testing.expectEqual(@as(u16, 1), try h.decode(&br));
    try std.testing.expectEqual(@as(u16, 0), try h.decode(&br));
    h.lens = .{ 1, 1, 1, 0 };
    try std.testing.expectError(error.BadTree, h.build(4));
    h.lens = .{ 0, 0, 0, 0 };
    try h.build(4);
    try std.testing.expect(h.empty);
    h.lens = .{ 1, 0, 0, 0 };
    try std.testing.expectError(error.BadTree, h.build(4));
}
