//! A zstd decoder (RFC 8878), written from the RFC for E7 (#103): std.compress.zstd decodes
//! Huffman literals one tree step at a time and ran at 1 to 13% of libzstd.
//!
//! How it is fast:
//! - Literals: a single-lookup Huffman table (up to 11 bits), and the four streams decoded
//!   interleaved, five symbols per stream per refill of a 64-bit backward bit buffer.
//! - Sequences: FSE tables whose entries carry the next-state baseline and the literal length,
//!   match length or offset base with its extra-bit count, so a sequence is three lookups and
//!   a few shifts. Literal and match copies move 16 bytes at a time into slack.
//! - A compressed block is read whole into a block buffer, so every bit reader works on memory.
//!
//! Memory is the caller's (`workLen`): the output buffer (twice the window plus a block, so the
//! window slides once per window of output, not once per block), the block and literal
//! buffers, and the tables. Every length, offset and table index is checked against those
//! buffers; a hostile frame gets an error, never an out-of-bounds access.
//!
//! Not supported, as in std: dictionaries (`DictionaryIdFlagUnsupported`). The content checksum
//! is skipped, not verified, as std does by default. Error names follow
//! std.compress.zstd.Decompress.Error.
const std = @import("std");
const Io = std.Io;
const container = @import("../../engine/container.zig");

pub const block_size_max = 128 * 1024;
/// Slack past every buffer that wild copies may touch.
const wild = 32;

pub const Error = error{
    BadMagic,
    ReservedBitSet,
    DictionaryIdFlagUnsupported,
    WindowOversize,
    BlockOversize,
    ReservedBlock,
    MalformedLiteralsHeader,
    MalformedLiteralsSection,
    MalformedHuffmanTree,
    TreelessLiteralsFirst,
    MalformedAccuracyLog,
    MalformedFseTable,
    RepeatModeFirst,
    MalformedSequence,
    MalformedCompressedBlock,
    MissingStartBit,
    EndOfStream,
    ReadFailed,
};

/// The output buffer for a window: twice the window plus one block and slack.
fn outLen(window_len: u32) usize {
    return 2 * @as(usize, window_len) + block_size_max + wild;
}

/// Bytes of caller memory a decoder with this window needs.
pub fn workLen(window_len: u32) usize {
    return outLen(window_len) + 2 * (block_size_max + wild) + @sizeOf(Tables) + @alignOf(Tables);
}

/// An FSE decode entry for sequences (and, with `base` the symbol, for Huffman weights).
const SeqEntry = extern struct {
    base: u32,
    new_state: u16,
    extra: u8,
    nbits: u8,
};

const ll_max_log = 9;
const ml_max_log = 9;
const of_max_log = 8;
const ll_max_sym = 35;
const ml_max_sym = 52;
const of_max_sym = 31;
const huf_max_bits = 11;

const Tables = struct {
    huf: [1 << huf_max_bits]u16,
    ll: [1 << ll_max_log]SeqEntry,
    ml: [1 << ml_max_log]SeqEntry,
    of: [1 << of_max_log]SeqEntry,
    ll_def: [1 << 6]SeqEntry,
    ml_def: [1 << 6]SeqEntry,
    of_def: [1 << 5]SeqEntry,
    weights: [1 << 6]SeqEntry,
};

const ll_base = [36]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
const ll_bits = [36]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
const ml_base = [53]u32{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539 };
const ml_bits = [53]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
const ll_default = [36]i16{ 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1 };
const ml_default = [53]i16{ 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1 };
const of_default = [29]i16{ 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1 };

const SeqKind = enum { ll, ml, of, raw };

inline fn load64(p: [*]const u8) u64 {
    return std.mem.readInt(u64, p[0..8], .little);
}

fn highBit(v: u32) u5 {
    return @intCast(31 - @clz(v));
}

/// Read an FSE table description (RFC 8878 section 4.1.1). Returns the accuracy log and the
/// bytes used; `norm` gets one probability per symbol up to `max_sym` (-1 is "less than 1").
fn readNCount(src: []const u8, norm: []i16, max_log: u5) Error!struct { log: u5, used: usize } {
    const max_sym1 = norm.len;
    var pos: usize = 0; // bit position
    const peek = struct {
        fn f(s: []const u8, bitpos: usize) u32 {
            const byte = bitpos >> 3;
            var v: u64 = 0;
            if (byte + 8 <= s.len) v = load64(s.ptr + byte) else {
                var i: usize = 0;
                while (byte + i < s.len and i < 8) : (i += 1) v |= @as(u64, s[byte + i]) << @intCast(8 * i);
            }
            return @truncate(v >> @intCast(bitpos & 7));
        }
    }.f;
    const log: u5 = @intCast((peek(src, 0) & 0xf) + 5);
    if (log > max_log) return error.MalformedAccuracyLog;
    pos = 4;
    var remaining: i32 = (@as(i32, 1) << log) + 1;
    var threshold: i32 = @as(i32, 1) << log;
    var nb: u5 = log + 1;
    var sym: usize = 0;
    var prev0 = false;
    while (true) {
        if (prev0) {
            var n0 = sym;
            while (true) {
                const v = peek(src, pos) & 3;
                pos += 2;
                n0 += v;
                if (v != 3) break;
                if (n0 > max_sym1) return error.MalformedFseTable;
            }
            if (n0 >= max_sym1) return error.MalformedFseTable;
            @memset(norm[sym..n0], 0);
            sym = n0;
        }
        const v = peek(src, pos);
        const max: i32 = (2 * threshold - 1) - remaining;
        var count: i32 = undefined;
        if (@as(i32, @intCast(v & @as(u32, @intCast(threshold - 1)))) < max) {
            count = @intCast(v & @as(u32, @intCast(threshold - 1)));
            pos += nb - 1;
        } else {
            count = @intCast(v & @as(u32, @intCast(2 * threshold - 1)));
            if (count >= threshold) count -= max;
            pos += nb;
        }
        count -= 1;
        remaining -= if (count < 0) -count else count;
        norm[sym] = @intCast(count);
        sym += 1;
        prev0 = count == 0;
        if (remaining < threshold) {
            if (remaining <= 1) break;
            nb = @as(u5, highBit(@intCast(remaining))) + 1;
            threshold = @as(i32, 1) << (nb - 1);
        }
        if (sym >= max_sym1) break;
    }
    if (remaining != 1) return error.MalformedFseTable;
    const used = (pos + 7) >> 3;
    if (used > src.len) return error.MalformedFseTable;
    @memset(norm[sym..], 0);
    return .{ .log = log, .used = used };
}

/// Spread the symbols of a normalised distribution over a decode table (RFC 8878 4.1.1).
fn buildFse(comptime kind: SeqKind, norm: []const i16, log: u5, table: []SeqEntry) void {
    const size: u32 = @as(u32, 1) << log;
    var next: [256]u16 = undefined;
    var high: u32 = size - 1;
    for (norm, 0..) |p, s| {
        if (p == -1) {
            table[high].base = @intCast(s);
            high -%= 1;
            next[s] = 1;
        } else next[s] = @intCast(@max(p, 0));
    }
    const step = (size >> 1) + (size >> 3) + 3;
    const mask = size - 1;
    var position: u32 = 0;
    for (norm, 0..) |p, s| {
        var i: i32 = 0;
        while (i < p) : (i += 1) {
            table[position].base = @intCast(s);
            position = (position + step) & mask;
            while (position > high) position = (position + step) & mask;
        }
    }
    for (table[0..size]) |*e| {
        const s = e.base;
        const ns: u32 = next[s];
        next[s] += 1;
        const nbits: u5 = @intCast(log - highBit(ns));
        e.nbits = nbits;
        e.new_state = @intCast((ns << nbits) - size);
        switch (kind) {
            .ll => {
                e.base = ll_base[s];
                e.extra = ll_bits[s];
            },
            .ml => {
                e.base = ml_base[s];
                e.extra = ml_bits[s];
            },
            .of => {
                e.base = @as(u32, 1) << @intCast(s);
                e.extra = @intCast(s);
            },
            .raw => e.extra = 0,
        }
    }
}

/// A backward bit reader (RFC 8878 4.1): the stream is read from its last byte towards its
/// first, the highest set bit of the last byte marking the start.
const BackReader = struct {
    src: [*]const u8,
    /// Index of the lowest byte in `container`.
    ptr: usize,
    container: u64,
    consumed: u32,
    /// 64, or 8 times the length for a stream shorter than 8 bytes (held whole, left-aligned).
    base_bits: u32,

    fn init(s: []const u8) Error!BackReader {
        if (s.len == 0) return error.MalformedCompressedBlock;
        if (s[s.len - 1] == 0) return error.MissingStartBit;
        var r: BackReader = undefined;
        r.src = s.ptr;
        if (s.len >= 8) {
            r.ptr = s.len - 8;
            r.container = load64(s.ptr + r.ptr);
            r.base_bits = 64;
        } else {
            var c: u64 = 0;
            for (s, 0..) |b, i| c |= @as(u64, b) << @intCast(8 * i);
            r.ptr = 0;
            r.container = c << @intCast(8 * (8 - s.len));
            r.base_bits = @intCast(8 * s.len);
        }
        r.consumed = @clz(r.container) + 1;
        return r;
    }

    /// The next `n` bits (n up to 56). Past the start of the stream, bits read as garbage and
    /// `unread` goes negative; callers check it.
    inline fn read(r: *BackReader, n: u32) u64 {
        const v = (r.container << @as(u6, @truncate(r.consumed))) >> 1 >> @as(u6, @truncate(63 - n));
        r.consumed += n;
        return v;
    }

    inline fn peek(r: *const BackReader, comptime_bits: u32) u64 {
        return (r.container << @as(u6, @truncate(r.consumed))) >> @as(u6, @truncate(64 - comptime_bits));
    }

    inline fn reload(r: *BackReader) void {
        if (r.ptr >= 8) {
            r.ptr -= r.consumed >> 3;
            r.consumed &= 7;
            r.container = load64(r.src + r.ptr);
        } else r.reloadSlow();
    }

    fn reloadSlow(r: *BackReader) void {
        if (r.base_bits < 64 or r.consumed > 64) return;
        const step = @min(r.consumed >> 3, r.ptr);
        r.ptr -= step;
        r.consumed -= @intCast(step * 8);
        r.container = load64(r.src + r.ptr);
    }

    /// Bits not yet read; negative when reads went past the start.
    fn unread(r: *const BackReader) i64 {
        return @as(i64, @intCast(r.ptr * 8 + r.base_bits)) - r.consumed;
    }
};

pub const Decoder = struct {
    in: *Io.Reader,
    window_len: u32,
    out: []u8,
    blk: []u8,
    lits: []u8,
    t: *Tables,
    /// Output: `rp..wp` is waiting for the consumer, below `rp` is history.
    wp: usize = 0,
    rp: usize = 0,
    /// Where the current frame's output starts in `out` (offsets may not reach before it).
    frame_base: usize = 0,
    state: State = .frame,
    frames: u32 = 0,
    skip_left: u32 = 0,
    last_block: bool = false,
    has_checksum: bool = false,
    block_max: u32 = 0,
    rep: [3]u32 = .{ 1, 4, 8 },
    huf_bits: u32 = 0,
    ll_log: u5 = 0,
    ml_log: u5 = 0,
    of_log: u5 = 0,
    ll_ok: bool = false,
    ml_ok: bool = false,
    of_ok: bool = false,
    err: ?Error = null,
    interface: Io.Reader,

    const State = enum { frame, block, skip, done };

    /// `work` must hold `workLen(window_len)` bytes. Frames whose window exceeds `window_len`
    /// fail with `error.WindowOversize`. Fill the result in place before reading.
    pub fn init(in: *Io.Reader, work: []u8, window_len: u32) Decoder {
        std.debug.assert(work.len >= workLen(window_len));
        const addr = std.mem.alignForward(usize, @intFromPtr(work.ptr), @alignOf(Tables));
        const off = addr - @intFromPtr(work.ptr);
        const t: *Tables = @ptrCast(@alignCast(work[off..].ptr));
        var rest = work[off + @sizeOf(Tables) ..];
        const out = rest[0..outLen(window_len)];
        rest = rest[out.len..];
        const blk = rest[0 .. block_size_max + wild];
        const lits = rest[blk.len..][0 .. block_size_max + wild];
        buildFse(.ll, &ll_default, 6, &t.ll_def);
        buildFse(.ml, &ml_default, 6, &t.ml_def);
        buildFse(.of, &of_default, 5, &t.of_def);
        return .{
            .in = in,
            .window_len = window_len,
            .out = out,
            .blk = blk,
            .lits = lits,
            .t = t,
            .interface = .{ .vtable = container.fillVTable(Decoder), .buffer = &.{}, .seek = 0, .end = 0 },
        };
    }

    pub fn fill(d: *Decoder, dest: []u8) Io.Reader.Error!usize {
        while (true) {
            if (d.rp < d.wp) {
                const n = @min(d.wp - d.rp, dest.len);
                @memcpy(dest[0..n], d.out[d.rp..][0..n]);
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

    /// Decode until a block adds output or the input ends. Only called with every decoded byte
    /// read (`rp == wp`).
    fn produce(d: *Decoder) Error!void {
        const in = d.in;
        while (true) switch (d.state) {
            .frame => {
                // A clean end of input between frames ends the stream.
                _ = in.peek(1) catch |e| switch (e) {
                    error.EndOfStream => {
                        if (d.frames == 0) return error.EndOfStream;
                        d.state = .done;
                        return;
                    },
                    error.ReadFailed => return error.ReadFailed,
                };
                const magic = try in.takeInt(u32, .little);
                if (magic & 0xFFFFFFF0 == 0x184D2A50) {
                    d.skip_left = try in.takeInt(u32, .little);
                    d.state = .skip;
                    continue;
                }
                if (magic != 0xFD2FB528) return error.BadMagic;
                try d.frameHeader();
                d.frames += 1;
                d.state = .block;
            },
            .skip => {
                try in.discardAll(d.skip_left);
                d.frames += 1;
                d.state = .frame;
            },
            .block => {
                if (d.last_block) {
                    if (d.has_checksum) try in.discardAll(4);
                    d.state = .frame;
                    continue;
                }
                if (d.wp + block_size_max + wild > d.out.len) {
                    const keep = d.window_len;
                    @memmove(d.out[0..keep], d.out[d.wp - keep .. d.wp]);
                    d.frame_base -|= d.wp - keep;
                    d.wp = keep;
                    d.rp = keep;
                }
                const h = try in.takeArray(3);
                const hv: u32 = @as(u32, h[0]) | @as(u32, h[1]) << 8 | @as(u32, h[2]) << 16;
                d.last_block = hv & 1 == 1;
                const size = hv >> 3;
                switch ((hv >> 1) & 3) {
                    0 => {
                        if (size > d.block_max) return error.BlockOversize;
                        try in.readSliceAll(d.out[d.wp..][0..size]);
                        d.wp += size;
                    },
                    1 => {
                        if (size > d.block_max) return error.BlockOversize;
                        const b = try in.takeByte();
                        @memset(d.out[d.wp..][0..size], b);
                        d.wp += size;
                    },
                    2 => {
                        if (size > d.block_max) return error.BlockOversize;
                        try in.readSliceAll(d.blk[0..size]);
                        try d.compressedBlock(d.blk[0..size]);
                    },
                    else => return error.ReservedBlock,
                }
                if (d.wp > d.rp) return;
            },
            .done => return,
        };
    }

    fn frameHeader(d: *Decoder) Error!void {
        const in = d.in;
        const fhd = try in.takeByte();
        if (fhd & 0x08 != 0) return error.ReservedBitSet;
        if (fhd & 3 != 0) return error.DictionaryIdFlagUnsupported;
        const single = fhd & 0x20 != 0;
        var window: u64 = 0;
        if (!single) {
            const wd = try in.takeByte();
            const base = @as(u64, 1) << @intCast(10 + (wd >> 3));
            window = base + (base / 8) * (wd & 7);
        }
        const fcs_len: usize = switch (fhd >> 6) {
            0 => if (single) 1 else 0,
            1 => 2,
            2 => 4,
            else => 8,
        };
        if (fcs_len != 0) {
            const f = try in.take(fcs_len);
            const fcs: u64 = switch (fcs_len) {
                1 => f[0],
                2 => @as(u64, std.mem.readInt(u16, f[0..2], .little)) + 256,
                4 => std.mem.readInt(u32, f[0..4], .little),
                else => std.mem.readInt(u64, f[0..8], .little),
            };
            if (single) window = fcs;
        }
        if (window > d.window_len) return error.WindowOversize;
        d.has_checksum = fhd & 0x04 != 0;
        d.block_max = @intCast(@min(window, block_size_max));
        d.last_block = false;
        d.frame_base = d.wp;
        d.rep = .{ 1, 4, 8 };
        d.huf_bits = 0;
        d.ll_ok = false;
        d.ml_ok = false;
        d.of_ok = false;
    }

    fn compressedBlock(d: *Decoder, src: []const u8) Error!void {
        if (src.len < 2) return error.MalformedCompressedBlock;
        // Literals section.
        var lit: [*]const u8 = undefined;
        var lit_len: usize = 0;
        var pos: usize = 0;
        const lt = src[0] & 3;
        const sf = (src[0] >> 2) & 3;
        switch (lt) {
            0, 1 => {
                const hsize: usize = switch (sf) {
                    0, 2 => 1,
                    1 => 2,
                    else => 3,
                };
                if (src.len < hsize) return error.MalformedLiteralsHeader;
                lit_len = switch (sf) {
                    0, 2 => src[0] >> 3,
                    1 => (src[0] >> 4) | @as(usize, src[1]) << 4,
                    else => (src[0] >> 4) | @as(usize, src[1]) << 4 | @as(usize, src[2]) << 12,
                };
                if (lit_len > d.block_max) return error.MalformedLiteralsSection;
                if (lt == 0) {
                    if (src.len < hsize + lit_len) return error.MalformedLiteralsSection;
                    lit = src.ptr + hsize;
                    pos = hsize + lit_len;
                } else {
                    if (src.len < hsize + 1) return error.MalformedLiteralsSection;
                    @memset(d.lits[0..lit_len], src[hsize]);
                    lit = d.lits.ptr;
                    pos = hsize + 1;
                }
            },
            else => {
                var hsize: usize = undefined;
                var csize: usize = undefined;
                const four = sf != 0;
                switch (sf) {
                    0, 1 => {
                        if (src.len < 3) return error.MalformedLiteralsHeader;
                        const v: u32 = @as(u32, src[0]) | @as(u32, src[1]) << 8 | @as(u32, src[2]) << 16;
                        hsize = 3;
                        lit_len = (v >> 4) & 0x3ff;
                        csize = v >> 14;
                    },
                    2 => {
                        if (src.len < 4) return error.MalformedLiteralsHeader;
                        const v = std.mem.readInt(u32, src[0..4], .little);
                        hsize = 4;
                        lit_len = (v >> 4) & 0x3fff;
                        csize = (v >> 18) & 0x3fff;
                    },
                    else => {
                        if (src.len < 5) return error.MalformedLiteralsHeader;
                        const v: u64 = std.mem.readInt(u32, src[0..4], .little) | @as(u64, src[4]) << 32;
                        hsize = 5;
                        lit_len = @intCast((v >> 4) & 0x3ffff);
                        csize = @intCast((v >> 22) & 0x3ffff);
                    },
                }
                if (lit_len > d.block_max) return error.MalformedLiteralsSection;
                if (src.len < hsize + csize) return error.MalformedLiteralsSection;
                var data = src[hsize..][0..csize];
                if (lt == 2) {
                    const used = try d.huffmanTable(data);
                    data = data[used..];
                } else if (d.huf_bits == 0) return error.TreelessLiteralsFirst;
                if (four) try d.huffman4(data, d.lits[0..lit_len]) else try d.huffman1(data, d.lits[0..lit_len]);
                lit = d.lits.ptr;
                pos = hsize + csize;
            },
        }

        // Sequences section.
        const seqs = src[pos..];
        if (seqs.len == 0) return error.MalformedCompressedBlock;
        var nseq: usize = seqs[0];
        var p: usize = 1;
        if (nseq >= 128) {
            if (nseq == 255) {
                if (seqs.len < 3) return error.MalformedCompressedBlock;
                nseq = @as(usize, seqs[1]) + (@as(usize, seqs[2]) << 8) + 0x7f00;
                p = 3;
            } else {
                if (seqs.len < 2) return error.MalformedCompressedBlock;
                nseq = ((nseq - 128) << 8) + seqs[1];
                p = 2;
            }
        }
        const oend = d.wp + d.block_max;
        if (nseq == 0) {
            if (d.wp + lit_len > oend) return error.MalformedCompressedBlock;
            @memcpy(d.out[d.wp..][0..lit_len], lit[0..lit_len]);
            d.wp += lit_len;
            return;
        }
        if (seqs.len <= p) return error.MalformedCompressedBlock;
        const modes = seqs[p];
        p += 1;
        if (modes & 3 != 0) return error.ReservedBitSet;
        p += try d.seqTable(.ll, modes >> 6, seqs[p..]);
        p += try d.seqTable(.of, (modes >> 4) & 3, seqs[p..]);
        p += try d.seqTable(.ml, (modes >> 2) & 3, seqs[p..]);
        try d.sequences(seqs[p..], nseq, lit, lit_len, oend);
    }

    /// Read a Huffman tree description and build the decode table; returns the bytes used.
    fn huffmanTable(d: *Decoder, data: []const u8) Error!usize {
        if (data.len == 0) return error.MalformedHuffmanTree;
        var weights: [256]u8 = undefined;
        var n: usize = 0;
        var used: usize = 0;
        const h = data[0];
        if (h < 128) {
            if (data.len < 1 + @as(usize, h) or h == 0) return error.MalformedHuffmanTree;
            const fse = data[1..][0..h];
            var norm: [256]i16 = undefined;
            const nc = readNCount(fse, &norm, 6) catch return error.MalformedHuffmanTree;
            buildFse(.raw, &norm, nc.log, &d.t.weights);
            const tbl = &d.t.weights;
            var br = try BackReader.init(fse[nc.used..]);
            var s1: u32 = @intCast(br.read(nc.log));
            var s2: u32 = @intCast(br.read(nc.log));
            br.reload();
            while (true) {
                if (n + 2 > 255) return error.MalformedHuffmanTree;
                weights[n] = @intCast(tbl[s1].base);
                n += 1;
                s1 = tbl[s1].new_state + @as(u32, @intCast(br.read(tbl[s1].nbits)));
                br.reload();
                if (br.unread() < 0) {
                    weights[n] = @intCast(tbl[s2].base);
                    n += 1;
                    break;
                }
                weights[n] = @intCast(tbl[s2].base);
                n += 1;
                s2 = tbl[s2].new_state + @as(u32, @intCast(br.read(tbl[s2].nbits)));
                br.reload();
                if (br.unread() < 0) {
                    weights[n] = @intCast(tbl[s1].base);
                    n += 1;
                    break;
                }
            }
            used = 1 + @as(usize, h);
        } else {
            n = h - 127;
            const bytes = (n + 1) / 2;
            if (data.len < 1 + bytes) return error.MalformedHuffmanTree;
            for (0..n) |i| {
                const b = data[1 + i / 2];
                weights[i] = if (i % 2 == 0) b >> 4 else b & 15;
            }
            used = 1 + bytes;
        }
        // The last weight is implied: it completes the sum to a power of two.
        var sum: u32 = 0;
        for (weights[0..n]) |w| {
            if (w > huf_max_bits) return error.MalformedHuffmanTree;
            if (w != 0) sum += @as(u32, 1) << @intCast(w - 1);
        }
        if (sum == 0) return error.MalformedHuffmanTree;
        const max_bits: u32 = @as(u32, highBit(sum)) + 1;
        if (max_bits > huf_max_bits) return error.MalformedHuffmanTree;
        const rest = (@as(u32, 1) << @intCast(max_bits)) - sum;
        if (rest & (rest - 1) != 0) return error.MalformedHuffmanTree;
        weights[n] = @as(u8, highBit(rest)) + 1;
        n += 1;
        // Fill the table: lowest weights (longest codes) first, symbols in order.
        var rank_count: [huf_max_bits + 2]u32 = @splat(0);
        for (weights[0..n]) |w| rank_count[w] += 1;
        var rank_start: [huf_max_bits + 2]u32 = undefined;
        var next: u32 = 0;
        for (1..max_bits + 1) |w| {
            rank_start[w] = next;
            next += rank_count[w] << @intCast(w - 1);
        }
        const huf = &d.t.huf;
        for (weights[0..n], 0..) |w, sym| {
            if (w == 0) continue;
            const len = @as(u32, 1) << @intCast(w - 1);
            const entry: u16 = @intCast((sym << 8) | (max_bits + 1 - w));
            @memset(huf[rank_start[w]..][0..len], entry);
            rank_start[w] += len;
        }
        d.huf_bits = max_bits;
        return used;
    }

    fn huffman1(d: *Decoder, src: []const u8, out: []u8) Error!void {
        var br = try BackReader.init(src);
        try d.huffStream(&br, out.ptr, out.len);
    }

    /// Decode one stream's `len` symbols, then check the stream was used exactly.
    fn huffStream(d: *Decoder, br: *BackReader, out: [*]u8, len: usize) Error!void {
        const huf = &d.t.huf;
        const bits = d.huf_bits;
        var i: usize = 0;
        // Five symbols per refill while the reader has 8 bytes behind it.
        while (i + 5 <= len and br.ptr >= 8) {
            inline for (0..5) |_| {
                const e = huf[@intCast(br.peek(bits))];
                br.consumed += e & 0xff;
                out[i] = @intCast(e >> 8);
                i += 1;
            }
            br.reload();
        }
        while (i < len) : (i += 1) {
            br.reload();
            if (br.consumed > 64) return error.MalformedLiteralsSection;
            const e = huf[@intCast(br.peek(bits))];
            br.consumed += e & 0xff;
            out[i] = @intCast(e >> 8);
        }
        br.reload();
        if (br.unread() != 0) return error.MalformedLiteralsSection;
    }

    fn huffman4(d: *Decoder, src: []const u8, out: []u8) Error!void {
        if (src.len < 10) return error.MalformedLiteralsSection;
        const s1: usize = std.mem.readInt(u16, src[0..2], .little);
        const s2: usize = std.mem.readInt(u16, src[2..4], .little);
        const s3: usize = std.mem.readInt(u16, src[4..6], .little);
        if (6 + s1 + s2 + s3 >= src.len) return error.MalformedLiteralsSection;
        const seg = (out.len + 3) / 4;
        if (3 * seg > out.len) return error.MalformedLiteralsSection;
        var b1 = try BackReader.init(src[6..][0..s1]);
        var b2 = try BackReader.init(src[6 + s1 ..][0..s2]);
        var b3 = try BackReader.init(src[6 + s1 + s2 ..][0..s3]);
        var b4 = try BackReader.init(src[6 + s1 + s2 + s3 ..]);
        const huf = &d.t.huf;
        const bits = d.huf_bits;
        const o = out.ptr;
        var i: usize = 0;
        const last = out.len - 3 * seg;
        // The four streams interleaved, five symbols each per refill.
        while (i + 5 <= last and b1.ptr >= 8 and b2.ptr >= 8 and b3.ptr >= 8 and b4.ptr >= 8) {
            inline for (0..5) |k| {
                const e1 = huf[@intCast(b1.peek(bits))];
                const e2 = huf[@intCast(b2.peek(bits))];
                const e3 = huf[@intCast(b3.peek(bits))];
                const e4 = huf[@intCast(b4.peek(bits))];
                b1.consumed += e1 & 0xff;
                b2.consumed += e2 & 0xff;
                b3.consumed += e3 & 0xff;
                b4.consumed += e4 & 0xff;
                o[i + k] = @intCast(e1 >> 8);
                o[seg + i + k] = @intCast(e2 >> 8);
                o[2 * seg + i + k] = @intCast(e3 >> 8);
                o[3 * seg + i + k] = @intCast(e4 >> 8);
            }
            i += 5;
            b1.reload();
            b2.reload();
            b3.reload();
            b4.reload();
        }
        try d.huffStream(&b1, o + i, seg - i);
        try d.huffStream(&b2, o + seg + i, seg - i);
        try d.huffStream(&b3, o + 2 * seg + i, seg - i);
        try d.huffStream(&b4, o + 3 * seg + i, last - i);
    }

    /// Set up the decode table for one sequence field; returns the bytes used.
    fn seqTable(d: *Decoder, comptime kind: SeqKind, mode: u8, src: []const u8) Error!usize {
        const t = d.t;
        const table: []SeqEntry, const def: []const SeqEntry, const max_log: u5, const max_sym: u32, const def_log: u5 = switch (kind) {
            .ll => .{ &t.ll, &t.ll_def, ll_max_log, ll_max_sym, 6 },
            .ml => .{ &t.ml, &t.ml_def, ml_max_log, ml_max_sym, 6 },
            .of => .{ &t.of, &t.of_def, of_max_log, of_max_sym, 5 },
            .raw => unreachable,
        };
        const log_ptr: *u5, const ok_ptr: *bool = switch (kind) {
            .ll => .{ &d.ll_log, &d.ll_ok },
            .ml => .{ &d.ml_log, &d.ml_ok },
            .of => .{ &d.of_log, &d.of_ok },
            .raw => unreachable,
        };
        switch (mode) {
            0 => {
                @memcpy(table[0..def.len], def);
                log_ptr.* = def_log;
                ok_ptr.* = true;
                return 0;
            },
            1 => {
                if (src.len < 1) return error.MalformedCompressedBlock;
                const s = src[0];
                if (s > max_sym) return error.MalformedSequence;
                table[0] = .{ .base = s, .new_state = 0, .extra = 0, .nbits = 0 };
                switch (kind) {
                    .ll => {
                        table[0].base = ll_base[s];
                        table[0].extra = ll_bits[s];
                    },
                    .ml => {
                        table[0].base = ml_base[s];
                        table[0].extra = ml_bits[s];
                    },
                    .of => {
                        table[0].base = @as(u32, 1) << @intCast(s);
                        table[0].extra = s;
                    },
                    .raw => unreachable,
                }
                log_ptr.* = 0;
                ok_ptr.* = true;
                return 1;
            },
            2 => {
                var norm: [ml_max_sym + 1]i16 = undefined;
                const nc = try readNCount(src, norm[0 .. max_sym + 1], max_log);
                buildFse(kind, norm[0 .. max_sym + 1], nc.log, table);
                log_ptr.* = nc.log;
                ok_ptr.* = true;
                return nc.used;
            },
            else => {
                if (!ok_ptr.*) return error.RepeatModeFirst;
                return 0;
            },
        }
    }

    fn sequences(d: *Decoder, src: []const u8, nseq: usize, lit: [*]const u8, lit_len: usize, oend: usize) Error!void {
        var sd: SeqDecoder = .{
            .t = d.t,
            .br = try BackReader.init(src),
            .rep = d.rep,
        };
        sd.ll_state = @intCast(sd.br.read(d.ll_log));
        sd.of_state = @intCast(sd.br.read(d.of_log));
        sd.ml_state = @intCast(sd.br.read(d.ml_log));
        sd.br.reload();
        const out = d.out.ptr;
        const out_len = d.out.len;
        var op = d.wp;
        var lp: usize = 0;
        const base = d.frame_base;

        // Sequences are decoded `ahead` places before they are executed, and each one's match
        // source is prefetched when it is decoded: on large windows the source is usually far
        // back and not in cache.
        const ahead = 8;
        var ring: [ahead]Seq = undefined;
        var pf = op;
        const pre = @min(nseq, ahead);
        for (0..pre) |i| {
            const sq = sd.next(i + 1 == nseq);
            pf += sq.ll;
            @prefetch(out + @min(pf -| sq.off, out_len), .{});
            pf += sq.ml;
            ring[i] = sq;
        }
        for (0..nseq) |i| {
            const sq = ring[i % ahead];
            if (i + ahead < nseq) {
                const nx = sd.next(i + ahead + 1 == nseq);
                pf += nx.ll;
                @prefetch(out + @min(pf -| nx.off, out_len), .{});
                pf += nx.ml;
                ring[i % ahead] = nx;
            }
            const ll: usize = sq.ll;
            const ml: usize = sq.ml;
            const off: usize = sq.off;
            // Bounds: literals, output room, and an offset inside this frame's output.
            if (ll > lit_len - lp or ml > oend - op or ll > oend - op - ml) return error.MalformedSequence;
            if (off == 0 or off > op + ll - base) return error.MalformedSequence;
            const dst = out + op;
            if (ll <= 16 and ml <= 16 and off >= 16) {
                // The common short sequence: one 16-byte copy each, no loops.
                dst[0..16].* = @as(@Vector(16, u8), lit[lp..][0..16].*);
                dst[ll..][0..16].* = @as(@Vector(16, u8), (dst + ll - off)[0..16].*);
            } else {
                copyLiterals(dst, lit + lp, ll);
                copyMatch(dst + ll, off, ml);
            }
            op += ll + ml;
            lp += ll;
        }
        if (sd.br.unread() != 0) return error.MalformedSequence;
        const rest = lit_len - lp;
        if (rest > oend - op) return error.MalformedSequence;
        @memcpy(out[op..][0..rest], lit[lp..][0..rest]);
        op += rest;
        d.wp = op;
        d.rep = sd.rep;
    }
};

const Seq = struct { ll: u32, ml: u32, off: u32 };

/// The FSE states, repeat offsets and bit reader of one block's sequences.
const SeqDecoder = struct {
    t: *const Tables,
    br: BackReader,
    rep: [3]u32,
    ll_state: u32 = 0,
    ml_state: u32 = 0,
    of_state: u32 = 0,

    /// Decode the next sequence; `last` skips the state update after the final one. Values
    /// are not checked here: execution bounds every length and offset.
    inline fn next(sd: *SeqDecoder, last: bool) Seq {
        const t = sd.t;
        const br = &sd.br;
        const lle = t.ll[sd.ll_state];
        const mle = t.ml[sd.ml_state];
        const ofe = t.of[sd.of_state];
        const ov: u32 = ofe.base + @as(u32, @intCast(br.read(ofe.extra)));
        const ml: u32 = mle.base + @as(u32, @intCast(br.read(mle.extra)));
        br.reload();
        const ll: u32 = lle.base + @as(u32, @intCast(br.read(lle.extra)));
        // Repeat offsets (RFC 8878 3.1.1.5). Built in temporaries: assigning an array literal
        // that reads `rep` straight into `rep` would overwrite it as it goes.
        var off: u32 = undefined;
        const r0 = sd.rep[0];
        const r1 = sd.rep[1];
        const r2 = sd.rep[2];
        if (ov > 3) {
            off = ov - 3;
            sd.rep = .{ off, r0, r1 };
        } else switch (ov - 1 + @intFromBool(ll == 0)) {
            0 => off = r0,
            1 => {
                off = r1;
                sd.rep = .{ r1, r0, r2 };
            },
            2 => {
                off = r2;
                sd.rep = .{ r2, r0, r1 };
            },
            else => {
                off = r0 -% 1;
                sd.rep = .{ off, r0, r1 };
            },
        }
        if (!last) {
            sd.ll_state = lle.new_state + @as(u32, @intCast(br.read(lle.nbits)));
            sd.ml_state = mle.new_state + @as(u32, @intCast(br.read(mle.nbits)));
            sd.of_state = ofe.new_state + @as(u32, @intCast(br.read(ofe.nbits)));
            br.reload();
        }
        return .{ .ll = ll, .ml = ml, .off = off };
    }
};

/// Copy `len` literal bytes 16 at a time; reads and writes up to 15 bytes past the end.
inline fn copyLiterals(dst: [*]u8, src: [*]const u8, len: usize) void {
    var i: usize = 0;
    while (i < len) : (i += 16) {
        const v: @Vector(16, u8) = src[i..][0..16].*;
        dst[i..][0..16].* = v;
    }
}

/// Copy a match of `len` bytes from `off` back; may write up to 15 bytes past the end.
inline fn copyMatch(dst: [*]u8, off: usize, len: usize) void {
    const src = dst - off;
    if (off >= 16) {
        var i: usize = 0;
        while (i < len) : (i += 16) {
            const v: @Vector(16, u8) = src[i..][0..16].*;
            dst[i..][0..16].* = v;
        }
    } else if (off >= 8) {
        var i: usize = 0;
        while (i < len) : (i += 8) {
            const v: [8]u8 = src[i..][0..8].*;
            dst[i..][0..8].* = v;
        }
    } else if (off == 1) {
        const v: @Vector(16, u8) = @splat(src[0]);
        var i: usize = 0;
        while (i < len) : (i += 16) dst[i..][0..16].* = v;
    } else {
        for (0..len) |i| dst[i] = src[i];
    }
}

// Tests: the reference vectors, a differential check against std's decoder on mutated frames,
// and the window limit.

const fixtures = @import("../fixtures/fixtures.zig");

fn decodeAll(gpa: std.mem.Allocator, compressed: []const u8, window_len: u32) ![]u8 {
    const work = try gpa.alloc(u8, workLen(window_len));
    defer gpa.free(work);
    var in: Io.Reader = .fixed(compressed);
    var d = Decoder.init(&in, work, window_len);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var chunk: [7000]u8 = undefined;
    while (true) {
        const n = container.readSome(&d.interface, &chunk) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return d.err.?,
        };
        try out.appendSlice(gpa, chunk[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

test "decodes the reference zstd vectors" {
    const gpa = std.testing.allocator;
    for (fixtures.zstd_vectors) |v| {
        if (std.mem.eql(u8, v.name, "window-128m")) {
            try std.testing.expectError(error.WindowOversize, decodeAll(gpa, v.compressed, 8 << 20));
            continue;
        }
        const out = try decodeAll(gpa, v.compressed, 1 << 20);
        defer gpa.free(out);
        try std.testing.expectEqual(v.plain_len, out.len);
        try std.testing.expectEqual(v.plain_crc, std.hash.Crc32.hash(out));
    }
}

test "agrees with std's decoder on mutated frames" {
    const gpa = std.testing.allocator;
    const window: u32 = 1 << 20;
    const std_buf = try gpa.alloc(u8, 2 * window + std.compress.zstd.block_size_max);
    defer gpa.free(std_buf);
    var prng = std.Random.DefaultPrng.init(17);
    const r = prng.random();
    for (fixtures.zstd_vectors) |v| {
        if (std.mem.eql(u8, v.name, "window-128m")) continue;
        const copy = try gpa.dupe(u8, v.compressed);
        defer gpa.free(copy);
        for (0..300) |round| {
            @memcpy(copy, v.compressed);
            for (0..1 + round % 3) |_| copy[r.uintLessThan(usize, copy.len)] ^= @as(u8, 1) << r.int(u3);
            var std_in: Io.Reader = .fixed(copy);
            var sd = std.compress.zstd.Decompress.init(&std_in, std_buf, .{ .window_len = window });
            var want: Io.Writer.Allocating = .init(gpa);
            defer want.deinit();
            const std_ok = if (sd.reader.streamRemaining(&want.writer)) |_| true else |_| false;
            const got = decodeAll(gpa, copy, window) catch continue;
            defer gpa.free(got);
            // We may accept what std rejects (std checks a few things we skip, such as the
            // content size); when both succeed the output must match.
            if (std_ok) try std.testing.expectEqualSlices(u8, want.written(), got);
        }
    }
}
