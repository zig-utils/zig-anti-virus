//! A streaming bzip2 decoder, written from the format description (Seward's bzip2 file format:
//! stream header "BZh1".."BZh9", blocks of Huffman-coded MTF/RLE2 symbols over a Burrows-Wheeler
//! transformed, RLE1-coded block, and an end-of-stream marker with a combined CRC). Zig std has
//! no bzip2.
//!
//! Memory: one u32 per block byte for the inverse BWT (the fast form: index and byte packed
//! together), so 3.6 MB for a level 9 block, plus about 30 KiB of tables. Blocks above 1 MiB of
//! working set take a big-window budget token through the caller. Output streams: a decoded
//! block is turned back into bytes as the consumer reads, never as a whole buffer.
//!
//! Randomised blocks (an obsolete encoder option, not written by bzip2 since 0.9.5) are reported
//! as unsupported rather than decoded.
const std = @import("std");
const Io = std.Io;

/// CRC-32/BZIP2 (polynomial 0x04C11DB7, MSB first, no reflection) with slicing-by-8 tables.
/// std.hash.crc.Generic updates the non-reflected CRCs a byte at a time, which cost a tenth of
/// the decode time here; this has the same init/update/final shape as std's, so it could replace
/// the byte loop there for every MSB-first CRC.
const Crc = struct {
    state: u32 = 0xffffffff,

    const tables = blk: {
        @setEvalBranchQuota(20_000);
        var t: [8][256]u32 = undefined;
        for (0..256) |i| {
            var c: u32 = @as(u32, i) << 24;
            for (0..8) |_| c = if (c & 0x80000000 != 0) (c << 1) ^ 0x04C11DB7 else c << 1;
            t[0][i] = c;
        }
        for (1..8) |k| {
            for (0..256) |i| t[k][i] = (t[k - 1][i] << 8) ^ t[0][t[k - 1][i] >> 24];
        }
        break :blk t;
    };

    pub fn init() Crc {
        return .{};
    }

    pub fn update(c: *Crc, bytes: []const u8) void {
        var crc = c.state;
        var b = bytes;
        while (b.len >= 8) {
            const hi = crc ^ std.mem.readInt(u32, b[0..4], .big);
            crc = tables[7][hi >> 24] ^ tables[6][(hi >> 16) & 0xff] ^ tables[5][(hi >> 8) & 0xff] ^ tables[4][hi & 0xff] ^
                tables[3][b[4]] ^ tables[2][b[5]] ^ tables[1][b[6]] ^ tables[0][b[7]];
            b = b[8..];
        }
        for (b) |x| crc = (crc << 8) ^ tables[0][(crc >> 24) ^ x];
        c.state = crc;
    }

    pub fn final(c: Crc) u32 {
        return ~c.state;
    }
};

pub const Error = error{
    BadHeader,
    BadBlock,
    BadHuffman,
    BadCrc,
    Randomised,
    ReadFailed,
    EndOfStream,
};

const max_groups = 6;
const max_alpha = 258;
const max_code_len = 20;
const max_selectors = 18002;
const group_size = 50;
const block_magic: u48 = 0x314159265359;
const end_magic: u48 = 0x177245385090;

/// Bytes of working memory a stream at `level` (1 to 9) needs.
pub fn workingSet(level: u8) usize {
    return @as(usize, level) * 100_000 * 4 + @sizeOf(Tables);
}

/// Codes up to this long decode in one lookup; longer ones continue through limit/base.
const lookup_bits = 10;

const Tables = struct {
    selectors: [max_selectors]u8,
    /// Per group, indexed by the next `lookup_bits` bits: symbol << 5 | code length, or 0 when
    /// the code is longer.
    lookup: [max_groups][1 << lookup_bits]u16,
    lens: [max_groups][max_alpha]u8,
    limit: [max_groups][max_code_len + 2]i32,
    base: [max_groups][max_code_len + 2]i32,
    perm: [max_groups][max_alpha]u16,
    min_len: [max_groups]u8,
};

pub const Decoder = struct {
    in: *Io.Reader,
    /// Inverse-BWT vector: low 8 bits the byte, high 24 bits the next index.
    tt: []u32,
    tables: *Tables,
    block_max: u32,
    bits: u64 = 0,
    nbits: u6 = 0,

    // Output state for the current block.
    t_pos: u32 = 0,
    left: u32 = 0,
    last: i16 = -1,
    run: u8 = 0,
    rep_left: u8 = 0,
    rep_byte: u8 = 0,
    crc: Crc = .init(),
    want_crc: u32 = 0,
    stream_crc: u32 = 0,
    in_block: bool = false,
    done: bool = false,
    err: ?Error = null,
    interface: Io.Reader,

    /// Parse the stream header and set up. `tt` must hold `level * 100000` entries; use
    /// `peekLevel` to size it. `tables` is caller-provided scratch.
    pub fn init(in: *Io.Reader, tt: []u32, tables: *Tables, buffer: []u8) Error!Decoder {
        const hdr = try in.takeArray(4);
        if (!std.mem.eql(u8, hdr[0..3], "BZh") or hdr[3] < '1' or hdr[3] > '9') return error.BadHeader;
        const block_max: u32 = @as(u32, hdr[3] - '0') * 100_000;
        if (tt.len < block_max) return error.BadHeader;
        return .{
            .in = in,
            .tt = tt,
            .tables = tables,
            .block_max = block_max,
            .interface = .{ .vtable = @import("../engine/container.zig").fillVTable(Decoder), .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    pub const TablesType = Tables;

    /// The level digit of a stream that starts at `head`, or null.
    pub fn peekLevel(head: []const u8) ?u8 {
        if (head.len < 4 or !std.mem.eql(u8, head[0..3], "BZh") or head[3] < '1' or head[3] > '9') return null;
        return head[3] - '0';
    }

    fn need(d: *Decoder, n: u6) Error!void {
        while (d.nbits < n) {
            const b = d.in.takeByte() catch |e| return e;
            d.bits = (d.bits << 8) | b;
            d.nbits += 8;
        }
    }

    fn take(d: *Decoder, n: u6) Error!u32 {
        try d.need(n);
        d.nbits -= n;
        return @intCast((d.bits >> d.nbits) & ((@as(u64, 1) << n) - 1));
    }

    fn bit(d: *Decoder) Error!u1 {
        return @intCast(try d.take(1));
    }

    pub fn fill(d: *Decoder, dest: []u8) Io.Reader.Error!usize {
        return d.fillInner(dest) catch |e| switch (e) {
            error.ReadFailed => return error.ReadFailed,
            else => {
                d.err = e;
                return error.ReadFailed;
            },
        };
    }

    fn fillInner(d: *Decoder, dest: []u8) Error!usize {
        var i: usize = 0;
        while (i < dest.len) {
            if (d.rep_left > 0) {
                const n = @min(d.rep_left, dest.len - i);
                @memset(dest[i..][0..n], d.rep_byte);
                d.crc.update(dest[i..][0..n]);
                i += n;
                d.rep_left -= @intCast(n);
                continue;
            }
            if (d.left == 0) {
                if (d.in_block) try d.endBlock();
                if (i != 0) return i;
                if (d.done or !try d.nextBlock()) {
                    d.done = true;
                    return 0;
                }
                continue;
            }
            // Fast path: emit bytes from the BWT until a run of four needs a count byte.
            const start = i;
            while (i < dest.len and d.left > 0) {
                const e = d.tt[d.t_pos];
                d.t_pos = e >> 8;
                d.left -= 1;
                const b: u8 = @truncate(e);
                if (d.run == 4) {
                    d.run = 0;
                    d.rep_left = b;
                    d.rep_byte = @intCast(d.last);
                    break;
                }
                if (b == d.last) d.run += 1 else {
                    d.run = 1;
                    d.last = b;
                }
                dest[i] = b;
                i += 1;
            }
            d.crc.update(dest[start..i]);
        }
        return i;
    }

    fn endBlock(d: *Decoder) Error!void {
        d.in_block = false;
        if (d.run == 4) {
            // A block ending exactly after four equal bytes has no count byte.
            d.run = 0;
        }
        const got = d.crc.final();
        if (got != d.want_crc) return error.BadCrc;
        d.stream_crc = ((d.stream_crc << 1) | (d.stream_crc >> 31)) ^ got;
    }

    /// Read the next block (true) or the end of the stream (false). Concatenated streams continue.
    fn nextBlock(d: *Decoder) Error!bool {
        while (true) {
            const magic: u48 = @intCast((@as(u64, try d.take(24)) << 24) | try d.take(24));
            if (magic == block_magic) break;
            if (magic != end_magic) return error.BadBlock;
            const combined = try d.take(32);
            if (combined != d.stream_crc) return error.BadCrc;
            // Byte-align, then another stream may follow. The block loop refills a word at a
            // time, so the next stream's first bytes may already be in the bit buffer.
            d.nbits -= d.nbits % 8;
            var next: [4]u8 = undefined;
            var have: usize = 0;
            while (have < 4 and d.nbits >= 8) : (have += 1) next[have] = @intCast(try d.take(8));
            if (have < 4) @memcpy(next[have..], d.in.peek(4 - have) catch return false);
            if (!std.mem.eql(u8, next[0..3], "BZh") or next[3] < '1' or next[3] > '9') return false;
            const level_max: u32 = @as(u32, next[3] - '0') * 100_000;
            if (level_max > d.tt.len) return false;
            if (have < 4) d.in.toss(4 - have);
            d.block_max = level_max;
            d.stream_crc = 0;
        }
        d.want_crc = try d.take(32);
        if (try d.bit() == 1) return error.Randomised;
        const orig_ptr = try d.take(24);
        const n = try d.readBlock();
        if (orig_ptr >= n) return error.BadBlock;
        // Inverse BWT.
        var counts: [256]u32 = @splat(0);
        for (d.tt[0..n]) |e| counts[e & 0xff] += 1;
        var sum: u32 = 0;
        for (&counts) |*c| {
            const t = c.*;
            c.* = sum;
            sum += t;
        }
        for (0..n) |i| {
            const b = d.tt[i] & 0xff;
            d.tt[counts[b]] |= @as(u32, @intCast(i)) << 8;
            counts[b] += 1;
        }
        d.t_pos = d.tt[orig_ptr] >> 8;
        d.left = n;
        d.last = -1;
        d.run = 0;
        d.crc = .init();
        d.in_block = true;
        return true;
    }

    /// Decode one block's symbols into tt (bytes only); returns its length.
    fn readBlock(d: *Decoder) Error!u32 {
        const t = d.tables;
        // Symbol map.
        var seq_to_unseq: [256]u8 = undefined;
        var n_in_use: u32 = 0;
        const used16 = try d.take(16);
        for (0..16) |i| {
            if (used16 & (@as(u32, 0x8000) >> @intCast(i)) == 0) continue;
            const used = try d.take(16);
            for (0..16) |j| {
                if (used & (@as(u32, 0x8000) >> @intCast(j)) != 0) {
                    seq_to_unseq[n_in_use] = @intCast(i * 16 + j);
                    n_in_use += 1;
                }
            }
        }
        if (n_in_use == 0) return error.BadBlock;
        const alpha = n_in_use + 2;

        const n_groups = try d.take(3);
        if (n_groups < 2 or n_groups > max_groups) return error.BadBlock;
        const n_selectors_raw = try d.take(15);
        if (n_selectors_raw == 0) return error.BadBlock;
        // Newer encoders never exceed 18002; extra selectors are read and ignored, as bzip2 1.0.8 does.
        const n_selectors = @min(n_selectors_raw, max_selectors);
        var mtf_groups: [max_groups]u8 = .{ 0, 1, 2, 3, 4, 5 };
        for (0..n_selectors_raw) |s| {
            var j: u8 = 0;
            while (try d.bit() == 1) {
                j += 1;
                if (j >= n_groups) return error.BadBlock;
            }
            if (s >= n_selectors) continue;
            const v = mtf_groups[j];
            var k = j;
            while (k > 0) : (k -= 1) mtf_groups[k] = mtf_groups[k - 1];
            mtf_groups[0] = v;
            t.selectors[s] = v;
        }

        for (0..n_groups) |g| {
            var len: i32 = @intCast(try d.take(5));
            for (0..alpha) |s| {
                while (true) {
                    if (len < 1 or len > max_code_len) return error.BadHuffman;
                    if (try d.bit() == 0) break;
                    len += if (try d.bit() == 0) 1 else -1;
                }
                t.lens[g][s] = @intCast(len);
            }
            try buildTable(t, g, alpha);
        }

        // MTF/RLE2 decode into tt. The bit buffer lives in locals for the loop.
        var mtf: [256]u8 = undefined;
        for (&mtf, 0..) |*m, i| m.* = @intCast(i);
        const eob = n_in_use + 1;
        var n: u32 = 0;
        var group_left: u32 = 0;
        var sel: u32 = 0;
        var g: usize = 0;
        var run: u32 = 0;
        var run_weight: u32 = 1;
        var bits = d.bits;
        var nbits: u32 = d.nbits;
        defer {
            d.bits = bits;
            d.nbits = @intCast(nbits);
        }
        const in = d.in;
        const tt = d.tt;
        while (true) {
            if (group_left == 0) {
                if (sel >= n_selectors) return error.BadBlock;
                g = t.selectors[sel];
                sel += 1;
                group_left = group_size;
            }
            group_left -= 1;
            // Refill to at least 20 bits (the longest code). A valid block is followed by at
            // least the 80-bit end-of-stream marker, so running dry here means truncation.
            if (nbits < max_code_len) {
                if (in.end - in.seek >= 8) {
                    const word = std.mem.readInt(u64, in.buffer[in.seek..][0..8], .big);
                    const take_n = (63 - nbits) >> 3;
                    bits = (bits << @intCast(take_n * 8)) | (word >> @intCast(64 - take_n * 8));
                    in.seek += take_n;
                    nbits += take_n * 8;
                } else while (nbits < max_code_len) {
                    const b = in.takeByte() catch |e| return e;
                    bits = (bits << 8) | b;
                    nbits += 8;
                }
            }
            const peek: u32 = @intCast((bits >> @intCast(nbits - lookup_bits)) & ((1 << lookup_bits) - 1));
            const hit = t.lookup[g][peek];
            var sym: u32 = undefined;
            if (hit != 0) {
                nbits -= hit & 31;
                sym = hit >> 5;
            } else {
                var len: u32 = lookup_bits + 1;
                while (true) : (len += 1) {
                    if (len > max_code_len) return error.BadHuffman;
                    const code: i32 = @intCast((bits >> @intCast(nbits - len)) & ((@as(u64, 1) << @intCast(len)) - 1));
                    if (code <= t.limit[g][len]) {
                        const idx = code - t.base[g][len];
                        if (idx < 0 or idx >= max_alpha) return error.BadHuffman;
                        sym = t.perm[g][@intCast(idx)];
                        nbits -= len;
                        break;
                    }
                }
            }
            if (sym <= 1) {
                // RUNA/RUNB: bijective base-2 run length of the front symbol.
                if (run_weight > d.block_max) return error.BadBlock;
                run += run_weight << @intCast(sym);
                run_weight <<= 1;
                if (run > d.block_max) return error.BadBlock;
                continue;
            }
            if (run > 0) {
                if (n + run > d.block_max) return error.BadBlock;
                const b = seq_to_unseq[mtf[0]];
                @memset(tt[n..][0..run], b);
                n += run;
                run = 0;
                run_weight = 1;
            }
            if (sym == eob) break;
            if (n >= d.block_max) return error.BadBlock;
            const idx = sym - 1;
            const v = mtf[idx];
            // Most indices are small: a byte loop beats a memmove call.
            var k = idx;
            while (k >= 4) : (k -= 4) {
                mtf[k] = mtf[k - 1];
                mtf[k - 1] = mtf[k - 2];
                mtf[k - 2] = mtf[k - 3];
                mtf[k - 3] = mtf[k - 4];
            }
            while (k > 0) : (k -= 1) mtf[k] = mtf[k - 1];
            mtf[0] = v;
            tt[n] = seq_to_unseq[v];
            n += 1;
        }
        if (n == 0) return error.BadBlock;
        return n;
    }
};

/// Canonical Huffman decode tables (limit/base/perm form).
fn buildTable(t: *Tables, g: usize, alpha: u32) Error!void {
    var min: u8 = max_code_len;
    var max: u8 = 0;
    for (t.lens[g][0..alpha]) |l| {
        min = @min(min, l);
        max = @max(max, l);
    }
    var pp: usize = 0;
    var len: u8 = min;
    while (len <= max) : (len += 1) {
        for (0..alpha) |s| if (t.lens[g][s] == len) {
            t.perm[g][pp] = @intCast(s);
            pp += 1;
        };
    }
    var count: [max_code_len + 2]i32 = @splat(0);
    for (t.lens[g][0..alpha]) |l| count[l] += 1;
    // Kraft check: an oversubscribed code is corrupt.
    var kraft: u64 = 0;
    for (1..max_code_len + 1) |l| kraft += @as(u64, @intCast(count[l])) << @intCast(max_code_len - l);
    if (kraft > (@as(u64, 1) << max_code_len)) return error.BadHuffman;
    var code: i32 = 0;
    var start: i32 = 0;
    for (0..max_code_len + 2) |l| {
        t.limit[g][l] = -1;
        t.base[g][l] = 0;
    }
    var l: usize = min;
    while (l <= max) : (l += 1) {
        t.base[g][l] = code - start;
        code += count[l];
        start += count[l];
        t.limit[g][l] = code - 1;
        code <<= 1;
    }
    t.min_len[g] = min;

    // One-lookup table for codes up to `lookup_bits` long, filled from the canonical codes.
    const look = &t.lookup[g];
    @memset(look, 0);
    var next_code: [max_code_len + 2]u32 = undefined;
    var c: u32 = 0;
    for (1..max_code_len + 1) |ln| {
        next_code[ln] = c;
        c = (c + @as(u32, @intCast(count[ln]))) << 1;
    }
    for (0..alpha) |sym| {
        const ln = t.lens[g][sym];
        const cw = next_code[ln];
        next_code[ln] += 1;
        if (ln > lookup_bits) continue;
        const shift: u5 = @intCast(lookup_bits - ln);
        const first = cw << shift;
        const entry: u16 = @intCast((sym << 5) | ln);
        @memset(look[first..][0 .. @as(u32, 1) << shift], entry);
    }
}

fn decodeAll(gpa: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var in: Io.Reader = .fixed(compressed);
    const level = Decoder.peekLevel(compressed) orelse return error.BadHeader;
    const tt = try gpa.alloc(u32, @as(usize, level) * 100_000);
    defer gpa.free(tt);
    const tables = try gpa.create(Tables);
    defer gpa.destroy(tables);
    var buf: [4096]u8 = undefined;
    var d = try Decoder.init(&in, tt, tables, &buf);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    while (true) {
        const chunk = d.interface.peekGreedy(1) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return d.err orelse error.ReadFailed,
        };
        try out.appendSlice(gpa, chunk);
        d.interface.toss(chunk.len);
    }
    return out.toOwnedSlice(gpa);
}

const fixtures = @import("fixtures/fixtures.zig");

test "decodes reference bzip2 streams" {
    const gpa = std.testing.allocator;
    for (fixtures.bzip2_vectors) |v| {
        const out = try decodeAll(gpa, v.compressed);
        defer gpa.free(out);
        try std.testing.expectEqual(v.plain_len, out.len);
        var h = std.hash.Crc32.init();
        h.update(out);
        try std.testing.expectEqual(v.plain_crc, h.final());
    }
}

test "corrupt streams fail cleanly" {
    const gpa = std.testing.allocator;
    const v = fixtures.bzip2_vectors[1].compressed;
    const copy = try gpa.dupe(u8, v);
    defer gpa.free(copy);
    var prng = std.Random.DefaultPrng.init(1);
    for (0..300) |_| {
        @memcpy(copy, v);
        for (0..3) |_| copy[4 + prng.random().uintLessThan(usize, copy.len - 4)] ^= prng.random().int(u8) | 1;
        if (decodeAll(gpa, copy)) |out| gpa.free(out) else |_| {}
    }
    try std.testing.expectError(error.BadHeader, decodeAll(gpa, "BZx9"));
}

test "slicing-by-8 CRC matches std's CRC-32/BZIP2" {
    var buf: [1000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    prng.random().bytes(&buf);
    for ([_]usize{ 0, 1, 7, 8, 9, 63, 1000 }) |len| {
        var ours: Crc = .init();
        ours.update(buf[0 .. len / 2]);
        ours.update(buf[len / 2 .. len]);
        try std.testing.expectEqual(std.hash.crc.@"CRC-32/BZIP2".hash(buf[0..len]), ours.final());
    }
}
