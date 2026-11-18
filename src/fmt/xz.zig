//! The .xz container (The .xz File Format, Tukaani, version 1.1.0): stream header, blocks with
//! a filter chain, index, stream footer, stream padding and concatenated streams. Blocks decode
//! through our own streaming LZMA2 (lzma.zig) with one dictionary per stream.
//!
//! Supported filter chain: LZMA2 alone. BCJ and delta filters are reported as unsupported (the
//! block's raw bytes are still scanned by the parent). Integrity checks are parsed and skipped,
//! as std does: a scanner reads damaged data anyway, and checks would only cost throughput.
const std = @import("std");
const Io = std.Io;
const lzma = @import("lzma.zig");
const Crc32 = std.hash.crc.@"CRC-32/ISO-HDLC";

pub const Error = error{ Corrupt, Unsupported, DictTooLarge, ReadFailed, EndOfStream };

pub const magic = "\xfd7zXZ\x00";

/// What a caller needs to allocate before decoding: the first block's dictionary.
pub const Plan = struct { dict_size: u64 };

/// Peek the stream header and first block header to learn the dictionary size, without
/// consuming anything. Errors mean "not decodable"; the caller reports them.
pub fn plan(in: *Io.Reader) Error!Plan {
    const head = in.peek(12) catch |e| return e;
    if (!std.mem.eql(u8, head[0..6], magic)) return error.Corrupt;
    const first = (in.peek(13) catch return .{ .dict_size = 0 })[12];
    if (first == 0) return .{ .dict_size = 0 }; // no blocks
    const hdr_len = (@as(usize, first) + 1) * 4;
    const all = in.peek(12 + hdr_len) catch |e| return e;
    const block = try parseBlockHeader(all[12..][0..hdr_len]);
    return .{ .dict_size = block.dictCap() };
}

const BlockHeader = struct {
    compressed: ?u64,
    uncompressed: ?u64,
    dict_size: u64,

    /// The dictionary actually needed: no larger than the block's declared output.
    fn dictCap(b: BlockHeader) u64 {
        const u = b.uncompressed orelse return b.dict_size;
        return @max(@min(b.dict_size, u), 1);
    }
};

fn leb(bytes: []const u8, pos: *usize) Error!u64 {
    var v: u64 = 0;
    var shift: u7 = 0;
    while (true) {
        if (pos.* >= bytes.len or shift > 63) return error.Corrupt;
        const b = bytes[pos.*];
        pos.* += 1;
        v |= @as(u64, b & 0x7f) << @intCast(shift);
        if (b & 0x80 == 0) {
            if (b == 0 and shift != 0) return error.Corrupt;
            return v;
        }
        shift += 7;
    }
}

fn parseBlockHeader(h: []const u8) Error!BlockHeader {
    if (h.len < 8) return error.Corrupt;
    if (Crc32.hash(h[0 .. h.len - 4]) != std.mem.readInt(u32, h[h.len - 4 ..][0..4], .little)) return error.Corrupt;
    const flags = h[1];
    if (flags & 0x3c != 0) return error.Corrupt;
    var pos: usize = 2;
    const body = h[0 .. h.len - 4];
    var out: BlockHeader = .{ .compressed = null, .uncompressed = null, .dict_size = 0 };
    if (flags & 0x40 != 0) out.compressed = try leb(body, &pos);
    if (flags & 0x80 != 0) out.uncompressed = try leb(body, &pos);
    const n_filters = (flags & 3) + 1;
    var lzma2_seen = false;
    for (0..n_filters) |i| {
        const id = try leb(body, &pos);
        const props_len = try leb(body, &pos);
        if (props_len > body.len - pos) return error.Corrupt;
        const props = body[pos..][0..@intCast(props_len)];
        pos += @intCast(props_len);
        if (id == 0x21) {
            if (i != n_filters - 1 or props.len != 1) return error.Corrupt;
            out.dict_size = lzma.Lzma2.dictSize(props[0]) catch return error.Corrupt;
            lzma2_seen = true;
        } else if (i == n_filters - 1) return error.Corrupt else return error.Unsupported;
    }
    if (!lzma2_seen) return error.Corrupt;
    for (body[pos..]) |b| if (b != 0) return error.Corrupt;
    return out;
}

fn checkSize(check: u4) usize {
    return switch (check) {
        0 => 0,
        1...3 => 4,
        4...6 => 8,
        7...9 => 16,
        10...12 => 32,
        13...15 => 64,
    };
}

pub const Decoder = struct {
    in: *Io.Reader,
    lz2: lzma.Lzma2,
    dict: lzma.Dict,
    check: u4 = 0,
    blocks: u64 = 0,
    state: enum { stream_header, block_header, block_data, after_streams } = .stream_header,
    /// Compressed bytes of the current block, to compute padding.
    block_header_len: usize = 0,
    /// Set by a caller that reads at most this many bytes of output (a disk image chunk): a
    /// dictionary larger than the output can never be referenced, so a block declaring one is
    /// decoded with `dict_buf` as long as that holds the whole output.
    output_bound: ?u64 = null,
    err: ?Error = null,
    interface: Io.Reader,

    /// `dict_buf` sized from `plan`; `probs` holds `lzma.Lzma2.probs_len`. A later block wanting
    /// a larger dictionary fails with DictTooLarge.
    pub fn init(in: *Io.Reader, dict_buf: []u8, probs: []u16, lz_buffer: []u8, buffer: []u8) Decoder {
        var d: Decoder = .{
            .in = in,
            .lz2 = undefined,
            .dict = .{ .buf = dict_buf },
            .interface = .{ .vtable = @import("../engine/container.zig").fillVTable(Decoder), .buffer = buffer, .seek = 0, .end = 0 },
        };
        d.lz2 = .init(in, probs, &d.dict, lz_buffer);
        return d;
    }

    pub fn fill(d: *Decoder, dest: []u8) Io.Reader.Error!usize {
        // The LZMA2 decoder points at `dict` by address; fix it in case this struct moved.
        d.lz2.lzma.dict = &d.dict;
        return d.fillInner(dest) catch |e| switch (e) {
            error.ReadFailed => error.ReadFailed,
            else => {
                d.err = e;
                return error.ReadFailed;
            },
        };
    }

    fn fillInner(d: *Decoder, dest: []u8) Error!usize {
        while (true) switch (d.state) {
            .after_streams => return 0,
            .stream_header => {
                const h = try d.in.takeArray(12);
                if (!std.mem.eql(u8, h[0..6], magic)) return error.Corrupt;
                if (h[6] != 0 or h[7] & 0xf0 != 0) return error.Corrupt;
                if (Crc32.hash(h[6..8]) != std.mem.readInt(u32, h[8..12], .little)) return error.Corrupt;
                d.check = @intCast(h[7] & 0x0f);
                d.blocks = 0;
                d.state = .block_header;
            },
            .block_header => {
                const first = try d.in.peekByte();
                if (first == 0) {
                    try d.finishStream();
                    continue;
                }
                const hdr_len = (@as(usize, first) + 1) * 4;
                const hb = try d.in.take(hdr_len);
                const block = try parseBlockHeader(hb);
                const bounded = if (d.output_bound) |b| b <= d.dict.buf.len else false;
                if (block.dictCap() > d.dict.buf.len and !bounded) return error.DictTooLarge;
                d.block_header_len = hdr_len;
                d.lz2.reset(d.in);
                d.state = .block_data;
            },
            .block_data => {
                const n = try d.lz2.decodeInto(dest);
                if (n != 0) return n;
                // Block done: padding to a multiple of four, then the check.
                d.blocks += 1;
                const counted = d.lz2.consumed;
                const pad = (4 - ((d.block_header_len + counted) % 4)) % 4;
                for (try d.in.take(pad)) |b| if (b != 0) return error.Corrupt;
                try d.in.discardAll(checkSize(d.check));
                d.state = .block_header;
            },
        };
    }

    /// Index, stream footer, stream padding; then either another stream or the end.
    fn finishStream(d: *Decoder) Error!void {
        var crc = Crc32.init();
        var counted: u64 = 1;
        crc.update(&.{try d.in.takeByte()});
        const records = try takeLeb(d.in, &crc, &counted);
        if (records != d.blocks) return error.Corrupt;
        for (0..records) |_| {
            _ = try takeLeb(d.in, &crc, &counted);
            _ = try takeLeb(d.in, &crc, &counted);
        }
        const pad = (4 - counted % 4) % 4;
        const padding = try d.in.take(@intCast(pad));
        for (padding) |b| if (b != 0) return error.Corrupt;
        crc.update(padding);
        if (crc.final() != try d.in.takeInt(u32, .little)) return error.Corrupt;
        const footer = try d.in.takeArray(12);
        if (!std.mem.eql(u8, footer[10..12], "YZ")) return error.Corrupt;
        // Stream padding: zero bytes in groups of four.
        while (true) {
            const p = d.in.peek(4) catch {
                d.state = .after_streams;
                return;
            };
            if (std.mem.eql(u8, p, "\x00\x00\x00\x00")) {
                d.in.toss(4);
                continue;
            }
            break;
        }
        const next = d.in.peek(6) catch {
            d.state = .after_streams;
            return;
        };
        d.state = if (std.mem.eql(u8, next, magic)) .stream_header else .after_streams;
    }
};

fn takeLeb(in: *Io.Reader, crc: *Crc32, counted: *u64) Error!u64 {
    var v: u64 = 0;
    var shift: u7 = 0;
    while (true) {
        const b = try in.takeByte();
        crc.update(&.{b});
        counted.* += 1;
        if (shift > 63) return error.Corrupt;
        v |= @as(u64, b & 0x7f) << @intCast(shift);
        if (b & 0x80 == 0) return v;
        shift += 7;
    }
}

const fixtures = @import("fixtures/fixtures.zig");

fn decodeAll(gpa: std.mem.Allocator, compressed: []const u8, dict_max: u64) !struct { len: usize, crc: u32 } {
    var src: Io.Reader = .fixed(compressed);
    const in = &src;
    const p = try plan(in);
    if (p.dict_size > dict_max) return error.DictTooLarge;
    const dict = try gpa.alloc(u8, @intCast(@max(p.dict_size, 1)));
    defer gpa.free(dict);
    const probs = try gpa.alloc(u16, lzma.Lzma2.probs_len);
    defer gpa.free(probs);
    var buf: [3000]u8 = undefined;
    var d = Decoder.init(in, dict, probs, &.{}, &buf);
    var crc = std.hash.Crc32.init();
    var total: usize = 0;
    while (true) {
        const chunk = d.interface.peekGreedy(1) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return d.err orelse error.ReadFailed,
        };
        crc.update(chunk);
        total += chunk.len;
        d.interface.toss(chunk.len);
    }
    return .{ .len = total, .crc = crc.final() };
}

test "decodes reference xz streams" {
    const gpa = std.testing.allocator;
    for (fixtures.xz_vectors) |v| {
        if (std.mem.eql(u8, v.name, "bcj-x86")) {
            try std.testing.expectError(error.Unsupported, decodeAll(gpa, v.compressed, 8 << 20));
            continue;
        }
        if (std.mem.eql(u8, v.name, "dict-64m")) {
            try std.testing.expectError(error.DictTooLarge, decodeAll(gpa, v.compressed, 8 << 20));
            continue;
        }
        const got = decodeAll(gpa, v.compressed, 8 << 20) catch |e| {
            std.debug.print("xz vector {s}: {t}\n", .{ v.name, e });
            return e;
        };
        try std.testing.expectEqual(v.plain_len, got.len);
        try std.testing.expectEqual(v.plain_crc, got.crc);
    }
}

test "corrupt xz fails cleanly" {
    const gpa = std.testing.allocator;
    const v = fixtures.xz_vectors[0].compressed;
    const copy = try gpa.dupe(u8, v);
    defer gpa.free(copy);
    var prng = std.Random.DefaultPrng.init(2);
    for (0..200) |_| {
        @memcpy(copy, v);
        for (0..2) |_| copy[prng.random().uintLessThan(usize, copy.len)] ^= prng.random().int(u8) | 1;
        _ = decodeAll(gpa, copy, 8 << 20) catch {};
    }
}
