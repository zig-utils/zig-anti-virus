//! VBA project parsing and MS-OVBA decompression, written from [MS-OVBA] section 2.4.1
//! (compressed containers) and 2.3.4.2 (the dir stream).
//!
//! A compressed container is a signature byte (1) and a run of chunks. Each chunk decompresses
//! to at most 4096 bytes, and its copy tokens only reach back inside the chunk, so the decoder
//! needs a 4 KiB window and streams chunk by chunk.
const std = @import("std");
const Io = std.Io;

pub const Error = error{ BadSignature, BadChunk, ReadFailed, EndOfStream };

/// Streaming MS-OVBA decompressor over a reader positioned at a compressed container.
pub const Decompressor = struct {
    in: *Io.Reader,
    chunk: [4096]u8 = undefined,
    chunk_len: usize = 0,
    chunk_pos: usize = 0,
    started: bool = false,
    done: bool = false,
    err: ?Error = null,
    interface: Io.Reader,

    pub fn init(in: *Io.Reader) Decompressor {
        return .{ .in = in, .interface = .{ .vtable = @import("../engine/container.zig").fillVTable(Decompressor), .buffer = &.{}, .seek = 0, .end = 0 } };
    }

    pub fn fill(d: *Decompressor, dest: []u8) Io.Reader.Error!usize {
        while (d.chunk_pos == d.chunk_len) {
            if (d.done) return 0;
            d.nextChunk() catch |e| switch (e) {
                error.ReadFailed => return error.ReadFailed,
                else => {
                    d.err = e;
                    return error.ReadFailed;
                },
            };
        }
        const n = @min(dest.len, d.chunk_len - d.chunk_pos);
        @memcpy(dest[0..n], d.chunk[d.chunk_pos..][0..n]);
        d.chunk_pos += n;
        return n;
    }

    fn nextChunk(d: *Decompressor) Error!void {
        if (!d.started) {
            if (try d.in.takeByte() != 1) return error.BadSignature;
            d.started = true;
        }
        const header = d.in.takeInt(u16, .little) catch |e| switch (e) {
            error.EndOfStream => {
                d.done = true;
                d.chunk_len = 0;
                d.chunk_pos = 0;
                return;
            },
            else => return e,
        };
        const size: usize = (header & 0x0fff) + 3; // including the header
        if ((header >> 12) & 0x7 != 0b011) return error.BadChunk;
        const compressed = header & 0x8000 != 0;
        d.chunk_len = 0;
        d.chunk_pos = 0;
        if (!compressed) {
            // A raw chunk is exactly 4096 bytes.
            if (size != 4098) return error.BadChunk;
            try d.in.readSliceAll(&d.chunk);
            d.chunk_len = 4096;
            return;
        }
        var left = size - 2;
        while (left > 0) {
            const flags = try d.in.takeByte();
            left -= 1;
            var bit: u4 = 0;
            while (bit < 8 and left > 0) : (bit += 1) {
                if (flags & (@as(u8, 1) << @intCast(bit)) == 0) {
                    if (d.chunk_len == d.chunk.len) return error.BadChunk;
                    d.chunk[d.chunk_len] = try d.in.takeByte();
                    d.chunk_len += 1;
                    left -= 1;
                } else {
                    if (left < 2) return error.BadChunk;
                    const token = try d.in.takeInt(u16, .little);
                    left -= 2;
                    const pos = d.chunk_len;
                    if (pos == 0) return error.BadChunk;
                    // Offset bits grow with the position in the chunk: max(ceil(log2(pos)), 4).
                    const bit_count: u5 = @intCast(@max(std.math.log2_int_ceil(usize, pos), 4));
                    const length_mask: u16 = @as(u16, 0xffff) >> @intCast(bit_count);
                    const offset: usize = (token >> @intCast(16 - @as(u6, bit_count))) + 1;
                    const length: usize = (token & length_mask) + 3;
                    if (offset > pos or pos + length > d.chunk.len) return error.BadChunk;
                    for (0..length) |k| d.chunk[pos + k] = d.chunk[pos + k - offset];
                    d.chunk_len += length;
                }
            }
        }
    }
};

/// Decompress a whole container held in memory into `out`; returns the length.
pub fn decompressInto(compressed: []const u8, out: []u8) Error![]u8 {
    var in: Io.Reader = .fixed(compressed);
    var d = Decompressor.init(&in);
    var n: usize = 0;
    while (n < out.len) {
        const got = d.fill(out[n..]) catch return d.err orelse error.ReadFailed;
        if (got == 0) break;
        n += got;
    }
    return out[0..n];
}

pub const Module = struct {
    /// MODULESTREAMNAME (MBCS): the stream under the VBA storage holding the module.
    stream_name: []const u8,
    /// MODULENAME, for the child's path.
    name: []const u8,
    /// MODULEOFFSET: where the compressed source starts in the module stream.
    text_offset: u32,
};

/// Parse a decompressed dir stream into modules (names are slices of `dir`). Records are
/// id (u16) + size (u32) + data; PROJECTVERSION (0x0009) is the one record whose size field
/// does not cover its data (6 more bytes follow). Stops at the end of the stream or after
/// `out.len` modules.
pub fn parseDir(dir: []const u8, out: []Module) []Module {
    var p: usize = 0;
    var n: usize = 0;
    var cur: Module = .{ .stream_name = "", .name = "", .text_offset = 0 };
    var in_module = false;
    while (p + 6 <= dir.len) {
        const id = std.mem.readInt(u16, dir[p..][0..2], .little);
        const size = std.mem.readInt(u32, dir[p + 2 ..][0..4], .little);
        p += 6;
        if (id == 0x0009) {
            p += 6;
            continue;
        }
        if (size > dir.len - p) break;
        const data = dir[p..][0..size];
        p += size;
        switch (id) {
            0x0019 => {
                cur = .{ .stream_name = "", .name = data, .text_offset = 0 };
                in_module = true;
            },
            0x001a => cur.stream_name = data,
            0x0031 => if (data.len >= 4) {
                cur.text_offset = std.mem.readInt(u32, data[0..4], .little);
            },
            0x002b => if (in_module) {
                if (n < out.len and cur.stream_name.len > 0) {
                    out[n] = cur;
                    n += 1;
                }
                in_module = false;
            },
            else => {},
        }
    }
    return out[0..n];
}

test "MS-OVBA example: compressed container with copy tokens" {
    // [MS-OVBA] 3.2.3: "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa".
    const compressed = [_]u8{
        0x01, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00, 0x70,
        0x61, 0x67, 0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00, 0x30, 0x6D, 0x6E, 0x6F,
        0x70, 0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10, 0x77, 0x78, 0x79,
        0x7A, 0x00, 0x3C,
    };
    var out: [128]u8 = undefined;
    try std.testing.expectEqualStrings("#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa", try decompressInto(&compressed, &out));
}

test "bad containers fail cleanly" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.BadSignature, decompressInto("\x02\x00\x00", &out));
    try std.testing.expectError(error.BadChunk, decompressInto("\x01\x00\x00", &out));
}
