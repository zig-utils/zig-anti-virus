//! zstd (RFC 8878) over std.compress.zstd. The window is decided before decoding: the first
//! frame header is peeked and its window size (or single-segment content size) sets the buffer,
//! with a floor that keeps small frames under the 1 MiB token-free size. A window over the cap
//! (8 MiB by default) is a limit event; so is a later frame that needs more than the first.
const std = @import("std");
const Io = std.Io;
const zstd = std.compress.zstd;

/// Buffers up to this many bytes need no big-window token, so small windows round up to it.
pub const floor_window: u32 = 1024 * 1024 - zstd.block_size_max;

pub const Error = error{ BadMagic, Truncated };

/// The window the first frame asks for. Skippable leading frames give `fallback` (the cap):
/// what follows is unknown, and a too-small window would fail later frames.
pub fn frameWindow(head: []const u8, fallback: u64) Error!u64 {
    if (head.len < 5) return error.Truncated;
    const magic = std.mem.readInt(u32, head[0..4], .little);
    if (magic & 0xFFFFFFF0 == 0x184D2A50) return fallback;
    if (magic != 0xFD2FB528) return error.BadMagic;
    const fhd = head[4];
    const single = (fhd >> 5) & 1 == 1;
    if (!single) {
        if (head.len < 6) return error.Truncated;
        const wd = head[5];
        const exponent: u6 = @intCast(wd >> 3);
        const base = @as(u64, 1) << (10 + exponent);
        return base + (base / 8) * (wd & 7);
    }
    const did_lens = [_]usize{ 0, 1, 2, 4 };
    const fcs_lens = [_]usize{ 1, 2, 4, 8 };
    const did_len = did_lens[fhd & 3];
    const fcs_len = fcs_lens[fhd >> 6];
    const off = 5 + did_len;
    if (head.len < off + fcs_len) return error.Truncated;
    const f = head[off..][0..fcs_len];
    return switch (fcs_len) {
        1 => f[0],
        2 => @as(u64, std.mem.readInt(u16, f[0..2], .little)) + 256,
        4 => std.mem.readInt(u32, f[0..4], .little),
        else => std.mem.readInt(u64, f[0..8], .little),
    };
}

/// Window length to configure and the buffer size it needs.
/// The buffer is twice the window plus one block. std's decoder keeps the whole window in its
/// buffer and slides it with a memmove whenever the buffer fills; with only one block of slack
/// that is a window-sized copy per 128 KiB block (E7 measured 12 MB/s), with a window of slack
/// it is one copy per window of output.
pub fn sizing(window: u64) struct { window_len: u32, buffer_len: usize } {
    const w: u32 = @intCast(@max(window, floor_window));
    return .{ .window_len = w, .buffer_len = 2 * @as(usize, w) + zstd.block_size_max };
}

const fixtures = @import("fixtures/fixtures.zig");

test "decodes reference zstd streams; oversized windows are refused" {
    const gpa = std.testing.allocator;
    const cap: u64 = 8 << 20;
    for (fixtures.zstd_vectors) |v| {
        const win = try frameWindow(v.compressed, cap);
        if (std.mem.eql(u8, v.name, "window-128m")) {
            try std.testing.expect(win > cap);
            continue;
        }
        try std.testing.expect(win <= cap);
        const s = sizing(win);
        const buffer = try gpa.alloc(u8, s.buffer_len);
        defer gpa.free(buffer);
        var in: Io.Reader = .fixed(v.compressed);
        var d = zstd.Decompress.init(&in, buffer, .{ .window_len = s.window_len });
        var crc = std.hash.Crc32.init();
        var total: usize = 0;
        while (true) {
            const chunk = d.reader.peekGreedy(1) catch |e| switch (e) {
                error.EndOfStream => break,
                error.ReadFailed => return d.err.?,
            };
            crc.update(chunk);
            total += chunk.len;
            d.reader.toss(chunk.len);
        }
        try std.testing.expectEqual(v.plain_len, total);
        try std.testing.expectEqual(v.plain_crc, crc.final());
    }
}
