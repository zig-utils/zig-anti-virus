//! gzip (RFC 1952) over std.compress.flate, including multi-member streams: when one member
//! ends and the next bytes are another gzip header, decoding continues with a fresh inflater over
//! the same 64 KiB window. Anything else after a member is trailing data, left for the parent.
//! std's inflater does not verify the CRC-32 trailer; neither do we (a scanner reads damaged
//! data anyway).
const std = @import("std");
const Io = std.Io;
const flate = std.compress.flate;
const container = @import("../engine/container.zig");

/// The inflater's window buffer: at least flate.max_window_len. Twice that gives 64 KiB of new
/// output per refill instead of 32 KiB.
pub const window_len = 2 * flate.max_window_len;

pub const Decoder = struct {
    in: *Io.Reader,
    inflate: flate.Decompress,
    window: []u8,
    members: u32 = 0,
    err: ?flate.Decompress.Error = null,
    interface: Io.Reader,

    /// `window` must hold at least `window_len` bytes. Fill the result in place (`d.* = init()`)
    /// before reading: the reader is found by its address.
    pub fn init(in: *Io.Reader, window: []u8) Decoder {
        return .{
            .in = in,
            .inflate = .init(in, .gzip, window),
            .window = window,
            .interface = .{ .vtable = container.fillVTable(Decoder), .buffer = &.{}, .seek = 0, .end = 0 },
        };
    }

    pub fn fill(d: *Decoder, dest: []u8) Io.Reader.Error!usize {
        while (true) {
            return container.readSome(&d.inflate.reader, dest) catch |e| switch (e) {
                error.EndOfStream => {
                    d.members += 1;
                    const next = d.in.peek(3) catch return 0;
                    if (!(next[0] == 0x1f and next[1] == 0x8b and next[2] == 8)) return 0;
                    d.inflate = .init(d.in, .gzip, d.window);
                    continue;
                },
                error.ReadFailed => {
                    d.err = d.inflate.err;
                    return error.ReadFailed;
                },
            };
        }
    }
};

const fixtures = @import("fixtures/fixtures.zig");

test "decodes reference gzip streams, multi-member included" {
    const gpa = std.testing.allocator;
    const window = try gpa.alloc(u8, window_len);
    defer gpa.free(window);
    for (fixtures.gzip_vectors) |v| {
        var in: Io.Reader = .fixed(v.compressed);
        var d = Decoder.init(&in, window);
        var crc = std.hash.Crc32.init();
        var total: usize = 0;
        var buf: [7000]u8 = undefined;
        while (true) {
            const n = container.readSome(&d.interface, &buf) catch |e| switch (e) {
                error.EndOfStream => break,
                error.ReadFailed => return d.err.?,
            };
            crc.update(buf[0..n]);
            total += n;
        }
        try std.testing.expectEqual(v.plain_len, total);
        try std.testing.expectEqual(v.plain_crc, crc.final());
    }
}
