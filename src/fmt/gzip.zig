//! gzip (RFC 1952) over our inflater (inflate.zig), including multi-member streams: when one
//! member ends and the next bytes are another gzip header, decoding continues with the inflater
//! reset over the same memory. Anything else after a member is trailing data, left for the
//! parent. The CRC-32 trailer is skipped, not verified (a scanner reads damaged data anyway).
const std = @import("std");
const Io = std.Io;
const inflate = @import("inflate.zig");
const container = @import("../engine/container.zig");

/// Caller memory a decoder needs: the inflater's output buffer and tables.
pub const window_len = inflate.work_len;

pub const Decoder = struct {
    in: *Io.Reader,
    inflate: inflate.Inflate,
    members: u32 = 0,
    err: ?inflate.Error = null,
    interface: Io.Reader,

    /// `window` must hold at least `window_len` bytes. Fill the result in place (`d.* = init()`)
    /// before reading: the reader is found by its address.
    pub fn init(in: *Io.Reader, window: []u8) Decoder {
        return .{
            .in = in,
            .inflate = .init(in, .gzip, window),
            .interface = .{ .vtable = container.fillVTable(Decoder), .buffer = &.{}, .seek = 0, .end = 0 },
        };
    }

    pub fn fill(d: *Decoder, dest: []u8) Io.Reader.Error!usize {
        while (true) {
            const n = d.inflate.fill(dest) catch {
                d.err = d.inflate.err;
                return error.ReadFailed;
            };
            if (n != 0) return n;
            d.members += 1;
            const next = d.in.peek(3) catch return 0;
            if (!(next[0] == 0x1f and next[1] == 0x8b and next[2] == 8)) return 0;
            d.inflate.reset();
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
