//! Streaming MD5, SHA-1 and SHA-256 over a variant's block kernels: buffering, padding and the
//! length trailer live here, compiled once; only the compression function is per variant.
const std = @import("std");
const dispatch = @import("dispatch.zig");

pub const Algo = enum(u2) {
    md5,
    sha1,
    sha256,

    pub fn digestLength(algo: Algo) usize {
        return switch (algo) {
            .md5 => 16,
            .sha1 => 20,
            .sha256 => 32,
        };
    }
};

pub fn Hasher(comptime algo: Algo) type {
    return struct {
        const Self = @This();

        pub const block_length = 64;
        pub const digest_length = algo.digestLength();
        const State = [digest_length / 4]u32;
        const endian: std.builtin.Endian = if (algo == .md5) .little else .big;
        const iv: State = switch (algo) {
            .md5 => .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 },
            .sha1 => .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
            .sha256 => .{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 },
        };
        const BlocksFn = *const fn (*State, [*]const u8, usize) callconv(.c) void;

        s: State,
        buf: [block_length]u8 = undefined,
        buf_len: u8 = 0,
        total_len: u64 = 0,
        blocks: BlocksFn,

        /// A hasher on the best variant for this CPU.
        pub fn init() Self {
            return initWith(dispatch.active());
        }

        /// A hasher on a specific variant. The caller guarantees the CPU can run it.
        pub fn initWith(kernels: *const dispatch.Kernels) Self {
            return .{ .s = iv, .blocks = @field(kernels, @tagName(algo)) };
        }

        pub fn update(d: *Self, bytes: []const u8) void {
            var rest = bytes;
            d.total_len +%= bytes.len;
            if (d.buf_len != 0) {
                const take = @min(block_length - d.buf_len, rest.len);
                @memcpy(d.buf[d.buf_len..][0..take], rest[0..take]);
                d.buf_len += @intCast(take);
                rest = rest[take..];
                if (d.buf_len < block_length) return;
                d.blocks(&d.s, &d.buf, 1);
                d.buf_len = 0;
            }
            const n = rest.len / block_length;
            if (n != 0) d.blocks(&d.s, rest.ptr, n);
            const tail = rest[n * block_length ..];
            @memcpy(d.buf[0..tail.len], tail);
            d.buf_len = @intCast(tail.len);
        }

        pub fn final(d: *Self, out: *[digest_length]u8) void {
            var block: [block_length]u8 = d.buf;
            @memset(block[d.buf_len..], 0);
            block[d.buf_len] = 0x80;
            if (d.buf_len >= block_length - 8) {
                d.blocks(&d.s, &block, 1);
                @memset(&block, 0);
            }
            std.mem.writeInt(u64, block[block_length - 8 ..], d.total_len *% 8, endian);
            d.blocks(&d.s, &block, 1);
            for (d.s, 0..) |word, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], word, endian);
        }

        pub fn finalResult(d: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            d.final(&out);
            return out;
        }

        /// One-shot digest on the best variant for this CPU.
        pub fn hash(bytes: []const u8) [digest_length]u8 {
            var d = init();
            d.update(bytes);
            return d.finalResult();
        }
    };
}

pub const Md5 = Hasher(.md5);
pub const Sha1 = Hasher(.sha1);
pub const Sha256 = Hasher(.sha256);
