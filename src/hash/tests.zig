//! Digest correctness for every kernel variant the running CPU can execute: published test vectors
//! (RFC 1321, FIPS 180-2 examples), odd lengths and split updates against std.crypto, and the
//! fused and speculative behaviour of Multihash. Variants the CPU lacks are skipped, never faked.
const std = @import("std");
const arch = @import("../simd/arch.zig");
const dispatch = @import("dispatch.zig");
const hasher = @import("hasher.zig");
const multihash = @import("multihash.zig");

const Md5Std = std.crypto.hash.Md5;
const Sha1Std = std.crypto.hash.Sha1;
const Sha256Std = std.crypto.hash.sha2.Sha256;

const Vector = struct { input: []const u8, repeat: usize = 1, md5: ?[]const u8 = null, sha1: ?[]const u8 = null, sha256: ?[]const u8 = null };

const vectors = [_]Vector{
    .{
        .input = "",
        .md5 = "d41d8cd98f00b204e9800998ecf8427e",
        .sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .input = "abc",
        .md5 = "900150983cd24fb0d6963f7d28e17f72",
        .sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d",
        .sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    .{ .input = "message digest", .md5 = "f96b697d7cb7938d525a2f31aaf161d0" },
    .{ .input = "abcdefghijklmnopqrstuvwxyz", .md5 = "c3fcd3d76192e4007dfb496cca67e13b" },
    .{
        .input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        .md5 = "57edf4a22be3c955ac49da2e2107b67a",
    },
    .{
        .input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        .sha1 = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        .sha256 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    },
    .{
        .input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        .sha1 = "a49b2446a02c645bf419f995b67091253a04a259",
        .sha256 = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    },
    .{
        .input = "a",
        .repeat = 1_000_000,
        .md5 = "7707d6ae4e027c70eea2a935c2296f21",
        .sha1 = "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
        .sha256 = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    },
};

/// Every kernel set this CPU can run: the linked variants it supports, plus the portable kernels.
fn runnable(buf: *[8]*const dispatch.Kernels) []const *const dispatch.Kernels {
    const features = arch.detect();
    var n: usize = 0;
    for (dispatch.all) |*k| if (dispatch.supports(features, k.requires)) {
        buf[n] = k;
        n += 1;
    };
    if (dispatch.all[0].md5 != dispatch.portable.md5) {
        buf[n] = &dispatch.portable;
        n += 1;
    }
    return buf[0..n];
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var hex: [64]u8 = undefined;
    const got = std.fmt.bufPrint(&hex, "{x}", .{actual}) catch unreachable;
    try std.testing.expectEqualStrings(expected, got);
}

fn digestOf(comptime algo: hasher.Algo, k: *const dispatch.Kernels, v: Vector) [algo.digestLength()]u8 {
    var h = hasher.Hasher(algo).initWith(k);
    for (0..v.repeat) |_| h.update(v.input);
    return h.finalResult();
}

test "published vectors on every runnable variant" {
    var buf: [8]*const dispatch.Kernels = undefined;
    for (runnable(&buf)) |k| {
        for (vectors) |v| {
            if (v.md5) |hex| try expectHex(hex, &digestOf(.md5, k, v));
            if (v.sha1) |hex| try expectHex(hex, &digestOf(.sha1, k, v));
            if (v.sha256) |hex| try expectHex(hex, &digestOf(.sha256, k, v));
        }
    }
}

fn checkAgainstStd(k: *const dispatch.Kernels, data: []const u8, splits: []const usize) !void {
    var md5 = hasher.Md5.initWith(k);
    var sha1 = hasher.Sha1.initWith(k);
    var sha256 = hasher.Sha256.initWith(k);
    var off: usize = 0;
    for (splits) |cut| {
        const end = @min(data.len, off + cut);
        md5.update(data[off..end]);
        sha1.update(data[off..end]);
        sha256.update(data[off..end]);
        off = end;
    }
    md5.update(data[off..]);
    sha1.update(data[off..]);
    sha256.update(data[off..]);

    var want_md5: [16]u8 = undefined;
    var want_sha1: [20]u8 = undefined;
    var want_sha256: [32]u8 = undefined;
    Md5Std.hash(data, &want_md5, .{});
    Sha1Std.hash(data, &want_sha1, .{});
    Sha256Std.hash(data, &want_sha256, .{});
    try std.testing.expectEqualSlices(u8, &want_md5, &md5.finalResult());
    try std.testing.expectEqualSlices(u8, &want_sha1, &sha1.finalResult());
    try std.testing.expectEqualSlices(u8, &want_sha256, &sha256.finalResult());
}

test "odd lengths and split updates match std on every runnable variant" {
    const gpa = std.testing.allocator;
    const data = try gpa.alloc(u8, 70_000);
    defer gpa.free(data);
    var prng = std.Random.DefaultPrng.init(0x8a5e_0001);
    prng.random().bytes(data);

    var buf: [8]*const dispatch.Kernels = undefined;
    for (runnable(&buf)) |k| {
        // Every length across the padding boundaries of the first few blocks, in one update.
        for (0..300) |len| try checkAgainstStd(k, data[0..len], &.{});
        for ([_]usize{ 4095, 4096, 4097, 16383, 16384, 16385, 65535, 65537, 70_000 }) |len|
            try checkAgainstStd(k, data[0..len], &.{});
        // Multi-call updates: byte at a time, odd strides, and block-straddling cuts.
        const ones: [200]usize = @splat(1);
        try checkAgainstStd(k, data[0..200], &ones);
        try checkAgainstStd(k, data[0..1000], &.{ 3, 61, 1, 64, 127, 0, 65, 200 });
        try checkAgainstStd(k, data[0..70_000], &.{ 63, 16_384, 1, 40_000 });
    }
}

test "Multihash computes any subset in one pass" {
    const gpa = std.testing.allocator;
    const data = try gpa.alloc(u8, 3 * multihash.Multihash.sub_block_len + 777);
    defer gpa.free(data);
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(data);

    var want_md5: [16]u8 = undefined;
    var want_sha1: [20]u8 = undefined;
    var want_sha256: [32]u8 = undefined;
    Md5Std.hash(data, &want_md5, .{});
    Sha1Std.hash(data, &want_sha1, .{});
    Sha256Std.hash(data, &want_sha256, .{});

    var buf: [8]*const dispatch.Kernels = undefined;
    for (runnable(&buf)) |k| {
        for (0..8) |bits| {
            var algos: multihash.Set = .empty;
            if (bits & 1 != 0) algos.insert(.md5);
            if (bits & 2 != 0) algos.insert(.sha1);
            if (bits & 4 != 0) algos.insert(.sha256);
            var m = multihash.Multihash.init(algos, .{ .kernels = k });
            m.update(data[0..10]);
            m.update(data[10..20_000]);
            m.update(data[20_000..]);
            const d = m.final();
            try std.testing.expect(d.computed.eql(algos));
            try std.testing.expect(d.dropped.eql(.empty));
            try std.testing.expectEqual(@as(u64, data.len), d.len);
            if (algos.contains(.md5)) try std.testing.expectEqualSlices(u8, &want_md5, &d.md5);
            if (algos.contains(.sha1)) try std.testing.expectEqualSlices(u8, &want_sha1, &d.sha1);
            if (algos.contains(.sha256)) try std.testing.expectEqualSlices(u8, &want_sha256, &d.sha256);
        }
    }
}

test "speculative Multihash drops a hasher once the stream passes its limit" {
    var data: [100]u8 = undefined;
    for (&data, 0..) |*c, i| c.* = '0' + @as(u8, @intCast(i % 10));
    var m = multihash.Multihash.init(.full, .{ .limits = .{ .md5 = 50, .sha1 = 100 } });
    m.update(data[0..50]);
    try std.testing.expect(m.running.eql(.full));
    m.update(data[50..51]);
    try std.testing.expect(!m.running.contains(.md5));
    m.update(data[51..]);
    const d = m.final();
    try std.testing.expect(d.dropped.eql(.initOne(.md5)));
    try std.testing.expect(d.computed.eql(.initMany(&.{ .sha1, .sha256 })));
    // A stream ending exactly at its limit is still hashed.
    var want: [20]u8 = undefined;
    Sha1Std.hash(&data, &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &d.sha1);

    // Dropping every hasher leaves nothing running.
    var tiny = multihash.Multihash.init(.initOne(.sha256), .{ .limits = .{ .sha256 = 0 } });
    tiny.update("x");
    try std.testing.expect(!tiny.active());
    try std.testing.expect(tiny.final().computed.eql(.empty));
}

test "one-shot digests use the active variant" {
    var want: [32]u8 = undefined;
    Sha256Std.hash("abc", &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &hasher.Sha256.hash("abc"));
}
