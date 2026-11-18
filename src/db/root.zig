//! Compiled signature database (.zavdb): on-disk layout, raw read-only mmap loader, verification.
//! See docs/DESIGN.md section 3.
const std = @import("std");

pub const format = @import("format.zig");
pub const writer = @import("writer.zig");
pub const reader = @import("reader.zig");

const Ed25519 = std.crypto.sign.Ed25519;

test {
    _ = format;
    _ = writer;
    _ = reader;
}

fn testKeyPair() !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic(@splat(7));
}

const test_sections = [_]writer.Section{
    .{ .kind = .hash_need_map, .hot = true, .bytes = "need-map" },
    .{ .kind = .prefilter, .variant = 1, .hot = true, .bytes = "prefilter for PE" },
    .{ .kind = .name_pool, .bytes = "Eicar-Test-Signature" },
    .{ .kind = .coverage_report, .bytes = "coverage: all supported" },
};

test "the hot region starts on a 2 MiB boundary and cold sections follow" {
    var layout = try writer.plan(&test_sections, .{ .db_version = 3, .key_pair = try testKeyPair() });
    try std.testing.expectEqual(format.hot_alignment, layout.offsets[0]);
    try std.testing.expect(layout.offsets[1] > layout.offsets[0] and layout.offsets[1] % 4096 == 0);
    try std.testing.expect(layout.offsets[2] > layout.offsets[1]);
    try std.testing.expectEqual(@as(u32, 4), layout.header().section_count);
}

test "write, open, read sections, and verify once" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const kp = try testKeyPair();
    try writer.write(io, tmp.dir, "test.zavdb", &test_sections, .{ .db_version = 9, .key_pair = kp });

    const trusted = [_]reader.TrustedKey{.{ .public_key = kp.public_key.toBytes() }};
    const db = try reader.open(io, tmp.dir, "test.zavdb", .{ .trusted_keys = &trusted });
    defer db.close();
    try std.testing.expectEqual(@as(u64, 9), db.header().db_version);
    try std.testing.expectEqualStrings("prefilter for PE", db.section(.prefilter, 1).?);
    try std.testing.expectEqualStrings("Eicar-Test-Signature", db.section(.name_pool, 0).?);
    try std.testing.expect(db.section(.prefilter, 2) == null);

    try std.testing.expect(try reader.verifyOnce(io, tmp.dir, "test.zavdb", db)); // full check ran
    try std.testing.expect(!try reader.verifyOnce(io, tmp.dir, "test.zavdb", db)); // sidecar vouched
}

test "unsigned and unknown-key databases are refused" {
    var layout = try writer.plan(&test_sections, .{ .db_version = 1 });
    const image = try buildImage(std.testing.allocator, &test_sections, &layout);
    defer std.testing.allocator.free(image);
    try std.testing.expectError(error.Unsigned, reader.validate(image, .{}));
    try reader.validate(image, .{ .allow_unsigned = true });

    var signed = try writer.plan(&test_sections, .{ .db_version = 1, .key_pair = try testKeyPair() });
    const signed_image = try buildImage(std.testing.allocator, &test_sections, &signed);
    defer std.testing.allocator.free(signed_image);
    try std.testing.expectError(error.UnknownKey, reader.validate(signed_image, .{}));
}

test "every flipped byte is caught by the check that owns it" {
    const kp = try testKeyPair();
    var layout = try writer.plan(&test_sections, .{ .db_version = 2, .key_pair = kp });
    const image = try buildImage(std.testing.allocator, &test_sections, &layout);
    defer std.testing.allocator.free(image);
    const trusted = [_]reader.TrustedKey{.{ .public_key = kp.public_key.toBytes() }};
    try reader.validate(image, .{ .trusted_keys = &trusted });
    try reader.verifyBody(image);

    // Header fields and the signed region: the signature check (or an earlier structural check).
    var i: usize = 0;
    while (i < format.signed_len) : (i += 7) {
        image[i] ^= 0x10;
        try std.testing.expect(std.meta.isError(reader.validate(image, .{ .trusted_keys = &trusted })));
        image[i] ^= 0x10;
    }
    // The signature itself.
    image[format.signed_len] ^= 1;
    try std.testing.expectError(error.BadSignature, reader.validate(image, .{ .trusted_keys = &trusted }));
    image[format.signed_len] ^= 1;
    // The section table: its hash is signed.
    image[format.section_table_offset + 8] ^= 1;
    try std.testing.expectError(error.BadSectionTable, reader.validate(image, .{ .trusted_keys = &trusted }));
    image[format.section_table_offset + 8] ^= 1;
    // Body bytes: caught by the install-time check, in sections and in padding alike.
    for ([_]u64{ layout.offsets[0], layout.offsets[3] + 3, format.header_size + 100 }) |at| {
        image[at] ^= 1;
        try std.testing.expectError(error.RootMismatch, reader.verifyBody(image));
        image[at] ^= 1;
    }
}

/// The file image `writer.write` would produce, in memory.
fn buildImage(gpa: std.mem.Allocator, sections: []const writer.Section, layout: *writer.Layout) ![]align(8) u8 {
    const image = try gpa.alignedAlloc(u8, .@"8", @intCast(layout.total_size));
    @memset(image, 0);
    @memcpy(image[0..format.header_size], &layout.block);
    for (sections, 0..) |s, i| @memcpy(image[layout.offsets[i]..][0..s.bytes.len], s.bytes);
    return image;
}
