//! Bounded signed source pack. Never extracts archive paths to the filesystem.
//! All integers are little endian; signature covers every byte preceding the 64-byte footer.
const std = @import("std");
const format = @import("../../db/format.zig");
pub const TrustedKey = @import("../../db/reader.zig").TrustedKey;
const Ed25519 = std.crypto.sign.Ed25519;
pub const max_bytes = 16 * 1024 * 1024;
pub const max_entries = 1024;
pub const max_rule_bytes = 256 * 1024;
pub const max_meta_bytes = 16 * 1024;
pub const Entry = struct { path: []const u8, bytes: []const u8 };
pub const Pack = struct { version: u64, entries: []const Entry };
const magic = "ZAVRULE\n";
pub const Header = extern struct {
    magic: [8]u8,
    format_version: u32,
    entry_count: u32,
    source_version: u64,
    total_size: u64,
    key_id: [8]u8,
};
pub const FileRecord = extern struct {
    path_len: u16,
    reserved: u16 = 0,
    content_len: u32,
};
comptime {
    std.debug.assert(@sizeOf(Header) == 40 and @alignOf(Header) == 8);
    std.debug.assert(@sizeOf(FileRecord) == 8 and @alignOf(FileRecord) == 4);
}
const header_size = @sizeOf(Header);
const record_size = @sizeOf(FileRecord);

fn component(s: []const u8) bool {
    if (s.len == 0 or s.len > 80) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    return true;
}

pub fn validPath(path: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, path, '/') orelse return false;
    if (!component(path[0..slash])) return false;
    const file = path[slash + 1 ..];
    return std.mem.eql(u8, file, "meta.toml") or (std.mem.endsWith(u8, file, ".yar") and component(file[0 .. file.len - 4]));
}

pub fn validateEntries(entries: []const Entry) !void {
    if (entries.len == 0 or entries.len > max_entries) return error.PackLimit;
    var total: usize = header_size + 64;
    for (entries, 0..) |e, i| {
        if (!validPath(e.path)) return error.InvalidPackPath;
        const limit: usize = if (std.mem.endsWith(u8, e.path, "/meta.toml")) max_meta_bytes else max_rule_bytes;
        if (e.bytes.len == 0 or e.bytes.len > limit) return error.PackLimit;
        total += record_size + e.path.len + e.bytes.len;
        if (total > max_bytes) return error.PackLimit;
        for (entries[0..i]) |prior| if (std.mem.eql(u8, e.path, prior.path)) return error.DuplicatePackPath;
    }
}

/// Return owned bundle bytes. Production signing keys are provided by the distributor.
pub fn encode(gpa: std.mem.Allocator, pack: Pack, kp: Ed25519.KeyPair) ![]u8 {
    try validateEntries(pack.entries);
    if (pack.version == 0 or pack.version > std.math.maxInt(u32)) return error.InvalidPackVersion;
    var n: usize = header_size + 64;
    for (pack.entries) |e| n += record_size + e.path.len + e.bytes.len;
    const bytes = try gpa.alloc(u8, n);
    errdefer gpa.free(bytes);
    @memcpy(bytes[0..8], magic);
    std.mem.writeInt(u32, bytes[8..12], 1, .little);
    std.mem.writeInt(u32, bytes[12..16], @intCast(pack.entries.len), .little);
    std.mem.writeInt(u64, bytes[16..24], pack.version, .little);
    std.mem.writeInt(u64, bytes[24..32], n, .little);
    @memcpy(bytes[32..40], &format.keyId(kp.public_key.toBytes()));
    var at: usize = header_size;
    for (pack.entries) |e| {
        std.mem.writeInt(u16, bytes[at..][0..2], @intCast(e.path.len), .little);
        std.mem.writeInt(u16, bytes[at + 2 ..][0..2], 0, .little);
        std.mem.writeInt(u32, bytes[at + 4 ..][0..4], @intCast(e.bytes.len), .little);
        at += record_size;
        @memcpy(bytes[at..][0..e.path.len], e.path);
        at += e.path.len;
        @memcpy(bytes[at..][0..e.bytes.len], e.bytes);
        at += e.bytes.len;
    }
    const sig = try kp.sign(bytes[0..at], null);
    @memcpy(bytes[at..][0..64], &sig.toBytes());
    return bytes;
}

/// Verify before reading any source records. Entries borrow bytes; array belongs to arena.
/// No embedded public key, unsigned mode, extraction, or implicit trust.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8, trusted: []const TrustedKey) !Pack {
    if (bytes.len > max_bytes) return error.PackLimit;
    if (bytes.len < header_size + 64 or !std.mem.eql(u8, bytes[0..8], magic)) return error.InvalidPack;
    if (std.mem.readInt(u32, bytes[8..12], .little) != 1) return error.InvalidPack;
    if (std.mem.readInt(u64, bytes[24..32], .little) != bytes.len) return error.InvalidPack;
    const count = std.mem.readInt(u32, bytes[12..16], .little);
    if (count == 0 or count > max_entries) return error.PackLimit;
    const version = std.mem.readInt(u64, bytes[16..24], .little);
    if (version == 0 or version > std.math.maxInt(u32)) return error.InvalidPackVersion;
    const key = for (trusted) |k| {
        if (std.mem.eql(u8, bytes[32..40], &format.keyId(k.public_key))) break k;
    } else return error.UnknownKey;
    const pk = Ed25519.PublicKey.fromBytes(key.public_key) catch return error.UnknownKey;
    const end = bytes.len - 64;
    const sig = Ed25519.Signature.fromBytes(bytes[end..][0..64].*);
    sig.verify(bytes[0..end], pk) catch return error.BadSignature;
    const entries = try arena.alloc(Entry, count);
    var at: usize = header_size;
    for (entries) |*e| {
        if (end - at < record_size) return error.InvalidPack;
        const plen = std.mem.readInt(u16, bytes[at..][0..2], .little);
        if (std.mem.readInt(u16, bytes[at + 2 ..][0..2], .little) != 0) return error.InvalidPack;
        const len = std.mem.readInt(u32, bytes[at + 4 ..][0..4], .little);
        at += record_size;
        if (plen > end - at) return error.InvalidPack;
        const path = bytes[at..][0..plen];
        at += plen;
        if (len > end - at) return error.InvalidPack;
        e.* = .{ .path = path, .bytes = bytes[at..][0..len] };
        at += len;
    }
    if (at != end) return error.InvalidPack;
    try validateEntries(entries);
    return .{ .version = version, .entries = entries };
}

test "Guardian bundle requires explicit trust and rejects tampered header payload and signature" {
    const a = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(0x42));
    const other = try Ed25519.KeyPair.generateDeterministic(@splat(0x43));
    const entries = [_]Entry{.{ .path = "php/test.yar", .bytes = "rule Test { strings: $a = \"zz\" condition: $a }" }};
    const bytes = try encode(a, .{ .version = 7, .entries = &entries }, kp);
    defer a.free(bytes);
    try std.testing.expectError(error.UnknownKey, decode(arena.allocator(), bytes, &.{}));
    try std.testing.expectError(error.UnknownKey, decode(arena.allocator(), bytes, &.{.{ .public_key = other.public_key.toBytes() }}));
    const trusted = [_]TrustedKey{.{ .public_key = kp.public_key.toBytes() }};
    const pack = try decode(arena.allocator(), bytes, &trusted);
    try std.testing.expectEqual(@as(u64, 7), pack.version);
    try std.testing.expectEqualStrings(entries[0].bytes, pack.entries[0].bytes);
    for ([_]usize{ 16, header_size + 12, bytes.len - 1 }) |offset| {
        bytes[offset] ^= 1;
        try std.testing.expectError(error.BadSignature, decode(arena.allocator(), bytes, &trusted));
        bytes[offset] ^= 1;
    }
    try std.testing.expectError(error.InvalidPack, decode(arena.allocator(), bytes[0 .. bytes.len - 1], &trusted));
}

test "Guardian bundle paths duplicates and sizes are bounded before signing" {
    for ([_][]const u8{ "../meta.toml", "/a/meta.toml", "a/../../x.yar", "a/b/c.yar", "a/../x.yar", "a\\x.yar", "a/.yar", "a/..yar" }) |path| {
        try std.testing.expectError(error.InvalidPackPath, validateEntries(&.{.{ .path = path, .bytes = "x" }}));
    }
    const e: Entry = .{ .path = "php/x.yar", .bytes = "x" };
    try std.testing.expectError(error.DuplicatePackPath, validateEntries(&.{ e, e }));
    const large = try std.testing.allocator.alloc(u8, max_rule_bytes + 1);
    defer std.testing.allocator.free(large);
    try std.testing.expectError(error.PackLimit, validateEntries(&.{.{ .path = e.path, .bytes = large }}));
}

test "Guardian authenticated hostile bundle still rejects traversal duplicates and malformed lengths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(0x42));
    const keys = [_]TrustedKey{.{ .public_key = kp.public_key.toBytes() }};
    const bytes = try encode(a, .{ .version = 1, .entries = &.{
        .{ .path = "php/x.yar", .bytes = "x" },
        .{ .path = "php/y.yar", .bytes = "y" },
    } }, kp);
    const path_at = header_size + record_size;
    @memcpy(bytes[path_at..][0..9], "../xx.yar");
    var sig = try kp.sign(bytes[0 .. bytes.len - 64], null);
    @memcpy(bytes[bytes.len - 64 ..], &sig.toBytes());
    try std.testing.expectError(error.InvalidPackPath, decode(a, bytes, &keys));
    @memcpy(bytes[path_at..][0..9], "php/y.yar");
    sig = try kp.sign(bytes[0 .. bytes.len - 64], null);
    @memcpy(bytes[bytes.len - 64 ..], &sig.toBytes());
    try std.testing.expectError(error.DuplicatePackPath, decode(a, bytes, &keys));
    std.mem.writeInt(u32, bytes[header_size + 4 ..][0..4], std.math.maxInt(u32), .little);
    sig = try kp.sign(bytes[0 .. bytes.len - 64], null);
    @memcpy(bytes[bytes.len - 64 ..], &sig.toBytes());
    try std.testing.expectError(error.InvalidPack, decode(a, bytes, &keys));
    std.mem.writeInt(u32, bytes[12..16], max_entries + 1, .little);
    try std.testing.expectError(error.PackLimit, decode(a, bytes, &keys));
}
