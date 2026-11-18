//! File digest cache keyed by (device, inode) and validated by size, mtime and ctime, so a deep
//! scan does not hash an unchanged file twice. ctime is in the key because it changes on every
//! metadata or content change and cannot be set from userspace, unlike mtime.
//!
//! On disk: a 16-byte header (`ZAVFC\0\r\n`, version, count) and fixed 112-byte records. A file
//! that fails any check is ignored and rebuilt, never trusted partially.
const std = @import("std");
const sys = @import("sys.zig");
const Host = @import("host.zig").Host;

pub const Algo = enum(u8) { md5 = 1, sha1 = 2, sha256 = 3, sha384 = 4, sha512 = 5 };

pub const magic = "ZAVFC\x00\r\n".*;
pub const version: u32 = 1;
pub const max_records = 4 * 1024 * 1024;

pub const Record = extern struct {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
    algo: u8,
    len: u8,
    _pad: [6]u8 = @splat(0),
    digest: [64]u8,
};

comptime {
    std.debug.assert(@sizeOf(Record) == 112);
}

const Key = struct { dev: u64, ino: u64, algo: u8 };

pub const Cache = struct {
    gpa: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged(Key, Record) = .empty,
    hits: u64 = 0,
    misses: u64 = 0,
    dirty: bool = false,

    pub fn init(gpa: std.mem.Allocator) Cache {
        return .{ .gpa = gpa };
    }

    pub fn deinit(c: *Cache) void {
        c.map.deinit(c.gpa);
    }

    fn clampNs(ns: i128) i64 {
        return @intCast(std.math.clamp(ns, std.math.minInt(i64), std.math.maxInt(i64)));
    }

    pub fn lookup(c: *Cache, st: sys.Stat, algo: Algo) ?[]const u8 {
        const r = c.map.getPtr(.{ .dev = st.dev, .ino = st.ino, .algo = @backingInt(algo) }) orelse {
            c.misses += 1;
            return null;
        };
        if (r.size != st.size or r.mtime_ns != clampNs(st.mtime_ns) or r.ctime_ns != clampNs(st.ctime_ns)) {
            c.misses += 1;
            return null;
        }
        c.hits += 1;
        return r.digest[0..r.len];
    }

    pub fn store(c: *Cache, st: sys.Stat, algo: Algo, digest: []const u8) !void {
        if (digest.len > 64) return;
        var r: Record = .{ .dev = st.dev, .ino = st.ino, .size = st.size, .mtime_ns = clampNs(st.mtime_ns), .ctime_ns = clampNs(st.ctime_ns), .algo = @backingInt(algo), .len = @intCast(digest.len), .digest = @splat(0) };
        @memcpy(r.digest[0..digest.len], digest);
        try c.map.put(c.gpa, .{ .dev = st.dev, .ino = st.ino, .algo = r.algo }, r);
        c.dirty = true;
    }

    /// Load a cache file; a missing or malformed file leaves the cache empty.
    pub fn load(c: *Cache, io: std.Io, dir: std.Io.Dir, name: []const u8) !void {
        const bytes = dir.readFileAlloc(io, name, c.gpa, .limited(16 + max_records * @sizeOf(Record))) catch return;
        defer c.gpa.free(bytes);
        try c.loadBytes(bytes);
    }

    pub fn loadBytes(c: *Cache, bytes: []const u8) !void {
        if (bytes.len < 16 or !std.mem.eql(u8, bytes[0..8], &magic)) return;
        if (std.mem.readInt(u32, bytes[8..12], .little) != version) return;
        const count = std.mem.readInt(u32, bytes[12..16], .little);
        if (count > max_records or 16 + @as(usize, count) * @sizeOf(Record) != bytes.len) return;
        try c.map.ensureTotalCapacity(c.gpa, count);
        for (0..count) |i| {
            var r: Record = undefined;
            @memcpy(std.mem.asBytes(&r), bytes[16 + i * @sizeOf(Record) ..][0..@sizeOf(Record)]);
            if (r.len > 64 or r.algo == 0 or r.algo > 5) continue;
            c.map.putAssumeCapacity(.{ .dev = r.dev, .ino = r.ino, .algo = r.algo }, r);
        }
    }

    /// Write the cache atomically (temp file and rename).
    pub fn save(c: *Cache, io: std.Io, dir: std.Io.Dir, name: []const u8) !void {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(c.gpa);
        try c.serialize(&buf);
        var tmp_name_buf: [256]u8 = undefined;
        const tmp_name = try std.fmt.bufPrint(&tmp_name_buf, "{s}.tmp", .{name});
        try dir.writeFile(io, .{ .sub_path = tmp_name, .data = buf.items });
        try dir.rename(tmp_name, dir, name, io);
        c.dirty = false;
    }

    pub fn serialize(c: *Cache, out: *std.ArrayList(u8)) !void {
        const count: u32 = @intCast(@min(c.map.count(), max_records));
        try out.appendSlice(c.gpa, &magic);
        try out.appendSlice(c.gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, version)));
        try out.appendSlice(c.gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, count)));
        var it = c.map.valueIterator();
        var n: u32 = 0;
        while (it.next()) |r| : (n += 1) {
            if (n == count) break;
            try out.appendSlice(c.gpa, std.mem.asBytes(r));
        }
    }
};

pub fn digestLen(algo: Algo) usize {
    return switch (algo) {
        .md5 => 16,
        .sha1 => 20,
        .sha256 => 32,
        .sha384 => 48,
        .sha512 => 64,
    };
}

/// Hash a file under the host root with `algo`, through the cache when given. Returns the digest
/// in `out` and whether it came from the cache.
pub fn digestFile(h: Host, path: []const u8, algo: Algo, cache: ?*Cache, out: *[64]u8) !struct { digest: []const u8, cached: bool, stat: sys.Stat } {
    const st = try h.stat(path, true);
    if (cache) |c| if (c.lookup(st, algo)) |d| {
        @memcpy(out[0..d.len], d);
        return .{ .digest = out[0..d.len], .cached = true, .stat = st };
    };
    var file = try h.root.openFile(h.io, Host.rel(path), .{});
    defer file.close(h.io);
    var read_buf: [64 * 1024]u8 = undefined;
    var reader = file.reader(h.io, &read_buf);
    const len = digestLen(algo);
    switch (algo) {
        inline else => |a| {
            const H = switch (a) {
                .md5 => std.crypto.hash.Md5,
                .sha1 => std.crypto.hash.Sha1,
                .sha256 => std.crypto.hash.sha2.Sha256,
                .sha384 => std.crypto.hash.sha2.Sha384,
                .sha512 => std.crypto.hash.sha2.Sha512,
            };
            var hasher = H.init(.{});
            while (true) {
                const chunk = reader.interface.peekGreedy(1) catch |e| switch (e) {
                    error.EndOfStream => break,
                    error.ReadFailed => return reader.err.?,
                };
                hasher.update(chunk);
                reader.interface.toss(chunk.len);
            }
            hasher.final(out[0..H.digest_length]);
        },
    }
    if (cache) |c| try c.store(st, algo, out[0..len]);
    return .{ .digest = out[0..len], .cached = false, .stat = st };
}

test "cache hits only while size, mtime and ctime are unchanged, and survives a round trip" {
    const gpa = std.testing.allocator;
    const Fixture = @import("host.zig").Fixture;
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/usr/bin/tool", "hello");
    const h = fx.host(.linux);
    var c = Cache.init(gpa);
    defer c.deinit();
    var out: [64]u8 = undefined;
    const first = try digestFile(h, "/usr/bin/tool", .sha256, &c, &out);
    try std.testing.expect(!first.cached);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hello", &want, .{});
    try std.testing.expectEqualSlices(u8, &want, first.digest);
    const second = try digestFile(h, "/usr/bin/tool", .sha256, &c, &out);
    try std.testing.expect(second.cached);
    try std.testing.expectEqual(@as(u64, 1), c.hits);

    // A different size invalidates.
    var st = second.stat;
    st.size += 1;
    try std.testing.expect(c.lookup(st, .sha256) == null);
    st = second.stat;
    st.ctime_ns += 1;
    try std.testing.expect(c.lookup(st, .sha256) == null);
    try std.testing.expect(c.lookup(second.stat, .md5) == null);

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try c.serialize(&bytes);
    var back = Cache.init(gpa);
    defer back.deinit();
    try back.loadBytes(bytes.items);
    try std.testing.expectEqualSlices(u8, &want, back.lookup(second.stat, .sha256).?);
    // Truncated or foreign files load as empty.
    var bad = Cache.init(gpa);
    defer bad.deinit();
    try bad.loadBytes(bytes.items[0 .. bytes.items.len - 1]);
    try std.testing.expectEqual(@as(u32, 0), bad.map.count());
}
