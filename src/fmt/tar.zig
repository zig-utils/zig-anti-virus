//! tar: v7, ustar (POSIX.1-1988), GNU (long names 'L'/'K', base-256 sizes, sparse 'S') and pax
//! (POSIX.1-2001 'x'/'g' extended headers: path, linkpath, size). Written against the POSIX
//! pax/ustar specification and the GNU tar manual's format chapter.
//!
//! Not std.tar: its iterator only exposes member contents as a stream, while over a positional
//! source every member here becomes a slice of the parent (no copy, and a zip inside a tar needs
//! no materialising). Header fields are untrusted: names are bounded and truncated, sizes are
//! checked against the archive, the header checksum must add up, extended headers are capped.
const std = @import("std");
const container = @import("../engine/container.zig");
const archive = @import("archive.zig");
const Walker = container.Walker;

/// Longest name kept (longer names are truncated for the container path; the member is still
/// scanned).
pub const max_name = 1024;
/// Largest pax or GNU long-name payload read; bigger ones are skipped and reported.
pub const max_extended = 64 * 1024;

pub const Error = container.Error;

const Header = struct {
    block: *const [512]u8,

    fn field(h: Header, off: usize, len: usize) []const u8 {
        return h.block[off..][0..len];
    }

    /// Octal, or GNU base-256 when the first byte has its high bit set.
    fn number(h: Header, off: usize, len: usize) ?u64 {
        const f = h.field(off, len);
        if (f[0] & 0x80 != 0) {
            if (f[0] & 0x40 != 0) return null; // negative
            var v: u64 = f[0] & 0x3f;
            for (f[1..]) |b| {
                if (v > (std.math.maxInt(u64) >> 8)) return null;
                v = (v << 8) | b;
            }
            return v;
        }
        var v: u64 = 0;
        var seen = false;
        for (f) |c| switch (c) {
            '0'...'7' => {
                if (v > (std.math.maxInt(u64) >> 3)) return null;
                v = v * 8 + (c - '0');
                seen = true;
            },
            ' ' => if (seen) break,
            0 => break,
            else => return null,
        };
        return v;
    }

    fn checksumOk(h: Header) bool {
        const stored = h.number(148, 8) orelse return false;
        var unsigned: u64 = 0;
        var signed: i64 = 0;
        for (h.block, 0..) |c, i| {
            const b: u8 = if (i >= 148 and i < 156) ' ' else c;
            unsigned += b;
            signed += @as(i8, @bitCast(b));
        }
        return stored == unsigned or @as(i64, @intCast(stored)) == signed;
    }

    fn isZero(h: Header) bool {
        return std.mem.allEqual(u8, h.block, 0);
    }
};

/// Walk a tar archive, scanning each regular member as a child.
pub fn walk(w: *Walker, cursor: *archive.Cursor) Error!void {
    var block: [512]u8 = undefined;
    // Extended-header payloads come from scratch: archives nest, stacks are small.
    const payload_buf = w.alloc(u8, max_extended) orelse return;
    var long_name: [max_name]u8 = undefined;
    var long_name_len: ?usize = null;
    var pax_size: ?u64 = null;
    var name_buf: [max_name]u8 = undefined;
    var first = true;
    while (true) {
        cursor.read(&block) catch |e| switch (e) {
            error.EndOfStream => {
                // A missing end-of-archive marker is common and harmless.
                return;
            },
            error.ReadFailed => return if (w.halt != null) error.Halted else {},
        };
        const h: Header = .{ .block = &block };
        if (h.isZero()) return; // end of archive (one zero block is enough)
        if (!h.checksumOk()) {
            w.notice(.malformed, if (first) "tar: bad header checksum" else "tar: bad header checksum mid-archive");
            return;
        }
        first = false;
        const size = pax_size orelse h.number(124, 12) orelse {
            w.notice(.malformed, "tar: bad size field");
            return;
        };
        const typeflag = block[156];
        const padded = std.math.add(u64, size, (512 - size % 512) % 512) catch {
            w.notice(.malformed, "tar: size overflow");
            return;
        };
        switch (typeflag) {
            'L', 'x' => {
                // Payload for the next header: a GNU long name, or pax records.
                if (size > max_extended) {
                    w.notice(.malformed, "tar: oversized extended header");
                    cursor.skip(padded) catch return;
                    continue;
                }
                const payload = payload_buf;
                cursor.read(payload[0..@intCast(size)]) catch return;
                cursor.skip(padded - size) catch return;
                if (typeflag == 'L') {
                    const n = archive.cstr(payload[0..@intCast(size)]);
                    const keep = @min(n.len, max_name);
                    @memcpy(long_name[0..keep], n[0..keep]);
                    long_name_len = keep;
                } else {
                    var it = PaxIterator{ .data = payload[0..@intCast(size)] };
                    while (it.next()) |rec| {
                        if (std.mem.eql(u8, rec.key, "path")) {
                            const keep = @min(rec.value.len, max_name);
                            @memcpy(long_name[0..keep], rec.value[0..keep]);
                            long_name_len = keep;
                        } else if (std.mem.eql(u8, rec.key, "size")) {
                            pax_size = std.fmt.parseInt(u64, rec.value, 10) catch null;
                        }
                    }
                    if (it.bad) w.notice(.malformed, "tar: bad pax record");
                }
                continue;
            },
            'K', 'g', 'V' => {
                // Long link names, global pax headers and volume labels carry no member.
                cursor.skip(padded) catch return;
                continue;
            },
            else => {},
        }
        const name = if (long_name_len) |n| long_name[0..n] else blk: {
            const base = archive.cstr(h.field(0, 100));
            const prefix = if (std.mem.eql(u8, h.field(257, 5), "ustar")) archive.cstr(h.field(345, 155)) else "";
            if (prefix.len == 0) break :blk base;
            @memcpy(name_buf[0..prefix.len], prefix);
            name_buf[prefix.len] = '/';
            @memcpy(name_buf[prefix.len + 1 ..][0..base.len], base);
            break :blk name_buf[0 .. prefix.len + 1 + base.len];
        };
        long_name_len = null;
        pax_size = null;
        // Regular files, contiguous files, GNU sparse data and unknown types with data are
        // scanned; links, devices, directories and FIFOs carry no data worth scanning.
        const has_data = switch (typeflag) {
            '1', '2', '3', '4', '5', '6' => false,
            else => true,
        };
        if (has_data and size > 0) {
            if (!try cursor.member(name, size, .member)) return;
            cursor.skip(padded - size) catch return;
        } else {
            cursor.skip(padded) catch return;
        }
    }
}

const PaxIterator = struct {
    data: []const u8,
    pos: usize = 0,
    bad: bool = false,

    const Record = struct { key: []const u8, value: []const u8 };

    /// Records are "<len> <key>=<value>\n", len counting the whole record.
    fn next(it: *PaxIterator) ?Record {
        if (it.pos >= it.data.len) return null;
        const rest = it.data[it.pos..];
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return it.fail();
        const len = std.fmt.parseInt(usize, rest[0..sp], 10) catch return it.fail();
        if (len <= sp + 1 or len > rest.len or rest[len - 1] != '\n') return it.fail();
        const body = rest[sp + 1 .. len - 1];
        const eq = std.mem.indexOfScalar(u8, body, '=') orelse return it.fail();
        it.pos += len;
        return .{ .key = body[0..eq], .value = body[eq + 1 ..] };
    }

    fn fail(it: *PaxIterator) ?Record {
        it.bad = true;
        return null;
    }
};

test "pax records" {
    var it = PaxIterator{ .data = "29 path=a/very/long/name.txt\n11 size=42\n" };
    const a = it.next().?;
    try std.testing.expectEqualStrings("path", a.key);
    try std.testing.expectEqualStrings("a/very/long/name.txt", a.value);
    try std.testing.expectEqualStrings("42", it.next().?.value);
    try std.testing.expect(it.next() == null);
    try std.testing.expect(!it.bad);
    var bad = PaxIterator{ .data = "99 path=x\n" };
    try std.testing.expect(bad.next() == null);
    try std.testing.expect(bad.bad);
}

test "header numbers: octal and base-256" {
    var block: [512]u8 = @splat(0);
    @memcpy(block[124..136], "00000001750 ");
    const h: Header = .{ .block = &block };
    try std.testing.expectEqual(@as(?u64, 1000), h.number(124, 12));
    block[124] = 0x80;
    @memset(block[125..136], 0);
    block[135] = 0x10;
    block[134] = 0x01;
    try std.testing.expectEqual(@as(?u64, 0x110), h.number(124, 12));
    block[124] = 'x';
    try std.testing.expectEqual(@as(?u64, null), h.number(124, 12));
}
