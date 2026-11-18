//! Go build information embedded in binaries (Go 1.18 and newer): the toolchain version and
//! every module the binary was built from, read from the `\xff Go buildinf:` blob without
//! running `go version -m`. The toolchain becomes the OSV `stdlib` package.
const std = @import("std");
const Item = @import("item.zig").Item;

pub const magic = "\xff Go buildinf:";

fn uvarint(b: []const u8, pos: *usize) ?u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < b.len) {
        const c = b[pos.*];
        pos.* += 1;
        v |= @as(u64, c & 0x7f) << shift;
        if (c & 0x80 == 0) return v;
        if (shift >= 63) return null;
        shift += 7;
    }
    return null;
}

pub const BuildInfo = struct { go_version: []const u8, modinfo: []const u8 };

/// Find and decode the inline build info blob. Pre-1.18 binaries store pointers instead and
/// are not decoded.
pub fn find(bytes: []const u8) ?BuildInfo {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, bytes, from, magic)) |at| {
        from = at + 1;
        if (at % 16 != 0 or at + 32 > bytes.len) continue;
        const flags = bytes[at + 15];
        if (flags & 0x2 == 0) continue;
        var pos = at + 32;
        const vlen = uvarint(bytes, &pos) orelse continue;
        if (vlen > 256 or pos + vlen > bytes.len) continue;
        const ver = bytes[pos..][0..@intCast(vlen)];
        pos += @intCast(vlen);
        const mlen = uvarint(bytes, &pos) orelse continue;
        if (mlen > 16 * 1024 * 1024 or pos + mlen > bytes.len) continue;
        var mod = bytes[pos..][0..@intCast(mlen)];
        // A 16-byte sentinel brackets the module info.
        if (mod.len >= 33 and mod[mod.len - 17] == '\n') mod = mod[16 .. mod.len - 16];
        return .{ .go_version = ver, .modinfo = mod };
    }
    return null;
}

/// Items for the toolchain and every module and dependency (replacements win).
pub fn items(gpa: std.mem.Allocator, info: BuildInfo, source: []const u8, out: *std.ArrayList(Item)) !void {
    var gv = info.go_version;
    if (std.mem.startsWith(u8, gv, "go")) gv = gv[2..];
    gv = std.mem.sliceTo(gv, ' ');
    if (gv.len > 0 and std.ascii.isDigit(gv[0])) try out.append(gpa, .{ .ecosystem = "Go", .name = "stdlib", .version = gv, .source = source });
    var lines = std.mem.splitScalar(u8, info.modinfo, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, '\t');
        const kind = f.next() orelse continue;
        if (!std.mem.eql(u8, kind, "mod") and !std.mem.eql(u8, kind, "dep") and !std.mem.eql(u8, kind, "=>")) continue;
        const path = f.next() orelse continue;
        const ver = f.next() orelse continue;
        if (ver.len < 2 or ver[0] != 'v') continue; // (devel) and local replacements
        if (std.mem.eql(u8, kind, "=>") and out.items.len > 0) {
            // A replacement applies to the dependency just before it.
            out.items[out.items.len - 1].name = path;
            out.items[out.items.len - 1].version = ver;
            continue;
        }
        try out.append(gpa, .{ .ecosystem = "Go", .name = path, .version = ver, .source = source });
    }
}

test "inline build info" {
    const gpa = std.testing.allocator;
    var buf: [512]u8 = @splat(0);
    @memcpy(buf[64..][0..magic.len], magic);
    buf[64 + 14] = 8;
    buf[64 + 15] = 2;
    const ver = "go1.22.1";
    const mod_body = "path\texample.com/cmd\nmod\texample.com/cmd\t(devel)\t\ndep\tgolang.org/x/net\tv0.17.0\th1:x\ndep\tgithub.com/a/b\tv1.0.0\th1:y\n=>\tgithub.com/c/b\tv1.0.1\th1:z\n";
    var mod: [256]u8 = undefined;
    @memset(mod[0..16], 0x30);
    @memcpy(mod[16..][0..mod_body.len], mod_body);
    @memset(mod[16 + mod_body.len ..][0..16], 0x31);
    const mod_all = mod[0 .. mod_body.len + 32];
    var pos: usize = 64 + 32;
    buf[pos] = ver.len;
    pos += 1;
    @memcpy(buf[pos..][0..ver.len], ver);
    pos += ver.len;
    // uvarint length (two bytes: the module info is over 127 bytes).
    buf[pos] = @as(u8, @intCast(mod_all.len & 0x7f)) | 0x80;
    buf[pos + 1] = @intCast(mod_all.len >> 7);
    pos += 2;
    @memcpy(buf[pos..][0..mod_all.len], mod_all);

    const info = find(&buf).?;
    try std.testing.expectEqualStrings("go1.22.1", info.go_version);
    var out: std.ArrayList(Item) = .empty;
    defer out.deinit(gpa);
    try items(gpa, info, "bin", &out);
    try std.testing.expectEqual(@as(usize, 3), out.items.len);
    try std.testing.expectEqualStrings("stdlib", out.items[0].name);
    try std.testing.expectEqualStrings("1.22.1", out.items[0].version);
    try std.testing.expectEqualStrings("golang.org/x/net", out.items[1].name);
    try std.testing.expectEqualStrings("github.com/c/b", out.items[2].name);
    try std.testing.expect(find("no build info here") == null);
}
