//! One installed thing that can be vulnerable, and how it is looked up in the index.
const std = @import("std");

pub const Item = struct {
    /// OSV ecosystem (npm, PyPI, Go, crates.io, Debian:12, Alpine:v3.20, ...), or a collector
    /// name for sources without one (homebrew, pantry, macos-app, banner).
    ecosystem: []const u8,
    name: []const u8,
    version: []const u8,
    /// Where it was found: a lockfile, a binary, a package database.
    source: []const u8,
    /// The name advisories use when it differs (Debian advisories name source packages).
    advisory_name: ?[]const u8 = null,
    /// CPE vendor and product for NVD matching, when known.
    cpe_vendor: ?[]const u8 = null,
    cpe_product: ?[]const u8 = null,
};

pub const CpeName = struct { vendor: []const u8, product: []const u8 };

/// Project domains (pantry) and Homebrew formula names for software NVD tracks by CPE.
const cpe_names = [_]struct { keys: []const []const u8, cpe: CpeName }{
    .{ .keys = &.{ "curl.se", "curl" }, .cpe = .{ .vendor = "haxx", .product = "curl" } },
    .{ .keys = &.{ "openssl.org", "openssl", "openssl@3", "openssl@1.1" }, .cpe = .{ .vendor = "openssl", .product = "openssl" } },
    .{ .keys = &.{ "sqlite.org", "sqlite" }, .cpe = .{ .vendor = "sqlite", .product = "sqlite" } },
    .{ .keys = &.{ "zlib.net", "zlib" }, .cpe = .{ .vendor = "zlib", .product = "zlib" } },
    .{ .keys = &.{ "git-scm.org", "git" }, .cpe = .{ .vendor = "git-scm", .product = "git" } },
    .{ .keys = &.{ "nginx.org", "nginx" }, .cpe = .{ .vendor = "f5", .product = "nginx" } },
    .{ .keys = &.{ "nodejs.org", "node", "node@20", "node@22" }, .cpe = .{ .vendor = "nodejs", .product = "node.js" } },
    .{ .keys = &.{ "python.org", "python@3.12", "python@3.13", "python@3.11" }, .cpe = .{ .vendor = "python", .product = "python" } },
    .{ .keys = &.{ "gnu.org/readline", "readline" }, .cpe = .{ .vendor = "gnu", .product = "readline" } },
    .{ .keys = &.{ "gnu.org/bash", "bash" }, .cpe = .{ .vendor = "gnu", .product = "bash" } },
    .{ .keys = &.{ "libexpat.github.io", "expat" }, .cpe = .{ .vendor = "libexpat_project", .product = "libexpat" } },
    .{ .keys = &.{ "openssh.com", "openssh" }, .cpe = .{ .vendor = "openbsd", .product = "openssh" } },
    .{ .keys = &.{ "redis.io", "redis" }, .cpe = .{ .vendor = "redis", .product = "redis" } },
    .{ .keys = &.{ "postgresql.org", "postgresql@16", "postgresql@17" }, .cpe = .{ .vendor = "postgresql", .product = "postgresql" } },
    .{ .keys = &.{ "mysql.com", "mysql" }, .cpe = .{ .vendor = "oracle", .product = "mysql" } },
    .{ .keys = &.{ "libpng.org", "libpng" }, .cpe = .{ .vendor = "libpng", .product = "libpng" } },
    .{ .keys = &.{ "tukaani.org/xz", "xz" }, .cpe = .{ .vendor = "tukaani", .product = "xz" } },
    .{ .keys = &.{ "gnupg.org", "gnupg" }, .cpe = .{ .vendor = "gnupg", .product = "gnupg" } },
    .{ .keys = &.{ "invisible-island.net/ncurses", "ncurses" }, .cpe = .{ .vendor = "gnu", .product = "ncurses" } },
    .{ .keys = &.{ "bun.sh", "bun" }, .cpe = .{ .vendor = "oven-sh", .product = "bun" } },
};

pub fn cpeFor(name: []const u8) ?CpeName {
    for (cpe_names) |e| for (e.keys) |k| if (std.mem.eql(u8, k, name)) return e.cpe;
    return null;
}

/// The OSV ecosystem for the host's OS packages, from /etc/os-release text.
pub fn osEcosystem(buf: []u8, os_release: []const u8) ?[]const u8 {
    var id: []const u8 = "";
    var version_id: []const u8 = "";
    var version: []const u8 = "";
    var lines = std.mem.splitScalar(u8, os_release, '\n');
    while (lines.next()) |line| {
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const v = std.mem.trim(u8, line[eq + 1 ..], "\"' \r");
        if (std.mem.eql(u8, line[0..eq], "ID")) id = v;
        if (std.mem.eql(u8, line[0..eq], "VERSION_ID")) version_id = v;
        if (std.mem.eql(u8, line[0..eq], "VERSION")) version = v;
    }
    if (std.mem.eql(u8, id, "debian")) return std.fmt.bufPrint(buf, "Debian:{s}", .{std.mem.sliceTo(version_id, '.')}) catch null;
    if (std.mem.eql(u8, id, "ubuntu")) return std.fmt.bufPrint(buf, "Ubuntu:{s}{s}", .{ version_id, if (std.mem.indexOf(u8, version, "LTS") != null) ":LTS" else "" }) catch null;
    if (std.mem.eql(u8, id, "alpine")) {
        var parts = std.mem.splitScalar(u8, version_id, '.');
        const major = parts.next() orelse return null;
        const minor = parts.next() orelse return null;
        return std.fmt.bufPrint(buf, "Alpine:v{s}.{s}", .{ major, minor }) catch null;
    }
    if (std.mem.eql(u8, id, "rocky")) return std.fmt.bufPrint(buf, "Rocky Linux:{s}", .{std.mem.sliceTo(version_id, '.')}) catch null;
    if (std.mem.eql(u8, id, "almalinux")) return std.fmt.bufPrint(buf, "AlmaLinux:{s}", .{std.mem.sliceTo(version_id, '.')}) catch null;
    return null;
}

test "os ecosystems and CPE names" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Ubuntu:24.04:LTS", osEcosystem(&buf, "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nID=ubuntu\n").?);
    try std.testing.expectEqualStrings("Debian:12", osEcosystem(&buf, "ID=debian\nVERSION_ID=\"12\"\n").?);
    try std.testing.expectEqualStrings("Alpine:v3.20", osEcosystem(&buf, "ID=alpine\nVERSION_ID=3.20.3\n").?);
    try std.testing.expect(osEcosystem(&buf, "ID=fedora\nVERSION_ID=41\n") == null);
    try std.testing.expectEqualStrings("haxx", cpeFor("curl.se").?.vendor);
    try std.testing.expectEqualStrings("openssl", cpeFor("openssl@3").?.product);
}
