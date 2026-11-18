//! Package file integrity (deep tier): executables and shared libraries owned by a package are
//! hashed and compared with the checksum the package manager recorded (dpkg md5sums, rpm file
//! digests, apk Q1 SHA-1). Configuration files are skipped because administrators edit them.
//! Hashes go through the inode/ctime/mtime/size cache, so unchanged files cost a stat.
const std = @import("std");
const scan = @import("../scan.zig");
const cache = @import("../cache.zig");
const packages = @import("packages.zig");

pub const checks = [_]scan.Check{
    .{ .id = "integrity.package_files", .category = .integrity, .tier = .deep, .privilege = .partial, .os = .linux, .summary = "Package-owned binaries and libraries match their package checksums", .run = checkPackageFiles },
};

/// Executables and shared libraries: what an attacker replaces to persist.
pub fn isBinaryPath(path: []const u8) bool {
    const bin_dirs = [_][]const u8{ "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/systemd/systemd" };
    for (bin_dirs) |d| if (std.mem.startsWith(u8, path, d)) return std.mem.indexOfScalarPos(u8, path, d.len, '/') == null;
    const lib_dirs = [_][]const u8{ "/lib/", "/lib64/", "/lib32/", "/usr/lib/", "/usr/lib64/", "/usr/lib32/" };
    for (lib_dirs) |d| if (std.mem.startsWith(u8, path, d)) {
        const base = path[std.mem.lastIndexOfScalar(u8, path, '/').? + 1 ..];
        return std.mem.endsWith(u8, base, ".so") or std.mem.indexOf(u8, base, ".so.") != null;
    };
    return false;
}

fn algoFor(a: packages.Algo) ?cache.Algo {
    return switch (a) {
        .none => null,
        .md5 => .md5,
        .sha1 => .sha1,
        .sha256 => .sha256,
        .sha384 => .sha384,
        .sha512 => .sha512,
    };
}

/// The expected digest as raw bytes: hex for dpkg and rpm, `Q1` + base64 for apk.
fn expected(ref: packages.FileRef, out: []u8) ?[]const u8 {
    if (std.mem.startsWith(u8, ref.digest, "Q1")) {
        const b64 = ref.digest[2..];
        const n = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return null;
        if (n > out.len) return null;
        std.base64.standard.Decoder.decode(out[0..n], b64) catch return null;
        return out[0..n];
    }
    if (ref.digest.len % 2 != 0 or ref.digest.len / 2 > out.len) return null;
    return std.fmt.hexToBytes(out[0 .. ref.digest.len / 2], ref.digest) catch null;
}

fn checkPackageFiles(s: *scan.Scan) !void {
    const db = s.packages() orelse {
        try s.reduced("no dpkg, rpm or apk database found", .{});
        return;
    };
    try db.loadDigests(s.host);
    var unreadable: usize = 0;
    var verified: usize = 0;
    var it = db.files.iterator();
    while (it.next()) |kv| {
        const path = kv.key_ptr.*;
        const ref = kv.value_ptr.*;
        if (ref.config or !isBinaryPath(path)) continue;
        // A diverted path holds the diverting package's file; its recorded digest may be the
        // original's.
        if (db.diverted_from.contains(path)) continue;
        const algo = algoFor(ref.algo) orelse continue;
        var want_buf: [64]u8 = undefined;
        const want = expected(ref, &want_buf) orelse continue;
        if (want.len != cache.digestLen(algo)) continue;
        const st = s.host.stat(path, false) catch |e| switch (e) {
            error.AccessDenied => {
                unreadable += 1;
                continue;
            },
            else => continue, // missing files are a package-state question, not tampering
        };
        if (st.kind() != .file) continue;
        var got_buf: [64]u8 = undefined;
        const got = cache.digestFile(s.host, path, algo, &s.file_cache, &got_buf) catch |e| switch (e) {
            error.AccessDenied, error.PermissionDenied => {
                unreadable += 1;
                continue;
            },
            else => continue,
        };
        verified += 1;
        if (std.mem.eql(u8, got.digest, want)) continue;
        const pkg = db.packages.items[ref.pkg];
        try s.add(.{
            .severity = .high,
            .category = .integrity,
            .title = "Package-owned binary does not match its package checksum",
            .description = try s.print("{s} belongs to {s} {s} but its {t} digest differs from the one the package manager recorded. Replaced system binaries and libraries are a classic rootkit and backdoor technique.", .{ path, pkg.name, pkg.version, algo }),
            .remediation = try s.print("Compare with a known-good copy, then reinstall the package ({s}) from a trusted mirror. If the change was not made by an administrator, treat the host as compromised.", .{reinstallHint(pkg)}),
            .subject = path,
            .details = try s.details(&.{
                .{ .key = "package", .value = pkg.name },
                .{ .key = "manager", .value = @tagName(pkg.manager) },
                .{ .key = "expected", .value = ref.digest },
                .{ .key = "actual", .value = try s.print("{x}", .{got.digest}) },
            }),
        });
    }
    if (unreadable > 0) try s.reduced("{d} package-owned files were unreadable; run as root to verify them", .{unreadable});
}

fn reinstallHint(p: packages.Package) []const u8 {
    return switch (p.manager) {
        .dpkg => "apt-get install --reinstall <package>",
        .rpm => "dnf reinstall <package>",
        .apk => "apk fix <package>",
    };
}

test "binary paths" {
    try std.testing.expect(isBinaryPath("/usr/bin/ls"));
    try std.testing.expect(isBinaryPath("/usr/lib/x86_64-linux-gnu/libc.so.6"));
    try std.testing.expect(isBinaryPath("/lib/x86_64-linux-gnu/security/pam_unix.so"));
    try std.testing.expect(!isBinaryPath("/usr/bin/subdir/x"));
    try std.testing.expect(!isBinaryPath("/usr/share/doc/README"));
    try std.testing.expect(!isBinaryPath("/usr/lib/python3/dist-packages/x.py"));
}

test "a modified package-owned binary is reported in the deep tier only" {
    const gpa = std.testing.allocator;
    const Fixture = @import("../host.zig").Fixture;
    var fx = try Fixture.init();
    defer fx.deinit();
    try packages.writeDpkgFixture(&fx);
    // ls matches its md5sum, cat was replaced.
    var ls_md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("ls-binary", &ls_md5, .{});
    const md5sums = try std.fmt.allocPrint(gpa, "{x}  usr/bin/ls\n0f343b0931126a20f133d67c2b018a3b  usr/bin/cat\n", .{&ls_md5});
    defer gpa.free(md5sums);
    try fx.file("/var/lib/dpkg/info/coreutils.md5sums", md5sums);
    try fx.file("/usr/bin/ls", "ls-binary");
    try fx.file("/usr/bin/cat", "trojaned cat");

    var fast = scan.Scan.init(gpa, fx.host(.linux), .{ .context = .{ .role = .server } });
    defer fast.deinit();
    try fast.runChecks(&checks);
    try std.testing.expectEqual(@as(usize, 0), fast.findings.items.len);

    var deep = scan.Scan.init(gpa, fx.host(.linux), .{ .tier = .deep, .context = .{ .role = .server } });
    defer deep.deinit();
    try deep.runChecks(&checks);
    try std.testing.expectEqual(@as(usize, 1), deep.findings.items.len);
    try std.testing.expectEqualStrings("/usr/bin/cat", deep.findings.items[0].subject.?);
    try std.testing.expectEqual(@import("../finding.zig").Severity.high, deep.findings.items[0].severity);
}
