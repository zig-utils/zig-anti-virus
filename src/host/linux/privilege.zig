//! Privilege checks: SUID and SGID binaries and file capabilities found by walking system paths
//! with statx and the security.capability xattr (never `find -perm`), judged by package
//! ownership and the last baseline; and running non-root processes holding dangerous
//! capabilities in the host user namespace.
const std = @import("std");
const scan = @import("../scan.zig");
const tokens = @import("../tokens.zig");
const sys = @import("../sys.zig");
const finding = @import("../finding.zig");
const procfs = @import("procfs.zig");
const process = @import("process.zig");
const Host = @import("../host.zig").Host;

pub const checks = [_]scan.Check{
    .{ .id = "privilege.suid", .category = .privilege, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "SUID and SGID binaries no package owns, in temp or home directories, or new since baseline", .run = checkSuid },
    .{ .id = "privilege.file_caps", .category = .privilege, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Unowned files carrying dangerous capabilities", .run = checkFileCaps },
    .{ .id = "privilege.process_caps", .category = .privilege, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Non-root processes with dangerous capabilities in the host user namespace", .run = checkProcessCaps },
};

/// Paths walked in the fast tier, and the extra ones the deep tier adds.
pub const fast_roots = [_][]const u8{ "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local", "/usr/lib", "/usr/lib64", "/usr/libexec", "/opt", "/tmp", "/var/tmp", "/dev/shm" };
pub const deep_roots = [_][]const u8{ "/home", "/root", "/var", "/srv", "/etc" };

pub const max_entries = 2_000_000;

pub const Hit = struct { path: []const u8, stat: sys.Stat };

/// Walk `roots` without following symlinks, calling `visit` for every regular file. Roots that
/// are themselves symlinks (merged /usr) are skipped so nothing is walked twice. Returns the
/// number of directories that could not be opened.
pub fn walk(s: *scan.Scan, roots: []const []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), *scan.Scan, []const u8, sys.Stat) anyerror!void) !usize {
    var denied: usize = 0;
    var stack: std.ArrayList([]const u8) = .empty;
    defer stack.deinit(s.gpa);
    var path_arena = std.heap.ArenaAllocator.init(s.gpa);
    defer path_arena.deinit();
    const pa = path_arena.allocator();
    for (roots) |r| {
        const st = s.host.stat(r, false) catch continue;
        if (st.kind() != .directory) continue;
        try stack.append(s.gpa, r);
    }
    var entries: usize = 0;
    while (stack.pop()) |dir_path| {
        var dir = (s.host.openDir(dir_path) catch {
            denied += 1;
            continue;
        }) orelse continue;
        defer dir.close(s.host.io);
        var it = dir.iterate();
        while (it.next(s.host.io) catch null) |entry| {
            entries += 1;
            if (entries > max_entries) return denied;
            const child = try std.fmt.allocPrint(pa, "{s}/{s}", .{ std.mem.trimEnd(u8, dir_path, "/"), entry.name });
            switch (entry.kind) {
                .directory => {
                    if (std.mem.eql(u8, child, "/proc") or std.mem.eql(u8, child, "/sys")) continue;
                    try stack.append(s.gpa, child);
                },
                .file => {
                    const st = sys.statAt(dir, entry.name, false) catch continue;
                    try visit(ctx, s, child, st);
                },
                else => {},
            }
        }
    }
    return denied;
}

fn walkRoots(s: *scan.Scan) []const []const u8 {
    return if (s.options.tier == .deep) &(fast_roots ++ deep_roots) else &fast_roots;
}

fn inUserWritable(path: []const u8) bool {
    return tokens.isTempPath(path) or std.mem.startsWith(u8, path, "/home/") or std.mem.startsWith(u8, path, "/root/") or std.mem.startsWith(u8, path, "/var/tmp/");
}

const SuidCtx = struct {};

fn visitSuid(_: SuidCtx, s: *scan.Scan, path: []const u8, st: sys.Stat) !void {
    if (!st.isSetuid() and !st.isSetgid()) return;
    const bits: []const u8 = if (st.isSetuid() and st.isSetgid()) "SUID and SGID" else if (st.isSetuid()) "SUID" else "SGID";
    const abs = try s.dupe(path);
    if (s.packages()) |db| if (db.ownerResolved(path) != null) {
        // rpm and apk record modes: a set-id bit the package did not ship was added later.
        const ref = db.files.get(path) orelse blk: {
            var buf: [4096]u8 = undefined;
            break :blk db.files.get(@import("packages.zig").usrAlias(path, &buf) orelse "") orelse return;
        };
        if (ref.mode != 0 and (st.mode & 0o6000) & ~@as(u32, ref.mode) != 0) {
            try s.add(.{
                .severity = .high,
                .category = .privilege,
                .title = "Set-id bit added to a package file",
                .description = try s.print("{s} has {s} set, but its package recorded mode {o}. A set-id bit added after install is a privilege-escalation backdoor.", .{ path, bits, ref.mode & 0o7777 }),
                .remediation = try s.print("chmod u-s,g-s {s} and reinstall its package; find out who changed it.", .{path}),
                .subject = abs,
            });
        }
        return;
    };
    if (s.options.ownership) |o| if (o.owner(path) != null) return;

    const writable_place = inUserWritable(path);
    const root_owned = st.uid == 0;
    const tracked = s.baseline.tracks("suid");
    const new = try s.drift("suid", path, try s.print("{o}:{d}", .{ st.mode & 0o7777, st.uid }));
    const severity: finding.Severity = if (writable_place) .critical else if (new and tracked) .high else .medium;
    try s.add(.{
        .severity = severity,
        .category = .privilege,
        .title = if (writable_place) "Set-id binary in a temp or home directory" else if (new and tracked) "New set-id binary since the baseline" else "Set-id binary no package owns",
        .description = try s.print("{s} is {s} (mode {o}, owner uid {d}){s} and belongs to no package. {s}", .{
            path,                                                                      bits,                                                                                                                                                                                                            st.mode & 0o7777, st.uid,
            if (root_owned) ", so it runs as root for anyone who executes it" else "", if (writable_place) "Set-id binaries never belong in temp or home directories; this is the classic persistence of a local root exploit." else "Unpackaged set-id programs are unreviewed privilege boundaries.",
        }),
        .remediation = try s.print("Unless you installed it deliberately, remove the bit (chmod u-s,g-s {s}) or the file, and investigate how it appeared.", .{path}),
        .subject = abs,
        .details = try s.details(&.{
            .{ .key = "mode", .value = try s.print("{o}", .{st.mode & 0o7777}) },
            .{ .key = "uid", .value = try s.print("{d}", .{st.uid}) },
            .{ .key = "gid", .value = try s.print("{d}", .{st.gid}) },
        }),
    });
}

fn checkSuid(s: *scan.Scan) !void {
    const denied = try walk(s, walkRoots(s), SuidCtx{}, visitSuid);
    if (denied > 0) try s.reduced("{d} directories were unreadable without root", .{denied});
}

// Capabilities ----------------------------------------------------------------------------------

pub const Cap = struct { bit: u6, name: []const u8 };

/// Capabilities that amount to root, or close to it.
pub const dangerous_caps = [_]Cap{
    .{ .bit = 0, .name = "cap_chown" },
    .{ .bit = 1, .name = "cap_dac_override" },
    .{ .bit = 2, .name = "cap_dac_read_search" },
    .{ .bit = 3, .name = "cap_fowner" },
    .{ .bit = 6, .name = "cap_setgid" },
    .{ .bit = 7, .name = "cap_setuid" },
    .{ .bit = 12, .name = "cap_net_admin" },
    .{ .bit = 16, .name = "cap_sys_module" },
    .{ .bit = 17, .name = "cap_sys_rawio" },
    .{ .bit = 19, .name = "cap_sys_ptrace" },
    .{ .bit = 21, .name = "cap_sys_admin" },
    .{ .bit = 31, .name = "cap_setfcap" },
    .{ .bit = 38, .name = "cap_perfmon" },
    .{ .bit = 39, .name = "cap_bpf" },
};

pub fn dangerousMask() u64 {
    var m: u64 = 0;
    for (dangerous_caps) |c| m |= @as(u64, 1) << c.bit;
    return m;
}

pub fn capNames(buf: []u8, mask: u64) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    for (dangerous_caps) |c| if (mask & (@as(u64, 1) << c.bit) != 0) {
        if (w.end > 0) w.writeByte(',') catch break;
        w.writeAll(c.name) catch break;
    };
    return w.buffered();
}

/// Permitted plus inheritable capabilities from a `security.capability` xattr
/// (vfs_cap_data revisions 1 to 3, little-endian).
pub fn decodeFileCaps(raw: []const u8) ?u64 {
    if (raw.len < 12) return null;
    const magic = std.mem.readInt(u32, raw[0..4], .little);
    const rev = magic & 0xff000000;
    const lo_p = std.mem.readInt(u32, raw[4..8], .little);
    const lo_i = std.mem.readInt(u32, raw[8..12], .little);
    var mask: u64 = lo_p | lo_i;
    switch (rev) {
        0x01000000 => {},
        0x02000000, 0x03000000 => {
            if (raw.len < 20) return null;
            const hi_p = std.mem.readInt(u32, raw[12..16], .little);
            const hi_i = std.mem.readInt(u32, raw[16..20], .little);
            mask |= (@as(u64, hi_p | hi_i)) << 32;
        },
        else => return null,
    }
    return mask;
}

const CapsCtx = struct {};

fn visitCaps(_: CapsCtx, s: *scan.Scan, path: []const u8, st: sys.Stat) !void {
    if (!st.executable()) return;
    var buf: [64]u8 = undefined;
    const raw = s.host.getXattr(path, "security.capability", &buf) catch return;
    const mask = decodeFileCaps(raw) orelse return;
    const bad = mask & dangerousMask();
    if (bad == 0 or s.owned(path)) return;
    var names: [512]u8 = undefined;
    const writable_place = inUserWritable(path);
    try s.add(.{
        .severity = if (writable_place) .critical else .high,
        .category = .privilege,
        .title = "Unowned file with dangerous capabilities",
        .description = try s.print("{s} carries file capabilities {s} and belongs to no package. Whoever runs it gets those privileges, several of which are equivalent to root.", .{ path, capNames(&names, bad) }),
        .remediation = try s.print("Remove them with setcap -r {s} unless you granted them deliberately.", .{path}),
        .subject = try s.dupe(path),
        .details = try s.details(&.{.{ .key = "capabilities", .value = try s.dupe(capNames(&names, bad)) }}),
    });
}

fn checkFileCaps(s: *scan.Scan) !void {
    if (!s.host.live and !sys.is_linux) {
        try s.reduced("security.capability xattrs are read on Linux only", .{});
        return;
    }
    const denied = try walk(s, walkRoots(s), CapsCtx{}, visitCaps);
    if (denied > 0) try s.reduced("{d} directories were unreadable without root", .{denied});
}

fn checkProcessCaps(s: *scan.Scan) !void {
    var own_ns_buf: [64]u8 = undefined;
    const own_ns = s.host.readLink("/proc/self/ns/user", &own_ns_buf);
    var path_buf: [64]u8 = undefined;
    var ns_buf: [64]u8 = undefined;
    for (try s.processes()) |p| {
        if (p.isKernelThread() or p.uid == 0 or p.euid == 0) continue;
        const bad = p.status.cap_eff & dangerousMask();
        if (bad == 0) continue;
        // Capabilities inside a rootless container's user namespace are not host privileges.
        if (own_ns) |mine| {
            const ns_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/user", .{p.pid}) catch continue;
            if (s.host.readLink(ns_path, &ns_buf)) |theirs| if (!std.mem.eql(u8, mine, theirs)) continue;
        }
        const exe = p.exe orelse continue;
        if (s.owned(exe)) continue;
        var names: [512]u8 = undefined;
        try s.add(.{
            .severity = if (process.exeRisk(exe) != null) .high else .medium,
            .category = .privilege,
            .title = "Non-root process with dangerous capabilities",
            .description = try s.print("Process {d} ({s}, {s}) runs as uid {d} but holds {s}, and no package owns its executable.", .{ p.pid, p.comm, exe, p.uid, capNames(&names, bad) }),
            .remediation = try s.print("Find what granted the capabilities (systemd AmbientCapabilities=, file capabilities on {s}, a parent process) and drop them if not required.", .{exe}),
            .subject = exe,
            .pid = p.pid,
            .details = try s.details(&.{.{ .key = "cap_eff", .value = try s.print("{x:0>16}", .{p.status.cap_eff}) }}),
        });
    }
}

// Tests -----------------------------------------------------------------------------------------

const Fixture = @import("../host.zig").Fixture;

test "file capability decoding" {
    // rev 2, cap_net_raw (13) permitted, effective flag.
    var raw: [20]u8 = @splat(0);
    std.mem.writeInt(u32, raw[0..4], 0x02000001, .little);
    std.mem.writeInt(u32, raw[4..8], 1 << 13, .little);
    try std.testing.expectEqual(@as(u64, 1 << 13), decodeFileCaps(&raw).?);
    try std.testing.expectEqual(@as(u64, 0), decodeFileCaps(&raw).? & dangerousMask());
    std.mem.writeInt(u32, raw[4..8], 1 << 21, .little);
    std.mem.writeInt(u32, raw[12..16], 1 << (39 - 32), .little);
    const m = decodeFileCaps(&raw).?;
    var names: [128]u8 = undefined;
    try std.testing.expectEqualStrings("cap_sys_admin,cap_bpf", capNames(&names, m & dangerousMask()));
    try std.testing.expect(decodeFileCaps(raw[0..8]) == null);
}

test "fixture: SUID in /tmp and home is critical, package-owned SUID is quiet" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.fileMode("/usr/bin/sudo", "sudo", 0o4755);
    try fx.fileMode("/usr/bin/passwd", "passwd", 0o4755);
    try fx.fileMode("/usr/bin/ls", "ls", 0o755);
    try fx.fileMode("/tmp/.x/rootsh", "sh", 0o4755);
    try fx.fileMode("/home/alice/bin/helper", "x", 0o2755);
    try fx.fileMode("/usr/local/bin/vendor-tool", "x", 0o4755);
    try fx.file("/var/lib/dpkg/status", "Package: sudo\nStatus: install ok installed\nVersion: 1\n\nPackage: passwd\nStatus: install ok installed\nVersion: 1\n");
    try fx.file("/var/lib/dpkg/info/sudo.list", "/usr/bin/sudo\n");
    try fx.file("/var/lib/dpkg/info/passwd.list", "/usr/bin/passwd\n");

    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{"privilege.suid"}, .tier = .deep, .context = .{ .role = .server } });
    defer s.deinit();
    try s.runChecks(&checks);
    var tmp_crit = false;
    var home_crit = false;
    var vendor_medium = false;
    for (s.findings.items) |f| {
        const subj = f.subject.?;
        try std.testing.expect(!std.mem.eql(u8, subj, "/usr/bin/sudo") and !std.mem.eql(u8, subj, "/usr/bin/passwd") and !std.mem.eql(u8, subj, "/usr/bin/ls"));
        if (std.mem.eql(u8, subj, "/tmp/.x/rootsh")) tmp_crit = f.severity == .critical;
        if (std.mem.eql(u8, subj, "/home/alice/bin/helper")) home_crit = f.severity == .critical;
        if (std.mem.eql(u8, subj, "/usr/local/bin/vendor-tool")) vendor_medium = f.severity == .medium;
    }
    try std.testing.expect(tmp_crit and home_crit and vendor_medium);
}

test "rpm modes: a SUID bit the package did not ship is reported" {
    var fx = try Fixture.init();
    defer fx.deinit();
    // The fixture rpmdb ships /usr/bin/bash 0755 and /usr/bin/sudo 04111.
    try fx.file("/var/lib/rpm/rpmdb.sqlite", @import("packages.zig").fixtures.rpmdb);
    try fx.fileMode("/usr/bin/bash", "bash", 0o4755);
    try fx.fileMode("/usr/bin/sudo", "sudo", 0o4111);
    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{"privilege.suid"}, .context = .{ .role = .server } });
    defer s.deinit();
    try s.runChecks(&checks);
    try std.testing.expectEqual(@as(usize, 1), s.findings.items.len);
    try std.testing.expectEqualStrings("/usr/bin/bash", s.findings.items[0].subject.?);
    try std.testing.expectEqualStrings("Set-id bit added to a package file", s.findings.items[0].title);
}
