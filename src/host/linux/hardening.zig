//! Hardening checks: firewall rules over nftables netlink (not `nft` or `iptables`), kernel
//! sysctls, AppArmor and SELinux state, disk encryption of the root filesystem through the
//! device-mapper tree in /sys, container isolation, and pending security updates computed from
//! the dpkg status and apt indexes. Server context downgrades what a role explains (disk
//! encryption on servers, sysctls and MAC inside containers) and the JSON keeps both severities.
const std = @import("std");
const builtin = @import("builtin");
const scan = @import("../scan.zig");
const finding = @import("../finding.zig");
const packages = @import("packages.zig");
const network = @import("network.zig");
const version = @import("../../cve/version.zig");
const Host = @import("../host.zig").Host;

pub const checks = [_]scan.Check{
    .{ .id = "hardening.firewall", .category = .hardening, .tier = .fast, .privilege = .root, .os = .linux, .summary = "Firewall rules present (nftables netlink, legacy iptables tables)", .run = checkFirewall },
    .{ .id = "hardening.sysctl", .category = .hardening, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Kernel sysctls: kptr_restrict, dmesg_restrict, unprivileged BPF, ptrace scope, rp_filter, ...", .run = checkSysctls },
    .{ .id = "hardening.mac", .category = .hardening, .tier = .fast, .privilege = .none, .os = .linux, .summary = "AppArmor or SELinux enabled and enforcing", .run = checkMac },
    .{ .id = "hardening.disk_encryption", .category = .hardening, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Root filesystem on a dm-crypt device", .run = checkDiskEncryption },
    .{ .id = "container.security", .category = .container, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Privileged containers, exposed Docker sockets and APIs, writable /proc/sys", .run = checkContainers },
    .{ .id = "hardening.updates", .category = .hardening, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Pending security updates from package metadata, and pending reboots", .run = checkUpdates },
};

// Sysctls ---------------------------------------------------------------------------------------

pub const Sysctl = struct {
    name: []const u8,
    path: []const u8,
    /// Acceptable values.
    ok: []const []const u8,
    severity: finding.Severity,
    why: []const u8,
    fix: []const u8,
};

pub const sysctls = [_]Sysctl{
    .{ .name = "kptr_restrict", .path = "/proc/sys/kernel/kptr_restrict", .ok = &.{ "1", "2" }, .severity = .low, .why = "kernel pointers are visible to unprivileged users, which defeats KASLR for exploits", .fix = "kernel.kptr_restrict = 1" },
    .{ .name = "dmesg_restrict", .path = "/proc/sys/kernel/dmesg_restrict", .ok = &.{"1"}, .severity = .low, .why = "unprivileged users can read the kernel log, which leaks addresses and hardware details", .fix = "kernel.dmesg_restrict = 1" },
    .{ .name = "unprivileged_bpf_disabled", .path = "/proc/sys/kernel/unprivileged_bpf_disabled", .ok = &.{ "1", "2" }, .severity = .medium, .why = "unprivileged users can load eBPF programs, a frequent kernel exploit vector", .fix = "kernel.unprivileged_bpf_disabled = 1" },
    .{ .name = "ptrace_scope", .path = "/proc/sys/kernel/yama/ptrace_scope", .ok = &.{ "1", "2", "3" }, .severity = .low, .why = "any process can ptrace other processes of the same user and read their secrets", .fix = "kernel.yama.ptrace_scope = 1" },
    .{ .name = "rp_filter", .path = "/proc/sys/net/ipv4/conf/all/rp_filter", .ok = &.{ "1", "2" }, .severity = .low, .why = "reverse-path filtering is off, so spoofed source addresses are accepted", .fix = "net.ipv4.conf.all.rp_filter = 1" },
    .{ .name = "randomize_va_space", .path = "/proc/sys/kernel/randomize_va_space", .ok = &.{"2"}, .severity = .medium, .why = "address space layout randomisation is reduced or off", .fix = "kernel.randomize_va_space = 2" },
    .{ .name = "protected_symlinks", .path = "/proc/sys/fs/protected_symlinks", .ok = &.{"1"}, .severity = .low, .why = "symlink races in world-writable directories are possible", .fix = "fs.protected_symlinks = 1" },
    .{ .name = "protected_hardlinks", .path = "/proc/sys/fs/protected_hardlinks", .ok = &.{"1"}, .severity = .low, .why = "hardlinks to files the user cannot write are allowed", .fix = "fs.protected_hardlinks = 1" },
    .{ .name = "suid_dumpable", .path = "/proc/sys/fs/suid_dumpable", .ok = &.{ "0", "2" }, .severity = .low, .why = "set-id programs can dump core with their privileged memory readable by the user", .fix = "fs.suid_dumpable = 0" },
    .{ .name = "accept_redirects", .path = "/proc/sys/net/ipv4/conf/all/accept_redirects", .ok = &.{"0"}, .severity = .low, .why = "ICMP redirects can change the routing table", .fix = "net.ipv4.conf.all.accept_redirects = 0" },
    .{ .name = "accept_source_route", .path = "/proc/sys/net/ipv4/conf/all/accept_source_route", .ok = &.{"0"}, .severity = .low, .why = "source-routed packets are accepted", .fix = "net.ipv4.conf.all.accept_source_route = 0" },
    .{ .name = "tcp_syncookies", .path = "/proc/sys/net/ipv4/tcp_syncookies", .ok = &.{ "1", "2" }, .severity = .low, .why = "SYN floods can exhaust the connection backlog", .fix = "net.ipv4.tcp_syncookies = 1" },
};

fn checkSysctls(s: *scan.Scan) !void {
    var buf: [64]u8 = undefined;
    var missing: usize = 0;
    for (sysctls) |c| {
        const value = std.mem.trim(u8, s.host.readOpt(c.path, &buf) orelse {
            missing += 1;
            continue;
        }, " \t\n");
        var ok = false;
        for (c.ok) |v| if (std.mem.eql(u8, value, v)) {
            ok = true;
        };
        if (ok) continue;
        try s.add(.{
            .check = try s.print("hardening.sysctl.{s}", .{c.name}),
            .severity = c.severity,
            .category = .hardening,
            .title = try s.print("Weak kernel setting: {s} = {s}", .{ c.name, value }),
            .description = try s.print("{s} is {s}: {s}.", .{ c.path, value, c.why }),
            .remediation = try s.print("Set {s} in /etc/sysctl.d/99-hardening.conf and run sysctl --system.", .{c.fix}),
            .subject = c.path,
            .details = try s.details(&.{.{ .key = "value", .value = try s.dupe(value) }}),
        });
    }
    if (missing == sysctls.len) try s.reduced("no sysctls readable under /proc/sys", .{});
}

// MAC -------------------------------------------------------------------------------------------

pub const MacState = enum { apparmor, selinux_enforcing, selinux_permissive, none };

pub fn macState(h: Host) MacState {
    var buf: [64]u8 = undefined;
    if (h.readOpt("/sys/fs/selinux/enforce", &buf)) |v| {
        return if (std.mem.startsWith(u8, std.mem.trim(u8, v, " \n"), "1")) .selinux_enforcing else .selinux_permissive;
    }
    if (h.readOpt("/sys/module/apparmor/parameters/enabled", &buf)) |v| {
        if (std.mem.startsWith(u8, std.mem.trim(u8, v, " \n"), "Y") and h.exists("/sys/kernel/security/apparmor")) return .apparmor;
    }
    if (h.readOpt("/sys/kernel/security/lsm", &buf)) |v| {
        if (std.mem.indexOf(u8, v, "apparmor") != null) return .apparmor;
    }
    return .none;
}

fn checkMac(s: *scan.Scan) !void {
    switch (macState(s.host)) {
        .apparmor, .selinux_enforcing => {},
        .selinux_permissive => try s.add(.{
            .severity = .low,
            .category = .hardening,
            .title = "SELinux is permissive",
            .description = "SELinux is loaded but only logs denials; its policy does not confine anything.",
            .remediation = "Fix the logged denials, then set SELINUX=enforcing in /etc/selinux/config (setenforce 1 for now).",
            .subject = "/sys/fs/selinux/enforce",
        }),
        .none => try s.add(.{
            .severity = .medium,
            .category = .hardening,
            .title = "No mandatory access control",
            .description = "Neither AppArmor nor SELinux is active, so a compromised service is confined only by Unix permissions.",
            .remediation = "Enable AppArmor (Debian, Ubuntu) or SELinux (Fedora, RHEL) and load the distribution's profiles.",
        }),
    }
}

// Disk encryption -------------------------------------------------------------------------------

/// The device a mount point is mounted from, from /proc/self/mounts text.
pub fn mountSource(mounts: []const u8, mount_point: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const src = f.next() orelse continue;
        const mp = f.next() orelse continue;
        if (std.mem.eql(u8, mp, mount_point)) found = src; // the last mount wins
    }
    return found;
}

pub const Encryption = enum { encrypted, plain, unknown };

/// Whether a block device sits on dm-crypt: dm devices whose uuid starts with CRYPT-, found by
/// walking /sys/block/<dev>/slaves down through LVM and other layers.
pub fn deviceEncryption(h: Host, dev_name: []const u8, depth: u8) Encryption {
    if (depth > 8) return .unknown;
    var path_buf: [256]u8 = undefined;
    var buf: [128]u8 = undefined;
    const uuid_path = std.fmt.bufPrint(&path_buf, "/sys/class/block/{s}/dm/uuid", .{dev_name}) catch return .unknown;
    if (h.readOpt(uuid_path, &buf)) |uuid| if (std.mem.startsWith(u8, uuid, "CRYPT-")) return .encrypted;
    const slaves = std.fmt.bufPrint(&path_buf, "/sys/class/block/{s}/slaves", .{dev_name}) catch return .unknown;
    var dir = (h.openDir(slaves) catch return .unknown) orelse return if (h.exists(std.fmt.bufPrint(&path_buf, "/sys/class/block/{s}", .{dev_name}) catch return .unknown)) .plain else .unknown;
    defer dir.close(h.io);
    var it = dir.iterate();
    var any = false;
    while (it.next(h.io) catch null) |entry| {
        any = true;
        switch (deviceEncryption(h, entry.name, depth + 1)) {
            .encrypted => return .encrypted,
            else => {},
        }
    }
    _ = &any;
    return .plain;
}

/// /dev/mapper/<name> or /dev/dm-N or /dev/sda2 -> the /sys/class/block name.
fn blockName(h: Host, source: []const u8, buf: []u8) ?[]const u8 {
    if (std.mem.startsWith(u8, source, "/dev/mapper/")) {
        const want = source["/dev/mapper/".len..];
        var dir = (h.openDir("/sys/class/block") catch return null) orelse return null;
        defer dir.close(h.io);
        var it = dir.iterate();
        var path_buf: [256]u8 = undefined;
        var name_buf: [128]u8 = undefined;
        while (it.next(h.io) catch null) |entry| {
            if (!std.mem.startsWith(u8, entry.name, "dm-")) continue;
            const p = std.fmt.bufPrint(&path_buf, "/sys/class/block/{s}/dm/name", .{entry.name}) catch continue;
            const name = std.mem.trim(u8, h.readOpt(p, &name_buf) orelse continue, " \n");
            if (std.mem.eql(u8, name, want)) return std.fmt.bufPrint(buf, "{s}", .{entry.name}) catch null;
        }
        return null;
    }
    if (std.mem.startsWith(u8, source, "/dev/")) return std.fmt.bufPrint(buf, "{s}", .{source[5..]}) catch null;
    return null;
}

fn checkDiskEncryption(s: *scan.Scan) !void {
    const mounts = s.host.readAlloc(s.gpa, "/proc/self/mounts", 4 * 1024 * 1024) catch {
        try s.reduced("/proc/self/mounts unreadable", .{});
        return;
    };
    defer s.gpa.free(mounts);
    const source = mountSource(mounts, "/") orelse return;
    var name_buf: [128]u8 = undefined;
    const name = blockName(s.host, source, &name_buf) orelse {
        try s.reduced("root is mounted from {s}, not a block device this check can follow", .{source});
        return;
    };
    switch (deviceEncryption(s.host, name, 0)) {
        .encrypted => {},
        .unknown => try s.reduced("could not resolve /sys/class/block/{s}", .{name}),
        .plain => try s.add(.{
            .severity = .medium,
            .category = .hardening,
            .title = "Root filesystem is not encrypted",
            .description = try s.print("/ is mounted from {s} ({s}), which is not on a dm-crypt device. Anyone with the disk can read every file, credentials included.", .{ source, name }),
            .remediation = "Reinstall with full-disk encryption (LUKS), or encrypt data volumes; on laptops this matters most.",
            .subject = try s.dupe(source),
        }),
    }
}

// Firewall --------------------------------------------------------------------------------------

/// Count NFT_MSG_NEWRULE messages in a netlink reply batch; sets `done` at NLMSG_DONE.
pub fn countNftRules(data: []const u8, rules: *usize, done: *bool) error{ Malformed, NetlinkError }!void {
    var off: usize = 0;
    while (off + 16 <= data.len) {
        const len = std.mem.readInt(u32, data[off..][0..4], .little);
        const typ = std.mem.readInt(u16, data[off + 4 ..][0..2], .little);
        if (len < 16 or off + len > data.len) return error.Malformed;
        if (typ == 3) {
            done.* = true;
            return;
        }
        if (typ == 2) {
            // NLMSG_ERROR with error 0 is an ACK.
            if (len >= 20 and std.mem.readInt(i32, data[off + 16 ..][0..4], .little) != 0) return error.NetlinkError;
        } else if (typ == (10 << 8) | 6) rules.* += 1; // NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE
        off += std.mem.alignForward(usize, len, 4);
    }
}

fn nftRuleCount() !usize {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 12); // NETLINK_NETFILTER
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var req: [20]u8 align(4) = @splat(0);
    std.mem.writeInt(u32, req[0..4], 20, .little);
    std.mem.writeInt(u16, req[4..6], (10 << 8) | 7, .little); // NFT_MSG_GETRULE
    std.mem.writeInt(u16, req[6..8], 0x1 | 0x300, .little); // REQUEST | DUMP
    std.mem.writeInt(u32, req[8..12], 1, .little);
    // nfgenmsg: family NFPROTO_UNSPEC, version 0, res_id 0.
    var addr: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    if (linux.errno(linux.sendto(fd, &req, req.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl))) != .SUCCESS) return error.SendFailed;
    var buf: [64 * 1024]u8 align(4) = undefined;
    var rules: usize = 0;
    var done = false;
    var guard: usize = 0;
    while (!done and guard < 1 << 16) : (guard += 1) {
        const n = linux.recvfrom(fd, &buf, buf.len, 0, null, null);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            else => return error.RecvFailed,
        }
        if (n == 0) break;
        countNftRules(buf[0..n], &rules, &done) catch |e| switch (e) {
            error.NetlinkError => return error.AccessDenied,
            else => return e,
        };
    }
    return rules;
}

fn checkFirewall(s: *scan.Scan) !void {
    if (!s.host.live) {
        try s.reduced("netfilter netlink needs the live host", .{});
        return;
    }
    const rules = nftRuleCount() catch |e| {
        try s.reduced("nftables netlink dump failed: {t}", .{e});
        return;
    };
    var buf: [256]u8 = undefined;
    const legacy = std.mem.trim(u8, s.host.readOpt("/proc/net/ip_tables_names", &buf) orelse "", " \n");
    if (rules > 0 or legacy.len > 0) return;
    try s.add(.{
        .severity = .medium,
        .category = .hardening,
        .title = "No firewall rules",
        .description = "The kernel has no nftables rules and no legacy iptables tables loaded, so every listening service is reachable from every network the host is on.",
        .remediation = "Enable a default-deny inbound policy (ufw enable, firewalld, or an nftables ruleset) allowing only the services you publish.",
    });
}

// Containers ------------------------------------------------------------------------------------

fn checkContainers(s: *scan.Scan) !void {
    const in_container = s.context.role == .container;
    for ([_][]const u8{ "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock" }) |sock| {
        const st = s.host.stat(sock, true) catch continue;
        if (in_container) {
            try s.add(.{
                .check = "container.runtime_socket",
                .severity = .high,
                .category = .container,
                .title = "Container runtime socket mounted into a container",
                .description = try s.print("{s} is reachable inside this container. Access to the runtime socket is root on the host: anyone in the container can start a privileged container that mounts /.", .{sock}),
                .remediation = "Remove the socket mount; use a narrowly scoped proxy if the workload really needs the API.",
                .subject = sock,
            });
        } else if (st.worldWritable()) {
            try s.add(.{
                .check = "container.runtime_socket",
                .severity = .critical,
                .category = .container,
                .title = "Container runtime socket writable by every user",
                .description = try s.print("{s} has mode {o}: every local user can drive the container runtime, which is root on the host.", .{ sock, st.mode & 0o777 }),
                .remediation = try s.print("chmod 660 {s} (owned by root and the docker group) and restart the runtime with the default socket permissions.", .{sock}),
                .subject = sock,
            });
        }
    }
    if (in_container) {
        var buf: [4096]u8 = undefined;
        if (s.host.readOpt("/proc/1/status", &buf)) |text| {
            const st = @import("procfs.zig").parseStatus(text);
            // Full capability set in the bounding set: --privileged (or cap-add=ALL).
            if (st.cap_bnd != 0 and st.cap_eff & (1 << 21) != 0 and st.cap_eff == st.cap_bnd and @popCount(st.cap_bnd) >= 38) try s.add(.{
                .check = "container.privileged",
                .severity = .high,
                .category = .container,
                .title = "Container runs privileged",
                .description = "PID 1 in this container holds the full capability set including CAP_SYS_ADMIN, the signature of --privileged; escaping to the host is trivial.",
                .remediation = "Run without --privileged and add only the capabilities the workload needs.",
                .subject = "/proc/1/status",
            });
        }
        const mountinfo = s.host.readAlloc(s.gpa, "/proc/self/mountinfo", 4 * 1024 * 1024) catch null;
        defer if (mountinfo) |m| s.gpa.free(m);
        if (mountinfo) |m| {
            var lines = std.mem.splitScalar(u8, m, '\n');
            while (lines.next()) |line| {
                var f = std.mem.tokenizeScalar(u8, line, ' ');
                _ = f.next();
                _ = f.next();
                _ = f.next();
                _ = f.next(); // root
                const mp = f.next() orelse continue;
                const opts = f.next() orelse continue;
                if (!std.mem.eql(u8, mp, "/proc/sys") and !std.mem.eql(u8, mp, "/sys")) continue;
                if (!std.mem.startsWith(u8, opts, "rw")) continue;
                try s.add(.{
                    .check = "container.writable_kernel_fs",
                    .severity = .medium,
                    .category = .container,
                    .title = "Kernel interfaces mounted writable in a container",
                    .description = try s.print("{s} is mounted read-write inside the container, so it can change host kernel settings.", .{mp}),
                    .remediation = "Mount /proc/sys and /sys read-only (the runtime default); avoid --privileged.",
                    .subject = try s.dupe(mp),
                });
            }
        }
    }
    // The Docker API over plain TCP is unauthenticated root on the host.
    var socks: std.ArrayList(network.Socket) = .empty;
    defer socks.deinit(s.gpa);
    try network.readInet(s.gpa, s.host, "/proc", &socks);
    for (socks.items) |so| {
        if (so.proto != .tcp or so.state != .listen or so.local.port != 2375 or so.local.isLoopback()) continue;
        try s.add(.{
            .check = "container.docker_tcp",
            .severity = .critical,
            .category = .container,
            .title = "Docker API exposed over plain TCP",
            .description = try s.print("Something listens on {f}, the unencrypted, unauthenticated Docker API port. Anyone who reaches it controls the host; miners scan the internet for it.", .{so.local}),
            .remediation = "Remove -H tcp://0.0.0.0:2375 from the daemon flags; use the unix socket, or TLS on 2376 with client certificates.",
            .subject = "tcp/2375",
        });
    }
}

// Pending updates -------------------------------------------------------------------------------

/// Packages with a newer version in a security suite's index than installed (dpkg ordering).
pub fn pendingSecurity(gpa: std.mem.Allocator, status: []const u8, indexes: []const []const u8, out: *std.ArrayList(Pending)) !void {
    var installed: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer installed.deinit(gpa);
    var it = packages.StanzaIterator{ .text = status };
    while (it.next()) |st| if (st.installed() and st.package.len > 0) try installed.put(gpa, st.package, st.version);
    var best: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer best.deinit(gpa);
    for (indexes) |index| {
        var pit = packages.StanzaIterator{ .text = index };
        while (pit.next()) |st| {
            const have = installed.get(st.package) orelse continue;
            if (version.dpkg(st.version, have) != .gt) continue;
            const gop = try best.getOrPut(gpa, st.package);
            if (!gop.found_existing or version.dpkg(st.version, gop.value_ptr.*) == .gt) gop.value_ptr.* = st.version;
        }
    }
    var bit = best.iterator();
    while (bit.next()) |kv| try out.append(gpa, .{ .package = kv.key_ptr.*, .installed = installed.get(kv.key_ptr.*).?, .available = kv.value_ptr.* });
    std.mem.sort(Pending, out.items, {}, struct {
        fn lt(_: void, a: Pending, b: Pending) bool {
            return std.mem.order(u8, a.package, b.package) == .lt;
        }
    }.lt);
}

pub const Pending = struct { package: []const u8, installed: []const u8, available: []const u8 };

fn checkUpdates(s: *scan.Scan) !void {
    if (s.host.exists("/var/run/reboot-required") or s.host.exists("/run/reboot-required")) try s.add(.{
        .check = "hardening.reboot_required",
        .severity = .low,
        .category = .hardening,
        .title = "Reboot required to finish updates",
        .description = "Updates were installed that only take effect after a reboot (usually the kernel or libc); the running system still has the old code.",
        .remediation = "Reboot in a maintenance window.",
        .subject = "/run/reboot-required",
    });
    const status = s.host.readAlloc(s.arena(), "/var/lib/dpkg/status", packages.max_db_bytes) catch {
        if (s.host.exists("/var/lib/rpm") or s.host.exists("/lib/apk/db/installed"))
            try s.reduced("pending updates are computed from apt indexes only; rpm and apk repositories are not read", .{});
        return;
    };
    var indexes: std.ArrayList([]const u8) = .empty;
    defer indexes.deinit(s.gpa);
    var compressed: usize = 0;
    if (s.host.openDir("/var/lib/apt/lists") catch null) |dir| {
        var d = dir;
        defer d.close(s.host.io);
        var it = d.iterate();
        var path_buf: [512]u8 = undefined;
        while (it.next(s.host.io) catch null) |entry| {
            if (std.mem.indexOf(u8, entry.name, "-security_") == null and std.mem.indexOf(u8, entry.name, "_security_") == null) continue;
            if (!std.mem.endsWith(u8, entry.name, "_Packages")) {
                if (std.mem.indexOf(u8, entry.name, "_Packages.") != null) compressed += 1;
                continue;
            }
            const p = std.fmt.bufPrint(&path_buf, "/var/lib/apt/lists/{s}", .{entry.name}) catch continue;
            try indexes.append(s.gpa, s.host.readAlloc(s.arena(), p, 512 * 1024 * 1024) catch continue);
        }
    }
    if (compressed > 0) try s.reduced("{d} compressed apt index files (lz4, xz) were not read", .{compressed});
    if (indexes.items.len == 0) {
        try s.reduced("no apt security index in /var/lib/apt/lists; run apt-get update", .{});
        return;
    }
    var pending: std.ArrayList(Pending) = .empty;
    defer pending.deinit(s.gpa);
    try pendingSecurity(s.gpa, status, indexes.items, &pending);
    if (pending.items.len == 0) return;
    var list: std.ArrayList(u8) = .empty;
    for (pending.items[0..@min(pending.items.len, 25)]) |p| try list.print(s.arena(), "{s} {s} -> {s}; ", .{ p.package, p.installed, p.available });
    try s.add(.{
        .severity = .medium,
        .category = .hardening,
        .title = "Security updates are pending",
        .description = try s.print("{d} installed packages have a newer version in the security archive: {s}", .{ pending.items.len, list.items }),
        .remediation = "apt-get update && apt-get upgrade (or enable unattended-upgrades for the security pocket).",
        .details = try s.details(&.{.{ .key = "count", .value = try s.print("{d}", .{pending.items.len}) }}),
    });
}

// Tests -----------------------------------------------------------------------------------------

const Fixture = @import("../host.zig").Fixture;

test "mounts, nft replies and pending updates" {
    try std.testing.expectEqualStrings("/dev/mapper/vg-root", mountSource("sysfs /sys sysfs rw 0 0\n/dev/mapper/vg-root / ext4 rw 0 0\n", "/").?);
    var msg: [40]u8 = @splat(0);
    std.mem.writeInt(u32, msg[0..4], 20, .little);
    std.mem.writeInt(u16, msg[4..6], (10 << 8) | 6, .little);
    std.mem.writeInt(u32, msg[20..24], 16, .little);
    std.mem.writeInt(u16, msg[24..26], 3, .little);
    var rules: usize = 0;
    var done = false;
    try countNftRules(&msg, &rules, &done);
    try std.testing.expect(done and rules == 1);

    var pending: std.ArrayList(Pending) = .empty;
    defer pending.deinit(std.testing.allocator);
    try pendingSecurity(std.testing.allocator, "Package: openssl\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.1\n\nPackage: bash\nStatus: install ok installed\nVersion: 5.2.21-2ubuntu4\n", &.{"Package: openssl\nVersion: 3.0.13-0ubuntu3.4\n\nPackage: bash\nVersion: 5.2.21-2ubuntu4\n\nPackage: nginx\nVersion: 9\n"}, &pending);
    try std.testing.expectEqual(@as(usize, 1), pending.items.len);
    try std.testing.expectEqualStrings("openssl", pending.items[0].package);
}

test "fixture: each hardening check, with server and container downgrades visible in JSON" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/proc/sys/kernel/kptr_restrict", "0\n");
    try fx.file("/proc/sys/kernel/dmesg_restrict", "1\n");
    try fx.file("/proc/sys/kernel/unprivileged_bpf_disabled", "2\n");
    try fx.file("/proc/sys/kernel/randomize_va_space", "2\n");
    try fx.file("/proc/self/mounts", "/dev/sda2 / ext4 rw,relatime 0 0\n");
    try fx.file("/sys/class/block/sda2/dev", "8:2\n");
    try fx.dir("/sys/class/block/sda2/slaves");
    try fx.fileMode("/var/run/docker.sock", "", 0o666);
    try fx.file("/run/reboot-required", "");
    try fx.file("/var/lib/dpkg/status", "Package: openssl\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.1\n");
    try fx.file("/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble-security_main_binary-amd64_Packages", "Package: openssl\nVersion: 3.0.13-0ubuntu3.4\n");

    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{ "hardening", "container" }, .context = .{ .role = .server, .virtualized = true } });
    defer s.deinit();
    try s.runChecks(&checks);
    const want = [_][]const u8{ "hardening.sysctl.kptr_restrict", "hardening.mac", "hardening.disk_encryption", "container.runtime_socket", "hardening.reboot_required", "hardening.updates" };
    for (want) |w| {
        var found = false;
        for (s.findings.items) |f| if (std.mem.eql(u8, f.check, w)) {
            found = true;
        };
        if (!found) {
            std.debug.print("missing {s}\n", .{w});
            return error.TestUnexpectedResult;
        }
    }
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try s.writeJson(&out.writer, .{});
    try @import("../schema.zig").expectValid(std.testing.allocator, scan.report_schema, out.written());
    // Disk encryption on a server VM: downgraded, and the JSON says from what and why.
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"downgraded\":{\"from\":\"medium\"") != null);
    var coverage_firewall = false;
    for (s.coverage.items) |c| if (std.mem.eql(u8, c.check, "hardening.firewall")) {
        coverage_firewall = true;
    };
    try std.testing.expect(coverage_firewall);

    // The same host as a container: sysctls and MAC are the host's business.
    var c = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{"hardening"}, .context = .{ .role = .container } });
    defer c.deinit();
    try c.runChecks(&checks);
    for (c.findings.items) |f| if (std.mem.startsWith(u8, f.check, "hardening.sysctl") or std.mem.eql(u8, f.check, "hardening.mac")) {
        try std.testing.expectEqual(finding.Severity.info, f.severity);
        try std.testing.expect(f.downgraded != null);
    };
}

test "live: hardening checks run on the CI image" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const h = try Host.openLive(std.testing.io);
    defer h.close();
    var s = scan.Scan.init(std.testing.allocator, h, .{ .only = &.{ "hardening", "container" } });
    defer s.deinit();
    try s.runChecks(&checks);
    for (s.findings.items) |f| std.debug.print("hardening on CI: {s} {t} {s}\n", .{ f.check, f.severity, f.title });
    for (s.coverage.items) |c| std.debug.print("hardening coverage: {s}: {s}\n", .{ c.check, c.reason });
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try s.writeJson(&out.writer, .{});
    try @import("../schema.zig").expectValid(std.testing.allocator, scan.report_schema, out.written());
}
