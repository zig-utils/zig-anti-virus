//! Server context: what kind of machine this is and which services it runs. Findings the role
//! explains are downgraded, not hidden: the JSON keeps the original severity and the reason.
//! For example a cloud VM without disk encryption is normal (the provider encrypts volumes and
//! physical theft is outside its threat model), while the same on a laptop is a real gap.
const std = @import("std");
const Host = @import("host.zig").Host;
const finding = @import("finding.zig");

pub const Role = enum { workstation, server, container };

pub const Service = enum {
    sshd,
    nginx,
    apache,
    caddy,
    haproxy,
    traefik,
    envoy,
    postgres,
    mysql,
    redis,
    memcached,
    mongodb,
    docker,
    containerd,
    kubelet,
    bun,
    node,
    php_fpm,
    postfix,
    exim,
    dovecot,
    named,
    unbound,
    dnsmasq,
    systemd_resolved,
    chronyd,
    ntpd,
    cupsd,
    avahi,
    zavd,
    clamd,

    /// Process names (comm, up to 15 bytes) that identify the service.
    pub fn names(s: Service) []const []const u8 {
        return switch (s) {
            .sshd => &.{"sshd"},
            .nginx => &.{"nginx"},
            .apache => &.{ "apache2", "httpd" },
            .caddy => &.{"caddy"},
            .haproxy => &.{"haproxy"},
            .traefik => &.{"traefik"},
            .envoy => &.{"envoy"},
            .postgres => &.{ "postgres", "postmaster" },
            .mysql => &.{ "mysqld", "mariadbd" },
            .redis => &.{ "redis-server", "valkey-server" },
            .memcached => &.{"memcached"},
            .mongodb => &.{"mongod"},
            .docker => &.{"dockerd"},
            .containerd => &.{"containerd"},
            .kubelet => &.{"kubelet"},
            .bun => &.{"bun"},
            .node => &.{ "node", "nodejs" },
            .php_fpm => &.{ "php-fpm", "php-fpm8.1", "php-fpm8.2", "php-fpm8.3", "php-fpm8.4" },
            .postfix => &.{"master"},
            .exim => &.{"exim4"},
            .dovecot => &.{"dovecot"},
            .named => &.{"named"},
            .unbound => &.{"unbound"},
            .dnsmasq => &.{"dnsmasq"},
            .systemd_resolved => &.{"systemd-resolve"},
            .chronyd => &.{"chronyd"},
            .ntpd => &.{"ntpd"},
            .cupsd => &.{"cupsd"},
            .avahi => &.{"avahi-daemon"},
            .zavd => &.{"zavd"},
            .clamd => &.{"clamd"},
        };
    }

    /// Ports the service normally listens on. Listeners outside these still get judged by the
    /// owning process, never by port number alone.
    pub fn ports(s: Service) []const u16 {
        return switch (s) {
            .sshd => &.{22},
            .nginx, .apache, .caddy, .haproxy, .traefik, .envoy => &.{ 80, 443, 8080, 8443 },
            .postgres => &.{5432},
            .mysql => &.{ 3306, 33060 },
            .redis => &.{6379},
            .memcached => &.{11211},
            .mongodb => &.{27017},
            .docker => &.{},
            .containerd => &.{},
            .kubelet => &.{ 10248, 10250 },
            .bun, .node => &.{ 3000, 3001, 8000, 8080 },
            .php_fpm => &.{9000},
            .postfix, .exim => &.{ 25, 465, 587 },
            .dovecot => &.{ 110, 143, 993, 995, 4190 },
            .named, .unbound, .dnsmasq => &.{ 53, 853 },
            .systemd_resolved => &.{ 53, 5355 },
            .chronyd => &.{ 123, 323 },
            .ntpd => &.{123},
            .cupsd => &.{631},
            .avahi => &.{5353},
            .zavd, .clamd => &.{3310},
        };
    }

    pub fn fromComm(comm: []const u8) ?Service {
        inline for (comptime std.enums.values(Service)) |s| {
            for (s.names()) |n| if (std.mem.eql(u8, comm, n)) return s;
        }
        return null;
    }
};

pub const Context = struct {
    role: Role,
    virtualized: bool = false,
    desktop: bool = false,
    services: std.EnumSet(Service) = .empty,

    pub fn has(c: Context, s: Service) bool {
        return c.services.contains(s);
    }

    /// A port some running service is expected to listen on.
    pub fn expectsPort(c: Context, port: u16) bool {
        var it = c.services.iterator();
        while (it.next()) |s| for (s.ports()) |p| if (p == port) return true;
        return false;
    }

    pub fn isServerLike(c: Context) bool {
        return c.role != .workstation or c.virtualized;
    }
};

const desktop_processes = [_][]const u8{ "Xorg", "Xwayland", "gnome-shell", "plasmashell", "kwin_wayland", "kwin_x11", "xfce4-session", "mutter", "sway", "weston", "Hyprland", "cinnamon", "mate-session", "lxsession" };

/// Detect the context of a Linux host from /proc, /sys and marker files.
pub fn detectLinux(h: Host) Context {
    var c: Context = .{ .role = .server };
    if (h.openDir("/proc") catch null) |dir| {
        var d = dir;
        defer d.close(h.io);
        var it = d.iterate();
        var path_buf: [64]u8 = undefined;
        var comm_buf: [64]u8 = undefined;
        while (it.next(h.io) catch null) |entry| {
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/comm", .{pid}) catch continue;
            const comm = std.mem.trimEnd(u8, h.readOpt(path, &comm_buf) orelse continue, "\n");
            if (Service.fromComm(comm)) |s| c.services.insert(s);
            for (desktop_processes) |p| if (std.mem.eql(u8, comm, p)) {
                c.desktop = true;
            };
        }
    }
    c.virtualized = detectVirtualization(h);
    if (detectContainer(h)) c.role = .container else if (c.desktop) c.role = .workstation;
    return c;
}

fn detectVirtualization(h: Host) bool {
    var buf: [256]u8 = undefined;
    const vendors = [_][]const u8{ "qemu", "kvm", "vmware", "virtualbox", "xen", "microsoft corporation", "amazon ec2", "google", "digitalocean", "hetzner", "openstack", "parallels", "bochs", "innotek", "upcloud", "linode", "vultr", "scaleway", "oracle" };
    for ([_][]const u8{ "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/board_vendor" }) |path| {
        const text = h.readOpt(path, &buf) orelse continue;
        var lower: [256]u8 = undefined;
        const l = std.ascii.lowerString(&lower, text);
        for (vendors) |v| if (std.mem.indexOf(u8, l, v) != null) return true;
    }
    if (h.exists("/sys/hypervisor/type")) return true;
    // The cpuinfo `hypervisor` flag (x86): look only at the flags line of the first CPU.
    var cpu_buf: [8192]u8 = undefined;
    if (h.readOpt("/proc/cpuinfo", &cpu_buf)) |text| {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, "flags")) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse break;
            var words = std.mem.tokenizeScalar(u8, line[colon + 1 ..], ' ');
            while (words.next()) |w| if (std.mem.eql(u8, w, "hypervisor")) return true;
            break;
        }
    }
    return false;
}

fn detectContainer(h: Host) bool {
    if (h.exists("/.dockerenv") or h.exists("/run/.containerenv")) return true;
    var buf: [4096]u8 = undefined;
    if (h.readOpt("/proc/1/environ", &buf)) |env| {
        var vars = std.mem.splitScalar(u8, env, 0);
        while (vars.next()) |v| if (std.mem.startsWith(u8, v, "container=")) return true;
    }
    if (h.readOpt("/proc/1/cgroup", &buf)) |cg| {
        const markers = [_][]const u8{ "/docker/", "/kubepods", "/containerd/", "/lxc/", "/libpod-" };
        for (markers) |m| if (std.mem.indexOf(u8, cg, m) != null) return true;
    }
    return false;
}

/// When a server context explains a finding, and what it becomes.
pub const Condition = enum { server_like, container, virtualized };

pub const Rule = struct {
    check: []const u8,
    when: Condition,
    to: finding.Severity,
    reason: []const u8,
};

pub const rules = [_]Rule{
    .{ .check = "hardening.disk_encryption", .when = .server_like, .to = .info, .reason = "servers and cloud VMs rely on provider or volume encryption; physical theft of the disk is outside their threat model" },
    .{ .check = "hardening.firewall", .when = .container, .to = .info, .reason = "inside a container the host or orchestrator enforces network policy" },
    .{ .check = "hardening.mac", .when = .container, .to = .info, .reason = "a container cannot load its own AppArmor or SELinux policy; the host's applies" },
    .{ .check = "hardening.sysctl", .when = .container, .to = .info, .reason = "kernel sysctls belong to the container host, not the container" },
    .{ .check = "kernel.taint", .when = .container, .to = .info, .reason = "the kernel belongs to the container host" },
    .{ .check = "process.cpu", .when = .server_like, .to = .low, .reason = "servers run sustained CPU loads (builds, databases, batch jobs)" },
    .{ .check = "access.sshd_password", .when = .server_like, .to = .low, .reason = "many servers keep password authentication behind other controls; still prefer keys only" },
};

fn conditionHolds(c: Context, cond: Condition) bool {
    return switch (cond) {
        .server_like => c.isServerLike(),
        .container => c.role == .container,
        .virtualized => c.virtualized,
    };
}

/// Lower a finding's severity when a rule for its check applies. Rules match a check id exactly or
/// as a dotted prefix (`hardening.sysctl` covers `hardening.sysctl.kptr_restrict`).
pub fn apply(c: Context, f: *finding.Finding) void {
    for (rules) |r| {
        const matches = std.mem.eql(u8, f.check, r.check) or
            (std.mem.startsWith(u8, f.check, r.check) and f.check.len > r.check.len and f.check[r.check.len] == '.');
        if (!matches or !conditionHolds(c, r.when)) continue;
        if (@backingInt(r.to) >= @backingInt(f.severity)) continue;
        f.downgraded = .{ .from = f.severity, .reason = r.reason };
        f.severity = r.to;
        return;
    }
}

test "context detection from a fixture /proc and /sys" {
    const Fixture = @import("host.zig").Fixture;
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/proc/1/comm", "systemd\n");
    try fx.file("/proc/812/comm", "sshd\n");
    try fx.file("/proc/900/comm", "nginx\n");
    try fx.file("/proc/self/comm", "zav\n");
    try fx.file("/sys/class/dmi/id/sys_vendor", "QEMU\n");
    const c = detectLinux(fx.host(.linux));
    try std.testing.expectEqual(Role.server, c.role);
    try std.testing.expect(c.virtualized);
    try std.testing.expect(c.has(.sshd) and c.has(.nginx) and !c.has(.postgres));
    try std.testing.expect(c.expectsPort(443) and c.expectsPort(22) and !c.expectsPort(5432));

    try fx.file("/proc/1200/comm", "gnome-shell\n");
    try fx.file("/.dockerenv", "");
    try std.testing.expectEqual(Role.container, detectLinux(fx.host(.linux)).role);
    try fx.remove("/.dockerenv");
    try std.testing.expectEqual(Role.workstation, detectLinux(fx.host(.linux)).role);
}

test "server context downgrades what it explains and nothing else" {
    var f: finding.Finding = .{ .check = "hardening.disk_encryption", .severity = .medium, .category = .hardening, .title = "", .description = "", .remediation = "" };
    apply(.{ .role = .server }, &f);
    try std.testing.expectEqual(finding.Severity.info, f.severity);
    try std.testing.expectEqual(finding.Severity.medium, f.downgraded.?.from);

    var laptop: finding.Finding = .{ .check = "hardening.disk_encryption", .severity = .medium, .category = .hardening, .title = "", .description = "", .remediation = "" };
    apply(.{ .role = .workstation }, &laptop);
    try std.testing.expectEqual(finding.Severity.medium, laptop.severity);
    try std.testing.expect(laptop.downgraded == null);

    var sysctl: finding.Finding = .{ .check = "hardening.sysctl.kptr_restrict", .severity = .low, .category = .hardening, .title = "", .description = "", .remediation = "" };
    apply(.{ .role = .container }, &sysctl);
    try std.testing.expectEqual(finding.Severity.info, sysctl.severity);

    var prefix_only: finding.Finding = .{ .check = "hardening.sysctlx", .severity = .low, .category = .hardening, .title = "", .description = "", .remediation = "" };
    apply(.{ .role = .container }, &prefix_only);
    try std.testing.expectEqual(finding.Severity.low, prefix_only.severity);

    var miner: finding.Finding = .{ .check = "process.miner", .severity = .critical, .category = .malware, .title = "", .description = "", .remediation = "" };
    apply(.{ .role = .server, .virtualized = true }, &miner);
    try std.testing.expectEqual(finding.Severity.critical, miner.severity);
}
