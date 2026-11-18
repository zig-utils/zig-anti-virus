//! macOS host checks for the persistence and tampering that matter on developer machines:
//! LaunchAgents and LaunchDaemons, login items (background task management databases),
//! configuration profiles, unsigned or ad-hoc executables in user Library paths, and downloaded
//! executables without the com.apple.quarantine attribute. Locations macOS protects with TCC or
//! root-only permissions are reported as reduced coverage (grant Full Disk Access or run as root).
const std = @import("std");
const scan = @import("../scan.zig");
const tokens = @import("../tokens.zig");
const finding = @import("../finding.zig");
const plist = @import("plist.zig");
const macho = @import("macho.zig");
const Host = @import("../host.zig").Host;

pub const checks = [_]scan.Check{
    .{ .id = "macos.launchd", .category = .persistence, .tier = .fast, .privilege = .partial, .os = .macos, .summary = "LaunchAgents and LaunchDaemons running from temp dirs, risky commands, unsigned programs, new jobs", .run = checkLaunchd },
    .{ .id = "macos.login_items", .category = .persistence, .tier = .fast, .privilege = .root, .os = .macos, .summary = "Login and background items registered with background task management", .run = checkLoginItems },
    .{ .id = "macos.profiles", .category = .persistence, .tier = .fast, .privilege = .root, .os = .macos, .summary = "Configuration profiles installed since the baseline", .run = checkProfiles },
    .{ .id = "macos.quarantine", .category = .malware, .tier = .fast, .privilege = .partial, .os = .macos, .summary = "Downloaded executables missing the com.apple.quarantine attribute", .run = checkQuarantine },
    .{ .id = "macos.unsigned_library", .category = .malware, .tier = .deep, .privilege = .partial, .os = .macos, .summary = "Unsigned or ad-hoc signed executables in user Library paths", .run = checkUnsignedLibrary },
};

/// Paths on the sealed system volume belong to macOS, the counterpart of package ownership.
pub fn systemOwner(path: []const u8) ?[]const u8 {
    const sealed = [_][]const u8{ "/System/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/share/", "/Library/Apple/" };
    for (sealed) |p| if (std.mem.startsWith(u8, path, p)) return "macOS";
    return null;
}

pub fn isMacTemp(path: []const u8) bool {
    const prefixes = [_][]const u8{ "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/", "/var/folders/", "/private/var/folders/" };
    for (prefixes) |p| if (std.mem.startsWith(u8, path, p)) return true;
    return false;
}

fn hiddenComponent(path: []const u8) bool {
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |p| {
        if (p.len < 2 or p[0] != '.' or std.mem.eql(u8, p, "..")) continue;
        // Dot directories in home directories host dev tools; only dots-and-spaces names hide.
        var only = true;
        for (p) |c| if (c != '.' and c != ' ') {
            only = false;
        };
        if (only) return true;
    }
    return false;
}

/// Home directories: /Users/* (not Shared) and root's /var/root.
fn homes(s: *scan.Scan) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (s.host.openDir("/Users") catch null) |dir| {
        var d = dir;
        defer d.close(s.host.io);
        var it = d.iterate();
        while (it.next(s.host.io) catch null) |e| {
            if (e.kind != .directory or e.name[0] == '.' or std.mem.eql(u8, e.name, "Shared") or std.mem.eql(u8, e.name, "Guest")) continue;
            try out.append(s.arena(), try s.print("/Users/{s}", .{e.name}));
        }
    }
    if (s.host.exists("/var/root/Library")) try out.append(s.arena(), "/var/root");
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    return out.items;
}

fn listFiles(s: *scan.Scan, dir_path: []const u8, denied: *usize) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var dir = (s.host.openDir(dir_path) catch {
        denied.* += 1;
        return out.items;
    }) orelse return out.items;
    defer dir.close(s.host.io);
    var it = dir.iterate();
    while (it.next(s.host.io) catch null) |e| {
        if (e.name[0] == '.') continue;
        try out.append(s.arena(), try s.print("{s}/{s}", .{ dir_path, e.name }));
        if (out.items.len > 5000) break;
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    return out.items;
}

// launchd ---------------------------------------------------------------------------------------

pub const Job = struct {
    label: []const u8,
    program: []const u8,
    args: []const []const u8,
    command: []const u8,
    working_directory: []const u8 = "",
    /// PATH from EnvironmentVariables, or launchd's default.
    path: []const u8 = "/usr/bin:/bin:/usr/sbin:/sbin",
};

/// The executable launchd will run: relative names resolve against WorkingDirectory, bare
/// names through the job's PATH (launchd execs ProgramArguments with a PATH search).
pub fn resolveProgram(s: *scan.Scan, job: Job) !?[]const u8 {
    if (job.program.len > 0 and job.program[0] == '/') return job.program;
    if (std.mem.indexOfScalar(u8, job.program, '/') != null) {
        if (job.working_directory.len == 0) return null;
        return try s.print("{s}/{s}", .{ std.mem.trimEnd(u8, job.working_directory, "/"), job.program });
    }
    var dirs = std.mem.tokenizeScalar(u8, job.path, ':');
    while (dirs.next()) |d| {
        const candidate = try s.print("{s}/{s}", .{ std.mem.trimEnd(u8, d, "/"), job.program });
        if (s.host.exists(candidate)) return candidate;
    }
    return null;
}

pub fn jobOf(arena: std.mem.Allocator, v: plist.Value) !?Job {
    if (v != .dict) return null;
    var args: std.ArrayList([]const u8) = .empty;
    if (v.getArray("ProgramArguments")) |a| for (a) |x| if (x == .string) try args.append(arena, x.string);
    const program = v.getString("Program") orelse (if (args.items.len > 0) args.items[0] else return null);
    var cmd: std.ArrayList(u8) = .empty;
    for (args.items, 0..) |a, i| {
        if (i > 0) try cmd.append(arena, ' ');
        try cmd.appendSlice(arena, a);
    }
    if (args.items.len == 0) try cmd.appendSlice(arena, program);
    var path: []const u8 = "/usr/bin:/bin:/usr/sbin:/sbin";
    if (v.dict.get("EnvironmentVariables")) |env| if (env == .dict) if (env.dict.get("PATH")) |p| if (p == .string) {
        path = p.string;
    };
    return .{ .label = v.getString("Label") orelse "", .program = program, .args = args.items, .command = cmd.items, .working_directory = v.getString("WorkingDirectory") orelse "", .path = path };
}

fn checkLaunchd(s: *scan.Scan) !void {
    var denied: usize = 0;
    var dirs: std.ArrayList([]const u8) = .empty;
    try dirs.appendSlice(s.arena(), &.{ "/Library/LaunchAgents", "/Library/LaunchDaemons" });
    for (try homes(s)) |h| try dirs.append(s.arena(), try s.print("{s}/Library/LaunchAgents", .{h}));
    for (dirs.items) |dir| for (try listFiles(s, dir, &denied)) |path| {
        if (!std.mem.endsWith(u8, path, ".plist")) continue;
        const bytes = s.host.readAlloc(s.arena(), path, 4 * 1024 * 1024) catch |e| {
            if (e == error.AccessDenied) denied += 1;
            continue;
        };
        const v = plist.parse(s.arena(), bytes) catch {
            try s.reduced("{s}: not a valid property list", .{path});
            continue;
        };
        const job = (try jobOf(s.arena(), v)) orelse continue;
        try judgeJob(s, path, job);
        const tracked = s.baseline.tracks("macos.launchd");
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(job.command, &digest, .{});
        if (try s.drift("macos.launchd", path, try s.print("{x}", .{digest[0..16]})) and tracked) try s.add(.{
            .severity = .medium,
            .category = .persistence,
            .title = "launchd job added or changed since the baseline",
            .description = try s.print("{s} ({s}) is new or runs something different since the last accepted scan: {s}", .{ path, job.label, job.command }),
            .remediation = "Confirm you installed it; accept it with zav host --update-baseline, or unload and delete it (launchctl bootout, then remove the plist).",
            .subject = path,
        });
    };
    if (denied > 0) try s.reduced("{d} launchd locations were unreadable", .{denied});
}

fn judgeJob(s: *scan.Scan, path: []const u8, job: Job) !void {
    // The program, and any argument that is a path (sh /tmp/x.sh, osascript ~/x.scpt).
    var risky: ?[]const u8 = null;
    if (isMacTemp(job.program) or hiddenComponent(job.program)) risky = job.program;
    for (job.args) |a| if (a.len > 0 and a[0] == '/' and (isMacTemp(a) or hiddenComponent(a))) {
        risky = a;
    };
    const cmd_risk = tokens.commandRisk(job.command);
    if (risky != null or (cmd_risk != null and cmd_risk.? != .temp_exec)) {
        try s.add(.{
            .severity = if (cmd_risk != null and cmd_risk.? != .temp_exec) .critical else .high,
            .category = .persistence,
            .title = "launchd job runs from a temp directory or runs a risky command",
            .description = try s.print("{s} ({s}) runs '{s}'{s}{s}. Malware persists on macOS through LaunchAgents that point into temp or hidden locations.", .{ path, job.label, job.command, if (risky) |r| try s.print(", using {s} from a world-writable or hidden location", .{r}) else "", if (cmd_risk) |r| try s.print(", which {s}", .{r.describe()}) else "" }),
            .remediation = try s.print("Unload it (launchctl bootout gui/$(id -u) {s} or system {s}), delete the plist and the program, and check how it was installed.", .{ path, path }),
            .subject = path,
            .details = try s.details(&.{ .{ .key = "label", .value = job.label }, .{ .key = "program", .value = job.program } }),
        });
        return;
    }
    const resolved = try resolveProgram(s, job);
    const program = resolved orelse job.program;
    if (systemOwner(program) != null) return;
    const st = (if (resolved) |r| s.host.stat(r, true) catch null else null) orelse {
        try s.add(.{
            .severity = .low,
            .category = .persistence,
            .title = "launchd job points at a missing program",
            .description = try s.print("{s} ({s}) runs {s}, which does not exist{s}. Leftovers of uninstalled software look like this; so does a job waiting for a payload.", .{ path, job.label, program, if (resolved == null) " in its working directory or PATH" else "" }),
            .remediation = "Remove the plist if the software is gone.",
            .subject = path,
        });
        return;
    };
    if (st.kind() != .file) return;
    if (s.options.scanner) |scanner| if (scanner.scan(s.host, program)) |name| {
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "launchd job runs known malware",
            .description = try s.print("{s} runs {s}, detected as {s}.", .{ path, program, name }),
            .remediation = "Unload the job, delete the plist and the program, and investigate.",
            .subject = path,
        });
        return;
    };
    const signing = macho.classifyPath(s.host, program) catch return;
    if (signing == .unsigned) try s.add(.{
        .severity = .medium,
        .category = .persistence,
        .title = "launchd job runs an unsigned program",
        .description = try s.print("{s} ({s}) runs {s}, a Mach-O binary with no code signature. Distributed macOS software is signed; unsigned persistent programs deserve a look.", .{ path, job.label, program }),
        .remediation = try s.print("Verify the program (codesign -dv {s}; spctl -a -vv {s}) and remove the job if you do not recognise it.", .{ program, program }),
        .subject = path,
        .details = try s.details(&.{.{ .key = "program", .value = program }}),
    });
}

// Login items, profiles -------------------------------------------------------------------------

fn pathFromItem(text: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, text, "file://")) {
        const p = text["file://".len..];
        return if (p.len > 0 and p[0] == '/') p else null;
    }
    if (text.len > 1 and text[0] == '/' and std.mem.indexOfScalar(u8, text, ' ') == null) return text;
    return null;
}

fn checkLoginItems(s: *scan.Scan) !void {
    var denied: usize = 0;
    var files: std.ArrayList([]const u8) = .empty;
    for (try listFiles(s, "/private/var/db/com.apple.backgroundtaskmanagement", &denied)) |p| {
        if (std.mem.endsWith(u8, p, ".btm")) try files.append(s.arena(), p);
    }
    for (try homes(s)) |h| try files.append(s.arena(), try s.print("{s}/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm", .{h}));
    var parsed: usize = 0;
    for (files.items) |path| {
        const bytes = s.host.readAlloc(s.arena(), path, 64 * 1024 * 1024) catch |e| {
            if (e == error.AccessDenied) denied += 1;
            continue;
        };
        const v = plist.parse(s.arena(), bytes) catch continue;
        parsed += 1;
        var strings: std.ArrayList([]const u8) = .empty;
        try plist.collectStrings(s.arena(), v, &strings, 0);
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(s.gpa);
        for (strings.items) |str| {
            const item = pathFromItem(str) orelse continue;
            if ((try seen.getOrPut(s.gpa, item)).found_existing) continue;
            if (isMacTemp(item) or hiddenComponent(item)) try s.add(.{
                .severity = .high,
                .category = .persistence,
                .title = "Login item in a temp or hidden location",
                .description = try s.print("A background or login item registered in {s} points at {s}.", .{ path, item }),
                .remediation = "Remove it in System Settings > General > Login Items, delete the file and investigate.",
                .subject = item,
            });
            const tracked = s.baseline.tracks("macos.login_item");
            if (try s.drift("macos.login_item", "btm", item) and tracked) try s.add(.{
                .severity = .medium,
                .category = .persistence,
                .title = "Login item added since the baseline",
                .description = try s.print("{s} was registered as a login or background item since the last accepted scan.", .{item}),
                .remediation = "Confirm you installed it; accept it with zav host --update-baseline.",
                .subject = item,
            });
        }
    }
    if (parsed == 0 and denied > 0) try s.reduced("background task management databases need root or Full Disk Access", .{});
}

fn checkProfiles(s: *scan.Scan) !void {
    var denied: usize = 0;
    for ([_][]const u8{ "/private/var/db/ConfigurationProfiles/Store", "/Library/Managed Preferences" }) |dir| {
        for (try listFiles(s, dir, &denied)) |p| {
            const tracked = s.baseline.tracks("macos.profile");
            if (try s.drift("macos.profile", dir, tokens.basename(p)) and tracked) try s.add(.{
                .severity = .medium,
                .category = .persistence,
                .title = "Configuration profile installed since the baseline",
                .description = try s.print("{s} appeared since the last accepted scan. Profiles can install root certificates, proxies and managed settings; adware and MDM-style attacks use them.", .{p}),
                .remediation = "Review it in System Settings > Privacy & Security > Profiles and remove anything you did not install.",
                .subject = p,
            });
        }
    }
    if (denied > 0) try s.reduced("configuration profile stores need root", .{});
}

// Quarantine and signatures ---------------------------------------------------------------------

/// What a downloaded file is, for the quarantine check.
pub fn downloadKind(name: []const u8, head: []const u8) ?[]const u8 {
    const exts = [_][]const u8{ ".app", ".pkg", ".dmg", ".command", ".tool", ".sh", ".mpkg" };
    for (exts) |e| if (std.ascii.endsWithIgnoreCase(name, e)) return e;
    if (head.len >= 4) {
        const le = std.mem.readInt(u32, head[0..4], .little);
        const be = std.mem.readInt(u32, head[0..4], .big);
        if (le == 0xfeedfacf or le == 0xfeedface or be == 0xcafebabe) return "Mach-O";
    }
    return null;
}

fn checkQuarantine(s: *scan.Scan) !void {
    var denied: usize = 0;
    for (try homes(s)) |h| for ([_][]const u8{ "Downloads", "Desktop" }) |sub| {
        const dir = try s.print("{s}/{s}", .{ h, sub });
        for (try listFiles(s, dir, &denied)) |p| {
            var head_buf: [8]u8 = undefined;
            const head = s.host.readOpt(p, &head_buf) orelse "";
            const kind = downloadKind(tokens.basename(p), head) orelse continue;
            var xbuf: [256]u8 = undefined;
            _ = s.host.getXattr(p, "com.apple.quarantine", &xbuf) catch |e| switch (e) {
                error.NoData => {
                    try s.add(.{
                        .severity = .medium,
                        .category = .malware,
                        .title = "Downloaded executable without a quarantine attribute",
                        .description = try s.print("{s} ({s}) has no com.apple.quarantine attribute, so Gatekeeper will not check it on first launch. Browsers set it; downloads by curl or a script, or a deliberately stripped attribute, do not.", .{ p, kind }),
                        .remediation = try s.print("Do not open it until verified (codesign -dv, spctl -a -vv); restore the check with xattr -w com.apple.quarantine \"0081;$(printf %x $(date +%s));zav;\" {s}.", .{p}),
                        .subject = p,
                    });
                    continue;
                },
                error.AccessDenied => {
                    denied += 1;
                    continue;
                },
                else => continue,
            };
        }
    };
    if (denied > 0) try s.reduced("{d} Downloads or Desktop entries were unreadable; grant Full Disk Access", .{denied});
}

fn checkUnsignedLibrary(s: *scan.Scan) !void {
    var denied: usize = 0;
    var budget: usize = 200_000;
    for (try homes(s)) |h| for ([_][]const u8{ "Library/Application Support", "Library/LaunchAgents", "Library/Scripts" }) |sub| {
        try walkUnsigned(s, try s.print("{s}/{s}", .{ h, sub }), 0, &budget, &denied);
    };
    if (denied > 0) try s.reduced("{d} Library directories were unreadable; grant Full Disk Access", .{denied});
}

fn walkUnsigned(s: *scan.Scan, dir_path: []const u8, depth: u8, budget: *usize, denied: *usize) !void {
    if (depth > 6 or budget.* == 0) return;
    var dir = (s.host.openDir(dir_path) catch {
        denied.* += 1;
        return;
    }) orelse return;
    defer dir.close(s.host.io);
    var it = dir.iterate();
    while (it.next(s.host.io) catch null) |e| {
        if (budget.* == 0) return;
        budget.* -= 1;
        const child = try s.print("{s}/{s}", .{ dir_path, e.name });
        switch (e.kind) {
            .directory => try walkUnsigned(s, child, depth + 1, budget, denied),
            .file => {
                const st = @import("../sys.zig").statAt(dir, e.name, false) catch continue;
                if (!st.executable() or st.size < 4096) continue;
                const signing = macho.classifyPath(s.host, child) catch continue;
                if (signing != .unsigned and signing != .adhoc) continue;
                try s.add(.{
                    .severity = if (signing == .unsigned) .medium else .low,
                    .category = .malware,
                    .title = if (signing == .unsigned) "Unsigned executable in a user Library path" else "Ad-hoc signed executable in a user Library path",
                    .description = try s.print("{s} is {s}. Software installed in Library normally carries a Developer ID signature; implants dropped there usually do not.", .{ child, if (signing == .unsigned) "a Mach-O binary with no signature" else "only ad-hoc signed (no identity)" }),
                    .remediation = try s.print("Check what it belongs to (codesign -dv {s}); delete it if it is not part of software you use.", .{child}),
                    .subject = child,
                });
            },
            else => {},
        }
    }
}

// Tests -----------------------------------------------------------------------------------------

const Fixture = @import("../host.zig").Fixture;

test "launchd job extraction and helpers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const v = try plist.parse(arena.allocator(), &plist.fixture_bplist);
    const job = (try jobOf(arena.allocator(), v)).?;
    try std.testing.expectEqualStrings("/tmp/a", job.program);
    try std.testing.expect(isMacTemp("/private/tmp/x"));
    try std.testing.expect(hiddenComponent("/Users/a/.../x"));
    try std.testing.expect(!hiddenComponent("/Users/a/.config/x"));
    try std.testing.expectEqualStrings("macOS", systemOwner("/usr/libexec/x").?);
    try std.testing.expect(systemOwner("/usr/local/bin/x") == null);
    try std.testing.expectEqualStrings("/Applications/X.app", pathFromItem("file:///Applications/X.app").?);
    try std.testing.expectEqualStrings(".dmg", downloadKind("Setup.DMG", "").?);
    try std.testing.expect(downloadKind("notes.txt", "hello") == null);
}

test "fixture: a LaunchAgent pointing at a script in /tmp is reported" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/Users/alice/Library/LaunchAgents/com.update.helper.plist",
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>Label</key><string>com.update.helper</string>
        \\<key>ProgramArguments</key><array><string>/bin/bash</string><string>/tmp/.u/run.sh</string></array>
        \\<key>RunAtLoad</key><true/>
        \\</dict></plist>
    );
    try fx.file("/Library/LaunchDaemons/com.vendor.agent.plist", &plist.fixture_bplist);
    var unsigned: [256]u8 = undefined;
    try fx.fileMode("/Library/Vendor/agent", macho.buildFixture(&unsigned, .none), 0o755);
    try fx.file("/Library/LaunchAgents/com.vendor.signed.plist",
        \\<plist version="1.0"><dict><key>Label</key><string>com.vendor.unsigned</string>
        \\<key>Program</key><string>/Library/Vendor/agent</string></dict></plist>
    );
    try fx.file("/Library/LaunchAgents/com.apple.ok.plist",
        \\<plist version="1.0"><dict><key>Label</key><string>ok</string>
        \\<key>Program</key><string>/usr/libexec/ok</string></dict></plist>
    );
    var s = scan.Scan.init(std.testing.allocator, fx.host(.macos), .{ .only = &.{"macos"}, .context = .{ .role = .workstation } });
    defer s.deinit();
    try s.runChecks(&checks);
    var tmp_agent = false;
    var unsigned_found = false;
    for (s.findings.items) |f| {
        const subj = f.subject orelse "";
        if (std.mem.endsWith(u8, subj, "com.update.helper.plist") and f.severity == .high) tmp_agent = true;
        if (std.mem.endsWith(u8, subj, "com.vendor.signed.plist") and f.severity == .medium) unsigned_found = true;
        try std.testing.expect(!std.mem.endsWith(u8, subj, "com.apple.ok.plist"));
    }
    try std.testing.expect(tmp_agent and unsigned_found);
}

test "live: macOS checks run on this host; a clean CI runner has no high or critical findings" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const h = try Host.openLive(std.testing.io);
    defer h.close();
    var s = scan.Scan.init(std.testing.allocator, h, .{ .only = &.{"macos"} });
    defer s.deinit();
    try s.runChecks(&checks);
    // On any machine: the report is well formed and every finding is actionable.
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try s.writeJson(&out.writer, .{});
    try @import("../schema.zig").expectValid(std.testing.allocator, scan.report_schema, out.written());
    // Only a CI runner is a known-clean image; developer machines carry real findings and other
    // processes may install launchd jobs while the suite runs.
    if (!@import("../host.zig").onCi()) return;
    var bad = false;
    for (s.findings.items) |f| if (f.severity.atLeast(.high)) {
        std.debug.print("macos on CI: {s} {t} {s} {?s}\n", .{ f.check, f.severity, f.title, f.subject });
        bad = true;
    };
    try std.testing.expect(!bad);
}
