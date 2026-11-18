//! A host scan: the check registry, the runner, and the report it produces.
//!
//! Each check declares its id, category, tier, the privilege it needs and the operating system it
//! applies to. The runner picks checks by tier and filters, runs them against a `Host`, then
//! applies suppressions and server-context downgrades and sorts by severity. A check that fails
//! or cannot see everything leaves a coverage note instead of passing silently.
const std = @import("std");
const finding = @import("finding.zig");
const context = @import("context.zig");
const suppress = @import("suppress.zig");
const host_mod = @import("host.zig");
const pkgs = @import("linux/packages.zig");
const cache_mod = @import("cache.zig");
const procfs = @import("linux/procfs.zig");
const baseline_mod = @import("baseline.zig");

const Host = host_mod.Host;
const Finding = finding.Finding;
const Severity = finding.Severity;
const Category = finding.Category;

pub const Check = struct {
    id: []const u8,
    category: Category,
    tier: finding.Tier,
    privilege: finding.Privilege,
    os: host_mod.Os,
    /// One line for `zav host --list`.
    summary: []const u8,
    run: *const fn (*Scan) anyerror!void,
};

/// Which package, if any, owns a path. Backed by dpkg, rpm or apk on Linux and by the sealed
/// system volume on macOS. Checks use it instead of hard-coded allowlists.
pub const Ownership = struct {
    ctx: *anyopaque,
    ownerFn: *const fn (ctx: *anyopaque, path: []const u8) ?[]const u8,

    pub fn owner(o: Ownership, path: []const u8) ?[]const u8 {
        return o.ownerFn(o.ctx, path);
    }
};

/// Scans a file with the signature engine. Returns the detection name, or null when clean.
pub const FileScanner = struct {
    ctx: *anyopaque,
    scanFn: *const fn (ctx: *anyopaque, h: Host, path: []const u8) ?[]const u8,

    pub fn scan(s: FileScanner, h: Host, path: []const u8) ?[]const u8 {
        return s.scanFn(s.ctx, h, path);
    }
};

pub const Options = struct {
    tier: finding.Tier = .fast,
    /// Only these categories, when set.
    categories: ?std.EnumSet(Category) = null,
    /// Findings below this severity are left out of the report (after downgrades).
    min_severity: Severity = .info,
    suppressions: ?*const suppress.Config = null,
    /// Run only checks whose id equals or starts with one of these (a dotted prefix).
    only: []const []const u8 = &.{},
    /// Package ownership override. When null, Linux scans load the dpkg, rpm and apk databases
    /// under the host root on first use.
    ownership: ?Ownership = null,
    scanner: ?FileScanner = null,
    /// Where baselines and the file cache live (`zav host` uses /var/lib/zav or the user state
    /// directory). Drift checks report reduced coverage without it.
    state_dir: ?std.Io.Dir = null,
    /// Write the current state as the new baseline after the scan.
    update_baseline: bool = false,
    /// CPU sampling window for the CPU-share check.
    cpu_sample_ms: u32 = 500,
    /// The context to use instead of detecting one (tests).
    context: ?context.Context = null,
};

pub const Suppressed = struct {
    finding: Finding,
    reason: []const u8,
};

pub const Disabled = struct {
    check: []const u8,
    reason: []const u8,
};

pub const Scan = struct {
    gpa: std.mem.Allocator,
    arena_state: std.heap.ArenaAllocator,
    host: Host,
    context: context.Context,
    options: Options,
    findings: std.ArrayList(Finding) = .empty,
    suppressed: std.ArrayList(Suppressed) = .empty,
    disabled: std.ArrayList(Disabled) = .empty,
    coverage: std.ArrayList(finding.Coverage) = .empty,
    ran: std.ArrayList([]const u8) = .empty,
    /// The check running now; findings and coverage notes are attributed to it.
    current: []const u8 = "",
    pkgdb: ?pkgs.Db = null,
    pkgdb_tried: bool = false,
    /// Digests of files already hashed, by inode, ctime, mtime and size.
    file_cache: cache_mod.Cache,
    procs: ?std.ArrayList(procfs.Process) = null,
    /// Drift state from the last accepted scan (empty and disabled without a state directory).
    baseline: baseline_mod.Baseline,

    pub const cache_file = "file-cache.zavc";

    pub fn init(gpa: std.mem.Allocator, h: Host, options: Options) Scan {
        var s: Scan = .{
            .gpa = gpa,
            .arena_state = .init(gpa),
            .host = h,
            .context = options.context orelse detect(h),
            .options = options,
            .file_cache = .init(gpa),
            .baseline = .init(gpa),
        };
        if (options.state_dir) |d| {
            s.file_cache.load(h.io, d, cache_file) catch {};
            s.baseline.load(h.io, d) catch {};
        }
        return s;
    }

    pub fn deinit(s: *Scan) void {
        if (s.pkgdb) |*db| db.deinit();
        if (s.procs) |*p| p.deinit(s.gpa);
        s.file_cache.deinit();
        s.baseline.deinit();
        s.findings.deinit(s.gpa);
        s.suppressed.deinit(s.gpa);
        s.disabled.deinit(s.gpa);
        s.coverage.deinit(s.gpa);
        s.ran.deinit(s.gpa);
        s.arena_state.deinit();
    }

    /// Allocator for strings that live as long as the report.
    pub fn arena(s: *Scan) std.mem.Allocator {
        return s.arena_state.allocator();
    }

    pub fn print(s: *Scan, comptime fmt: []const u8, args: anytype) ![]const u8 {
        return std.fmt.allocPrint(s.arena(), fmt, args);
    }

    pub fn dupe(s: *Scan, text: []const u8) ![]const u8 {
        return s.arena().dupe(u8, text);
    }

    pub fn details(s: *Scan, items: []const finding.Detail) ![]const finding.Detail {
        return s.arena().dupe(finding.Detail, items);
    }

    pub fn add(s: *Scan, f: Finding) !void {
        var copy = f;
        if (copy.check.len == 0) copy.check = s.current;
        try s.findings.append(s.gpa, copy);
    }

    /// Record reduced coverage for the running check.
    pub fn reduced(s: *Scan, comptime fmt: []const u8, args: anytype) !void {
        try s.coverage.append(s.gpa, .{ .check = s.current, .reason = try s.print(fmt, args) });
    }

    pub fn owner(s: *Scan, path: []const u8) ?[]const u8 {
        if (s.options.ownership) |o| return o.owner(path);
        const db = s.packages() orelse return null;
        const p = db.ownerResolved(path) orelse return null;
        return p.name;
    }

    /// Record an observation for drift tracking. Returns true when it differs from a stored
    /// baseline that tracks `kind`; notes reduced coverage once when there is no state directory.
    pub fn drift(s: *Scan, kind: []const u8, subject: []const u8, value: []const u8) !bool {
        if (!s.baseline.enabled) {
            for (s.coverage.items) |c| if (std.mem.eql(u8, c.check, s.current) and std.mem.startsWith(u8, c.reason, "no state directory")) return false;
            try s.reduced("no state directory: changes since the last baseline are not tracked", .{});
            return false;
        }
        return s.baseline.observe(kind, subject, value);
    }

    /// Every process, read once per scan (Linux).
    pub fn processes(s: *Scan) ![]const procfs.Process {
        if (s.procs) |p| return p.items;
        var list: std.ArrayList(procfs.Process) = .empty;
        errdefer list.deinit(s.gpa);
        try procfs.snapshot(s.gpa, s.arena(), s.host, &list);
        s.procs = list;
        return list.items;
    }

    /// The package databases under the host root, loaded on first use. Null when there are none
    /// (or on macOS); load problems become coverage notes of the asking check.
    pub fn packages(s: *Scan) ?*pkgs.Db {
        if (s.pkgdb) |*db| return db;
        if (s.pkgdb_tried or s.host.os != .linux) return null;
        s.pkgdb_tried = true;
        var db = pkgs.Db.load(s.gpa, s.host) catch |e| {
            s.reduced("package database unreadable: {t}", .{e}) catch {};
            return null;
        };
        for (db.problems.items) |p| s.reduced("package database: {s}", .{p}) catch {};
        if (db.managers.count() == 0) {
            db.deinit();
            return null;
        }
        s.pkgdb = db;
        return &s.pkgdb.?;
    }

    pub fn owned(s: *Scan, path: []const u8) bool {
        return s.owner(path) != null;
    }

    fn selected(s: *Scan, c: Check) bool {
        if (c.os != s.host.os) return false;
        if (!s.options.tier.includes(c.tier)) return false;
        if (s.options.categories) |cats| if (!cats.contains(c.category)) return false;
        if (s.options.only.len > 0) {
            var any = false;
            for (s.options.only) |o| if (suppress.checkMatches(o, c.id) or std.mem.eql(u8, o, c.id) or
                (std.mem.startsWith(u8, c.id, o) and c.id.len > o.len and c.id[o.len] == '.'))
            {
                any = true;
            };
            if (!any) return false;
        }
        return true;
    }

    /// Run the selected checks from `registry`, then finalize the report.
    pub fn runChecks(s: *Scan, registry: []const Check) !void {
        for (registry) |c| {
            if (!s.selected(c)) continue;
            if (s.options.suppressions) |cfg| if (cfg.disables(c.id)) |e| {
                try s.disabled.append(s.gpa, .{ .check = c.id, .reason = e.reason });
                continue;
            };
            s.current = c.id;
            if (c.privilege == .root and s.host.euid != 0) {
                try s.reduced("skipped: needs root", .{});
                continue;
            }
            try s.ran.append(s.gpa, c.id);
            c.run(s) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => try s.reduced("check failed: {t}", .{e}),
            };
        }
        s.current = "";
        if (s.options.state_dir) |d| {
            if (s.file_cache.dirty) s.file_cache.save(s.host.io, d, cache_file) catch |e| try s.reduced("file cache not saved: {t}", .{e});
            if (s.options.update_baseline or s.baseline.hasNewKinds())
                s.baseline.save(s.host.io, d, s.options.update_baseline) catch |e| try s.reduced("baseline not saved: {t}", .{e});
        }
        try s.finalize();
    }

    /// Apply suppressions, server-context downgrades and the severity floor, then sort.
    pub fn finalize(s: *Scan) !void {
        var kept: usize = 0;
        for (s.findings.items) |f| {
            if (s.options.suppressions) |cfg| if (cfg.suppresses(f)) |e| {
                try s.suppressed.append(s.gpa, .{ .finding = f, .reason = e.reason });
                continue;
            };
            var g = f;
            context.apply(s.context, &g);
            if (!g.severity.atLeast(s.options.min_severity)) continue;
            s.findings.items[kept] = g;
            kept += 1;
        }
        s.findings.shrinkRetainingCapacity(kept);
        std.mem.sort(Finding, s.findings.items, {}, struct {
            fn lt(_: void, a: Finding, b: Finding) bool {
                if (a.severity != b.severity) return @backingInt(a.severity) > @backingInt(b.severity);
                return std.mem.order(u8, a.check, b.check) == .lt;
            }
        }.lt);
    }

    pub fn score(s: *const Scan) u8 {
        return finding.score(s.findings.items);
    }

    pub fn exitCode(s: *const Scan) u8 {
        return finding.exitCode(s.findings.items);
    }

    /// The report as JSON; the shape is `report.schema.json`.
    pub fn writeJson(s: *const Scan, w: *std.Io.Writer, options: std.json.Stringify.Options) !void {
        var jw: std.json.Stringify = .{ .writer = w, .options = options };
        try jw.beginObject();
        try jw.objectField("schema");
        try jw.write(schema_id);
        try jw.objectField("host");
        try jw.beginObject();
        try jw.objectField("os");
        try jw.write(@tagName(s.host.os));
        try jw.objectField("role");
        try jw.write(@tagName(s.context.role));
        try jw.objectField("virtualized");
        try jw.write(s.context.virtualized);
        try jw.objectField("desktop");
        try jw.write(s.context.desktop);
        try jw.objectField("services");
        try jw.beginArray();
        var services = s.context.services.iterator();
        while (services.next()) |svc| try jw.write(@tagName(svc));
        try jw.endArray();
        try jw.objectField("privileged");
        try jw.write(s.host.euid == 0);
        try jw.endObject();
        try jw.objectField("tier");
        try jw.write(@tagName(s.options.tier));
        const points = s.score();
        try jw.objectField("score");
        try jw.write(points);
        try jw.objectField("label");
        try jw.write(@tagName(finding.Label.of(points)));
        try jw.objectField("highest");
        if (finding.highest(s.findings.items)) |h| try jw.write(@tagName(h)) else try jw.write(null);
        try jw.objectField("exit_code");
        try jw.write(s.exitCode());
        try jw.objectField("findings");
        try jw.beginArray();
        for (s.findings.items) |f| try finding.writeFinding(&jw, f);
        try jw.endArray();
        try jw.objectField("suppressed");
        try jw.beginArray();
        for (s.suppressed.items) |sup| {
            try jw.beginObject();
            try jw.objectField("check");
            try jw.write(sup.finding.check);
            try jw.objectField("severity");
            try jw.write(@tagName(sup.finding.severity));
            try jw.objectField("title");
            try jw.write(sup.finding.title);
            if (sup.finding.subject) |subj| {
                try jw.objectField("subject");
                try jw.write(subj);
            }
            try jw.objectField("reason");
            try jw.write(sup.reason);
            try jw.endObject();
        }
        try jw.endArray();
        try jw.objectField("disabled");
        try jw.beginArray();
        for (s.disabled.items) |d| {
            try jw.beginObject();
            try jw.objectField("check");
            try jw.write(d.check);
            try jw.objectField("reason");
            try jw.write(d.reason);
            try jw.endObject();
        }
        try jw.endArray();
        try jw.objectField("coverage");
        try jw.beginArray();
        for (s.coverage.items) |c| {
            try jw.beginObject();
            try jw.objectField("check");
            try jw.write(c.check);
            try jw.objectField("reason");
            try jw.write(c.reason);
            try jw.endObject();
        }
        try jw.endArray();
        try jw.objectField("checks");
        try jw.write(s.ran.items);
        try jw.endObject();
    }
};

pub const schema_id = "zav.host.report/1";

fn detect(h: Host) context.Context {
    return switch (h.os) {
        .linux => context.detectLinux(h),
        .macos => .{ .role = .workstation },
    };
}

// Tests: a registry of fake checks exercises selection, privilege skips, failures, suppression,
// downgrades and JSON output against the committed schema.

fn fakeMiner(s: *Scan) !void {
    try s.add(.{ .severity = .critical, .category = .malware, .title = "Cryptominer", .description = "xmrig running", .remediation = "kill it", .subject = "/dev/shm/x", .pid = 42, .details = try s.details(&.{.{ .key = "comm", .value = "xmrig" }}) });
}
fn fakeTemp(s: *Scan) !void {
    try s.add(.{ .severity = .high, .category = .process, .title = "Temp exec", .description = "d", .remediation = "r", .subject = "/tmp/ci-7/node" });
}
fn fakeDisk(s: *Scan) !void {
    try s.add(.{ .severity = .medium, .category = .hardening, .title = "No disk encryption", .description = "d", .remediation = "r" });
}
fn fakeFails(_: *Scan) !void {
    return error.Unexpected;
}
fn fakeRoot(s: *Scan) !void {
    try s.add(.{ .severity = .high, .category = .kernel, .title = "root only", .description = "d", .remediation = "r" });
}

const fake_registry = [_]Check{
    .{ .id = "process.miner", .category = .malware, .tier = .fast, .privilege = .none, .os = .linux, .summary = "", .run = fakeMiner },
    .{ .id = "process.temp_exec", .category = .process, .tier = .fast, .privilege = .none, .os = .linux, .summary = "", .run = fakeTemp },
    .{ .id = "hardening.disk_encryption", .category = .hardening, .tier = .fast, .privilege = .none, .os = .linux, .summary = "", .run = fakeDisk },
    .{ .id = "kernel.fails", .category = .kernel, .tier = .fast, .privilege = .none, .os = .linux, .summary = "", .run = fakeFails },
    .{ .id = "kernel.ebpf", .category = .kernel, .tier = .deep, .privilege = .root, .os = .linux, .summary = "", .run = fakeRoot },
    .{ .id = "macos.launchd", .category = .persistence, .tier = .fast, .privilege = .none, .os = .macos, .summary = "", .run = fakeRoot },
};

test "runner applies tiers, suppressions, downgrades and coverage notes" {
    const gpa = std.testing.allocator;
    var fx = try host_mod.Fixture.init();
    defer fx.deinit();
    var h = fx.host(.linux);
    h.euid = 1000;
    var cfg = try suppress.Config.parse(gpa,
        \\{ "suppress": [ { "check": "process.temp_exec", "path": "/tmp/ci-*", "reason": "CI builds run from /tmp" } ] }
    );
    defer cfg.deinit();

    var s = Scan.init(gpa, h, .{ .suppressions = &cfg, .context = .{ .role = .server, .virtualized = true } });
    defer s.deinit();
    try s.runChecks(&fake_registry);

    try std.testing.expectEqual(@as(usize, 2), s.findings.items.len);
    try std.testing.expectEqualStrings("process.miner", s.findings.items[0].check);
    try std.testing.expectEqualStrings("hardening.disk_encryption", s.findings.items[1].check);
    try std.testing.expectEqual(Severity.info, s.findings.items[1].severity);
    try std.testing.expectEqual(Severity.medium, s.findings.items[1].downgraded.?.from);
    try std.testing.expectEqual(@as(usize, 1), s.suppressed.items.len);
    try std.testing.expectEqual(@as(usize, 1), s.coverage.items.len); // kernel.fails; ebpf is deep
    try std.testing.expectEqual(@as(u8, 14), s.exitCode());
    try std.testing.expectEqual(@as(u8, 70), s.score());

    var deep = Scan.init(gpa, h, .{ .tier = .deep, .min_severity = .high, .context = .{ .role = .workstation } });
    defer deep.deinit();
    try deep.runChecks(&fake_registry);
    try std.testing.expectEqual(@as(usize, 2), deep.findings.items.len); // miner, temp; disk below floor
    try std.testing.expectEqual(@as(usize, 2), deep.coverage.items.len); // failure + needs root
    try std.testing.expectEqualStrings("skipped: needs root", deep.coverage.items[1].reason);
}

test "report JSON validates against the committed schema" {
    const gpa = std.testing.allocator;
    var fx = try host_mod.Fixture.init();
    defer fx.deinit();
    var cfg = try suppress.Config.parse(gpa,
        \\{ "suppress": [ { "check": "process.temp_exec", "path": "/tmp/*", "reason": "builds" }, { "check": "kernel.*", "reason": "managed kernel" } ] }
    );
    defer cfg.deinit();
    var s = Scan.init(gpa, fx.host(.linux), .{ .suppressions = &cfg, .tier = .deep, .context = .{ .role = .server, .virtualized = true, .services = .initMany(&.{ .sshd, .nginx }) } });
    defer s.deinit();
    try s.runChecks(&fake_registry);

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try s.writeJson(&out.writer, .{});
    const schema = @import("schema.zig");
    try schema.expectValid(gpa, report_schema, out.written());

    // And the validator does reject wrong shapes.
    try std.testing.expectError(error.SchemaViolation, schema.validate(gpa, report_schema, "{\"schema\":\"zav.host.report/1\"}"));
}

pub const report_schema = @embedFile("report.schema.json");
