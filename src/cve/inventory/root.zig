//! Inventory collectors and the audit checks that match them against the .zavcve index.
//!
//! Collected: OS packages (dpkg, rpm, apk through the host package databases), Homebrew Cellar,
//! pantry installs, macOS application bundles (Info.plist), lockfiles (bun.lock,
//! package-lock.json, pnpm-lock.yaml, pantry.lock, Cargo.lock), Python dist-info, Go build info
//! in binaries, and service banners from local listeners. Matches become `vulnerability`
//! findings; a KEV hit is always critical.
const std = @import("std");
const builtin = @import("builtin");
pub const item = @import("item.zig");
pub const lockfiles = @import("lockfiles.zig");
pub const gobuild = @import("gobuild.zig");
const scan = @import("../../host/scan.zig");
const finding = @import("../../host/finding.zig");
const Host = @import("../../host/host.zig").Host;
const plist = @import("../../host/macos/plist.zig");
const index_mod = @import("../index.zig");

pub const Item = item.Item;

pub const checks = [_]scan.Check{
    .{ .id = "vulnerability.packages", .category = .vulnerability, .tier = .fast, .privilege = .none, .os = .linux, .summary = "OS packages and installed software with known vulnerabilities (KEV hits critical)", .run = checkHostPackages },
    .{ .id = "vulnerability.packages", .category = .vulnerability, .tier = .fast, .privilege = .none, .os = .macos, .summary = "Homebrew, pantry and application bundles with known vulnerabilities (KEV hits critical)", .run = checkHostPackages },
    .{ .id = "vulnerability.services", .category = .vulnerability, .tier = .deep, .privilege = .none, .os = .linux, .summary = "Versions announced by local listening services", .run = checkServices },
    .{ .id = "vulnerability.paths", .category = .vulnerability, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Lockfiles, Python packages and Go binaries under the audited paths", .run = checkPaths },
    .{ .id = "vulnerability.paths", .category = .vulnerability, .tier = .fast, .privilege = .none, .os = .macos, .summary = "Lockfiles, Python packages and Go binaries under the audited paths", .run = checkPaths },
};

// Host collectors -------------------------------------------------------------------------------

/// OS packages from the package databases, with the advisory ecosystem from /etc/os-release.
pub fn collectOsPackages(s: *scan.Scan, out: *std.ArrayList(Item)) !void {
    const db = s.packages() orelse return;
    var rel_buf: [4096]u8 = undefined;
    var eco_buf: [64]u8 = undefined;
    const eco = if (s.host.readOpt("/etc/os-release", &rel_buf)) |t| item.osEcosystem(&eco_buf, t) else null;
    const eco_owned = if (eco) |e| try s.dupe(e) else null;
    // Debian advisories name source packages: read Source fields from the status file.
    var sources: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer sources.deinit(s.gpa);
    if (db.managers.contains(.dpkg)) if (s.host.readAlloc(s.arena(), "/var/lib/dpkg/status", 512 * 1024 * 1024)) |status| {
        var it = @import("../../host/linux/packages.zig").StanzaIterator{ .text = status };
        while (it.next()) |st| if (st.source.len > 0) try sources.put(s.gpa, st.package, std.mem.sliceTo(st.source, ' '));
    } else |_| {};
    for (db.packages.items) |p| {
        if (p.version.len == 0) continue;
        const src: []const u8 = switch (p.manager) {
            .dpkg => "/var/lib/dpkg/status",
            .rpm => "/var/lib/rpm/rpmdb.sqlite",
            .apk => "/lib/apk/db/installed",
        };
        try out.append(s.gpa, .{
            .ecosystem = eco_owned orelse @tagName(p.manager),
            .name = p.base,
            .version = p.version,
            .source = src,
            .advisory_name = sources.get(p.base),
        });
    }
}

fn listDir(s: *scan.Scan, path: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var dir = (s.host.openDir(path) catch return out.items) orelse return out.items;
    defer dir.close(s.host.io);
    var it = dir.iterate();
    while (it.next(s.host.io) catch null) |e| {
        if (e.name[0] == '.') continue;
        try out.append(s.arena(), try s.dupe(e.name));
        if (out.items.len > 20000) break;
    }
    return out.items;
}

/// Homebrew Cellar (`<prefix>/Cellar/<formula>/<version>`) and pantry installs
/// (`pantry/<domain>/v<version>`).
pub fn collectHomebrewPantry(s: *scan.Scan, extra_pantry_roots: []const []const u8, out: *std.ArrayList(Item)) !void {
    for ([_][]const u8{ "/opt/homebrew/Cellar", "/usr/local/Cellar", "/home/linuxbrew/.linuxbrew/Cellar" }) |cellar| {
        for (try listDir(s, cellar)) |formula| {
            const dir = try s.print("{s}/{s}", .{ cellar, formula });
            for (try listDir(s, dir)) |ver| {
                const cpe = item.cpeFor(formula);
                try out.append(s.gpa, .{ .ecosystem = "homebrew", .name = formula, .version = std.mem.sliceTo(ver, '_'), .source = dir, .cpe_vendor = if (cpe) |c| c.vendor else null, .cpe_product = if (cpe) |c| c.product else null });
            }
        }
    }
    for (extra_pantry_roots) |root| try collectPantryTree(s, root, "", 0, out);
}

fn collectPantryTree(s: *scan.Scan, root: []const u8, prefix: []const u8, depth: u8, out: *std.ArrayList(Item)) !void {
    if (depth > 3) return;
    const dir = if (prefix.len == 0) root else try s.print("{s}/{s}", .{ root, prefix });
    for (try listDir(s, dir)) |name| {
        if (name[0] == 'v' and name.len > 1 and std.ascii.isDigit(name[1])) {
            // Only full versions (v8.23.0.2), not the v8 / v8.23 alias links.
            if (std.mem.count(u8, name, ".") < 2 or prefix.len == 0) continue;
            const cpe = item.cpeFor(prefix);
            try out.append(s.gpa, .{ .ecosystem = "pantry", .name = prefix, .version = name[1..], .source = dir, .cpe_vendor = if (cpe) |c| c.vendor else null, .cpe_product = if (cpe) |c| c.product else null });
        } else if (std.mem.indexOfScalar(u8, name, '.') != null or depth > 0) {
            try collectPantryTree(s, root, if (prefix.len == 0) name else try s.print("{s}/{s}", .{ prefix, name }), depth + 1, out);
        }
    }
}

/// Application bundles in /Applications and ~/Applications: CFBundleShortVersionString.
pub fn collectApps(s: *scan.Scan, out: *std.ArrayList(Item)) !void {
    var roots: std.ArrayList([]const u8) = .empty;
    try roots.append(s.arena(), "/Applications");
    for (try listDir(s, "/Users")) |u| try roots.append(s.arena(), try s.print("/Users/{s}/Applications", .{u}));
    for (roots.items) |root| for (try listDir(s, root)) |name| {
        if (!std.mem.endsWith(u8, name, ".app")) continue;
        const path = try s.print("{s}/{s}/Contents/Info.plist", .{ root, name });
        const bytes = s.host.readAlloc(s.arena(), path, 4 * 1024 * 1024) catch continue;
        const v = plist.parse(s.arena(), bytes) catch continue;
        const ver = v.getString("CFBundleShortVersionString") orelse v.getString("CFBundleVersion") orelse continue;
        const id = v.getString("CFBundleIdentifier") orelse name;
        try out.append(s.gpa, .{ .ecosystem = "macos-app", .name = id, .version = ver, .source = path });
    };
}

// Path collectors -------------------------------------------------------------------------------

pub const max_walk_entries = 500_000;

/// Walk `root` for lockfiles, dist-info and Go binaries. node_modules, .git and pantry package
/// trees are skipped: the lockfile already lists what they hold.
pub fn collectPath(s: *scan.Scan, root: []const u8, out: *std.ArrayList(Item)) !void {
    var stack: std.ArrayList(struct { path: []const u8, depth: u8 }) = .empty;
    defer stack.deinit(s.gpa);
    try stack.append(s.gpa, .{ .path = root, .depth = 0 });
    var entries: usize = 0;
    var unreadable: usize = 0;
    while (stack.pop()) |d| {
        var dir = (s.host.openDir(d.path) catch {
            unreadable += 1;
            continue;
        }) orelse continue;
        defer dir.close(s.host.io);
        var it = dir.iterate();
        while (it.next(s.host.io) catch null) |e| {
            entries += 1;
            if (entries > max_walk_entries) {
                try s.reduced("{s}: walk stopped after {d} entries", .{ root, max_walk_entries });
                return;
            }
            const child = try s.print("{s}/{s}", .{ std.mem.trimEnd(u8, d.path, "/"), e.name });
            switch (e.kind) {
                .directory => {
                    if (std.mem.eql(u8, e.name, "node_modules") or std.mem.eql(u8, e.name, ".git") or std.mem.eql(u8, e.name, "pantry") or std.mem.eql(u8, e.name, ".zig-cache") or std.mem.eql(u8, e.name, "zig-pkg")) continue;
                    if (std.mem.endsWith(u8, e.name, ".dist-info") or std.mem.endsWith(u8, e.name, ".egg-info")) {
                        const meta = try s.print("{s}/{s}", .{ child, if (std.mem.endsWith(u8, e.name, ".dist-info")) "METADATA" else "PKG-INFO" });
                        if (s.host.readAlloc(s.arena(), meta, 4 * 1024 * 1024)) |t| try lockfiles.pythonMetadata(s.gpa, t, meta, out) else |_| {}
                        continue;
                    }
                    if (d.depth < 12) try stack.append(s.gpa, .{ .path = child, .depth = d.depth + 1 });
                },
                .file => try collectFile(s, child, e.name, out),
                else => {},
            }
        }
    }
    if (unreadable > 0) try s.reduced("{s}: {d} directories unreadable", .{ root, unreadable });
}

fn collectFile(s: *scan.Scan, path: []const u8, name: []const u8, out: *std.ArrayList(Item)) !void {
    const a = s.arena();
    const parse = struct {
        fn f(sc: *scan.Scan, comptime what: []const u8, err: anyerror, p: []const u8) !void {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            try sc.reduced("{s}: unreadable " ++ what ++ " ({t})", .{ p, err });
        }
    }.f;
    if (std.mem.eql(u8, name, "bun.lock")) {
        const t = s.host.readAlloc(a, path, 256 * 1024 * 1024) catch return;
        lockfiles.bunLock(s.gpa, a, t, path, out) catch |e| try parse(s, "bun.lock", e, path);
    } else if (std.mem.eql(u8, name, "package-lock.json") or std.mem.eql(u8, name, "npm-shrinkwrap.json")) {
        const t = s.host.readAlloc(a, path, 256 * 1024 * 1024) catch return;
        lockfiles.packageLock(s.gpa, a, t, path, out) catch |e| try parse(s, "package-lock.json", e, path);
    } else if (std.mem.eql(u8, name, "pnpm-lock.yaml")) {
        const t = s.host.readAlloc(a, path, 256 * 1024 * 1024) catch return;
        try lockfiles.pnpmLock(s.gpa, t, path, out);
    } else if (std.mem.eql(u8, name, "pantry.lock")) {
        const t = s.host.readAlloc(a, path, 64 * 1024 * 1024) catch return;
        lockfiles.pantryLock(s.gpa, a, t, path, out) catch |e| try parse(s, "pantry.lock", e, path);
        for (out.items) |*i| if (std.mem.eql(u8, i.ecosystem, "pantry") and i.cpe_vendor == null) {
            if (item.cpeFor(i.name)) |c| {
                i.cpe_vendor = c.vendor;
                i.cpe_product = c.product;
            }
        };
    } else if (std.mem.eql(u8, name, "Cargo.lock")) {
        const t = s.host.readAlloc(a, path, 64 * 1024 * 1024) catch return;
        try lockfiles.cargoLock(s.gpa, t, path, out);
    } else {
        // Executables: Go build info.
        const st = s.host.stat(path, false) catch return;
        if (!st.executable() or st.size < 1024 or st.size > 256 * 1024 * 1024) return;
        var head: [4]u8 = undefined;
        const h = s.host.readOpt(path, &head) orelse return;
        if (h.len < 4) return;
        const elf = std.mem.eql(u8, h, "\x7fELF");
        const macho = std.mem.readInt(u32, h[0..4], .little) == 0xfeedfacf or std.mem.readInt(u32, h[0..4], .big) == 0xcafebabe;
        const pe = h[0] == 'M' and h[1] == 'Z';
        if (!elf and !macho and !pe) return;
        const bytes = s.host.readAlloc(s.gpa, path, 256 * 1024 * 1024) catch return;
        defer s.gpa.free(bytes);
        const info = gobuild.find(bytes) orelse return;
        const owned: gobuild.BuildInfo = .{ .go_version = try a.dupe(u8, info.go_version), .modinfo = try a.dupe(u8, info.modinfo) };
        try gobuild.items(s.gpa, owned, path, out);
    }
}

// Matching --------------------------------------------------------------------------------------

fn severityOf(info: index_mod.Info) finding.Severity {
    if (info.kev) return .critical;
    return switch (info.severity) {
        .critical => .critical,
        .high => .high,
        .medium => .medium,
        .low => .low,
        .none => .medium, // unscored advisories are still advisories
    };
}

/// Match items against the index and add one finding per (item, vulnerability).
pub fn report(s: *scan.Scan, idx: index_mod.Index, items: []const Item) !void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(s.gpa);
    for (items) |it| {
        var hits_buf: [64]index_mod.Hit = undefined;
        var n: usize = 0;
        const pkg_hits = idx.queryPackage(it.ecosystem, it.advisory_name orelse it.name, it.version, &hits_buf);
        n = pkg_hits.len;
        if (it.cpe_vendor) |v| {
            const cpe_hits = idx.queryCpe(v, it.cpe_product.?, it.version, hits_buf[n..]);
            n += cpe_hits.len;
        }
        for (hits_buf[0..n]) |h| {
            const info = idx.info(h.record);
            if (info.withdrawn) continue;
            const key = try s.print("{s}\x00{s}\x00{s}\x00{s}", .{ it.source, it.name, it.version, info.id });
            if ((try seen.getOrPut(s.gpa, key)).found_existing) continue;
            const sev = severityOf(info);
            var cves = try s.arena().alloc([]const u8, 1);
            cves[0] = try s.dupe(info.id);
            try s.add(.{
                .check = "vulnerability.package",
                .severity = sev,
                .category = .vulnerability,
                .title = try s.print("{s} {s} is affected by {s}{s}", .{ it.name, it.version, info.id, if (info.kev) " (known exploited)" else "" }),
                .description = try s.print("{s} {s} ({s}, from {s}) matches {s}{s}{s}. {s}{s}", .{
                    it.name,                                                              it.version,                                                            it.ecosystem,                                                                                        it.source,                                                                      info.id,
                    if (info.alias.len > 0) try s.print(" ({s})", .{info.alias}) else "", if (info.cvss > 0) try s.print(", CVSS {d:.1}", .{info.cvss}) else "", if (info.kev) "It is in CISA's Known Exploited Vulnerabilities catalog: attackers use it. " else "", if (info.summary.len > 0) info.summary[0..@min(info.summary.len, 300)] else "",
                }),
                .remediation = if (h.fixed.len > 0)
                    try s.print("Upgrade {s} to {s} or later{s}.", .{ it.name, h.fixed, if (info.kev) "; CISA requires remediation by the KEV due date" else "" })
                else
                    try s.print("No fixed version is recorded for {s}; check the advisory for a patch or mitigation, or replace the dependency.", .{it.name}),
                .cve = cves,
                .subject = it.source,
                .details = try s.details(&.{
                    .{ .key = "ecosystem", .value = it.ecosystem },
                    .{ .key = "package", .value = it.name },
                    .{ .key = "version", .value = it.version },
                    .{ .key = "fixed", .value = try s.dupe(h.fixed) },
                    .{ .key = "kev", .value = if (info.kev) "true" else "false" },
                    .{ .key = "ransomware", .value = if (info.ransomware) "true" else "false" },
                    .{ .key = "cvss", .value = try s.print("{d:.1}", .{info.cvss}) },
                }),
            });
        }
    }
}

fn needIndex(s: *scan.Scan) ?index_mod.Index {
    const idx = s.options.cve_index orelse {
        s.reduced("no .zavcve index loaded; run zav update cve and zav compile-cve", .{}) catch {};
        return null;
    };
    return idx.*;
}

fn checkHostPackages(s: *scan.Scan) !void {
    const idx = needIndex(s) orelse return;
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(s.gpa);
    try collectOsPackages(s, &items);
    try collectHomebrewPantry(s, s.options.pantry_roots, &items);
    if (s.host.os == .macos) try collectApps(s, &items);
    try report(s, idx, items.items);
}

fn checkPaths(s: *scan.Scan) !void {
    if (s.options.audit_paths.len == 0) return;
    const idx = needIndex(s) orelse return;
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(s.gpa);
    for (s.options.audit_paths) |p| try collectPath(s, p, &items);
    try report(s, idx, items.items);
}

/// The product and version a greeting announces, for the ones that carry a version.
pub fn bannerItem(banner: []const u8) ?Item {
    // SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
    if (std.mem.startsWith(u8, banner, "SSH-")) {
        const i = std.mem.indexOf(u8, banner, "OpenSSH_") orelse return null;
        const rest = banner[i + 8 ..];
        const end = std.mem.indexOfAny(u8, rest, " \r\n") orelse rest.len;
        if (end == 0) return null;
        return .{ .ecosystem = "banner", .name = "openssh", .version = rest[0..end], .source = "", .cpe_vendor = "openbsd", .cpe_product = "openssh" };
    }
    return null;
}

fn checkServices(s: *scan.Scan) !void {
    if (!s.host.live or builtin.os.tag != .linux) {
        try s.reduced("service banners are read from the live host only", .{});
        return;
    }
    const idx = needIndex(s) orelse return;
    const network = @import("../../host/linux/network.zig");
    var socks: std.ArrayList(network.Socket) = .empty;
    defer socks.deinit(s.gpa);
    try network.readInet(s.gpa, s.host, "/proc", &socks);
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(s.gpa);
    var done: std.AutoHashMapUnmanaged(u16, void) = .empty;
    defer done.deinit(s.gpa);
    for (socks.items) |so| {
        if (so.proto != .tcp or so.state != .listen or so.local.family != 4) continue;
        if ((try done.getOrPut(s.gpa, so.local.port)).found_existing) continue;
        var buf: [256]u8 = undefined;
        // Only services that greet first are read; nothing is sent.
        const banner = readBanner(so.local.port, &buf) orelse continue;
        var it = bannerItem(banner) orelse continue;
        it.source = try s.print("tcp/{d}", .{so.local.port});
        it.version = try s.dupe(it.version);
        try items.append(s.gpa, it);
    }
    try report(s, idx, items.items);
}

/// Connect to 127.0.0.1:port and read what the service sends within half a second.
fn readBanner(port: u16, buf: []u8) ?[]const u8 {
    if (builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const tv: linux.timeval = .{ .sec = 0, .usec = 500_000 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    var addr: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return null;
    const n = linux.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
    if (linux.errno(n) != .SUCCESS or n == 0) return null;
    return buf[0..n];
}

// Tests -----------------------------------------------------------------------------------------

const Fixture = @import("../../host/host.zig").Fixture;

fn fixtureIndex(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !index_mod.Index {
    const feeds = @import("../feeds.zig");
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var b = index_mod.Builder.init(gpa);
    defer b.deinit();
    try b.addKev(try feeds.parseKev(arena.allocator(), feeds.fixtures.kev));
    try b.addNvd(try feeds.parseNvdPage(arena.allocator(), feeds.fixtures.nvd_log4shell));
    try b.addOsv(try feeds.parseOsv(arena.allocator(), feeds.fixtures.osv_lodash));
    try b.addOsv(try feeds.parseOsv(arena.allocator(), feeds.fixtures.osv_requests));
    _ = try b.write(io, dir, "fixture.zavcve", .{});
    return index_mod.Index.open(io, dir, "fixture.zavcve", .{ .allow_unsigned = true });
}

test "a fixture Stacks app with a vulnerable dependency in bun.lock is reported with the CVE id" {
    const gpa = std.testing.allocator;
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/srv/app/bun.lock",
        \\{
        \\  "lockfileVersion": 1,
        \\  "workspaces": { "": { "name": "my-stacks-app", "dependencies": { "lodash": "^4.17.20", "@stacksjs/ai": "workspace:*", }, }, },
        \\  "packages": {
        \\    "lodash": ["lodash@4.17.20", "", {}, "sha512-x"],
        \\    "@stacksjs/ai": ["@stacksjs/ai@workspace:storage/framework/core/ai"],
        \\    "requests-not-npm": ["requests-not-npm@2.31.0", "", {}, "sha512-y"],
        \\  },
        \\}
    );
    try fx.file("/srv/app/node_modules/lodash/package.json", "{}");
    try fx.file("/srv/app/.venv/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n");
    try fx.file("/srv/app/pantry.lock", "{\"packages\":{\"curl.se@8.23.0.2\":{\"name\":\"curl.se\",\"version\":\"8.23.0.2\",\"source\":\"pantry\"}}}");
    const idx = try fixtureIndex(gpa, std.testing.io, fx.tmp.dir);
    defer idx.close();

    var s = scan.Scan.init(gpa, fx.host(.linux), .{ .only = &.{"vulnerability.paths"}, .audit_paths = &.{"/srv/app"}, .cve_index = &idx, .context = .{ .role = .server } });
    defer s.deinit();
    try s.runChecks(&checks);
    var lodash = false;
    var requests = false;
    for (s.findings.items) |f| {
        try std.testing.expectEqualStrings("vulnerability.package", f.check);
        if (std.mem.eql(u8, f.cve[0], "CVE-2021-23337")) {
            lodash = true;
            try std.testing.expectEqualStrings("/srv/app/bun.lock", f.subject.?);
            try std.testing.expect(std.mem.indexOf(u8, f.remediation, "4.17.21") != null);
        }
        if (std.mem.eql(u8, f.cve[0], "CVE-2024-35195")) requests = true;
    }
    try std.testing.expect(lodash and requests);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try s.writeJson(&out.writer, .{});
    try @import("../../host/schema.zig").expectValid(gpa, scan.report_schema, out.written());
}

test "OS packages match by advisory ecosystem and source name; KEV hits are critical" {
    const gpa = std.testing.allocator;
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
    try fx.file("/var/lib/dpkg/status", "Package: liblog4j2-java\nStatus: install ok installed\nSource: apache-log4j2 (2.14.1-1)\nVersion: 2.14.1-1\n");
    try fx.file("/var/lib/dpkg/info/liblog4j2-java.list", "/usr/share/java/log4j-core.jar\n");
    try fx.file("/osv.json",
        \\{"id":"DEBIAN-CVE-2021-44228","aliases":["CVE-2021-44228"],"affected":[{"package":{"ecosystem":"Debian:12","name":"apache-log4j2"},
        \\"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.15.0-1"}]}]}]}
    );
    const feeds = @import("../feeds.zig");
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var b = index_mod.Builder.init(gpa);
    defer b.deinit();
    try b.addKev(try feeds.parseKev(arena.allocator(), feeds.fixtures.kev));
    try b.addOsv(try feeds.parseOsv(arena.allocator(), try fx.tmp.dir.readFileAlloc(std.testing.io, "osv.json", arena.allocator(), .limited(1 << 20))));
    _ = try b.write(std.testing.io, fx.tmp.dir, "os.zavcve", .{});
    const idx = try index_mod.Index.open(std.testing.io, fx.tmp.dir, "os.zavcve", .{ .allow_unsigned = true });
    defer idx.close();
    var s = scan.Scan.init(gpa, fx.host(.linux), .{ .only = &.{"vulnerability.packages"}, .cve_index = &idx, .context = .{ .role = .server } });
    defer s.deinit();
    try s.runChecks(&checks);
    try std.testing.expectEqual(@as(usize, 1), s.findings.items.len);
    try std.testing.expectEqual(finding.Severity.critical, s.findings.items[0].severity);
    try std.testing.expectEqualStrings("CVE-2021-44228", s.findings.items[0].cve[0]);
}

test "service banners" {
    const i = bannerItem("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n").?;
    try std.testing.expectEqualStrings("9.6p1", i.version);
    try std.testing.expectEqualStrings("openssh", i.cpe_product.?);
    try std.testing.expect(bannerItem("220 mail ESMTP Postfix\r\n") == null);
}

test "live: dpkg and rpm inventory matches the package manager's own list" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const h = try Host.openLive(io);
    defer h.close();
    var s = scan.Scan.init(gpa, h, .{ .context = .{ .role = .server } });
    defer s.deinit();
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    try collectOsPackages(&s, &items);
    const db = s.packages() orelse return error.SkipZigTest;
    const argv: []const []const u8 = if (db.managers.contains(.dpkg))
        &.{ "dpkg-query", "-W", "-f", "${db:Status-Status}\\t${Package}\\t${Version}\\n" }
    else if (db.managers.contains(.rpm))
        &.{ "rpm", "-qa", "--qf", "installed\\t%{NAME}\\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\\n" }
    else
        return error.SkipZigTest;
    const r = try std.process.run(gpa, io, .{ .argv = argv, .stdout_limit = .limited(64 * 1024 * 1024) });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    var theirs: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer theirs.deinit(gpa);
    var lines = std.mem.splitScalar(u8, r.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, '\t');
        const status = f.next() orelse continue;
        const name = f.next() orelse continue;
        const ver = f.next() orelse continue;
        if (!std.mem.eql(u8, status, "installed")) continue;
        try theirs.put(gpa, name, ver);
    }
    var mismatches: usize = 0;
    var matched: usize = 0;
    var it = theirs.iterator();
    while (it.next()) |kv| {
        var found = false;
        for (items.items) |i| if (std.mem.eql(u8, i.name, kv.key_ptr.*) and std.mem.eql(u8, i.version, kv.value_ptr.*)) {
            found = true;
        };
        if (found) matched += 1 else {
            mismatches += 1;
            if (mismatches < 10) std.debug.print("inventory lacks {s} {s}\n", .{ kv.key_ptr.*, kv.value_ptr.* });
        }
    }
    std.debug.print("inventory: {d} of {d} installed packages match the package manager\n", .{ matched, theirs.count() });
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
