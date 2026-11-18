//! Package managers as the source of truth for which files belong on a system: dpkg
//! (`/var/lib/dpkg`), rpm (`/var/lib/rpm/rpmdb.sqlite`, rpm 4.16 and newer) and apk
//! (`/lib/apk/db/installed`). Checks ask `owner(path)` instead of consulting hard-coded
//! allowlists, and the deep tier verifies owned binaries against the package checksums.
//!
//! Ownership answers are literal, like `dpkg -S` and `rpm -qf`; `ownerResolved` additionally
//! tries the merged-/usr aliases (/bin and /usr/bin, /lib and /usr/lib, ...) because a running
//! process reports whichever spelling it was started with.
const std = @import("std");
const Host = @import("../host.zig").Host;
const sqlite = @import("sqlite.zig");
const rpm = @import("rpm.zig");

pub const Manager = enum { dpkg, rpm, apk };

pub const Algo = enum { none, md5, sha1, sha256, sha384, sha512 };

pub const Package = struct {
    /// dpkg: the list name (`libc6:amd64` for Multi-Arch: same), as `dpkg -S` prints it.
    /// rpm: name-version-release.arch, as `rpm -qf` prints it. apk: the package name.
    name: []const u8,
    /// The bare package name, without arch or version.
    base: []const u8,
    version: []const u8,
    arch: []const u8,
    manager: Manager,
};

pub const FileRef = struct {
    pkg: u32,
    algo: Algo = .none,
    /// Lowercase hex (dpkg, rpm) or apk's `Q1` base64 SHA-1.
    digest: []const u8 = "",
    config: bool = false,
    /// File mode recorded by the package (rpm FILEMODES, apk a: lines); 0 when unknown (dpkg).
    mode: u16 = 0,
};

/// Recorded databases for tests and fuzzing (regenerate with fixtures/make_fixtures.py).
pub const fixtures = struct {
    pub const rpmdb = @embedFile("fixtures/rpmdb.sqlite");
    pub const wal_db = @embedFile("fixtures/wal.sqlite");
    pub const wal = @embedFile("fixtures/wal.sqlite-wal");
};

/// Bounds for hostile databases.
pub const max_db_bytes = 512 * 1024 * 1024;
pub const max_list_bytes = 64 * 1024 * 1024;

pub const Db = struct {
    gpa: std.mem.Allocator,
    arena_state: std.heap.ArenaAllocator,
    packages: std.ArrayList(Package) = .empty,
    files: std.StringHashMapUnmanaged(FileRef) = .empty,
    /// Additional owners of a path beyond the first (shared directories, mostly).
    extra: std.StringHashMapUnmanaged(std.ArrayList(u32)) = .empty,
    /// dpkg diversions: diverted-to path -> package that owns the original.
    diverted_to: std.StringHashMapUnmanaged(u32) = .empty,
    /// Paths with a diversion in place, which `dpkg -S` reports specially.
    diverted_from: std.StringHashMapUnmanaged(void) = .empty,
    managers: std.EnumSet(Manager) = .empty,
    /// dpkg md5sums have been read.
    digests_loaded: bool = false,
    /// Parts of the databases that could not be read.
    problems: std.ArrayList([]const u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Db {
        return .{ .gpa = gpa, .arena_state = .init(gpa) };
    }

    pub fn deinit(db: *Db) void {
        db.packages.deinit(db.gpa);
        db.files.deinit(db.gpa);
        var it = db.extra.valueIterator();
        while (it.next()) |l| l.deinit(db.gpa);
        db.extra.deinit(db.gpa);
        db.diverted_to.deinit(db.gpa);
        db.diverted_from.deinit(db.gpa);
        db.problems.deinit(db.gpa);
        db.arena_state.deinit();
    }

    fn arena(db: *Db) std.mem.Allocator {
        return db.arena_state.allocator();
    }

    /// Load every package database present under the host root.
    pub fn load(gpa: std.mem.Allocator, h: Host) !Db {
        var db = Db.init(gpa);
        errdefer db.deinit();
        try db.loadDpkg(h);
        try db.loadRpm(h);
        try db.loadApk(h);
        return db;
    }

    fn problem(db: *Db, comptime fmt: []const u8, args: anytype) !void {
        try db.problems.append(db.gpa, try std.fmt.allocPrint(db.arena(), fmt, args));
    }

    fn addPackage(db: *Db, p: Package) !u32 {
        const id: u32 = @intCast(db.packages.items.len);
        try db.packages.append(db.gpa, p);
        return id;
    }

    fn addFile(db: *Db, path: []const u8, ref: FileRef) !void {
        const gop = try db.files.getOrPut(db.gpa, path);
        if (!gop.found_existing) {
            gop.value_ptr.* = ref;
            return;
        }
        if (gop.value_ptr.pkg == ref.pkg) return;
        const extra = try db.extra.getOrPut(db.gpa, path);
        if (!extra.found_existing) extra.value_ptr.* = .empty;
        for (extra.value_ptr.items) |p| if (p == ref.pkg) return;
        try extra.value_ptr.append(db.gpa, ref.pkg);
    }

    // dpkg ------------------------------------------------------------------------------------

    fn loadDpkg(db: *Db, h: Host) !void {
        const status = h.readAlloc(db.arena(), "/var/lib/dpkg/status", max_db_bytes) catch |e| switch (e) {
            error.FileNotFound => return,
            error.OutOfMemory => return error.OutOfMemory,
            else => return db.problem("dpkg status: {t}", .{e}),
        };
        db.managers.insert(.dpkg);

        // Versions and conffiles from status; the file lists name the packages that own files.
        var versions: std.StringHashMapUnmanaged(Stanza) = .empty;
        defer versions.deinit(db.gpa);
        var stanzas = StanzaIterator{ .text = status };
        var conffiles: std.StringHashMapUnmanaged(void) = .empty;
        defer conffiles.deinit(db.gpa);
        while (stanzas.next()) |s| {
            if (s.package.len == 0) continue;
            const key = if (std.mem.eql(u8, s.multi_arch, "same") and s.arch.len > 0)
                try std.fmt.allocPrint(db.arena(), "{s}:{s}", .{ s.package, s.arch })
            else
                s.package;
            try versions.put(db.gpa, key, s);
            var lines = std.mem.splitScalar(u8, s.conffiles, '\n');
            while (lines.next()) |line| {
                var words = std.mem.tokenizeScalar(u8, line, ' ');
                const path = words.next() orelse continue;
                if (path[0] == '/') try conffiles.put(db.gpa, path, {});
            }
        }

        var dir = (h.openDir("/var/lib/dpkg/info") catch {
            return db.problem("/var/lib/dpkg/info: access denied", .{});
        }) orelse return;
        defer dir.close(h.io);
        var it = dir.iterate();
        var path_buf: [512]u8 = undefined;
        while (it.next(h.io) catch null) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".list")) continue;
            const stem = entry.name[0 .. entry.name.len - ".list".len];
            const path = std.fmt.bufPrint(&path_buf, "/var/lib/dpkg/info/{s}", .{entry.name}) catch continue;
            const list = h.readAlloc(db.arena(), path, max_list_bytes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    try db.problem("{s}: {t}", .{ path, e });
                    continue;
                },
            };
            const name = try db.arena().dupe(u8, stem);
            const colon = std.mem.indexOfScalar(u8, name, ':');
            const s = versions.get(name) orelse versions.get(if (colon) |c| name[0..c] else name);
            const id = try db.addPackage(.{
                .name = name,
                .base = if (colon) |c| name[0..c] else name,
                .version = if (s) |v| v.version else "",
                .arch = if (s) |v| v.arch else "",
                .manager = .dpkg,
            });
            var lines = std.mem.splitScalar(u8, list, '\n');
            while (lines.next()) |line| {
                if (line.len == 0 or line[0] != '/') continue;
                try db.addFile(line, .{ .pkg = id, .config = conffiles.contains(line) });
            }
        }

        if (h.readAlloc(db.arena(), "/var/lib/dpkg/diversions", max_list_bytes)) |text| {
            var lines = std.mem.splitScalar(u8, text, '\n');
            while (true) {
                const from = lines.next() orelse break;
                const to = lines.next() orelse break;
                const by = lines.next() orelse break; // diverting package, or ':' for a local one
                if (from.len == 0 or to.len == 0) continue;
                try db.diverted_from.put(db.gpa, from, {});
                // The package that ships `from` in its list, other than the diverting package,
                // now has its file at `to`.
                var ids: [16]u32 = undefined;
                for (db.owners(from, &ids)) |id| {
                    if (std.mem.eql(u8, db.packages.items[id].base, by)) continue;
                    try db.diverted_to.put(db.gpa, to, id);
                    break;
                }
            }
        } else |_| {}
    }

    /// Read every package's md5sums (deep tier).
    pub fn loadDigests(db: *Db, h: Host) !void {
        if (db.digests_loaded) return;
        db.digests_loaded = true;
        if (!db.managers.contains(.dpkg)) return;
        var path_buf: [512]u8 = undefined;
        var abs_buf: [4096]u8 = undefined;
        for (db.packages.items, 0..) |p, id| {
            if (p.manager != .dpkg) continue;
            const path = std.fmt.bufPrint(&path_buf, "/var/lib/dpkg/info/{s}.md5sums", .{p.name}) catch continue;
            const text = h.readAlloc(db.gpa, path, max_list_bytes) catch continue;
            defer db.gpa.free(text);
            var lines = std.mem.splitScalar(u8, text, '\n');
            while (lines.next()) |line| {
                if (line.len < 34 or line[32] != ' ') continue;
                const rel = std.mem.trimStart(u8, line[33..], " ");
                if (rel.len == 0 or rel.len + 1 > abs_buf.len) continue;
                abs_buf[0] = '/';
                @memcpy(abs_buf[1..][0..rel.len], rel);
                const ref = db.files.getPtr(abs_buf[0 .. rel.len + 1]) orelse continue;
                if (ref.pkg != id and !db.ownsAlso(abs_buf[0 .. rel.len + 1], @intCast(id))) continue;
                ref.algo = .md5;
                ref.digest = try db.arena().dupe(u8, line[0..32]);
            }
        }
    }

    fn ownsAlso(db: *Db, path: []const u8, id: u32) bool {
        const extra = db.extra.get(path) orelse return false;
        for (extra.items) |p| if (p == id) return true;
        return false;
    }

    // rpm -------------------------------------------------------------------------------------

    fn loadRpm(db: *Db, h: Host) !void {
        const bytes = h.readAlloc(db.gpa, "/var/lib/rpm/rpmdb.sqlite", max_db_bytes) catch |e| switch (e) {
            error.FileNotFound => {
                if (h.exists("/var/lib/rpm/Packages") or h.exists("/var/lib/rpm/Packages.db"))
                    try db.problem("rpm: BerkeleyDB and ndb databases are not supported (rpm 4.16+ uses SQLite)", .{});
                return;
            },
            error.OutOfMemory => return error.OutOfMemory,
            else => return db.problem("rpmdb.sqlite: {t}", .{e}),
        };
        defer db.gpa.free(bytes);
        const wal = h.readAlloc(db.gpa, "/var/lib/rpm/rpmdb.sqlite-wal", max_db_bytes) catch null;
        defer if (wal) |w| db.gpa.free(w);
        db.managers.insert(.rpm);
        db.loadRpmBytes(bytes, wal) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => try db.problem("rpmdb.sqlite: {t}", .{e}),
        };
    }

    pub fn loadRpmBytes(db: *Db, bytes: []const u8, wal: ?[]const u8) !void {
        var sdb = try sqlite.Db.open(db.gpa, bytes, wal);
        defer sdb.deinit();
        var rows = try sdb.rows(try sdb.tableRoot("Packages"));
        defer rows.deinit();
        var files: std.ArrayList(rpm.File) = .empty;
        defer files.deinit(db.gpa);
        while (try rows.next()) |row| {
            var rec = sqlite.Record.init(row.payload) catch continue;
            _ = rec.next() catch continue;
            const blob = (rec.next() catch continue) orelse continue;
            if (blob != .blob) continue;
            const hdr = rpm.Header.parse(blob.blob) catch continue;
            const name = hdr.string(.name) orelse continue;
            const version = hdr.string(.version) orelse "";
            const release = hdr.string(.release) orelse "";
            const arch = hdr.string(.arch) orelse "";
            const a = db.arena();
            const epoch = hdr.int32(.epoch);
            const full_version = if (epoch) |e|
                try std.fmt.allocPrint(a, "{d}:{s}-{s}", .{ e, version, release })
            else
                try std.fmt.allocPrint(a, "{s}-{s}", .{ version, release });
            const nevra = if (arch.len > 0)
                try std.fmt.allocPrint(a, "{s}-{s}-{s}.{s}", .{ name, version, release, arch })
            else
                try std.fmt.allocPrint(a, "{s}-{s}-{s}", .{ name, version, release });
            const id = try db.addPackage(.{ .name = nevra, .base = try a.dupe(u8, name), .version = full_version, .arch = try a.dupe(u8, arch), .manager = .rpm });
            files.clearRetainingCapacity();
            rpm.files(a, hdr, &files, db.gpa) catch continue;
            const algo: Algo = switch (@as(rpm.DigestAlgo, @fromBackingInt(@intCast(hdr.int32(.filedigestalgo) orelse 1)))) {
                .md5 => .md5,
                .sha1 => .sha1,
                .sha256 => .sha256,
                .sha384 => .sha384,
                .sha512 => .sha512,
                _ => .none,
            };
            for (files.items) |f| {
                try db.addFile(f.path, .{
                    .pkg = id,
                    .algo = if (f.digest.len > 0) algo else .none,
                    .digest = try a.dupe(u8, f.digest),
                    .config = f.flags & rpm.file_config != 0,
                    .mode = f.mode,
                });
            }
        }
    }

    // apk -------------------------------------------------------------------------------------

    fn loadApk(db: *Db, h: Host) !void {
        const text = h.readAlloc(db.arena(), "/lib/apk/db/installed", max_db_bytes) catch |e| switch (e) {
            error.FileNotFound => return,
            error.OutOfMemory => return error.OutOfMemory,
            else => return db.problem("apk installed: {t}", .{e}),
        };
        db.managers.insert(.apk);
        try db.loadApkText(text);
    }

    pub fn loadApkText(db: *Db, text: []const u8) !void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        var id: ?u32 = null;
        var dir: []const u8 = "";
        var last_file: ?[]const u8 = null;
        var pending: Package = .{ .name = "", .base = "", .version = "", .arch = "", .manager = .apk };
        while (lines.next()) |line| {
            if (line.len == 0) {
                id = null;
                pending = .{ .name = "", .base = "", .version = "", .arch = "", .manager = .apk };
                last_file = null;
                continue;
            }
            if (line.len < 2 or line[1] != ':') continue;
            const value = line[2..];
            switch (line[0]) {
                'P' => pending.name = value,
                'V' => pending.version = value,
                'A' => pending.arch = value,
                'F' => {
                    dir = value;
                    last_file = null;
                },
                'R' => {
                    if (id == null) {
                        if (pending.name.len == 0) continue;
                        pending.base = pending.name;
                        id = try db.addPackage(pending);
                    }
                    const path = if (dir.len == 0)
                        try std.fmt.allocPrint(db.arena(), "/{s}", .{value})
                    else
                        try std.fmt.allocPrint(db.arena(), "/{s}/{s}", .{ dir, value });
                    try db.addFile(path, .{ .pkg = id.? });
                    last_file = path;
                },
                'Z' => if (last_file) |p| if (db.files.getPtr(p)) |ref| if (std.mem.startsWith(u8, value, "Q1")) {
                    ref.algo = .sha1;
                    ref.digest = value;
                },
                // a:uid:gid:mode for the preceding file.
                'a' => if (last_file) |p| if (db.files.getPtr(p)) |ref| {
                    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse continue;
                    const perm = std.fmt.parseInt(u16, value[colon + 1 ..], 8) catch continue;
                    ref.mode = 0o100000 | perm;
                },
                else => {},
            }
        }
    }

    // queries ---------------------------------------------------------------------------------

    pub fn owner(db: *const Db, path: []const u8) ?*const Package {
        if (db.diverted_to.get(path)) |id| return &db.packages.items[id];
        const ref = db.files.get(path) orelse return null;
        return &db.packages.items[ref.pkg];
    }

    /// Every package that lists `path`.
    pub fn owners(db: *const Db, path: []const u8, out: []u32) []u32 {
        const ref = db.files.get(path) orelse return out[0..0];
        if (out.len == 0) return out;
        out[0] = ref.pkg;
        var n: usize = 1;
        if (db.extra.get(path)) |extra| for (extra.items) |p| {
            if (n == out.len) break;
            out[n] = p;
            n += 1;
        };
        return out[0..n];
    }

    /// `owner` that also tries the merged-/usr spelling of the path.
    pub fn ownerResolved(db: *const Db, path: []const u8) ?*const Package {
        if (db.owner(path)) |p| return p;
        var buf: [4096]u8 = undefined;
        const aliased = usrAlias(path, &buf) orelse return null;
        return db.owner(aliased);
    }

    pub fn ownership(db: *Db) @import("../scan.zig").Ownership {
        return .{ .ctx = db, .ownerFn = ownerName };
    }

    fn ownerName(ctx: *anyopaque, path: []const u8) ?[]const u8 {
        const db: *Db = @ptrCast(@alignCast(ctx));
        const p = db.ownerResolved(path) orelse return null;
        return p.name;
    }

    pub fn find(db: *const Db, base: []const u8) ?*const Package {
        for (db.packages.items) |*p| if (std.mem.eql(u8, p.base, base)) return p;
        return null;
    }
};

/// /bin <-> /usr/bin and friends, for merged-/usr systems.
pub fn usrAlias(path: []const u8, buf: []u8) ?[]const u8 {
    const merged = [_][]const u8{ "bin/", "sbin/", "lib/", "lib32/", "lib64/", "libx32/" };
    if (std.mem.startsWith(u8, path, "/usr/")) {
        for (merged) |m| if (std.mem.startsWith(u8, path[5..], m)) return path[4..];
        return null;
    }
    for (merged) |m| if (path.len > 1 and std.mem.startsWith(u8, path[1..], m)) {
        return std.fmt.bufPrint(buf, "/usr{s}", .{path}) catch null;
    };
    return null;
}

/// One dpkg status stanza (only the fields used here).
pub const Stanza = struct {
    package: []const u8 = "",
    version: []const u8 = "",
    arch: []const u8 = "",
    status: []const u8 = "",
    multi_arch: []const u8 = "",
    source: []const u8 = "",
    /// Continuation lines of `Conffiles:`, newline separated.
    conffiles: []const u8 = "",

    pub fn installed(s: Stanza) bool {
        return std.mem.endsWith(u8, s.status, " installed");
    }
};

/// Iterates the stanzas of a dpkg status file (or an apt Packages index).
pub const StanzaIterator = struct {
    text: []const u8,
    pos: usize = 0,

    pub fn next(it: *StanzaIterator) ?Stanza {
        while (it.pos < it.text.len and (it.text[it.pos] == '\n' or it.text[it.pos] == '\r')) it.pos += 1;
        if (it.pos >= it.text.len) return null;
        var s: Stanza = .{};
        var field: enum { other, conffiles } = .other;
        var conf_start: ?usize = null;
        var conf_end: usize = 0;
        while (it.pos < it.text.len) {
            const end = std.mem.indexOfScalarPos(u8, it.text, it.pos, '\n') orelse it.text.len;
            const line = std.mem.trimEnd(u8, it.text[it.pos..end], "\r");
            const line_start = it.pos;
            it.pos = @min(end + 1, it.text.len);
            if (line.len == 0) break;
            if (line[0] == ' ' or line[0] == '\t') {
                if (field == .conffiles) {
                    if (conf_start == null) conf_start = line_start;
                    conf_end = end;
                }
                continue;
            }
            field = .other;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const key = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.mem.eql(u8, key, "Package")) s.package = value else if (std.mem.eql(u8, key, "Version")) s.version = value else if (std.mem.eql(u8, key, "Architecture")) s.arch = value else if (std.mem.eql(u8, key, "Status")) s.status = value else if (std.mem.eql(u8, key, "Multi-Arch")) s.multi_arch = value else if (std.mem.eql(u8, key, "Source")) s.source = value else if (std.mem.eql(u8, key, "Conffiles")) field = .conffiles;
        }
        if (conf_start) |c| s.conffiles = it.text[c..conf_end];
        return s;
    }
};

// Tests ---------------------------------------------------------------------------------------

const Fixture = @import("../host.zig").Fixture;

pub fn writeDpkgFixture(fx: *Fixture) !void {
    try fx.file("/var/lib/dpkg/status",
        \\Package: coreutils
        \\Status: install ok installed
        \\Priority: required
        \\Architecture: amd64
        \\Multi-Arch: foreign
        \\Version: 9.4-3ubuntu6
        \\Description: GNU core utilities
        \\ with a continuation line
        \\
        \\Package: libc6
        \\Status: install ok installed
        \\Architecture: amd64
        \\Multi-Arch: same
        \\Version: 2.39-0ubuntu8.3
        \\
        \\Package: openssh-server
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1:9.6p1-3ubuntu13.5
        \\Conffiles:
        \\ /etc/ssh/moduli 1a2b3c
        \\ /etc/pam.d/sshd 4d5e6f
        \\
    );
    try fx.file("/var/lib/dpkg/info/coreutils.list", "/.\n/usr\n/usr/bin\n/usr/bin/ls\n/usr/bin/cat\n");
    try fx.file("/var/lib/dpkg/info/coreutils.md5sums", "c2a8b0ae0e4f2fa7ab1a5a2e0d3d8b19  usr/bin/ls\n" ++ "0f343b0931126a20f133d67c2b018a3b  usr/bin/cat\n");
    try fx.file("/var/lib/dpkg/info/libc6:amd64.list", "/.\n/usr\n/usr/lib\n/usr/lib/x86_64-linux-gnu/libc.so.6\n");
    try fx.file("/var/lib/dpkg/info/openssh-server.list", "/.\n/usr\n/usr/sbin\n/usr/sbin/sshd\n/etc/ssh/moduli\n/etc/pam.d/sshd\n");
}

test "dpkg ownership, multi-arch names, shared directories and conffiles" {
    const gpa = std.testing.allocator;
    var fx = try Fixture.init();
    defer fx.deinit();
    try writeDpkgFixture(&fx);
    var db = try Db.load(gpa, fx.host(.linux));
    defer db.deinit();
    try std.testing.expect(db.managers.contains(.dpkg));
    try std.testing.expectEqualStrings("coreutils", db.owner("/usr/bin/ls").?.name);
    try std.testing.expectEqualStrings("9.4-3ubuntu6", db.owner("/usr/bin/ls").?.version);
    try std.testing.expectEqualStrings("libc6:amd64", db.owner("/usr/lib/x86_64-linux-gnu/libc.so.6").?.name);
    try std.testing.expectEqualStrings("libc6", db.owner("/usr/lib/x86_64-linux-gnu/libc.so.6").?.base);
    try std.testing.expect(db.owner("/usr/bin/xmrig") == null);
    try std.testing.expect(db.owner("/bin/ls") == null); // literal, like dpkg -S
    try std.testing.expectEqualStrings("coreutils", db.ownerResolved("/bin/ls").?.name);
    var owners: [8]u32 = undefined;
    try std.testing.expectEqual(@as(usize, 3), db.owners("/usr", &owners).len);
    try std.testing.expect(db.files.get("/etc/pam.d/sshd").?.config);
    try std.testing.expect(!db.files.get("/usr/sbin/sshd").?.config);
    try db.loadDigests(fx.host(.linux));
    try std.testing.expectEqualStrings("c2a8b0ae0e4f2fa7ab1a5a2e0d3d8b19", db.files.get("/usr/bin/ls").?.digest);
    try std.testing.expectEqual(Algo.md5, db.files.get("/usr/bin/cat").?.algo);
}

test "rpm 4.16 SQLite database: NEVRA owners, digests, config flags and big headers" {
    const gpa = std.testing.allocator;
    var db = Db.init(gpa);
    defer db.deinit();
    try db.loadRpmBytes(@embedFile("fixtures/rpmdb.sqlite"), null);
    try std.testing.expectEqual(@as(usize, 4), db.packages.items.len);
    try std.testing.expectEqualStrings("bash-5.2.26-3.fc40.x86_64", db.owner("/usr/bin/bash").?.name);
    try std.testing.expectEqualStrings("1:1.9.15-1.p5.fc40", db.owner("/usr/bin/sudo").?.version);
    const bash = db.files.get("/usr/bin/bash").?;
    try std.testing.expectEqual(Algo.sha256, bash.algo);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("bash-binary\n", &want, .{});
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(want, .lower), bash.digest);
    try std.testing.expect(db.files.get("/etc/skel/.bashrc").?.config);
    try std.testing.expectEqualStrings("kernel-core-6.8.5-301.fc40.x86_64", db.owner("/usr/lib/modules/6.8.5-301.fc40.x86_64/kernel/drivers/net/mod299.ko.xz").?.name);
    try std.testing.expect(db.find("gpg-pubkey") != null);
}

test "apk installed database" {
    const gpa = std.testing.allocator;
    var db = Db.init(gpa);
    defer db.deinit();
    try db.loadApkText(
        \\C:Q1abc=
        \\P:busybox
        \\V:1.36.1-r29
        \\A:x86_64
        \\F:bin
        \\R:busybox
        \\a:0:0:755
        \\Z:Q1hHaq8ch7nfI2Ht9U6RiuERhRFm8=
        \\F:etc
        \\R:securetty
        \\
        \\P:musl
        \\V:1.2.5-r0
        \\F:lib
        \\R:ld-musl-x86_64.so.1
        \\
    );
    try std.testing.expectEqualStrings("busybox", db.owner("/bin/busybox").?.name);
    try std.testing.expectEqualStrings("1.36.1-r29", db.owner("/etc/securetty").?.version);
    try std.testing.expectEqual(Algo.sha1, db.files.get("/bin/busybox").?.algo);
    try std.testing.expectEqualStrings("musl", db.owner("/lib/ld-musl-x86_64.so.1").?.name);
}

test "usr aliases" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/bin/ls", usrAlias("/usr/bin/ls", &buf).?);
    try std.testing.expectEqualStrings("/usr/lib64/ld.so", usrAlias("/lib64/ld.so", &buf).?);
    try std.testing.expect(usrAlias("/usr/share/x", &buf) == null);
    try std.testing.expect(usrAlias("/etc/passwd", &buf) == null);
}

test "live: ownership answers match dpkg -S and rpm -qf for 1,000 sampled paths" {
    const builtin = @import("builtin");
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const h = try Host.openLive(io);
    defer h.close();
    var db = try Db.load(gpa, h);
    defer db.deinit();
    if (db.managers.count() == 0) return error.SkipZigTest;

    // Regular files the databases list, in a stable order, sampled evenly.
    var all: std.ArrayList([]const u8) = .empty;
    defer all.deinit(gpa);
    var it = db.files.keyIterator();
    while (it.next()) |k| {
        const p = k.*;
        if (std.mem.indexOfAny(u8, p, "*?[]\\ \n") != null) continue;
        if (db.diverted_from.contains(p) or db.diverted_to.contains(p)) continue;
        const st = h.stat(p, false) catch continue;
        if (st.kind() != .file) continue;
        try all.append(gpa, p);
    }
    std.mem.sort([]const u8, all.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    const want_n = @min(all.items.len, 1000);
    var sample: std.ArrayList([]const u8) = .empty;
    defer sample.deinit(gpa);
    for (0..want_n) |i| try sample.append(gpa, all.items[i * all.items.len / want_n]);

    var mismatches: usize = 0;
    if (db.managers.contains(.dpkg)) {
        var start: usize = 0;
        while (start < sample.items.len) : (start += 100) {
            const batch = sample.items[start..@min(start + 100, sample.items.len)];
            var argv: std.ArrayList([]const u8) = .empty;
            defer argv.deinit(gpa);
            try argv.appendSlice(gpa, &.{ "dpkg", "-S" });
            try argv.appendSlice(gpa, batch);
            const r = try std.process.run(gpa, io, .{ .argv = argv.items });
            defer gpa.free(r.stdout);
            defer gpa.free(r.stderr);
            var lines = std.mem.splitScalar(u8, r.stdout, '\n');
            while (lines.next()) |line| {
                if (line.len == 0 or std.mem.startsWith(u8, line, "diversion by")) continue;
                const sep = std.mem.indexOf(u8, line, ": /") orelse continue;
                const path = line[sep + 2 ..];
                var ids: [64]u32 = undefined;
                const ours = db.owners(path, &ids);
                var theirs = std.mem.splitSequence(u8, line[0..sep], ", ");
                var count: usize = 0;
                while (theirs.next()) |name| {
                    count += 1;
                    var found = false;
                    for (ours) |id| if (std.mem.eql(u8, db.packages.items[id].name, name)) {
                        found = true;
                    };
                    if (!found) {
                        mismatches += 1;
                        std.debug.print("dpkg -S says {s} owns {s}; zav does not\n", .{ name, path });
                    }
                }
                if (count != ours.len) {
                    mismatches += 1;
                    std.debug.print("{s}: dpkg -S lists {d} owners, zav {d}\n", .{ path, count, ours.len });
                }
            }
        }
    }
    if (db.managers.contains(.rpm)) {
        for (sample.items) |path| {
            var ids: [64]u32 = undefined;
            const ours = db.owners(path, &ids);
            if (ours.len == 0 or db.packages.items[ours[0]].manager != .rpm) continue;
            const r = try std.process.run(gpa, io, .{ .argv = &.{ "rpm", "-qf", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n", path } });
            defer gpa.free(r.stdout);
            defer gpa.free(r.stderr);
            var lines = std.mem.tokenizeScalar(u8, r.stdout, '\n');
            var count: usize = 0;
            while (lines.next()) |name| {
                count += 1;
                var found = false;
                for (ours) |id| if (std.mem.eql(u8, db.packages.items[id].name, name)) {
                    found = true;
                };
                if (!found) {
                    mismatches += 1;
                    std.debug.print("rpm -qf says {s} owns {s}; zav does not\n", .{ name, path });
                }
            }
            if (count != ours.len) {
                mismatches += 1;
                std.debug.print("{s}: rpm -qf lists {d} owners, zav {d}\n", .{ path, count, ours.len });
            }
        }
    }
    std.debug.print("ownership: compared {d} sampled paths of {d}, {d} mismatches\n", .{ sample.items.len, all.items.len, mismatches });
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
