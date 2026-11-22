//! The .zavcve index: vulnerability data compiled into the same signed, mmapped container as
//! .zavdb (format.cve_magic), answering package and CPE queries without parsing at query time.
//!
//! Sections, all little-endian `extern struct` arrays plus one string pool:
//!   cve_strings         string bytes; every reference is (offset, length) into it
//!   cve_records         one per vulnerability, sorted by id: CVSS, severity, KEV flag, due date,
//!                       ransomware use, alias, summary
//!   cve_packages        (ecosystem, name) keys sorted by hash, each pointing at a run of ranges
//!   cve_package_ranges  affected intervals per package in the package's version scheme
//!   cve_cpes            (vendor, product) keys sorted by hash
//!   cve_cpe_ranges      NVD cpeMatch intervals and exact versions
//!
//! Versions are stored as canonical strings (trimmed; leading `v` dropped for Go and semver;
//! lowercased for PEP 440 and Maven) and compared with the scheme's comparator (version.zig)
//! directly on the mapped bytes, so a query allocates nothing and the index stays clean,
//! file-backed memory.
const std = @import("std");
const db = @import("../db/root.zig");
const format = db.format;
const version = @import("version.zig");
const feeds = @import("feeds.zig");

pub const Str = extern struct {
    off: u32 = 0,
    len: u32 = 0,
};

pub const RecordFlags = packed struct(u8) {
    kev: bool = false,
    ransomware: bool = false,
    withdrawn: bool = false,
    _: u5 = 0,
};

pub const Severity = enum(u8) { none, low, medium, high, critical };

pub const Record = extern struct {
    id: Str,
    alias: Str,
    summary: Str,
    /// CVSS base score times ten.
    cvss_x10: u16,
    severity: Severity,
    flags: RecordFlags,
    /// KEV due date as days since the Unix epoch; 0 when not in KEV.
    kev_due_day: u32,
};

pub const Package = extern struct {
    hash: u64,
    ecosystem: Str,
    name: Str,
    first: u32,
    count: u32,
    /// version.Scheme as an integer: a mapped file must not hold an invalid enum value.
    scheme: u8,
    _pad: [7]u8 = @splat(0),
};

pub const RangeFlags = packed struct(u8) {
    has_start: bool = false,
    start_inclusive: bool = true,
    has_end: bool = false,
    end_inclusive: bool = false,
    _: u4 = 0,
};

pub const Range = extern struct {
    record: u32,
    flags: RangeFlags,
    _pad: [3]u8 = @splat(0),
    start: Str,
    end: Str,
};

pub const Cpe = extern struct {
    hash: u64,
    vendor: Str,
    product: Str,
    first: u32,
    count: u32,
};

comptime {
    std.debug.assert(@sizeOf(Str) == 8);
    std.debug.assert(@sizeOf(Record) == 32);
    std.debug.assert(@sizeOf(Package) == 40);
    std.debug.assert(@sizeOf(Range) == 24);
    std.debug.assert(@sizeOf(Cpe) == 32);
}

/// The version scheme of an OSV ecosystem.
pub fn schemeFor(ecosystem: []const u8) version.Scheme {
    const base = std.mem.sliceTo(ecosystem, ':');
    const eq = std.ascii.eqlIgnoreCase;
    if (eq(base, "PyPI")) return .pep440;
    if (eq(base, "Go")) return .go;
    if (eq(base, "Maven")) return .maven;
    if (eq(base, "Debian") or eq(base, "Ubuntu")) return .dpkg;
    if (eq(base, "Alpine") or eq(base, "Wolfi") or eq(base, "Chainguard")) return .apk;
    if (eq(base, "Rocky Linux") or eq(base, "AlmaLinux") or eq(base, "Red Hat") or eq(base, "openSUSE") or eq(base, "SUSE") or eq(base, "Mageia")) return .rpm;
    return .semver;
}

/// Canonical package names: lowercase, and PyPI's PEP 503 normalisation (runs of -, _ and . are
/// one '-').
pub fn canonicalName(buf: []u8, ecosystem: []const u8, name: []const u8) []const u8 {
    const pypi = std.ascii.eqlIgnoreCase(std.mem.sliceTo(ecosystem, ':'), "PyPI");
    var n: usize = 0;
    var last_sep = false;
    for (name) |c| {
        if (n == buf.len) break;
        if (pypi and (c == '-' or c == '_' or c == '.')) {
            if (!last_sep) {
                buf[n] = '-';
                n += 1;
            }
            last_sep = true;
            continue;
        }
        last_sep = false;
        buf[n] = std.ascii.toLower(c);
        n += 1;
    }
    return buf[0..n];
}

pub fn canonicalVersion(buf: []u8, scheme: version.Scheme, v: []const u8) []const u8 {
    var t = std.mem.trim(u8, v, " \t\r\n");
    if ((scheme == .go or scheme == .semver) and t.len > 1 and t[0] == 'v' and std.ascii.isDigit(t[1])) t = t[1..];
    const n = @min(t.len, buf.len);
    if (scheme == .pep440 or scheme == .maven) return std.ascii.lowerString(buf[0..n], t[0..n]);
    @memcpy(buf[0..n], t[0..n]);
    return buf[0..n];
}

fn keyHash(a: []const u8, b: []const u8) u64 {
    var h = std.hash.XxHash3.init(0x2a);
    h.update(a);
    h.update("\x00");
    h.update(b);
    return h.final();
}

fn sevFrom(text: []const u8) Severity {
    if (std.ascii.eqlIgnoreCase(text, "CRITICAL")) return .critical;
    if (std.ascii.eqlIgnoreCase(text, "HIGH")) return .high;
    if (std.ascii.eqlIgnoreCase(text, "MEDIUM") or std.ascii.eqlIgnoreCase(text, "MODERATE")) return .medium;
    if (std.ascii.eqlIgnoreCase(text, "LOW")) return .low;
    return .none;
}

fn severityFromScore(score: f64) Severity {
    if (score >= 9.0) return .critical;
    if (score >= 7.0) return .high;
    if (score >= 4.0) return .medium;
    if (score > 0) return .low;
    return .none;
}

/// YYYY-MM-DD to days since the epoch.
pub fn dayNumber(date: []const u8) u32 {
    if (date.len < 10) return 0;
    const y = std.fmt.parseInt(u32, date[0..4], 10) catch return 0;
    const m = std.fmt.parseInt(u32, date[5..7], 10) catch return 0;
    const d = std.fmt.parseInt(u32, date[8..10], 10) catch return 0;
    if (m < 1 or m > 12 or d < 1 or d > 31 or y < 1970) return 0;
    // Days from civil (Howard Hinnant's algorithm).
    const yy: i64 = @as(i64, y) - @intFromBool(m <= 2);
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp: i64 = @mod(@as(i64, m) + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + @as(i64, d) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return if (days < 0) 0 else @intCast(days);
}

// Builder ---------------------------------------------------------------------------------------

const BRecord = struct { id: []const u8, alias: []const u8 = "", summary: []const u8 = "", cvss_x10: u16 = 0, severity: Severity = .none, flags: RecordFlags = .{}, due: u32 = 0 };
const BRange = struct { record_id: []const u8, flags: RangeFlags, start: []const u8 = "", end: []const u8 = "" };
const BKey = struct { a: []const u8, b: []const u8, scheme: version.Scheme = .semver, ranges: std.ArrayList(BRange) = .empty };

pub const Builder = struct {
    gpa: std.mem.Allocator,
    arena_state: std.heap.ArenaAllocator,
    records: std.StringHashMapUnmanaged(BRecord) = .empty,
    /// GHSA and other ids that alias a CVE, so OSV records join the CVE's KEV and NVD data.
    aliases: std.StringHashMapUnmanaged([]const u8) = .empty,
    packages: std.StringHashMapUnmanaged(BKey) = .empty,
    cpes: std.StringHashMapUnmanaged(BKey) = .empty,

    pub fn init(gpa: std.mem.Allocator) Builder {
        return .{ .gpa = gpa, .arena_state = .init(gpa) };
    }

    pub fn deinit(b: *Builder) void {
        b.records.deinit(b.gpa);
        b.aliases.deinit(b.gpa);
        var it = b.packages.valueIterator();
        while (it.next()) |k| k.ranges.deinit(b.gpa);
        b.packages.deinit(b.gpa);
        var ci = b.cpes.valueIterator();
        while (ci.next()) |k| k.ranges.deinit(b.gpa);
        b.cpes.deinit(b.gpa);
        b.arena_state.deinit();
    }

    fn arena(b: *Builder) std.mem.Allocator {
        return b.arena_state.allocator();
    }

    fn record(b: *Builder, id: []const u8) !*BRecord {
        const gop = try b.records.getOrPut(b.gpa, id);
        if (!gop.found_existing) {
            const owned = try b.arena().dupe(u8, id);
            gop.key_ptr.* = owned;
            gop.value_ptr.* = .{ .id = owned };
        }
        return gop.value_ptr;
    }

    pub fn addKev(b: *Builder, kev: feeds.Kev) !void {
        for (kev.vulnerabilities) |v| {
            const r = try b.record(v.cveID);
            r.flags.kev = true;
            r.flags.ransomware = v.ransomware();
            r.due = dayNumber(v.dueDate);
            if (r.summary.len == 0) r.summary = try b.arena().dupe(u8, v.vulnerabilityName);
        }
    }

    pub fn addNvd(b: *Builder, page: feeds.NvdPage) !void {
        const a = b.arena();
        for (page.vulnerabilities) |item| {
            const c = item.cve;
            const r = try b.record(c.id);
            const score = c.cvss();
            r.cvss_x10 = @intFromFloat(@min(@max(score.score, 0), 10) * 10 + 0.5);
            r.severity = if (sevFrom(score.severity) != .none) sevFrom(score.severity) else severityFromScore(score.score);
            r.flags.withdrawn = std.mem.eql(u8, c.vulnStatus, "Rejected");
            const desc = c.description();
            r.summary = try a.dupe(u8, desc[0..@min(desc.len, 512)]);
            for (c.configurations) |cfg| for (cfg.nodes) |node| {
                if (node.negate) continue;
                for (node.cpeMatch) |m| {
                    if (!m.vulnerable) continue;
                    const cpe = feeds.Cpe.parse(m.criteria) orelse continue;
                    var flags: RangeFlags = .{};
                    var start: []const u8 = "";
                    var end: []const u8 = "";
                    if (m.versionStartIncluding) |v| {
                        flags.has_start = true;
                        start = v;
                    } else if (m.versionStartExcluding) |v| {
                        flags.has_start = true;
                        flags.start_inclusive = false;
                        start = v;
                    }
                    if (m.versionEndIncluding) |v| {
                        flags.has_end = true;
                        flags.end_inclusive = true;
                        end = v;
                    } else if (m.versionEndExcluding) |v| {
                        flags.has_end = true;
                        end = v;
                    }
                    if (!flags.has_start and !flags.has_end and !std.mem.eql(u8, cpe.version, "*") and !std.mem.eql(u8, cpe.version, "-")) {
                        // An exact version, with the update field (2.0 beta9 -> 2.0-beta9).
                        const exact = if (std.mem.eql(u8, cpe.update, "*") or std.mem.eql(u8, cpe.update, "-") or cpe.update.len == 0)
                            cpe.version
                        else
                            try std.fmt.allocPrint(a, "{s}-{s}", .{ cpe.version, cpe.update });
                        flags = .{ .has_start = true, .start_inclusive = true, .has_end = true, .end_inclusive = true };
                        start = exact;
                        end = exact;
                    }
                    try b.addRange(&b.cpes, cpe.vendor, cpe.product, .rpm, .{ .record_id = r.id, .flags = flags, .start = try a.dupe(u8, start), .end = try a.dupe(u8, end) });
                }
            };
        }
    }

    fn addRange(b: *Builder, map: *std.StringHashMapUnmanaged(BKey), first: []const u8, second: []const u8, scheme: version.Scheme, range: BRange) !void {
        const key = try std.fmt.allocPrint(b.arena(), "{s}\x00{s}", .{ first, second });
        const gop = try map.getOrPut(b.gpa, key);
        if (!gop.found_existing) gop.value_ptr.* = .{ .a = key[0..first.len], .b = key[first.len + 1 ..], .scheme = scheme };
        try gop.value_ptr.ranges.append(b.gpa, range);
    }

    pub fn addOsv(b: *Builder, v: feeds.OsvVuln) !void {
        const a = b.arena();
        var ids: [8][]const u8 = undefined;
        const cves = v.cves(&ids);
        const id = if (cves.len > 0) cves[0] else v.id;
        const r = try b.record(id);
        if (!std.mem.eql(u8, id, v.id)) r.alias = try a.dupe(u8, v.id);
        if (r.summary.len == 0) r.summary = try a.dupe(u8, v.summary[0..@min(v.summary.len, 512)]);
        if (v.withdrawn != null) r.flags.withdrawn = true;
        for (v.affected) |aff| {
            const eco = aff.package.ecosystem;
            if (eco.len == 0 or aff.package.name.len == 0) continue;
            const scheme = schemeFor(eco);
            var name_buf: [256]u8 = undefined;
            var eco_buf: [64]u8 = undefined;
            const name = try a.dupe(u8, canonicalName(&name_buf, eco, aff.package.name));
            const eco_l = try a.dupe(u8, std.ascii.lowerString(eco_buf[0..@min(eco.len, eco_buf.len)], eco[0..@min(eco.len, eco_buf.len)]));
            var vbuf: [128]u8 = undefined;
            for (aff.ranges) |range| {
                if (std.mem.eql(u8, range.type, "GIT")) continue;
                var open: ?[]const u8 = null;
                for (range.events) |e| {
                    if (e.introduced) |x| {
                        open = if (std.mem.eql(u8, x, "0")) "" else try a.dupe(u8, canonicalVersion(&vbuf, scheme, x));
                    } else if (e.fixed orelse e.last_affected) |y| {
                        const start = open orelse continue;
                        try b.addRange(&b.packages, eco_l, name, scheme, .{
                            .record_id = r.id,
                            .flags = .{ .has_start = start.len > 0, .start_inclusive = true, .has_end = true, .end_inclusive = e.fixed == null },
                            .start = start,
                            .end = try a.dupe(u8, canonicalVersion(&vbuf, scheme, y)),
                        });
                        open = null;
                    }
                }
                if (open) |start| try b.addRange(&b.packages, eco_l, name, scheme, .{ .record_id = r.id, .flags = .{ .has_start = start.len > 0, .start_inclusive = true }, .start = start });
            }
            // Explicit version lists (when no range describes them).
            if (aff.ranges.len == 0) for (aff.versions) |ver| {
                const cv = try a.dupe(u8, canonicalVersion(&vbuf, scheme, ver));
                try b.addRange(&b.packages, eco_l, name, scheme, .{ .record_id = r.id, .flags = .{ .has_start = true, .has_end = true, .end_inclusive = true }, .start = cv, .end = cv });
            };
        }
    }

    /// Lay the sections out and write the signed (or unsigned) container.
    pub fn write(b: *Builder, io: std.Io, dir: std.Io.Dir, sub_path: []const u8, options: WriteOptions) !Summary {
        var out = try b.serialize();
        defer out.deinit(b.gpa);
        const sections = [_]db.writer.Section{
            .{ .kind = .cve_records, .hot = true, .bytes = out.records.items },
            .{ .kind = .cve_packages, .hot = true, .bytes = out.packages.items },
            .{ .kind = .cve_cpes, .hot = true, .bytes = out.cpes.items },
            .{ .kind = .cve_package_ranges, .bytes = out.package_ranges.items },
            .{ .kind = .cve_cpe_ranges, .bytes = out.cpe_ranges.items },
            .{ .kind = .cve_strings, .bytes = out.strings.items },
        };
        try db.writer.write(io, dir, sub_path, &sections, .{ .magic = format.cve_magic, .db_version = options.db_version, .build_unix_time = options.build_unix_time, .key_pair = options.key_pair });
        return out.summary;
    }

    pub const Serialized = struct {
        strings: std.ArrayList(u8) = .empty,
        records: std.ArrayList(u8) = .empty,
        packages: std.ArrayList(u8) = .empty,
        package_ranges: std.ArrayList(u8) = .empty,
        cpes: std.ArrayList(u8) = .empty,
        cpe_ranges: std.ArrayList(u8) = .empty,
        summary: Summary = .{},

        pub fn deinit(s: *Serialized, gpa: std.mem.Allocator) void {
            s.strings.deinit(gpa);
            s.records.deinit(gpa);
            s.packages.deinit(gpa);
            s.package_ranges.deinit(gpa);
            s.cpes.deinit(gpa);
            s.cpe_ranges.deinit(gpa);
        }
    };

    pub fn serialize(b: *Builder) !Serialized {
        const gpa = b.gpa;
        var out: Serialized = .{};
        errdefer out.deinit(gpa);
        var dedup: std.StringHashMapUnmanaged(Str) = .empty;
        defer dedup.deinit(gpa);
        const intern = struct {
            fn f(o: *Serialized, d: *std.StringHashMapUnmanaged(Str), g: std.mem.Allocator, text: []const u8) !Str {
                if (text.len == 0) return .{};
                if (d.get(text)) |s| return s;
                if (o.strings.items.len + text.len > std.math.maxInt(u32)) return error.IndexTooLarge;
                const s: Str = .{ .off = @intCast(o.strings.items.len), .len = @intCast(text.len) };
                try o.strings.appendSlice(g, text);
                try d.put(g, text, s);
                return s;
            }
        }.f;

        // Records sorted by id; their positions are the range targets.
        var ids: std.ArrayList([]const u8) = .empty;
        defer ids.deinit(gpa);
        var rit = b.records.keyIterator();
        while (rit.next()) |k| try ids.append(gpa, k.*);
        std.mem.sort([]const u8, ids.items, {}, lessStr);
        var position: std.StringHashMapUnmanaged(u32) = .empty;
        defer position.deinit(gpa);
        for (ids.items, 0..) |id, i| {
            try position.put(gpa, id, @intCast(i));
            const r = b.records.get(id).?;
            const rec: Record = .{ .id = try intern(&out, &dedup, gpa, r.id), .alias = try intern(&out, &dedup, gpa, r.alias), .summary = try intern(&out, &dedup, gpa, r.summary), .cvss_x10 = r.cvss_x10, .severity = r.severity, .flags = r.flags, .kev_due_day = r.due };
            try out.records.appendSlice(gpa, std.mem.asBytes(&rec));
            if (r.flags.kev) out.summary.kev += 1;
        }
        out.summary.records = @intCast(ids.items.len);

        inline for (.{ .{ &b.packages, &out.packages, &out.package_ranges, true }, .{ &b.cpes, &out.cpes, &out.cpe_ranges, false } }) |t| {
            const map = t[0];
            var keys: std.ArrayList(*BKey) = .empty;
            defer keys.deinit(gpa);
            var it = map.valueIterator();
            while (it.next()) |k| try keys.append(gpa, k);
            std.mem.sort(*BKey, keys.items, {}, struct {
                fn lt(_: void, x: *BKey, y: *BKey) bool {
                    const hx = keyHash(x.a, x.b);
                    const hy = keyHash(y.a, y.b);
                    if (hx != hy) return hx < hy;
                    return std.mem.order(u8, x.b, y.b) == .lt;
                }
            }.lt);
            for (keys.items) |k| {
                const first: u32 = @intCast(t[2].items.len / @sizeOf(Range));
                for (k.ranges.items) |r| {
                    const rg: Range = .{ .record = position.get(r.record_id).?, .flags = r.flags, .start = try intern(&out, &dedup, gpa, r.start), .end = try intern(&out, &dedup, gpa, r.end) };
                    try t[2].appendSlice(gpa, std.mem.asBytes(&rg));
                }
                const count: u32 = @intCast(k.ranges.items.len);
                if (t[3]) {
                    const p: Package = .{ .hash = keyHash(k.a, k.b), .ecosystem = try intern(&out, &dedup, gpa, k.a), .name = try intern(&out, &dedup, gpa, k.b), .first = first, .count = count, .scheme = @backingInt(k.scheme) };
                    try t[1].appendSlice(gpa, std.mem.asBytes(&p));
                    out.summary.packages += 1;
                } else {
                    const c: Cpe = .{ .hash = keyHash(k.a, k.b), .vendor = try intern(&out, &dedup, gpa, k.a), .product = try intern(&out, &dedup, gpa, k.b), .first = first, .count = count };
                    try t[1].appendSlice(gpa, std.mem.asBytes(&c));
                    out.summary.cpes += 1;
                }
                out.summary.ranges += count;
            }
        }
        return out;
    }

    /// Load every raw feed file under a feeds directory (see feeds.zig for the layout).
    pub fn addFeedsDir(b: *Builder, io: std.Io, dir: std.Io.Dir) !void {
        const a = b.arena();
        if (dir.readFileAlloc(io, "kev/known_exploited_vulnerabilities.json", a, .limited(feeds.max_feed_bytes))) |text| {
            try b.addKev(try feeds.parseKev(a, text));
        } else |_| {}
        if (dir.openDir(io, "nvd/pages", .{ .iterate = true })) |pages_dir| {
            var pd = pages_dir;
            defer pd.close(io);
            var names: std.ArrayList([]const u8) = .empty;
            defer names.deinit(b.gpa);
            var it = pd.iterate();
            while (try it.next(io)) |e| if (std.mem.endsWith(u8, e.name, ".json")) try names.append(b.gpa, try a.dupe(u8, e.name));
            // Oldest windows first, so later pages (newer lastModified) win.
            std.mem.sort([]const u8, names.items, {}, lessStr);
            for (names.items) |n| {
                var page_arena = std.heap.ArenaAllocator.init(b.gpa);
                defer page_arena.deinit();
                const text = try pd.readFileAlloc(io, n, page_arena.allocator(), .limited(feeds.max_feed_bytes));
                try b.addNvd(try feeds.parseNvdPage(page_arena.allocator(), text));
            }
        } else |_| {}
        if (dir.openDir(io, "osv", .{ .iterate = true })) |osv_dir| {
            var od = osv_dir;
            defer od.close(io);
            var it = od.iterate();
            while (try it.next(io)) |e| {
                if (e.kind != .directory) continue;
                var path_buf: [256]u8 = undefined;
                const p = try std.fmt.bufPrint(&path_buf, "{s}/all.zip", .{e.name});
                const zip = od.readFileAlloc(io, p, b.gpa, .limited(2 * 1024 * 1024 * 1024)) catch continue;
                defer b.gpa.free(zip);
                const Ctx = struct {
                    b: *Builder,
                    fn each(c: @This(), json: []const u8) !void {
                        var arena_tmp = std.heap.ArenaAllocator.init(c.b.gpa);
                        defer arena_tmp.deinit();
                        const v = feeds.parseOsv(arena_tmp.allocator(), json) catch return;
                        try c.b.addOsv(v);
                    }
                };
                _ = try feeds.osvZipRecords(b.gpa, zip, Ctx{ .b = b }, Ctx.each);
            }
        } else |_| {}
    }
};

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

pub const WriteOptions = struct {
    db_version: u64 = 1,
    build_unix_time: u64 = 0,
    key_pair: ?std.crypto.sign.Ed25519.KeyPair = null,
};

pub const Summary = struct { records: u32 = 0, kev: u32 = 0, packages: u32 = 0, cpes: u32 = 0, ranges: u32 = 0 };

// Index (reader) --------------------------------------------------------------------------------

pub const Hit = struct {
    record: u32,
    /// The first fixed version for the matching range, empty when none is known.
    fixed: []const u8,
};

pub const Info = struct {
    id: []const u8,
    alias: []const u8,
    summary: []const u8,
    cvss: f32,
    severity: Severity,
    kev: bool,
    ransomware: bool,
    withdrawn: bool,
    kev_due_day: u32,
};

pub const Error = error{ MissingSection, Corrupt };

pub const Index = struct {
    database: ?db.reader.Database = null,
    strings: []const u8,
    records: []align(1) const Record,
    packages: []align(1) const Package,
    package_ranges: []align(1) const Range,
    cpes: []align(1) const Cpe,
    cpe_ranges: []align(1) const Range,

    pub fn open(io: std.Io, dir: std.Io.Dir, sub_path: []const u8, options: db.reader.OpenOptions) !Index {
        var o = options;
        o.magic = format.cve_magic;
        const d = try db.reader.open(io, dir, sub_path, o);
        errdefer d.close();
        var idx = try fromSections(d);
        idx.database = d;
        return idx;
    }

    pub fn close(idx: Index) void {
        if (idx.database) |d| d.close();
    }

    /// The checks `open` leaves out: BLAKE3 over the whole body against the root in the (signed)
    /// header, every section's xxh3, and that the header bytes no signature covers (the tail after
    /// the signature, and the section table past its last entry) are zero, as the writer leaves
    /// them. It reads every page, so it runs where authenticity matters more than startup time:
    /// when a consumer requires a trusted signature.
    ///
    /// The section table itself is bound to the signature only through the header's xxh3 of it,
    /// which is not a cryptographic hash; a format revision would sign a BLAKE3 of it instead.
    pub fn verifyBody(idx: Index) !void {
        const d = idx.database orelse return error.MissingSection;
        const bytes = d.mapping;
        const table_end = format.section_table_offset + d.header().section_count * @sizeOf(format.SectionEntry);
        if (!std.mem.allEqual(u8, bytes[@offsetOf(format.Header, "_tail")..format.section_table_offset], 0) or
            !std.mem.allEqual(u8, bytes[table_end..format.header_size], 0)) return error.UnsignedHeaderData;
        try db.reader.verifyBody(bytes);
    }

    fn fromSections(d: db.reader.Database) !Index {
        const get = struct {
            fn f(dd: db.reader.Database, kind: format.SectionKind) ![]const u8 {
                return dd.section(kind, 0) orelse error.MissingSection;
            }
        }.f;
        return fromBytes(.{
            .strings = try get(d, .cve_strings),
            .records = try get(d, .cve_records),
            .packages = try get(d, .cve_packages),
            .package_ranges = try get(d, .cve_package_ranges),
            .cpes = try get(d, .cve_cpes),
            .cpe_ranges = try get(d, .cve_cpe_ranges),
        });
    }

    pub const Raw = struct { strings: []const u8, records: []const u8, packages: []const u8, package_ranges: []const u8, cpes: []const u8, cpe_ranges: []const u8 };

    /// Check section sizes only. Opening must not touch every page (the index is 50 to 150 MB),
    /// so references are bounds-checked where queries follow them instead; a corrupt reference
    /// reads as empty, never out of bounds.
    pub fn fromBytes(raw: Raw) Error!Index {
        const cast = struct {
            fn f(comptime T: type, bytes: []const u8) Error![]align(1) const T {
                if (bytes.len % @sizeOf(T) != 0) return error.Corrupt;
                return std.mem.bytesAsSlice(T, bytes);
            }
        }.f;
        const idx: Index = .{
            .strings = raw.strings,
            .records = try cast(Record, raw.records),
            .packages = try cast(Package, raw.packages),
            .package_ranges = try cast(Range, raw.package_ranges),
            .cpes = try cast(Cpe, raw.cpes),
            .cpe_ranges = try cast(Range, raw.cpe_ranges),
        };
        return idx;
    }

    fn str(idx: Index, s: Str) []const u8 {
        if (s.off > idx.strings.len or s.len > idx.strings.len - s.off) return "";
        return idx.strings[s.off..][0..s.len];
    }

    fn slice(ranges: []align(1) const Range, first: u32, count: u32) []align(1) const Range {
        if (first > ranges.len or count > ranges.len - first) return ranges[0..0];
        return ranges[first..][0..count];
    }

    pub fn info(idx: Index, record: u32) Info {
        const r = if (record < idx.records.len) idx.records[record] else std.mem.zeroes(Record);
        return .{
            .id = idx.str(r.id),
            .alias = idx.str(r.alias),
            .summary = idx.str(r.summary),
            .cvss = @as(f32, @floatFromInt(r.cvss_x10)) / 10,
            .severity = r.severity,
            .kev = r.flags.kev,
            .ransomware = r.flags.ransomware,
            .withdrawn = r.flags.withdrawn,
            .kev_due_day = r.kev_due_day,
        };
    }

    pub fn find(idx: Index, id: []const u8) ?u32 {
        var lo: usize = 0;
        var hi: usize = idx.records.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            switch (std.mem.order(u8, idx.str(idx.records[mid].id), id)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return @intCast(mid),
            }
        }
        return null;
    }

    fn inRange(idx: Index, scheme: version.Scheme, r: Range, v: []const u8) bool {
        if (r.record >= idx.records.len) return false;
        if (r.flags.has_start) {
            const o = version.compare(scheme, v, idx.str(r.start));
            if (o == .lt or (o == .eq and !r.flags.start_inclusive)) return false;
        }
        if (r.flags.has_end) {
            const o = version.compare(scheme, v, idx.str(r.end));
            if (o == .gt or (o == .eq and !r.flags.end_inclusive)) return false;
        }
        return true;
    }

    fn collect(idx: Index, scheme: version.Scheme, ranges: []align(1) const Range, v: []const u8, out: []Hit, n: *usize) void {
        for (ranges) |r| {
            if (!idx.inRange(scheme, r, v)) continue;
            // One hit per record.
            var dup = false;
            for (out[0..n.*]) |h| if (h.record == r.record) {
                dup = true;
            };
            if (dup or n.* == out.len) continue;
            out[n.*] = .{ .record = r.record, .fixed = if (r.flags.has_end and !r.flags.end_inclusive) idx.str(r.end) else "" };
            n.* += 1;
        }
    }

    /// Vulnerabilities affecting `name` at `ver` in an OSV ecosystem (npm, PyPI, Go, Debian:12, ...).
    pub fn queryPackage(idx: Index, ecosystem: []const u8, name: []const u8, ver: []const u8, out: []Hit) []Hit {
        var nb: [256]u8 = undefined;
        var eb: [64]u8 = undefined;
        const cname = canonicalName(&nb, ecosystem, name);
        const ceco = std.ascii.lowerString(eb[0..@min(ecosystem.len, eb.len)], ecosystem[0..@min(ecosystem.len, eb.len)]);
        const h = keyHash(ceco, cname);
        var n: usize = 0;
        var i = lowerBound(Package, idx.packages, h);
        while (i < idx.packages.len and idx.packages[i].hash == h) : (i += 1) {
            const p = idx.packages[i];
            if (!std.mem.eql(u8, idx.str(p.name), cname) or !std.mem.eql(u8, idx.str(p.ecosystem), ceco)) continue;
            if (p.scheme >= std.enums.values(version.Scheme).len) continue;
            const scheme: version.Scheme = @fromBackingInt(@intCast(p.scheme));
            var vb: [128]u8 = undefined;
            const cv = canonicalVersion(&vb, scheme, ver);
            idx.collect(scheme, slice(idx.package_ranges, p.first, p.count), cv, out, &n);
        }
        return out[0..n];
    }

    /// Vulnerabilities affecting a CPE vendor and product at `ver` (NVD configurations).
    pub fn queryCpe(idx: Index, vendor: []const u8, product: []const u8, ver: []const u8, out: []Hit) []Hit {
        const h = keyHash(vendor, product);
        var n: usize = 0;
        var i = lowerBound(Cpe, idx.cpes, h);
        while (i < idx.cpes.len and idx.cpes[i].hash == h) : (i += 1) {
            const c = idx.cpes[i];
            if (!std.mem.eql(u8, idx.str(c.vendor), vendor) or !std.mem.eql(u8, idx.str(c.product), product)) continue;
            idx.collect(.rpm, slice(idx.cpe_ranges, c.first, c.count), ver, out, &n);
        }
        return out[0..n];
    }
};

fn lowerBound(comptime T: type, items: []align(1) const T, h: u64) usize {
    var lo: usize = 0;
    var hi: usize = items.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (items[mid].hash < h) lo = mid + 1 else hi = mid;
    }
    return lo;
}

// Tests -----------------------------------------------------------------------------------------

fn fixtureBuilder(gpa: std.mem.Allocator, arena: std.mem.Allocator) !Builder {
    var b = Builder.init(gpa);
    errdefer b.deinit();
    try b.addKev(try feeds.parseKev(arena, feeds.fixtures.kev));
    try b.addNvd(try feeds.parseNvdPage(arena, feeds.fixtures.nvd_log4shell));
    try b.addOsv(try feeds.parseOsv(arena, feeds.fixtures.osv_lodash));
    try b.addOsv(try feeds.parseOsv(arena, feeds.fixtures.osv_requests));
    return b;
}

test "fixture vulnerable versions match and patched versions do not" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var b = try fixtureBuilder(gpa, arena.allocator());
    defer b.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(3));
    const summary = try b.write(io, tmp.dir, "test.zavcve", .{ .key_pair = kp });
    try std.testing.expect(summary.records >= 4 and summary.kev == 3);

    // Signed: an unsigned open and a .zavdb open are both refused.
    const trusted = [_]db.reader.TrustedKey{.{ .public_key = kp.public_key.toBytes() }};
    try std.testing.expectError(error.UnknownKey, Index.open(io, tmp.dir, "test.zavcve", .{}));
    try std.testing.expectError(error.BadMagic, db.reader.open(io, tmp.dir, "test.zavcve", .{ .trusted_keys = &trusted }));
    const idx = try Index.open(io, tmp.dir, "test.zavcve", .{ .trusted_keys = &trusted });
    defer idx.close();

    var hits: [8]Hit = undefined;
    // lodash < 4.17.21 (npm, semver).
    const lodash = idx.queryPackage("npm", "lodash", "4.17.20", &hits);
    try std.testing.expectEqual(@as(usize, 1), lodash.len);
    try std.testing.expectEqualStrings("CVE-2021-23337", idx.info(lodash[0].record).id);
    try std.testing.expectEqualStrings("GHSA-35jh-r3h4-6jhm", idx.info(lodash[0].record).alias);
    try std.testing.expectEqualStrings("4.17.21", lodash[0].fixed);
    try std.testing.expectEqual(@as(usize, 0), idx.queryPackage("npm", "lodash", "4.17.21", &hits).len);
    try std.testing.expectEqual(@as(usize, 0), idx.queryPackage("npm", "underscore", "1.13.0", &hits).len);
    try std.testing.expectEqual(@as(usize, 1), idx.queryPackage("npm", "lodash-es", "4.17.20", &hits).len); // listed by the advisory too
    // requests < 2.32.0 (PyPI, PEP 440, case and separator normalised).
    try std.testing.expectEqual(@as(usize, 1), idx.queryPackage("PyPI", "Requests", "2.31.0", &hits).len);
    try std.testing.expectEqual(@as(usize, 0), idx.queryPackage("PyPI", "requests", "2.32.0", &hits).len);
    try std.testing.expectEqual(@as(usize, 1), idx.queryPackage("PyPI", "requests", "2.32.0rc1", &hits).len);
    // log4j through NVD CPE ranges: 2.14.1 in [2.13.0, 2.15.0), 2.12.2 excluded, beta9 exact.
    const log4j = idx.queryCpe("apache", "log4j", "2.14.1", &hits);
    try std.testing.expectEqual(@as(usize, 1), log4j.len);
    const li = idx.info(log4j[0].record);
    try std.testing.expectEqualStrings("CVE-2021-44228", li.id);
    try std.testing.expect(li.kev and li.ransomware and li.severity == .critical);
    try std.testing.expectEqual(@as(f32, 10.0), li.cvss);
    try std.testing.expectEqual(@as(usize, 0), idx.queryCpe("apache", "log4j", "2.15.0", &hits).len);
    try std.testing.expectEqual(@as(usize, 0), idx.queryCpe("apache", "log4j", "2.12.2", &hits).len);
    try std.testing.expectEqual(@as(usize, 1), idx.queryCpe("apache", "log4j", "2.0-beta9", &hits).len);
    try std.testing.expect(idx.find("CVE-2023-4863") != null);
    try std.testing.expect(idx.find("CVE-1999-0001") == null);
}

test "a required key refuses unsigned, unknown-key and tampered indexes" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var b = try fixtureBuilder(gpa, arena.allocator());
    defer b.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(5));
    const other = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(6));
    _ = try b.write(io, tmp.dir, "signed.zavcve", .{ .key_pair = kp });
    _ = try b.write(io, tmp.dir, "unsigned.zavcve", .{});
    const required: db.reader.OpenOptions = .{ .trusted_keys = &.{.{ .public_key = kp.public_key.toBytes() }}, .allow_unsigned = false };

    // The right key opens it and the whole body checks out.
    {
        const idx = try Index.open(io, tmp.dir, "signed.zavcve", required);
        defer idx.close();
        try idx.verifyBody();
        try std.testing.expect(idx.find("CVE-2021-44228") != null);
    }
    // A key other than the signer's, and an unsigned index, are both refused.
    try std.testing.expectError(error.UnknownKey, Index.open(io, tmp.dir, "signed.zavcve", .{ .trusted_keys = &.{.{ .public_key = other.public_key.toBytes() }}, .allow_unsigned = false }));
    try std.testing.expectError(error.Unsigned, Index.open(io, tmp.dir, "unsigned.zavcve", required));

    const bytes = try tmp.dir.readFileAlloc(io, "signed.zavcve", gpa, .unlimited);
    defer gpa.free(bytes);
    // A changed header byte breaks the signature.
    const h: *format.Header = @ptrCast(@alignCast(bytes.ptr));
    h.db_version +%= 1;
    try tmp.dir.writeFile(io, .{ .sub_path = "header.zavcve", .data = bytes });
    try std.testing.expectError(error.BadSignature, Index.open(io, tmp.dir, "header.zavcve", required));
    h.db_version -%= 1;
    // A changed body byte keeps the header valid, so open alone accepts it; verifyBody does not.
    const table: [*]const format.SectionEntry = @ptrCast(@alignCast(bytes.ptr + format.section_table_offset));
    const strings = for (table[0..h.section_count]) |entry| {
        if (entry.kind == .cve_strings) break entry;
    } else return error.TestUnexpectedResult;
    try std.testing.expect(strings.size > 0);
    bytes[strings.offset] ^= 0x01;
    try tmp.dir.writeFile(io, .{ .sub_path = "body.zavcve", .data = bytes });
    const tampered = try Index.open(io, tmp.dir, "body.zavcve", required);
    defer tampered.close();
    try std.testing.expectError(error.RootMismatch, tampered.verifyBody());
    bytes[strings.offset] ^= 0x01;
    // Header bytes outside the signed region (the tail, the unused end of the section table)
    // keep the signature valid, so open accepts them; verifyBody requires them to be zero.
    for ([_]usize{ @offsetOf(format.Header, "_tail") + 40, format.header_size - 1 }) |offset| {
        bytes[offset] ^= 0x01;
        try tmp.dir.writeFile(io, .{ .sub_path = "tail.zavcve", .data = bytes });
        const padded = try Index.open(io, tmp.dir, "tail.zavcve", required);
        defer padded.close();
        try std.testing.expectError(error.UnsignedHeaderData, padded.verifyBody());
        bytes[offset] ^= 0x01;
    }
}

test "index load stays under 10 ms on a warm cache" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var b = Builder.init(gpa);
    defer b.deinit();
    // 50,000 packages with two ranges each.
    var name_buf: [32]u8 = undefined;
    var id_buf: [32]u8 = undefined;
    for (0..50_000) |i| {
        const id = try std.fmt.bufPrint(&id_buf, "CVE-2026-{d:0>6}", .{i});
        const r = try b.record(id);
        r.cvss_x10 = 75;
        const name = try b.arena().dupe(u8, try std.fmt.bufPrint(&name_buf, "pkg-{d}", .{i}));
        try b.addRange(&b.packages, "npm", name, .semver, .{ .record_id = r.id, .flags = .{ .has_start = true, .has_end = true }, .start = "1.0.0", .end = "1.2.0" });
        try b.addRange(&b.packages, "npm", name, .semver, .{ .record_id = r.id, .flags = .{ .has_start = true, .has_end = true }, .start = "2.0.0", .end = "2.0.5" });
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    _ = try b.write(io, tmp.dir, "big.zavcve", .{});
    // Warm the page cache, then time open + validation.
    (try Index.open(io, tmp.dir, "big.zavcve", .{ .allow_unsigned = true })).close();
    var best: u64 = std.math.maxInt(u64);
    for (0..5) |_| {
        const t0 = std.Io.Clock.awake.now(io);
        const idx = try Index.open(io, tmp.dir, "big.zavcve", .{ .allow_unsigned = true });
        const ns: u64 = @intCast(t0.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds());
        best = @min(best, ns);
        var hits: [4]Hit = undefined;
        try std.testing.expectEqual(@as(usize, 1), idx.queryPackage("npm", "pkg-42", "2.0.1", &hits).len);
        try std.testing.expectEqual(@as(usize, 0), idx.queryPackage("npm", "pkg-42", "1.2.0", &hits).len);
        idx.close();
    }
    if (best > 10 * std.time.ns_per_ms) {
        std.debug.print("index open took {d} us\n", .{best / 1000});
        return error.TestUnexpectedResult;
    }
}

test "corrupt sections are refused or read as empty" {
    const bad_ref: Range = .{ .record = 9, .flags = .{}, .start = .{ .off = 100, .len = 5 }, .end = .{} };
    const pkg: Package = .{ .hash = keyHash("npm", "x"), .ecosystem = .{ .off = 0, .len = 3 }, .name = .{ .off = 3, .len = 1 }, .first = 0, .count = 7, .scheme = 0 };
    const idx = try Index.fromBytes(.{ .strings = "npmx", .records = "", .packages = std.mem.asBytes(&pkg), .package_ranges = std.mem.asBytes(&bad_ref), .cpes = "", .cpe_ranges = "" });
    var hits: [4]Hit = undefined;
    try std.testing.expectEqual(@as(usize, 0), idx.queryPackage("npm", "x", "1.0.0", &hits).len);
    try std.testing.expectError(error.Corrupt, Index.fromBytes(.{ .strings = "", .records = "abc", .packages = "", .package_ranges = "", .cpes = "", .cpe_ranges = "" }));
    try std.testing.expectEqual(@as(u32, 20406), dayNumber("2025-11-14"));
}
