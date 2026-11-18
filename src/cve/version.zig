//! Version comparison per packaging scheme. Each scheme has its own ordering rules (tildes sort
//! before everything in dpkg and rpm, pre-releases sort before releases in semver and PEP 440,
//! epochs override everything), so vulnerable-range checks compare with the scheme of the
//! package, never as plain strings.
const std = @import("std");

pub const Scheme = enum {
    semver,
    dpkg,
    rpm,
    apk,
    pep440,
    maven,
    go,

    pub fn parse(text: []const u8) ?Scheme {
        return std.meta.stringToEnum(Scheme, text);
    }
};

pub fn compare(scheme: Scheme, a: []const u8, b: []const u8) std.math.Order {
    return switch (scheme) {
        .dpkg => dpkg(a, b),
        .rpm => rpm(a, b),
        .apk => apk(a, b),
        .semver => semver(a, b),
        .go => semver(trimV(a), trimV(b)),
        .pep440 => pep440(a, b),
        .maven => maven(a, b),
    };
}

fn trimV(v: []const u8) []const u8 {
    return if (v.len > 0 and v[0] == 'v') v[1..] else v;
}

fn order(a: anytype, b: @TypeOf(a)) std.math.Order {
    return std.math.order(a, b);
}

/// Parse leading decimal digits (saturating), returning the value and the digit count.
fn digits(s: []const u8) struct { value: u64, len: usize } {
    var v: u64 = 0;
    var i: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) v = v *| 10 +| (s[i] - '0');
    return .{ .value = v, .len = i };
}

// dpkg ------------------------------------------------------------------------------------------

/// dpkg's character order: '~' before the end of the string, letters before non-letters.
fn dpkgCharOrder(c: ?u8) i32 {
    const ch = c orelse return 0;
    if (std.ascii.isDigit(ch)) return 0;
    if (std.ascii.isAlphabetic(ch)) return ch;
    if (ch == '~') return -1;
    return @as(i32, ch) + 256;
}

/// dpkg's verrevcmp over an upstream version or a revision.
fn verrevcmp(a_in: []const u8, b_in: []const u8) std.math.Order {
    var a = a_in;
    var b = b_in;
    while (a.len > 0 or b.len > 0) {
        // Non-digit prefix.
        while ((a.len > 0 and !std.ascii.isDigit(a[0])) or (b.len > 0 and !std.ascii.isDigit(b[0]))) {
            const ac = dpkgCharOrder(if (a.len > 0) a[0] else null);
            const bc = dpkgCharOrder(if (b.len > 0) b[0] else null);
            if (ac != bc) return order(ac, bc);
            if (a.len > 0) a = a[1..];
            if (b.len > 0) b = b[1..];
        }
        // Digit run, compared numerically (leading zeros ignored).
        while (a.len > 0 and a[0] == '0') a = a[1..];
        while (b.len > 0 and b[0] == '0') b = b[1..];
        var first: std.math.Order = .eq;
        while (a.len > 0 and std.ascii.isDigit(a[0]) and b.len > 0 and std.ascii.isDigit(b[0])) {
            if (first == .eq) first = order(a[0], b[0]);
            a = a[1..];
            b = b[1..];
        }
        if (a.len > 0 and std.ascii.isDigit(a[0])) return .gt;
        if (b.len > 0 and std.ascii.isDigit(b[0])) return .lt;
        if (first != .eq) return first;
    }
    return .eq;
}

const Evr = struct { epoch: u64, version: []const u8, release: []const u8 };

fn splitEvr(v: []const u8) Evr {
    var rest = v;
    var epoch: u64 = 0;
    if (std.mem.indexOfScalar(u8, rest, ':')) |c| {
        const d = digits(rest[0..c]);
        if (d.len == c) {
            epoch = d.value;
            rest = rest[c + 1 ..];
        }
    }
    if (std.mem.lastIndexOfScalar(u8, rest, '-')) |dash| return .{ .epoch = epoch, .version = rest[0..dash], .release = rest[dash + 1 ..] };
    return .{ .epoch = epoch, .version = rest, .release = "" };
}

pub fn dpkg(a: []const u8, b: []const u8) std.math.Order {
    const x = splitEvr(a);
    const y = splitEvr(b);
    if (x.epoch != y.epoch) return order(x.epoch, y.epoch);
    const v = verrevcmp(x.version, y.version);
    if (v != .eq) return v;
    return verrevcmp(x.release, y.release);
}

// rpm -------------------------------------------------------------------------------------------

/// rpmvercmp: alphanumeric segments; numeric beats alpha; '~' sorts before everything and '^'
/// after the end but before anything else.
fn rpmvercmp(a_in: []const u8, b_in: []const u8) std.math.Order {
    if (std.mem.eql(u8, a_in, b_in)) return .eq;
    var a = a_in;
    var b = b_in;
    while (a.len > 0 or b.len > 0) {
        while (a.len > 0 and !std.ascii.isAlphanumeric(a[0]) and a[0] != '~' and a[0] != '^') a = a[1..];
        while (b.len > 0 and !std.ascii.isAlphanumeric(b[0]) and b[0] != '~' and b[0] != '^') b = b[1..];
        const at = a.len > 0 and a[0] == '~';
        const bt = b.len > 0 and b[0] == '~';
        if (at or bt) {
            if (!at) return .gt;
            if (!bt) return .lt;
            a = a[1..];
            b = b[1..];
            continue;
        }
        const ac = a.len > 0 and a[0] == '^';
        const bc = b.len > 0 and b[0] == '^';
        if (ac or bc) {
            if (a.len == 0) return .lt;
            if (b.len == 0) return .gt;
            if (!ac) return .gt;
            if (!bc) return .lt;
            a = a[1..];
            b = b[1..];
            continue;
        }
        if (a.len == 0 or b.len == 0) break;
        const numeric = std.ascii.isDigit(a[0]);
        const seg_len = struct {
            fn f(s: []const u8, num: bool) usize {
                var i: usize = 0;
                while (i < s.len and (if (num) std.ascii.isDigit(s[i]) else std.ascii.isAlphabetic(s[i]))) i += 1;
                return i;
            }
        }.f;
        const la = seg_len(a, numeric);
        const lb = seg_len(b, numeric);
        if (lb == 0) return if (numeric) .gt else .lt;
        var sa = a[0..la];
        var sb = b[0..lb];
        a = a[la..];
        b = b[lb..];
        if (numeric) {
            sa = std.mem.trimStart(u8, sa, "0");
            sb = std.mem.trimStart(u8, sb, "0");
            if (sa.len != sb.len) return order(sa.len, sb.len);
        }
        const o = std.mem.order(u8, sa, sb);
        if (o != .eq) return o;
    }
    if (a.len == 0 and b.len == 0) return .eq;
    return if (a.len == 0) .lt else .gt;
}

pub fn rpm(a: []const u8, b: []const u8) std.math.Order {
    const x = splitEvr(a);
    const y = splitEvr(b);
    if (x.epoch != y.epoch) return order(x.epoch, y.epoch);
    const v = rpmvercmp(x.version, y.version);
    if (v != .eq) return v;
    if (x.release.len == 0 or y.release.len == 0) return .eq; // a missing release matches any
    return rpmvercmp(x.release, y.release);
}

// apk -------------------------------------------------------------------------------------------

const apk_suffixes = [_]struct { name: []const u8, rank: i8 }{
    .{ .name = "alpha", .rank = -4 }, .{ .name = "beta", .rank = -3 }, .{ .name = "pre", .rank = -2 }, .{ .name = "rc", .rank = -1 },
    .{ .name = "cvs", .rank = 1 },    .{ .name = "svn", .rank = 2 },   .{ .name = "git", .rank = 3 },  .{ .name = "hg", .rank = 4 },
    .{ .name = "p", .rank = 5 },
};

/// apk versions: dotted numbers, an optional letter, `_suffix[N]` (alpha < beta < pre < rc <
/// release < cvs < svn < git < hg < p), then `-rN`.
pub fn apk(a: []const u8, b: []const u8) std.math.Order {
    const ra = splitApkRevision(a);
    const rb = splitApkRevision(b);
    var x = ra.version;
    var y = rb.version;
    while (true) {
        const dx = digits(x);
        const dy = digits(y);
        if (dx.len == 0 or dy.len == 0) break;
        if (dx.value != dy.value) return order(dx.value, dy.value);
        x = x[dx.len..];
        y = y[dy.len..];
        const xd = x.len > 0 and x[0] == '.';
        const yd = y.len > 0 and y[0] == '.';
        if (xd and yd) {
            x = x[1..];
            y = y[1..];
            continue;
        }
        if (xd != yd) return if (xd) .gt else .lt;
        break;
    }
    // Letter.
    const lx: u8 = if (x.len > 0 and std.ascii.isAlphabetic(x[0])) x[0] else 0;
    const ly: u8 = if (y.len > 0 and std.ascii.isAlphabetic(y[0])) y[0] else 0;
    if (lx != ly) return order(lx, ly);
    if (lx != 0) {
        x = x[1..];
        y = y[1..];
    }
    // Suffixes.
    while (x.len > 0 or y.len > 0) {
        const sx = apkSuffix(x);
        const sy = apkSuffix(y);
        if (sx.rank != sy.rank) return order(sx.rank, sy.rank);
        if (sx.num != sy.num) return order(sx.num, sy.num);
        if (sx.len == 0 and sy.len == 0) break;
        x = x[sx.len..];
        y = y[sy.len..];
    }
    return order(ra.revision, rb.revision);
}

fn splitApkRevision(v: []const u8) struct { version: []const u8, revision: u64 } {
    if (std.mem.lastIndexOf(u8, v, "-r")) |i| {
        const d = digits(v[i + 2 ..]);
        if (d.len > 0 and i + 2 + d.len == v.len) return .{ .version = v[0..i], .revision = d.value };
    }
    return .{ .version = v, .revision = 0 };
}

fn apkSuffix(s: []const u8) struct { rank: i8, num: u64, len: usize } {
    if (s.len == 0 or s[0] != '_') return .{ .rank = 0, .num = 0, .len = 0 };
    for (apk_suffixes) |suf| if (std.mem.startsWith(u8, s[1..], suf.name)) {
        const d = digits(s[1 + suf.name.len ..]);
        return .{ .rank = suf.rank, .num = d.value, .len = 1 + suf.name.len + d.len };
    };
    return .{ .rank = 0, .num = 0, .len = s.len };
}

// semver ----------------------------------------------------------------------------------------

/// Semantic versioning 2.0 precedence: major.minor.patch, then a pre-release sorts before the
/// release, identifiers compared numerically or lexically; build metadata is ignored.
pub fn semver(a_in: []const u8, b_in: []const u8) std.math.Order {
    const a = std.mem.sliceTo(a_in, '+');
    const b = std.mem.sliceTo(b_in, '+');
    const ap = std.mem.indexOfScalar(u8, a, '-');
    const bp = std.mem.indexOfScalar(u8, b, '-');
    var ca = std.mem.splitScalar(u8, a[0 .. ap orelse a.len], '.');
    var cb = std.mem.splitScalar(u8, b[0 .. bp orelse b.len], '.');
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const x = digits(ca.next() orelse "0").value;
        const y = digits(cb.next() orelse "0").value;
        if (x != y) return order(x, y);
    }
    if (ap == null and bp == null) return .eq;
    if (ap == null) return .gt;
    if (bp == null) return .lt;
    var pa = std.mem.splitScalar(u8, a[ap.? + 1 ..], '.');
    var pb = std.mem.splitScalar(u8, b[bp.? + 1 ..], '.');
    while (true) {
        const x = pa.next();
        const y = pb.next();
        if (x == null and y == null) return .eq;
        if (x == null) return .lt;
        if (y == null) return .gt;
        const dx = digits(x.?);
        const dy = digits(y.?);
        const nx = dx.len == x.?.len and x.?.len > 0;
        const ny = dy.len == y.?.len and y.?.len > 0;
        if (nx and ny) {
            if (dx.value != dy.value) return order(dx.value, dy.value);
        } else if (nx != ny) {
            return if (nx) .lt else .gt;
        } else {
            const o = std.mem.order(u8, x.?, y.?);
            if (o != .eq) return o;
        }
    }
}

// PEP 440 ---------------------------------------------------------------------------------------

const Pep = struct {
    epoch: u64 = 0,
    release: [8]u64 = @splat(0),
    release_len: usize = 0,
    /// -3 dev only, -2 a, -1 b, 0 rc... encoded as (phase, n); phase 3 = final.
    pre_phase: i8 = 3,
    pre_num: u64 = 0,
    post: ?u64 = null,
    dev: ?u64 = null,
};

fn parsePep(v_in: []const u8) Pep {
    var buf: [128]u8 = undefined;
    const v = std.ascii.lowerString(&buf, v_in[0..@min(v_in.len, buf.len)]);
    var p: Pep = .{};
    var s: []const u8 = std.mem.trim(u8, v, " ");
    if (s.len > 0 and s[0] == 'v') s = s[1..];
    if (std.mem.indexOfScalar(u8, s, '!')) |i| {
        p.epoch = digits(s[0..i]).value;
        s = s[i + 1 ..];
    }
    while (p.release_len < p.release.len) {
        const d = digits(s);
        if (d.len == 0) break;
        p.release[p.release_len] = d.value;
        p.release_len += 1;
        s = s[d.len..];
        if (s.len > 1 and s[0] == '.' and std.ascii.isDigit(s[1])) s = s[1..] else break;
    }
    while (s.len > 0) {
        while (s.len > 0 and (s[0] == '.' or s[0] == '-' or s[0] == '_')) s = s[1..];
        const tags = [_]struct { t: []const u8, phase: i8 }{
            .{ .t = "alpha", .phase = 0 }, .{ .t = "beta", .phase = 1 }, .{ .t = "preview", .phase = 2 }, .{ .t = "pre", .phase = 2 },
            .{ .t = "rc", .phase = 2 },    .{ .t = "c", .phase = 2 },    .{ .t = "a", .phase = 0 },       .{ .t = "b", .phase = 1 },
        };
        var matched = false;
        if (std.mem.startsWith(u8, s, "post") or std.mem.startsWith(u8, s, "rev") or std.mem.startsWith(u8, s, "r")) {
            const n: usize = if (std.mem.startsWith(u8, s, "post")) 4 else if (std.mem.startsWith(u8, s, "rev")) 3 else 1;
            s = s[n..];
            while (s.len > 0 and (s[0] == '.' or s[0] == '-' or s[0] == '_')) s = s[1..];
            const d = digits(s);
            p.post = d.value;
            s = s[d.len..];
            matched = true;
        } else if (std.mem.startsWith(u8, s, "dev")) {
            s = s[3..];
            const d = digits(s);
            p.dev = d.value;
            s = s[d.len..];
            matched = true;
        } else for (tags) |t| if (std.mem.startsWith(u8, s, t.t)) {
            s = s[t.t.len..];
            while (s.len > 0 and (s[0] == '.' or s[0] == '-' or s[0] == '_')) s = s[1..];
            const d = digits(s);
            p.pre_phase = t.phase;
            p.pre_num = d.value;
            s = s[d.len..];
            matched = true;
            break;
        };
        if (!matched) {
            if (s.len > 0 and std.ascii.isDigit(s[0])) {
                // implicit post release: 1.0-1
                const d = digits(s);
                p.post = d.value;
                s = s[d.len..];
            } else break;
        }
    }
    return p;
}

pub fn pep440(a: []const u8, b: []const u8) std.math.Order {
    const x = parsePep(a);
    const y = parsePep(b);
    if (x.epoch != y.epoch) return order(x.epoch, y.epoch);
    const n = @max(x.release_len, y.release_len);
    for (0..n) |i| if (x.release[i] != y.release[i]) return order(x.release[i], y.release[i]);
    // A dev release with no pre or post sorts before any pre-release.
    const xp: i8 = if (x.pre_phase == 3 and x.post == null and x.dev != null) -1 else x.pre_phase;
    const yp: i8 = if (y.pre_phase == 3 and y.post == null and y.dev != null) -1 else y.pre_phase;
    if (xp != yp) return order(xp, yp);
    if (x.pre_num != y.pre_num) return order(x.pre_num, y.pre_num);
    const xpost: i128 = if (x.post) |v| v else -1;
    const ypost: i128 = if (y.post) |v| v else -1;
    if (xpost != ypost) return order(xpost, ypost);
    const xdev: i128 = if (x.dev) |v| v else std.math.maxInt(i64);
    const ydev: i128 = if (y.dev) |v| v else std.math.maxInt(i64);
    return order(xdev, ydev);
}

// Maven -----------------------------------------------------------------------------------------

/// Maven ComparableVersion, simplified: numeric items compare numerically; qualifiers order
/// alpha < beta < milestone < rc < snapshot < "" (release) < sp, unknown qualifiers lexically after.
pub fn maven(a: []const u8, b: []const u8) std.math.Order {
    var ia = MavenItems{ .rest = a };
    var ib = MavenItems{ .rest = b };
    while (true) {
        const x = ia.next();
        const y = ib.next();
        if (x == null and y == null) return .eq;
        // A missing item is 0 against a number and the release qualifier against a qualifier.
        const xi = x orelse (if (y.?.num != null) MavenItem{ .num = 0 } else MavenItem{});
        const yi = y orelse (if (x.?.num != null) MavenItem{ .num = 0 } else MavenItem{});
        const o = compareMaven(xi, yi);
        if (o != .eq) return o;
    }
}

const MavenItem = struct { num: ?u64 = null, qual: []const u8 = "" };

const MavenItems = struct {
    rest: []const u8,
    fn next(it: *MavenItems) ?MavenItem {
        while (it.rest.len > 0 and (it.rest[0] == '.' or it.rest[0] == '-')) it.rest = it.rest[1..];
        if (it.rest.len == 0) return null;
        if (std.ascii.isDigit(it.rest[0])) {
            const d = digits(it.rest);
            it.rest = it.rest[d.len..];
            return .{ .num = d.value };
        }
        var i: usize = 0;
        while (i < it.rest.len and !std.ascii.isDigit(it.rest[i]) and it.rest[i] != '.' and it.rest[i] != '-') i += 1;
        const q = it.rest[0..i];
        it.rest = it.rest[i..];
        return .{ .qual = q };
    }
};

fn qualRank(q: []const u8) i32 {
    const names = [_]struct { n: []const u8, r: i32 }{
        .{ .n = "alpha", .r = 1 },   .{ .n = "a", .r = 1 },  .{ .n = "beta", .r = 2 },     .{ .n = "b", .r = 2 }, .{ .n = "milestone", .r = 3 }, .{ .n = "m", .r = 3 },
        .{ .n = "rc", .r = 4 },      .{ .n = "cr", .r = 4 }, .{ .n = "snapshot", .r = 5 }, .{ .n = "", .r = 6 },  .{ .n = "ga", .r = 6 },        .{ .n = "final", .r = 6 },
        .{ .n = "release", .r = 6 }, .{ .n = "sp", .r = 7 },
    };
    for (names) |n| if (std.ascii.eqlIgnoreCase(q, n.n)) return n.r;
    return 8;
}

fn compareMaven(x: MavenItem, y: MavenItem) std.math.Order {
    if (x.num != null and y.num != null) return order(x.num.?, y.num.?);
    if (x.num != null) return if (y.qual.len == 0) order(x.num.?, 0) else .gt;
    if (y.num != null) return if (x.qual.len == 0) order(@as(u64, 0), y.num.?) else .lt;
    const rx = qualRank(x.qual);
    const ry = qualRank(y.qual);
    if (rx != ry) return order(rx, ry);
    if (rx == 8) return std.ascii.orderIgnoreCase(x.qual, y.qual);
    return .eq;
}

// Tests -----------------------------------------------------------------------------------------

fn lt(s: Scheme, a: []const u8, b: []const u8) !void {
    if (compare(s, a, b) != .lt or compare(s, b, a) != .gt) {
        std.debug.print("{t}: expected {s} < {s}\n", .{ s, a, b });
        return error.TestUnexpectedResult;
    }
}

fn eq(s: Scheme, a: []const u8, b: []const u8) !void {
    try std.testing.expectEqual(std.math.Order.eq, compare(s, a, b));
}

test "dpkg: epochs, tildes, revisions" {
    try lt(.dpkg, "1.0~rc1", "1.0");
    try lt(.dpkg, "1.0", "1.0-1");
    try lt(.dpkg, "1.0-1", "1.0-1ubuntu1");
    try lt(.dpkg, "2.0", "1:1.0");
    try lt(.dpkg, "1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13.5");
    try lt(.dpkg, "1.2.3", "1.2.10");
    try lt(.dpkg, "1.0~~", "1.0~");
    try lt(.dpkg, "1.0a", "1.0+");
    try eq(.dpkg, "1.01", "1.1");
    try eq(.dpkg, "0:1.0", "1.0");
}

test "rpm: tildes, carets, epochs, alpha vs numeric" {
    try lt(.rpm, "1.0~rc1", "1.0");
    try lt(.rpm, "1.0", "1.0^git1");
    try lt(.rpm, "1.0^git1", "1.0.1");
    try lt(.rpm, "1.9.15-1.p5.fc40", "1.9.15-2.fc40");
    try lt(.rpm, "1.0a", "1.0.1");
    try lt(.rpm, "2.0", "1:1.0");
    try lt(.rpm, "5.2.26-3.fc40", "5.2.26-10.fc40");
    try eq(.rpm, "1.0-1", "1.0");
}

test "apk: suffixes and revisions" {
    try lt(.apk, "1.36.1-r28", "1.36.1-r29");
    try lt(.apk, "1.2_rc1", "1.2");
    try lt(.apk, "1.2_alpha2", "1.2_beta1");
    try lt(.apk, "1.2", "1.2_p1");
    try lt(.apk, "1.2", "1.2a");
    try lt(.apk, "1.2.9", "1.2.10");
    try lt(.apk, "1.2", "1.2.1");
}

test "semver and go: pre-releases" {
    try lt(.semver, "1.0.0-alpha", "1.0.0");
    try lt(.semver, "1.0.0-alpha", "1.0.0-alpha.1");
    try lt(.semver, "1.0.0-alpha.1", "1.0.0-alpha.beta");
    try lt(.semver, "1.0.0-beta.2", "1.0.0-beta.11");
    try lt(.semver, "1.0.0-rc.1", "1.0.0");
    try lt(.semver, "4.17.20", "4.17.21");
    try eq(.semver, "1.0.0+build.1", "1.0.0");
    try lt(.go, "v1.21.0", "v1.21.1");
    try lt(.go, "v0.0.0-20230101000000-abcdef", "v0.1.0");
}

test "pep440: epochs, pre, post and dev releases" {
    try lt(.pep440, "1.0.dev1", "1.0a1");
    try lt(.pep440, "1.0a1", "1.0b1");
    try lt(.pep440, "1.0b2", "1.0rc1");
    try lt(.pep440, "1.0rc1", "1.0");
    try lt(.pep440, "1.0", "1.0.post1");
    try lt(.pep440, "1.0", "1!0.5");
    try lt(.pep440, "2.31.0", "2.32.0");
    try eq(.pep440, "1.0", "1.0.0");
}

test "maven: qualifiers" {
    try lt(.maven, "2.14.0-rc1", "2.14.0");
    try lt(.maven, "2.14.0-SNAPSHOT", "2.14.0");
    try lt(.maven, "2.14.0", "2.14.0-sp1");
    try lt(.maven, "2.14.1", "2.15.0");
    try lt(.maven, "1.0-alpha", "1.0-beta");
    try eq(.maven, "1.0", "1.0.0");
}
