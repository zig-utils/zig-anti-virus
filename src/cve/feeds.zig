//! Vulnerability feeds: CISA's Known Exploited Vulnerabilities catalog, NVD through API 2.0
//! (an initial full sync, then incremental windows by lastModStartDate and lastModEndDate,
//! resumable after interruption), and OSV per-ecosystem exports.
//!
//! Raw responses are stored under a feeds directory with their fetch times, so an index build
//! is reproducible from disk:
//!
//!   kev/known_exploited_vulnerabilities.json, kev/fetched
//!   nvd/state.json, nvd/pages/<window>-<startIndex>.json
//!   osv/<ecosystem>/all.zip, osv/<ecosystem>/fetched
//!
//! Network access goes through a `Fetcher`, so tests run the sync logic against recorded pages
//! and nothing in the test suite touches the network. linux-guardian cached CVEs in SQLite; zav
//! compiles these files into the .zavcve index instead (index.zig).
const std = @import("std");

pub const kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const osv_url = "https://osv-vulnerabilities.storage.googleapis.com";

/// NVD allows at most 120 days per lastModified window and 2,000 results per page.
pub const nvd_max_window_days = 120;
pub const nvd_page_size = 2000;
/// Feed files are bounded; KEV is about 2 MB, an NVD page about 15 MB.
pub const max_feed_bytes = 256 * 1024 * 1024;

// KEV -------------------------------------------------------------------------------------------

pub const KevEntry = struct {
    cveID: []const u8,
    vendorProject: []const u8 = "",
    product: []const u8 = "",
    vulnerabilityName: []const u8 = "",
    dateAdded: []const u8 = "",
    shortDescription: []const u8 = "",
    requiredAction: []const u8 = "",
    dueDate: []const u8 = "",
    knownRansomwareCampaignUse: []const u8 = "",

    pub fn ransomware(e: KevEntry) bool {
        return std.ascii.eqlIgnoreCase(e.knownRansomwareCampaignUse, "Known");
    }
};

pub const Kev = struct {
    title: []const u8 = "",
    catalogVersion: []const u8 = "",
    dateReleased: []const u8 = "",
    count: u32 = 0,
    vulnerabilities: []const KevEntry = &.{},
};

const parse_options: std.json.ParseOptions = .{ .ignore_unknown_fields = true, .allocate = .alloc_always, .max_value_len = max_feed_bytes };

/// Parse the KEV catalog; strings are allocated from `arena`.
pub fn parseKev(arena: std.mem.Allocator, text: []const u8) !Kev {
    return std.json.parseFromSliceLeaky(Kev, arena, text, parse_options);
}

// NVD -------------------------------------------------------------------------------------------

pub const CvssData = struct {
    baseScore: f64 = 0,
    baseSeverity: []const u8 = "",
    vectorString: []const u8 = "",
};

pub const Metric = struct {
    source: []const u8 = "",
    type: []const u8 = "",
    cvssData: CvssData = .{},
    /// CVSS v2 carries the severity on the metric, not in cvssData.
    baseSeverity: []const u8 = "",
};

pub const Metrics = struct {
    cvssMetricV40: []const Metric = &.{},
    cvssMetricV31: []const Metric = &.{},
    cvssMetricV30: []const Metric = &.{},
    cvssMetricV2: []const Metric = &.{},
};

pub const CpeMatch = struct {
    vulnerable: bool = false,
    criteria: []const u8,
    versionStartIncluding: ?[]const u8 = null,
    versionStartExcluding: ?[]const u8 = null,
    versionEndIncluding: ?[]const u8 = null,
    versionEndExcluding: ?[]const u8 = null,
};

pub const Node = struct {
    operator: []const u8 = "OR",
    negate: bool = false,
    cpeMatch: []const CpeMatch = &.{},
};

pub const Configuration = struct {
    operator: ?[]const u8 = null,
    negate: bool = false,
    nodes: []const Node = &.{},
};

pub const Description = struct { lang: []const u8 = "", value: []const u8 = "" };

pub const Cve = struct {
    id: []const u8,
    published: []const u8 = "",
    lastModified: []const u8 = "",
    vulnStatus: []const u8 = "",
    descriptions: []const Description = &.{},
    metrics: Metrics = .{},
    configurations: []const Configuration = &.{},
    cisaExploitAdd: ?[]const u8 = null,

    /// The preferred CVSS base score and severity: v4.0, then v3.1, v3.0, v2.
    pub fn cvss(c: Cve) struct { score: f64, severity: []const u8, version: []const u8 } {
        const sets = [_]struct { m: []const Metric, v: []const u8 }{ .{ .m = c.metrics.cvssMetricV40, .v = "4.0" }, .{ .m = c.metrics.cvssMetricV31, .v = "3.1" }, .{ .m = c.metrics.cvssMetricV30, .v = "3.0" }, .{ .m = c.metrics.cvssMetricV2, .v = "2.0" } };
        for (sets) |set| {
            if (set.m.len == 0) continue;
            // Primary (NVD's own) score when present.
            var pick = set.m[0];
            for (set.m) |m| if (std.mem.eql(u8, m.type, "Primary")) {
                pick = m;
            };
            const sev = if (pick.cvssData.baseSeverity.len > 0) pick.cvssData.baseSeverity else pick.baseSeverity;
            return .{ .score = pick.cvssData.baseScore, .severity = sev, .version = set.v };
        }
        return .{ .score = 0, .severity = "", .version = "" };
    }

    pub fn description(c: Cve) []const u8 {
        for (c.descriptions) |d| if (std.mem.eql(u8, d.lang, "en")) return d.value;
        return if (c.descriptions.len > 0) c.descriptions[0].value else "";
    }
};

pub const NvdItem = struct { cve: Cve };

pub const NvdPage = struct {
    resultsPerPage: u32 = 0,
    startIndex: u32 = 0,
    totalResults: u32 = 0,
    timestamp: []const u8 = "",
    vulnerabilities: []const NvdItem = &.{},
};

pub fn parseNvdPage(arena: std.mem.Allocator, text: []const u8) !NvdPage {
    return std.json.parseFromSliceLeaky(NvdPage, arena, text, parse_options);
}

/// A CPE 2.3 formatted string split into its fields: part, vendor, product, version, update, ...
pub const Cpe = struct {
    part: []const u8,
    vendor: []const u8,
    product: []const u8,
    version: []const u8,
    update: []const u8,

    pub fn parse(text: []const u8) ?Cpe {
        if (!std.mem.startsWith(u8, text, "cpe:2.3:")) return null;
        var fields: [11][]const u8 = undefined;
        var n: usize = 0;
        var start: usize = "cpe:2.3:".len;
        var i = start;
        while (i <= text.len and n < fields.len) : (i += 1) {
            if (i == text.len or (text[i] == ':' and text[i - 1] != '\\')) {
                fields[n] = text[start..i];
                n += 1;
                start = i + 1;
            }
        }
        if (n < 5) return null;
        return .{ .part = fields[0], .vendor = fields[1], .product = fields[2], .version = fields[3], .update = fields[4] };
    }
};

// OSV -------------------------------------------------------------------------------------------

pub const OsvEvent = struct {
    introduced: ?[]const u8 = null,
    fixed: ?[]const u8 = null,
    last_affected: ?[]const u8 = null,
    limit: ?[]const u8 = null,
};

pub const OsvRange = struct {
    type: []const u8 = "",
    events: []const OsvEvent = &.{},
};

pub const OsvPackage = struct {
    ecosystem: []const u8 = "",
    name: []const u8 = "",
    purl: ?[]const u8 = null,
};

pub const OsvAffected = struct {
    package: OsvPackage = .{},
    ranges: []const OsvRange = &.{},
    versions: []const []const u8 = &.{},
};

pub const OsvSeverity = struct { type: []const u8 = "", score: []const u8 = "" };

pub const OsvVuln = struct {
    id: []const u8,
    modified: []const u8 = "",
    published: []const u8 = "",
    withdrawn: ?[]const u8 = null,
    aliases: []const []const u8 = &.{},
    summary: []const u8 = "",
    affected: []const OsvAffected = &.{},
    severity: []const OsvSeverity = &.{},

    /// The CVE ids this record covers: its own id when it is one, plus CVE aliases.
    pub fn cves(v: OsvVuln, out: [][]const u8) [][]const u8 {
        var n: usize = 0;
        if (std.mem.startsWith(u8, v.id, "CVE-") and n < out.len) {
            out[n] = v.id;
            n += 1;
        }
        for (v.aliases) |a| if (std.mem.startsWith(u8, a, "CVE-") and n < out.len) {
            out[n] = a;
            n += 1;
        };
        return out[0..n];
    }
};

pub fn parseOsv(arena: std.mem.Allocator, text: []const u8) !OsvVuln {
    return std.json.parseFromSliceLeaky(OsvVuln, arena, text, parse_options);
}

/// Every JSON record in an OSV export zip (`all.zip`), stored or deflated.
pub fn osvZipRecords(gpa: std.mem.Allocator, zip_bytes: []const u8, ctx: anytype, comptime each: fn (@TypeOf(ctx), []const u8) anyerror!void) !usize {
    var count: usize = 0;
    // Walk the central directory; local headers are trusted only for their data offset.
    const eocd = findEocd(zip_bytes) orelse return error.NotZip;
    const entries = std.mem.readInt(u16, zip_bytes[eocd + 10 ..][0..2], .little);
    var off: usize = std.mem.readInt(u32, zip_bytes[eocd + 16 ..][0..4], .little);
    var e: usize = 0;
    while (e < entries) : (e += 1) {
        if (off + 46 > zip_bytes.len or !std.mem.eql(u8, zip_bytes[off..][0..4], "PK\x01\x02")) return error.Corrupt;
        const method = std.mem.readInt(u16, zip_bytes[off + 10 ..][0..2], .little);
        const csize = std.mem.readInt(u32, zip_bytes[off + 20 ..][0..4], .little);
        const usize_ = std.mem.readInt(u32, zip_bytes[off + 24 ..][0..4], .little);
        const nlen = std.mem.readInt(u16, zip_bytes[off + 28 ..][0..2], .little);
        const xlen = std.mem.readInt(u16, zip_bytes[off + 30 ..][0..2], .little);
        const clen = std.mem.readInt(u16, zip_bytes[off + 32 ..][0..2], .little);
        const local = std.mem.readInt(u32, zip_bytes[off + 42 ..][0..4], .little);
        off += 46 + @as(usize, nlen) + xlen + clen;
        if (usize_ > 64 * 1024 * 1024) return error.Corrupt;
        if (local + 30 > zip_bytes.len or !std.mem.eql(u8, zip_bytes[local..][0..4], "PK\x03\x04")) return error.Corrupt;
        const lnlen = std.mem.readInt(u16, zip_bytes[local + 26 ..][0..2], .little);
        const lxlen = std.mem.readInt(u16, zip_bytes[local + 28 ..][0..2], .little);
        const data_off = local + 30 + @as(usize, lnlen) + lxlen;
        if (data_off + csize > zip_bytes.len) return error.Corrupt;
        const data = zip_bytes[data_off..][0..csize];
        switch (method) {
            0 => try each(ctx, data),
            8 => {
                const out = try gpa.alloc(u8, usize_);
                defer gpa.free(out);
                var in: std.Io.Reader = .fixed(data);
                var window: [std.compress.flate.max_window_len]u8 = undefined;
                var d = std.compress.flate.Decompress.init(&in, .raw, &window);
                d.reader.readSliceAll(out) catch return error.Corrupt;
                try each(ctx, out);
            },
            else => continue,
        }
        count += 1;
    }
    return count;
}

fn findEocd(b: []const u8) ?usize {
    if (b.len < 22) return null;
    var i: usize = b.len - 22;
    const stop = if (b.len > 22 + 65535) b.len - 22 - 65535 else 0;
    while (true) : (i -= 1) {
        if (std.mem.eql(u8, b[i..][0..4], "PK\x05\x06")) return i;
        if (i == stop) return null;
    }
}

// Fetching and NVD sync -------------------------------------------------------------------------

/// Performs one GET and writes the body to `out`; returns the HTTP status.
pub const Fetcher = struct {
    ctx: *anyopaque,
    getFn: *const fn (ctx: *anyopaque, url: []const u8, api_key: ?[]const u8, out: *std.Io.Writer) anyerror!u16,
    /// Called between requests with the delay the rate limit needs; tests pass a no-op.
    pauseFn: *const fn (ctx: *anyopaque, ms: u64) void,

    pub fn get(f: Fetcher, url: []const u8, api_key: ?[]const u8, out: *std.Io.Writer) !u16 {
        return f.getFn(f.ctx, url, api_key, out);
    }
};

/// std.http fetcher with a generic User-Agent and the NVD apiKey header.
pub const HttpFetcher = struct {
    client: std.http.Client,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) HttpFetcher {
        return .{ .client = .{ .allocator = gpa, .io = io } };
    }

    pub fn deinit(h: *HttpFetcher) void {
        h.client.deinit();
    }

    pub fn fetcher(h: *HttpFetcher) Fetcher {
        return .{ .ctx = h, .getFn = get, .pauseFn = pause };
    }

    fn get(ctx: *anyopaque, url: []const u8, api_key: ?[]const u8, out: *std.Io.Writer) anyerror!u16 {
        const h: *HttpFetcher = @ptrCast(@alignCast(ctx));
        var headers: [1]std.http.Header = undefined;
        var n: usize = 0;
        if (api_key) |k| {
            headers[0] = .{ .name = "apiKey", .value = k };
            n = 1;
        }
        const r = try h.client.fetch(.{
            .location = .{ .url = url },
            .response_writer = out,
            .headers = .{ .user_agent = .{ .override = "zav-feeds/1" } },
            .privileged_headers = headers[0..n],
        });
        return @backingInt(r.status);
    }

    fn pause(ctx: *anyopaque, ms: u64) void {
        const h: *HttpFetcher = @ptrCast(@alignCast(ctx));
        h.client.io.sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
    }
};

/// Progress of the NVD mirror, saved after every page so an interrupted sync resumes.
pub const NvdState = struct {
    /// End of the last completed window (UTC seconds); 0 before the initial sync finished.
    synced_until: i64 = 0,
    /// The window being fetched: start and end in UTC seconds; full sync when start is 0.
    window_start: i64 = 0,
    window_end: i64 = 0,
    next_index: u32 = 0,
    in_progress: bool = false,
    pages: u32 = 0,
};

pub const SyncOptions = struct {
    api_key: ?[]const u8 = null,
    /// UTC seconds; the end of the incremental window.
    now: i64,
    page_size: u32 = nvd_page_size,
    base_url: []const u8 = nvd_url,
    max_retries: u8 = 6,
};

pub const SyncResult = struct { pages: u32, cves: u32, state: NvdState };

pub fn loadState(io: std.Io, dir: std.Io.Dir) NvdState {
    var buf: [1024]u8 = undefined;
    const text = dir.readFile(io, "state.json", &buf) catch return .{};
    var fba = std.heap.FixedBufferAllocator.init(buf[text.len..]);
    return std.json.parseFromSliceLeaky(NvdState, fba.allocator(), text, .{ .ignore_unknown_fields = true }) catch .{};
}

fn saveState(io: std.Io, dir: std.Io.Dir, st: NvdState) !void {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try std.json.Stringify.value(st, .{}, &w);
    try dir.writeFile(io, .{ .sub_path = "state.json.tmp", .data = w.buffered() });
    try dir.rename("state.json.tmp", dir, "state.json", io);
}

/// NVD's date format with an explicit UTC offset, URL-encoded.
pub fn nvdDate(buf: []u8, secs: i64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(secs, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.000%2B00:00", .{ day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });
}

/// Run or resume the NVD sync: the initial full mirror when nothing is synced yet, otherwise
/// incremental windows (at most 120 days each) from the last synced point to `now`.
pub fn syncNvd(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, f: Fetcher, options: SyncOptions) !SyncResult {
    try dir.createDirPath(io, "pages");
    var st = loadState(io, dir);
    var result: SyncResult = .{ .pages = 0, .cves = 0, .state = st };
    const pause_ms: u64 = if (options.api_key != null) 700 else 6500;
    var first_request = true;
    while (true) {
        if (!st.in_progress) {
            if (st.synced_until == 0) {
                st = .{ .window_start = 0, .window_end = options.now, .in_progress = true };
            } else if (st.synced_until < options.now) {
                const end = @min(options.now, st.synced_until + nvd_max_window_days * std.time.s_per_day);
                st = .{ .synced_until = st.synced_until, .window_start = st.synced_until, .window_end = end, .in_progress = true };
            } else break;
            try saveState(io, dir, st);
        }
        // Page through the window.
        while (true) {
            var url_buf: [512]u8 = undefined;
            var a: [64]u8 = undefined;
            var b: [64]u8 = undefined;
            const url = if (st.window_start == 0)
                try std.fmt.bufPrint(&url_buf, "{s}?resultsPerPage={d}&startIndex={d}", .{ options.base_url, options.page_size, st.next_index })
            else
                try std.fmt.bufPrint(&url_buf, "{s}?resultsPerPage={d}&startIndex={d}&lastModStartDate={s}&lastModEndDate={s}", .{ options.base_url, options.page_size, st.next_index, try nvdDate(&a, st.window_start), try nvdDate(&b, st.window_end) });

            var body: std.Io.Writer.Allocating = .init(gpa);
            defer body.deinit();
            var attempt: u8 = 0;
            while (true) : (attempt += 1) {
                if (!first_request) f.pauseFn(f.ctx, pause_ms * (@as(u64, 1) << @intCast(@min(attempt, 5))));
                first_request = false;
                body.clearRetainingCapacity();
                const status = try f.get(url, options.api_key, &body.writer);
                if (status == 200) break;
                // 403 and 429 are NVD's rate-limit answers; 5xx are transient.
                const retry = status == 403 or status == 429 or status >= 500;
                if (!retry or attempt + 1 >= options.max_retries) return error.HttpError;
            }
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const page = parseNvdPage(arena.allocator(), body.written()) catch return error.BadNvdPage;
            var name_buf: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "pages/{d}-{d}-{d:0>8}.json", .{ st.window_start, st.window_end, st.next_index });
            try dir.writeFile(io, .{ .sub_path = name, .data = body.written() });
            result.pages += 1;
            result.cves += @intCast(page.vulnerabilities.len);
            st.pages += 1;
            st.next_index += @intCast(page.vulnerabilities.len);
            const done = page.vulnerabilities.len == 0 or st.next_index >= page.totalResults;
            if (done) {
                st.synced_until = st.window_end;
                st.in_progress = false;
                st.next_index = 0;
            }
            try saveState(io, dir, st);
            if (done) break;
        }
    }
    result.state = st;
    return result;
}

/// Download a whole feed file and store it with its fetch time.
pub fn fetchFile(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, f: Fetcher, url: []const u8, name: []const u8, now: i64) !usize {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    const status = try f.get(url, null, &body.writer);
    if (status != 200) return error.HttpError;
    if (std.fs.path.dirname(name)) |d| try dir.createDirPath(io, d);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{name});
    try dir.writeFile(io, .{ .sub_path = tmp, .data = body.written() });
    try dir.rename(tmp, dir, name, io);
    var stamp_name_buf: [256]u8 = undefined;
    var stamp_buf: [32]u8 = undefined;
    const stamp_name = try std.fmt.bufPrint(&stamp_name_buf, "{s}/fetched", .{std.fs.path.dirname(name) orelse "."});
    try dir.writeFile(io, .{ .sub_path = stamp_name, .data = try std.fmt.bufPrint(&stamp_buf, "{d}\n", .{now}) });
    return body.written().len;
}

// Recorded fixtures and tests -------------------------------------------------------------------

pub const fixtures = struct {
    pub const kev = @embedFile("fixtures/kev.json");
    pub const nvd_log4shell = @embedFile("fixtures/nvd-cve-2021-44228.json");
    pub const osv_lodash = @embedFile("fixtures/osv-lodash.json");
    pub const osv_requests = @embedFile("fixtures/osv-requests.json");
    /// Both OSV records, one deflated and one stored, as an export zip.
    pub const osv_zip = @embedFile("fixtures/osv-npm.zip");
};

test "KEV catalog" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const kev = try parseKev(arena.allocator(), fixtures.kev);
    try std.testing.expectEqual(@as(usize, 3), kev.vulnerabilities.len);
    var log4j: ?KevEntry = null;
    for (kev.vulnerabilities) |v| if (std.mem.eql(u8, v.cveID, "CVE-2021-44228")) {
        log4j = v;
    };
    try std.testing.expectEqualStrings("Apache", log4j.?.vendorProject);
    try std.testing.expect(log4j.?.ransomware());
    try std.testing.expect(log4j.?.dueDate.len == 10);
}

test "NVD 2.0 page: CVSS, configurations and CPE fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const page = try parseNvdPage(arena.allocator(), fixtures.nvd_log4shell);
    try std.testing.expectEqual(@as(u32, 1), page.totalResults);
    const cve = page.vulnerabilities[0].cve;
    try std.testing.expectEqualStrings("CVE-2021-44228", cve.id);
    const score = cve.cvss();
    try std.testing.expectEqual(@as(f64, 10.0), score.score);
    try std.testing.expectEqualStrings("CRITICAL", score.severity);
    try std.testing.expect(cve.cisaExploitAdd != null);
    var ranges: usize = 0;
    for (cve.configurations) |c| for (c.nodes) |n| for (n.cpeMatch) |m| {
        const cpe = Cpe.parse(m.criteria).?;
        try std.testing.expectEqualStrings("apache", cpe.vendor);
        try std.testing.expectEqualStrings("log4j", cpe.product);
        if (m.versionEndExcluding != null) ranges += 1;
    };
    try std.testing.expectEqual(@as(usize, 3), ranges);
    try std.testing.expect(std.mem.indexOf(u8, cve.description(), "JNDI") != null);
}

test "OSV records" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const v = try parseOsv(arena.allocator(), fixtures.osv_lodash);
    var buf: [4][]const u8 = undefined;
    try std.testing.expectEqualStrings("CVE-2021-23337", v.cves(&buf)[0]);
    try std.testing.expectEqualStrings("npm", v.affected[0].package.ecosystem);
    try std.testing.expectEqualStrings("lodash", v.affected[0].package.name);
    try std.testing.expectEqualStrings("4.17.21", v.affected[0].ranges[0].events[1].fixed.?);
    const r = try parseOsv(arena.allocator(), fixtures.osv_requests);
    try std.testing.expectEqualStrings("PyPI", r.affected[0].package.ecosystem);
}

test "OSV export zip, deflated and stored members" {
    const Collect = struct {
        ids: std.ArrayList([]const u8) = .empty,
        arena: std.mem.Allocator,
        fn each(c: *@This(), json: []const u8) !void {
            const v = try parseOsv(c.arena, json);
            try c.ids.append(c.arena, v.id);
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var c: Collect = .{ .arena = arena.allocator() };
    try std.testing.expectEqual(@as(usize, 2), try osvZipRecords(std.testing.allocator, fixtures.osv_zip, &c, Collect.each));
    try std.testing.expectEqualStrings("GHSA-35jh-r3h4-6jhm", c.ids.items[0]);
    try std.testing.expectEqualStrings("GHSA-9wx4-h78v-vm56", c.ids.items[1]);
    try std.testing.expectError(error.NotZip, osvZipRecords(std.testing.allocator, "not a zip at all, definitely", &c, Collect.each));
}

/// Serves NVD-shaped pages over a synthetic dataset and can fail one request.
const FakeNvd = struct {
    total: u32,
    fail_at_request: ?u32 = null,
    requests: u32 = 0,
    urls: std.ArrayList([]u8) = .empty,
    gpa: std.mem.Allocator,

    fn fetcher(n: *FakeNvd) Fetcher {
        return .{ .ctx = n, .getFn = get, .pauseFn = struct {
            fn p(_: *anyopaque, _: u64) void {}
        }.p };
    }

    fn get(ctx: *anyopaque, url: []const u8, _: ?[]const u8, out: *std.Io.Writer) anyerror!u16 {
        const n: *FakeNvd = @ptrCast(@alignCast(ctx));
        n.requests += 1;
        try n.urls.append(n.gpa, try n.gpa.dupe(u8, url));
        if (n.fail_at_request) |f| if (f == n.requests) return error.ConnectionResetByPeer;
        const si = std.mem.indexOf(u8, url, "startIndex=").?;
        const start = try std.fmt.parseInt(u32, std.mem.sliceTo(url[si + 11 ..], '&'), 10);
        const per = try std.fmt.parseInt(u32, std.mem.sliceTo(url[std.mem.indexOf(u8, url, "resultsPerPage=").? + 15 ..], '&'), 10);
        const total: u32 = if (std.mem.indexOf(u8, url, "lastModStartDate") != null) 3 else n.total;
        try out.print("{{\"resultsPerPage\":{d},\"startIndex\":{d},\"totalResults\":{d},\"vulnerabilities\":[", .{ per, start, total });
        var i = start;
        while (i < @min(start + per, total)) : (i += 1) {
            if (i > start) try out.writeByte(',');
            try out.print("{{\"cve\":{{\"id\":\"CVE-2026-{d:0>5}\"}}}}", .{i});
        }
        try out.writeAll("]}");
        return 200;
    }

    fn deinit(n: *FakeNvd) void {
        for (n.urls.items) |u| n.gpa.free(u);
        n.urls.deinit(n.gpa);
    }
};

test "NVD sync: initial mirror resumes after an interruption, then increments" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fake: FakeNvd = .{ .total = 25, .fail_at_request = 3, .gpa = gpa };
    defer fake.deinit();
    const t0: i64 = 1_763_000_000;

    // Pages of 10: the third request fails mid-sync.
    try std.testing.expectError(error.ConnectionResetByPeer, syncNvd(gpa, io, tmp.dir, fake.fetcher(), .{ .now = t0, .page_size = 10 }));
    const mid = loadState(io, tmp.dir);
    try std.testing.expect(mid.in_progress);
    try std.testing.expectEqual(@as(u32, 20), mid.next_index);
    try std.testing.expectEqual(@as(i64, 0), mid.synced_until);

    // Resume: only the remaining page is fetched.
    fake.fail_at_request = null;
    const resumed = try syncNvd(gpa, io, tmp.dir, fake.fetcher(), .{ .now = t0, .page_size = 10 });
    try std.testing.expectEqual(@as(u32, 1), resumed.pages);
    try std.testing.expectEqual(@as(u32, 5), resumed.cves);
    try std.testing.expect(std.mem.indexOf(u8, fake.urls.items[3], "startIndex=20") != null);
    try std.testing.expectEqual(t0, resumed.state.synced_until); // the window that was started
    try std.testing.expect(!resumed.state.in_progress);

    // Incremental: windows from the synced point, by lastModified, split at 120 days.
    const later = t0 + 200 * std.time.s_per_day;
    const inc = try syncNvd(gpa, io, tmp.dir, fake.fetcher(), .{ .now = later, .page_size = 10 });
    try std.testing.expectEqual(@as(u32, 2), inc.pages);
    try std.testing.expectEqual(later, inc.state.synced_until);
    const last = fake.urls.items[fake.urls.items.len - 1];
    try std.testing.expect(std.mem.indexOf(u8, last, "lastModStartDate=") != null and std.mem.indexOf(u8, last, "%2B00:00") != null);

    // Up to date: nothing to fetch.
    const before = fake.requests;
    _ = try syncNvd(gpa, io, tmp.dir, fake.fetcher(), .{ .now = later, .page_size = 10 });
    try std.testing.expectEqual(before, fake.requests);

    // The raw pages are on disk for reproducible builds.
    var pages = try tmp.dir.openDir(io, "pages", .{ .iterate = true });
    defer pages.close(io);
    var it = pages.iterate();
    var count: usize = 0;
    while (try it.next(io)) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 5), count);
}

test "NVD dates" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("2025-11-13T02:13:20.000%2B00:00", try nvdDate(&buf, 1_763_000_000));
}
