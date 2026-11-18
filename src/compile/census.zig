//! E0: the database census (docs/DESIGN.md section 14). Reads verified ClamAV containers line by
//! line through the compiler's own parsers and counts what the design needs to know: signatures
//! by extension, target type and offset kind, the longest fixed run of every body subsignature
//! (atom tiers A to D), size-less hashes, size coverage, how well names tokenise, PCRE subsigs
//! and functionality levels. Nothing is built and nothing is kept per signature beyond 64-bit
//! hashes for distinct counts, so a census of every database runs in a few tens of MB.
//!
//! Output is deterministic: every table is sorted, every hash is seeded with a constant, so the
//! same databases always render the same report.
const std = @import("std");
const Io = std.Io;
const ir = @import("ir.zig");
const cvd = @import("cvd.zig");
const hashsig = @import("hashsig.zig");
const hexsig = @import("hexsig.zig");
const ndb = @import("ndb.zig");
const ldb = @import("ldb.zig");
const ftm = @import("ftm.zig");
const cdb = @import("cdb.zig");
const filters = @import("filters.zig");
const lines_mod = @import("lines.zig");

const reason_count = @typeInfo(ir.Reason).@"enum".field_names.len;
const target_count = ndb.max_target + 1;
const offset_kinds = 7;

/// Atom tiers by the length L of a subsignature's longest fixed run (docs/DESIGN.md 4.2).
pub const Tier = enum(u2) {
    /// L >= 11
    a,
    /// 7 <= L <= 10
    b,
    /// 4 <= L <= 6
    c,
    /// L <= 3
    d,

    pub fn of(run: usize) Tier {
        if (run >= 11) return .a;
        if (run >= 7) return .b;
        if (run >= 4) return .c;
        return .d;
    }
};

/// Longest run of fixed bytes inside one part: consecutive literal ops (nocase literals count,
/// they are fixed after folding). Masked nibbles, gaps, alternations and part breaks end a run.
pub fn longestFixedRun(p: ir.Pattern) usize {
    var best: usize = 0;
    var run: usize = 0;
    for (p.ops) |op| {
        if (op.code == .lit) {
            run += op.len;
            best = @max(best, run);
        } else run = 0;
    }
    return best;
}

/// The run that decides a subsignature's tier: the weakest of its compile-time variants (a wide
/// form doubles the run, a case or alternation variant can shorten it).
pub fn subsigRun(arena: std.mem.Allocator, sub: ir.Subsig) struct { run: usize, variants: usize, expanded: bool } {
    const variants = hexsig.expand(arena, sub.pattern, sub.mods) catch
        return .{ .run = longestFixedRun(sub.pattern), .variants = 0, .expanded = false };
    var run: usize = std.math.maxInt(usize);
    for (variants) |v| run = @min(run, longestFixedRun(v.pattern));
    return .{ .run = run, .variants = variants.len, .expanded = true };
}

/// Names in the shape `Family-N` or `Family-N-R` with canonical decimal fields (no sign, no
/// leading zero), N below 2^32 and R below 256: these round-trip through (family, number,
/// revision) exactly.
pub const SchemeTokens = struct {
    family: []const u8,
    number: ?u32 = null,
    revision: ?u8 = null,

    pub fn parse(name: []const u8) SchemeTokens {
        const last = std.mem.lastIndexOfScalar(u8, name, '-') orelse return .{ .family = name };
        if (last == 0) return .{ .family = name };
        const tail = canonical(u32, name[last + 1 ..]) orelse return .{ .family = name };
        const head = name[0..last];
        if (std.mem.lastIndexOfScalar(u8, head, '-')) |second| {
            if (second > 0 and tail <= 255) {
                if (canonical(u32, head[second + 1 ..])) |n| return .{ .family = head[0..second], .number = n, .revision = @intCast(tail) };
            }
        }
        return .{ .family = head, .number = tail };
    }

    fn canonical(comptime T: type, text: []const u8) ?T {
        if (text.len == 0 or text.len > 10) return null;
        if (text.len > 1 and text[0] == '0') return null;
        for (text) |c| if (c < '0' or c > '9') return null;
        return std.fmt.parseInt(T, text, 10) catch null;
    }
};

const TableStats = struct {
    entries: u64 = 0,
    sizeless: u64 = 0,
    /// Entries per exact size.
    sizes: std.AutoHashMapUnmanaged(u64, u32) = .empty,
};

const MemberStats = struct {
    container: []const u8,
    bytes: u64 = 0,
    /// Files folded into this row (bytecode programs).
    files: u64 = 1,
    lines: u64 = 0,
    parsed: u64 = 0,
    rejected: [reason_count]u64 = @splat(0),
};

const Histogram = std.AutoArrayHashMapUnmanaged(u32, u64);

const KindStats = struct {
    signatures: u64 = 0,
    targets: [target_count]u64 = @splat(0),
    offsets: [offset_kinds]u64 = @splat(0),
    tiers: [4]u64 = @splat(0),
    /// Tier-D subsigs with a fixed offset (anchorable).
    tier_d_anchored: u64 = 0,
    /// Tier-D subsigs whose logical signature has a tier A-C hex subsig as well.
    tier_d_with_partner: u64 = 0,
    /// Signatures whose best hex subsig is in each tier.
    best_tiers: [4]u64 = @splat(0),
    /// Hex subsigs and their compile-time variants.
    hex_subsigs: u64 = 0,
    variants: u64 = 0,
    expand_failed: u64 = 0,
    nocase: u64 = 0,
    wide: u64 = 0,
    ascii: u64 = 0,
    fullword: u64 = 0,
    pcre: u64 = 0,
    pcre_signatures: u64 = 0,
    byte_compare: u64 = 0,
    subsig_counts: Histogram = .empty,
    run_lengths: Histogram = .empty,
};

const LevelStats = struct {
    min: Histogram = .empty,
    with_max: u64 = 0,
    out_of_range: u64 = 0,
    total: u64 = 0,
};

pub const ContainerInfo = struct {
    path: []const u8,
    version: u32,
    signatures: u32,
    functionality_level: u32,
    build_time: []const u8,
    build_seconds: u64,
};

pub const Census = struct {
    gpa: std.mem.Allocator,
    /// Owns names and paths kept for the report.
    keep: std.heap.ArenaAllocator,
    /// Per-line scratch, reset after every line.
    scratch: std.heap.ArenaAllocator,
    containers: std.ArrayList(ContainerInfo) = .empty,
    members: std.StringArrayHashMapUnmanaged(MemberStats) = .empty,
    tables: [9]TableStats = @splat(.{}),
    body: KindStats = .{},
    logical: KindStats = .{},
    levels: [6]LevelStats = @splat(.{}),
    ftm_rules: u64 = 0,
    cdb_rules: u64 = 0,
    cdb_regex: u64 = 0,

    names_total: u64 = 0,
    name_set: std.AutoHashMapUnmanaged(u64, void) = .empty,
    name_bytes: u64 = 0,
    /// Names the engine's NameTokens splits into family, number and revision.
    current_tokenised: u64 = 0,
    current_roundtrip_failures: u64 = 0,
    current_families: std.AutoHashMapUnmanaged(u64, void) = .empty,
    current_family_bytes: u64 = 0,
    scheme_n: u64 = 0,
    scheme_nr: u64 = 0,
    scheme_families: std.AutoHashMapUnmanaged(u64, void) = .empty,
    scheme_family_bytes: u64 = 0,
    max_number: u32 = 0,

    pub fn init(gpa: std.mem.Allocator) Census {
        return .{ .gpa = gpa, .keep = .init(gpa), .scratch = .init(gpa) };
    }

    pub fn deinit(c: *Census) void {
        c.containers.deinit(c.gpa);
        c.members.deinit(c.gpa);
        for (&c.tables) |*t| t.sizes.deinit(c.gpa);
        for ([_]*KindStats{ &c.body, &c.logical }) |k| {
            k.subsig_counts.deinit(c.gpa);
            k.run_lengths.deinit(c.gpa);
        }
        for (&c.levels) |*l| l.min.deinit(c.gpa);
        c.name_set.deinit(c.gpa);
        c.current_families.deinit(c.gpa);
        c.scheme_families.deinit(c.gpa);
        c.scratch.deinit();
        c.keep.deinit();
    }

    /// Verify a CVD (MD5 and signature with the default options) and count its members.
    pub fn addContainer(c: *Census, io: Io, dir: Io.Dir, sub_path: []const u8, options: cvd.VerifyOptions) !cvd.Header {
        const file = try dir.openFile(io, sub_path, .{});
        defer file.close(io);
        const keep = c.keep.allocator();
        const header_bytes = try keep.alloc(u8, cvd.header_len);
        if (try file.readPositionalAll(io, header_bytes, 0) != cvd.header_len) return error.Truncated;
        const header = try cvd.parseHeader(header_bytes);
        var buf: [64 * 1024]u8 = undefined;
        {
            var r = file.reader(io, &buf);
            try r.seekTo(cvd.header_len);
            try cvd.verify(header, &r.interface, options);
        }
        const label = try keep.dupe(u8, std.fs.path.basename(sub_path));
        try c.containers.append(c.gpa, .{
            .path = label,
            .version = header.version,
            .signatures = header.signatures,
            .functionality_level = header.functionality_level,
            .build_time = header.build_time,
            .build_seconds = header.build_seconds,
        });
        var r = file.reader(io, &buf);
        try r.seekTo(cvd.header_len);
        var visitor: Visitor = .{ .census = c, .container = label };
        try cvd.walk(c.gpa, header, &r.interface, .{}, &visitor);
        return header;
    }

    const Visitor = struct {
        census: *Census,
        container: []const u8,

        pub fn member(v: *Visitor, name: []const u8, size: u64, reader: *Io.Reader) !void {
            try v.census.addMember(v.container, name, size, reader);
        }
    };

    /// Count one database file read from `reader`.
    pub fn addMember(c: *Census, container: []const u8, name: []const u8, size: u64, reader: *Io.Reader) !void {
        // Bytecode programs are one file each; they are counted together.
        const bytecode = std.mem.endsWith(u8, name, ".cbc");
        const key = if (bytecode) "*.cbc" else name;
        const gop = try c.members.getOrPut(c.gpa, key);
        if (gop.found_existing and !bytecode) return error.DuplicateMember;
        if (!gop.found_existing) {
            gop.key_ptr.* = try c.keep.allocator().dupe(u8, key);
            gop.value_ptr.* = .{ .container = container, .files = if (bytecode) 0 else 1 };
        }
        const stats = gop.value_ptr;
        stats.bytes += size;
        if (bytecode) {
            stats.files += 1;
            stats.parsed += 1;
            stats.lines += 1;
            return;
        }

        const ext = extension(name);
        const kind = classify(ext);
        var lr = lines_mod.LineReader.init(c.gpa, reader);
        defer lr.deinit();
        while (try lr.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r \t");
            if (line.len == 0) continue;
            if (line[0] == '#' and kind != .other) continue;
            stats.lines += 1;
            defer _ = c.scratch.reset(.retain_capacity);
            const ok = try c.countLine(kind, ext, line, stats);
            if (ok) stats.parsed += 1;
        }
    }

    const Kind = enum { hash, body, logical, magic, container, other };

    fn classify(ext: []const u8) Kind {
        if (hashsig.formatFor(ext) != null) return .hash;
        if (eql(ext, "ndb") or eql(ext, "ndu")) return .body;
        if (eql(ext, "ldb") or eql(ext, "ldu")) return .logical;
        if (eql(ext, "ftm")) return .magic;
        if (eql(ext, "cdb") or eql(ext, "cdu")) return .container;
        return .other;
    }

    fn countLine(c: *Census, kind: Kind, ext: []const u8, line: []const u8, stats: *MemberStats) !bool {
        const arena = c.scratch.allocator();
        var column: u32 = 0;
        switch (kind) {
            .hash => {
                const rule = hashsig.parseLine(hashsig.formatFor(ext).?, line) catch |err| {
                    stats.rejected[@backingInt(hashReason(err))] += 1;
                    return false;
                };
                const t = @as(usize, @backingInt(rule.algo)) * 3 + @backingInt(rule.scope);
                const table = &c.tables[t];
                table.entries += 1;
                if (rule.size) |size| {
                    const g = try table.sizes.getOrPut(c.gpa, size);
                    if (!g.found_existing) g.value_ptr.* = 0;
                    g.value_ptr.* += 1;
                } else table.sizeless += 1;
                try c.level(0, rule.flevel_min, rule.flevel_max);
                try c.countName(rule.name);
            },
            .body => {
                const rule = ndb.parseLine(arena, line, &column) catch |err| {
                    stats.rejected[@backingInt(ndb.reasonOf(err))] += 1;
                    return false;
                };
                const k = &c.body;
                k.signatures += 1;
                k.targets[rule.target] += 1;
                try c.countHex(k, rule.subsig, false);
                const run = subsigRun(arena, rule.subsig).run;
                k.best_tiers[@backingInt(Tier.of(run))] += 1;
                try c.level(1, rule.flevel_min, rule.flevel_max);
                try c.countName(rule.name);
            },
            .logical => {
                const rule = ldb.parseLine(arena, line, &column) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    stats.rejected[@backingInt(ldb.reasonOf(err))] += 1;
                    return false;
                };
                const k = &c.logical;
                k.signatures += 1;
                k.targets[rule.tdb.target] += 1;
                try bump(c.gpa, &k.subsig_counts, @intCast(rule.subsigs.len));
                var best: ?Tier = null;
                var has_pcre = false;
                for (rule.subsigs) |sub| switch (sub) {
                    .hex => |h| {
                        const t = Tier.of(subsigRun(arena, h).run);
                        if (best == null or @backingInt(t) < @backingInt(best.?)) best = t;
                    },
                    .pcre => has_pcre = true,
                    .byte_compare => {},
                };
                const partner = best != null and best.? != .d;
                for (rule.subsigs) |sub| switch (sub) {
                    .hex => |h| try c.countHex(k, h, partner),
                    .pcre => k.pcre += 1,
                    .byte_compare => k.byte_compare += 1,
                };
                if (has_pcre) k.pcre_signatures += 1;
                if (best) |b| k.best_tiers[@backingInt(b)] += 1;
                try c.level(2, rule.flevel_min, rule.flevel_max);
                try c.countName(rule.name);
            },
            .magic => {
                const rule = ftm.parseLine(arena, line, &column) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    stats.rejected[@backingInt(ftm.reasonOf(err))] += 1;
                    return false;
                };
                c.ftm_rules += 1;
                try c.level(3, rule.flevel_min, rule.flevel_max);
            },
            .container => {
                const rule = cdb.parseLine(arena, line, &column) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    stats.rejected[@backingInt(cdb.reasonOf(err))] += 1;
                    return false;
                };
                c.cdb_rules += 1;
                if (rule.filename_regex != null) c.cdb_regex += 1;
                try c.level(4, rule.flevel_min, rule.flevel_max);
                try c.countName(rule.name);
            },
            .other => {},
        }
        return true;
    }

    fn countHex(c: *Census, k: *KindStats, sub: ir.Subsig, partner: bool) !void {
        const arena = c.scratch.allocator();
        k.hex_subsigs += 1;
        k.offsets[@min(@backingInt(sub.offset.kind), offset_kinds - 1)] += 1;
        const r = subsigRun(arena, sub);
        if (!r.expanded) k.expand_failed += 1;
        k.variants += r.variants;
        const tier = Tier.of(r.run);
        k.tiers[@backingInt(tier)] += 1;
        try bump(c.gpa, &k.run_lengths, @intCast(@min(r.run, 64)));
        if (tier == .d) {
            if (sub.offset.kind != .any) k.tier_d_anchored += 1;
            if (partner) k.tier_d_with_partner += 1;
        }
        if (sub.mods.nocase) k.nocase += 1;
        if (sub.mods.wide) k.wide += 1;
        if (sub.mods.ascii) k.ascii += 1;
        if (sub.mods.fullword) k.fullword += 1;
    }

    fn level(c: *Census, which: usize, min: u16, max: u16) !void {
        const l = &c.levels[which];
        l.total += 1;
        try bump(c.gpa, &l.min, min);
        if (max != 0) l.with_max += 1;
        if ((min != 0 and min > filters.engine_flevel) or (max != 0 and max < filters.engine_flevel)) l.out_of_range += 1;
    }

    fn countName(c: *Census, name: []const u8) !void {
        c.names_total += 1;
        const h = std.hash.Wyhash.hash(0, name);
        if (!(try c.name_set.getOrPut(c.gpa, h)).found_existing) c.name_bytes += name.len;

        const cur = ir.NameTokens.parse(name);
        if (cur.number != null) c.current_tokenised += 1;
        var buf: [1024]u8 = undefined;
        const back = cur.format(&buf) catch name;
        if (!std.mem.eql(u8, back, name)) c.current_roundtrip_failures += 1;
        const fh = std.hash.Wyhash.hash(1, cur.family);
        if (!(try c.current_families.getOrPut(c.gpa, fh)).found_existing) c.current_family_bytes += cur.family.len;

        const s = SchemeTokens.parse(name);
        if (s.number) |n| {
            c.max_number = @max(c.max_number, n);
            if (s.revision != null) c.scheme_nr += 1 else c.scheme_n += 1;
        }
        const sh = std.hash.Wyhash.hash(2, s.family);
        if (!(try c.scheme_families.getOrPut(c.gpa, sh)).found_existing) c.scheme_family_bytes += s.family.len;
    }

    /// The census as Markdown.
    pub fn render(c: *Census, w: *Io.Writer) !void {
        try w.writeAll("## Databases\n\n| file | version | signatures | flevel | built |\n|---|---:|---:|---:|---|\n");
        for (c.containers.items) |x| try w.print("| {s} | {d} | {d} | {d} | {s} |\n", .{ x.path, x.version, x.signatures, x.functionality_level, x.build_time });

        try w.writeAll("\n## Members\n\nLines are non-blank, non-comment lines; rejected lines are listed by reason below. " ++
            "Bytecode programs are one signature per file and are counted as files.\n\n" ++
            "| member | bytes | lines | parsed | rejected |\n|---|---:|---:|---:|---:|\n");
        const order = try c.sortedMembers();
        defer c.gpa.free(order);
        var tot_lines: u64 = 0;
        var tot_parsed: u64 = 0;
        var tot_bytes: u64 = 0;
        for (order) |i| {
            const name = c.members.keys()[i];
            const s = c.members.values()[i];
            var rej: u64 = 0;
            for (s.rejected) |n| rej += n;
            tot_lines += s.lines;
            tot_parsed += s.parsed;
            tot_bytes += s.bytes;
            if (s.files > 1) {
                try w.print("| {s} ({d} files) | {d} | {d} | {d} | {d} |\n", .{ name, s.files, s.bytes, s.lines, s.parsed, rej });
            } else try w.print("| {s} | {d} | {d} | {d} | {d} |\n", .{ name, s.bytes, s.lines, s.parsed, rej });
        }
        try w.print("| **total** | {d} | {d} | {d} | {d} |\n", .{ tot_bytes, tot_lines, tot_parsed, tot_lines - tot_parsed });
        try w.writeAll("\nRejections:\n\n");
        var any = false;
        for (order) |i| {
            const s = c.members.values()[i];
            for (s.rejected, 0..) |n, r| if (n > 0) {
                any = true;
                try w.print("- {s}: {d} {t}\n", .{ c.members.keys()[i], n, @as(ir.Reason, @fromBackingInt(@intCast(r))) });
            };
        }
        if (!any) try w.writeAll("- none\n");

        try c.renderHashes(w);
        try w.writeAll("\n## Body signatures (.ndb, .ndu)\n\n");
        try renderKind(w, &c.body, false);
        try w.writeAll("\n## Logical signatures (.ldb, .ldu)\n\n");
        try renderKind(w, &c.logical, true);
        try w.print("\n## Other signature kinds\n\n- .ftm file-type magic: {d}\n- .cdb container signatures: {d} ({d} with a filename regex)\n", .{ c.ftm_rules, c.cdb_rules, c.cdb_regex });
        try c.renderNames(w);
        try c.renderLevels(w);
    }

    fn sortedMembers(c: *Census) ![]usize {
        const order = try c.gpa.alloc(usize, c.members.count());
        for (order, 0..) |*o, i| o.* = i;
        std.mem.sortUnstable(usize, order, c.members.keys(), struct {
            fn less(keys: [][]const u8, a: usize, b: usize) bool {
                return std.mem.order(u8, keys[a], keys[b]) == .lt;
            }
        }.less);
        return order;
    }

    fn renderHashes(c: *Census, w: *Io.Writer) !void {
        try w.writeAll("\n## Hash signatures\n\nOne table per (algorithm, scope). Sizes below 2^24 are the dense need map's range.\n\n" ++
            "| table | entries | size-less | distinct sizes | entries < 2^24 | sizes < 2^24 | largest bucket | max size |\n" ++
            "|---|---:|---:|---:|---:|---:|---:|---:|\n");
        const algos = [_][]const u8{ "md5", "sha1", "sha256" };
        const scopes = [_][]const u8{ "file", "pe_section", "pe_import" };
        var total: u64 = 0;
        var sizeless: u64 = 0;
        for (c.tables, 0..) |t, i| {
            if (t.entries == 0) continue;
            total += t.entries;
            sizeless += t.sizeless;
            var small_entries: u64 = 0;
            var small_sizes: u64 = 0;
            var largest: u32 = 0;
            var max_size: u64 = 0;
            var it = t.sizes.iterator();
            while (it.next()) |kv| {
                largest = @max(largest, kv.value_ptr.*);
                max_size = @max(max_size, kv.key_ptr.*);
                if (kv.key_ptr.* < 1 << 24) {
                    small_sizes += 1;
                    small_entries += kv.value_ptr.*;
                }
            }
            try w.print("| {s} {s} | {d} | {d} | {d} | {d} ({d:.2}%) | {d} | {d} | {d} |\n", .{
                algos[i / 3],  scopes[i % 3],                              t.entries,   t.sizeless, t.sizes.count(),
                small_entries, pct(small_entries, t.entries - t.sizeless), small_sizes, largest,    max_size,
            });
        }
        try w.print("\nTotal hash signatures: {d}; size-less: {d}.\n", .{ total, sizeless });
    }

    fn renderNames(c: *Census, w: *Io.Writer) !void {
        try w.writeAll("\n## Signature names\n\n");
        try w.print("- names: {d}, distinct: {d}, distinct name bytes: {d}\n", .{ c.names_total, c.name_set.count(), c.name_bytes });
        try w.print("- current tokeniser (`Family-N-R` only): {d} tokenised ({d:.2}%), {d} distinct families, {d} family bytes, {d} round-trip failures\n", .{
            c.current_tokenised, pct(c.current_tokenised, c.names_total), c.current_families.count(), c.current_family_bytes, c.current_roundtrip_failures,
        });
        try w.print("- `Family-N` or `Family-N-R`, canonical decimals: {d} `Family-N` and {d} `Family-N-R` ({d:.2}%), {d} distinct families, {d} family bytes, largest N {d}\n", .{
            c.scheme_n, c.scheme_nr, pct(c.scheme_n + c.scheme_nr, c.names_total), c.scheme_families.count(), c.scheme_family_bytes, c.max_number,
        });
    }

    fn renderLevels(c: *Census, w: *Io.Writer) !void {
        try w.print("\n## Functionality levels\n\nThe engine declares level {d}; a rule is out of range when its minimum is above it or its maximum below it.\n\n" ++
            "| kind | rules | with a minimum | with a maximum | out of range | minimum levels (level: rules) |\n|---|---:|---:|---:|---:|---|\n", .{filters.engine_flevel});
        const labels = [_][]const u8{ "hash", "ndb", "ldb", "ftm", "cdb" };
        for (labels, 0..) |label, i| {
            const l = &c.levels[i];
            if (l.total == 0) continue;
            const zero = l.min.get(0) orelse 0;
            try w.print("| {s} | {d} | {d} | {d} | {d} | ", .{ label, l.total, l.total - zero, l.with_max, l.out_of_range });
            try renderHistogram(w, &l.min, 0);
            try w.writeAll(" |\n");
        }
    }
};

fn renderKind(w: *Io.Writer, k: *KindStats, logical: bool) !void {
    const target_names = [_][]const u8{ "any", "PE", "OLE2", "HTML", "mail", "graphics", "ELF", "ASCII", "unused", "Mach-O", "PDF", "Flash", "Java", "13", "14" };
    const offset_names = [_][]const u8{ "any (*)", "absolute", "EOF-n", "EP+n", "Sx+n", "SEx", "SL+n" };
    try w.print("Signatures: {d}. Hex subsignatures: {d}, compiled into {d} variants ({d} do not expand and are listed in the coverage report).\n\n", .{ k.signatures, k.hex_subsigs, k.variants, k.expand_failed });
    try w.writeAll("By target type: ");
    var first = true;
    for (k.targets, 0..) |n, t| if (n > 0) {
        try w.print("{s}{s} {d}", .{ if (first) "" else ", ", target_names[t], n });
        first = false;
    };
    try w.writeAll(".\n\nHex subsignatures by offset kind: ");
    first = true;
    for (k.offsets, 0..) |n, o| if (n > 0) {
        try w.print("{s}{s} {d}", .{ if (first) "" else ", ", offset_names[o], n });
        first = false;
    };
    try w.writeAll(".\n\n| tier | longest fixed run | hex subsigs | share |\n|---|---|---:|---:|\n");
    const labels = [_][]const u8{ "A", "B", "C", "D" };
    const ranges = [_][]const u8{ "11+", "7-10", "4-6", "0-3" };
    for (k.tiers, 0..) |n, t| try w.print("| {s} | {s} | {d} | {d:.2}% |\n", .{ labels[t], ranges[t], n, pct(n, k.hex_subsigs) });
    try w.print("\nTier D: {d} anchorable (fixed offset)", .{k.tier_d_anchored});
    if (logical) try w.print(", {d} in a signature that also has a tier A-C hex subsig (deferrable candidates)", .{k.tier_d_with_partner});
    try w.writeAll(".\n\nSignatures by their best hex subsig: ");
    for (k.best_tiers, 0..) |n, t| try w.print("{s}{s} {d}", .{ if (t == 0) "" else ", ", labels[t], n });
    try w.print(".\n\nModifiers: nocase {d}, wide {d}, ascii {d}, fullword {d}.\n", .{ k.nocase, k.wide, k.ascii, k.fullword });
    if (logical) {
        try w.print("\nPCRE subsigs: {d} in {d} signatures. Byte-compare subsigs: {d}.\n\nSubsigs per signature (count: signatures): ", .{ k.pcre, k.pcre_signatures, k.byte_compare });
        try renderHistogram(w, &k.subsig_counts, 0);
        try w.writeAll(".\n");
    }
    try w.writeAll("\nLongest fixed run per hex subsig (bytes: subsigs, 64 means 64 or more): ");
    try renderHistogram(w, &k.run_lengths, 0);
    try w.writeAll(".\n");
}

fn renderHistogram(w: *Io.Writer, h: *Histogram, _: u32) !void {
    const keys = h.keys();
    const order = try std.heap.page_allocator.alloc(usize, keys.len);
    defer std.heap.page_allocator.free(order);
    for (order, 0..) |*o, i| o.* = i;
    std.mem.sortUnstable(usize, order, keys, struct {
        fn less(ks: []u32, a: usize, b: usize) bool {
            return ks[a] < ks[b];
        }
    }.less);
    for (order, 0..) |i, n| try w.print("{s}{d}: {d}", .{ if (n == 0) "" else ", ", keys[i], h.values()[i] });
}

fn bump(gpa: std.mem.Allocator, h: *Histogram, key: u32) !void {
    const g = try h.getOrPut(gpa, key);
    if (!g.found_existing) g.value_ptr.* = 0;
    g.value_ptr.* += 1;
}

fn pct(n: u64, of: u64) f64 {
    if (of == 0) return 0;
    return @as(f64, @floatFromInt(n)) * 100.0 / @as(f64, @floatFromInt(of));
}

fn hashReason(err: anyerror) ir.Reason {
    return switch (err) {
        error.FieldCount => .field_count,
        error.BadHash => .bad_hash,
        error.BadSize => .bad_size,
        error.WildcardNeedsFlevel73 => .wildcard_needs_flevel_73,
        error.BadFlevel => .bad_flevel,
        error.EmptyName => .empty_name,
        else => .field_count,
    };
}

fn extension(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "";
    return name[dot + 1 ..];
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test "tiers come from the longest fixed run of the weakest variant" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diag: hexsig.Diag = .{};
    const p = try hexsig.parse(a, "aabbccdd??112233445566778899*00", &diag);
    try std.testing.expectEqual(@as(usize, 9), longestFixedRun(p));
    try std.testing.expectEqual(Tier.b, Tier.of(longestFixedRun(p)));
    const wide = subsigRun(a, .{ .pattern = p, .mods = .{ .wide = true } });
    try std.testing.expectEqual(@as(usize, 18), wide.run);
    try std.testing.expectEqual(Tier.d, Tier.of(3));
    try std.testing.expectEqual(Tier.c, Tier.of(4));
    try std.testing.expectEqual(Tier.a, Tier.of(11));
}

test "scheme tokens round-trip only canonical names" {
    const t = SchemeTokens.parse("Win.Trojan.VB-1770");
    try std.testing.expectEqualStrings("Win.Trojan.VB", t.family);
    try std.testing.expectEqual(@as(?u32, 1770), t.number);
    try std.testing.expectEqual(@as(?u8, null), t.revision);
    const r = SchemeTokens.parse("Win.Trojan.Agent-1234567-0");
    try std.testing.expectEqualStrings("Win.Trojan.Agent", r.family);
    try std.testing.expectEqual(@as(?u8, 0), r.revision);
    try std.testing.expectEqual(@as(?u32, null), SchemeTokens.parse("Win.X-01").number);
    try std.testing.expectEqual(@as(?u32, null), SchemeTokens.parse("-5").number);
    try std.testing.expectEqualStrings("Win.X-007", SchemeTokens.parse("Win.X-007-1").family);
}

test "census of the fixture CVD is deterministic" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "test.cvd", .data = cvd.fixture_cvd });

    var outputs: [2][]u8 = undefined;
    for (&outputs) |*out| {
        var c = Census.init(gpa);
        defer c.deinit();
        // The fixture is signed with a test-only key, not Talos's.
        _ = try c.addContainer(io, tmp.dir, "test.cvd", .{ .allow_unverified = true });
        try std.testing.expect(c.members.count() > 0);
        var w: Io.Writer.Allocating = .init(gpa);
        defer w.deinit();
        try c.render(&w.writer);
        out.* = try w.toOwnedSlice();
    }
    defer for (outputs) |o| gpa.free(o);
    try std.testing.expectEqualStrings(outputs[0], outputs[1]);

    // Members counted line by line through the parsers.
    var c = Census.init(gpa);
    defer c.deinit();
    var r: Io.Reader = .fixed("44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\nbad\nffeeddccbbaa99887766554433221100:*:Doc.X-2-1:73\n");
    try c.addMember("loose", "local.hdb", 0, &r);
    var n: Io.Reader = .fixed("Win.Trojan.A-1-0:1:EP+0:4d5a9000\nHtml.B-2:3:*:3c736372697074\n");
    try c.addMember("loose", "local.ndb", 0, &n);
    try std.testing.expectEqual(@as(u64, 2), c.tables[0].entries);
    try std.testing.expectEqual(@as(u64, 1), c.tables[0].sizeless);
    try std.testing.expectEqual(@as(u64, 1), c.members.get("local.hdb").?.rejected[@backingInt(ir.Reason.field_count)]);
    try std.testing.expectEqual(@as(u64, 1), c.body.offsets[@backingInt(ir.OffsetKind.entry_point)]);
    try std.testing.expectEqual(@as(u64, 1), c.body.tiers[@backingInt(Tier.c)]);
    try std.testing.expectEqual(@as(u64, 1), c.body.tiers[@backingInt(Tier.b)]);
    try std.testing.expectEqual(@as(u64, 1), c.body.targets[3]);
    try std.testing.expectEqual(@as(u64, 4), c.names_total);
}
