//! E1 (docs/DESIGN.md section 14): what the hash index costs and how much hashing it avoids.
//!
//!     zig build e1 -- <compiled.zavdb> <clamav-db-dir> <corpus-root>...
//!     zig build e1 -- <compiled.zavdb> <clamav-db-dir> --check-only
//!
//! 1. Every hash line of the CVDs in `<clamav-db-dir>` is looked up in the compiled database
//!    through the scan path's structures (need map, hot and cold tables, SIGMETA): each must be
//!    found under its own name, under the name of an identical earlier rule, or be one the coverage
//!    report lists as ignored (the P3.15 gate).
//! 2. Lookup cost on the real tables, warm (after a first pass) and cold (a fresh copy of the
//!    database written around the page cache, so first touches read from disk), for hits and for
//!    misses at sizes that have entries; then on synthetic tables of 4M MD5 plus 1M SHA-256.
//! 3. The share of files and bytes each algorithm skips on the corpus roots (B1) and on the files
//!    of 4 MiB or more among them (B2), with the size-less signatures and without them.
//!
//! Output is Markdown with the hardware and corpus identifiers.
const std = @import("std");
const builtin = @import("builtin");
const zav = @import("zav");
const Io = std.Io;
const hashidx = zav.match.hashidx;
const ir = zav.compile.ir;

const large_file: u64 = 4 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 4) {
        std.debug.print("usage: e1 <compiled.zavdb> <clamav-db-dir> <corpus-root>...\n", .{});
        std.process.exit(2);
    }
    var out_buf: [64 * 1024]u8 = undefined;
    var out_file = Io.File.stdout().writer(io, &out_buf);
    const w = &out_file.interface;
    defer w.flush() catch {};
    const cwd = Io.Dir.cwd();

    var brand_buf: [64]u8 = undefined;
    try w.print("# E1 run\n\n- CPU: {s}, {s} {t}\n- database: {s}\n\n", .{ zav.simd.arch.brand(&brand_buf) orelse "unknown", @tagName(builtin.os.tag), builtin.cpu.arch, args[1] });

    // Open: the daemon's start-up path for the hash sections.
    const t_open = Io.Clock.awake.now(io);
    const database = try zav.db.reader.open(io, cwd, args[1], .{ .allow_unsigned = true });
    defer database.close();
    const index = try zav.engine.hashscan.HashIndex.load(database);
    const open_ns = t_open.durationTo(Io.Clock.awake.now(io)).toNanoseconds();
    try w.print("## Open\n\nreader.open plus HashIndex.load, warm page cache: {d:.2} ms.\n\n", .{@as(f64, @floatFromInt(open_ns)) / 1e6});

    // 1. Every real hash line, looked up. Apply the same explicit ignore/flevel policy as
    // compilation, so an unexplained missing rule fails the gate rather than looking expected.
    var filters = zav.compile.compiler.Compiler.init(gpa);
    defer filters.deinit();
    for ([_][]const u8{ "main.cvd", "daily.cvd" }) |name| {
        const path = try std.fs.path.join(gpa, &.{ args[2], name });
        defer gpa.free(path);
        try filters.preloadIgnores(io, cwd, path, .{});
    }
    var probes: std.ArrayList(Probe) = .empty;
    defer probes.deinit(gpa);
    var check: Check = .{ .index = &index, .probes = &probes, .gpa = gpa, .ignore = &filters.ignore };
    var db_dir = try cwd.openDir(io, args[2], .{});
    defer db_dir.close(io);
    for ([_][]const u8{ "main.cvd", "daily.cvd" }) |name| {
        const file = try db_dir.openFile(io, name, .{});
        defer file.close(io);
        var header_buf: [zav.compile.cvd.header_len]u8 = undefined;
        const header = try zav.compile.compiler.verifyContainer(gpa, io, db_dir, name, file, &header_buf, .{});
        var buf: [64 * 1024]u8 = undefined;
        var r = file.reader(io, &buf);
        try r.seekTo(zav.compile.cvd.header_len);
        try zav.compile.cvd.walk(gpa, header, &r.interface, .{}, &check);
    }
    try w.print("## Every hash signature (P3.15)\n\n- hash lines: {d}\n- found under their own name: {d}\n- found under the name of an identical rule: {d}\n- explicitly ignored or outside the functionality level: {d}\n- unexpectedly missing: {d}\n\n", .{
        check.lines, check.same, check.other, check.filtered, check.missing,
    });
    if (check.lines == 0 or check.missing != 0) return error.HashGateFailed;
    if (std.mem.eql(u8, args[3], "--check-only")) return;

    // 2. Lookup cost on the real MD5 tables.
    try w.writeAll("## Lookup cost\n\nNanoseconds per lookup, one thread, mean over the whole set (warm: second pass).\n\n| tables | probes | warm hit | warm miss (populated size) | cold hit |\n|---|---:|---:|---:|---:|\n");
    var prng = std.Random.DefaultPrng.init(0xe1);
    const random = prng.random();
    random.shuffle(Probe, probes.items);
    const real = try lookupCost(io, &index, probes.items, random);
    const cold = try coldCost(gpa, io, cwd, args[1], probes.items);
    try w.print("| main + daily (real, {d} MD5 entries) | {d} | {d:.0} | {d:.0} | {d:.0} |\n", .{ check.lines, probes.items.len, real.hit, real.miss, cold });

    // Synthetic 4M MD5 + 1M SHA-256, sizes drawn from the real distinct sizes.
    {
        var sizes: std.ArrayList(u64) = .empty;
        defer sizes.deinit(gpa);
        for (index.tables[hashidx.tableVariant(.md5, .file)].?.sizes) |s| try sizes.append(gpa, s);
        var b = zav.compile.hash_build.Builder.init(gpa, null, zav.compile.hash_build.Builder.default_budget);
        defer b.deinit();
        var syn: std.ArrayList(Probe) = .empty;
        defer syn.deinit(gpa);
        for (0..5_000_000) |i| {
            var d: [32]u8 = undefined;
            random.bytes(&d);
            const algo: ir.HashAlgo = if (i < 4_000_000) .md5 else .sha256;
            const size = sizes.items[random.uintLessThan(usize, sizes.items.len)];
            try b.add(algo, .file, size, &d, @intCast(i));
            if (i % 5 == 0) try syn.append(gpa, .{ .algo = algo, .scope = .file, .size = size, .digest = d });
        }
        var built = try b.finish();
        defer built.deinit();
        var syn_index: zav.engine.hashscan.HashIndex = .{};
        syn_index.need[0] = try .init(built.need_maps[0].?);
        for (0..9) |t| if (built.hot[t]) |hot| {
            syn_index.tables[t] = try .init(hot, built.cold[t].?);
        };
        random.shuffle(Probe, syn.items);
        const s = try lookupCost(io, &syn_index, syn.items, random);
        try w.print("| synthetic 4M MD5 + 1M SHA-256 | {d} | {d:.0} | {d:.0} | n/a |\n", .{ syn.items.len, s.hit, s.miss });
        try w.print("\nSynthetic hot sections: {d:.1} MB (need map plus hot tables).\n", .{@as(f64, @floatFromInt(built.hotBytes())) / 1e6});
    }

    // 3. Skipped hashing on the corpus.
    try skipShare(gpa, io, w, &index, args[3..]);
}

const Probe = struct {
    algo: ir.HashAlgo,
    scope: ir.HashScope,
    size: u64,
    digest: [32]u8,
};

const Check = struct {
    index: *const zav.engine.hashscan.HashIndex,
    probes: *std.ArrayList(Probe),
    gpa: std.mem.Allocator,
    ignore: *const zav.compile.filters.Ignore,
    lines: u64 = 0,
    same: u64 = 0,
    other: u64 = 0,
    missing: u64 = 0,
    filtered: u64 = 0,

    pub fn member(c: *Check, name: []const u8, _: u64, reader: *Io.Reader) !void {
        const ext = name[std.mem.lastIndexOfScalar(u8, name, '.').? + 1 ..];
        const fmt = zav.compile.hashsig.formatFor(ext) orelse return;
        var lr = zav.compile.lines.LineReader.init(c.gpa, reader);
        defer lr.deinit();
        var name_buf: [512]u8 = undefined;
        while (try lr.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r \t");
            if (line.len == 0 or line[0] == '#') continue;
            const rule = try zav.compile.hashsig.parseLine(fmt, line);
            c.lines += 1;
            if (zav.compile.filters.skipReason(&rule, c.ignore, zav.compile.filters.engine_flevel) != null) {
                c.filtered += 1;
                continue;
            }
            const t = hashidx.tableVariant(rule.algo, rule.scope);
            const table = c.index.tables[t] orelse {
                c.missing += 1;
                continue;
            };
            // The scan path: the need map first (a size-less rule passes through the mask).
            const need = c.index.need[@backingInt(rule.scope)] orelse {
                c.missing += 1;
                continue;
            };
            const size = rule.size orelse 0;
            if (!need.covers(rule.algo, rule.size)) {
                c.missing += 1;
                continue;
            }
            const sig = table.lookup(size, rule.digestBytes()) orelse {
                c.missing += 1;
                continue;
            };
            const got = try c.index.meta.?.name(sig, &name_buf);
            if (std.mem.eql(u8, got, rule.name)) c.same += 1 else c.other += 1;
            if (rule.algo == .md5 and rule.scope != .pe_import and rule.size != null)
                try c.probes.append(c.gpa, .{ .algo = rule.algo, .scope = rule.scope, .size = size, .digest = rule.digest });
        }
    }
};

var sink: u64 = 0;

fn lookupCost(io: Io, index: *const zav.engine.hashscan.HashIndex, probes: []const Probe, random: std.Random) !struct { hit: f64, miss: f64 } {
    var hit: f64 = 0;
    for (0..2) |_| {
        const start = Io.Clock.awake.now(io);
        for (probes) |p| {
            const table = index.tables[hashidx.tableVariant(p.algo, p.scope)].?;
            sink +%= table.lookup(p.size, p.digest[0..p.algo.digestLen()]) orelse return error.LookupMissed;
        }
        hit = nsPer(start, io, probes.len);
    }
    // Misses at populated sizes: a random digest at a size that has entries.
    const misses = try std.heap.page_allocator.alloc([32]u8, probes.len);
    defer std.heap.page_allocator.free(misses);
    for (misses) |*m| random.bytes(m);
    var miss: f64 = 0;
    for (0..2) |_| {
        const start = Io.Clock.awake.now(io);
        for (probes, misses) |p, m| {
            const table = index.tables[hashidx.tableVariant(p.algo, p.scope)].?;
            if (table.lookup(p.size, m[0..p.algo.digestLen()])) |sig| sink +%= sig;
        }
        miss = nsPer(start, io, probes.len);
    }
    return .{ .hit = hit, .miss = miss };
}

fn nsPer(start: Io.Timestamp, io: Io, n: usize) f64 {
    const ns = start.durationTo(Io.Clock.awake.now(io)).toNanoseconds();
    return @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(n));
}

/// Hits on a copy of the database written around the page cache: each probe's pages are read
/// from disk on first touch. 2,000 probes over 64 MB of table touch mostly distinct pages.
fn coldCost(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, probes: []const Probe) !f64 {
    var copy_buf: [std.fs.max_path_bytes]u8 = undefined;
    const copy_path = try std.fmt.bufPrint(&copy_buf, "{s}.e1-cold", .{path});
    defer dir.deleteFile(io, copy_path) catch {};
    {
        const src = try dir.openFile(io, path, .{});
        defer src.close(io);
        const dst = try dir.createFile(io, copy_path, .{ .truncate = true });
        defer dst.close(io);
        if (builtin.os.tag.isDarwin()) _ = std.c.fcntl(dst.handle, std.c.F.NOCACHE, @as(c_int, 1));
        const buf = try gpa.alloc(u8, 4 * 1024 * 1024);
        defer gpa.free(buf);
        var off: u64 = 0;
        while (true) {
            const n = try src.readPositionalAll(io, buf, off);
            if (n == 0) break;
            try dst.writePositionalAll(io, buf[0..n], off);
            off += n;
            if (n < buf.len) break;
        }
        try dst.sync(io);
        if (builtin.os.tag == .linux) _ = std.os.linux.fadvise(dst.handle, 0, 0, std.os.linux.POSIX_FADV.DONTNEED);
    }
    const database = try zav.db.reader.open(io, dir, copy_path, .{ .allow_unsigned = true });
    defer database.close();
    const index = try zav.engine.hashscan.HashIndex.load(database);
    const n = @min(probes.len, 2000);
    const start = Io.Clock.awake.now(io);
    for (probes[0..n]) |p| {
        const table = index.tables[hashidx.tableVariant(p.algo, p.scope)].?;
        sink +%= table.lookup(p.size, p.digest[0..p.algo.digestLen()]) orelse return error.LookupMissed;
    }
    return nsPer(start, io, n);
}

const Tally = struct {
    files: u64 = 0,
    bytes: u64 = 0,
    /// Files and bytes that do not need each algorithm: [md5, sha1, sha256], with size-less
    /// signatures and without them.
    skip_files: [2][3]u64 = @splat(@splat(0)),
    skip_bytes: [2][3]u64 = @splat(@splat(0)),

    fn add(t: *Tally, need: hashidx.NeedMap, size: u64) void {
        t.files += 1;
        t.bytes += size;
        const with = need.mask(size);
        const sized = sizedMask(need, size);
        for ([_]u8{ with, sized }, 0..) |m, k| {
            for (0..3) |a| if (m & (@as(u8, 1) << @intCast(a)) == 0) {
                t.skip_files[k][a] += 1;
                t.skip_bytes[k][a] += size;
            };
        }
    }
};

/// The need mask without the size-less signatures.
fn sizedMask(need: hashidx.NeedMap, size: u64) u8 {
    var copy = need;
    var header = need.header.*;
    header.sizeless_mask = 0;
    copy.header = &header;
    return copy.mask(size);
}

fn skipShare(gpa: std.mem.Allocator, io: Io, w: *Io.Writer, index: *const zav.engine.hashscan.HashIndex, roots: []const []const u8) !void {
    const need = index.need[@backingInt(ir.HashScope.file)].?;
    var all: Tally = .{};
    var large: Tally = .{};
    var manifest = std.crypto.hash.sha2.Sha256.init(.{});
    var unreadable: u64 = 0;
    for (roots) |root| {
        var dir = Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch {
            unreadable += 1;
            continue;
        };
        defer dir.close(io);
        var walker = try dir.walkSelectively(gpa);
        defer walker.deinit();
        while (true) {
            const entry = walker.next(io) catch {
                unreadable += 1;
                continue;
            } orelse break;
            switch (entry.kind) {
                .directory => walker.enter(io, entry) catch {
                    unreadable += 1;
                },
                .file => {
                    const st = entry.dir.statFile(io, entry.basename, .{ .follow_symlinks = false }) catch {
                        unreadable += 1;
                        continue;
                    };
                    all.add(need, st.size);
                    if (st.size >= large_file) large.add(need, st.size);
                    var size_buf: [24]u8 = undefined;
                    manifest.update(root);
                    manifest.update("/");
                    manifest.update(entry.path);
                    manifest.update(std.fmt.bufPrint(&size_buf, "\t{d}\n", .{st.size}) catch unreachable);
                },
                else => {},
            }
        }
    }
    var digest: [32]u8 = undefined;
    manifest.final(&digest);
    try w.writeAll("\n## Hashing skipped by the need map\n\nCorpus roots: ");
    for (roots, 0..) |r, i| try w.print("{s}`{s}`", .{ if (i == 0) "" else ", ", r });
    try w.print(". Manifest SHA-256 (root, path, size per file, walk order): `{x}`. Unreadable entries: {d}.\n\n", .{ &digest, unreadable });
    try w.writeAll("| corpus | files | GB | MD5 files / bytes skipped | SHA-1 | SHA-256 | MD5 without size-less sigs | SHA-256 without size-less sigs |\n|---|---:|---:|---:|---:|---:|---:|---:|\n");
    for ([_]struct { []const u8, *const Tally }{ .{ "B1 all files", &all }, .{ "B2 files of 4 MiB or more", &large } }) |row| {
        const t = row[1];
        try w.print("| {s} | {d} | {d:.2} | {d:.1}% / {d:.1}% | {d:.1}% / {d:.1}% | {d:.1}% / {d:.1}% | {d:.2}% / {d:.2}% | {d:.2}% / {d:.2}% |\n", .{
            row[0],                           t.files,                          @as(f64, @floatFromInt(t.bytes)) / 1e9,
            pct(t.skip_files[0][0], t.files), pct(t.skip_bytes[0][0], t.bytes), pct(t.skip_files[0][1], t.files),
            pct(t.skip_bytes[0][1], t.bytes), pct(t.skip_files[0][2], t.files), pct(t.skip_bytes[0][2], t.bytes),
            pct(t.skip_files[1][0], t.files), pct(t.skip_bytes[1][0], t.bytes), pct(t.skip_files[1][2], t.files),
            pct(t.skip_bytes[1][2], t.bytes),
        });
    }
}

fn pct(n: u64, of: u64) f64 {
    if (of == 0) return 0;
    return @as(f64, @floatFromInt(n)) * 100.0 / @as(f64, @floatFromInt(of));
}
