//! Builds the hash-index sections: one need map per scope and a hot and a cold table per
//! (algorithm, scope). Layouts are defined in `match/hashidx.zig`, which reads them back.
//!
//! Rules arrive one at a time as compact fixed-size records (size, digest, signature id) and are
//! sorted with the compiler's external merge sort (`spill.Sorter`), so a table of millions of
//! entries is built in a bounded amount of memory; cold rows go to a spill-backed sink. Exact
//! duplicates (same algorithm, scope, size and digest) keep the first signature id.
const std = @import("std");
const ir = @import("ir.zig");
const hashidx = @import("../match/hashidx.zig");
const writer = @import("../db/writer.zig");
const spill_mod = @import("spill.zig");
const names_mod = @import("names.zig");

pub const table_count = 9;

/// Size recorded for an any-size signature; sorts after every real size.
const sizeless: u64 = std.math.maxInt(u64);

fn Record(comptime digest_len: usize) type {
    return extern struct {
        const Self = @This();
        size_lo: u32,
        size_hi: u32,
        digest: [digest_len]u8,
        sig: u32,

        fn size(r: Self) u64 {
            return @as(u64, r.size_hi) << 32 | r.size_lo;
        }

        fn lessThan(_: void, a: Self, b: Self) bool {
            if (a.size() != b.size()) return a.size() < b.size();
            switch (std.mem.order(u8, &a.digest, &b.digest)) {
                .lt => return true,
                .gt => return false,
                .eq => return a.sig < b.sig,
            }
        }
    };
}

fn TableSorter(comptime digest_len: usize) type {
    const Rec = Record(digest_len);
    return spill_mod.Sorter(Rec, Rec.lessThan);
}

pub const Built = struct {
    gpa: std.mem.Allocator,
    need_maps: [3]?[]align(8) u8 = @splat(null),
    hot: [table_count]?[]align(8) u8 = @splat(null),
    cold: [table_count]?[]const u8 = @splat(null),
    cold_sinks: [table_count]?spill_mod.Sink = @splat(null),
    /// SIGMETA and NAME_POOL, when the names were interned by `build`.
    names: ?names_mod.NameTable = null,
    sigmeta: []align(8) u8 = &.{},
    signature_count: u32 = 0,
    /// Rules dropped because an identical (algorithm, scope, size, digest) came first.
    duplicates: u64 = 0,
    /// Entries per table, after deduplication.
    entries: [table_count]u64 = @splat(0),

    pub fn deinit(b: *Built) void {
        for (b.need_maps) |m| if (m) |bytes| b.gpa.free(bytes);
        for (b.hot) |h| if (h) |bytes| b.gpa.free(bytes);
        for (&b.cold_sinks) |*s| if (s.*) |*sink| sink.deinit();
        if (b.names) |*n| n.deinit();
        b.gpa.free(b.sigmeta);
        b.* = undefined;
    }

    /// Bytes of the hot sections (need maps and hot tables).
    pub fn hotBytes(b: *const Built) u64 {
        var n: u64 = 0;
        for (b.need_maps) |m| if (m) |bytes| {
            n += bytes.len;
        };
        for (b.hot) |h| if (h) |bytes| {
            n += bytes.len;
        };
        return n;
    }

    /// The sections to hand to `db.writer`. `out` needs room for 3 + 2 * 9 + 2 entries.
    pub fn sections(b: *const Built, out: []writer.Section) []writer.Section {
        var n: usize = 0;
        for (b.need_maps, 0..) |map, scope| if (map) |bytes| {
            out[n] = .{ .kind = .hash_need_map, .variant = @intCast(scope), .hot = true, .bytes = bytes };
            n += 1;
        };
        for (b.hot, 0..) |hot, t| if (hot) |bytes| {
            out[n] = .{ .kind = .hash_hot, .variant = @intCast(t), .hot = true, .bytes = bytes };
            n += 1;
            out[n] = .{ .kind = .hash_cold, .variant = @intCast(t), .bytes = b.cold[t].? };
            n += 1;
        };
        if (b.names) |*names| {
            out[n] = .{ .kind = .sigmeta, .bytes = b.sigmeta };
            out[n + 1] = .{ .kind = .name_pool, .bytes = names.namePool() };
            n += 2;
        }
        return out[0..n];
    }
};

pub const Builder = struct {
    gpa: std.mem.Allocator,
    spill: ?*spill_mod.Spill,
    /// Sort buffer per table before a run is spilled.
    budget: usize,
    md5: [3]?TableSorter(16) = @splat(null),
    sha1: [3]?TableSorter(20) = @splat(null),
    sha256: [3]?TableSorter(32) = @splat(null),

    pub const default_budget = 32 * 1024 * 1024;

    pub fn init(gpa: std.mem.Allocator, spill: ?*spill_mod.Spill, budget: usize) Builder {
        return .{ .gpa = gpa, .spill = spill, .budget = budget };
    }

    pub fn deinit(b: *Builder) void {
        inline for (.{ &b.md5, &b.sha1, &b.sha256 }) |tables| {
            for (tables) |*t| if (t.*) |*s| s.deinit();
        }
        b.* = undefined;
    }

    /// Add one rule. `digest` holds at least the algorithm's digest length.
    pub fn add(b: *Builder, algo: ir.HashAlgo, scope: ir.HashScope, size: ?u64, digest: []const u8, sig: u32) !void {
        const s = @backingInt(scope);
        const sz = size orelse sizeless;
        switch (algo) {
            inline else => |a| {
                const n = comptime a.digestLen();
                const tables = &@field(b, @tagName(a));
                if (tables[s] == null) tables[s] = TableSorter(n).init(b.gpa, b.spill, b.budget);
                try tables[s].?.add(.{ .size_lo = @truncate(sz), .size_hi = @intCast(sz >> 32), .digest = digest[0..n].*, .sig = sig });
            },
        }
    }

    pub fn addRule(b: *Builder, rule: *const ir.HashRule, sig: u32) !void {
        return b.add(rule.algo, rule.scope, rule.size, rule.digestBytes(), sig);
    }

    /// Sort, deduplicate and lay out every table and the need maps.
    pub fn finish(b: *Builder) !Built {
        var built: Built = .{ .gpa = b.gpa };
        errdefer built.deinit();
        var sizes: [3][3]std.ArrayList(u64) = @splat(@splat(.empty));
        defer for (&sizes) |*row| for (row) |*l| l.deinit(b.gpa);
        var sizeless_mask: [3]u8 = @splat(0);
        var any_scope: [3]bool = @splat(false);

        inline for (comptime std.enums.values(ir.HashAlgo)) |algo| {
            const tables = &@field(b, @tagName(algo));
            for (tables, 0..) |*slot, s| {
                const sorter = if (slot.*) |*x| x else continue;
                const scope: ir.HashScope = @fromBackingInt(@intCast(s));
                const t = hashidx.tableVariant(algo, scope);
                built.cold_sinks[t] = spill_mod.Sink.init(b.gpa, b.spill);
                const has_sizeless = try emitTable(comptime algo.digestLen(), b.gpa, sorter, algo, scope, &built, t, &sizes[s][@backingInt(algo)]);
                if (has_sizeless) sizeless_mask[s] |= hashidx.needBit(algo);
                built.cold[t] = try built.cold_sinks[t].?.finish();
                any_scope[s] = true;
                // The records are in the table now; free the sort buffer and runs early.
                sorter.deinit();
                slot.* = null;
            }
        }
        for (0..3) |s| {
            if (!any_scope[s]) continue;
            built.need_maps[s] = try emitNeedMap(b.gpa, &sizes[s], sizeless_mask[s]);
        }
        return built;
    }
};

/// Lay out one table; returns whether it has any-size entries.
fn emitTable(comptime digest_len: usize, gpa: std.mem.Allocator, sorter: *TableSorter(digest_len), algo: ir.HashAlgo, scope: ir.HashScope, built: *Built, t: usize, sizes: *std.ArrayList(u64)) !bool {
    const Rec = Record(digest_len);
    var starts: std.ArrayList(u32) = .empty;
    defer starts.deinit(gpa);
    var keys: std.ArrayList(u32) = .empty;
    defer keys.deinit(gpa);
    const cold = &built.cold_sinks[t].?;

    var merge = try sorter.merge();
    defer merge.deinit();
    var prev: ?Rec = null;
    var sized_count: u32 = 0;
    var sizeless_count: u32 = 0;
    while (try merge.next()) |r| {
        if (prev) |p| if (p.size() == r.size() and std.mem.eql(u8, &p.digest, &r.digest)) {
            built.duplicates += 1;
            continue;
        };
        prev = r;
        const index: u32 = @intCast(keys.items.len);
        if (r.size() != sizeless) {
            if (sizes.items.len == 0 or sizes.items[sizes.items.len - 1] != r.size()) {
                try sizes.append(gpa, r.size());
                try starts.append(gpa, index);
            }
            sized_count += 1;
        } else sizeless_count += 1;
        try keys.append(gpa, hashidx.prefix(&r.digest));
        try cold.append(r.digest[hashidx.key_len..]);
        var sig: [4]u8 = undefined;
        std.mem.writeInt(u32, &sig, r.sig, .little);
        try cold.append(&sig);
    }
    try starts.append(gpa, sized_count);
    built.entries[t] = keys.items.len;

    const size_count: u32 = @intCast(sizes.items.len);
    const radix_count: u32 = if (size_count > hashidx.list_limit) hashidx.radix_entries else 0;
    const sizes_at = @sizeOf(hashidx.TableHeader);
    const starts_at = sizes_at + @as(usize, size_count) * 8;
    const radix_at = starts_at + (@as(usize, size_count) + 1) * 4;
    const keys_at = std.mem.alignForward(usize, radix_at + @as(usize, radix_count) * 4, 8);
    const hot = try gpa.alignedAlloc(u8, .@"8", keys_at + keys.items.len * 4);
    @memset(hot, 0);
    const header: *hashidx.TableHeader = @ptrCast(hot.ptr);
    header.* = .{
        .algo = @backingInt(algo),
        .scope = @backingInt(scope),
        .size_count = size_count,
        .sized_count = sized_count,
        .sizeless_count = sizeless_count,
        .radix_count = radix_count,
    };
    @memcpy(hot[sizes_at..starts_at], std.mem.sliceAsBytes(sizes.items));
    @memcpy(hot[starts_at..][0 .. starts.items.len * 4], std.mem.sliceAsBytes(starts.items));
    if (radix_count > 0) {
        const radix: [*]u32 = @ptrCast(@alignCast(hot.ptr + radix_at));
        var pos: u32 = 0;
        for (0..radix_count) |i| {
            const floor = @as(u64, i) << hashidx.radix_shift;
            while (pos < size_count and sizes.items[pos] < floor) pos += 1;
            radix[i] = pos;
        }
    }
    @memcpy(hot[keys_at..], std.mem.sliceAsBytes(keys.items));
    built.hot[t] = hot;
    return sizeless_count > 0;
}

/// One scope's need map from the sorted distinct sizes of each algorithm's table.
fn emitNeedMap(gpa: std.mem.Allocator, sizes: *const [3]std.ArrayList(u64), sizeless_mask: u8) ![]align(8) u8 {
    var header: hashidx.NeedHeader = .{ .sizeless_mask = sizeless_mask };
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try bytes.appendNTimes(gpa, 0, @sizeOf(hashidx.NeedHeader));
    for (sizes, &header.maps) |list, *map| {
        const all = list.items;
        if (all.len == 0) continue;
        if (all.len <= hashidx.list_limit) {
            map.* = .{ .mode = .list, .count = @intCast(all.len), .off = @intCast(bytes.items.len) };
            try bytes.appendSlice(gpa, std.mem.sliceAsBytes(all));
            continue;
        }
        // Bitmap: dense sizes split into 1 KiB blocks, numbered in order of first use.
        const dense_end = std.sort.partitionPoint(u64, all, {}, struct {
            fn below(_: void, v: u64) bool {
                return v < hashidx.dense_limit;
            }
        }.below);
        var top: [hashidx.top_entries]u32 = @splat(0);
        var block_count: u32 = 0;
        for (all[0..dense_end]) |size| {
            const slot = &top[@intCast(size / hashidx.block_sizes)];
            if (slot.* == 0) {
                block_count += 1;
                slot.* = block_count;
            }
        }
        map.* = .{ .mode = .bitmap, .count = block_count, .off = @intCast(bytes.items.len) };
        try bytes.appendSlice(gpa, std.mem.sliceAsBytes(&top));
        const blocks_at = bytes.items.len;
        try bytes.appendNTimes(gpa, 0, @as(usize, block_count) * hashidx.block_bytes);
        for (all[0..dense_end]) |size| {
            const block = top[@intCast(size / hashidx.block_sizes)] - 1;
            const bit: usize = @intCast(size % hashidx.block_sizes);
            bytes.items[blocks_at + block * hashidx.block_bytes + bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
        }
        const large = all[dense_end..];
        map.large_count = @intCast(large.len);
        map.large_off = @intCast(bytes.items.len);
        try bytes.appendSlice(gpa, std.mem.sliceAsBytes(large));
    }
    @memcpy(bytes.items[0..@sizeOf(hashidx.NeedHeader)], std.mem.asBytes(&header));
    const out = try gpa.alignedAlloc(u8, .@"8", bytes.items.len);
    @memcpy(out, bytes.items);
    return out;
}

/// Build tables and names from parsed rules in memory (allowlists, tests, benchmarks).
pub fn build(gpa: std.mem.Allocator, rules: []const ir.HashRule) !Built {
    var names = names_mod.NameTable.init(gpa);
    var names_owned = true;
    errdefer if (names_owned) names.deinit();
    var b = Builder.init(gpa, null, Builder.default_budget);
    defer b.deinit();
    for (rules) |*rule| try b.addRule(rule, try names.intern(rule.name, rule.flags, rule.source));
    var built = try b.finish();
    errdefer built.deinit();
    built.sigmeta = try names.sigmeta(gpa);
    built.signature_count = names.count();
    built.names = names;
    names_owned = false;
    return built;
}

fn md5Rule(hex: []const u8, size: ?u64, name: []const u8) !ir.HashRule {
    var digest: [32]u8 = @splat(0);
    _ = try std.fmt.hexToBytes(digest[0..16], hex);
    return .{ .algo = .md5, .scope = .file, .digest = digest, .size = size, .name = name, .source = .hdb, .flevel_min = if (size == null) 73 else 0 };
}

test "build, write, open and look up through the mapped sections" {
    const gpa = std.testing.allocator;
    const db = @import("../db/root.zig");
    var sha_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", &sha_digest, .{});
    const rules = [_]ir.HashRule{
        try md5Rule("44d88612fea8a8f36de82e1278abb02f", 68, "Eicar-Test-Signature"),
        try md5Rule("44d88612fea8a8f36de82e1278abb02f", 68, "Eicar-Test-Signature"), // duplicate
        try md5Rule("00112233445566778899aabbccddeeff", 20_000_000, "Win.Trojan.Large-1-0"),
        try md5Rule("ffeeddccbbaa99887766554433221100", null, "Doc.Malware.AnySize-2-1"),
        .{ .algo = .sha256, .scope = .file, .digest = sha_digest, .size = 68, .name = "Eicar-Test-Signature", .source = .hsb },
        .{ .algo = .md5, .scope = .pe_section, .digest = @splat(0xab), .size = 4096, .name = "Win.Packed.Section-3-0", .source = .mdb },
    };
    var built = try build(gpa, &rules);
    defer built.deinit();
    try std.testing.expectEqual(@as(u64, 1), built.duplicates);
    try std.testing.expectEqual(@as(u32, 4), built.signature_count);

    var section_buf: [32]writer.Section = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try writer.write(io, tmp.dir, "h.zavdb", built.sections(&section_buf), .{ .db_version = 1 });
    const opened = try db.reader.open(io, tmp.dir, "h.zavdb", .{ .allow_unsigned = true });
    defer opened.close();

    const need = try hashidx.NeedMap.init(opened.section(.hash_need_map, @backingInt(ir.HashScope.file)).?);
    try std.testing.expectEqual(hashidx.need_md5 | hashidx.need_sha256, need.mask(68));
    try std.testing.expectEqual(hashidx.need_md5, need.mask(20_000_000)); // large list
    try std.testing.expectEqual(hashidx.need_md5, need.mask(69)); // only the any-size MD5
    try std.testing.expectEqual(hashidx.need_md5, need.header.sizeless_mask);

    const t = hashidx.tableVariant(.md5, .file);
    const md5 = try hashidx.Table.init(opened.section(.hash_hot, t).?, opened.section(.hash_cold, t).?);
    const meta = try hashidx.SigMeta.init(opened.section(.sigmeta, 0).?, opened.section(.name_pool, 0).?);
    var name_buf: [64]u8 = undefined;

    var eicar: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&eicar, "44d88612fea8a8f36de82e1278abb02f");
    const sig = md5.lookup(68, &eicar).?;
    try std.testing.expectEqualStrings("Eicar-Test-Signature", try meta.name(sig, &name_buf));
    try std.testing.expectEqual(@as(?u32, null), md5.lookup(67, &eicar)); // wrong size

    var any: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&any, "ffeeddccbbaa99887766554433221100");
    try std.testing.expectEqualStrings("Doc.Malware.AnySize-2-1", try meta.name(md5.lookup(12345, &any).?, &name_buf));

    const ts = hashidx.tableVariant(.sha256, .file);
    const sha = try hashidx.Table.init(opened.section(.hash_hot, ts).?, opened.section(.hash_cold, ts).?);
    try std.testing.expectEqual(sig, sha.lookup(68, &sha_digest).?); // same name, same id

    const section_need = try hashidx.NeedMap.init(opened.section(.hash_need_map, @backingInt(ir.HashScope.pe_section)).?);
    try std.testing.expectEqual(hashidx.need_md5, section_need.mask(4096));
    try std.testing.expectEqual(@as(u8, 0), section_need.mask(4097));
}

test "a prefix collision never becomes a detection, and random digests never match" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x1234);
    const random = prng.random();
    var rules: [2000]ir.HashRule = undefined;
    for (&rules, 0..) |*r, i| {
        var digest: [32]u8 = @splat(0);
        random.bytes(digest[0..16]);
        r.* = .{ .algo = .md5, .scope = .file, .digest = digest, .size = 1000 + (i % 50), .name = "Fuzz.Sig", .source = .hdb };
    }
    // Same 4-byte prefix as rule 0, different tail, same size.
    var twin = rules[0];
    twin.digest[15] ^= 0xff;
    var built = try build(gpa, &rules);
    defer built.deinit();

    const t = hashidx.tableVariant(.md5, .file);
    const table = try hashidx.Table.init(built.hot[t].?, built.cold[t].?);
    for (rules) |r| try std.testing.expect(table.lookup(r.size.?, r.digest[0..16]) != null);
    try std.testing.expectEqual(@as(?u32, null), table.lookup(twin.size.?, twin.digest[0..16]));
    var misses: usize = 0;
    for (0..100_000) |i| {
        var d: [16]u8 = undefined;
        random.bytes(&d);
        if (table.lookup(1000 + (i % 50), &d) == null) misses += 1;
    }
    try std.testing.expectEqual(@as(usize, 100_000), misses);
}

test "spilled tables, bitmap and list need maps, and every entry found" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spill: spill_mod.Spill = .init(io, tmp.dir);
    var b = Builder.init(gpa, &spill, 64 * 1024);
    defer b.deinit();
    var prng = std.Random.DefaultPrng.init(99);
    const random = prng.random();
    const n = 20_000;
    const digests = try gpa.alloc([32]u8, n);
    defer gpa.free(digests);
    const sizes = try gpa.alloc(u64, n);
    defer gpa.free(sizes);
    for (digests, sizes, 0..) |*d, *size, i| {
        random.bytes(d);
        size.* = if (i % 97 == 0) (1 << 24) + i else random.uintLessThan(u64, 1 << 24);
        try b.add(.md5, .file, size.*, d, @intCast(i));
        if (i % 1000 == 0) try b.add(.sha256, .file, size.*, d, @intCast(i));
    }
    try b.add(.md5, .file, sizes[5], &digests[5], 77); // a duplicate: the first id stays
    var built = try b.finish();
    defer built.deinit();
    try std.testing.expectEqual(@as(u64, 1), built.duplicates);
    const need = try hashidx.NeedMap.init(built.need_maps[0].?);
    try std.testing.expectEqual(hashidx.MapMode.bitmap, need.header.maps[0].mode);
    try std.testing.expectEqual(hashidx.MapMode.list, need.header.maps[2].mode);
    const md5 = try hashidx.Table.init(built.hot[0].?, built.cold[0].?);
    for (digests, sizes, 0..) |d, size, i| {
        try std.testing.expect(need.mask(size) & hashidx.need_md5 != 0);
        try std.testing.expectEqual(@as(?u32, @intCast(i)), md5.lookup(size, d[0..16]));
    }
    try std.testing.expectEqual(hashidx.need_sha256 | hashidx.need_md5, need.mask(sizes[1000]));
    var absent: usize = 0;
    for (0..10_000) |_| {
        const size = random.uintLessThan(u64, 1 << 25);
        const want = std.mem.indexOfScalar(u64, sizes, size) != null;
        if (!want) absent += 1;
        try std.testing.expectEqual(want, need.mask(size) & hashidx.need_md5 != 0);
    }
    try std.testing.expect(absent > 9000);
}
