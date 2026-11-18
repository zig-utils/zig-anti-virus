//! Builds the hash-index sections from parsed hash rules: one need map per scope, a hot and a cold
//! table per (algorithm, scope), signature metadata and the name pool. Layouts are defined in
//! `match/hashidx.zig`, which reads them back.
const std = @import("std");
const ir = @import("ir.zig");
const hashidx = @import("../match/hashidx.zig");
const writer = @import("../db/writer.zig");

const table_count = 9;

pub const Built = struct {
    arena: std.heap.ArenaAllocator,
    need_maps: [3]?[]u8 = @splat(null),
    hot: [table_count]?[]u8 = @splat(null),
    cold: [table_count]?[]u8 = @splat(null),
    sigmeta: []u8 = &.{},
    name_pool: []u8 = &.{},
    signature_count: u32 = 0,
    /// Rules dropped because an identical (algorithm, scope, size, digest) came first.
    duplicates: u64 = 0,
    /// Signature ids of the `extra` names passed to `buildWithNames`, in the same order.
    extra_sigs: []u32 = &.{},

    pub fn deinit(b: *Built) void {
        b.arena.deinit();
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
        out[n] = .{ .kind = .sigmeta, .bytes = b.sigmeta };
        out[n + 1] = .{ .kind = .name_pool, .bytes = b.name_pool };
        return out[0 .. n + 2];
    }
};

const Entry = struct {
    size: ?u64,
    key: u64,
    digest: [32]u8,
    sig: u32,

    fn lessThan(_: void, a: Entry, b: Entry) bool {
        // Sized entries first, grouped by size; any-size entries after; then by digest.
        if ((a.size == null) != (b.size == null)) return b.size == null;
        if (a.size) |sa| if (sa != b.size.?) return sa < b.size.?;
        if (a.key != b.key) return a.key < b.key;
        return std.mem.order(u8, &a.digest, &b.digest) == .lt;
    }
};

/// A signature that is not a hash rule (a body or logical signature) but shares the id space,
/// the metadata records and the name pool.
pub const ExtraName = struct {
    name: []const u8,
    flags: ir.Flags = .{},
    source: ir.Source,
};

pub fn build(gpa: std.mem.Allocator, rules: []const ir.HashRule) !Built {
    return buildWithNames(gpa, rules, &.{});
}

pub fn buildWithNames(gpa: std.mem.Allocator, rules: []const ir.HashRule, extra: []const ExtraName) !Built {
    var built: Built = .{ .arena = .init(gpa) };
    errdefer built.deinit();
    const arena = built.arena.allocator();

    // Signature ids: one per distinct (name, PUA flag), in first-seen order.
    var sig_ids: std.StringHashMapUnmanaged(u32) = .empty;
    defer sig_ids.deinit(gpa);
    var families: std.StringHashMapUnmanaged(u32) = .empty;
    defer families.deinit(gpa);
    var meta: std.ArrayList(hashidx.MetaRecord) = .empty;
    defer meta.deinit(gpa);
    var pool: std.ArrayList(u8) = .empty;
    defer pool.deinit(gpa);
    var rule_sigs = try gpa.alloc(u32, rules.len);
    defer gpa.free(rule_sigs);

    var key_buf: std.ArrayList(u8) = .empty;
    defer key_buf.deinit(gpa);
    const extra_sigs = try arena.alloc(u32, extra.len);
    for (0..rules.len + extra.len) |i| {
        const name, const flags, const source = if (i < rules.len)
            .{ rules[i].name, rules[i].flags, rules[i].source }
        else
            .{ extra[i - rules.len].name, extra[i - rules.len].flags, extra[i - rules.len].source };
        key_buf.clearRetainingCapacity();
        try key_buf.append(gpa, @bitCast(flags));
        try key_buf.appendSlice(gpa, name);
        const gop = try sig_ids.getOrPut(gpa, try arena.dupe(u8, key_buf.items));
        if (!gop.found_existing) {
            gop.value_ptr.* = @intCast(meta.items.len);
            const tokens = ir.NameTokens.parse(name);
            const fam = try families.getOrPut(gpa, tokens.family);
            if (!fam.found_existing) {
                fam.value_ptr.* = @intCast(pool.items.len);
                try pool.appendSlice(gpa, tokens.family);
            }
            try meta.append(gpa, .{
                .family_offset = fam.value_ptr.*,
                .family_len = @intCast(tokens.family.len),
                .flags = @bitCast(flags),
                .source = @backingInt(source),
                .number = tokens.number orelse hashidx.no_number,
                .revision = tokens.revision orelse 0,
            });
        }
        if (i < rules.len) rule_sigs[i] = gop.value_ptr.* else extra_sigs[i - rules.len] = gop.value_ptr.*;
    }
    built.extra_sigs = extra_sigs;
    built.signature_count = @intCast(meta.items.len);
    built.sigmeta = try arena.dupe(u8, std.mem.sliceAsBytes(meta.items));
    built.name_pool = try arena.dupe(u8, pool.items);

    // Tables.
    var entries: [table_count]std.ArrayList(Entry) = @splat(.empty);
    defer for (&entries) |*e| e.deinit(gpa);
    for (rules, 0..) |rule, i| {
        const t = hashidx.tableVariant(rule.algo, rule.scope);
        try entries[t].append(gpa, .{ .size = rule.size, .key = hashidx.prefix(&rule.digest), .digest = rule.digest, .sig = rule_sigs[i] });
    }

    var need_sized: [3]std.AutoHashMapUnmanaged(u64, u8) = @splat(.empty);
    defer for (&need_sized) |*m| m.deinit(gpa);
    var sizeless_mask: [3]u8 = @splat(0);
    var any_scope: [3]bool = @splat(false);

    for (&entries, 0..) |*list, t| {
        if (list.items.len == 0) continue;
        const algo: ir.HashAlgo = @fromBackingInt(@intCast(t / 3));
        const scope: ir.HashScope = @fromBackingInt(@intCast(t % 3));
        std.mem.sortUnstable(Entry, list.items, {}, Entry.lessThan);

        // Drop exact duplicates, keeping the first (stable by sort order on digest).
        var kept: usize = 0;
        for (list.items) |e| {
            if (kept > 0) {
                const prev = list.items[kept - 1];
                if (std.meta.eql(prev.size, e.size) and std.mem.eql(u8, &prev.digest, &e.digest)) {
                    built.duplicates += 1;
                    continue;
                }
            }
            list.items[kept] = e;
            kept += 1;
        }
        const items = list.items[0..kept];

        const s = @backingInt(scope);
        any_scope[s] = true;
        for (items) |e| {
            if (e.size) |size| {
                const gop = try need_sized[s].getOrPut(gpa, size);
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* |= hashidx.needBit(algo);
            } else sizeless_mask[s] |= hashidx.needBit(algo);
        }

        const hot_cold = try emitTable(arena, algo, scope, items);
        built.hot[t] = hot_cold[0];
        built.cold[t] = hot_cold[1];
    }

    for (0..3) |s| {
        if (!any_scope[s]) continue;
        built.need_maps[s] = try emitNeedMap(gpa, arena, &need_sized[s], sizeless_mask[s]);
    }
    return built;
}

fn emitTable(arena: std.mem.Allocator, algo: ir.HashAlgo, scope: ir.HashScope, items: []const Entry) ![2][]u8 {
    var size_count: u32 = 0;
    var sized_count: u32 = 0;
    for (items, 0..) |e, i| {
        const size = e.size orelse break;
        sized_count += 1;
        if (i == 0 or items[i - 1].size.? != size) size_count += 1;
    }
    const sizeless_count: u32 = @intCast(items.len - sized_count);

    const sizes_at = @sizeOf(hashidx.TableHeader);
    const starts_at = sizes_at + @as(usize, size_count) * 8;
    const keys_at = std.mem.alignForward(usize, starts_at + (@as(usize, size_count) + 1) * 4, 8);
    const hot = try arena.alignedAlloc(u8, .@"8", keys_at + items.len * 8);
    @memset(hot, 0);
    const header: *hashidx.TableHeader = @ptrCast(hot.ptr);
    header.* = .{
        .algo = @backingInt(algo),
        .scope = @backingInt(scope),
        .size_count = size_count,
        .sized_count = sized_count,
        .sizeless_count = sizeless_count,
    };
    const sizes: [*]u64 = @ptrCast(@alignCast(hot.ptr + sizes_at));
    const starts: [*]u32 = @ptrCast(@alignCast(hot.ptr + starts_at));
    const keys: [*]u64 = @ptrCast(@alignCast(hot.ptr + keys_at));

    const digest_len = algo.digestLen();
    const row_len = digest_len + 4;
    const cold = try arena.alloc(u8, items.len * row_len);

    var size_index: usize = 0;
    for (items, 0..) |e, i| {
        if (e.size) |size| {
            if (i == 0 or items[i - 1].size.? != size) {
                sizes[size_index] = size;
                starts[size_index] = @intCast(i);
                size_index += 1;
            }
        }
        keys[i] = e.key;
        const row = cold[i * row_len ..][0..row_len];
        @memcpy(row[0..digest_len], e.digest[0..digest_len]);
        std.mem.writeInt(u32, row[digest_len..][0..4], e.sig, .little);
    }
    starts[size_count] = sized_count;
    return .{ hot, cold };
}

fn emitNeedMap(gpa: std.mem.Allocator, arena: std.mem.Allocator, sized: *const std.AutoHashMapUnmanaged(u64, u8), sizeless_mask: u8) ![]u8 {
    // Which dense blocks are used, in order, and the large sizes.
    var used: std.AutoArrayHashMapUnmanaged(u32, void) = .empty;
    defer used.deinit(gpa);
    var large: std.ArrayList(hashidx.LargeEntry) = .empty;
    defer large.deinit(gpa);
    var it = sized.iterator();
    while (it.next()) |kv| {
        const size = kv.key_ptr.*;
        if (size < hashidx.dense_limit) {
            try used.put(gpa, @intCast(size / hashidx.block_sizes), {});
        } else try large.append(gpa, .{ .size = size, .mask = kv.value_ptr.* });
    }
    const block_ids = used.keys();
    std.mem.sortUnstable(u32, block_ids, {}, std.sort.asc(u32));
    std.mem.sortUnstable(hashidx.LargeEntry, large.items, {}, struct {
        fn less(_: void, a: hashidx.LargeEntry, b: hashidx.LargeEntry) bool {
            return a.size < b.size;
        }
    }.less);

    const blocks_at = @sizeOf(hashidx.NeedHeader) + hashidx.top_entries * 4;
    const large_at = blocks_at + block_ids.len * 4096;
    const bytes = try arena.alignedAlloc(u8, .@"8", large_at + large.items.len * @sizeOf(hashidx.LargeEntry));
    @memset(bytes, 0);
    const header: *hashidx.NeedHeader = @ptrCast(bytes.ptr);
    header.* = .{ .sizeless_mask = sizeless_mask, .block_count = @intCast(block_ids.len), .large_count = @intCast(large.items.len) };
    const top: *[hashidx.top_entries]u32 = @ptrCast(@alignCast(bytes.ptr + @sizeOf(hashidx.NeedHeader)));
    for (block_ids, 0..) |block, n| top[block] = @intCast(n + 1);

    it = sized.iterator();
    while (it.next()) |kv| {
        const size = kv.key_ptr.*;
        if (size >= hashidx.dense_limit) continue;
        const block = top[@intCast(size / hashidx.block_sizes)] - 1;
        const in_block = size % hashidx.block_sizes;
        const byte = &bytes[blocks_at + block * 4096 + @as(usize, @intCast(in_block / 2))];
        byte.* |= if (in_block % 2 == 0) kv.value_ptr.* else kv.value_ptr.* << 4;
    }
    @memcpy(bytes[large_at..], std.mem.sliceAsBytes(large.items));
    return bytes;
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
    // Same 8-byte prefix as rule 0, different tail, same size.
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
