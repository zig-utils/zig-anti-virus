//! Hash signature lookup over mapped `.zavdb` sections (docs/DESIGN.md section 3.3).
//!
//! The scan path asks two questions per file, both answered from read-only mapped bytes with no
//! allocation:
//! 1. `NeedMap.mask(size)`: which algorithms have any signature for this exact size (or for any
//!    size)? A zero mask means the file is not hashed at all.
//! 2. `Table.lookup(size, digest)`: binary search the sorted sizes, then the 4-byte digest
//!    prefixes inside that size's bucket (the hot tier), and confirm a prefix hit against the rest
//!    of the digest (the cold tier). A prefix collision can never become a detection.
//!
//! Version 2 layouts (E0, docs/experiments/E0-census.md): MD5 is the only algorithm with more than
//! a few hundred entries, so the need map keeps one bit per size per algorithm, and only for an
//! algorithm with many distinct sizes; the rest are short sorted lists. Hot keys are 4 bytes, since
//! a bucket rarely holds more than a few thousand digests and a 32-bit prefix collision only costs
//! one cold read. Cold rows hold the digest after those 4 bytes.
//!
//! Layouts are little-endian and offset based; the builder lives in `compile/hash_build.zig`.
const std = @import("std");
const ir = @import("../compile/ir.zig");

test "need-map coverage distinguishes a zero-sized entry from any-size hashing" {
    for ([_]Algo{ .md5, .sha1, .sha256 }) |algo| {
        var bytes: [@sizeOf(NeedHeader) + 16]u8 align(8) = @splat(0);
        const header: *NeedHeader = @ptrCast(&bytes);
        header.* = .{};
        header.maps[@backingInt(algo)] = .{ .mode = .list, .count = 2, .off = @sizeOf(NeedHeader) };
        std.mem.writeInt(u64, bytes[@sizeOf(NeedHeader)..][0..8], 0, .little);
        std.mem.writeInt(u64, bytes[@sizeOf(NeedHeader) + 8 ..][0..8], 64, .little);
        const need = try NeedMap.init(&bytes);
        try std.testing.expect(need.mask(0) & needBit(algo) != 0);
        try std.testing.expect(need.covers(algo, 0));
        try std.testing.expect(need.covers(algo, 64));
        try std.testing.expect(!need.covers(algo, 65));
        try std.testing.expect(!need.covers(algo, null));
        header.sizeless_mask = needBit(algo);
        try std.testing.expect(need.covers(algo, null));
        try std.testing.expect(need.covers(algo, 65));
    }
}

pub const Algo = ir.HashAlgo;
pub const Scope = ir.HashScope;

/// Need-map bits per size.
pub const need_md5: u8 = 1 << 0;
pub const need_sha1: u8 = 1 << 1;
pub const need_sha256: u8 = 1 << 2;

pub fn needBit(algo: Algo) u8 {
    return switch (algo) {
        .md5 => need_md5,
        .sha1 => need_sha1,
        .sha256 => need_sha256,
    };
}

/// Table variant number: one table per algorithm and scope.
pub fn tableVariant(algo: Algo, scope: Scope) u16 {
    return @as(u16, @backingInt(algo)) * 3 + @backingInt(scope);
}

/// Sizes below this can use the dense bitmap; larger sizes are always in a sorted list.
pub const dense_limit: u64 = 1 << 24;
/// Sizes covered by one 1 KiB bitmap block.
pub const block_sizes: u64 = 8192;
pub const block_bytes: usize = block_sizes / 8;
pub const top_entries: usize = dense_limit / block_sizes;
/// An algorithm with more distinct sizes than this gets a bitmap; fewer stay a sorted list
/// (at most 12 probes over at most 32 KiB).
pub const list_limit: usize = 4096;

pub const MapMode = enum(u8) {
    /// No sized signatures for this algorithm in this scope.
    none = 0,
    /// `[top_entries]u32` block numbers plus one (0: empty block) at `off`, then `count` blocks of
    /// `block_bytes`; sizes from `dense_limit` on as a sorted `[large_count]u64` at `large_off`.
    bitmap = 1,
    /// A sorted `[count]u64` of every size at `off`.
    list = 2,
    _,
};

pub const AlgoMap = extern struct {
    mode: MapMode = .none,
    _pad: [3]u8 = @splat(0),
    count: u32 = 0,
    off: u32 = 0,
    large_count: u32 = 0,
    large_off: u32 = 0,
    _reserved: u32 = 0,
};

pub const NeedHeader = extern struct {
    magic: [4]u8 = "NEED".*,
    version: u32 = 2,
    /// Algorithms with at least one any-size signature: those always have to run.
    sizeless_mask: u8 = 0,
    _pad: [3]u8 = @splat(0),
    maps: [3]AlgoMap = @splat(.{}),
    _reserved: [12]u8 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(AlgoMap) == 24);
    std.debug.assert(@sizeOf(NeedHeader) == 96);
}

/// One need-map section per scope.
pub const NeedMap = struct {
    header: *const NeedHeader,
    maps: [3]Map,

    const Map = union(enum) {
        none,
        bitmap: struct { top: *const [top_entries]u32, blocks: []const u8, large: []const u64 },
        list: []const u64,
    };

    pub const Error = error{BadNeedMap};

    pub fn init(bytes: []const u8) Error!NeedMap {
        if (bytes.len < @sizeOf(NeedHeader) or @intFromPtr(bytes.ptr) % 8 != 0) return error.BadNeedMap;
        const header: *const NeedHeader = @ptrCast(@alignCast(bytes.ptr));
        if (!std.mem.eql(u8, &header.magic, "NEED") or header.version != 2) return error.BadNeedMap;
        var maps: [3]Map = undefined;
        for (&maps, header.maps) |*out, m| out.* = switch (m.mode) {
            .none => .none,
            .list => .{ .list = try u64s(bytes, m.off, m.count) },
            .bitmap => blk: {
                const top_bytes = top_entries * 4;
                if (m.off % 8 != 0 or m.off > bytes.len or bytes.len - m.off < top_bytes) return error.BadNeedMap;
                const top: *const [top_entries]u32 = @ptrCast(@alignCast(bytes.ptr + m.off));
                const blocks_at = @as(usize, m.off) + top_bytes;
                const blocks_len = @as(usize, m.count) * block_bytes;
                if (bytes.len - blocks_at < blocks_len) return error.BadNeedMap;
                for (top) |entry| if (entry > m.count) return error.BadNeedMap;
                break :blk .{ .bitmap = .{ .top = top, .blocks = bytes[blocks_at..][0..blocks_len], .large = try u64s(bytes, m.large_off, m.large_count) } };
            },
            _ => return error.BadNeedMap,
        };
        return .{ .header = header, .maps = maps };
    }

    fn u64s(bytes: []const u8, off: u32, count: u32) Error![]const u64 {
        if (count == 0) return &.{};
        if (off % 8 != 0 or off > bytes.len or (bytes.len - off) / 8 < count) return error.BadNeedMap;
        const p: [*]const u64 = @ptrCast(@alignCast(bytes.ptr + off));
        return p[0..count];
    }

    /// Algorithms (need_* bits) to compute for data of this size.
    /// Whether a rule's algorithm is covered by this map. An any-size rule must have its
    /// global bit set; a sized entry at zero cannot stand in for any-size coverage.
    pub fn covers(map: NeedMap, algo: Algo, size: ?u64) bool {
        const bits = if (size) |n| map.mask(n) else map.header.sizeless_mask;
        return bits & needBit(algo) != 0;
    }

    pub fn mask(map: NeedMap, size: u64) u8 {
        var m = map.header.sizeless_mask;
        inline for (0..3) |a| {
            if (map.has(a, size)) m |= @as(u8, 1) << a;
        }
        return m;
    }

    fn has(map: NeedMap, algo: usize, size: u64) bool {
        return switch (map.maps[algo]) {
            .none => false,
            .list => |l| contains(l, size),
            .bitmap => |b| blk: {
                if (size >= dense_limit) break :blk contains(b.large, size);
                const block = b.top[@intCast(size / block_sizes)];
                if (block == 0) break :blk false;
                const bit: usize = @intCast(size % block_sizes);
                break :blk (b.blocks[(block - 1) * block_bytes + bit / 8] >> @intCast(bit % 8)) & 1 != 0;
            },
        };
    }
};

fn contains(sorted: []const u64, size: u64) bool {
    var lo: usize = 0;
    var hi: usize = sorted.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (sorted[mid] < size) lo = mid + 1 else hi = mid;
    }
    return lo < sorted.len and sorted[lo] == size;
}

pub const TableHeader = extern struct {
    magic: [4]u8 = "HASH".*,
    version: u32 = 2,
    algo: u8,
    scope: u8,
    _pad: [2]u8 = @splat(0),
    /// Distinct sizes with signatures.
    size_count: u32,
    /// Entries with an exact size, grouped by size, prefix sorted within each group.
    sized_count: u32,
    /// Entries for any size, prefix sorted.
    sizeless_count: u32,
    /// 0, or `radix_entries` when the size index follows the starts (tables with more than
    /// `list_limit` distinct sizes).
    radix_count: u32 = 0,
    _reserved: [36]u8 = @splat(0),
};

/// Size index: entry i is the first position in `sizes` whose size is at least `i << radix_shift`,
/// for sizes below `dense_limit`, so a size search starts inside a range of at most 256 sizes.
pub const radix_shift = 8;
pub const radix_entries: u32 = (dense_limit >> radix_shift) + 1;

comptime {
    std.debug.assert(@sizeOf(TableHeader) == 64);
}

/// Bytes of the digest held in the hot tier.
pub const key_len = 4;

/// Hot section: header, sizes [size_count]u64, starts [size_count + 1]u32, the size index
/// [radix_count]u32 when present, then (8-aligned) prefix keys [sized_count + sizeless_count]u32
/// (sized first). Cold section: one row per key in the same
/// order, the digest after its first `key_len` bytes followed by a little-endian u32 signature id.
pub const Table = struct {
    header: *const TableHeader,
    algo: Algo,
    sizes: []const u64,
    starts: []const u32,
    radix: []const u32,
    keys: []const u32,
    cold: []const u8,
    row_len: usize,

    pub const Error = error{BadHashTable};

    pub fn rowLen(algo: Algo) usize {
        return algo.digestLen() - key_len + 4;
    }

    pub fn init(hot: []const u8, cold: []const u8) Error!Table {
        if (hot.len < @sizeOf(TableHeader) or @intFromPtr(hot.ptr) % 8 != 0) return error.BadHashTable;
        const h: *const TableHeader = @ptrCast(@alignCast(hot.ptr));
        if (!std.mem.eql(u8, &h.magic, "HASH") or h.version != 2 or h.algo > 2 or h.scope > 2) return error.BadHashTable;
        const algo: Algo = @fromBackingInt(@intCast(h.algo));
        const sizes_at = @sizeOf(TableHeader);
        if (h.radix_count != 0 and h.radix_count != radix_entries) return error.BadHashTable;
        const starts_at = sizes_at + @as(usize, h.size_count) * 8;
        const radix_at = starts_at + (@as(usize, h.size_count) + 1) * 4;
        const keys_at = std.mem.alignForward(usize, radix_at + @as(usize, h.radix_count) * 4, 8);
        const total_keys = @as(usize, h.sized_count) + h.sizeless_count;
        if (hot.len < keys_at or (hot.len - keys_at) / 4 < total_keys) return error.BadHashTable;
        const row_len = rowLen(algo);
        if (cold.len / row_len < total_keys) return error.BadHashTable;

        const sizes: [*]const u64 = @ptrCast(@alignCast(hot.ptr + sizes_at));
        const starts: [*]const u32 = @ptrCast(@alignCast(hot.ptr + starts_at));
        const radix: [*]const u32 = @ptrCast(@alignCast(hot.ptr + radix_at));
        const keys: [*]const u32 = @ptrCast(@alignCast(hot.ptr + keys_at));
        const t: Table = .{
            .header = h,
            .algo = algo,
            .sizes = sizes[0..h.size_count],
            .starts = starts[0 .. h.size_count + 1],
            .radix = radix[0..h.radix_count],
            .keys = keys[0..total_keys],
            .cold = cold[0 .. total_keys * row_len],
            .row_len = row_len,
        };
        // Starts must be monotonic and end at sized_count, or lookups could index out of bounds.
        if (t.starts[0] != 0 or t.starts[h.size_count] != h.sized_count) return error.BadHashTable;
        for (t.starts[1..], t.starts[0..h.size_count]) |next, prev| if (next < prev) return error.BadHashTable;
        if (t.radix.len > 0) {
            if (t.radix[0] != 0) return error.BadHashTable;
            for (t.radix[1..], t.radix[0 .. t.radix.len - 1]) |next, prev| if (next < prev or next > h.size_count) return error.BadHashTable;
        }
        return t;
    }

    /// Signature id for data of `size` with this `digest`, or null.
    pub fn lookup(t: Table, size: u64, digest: []const u8) ?u32 {
        std.debug.assert(digest.len == t.algo.digestLen());
        const key = prefix(digest);
        if (t.findSize(size)) |i| {
            if (t.searchRange(t.starts[i], t.starts[i + 1], key, digest)) |sig| return sig;
        }
        const sized = t.header.sized_count;
        return t.searchRange(sized, sized + t.header.sizeless_count, key, digest);
    }

    fn findSize(t: Table, size: u64) ?usize {
        if (t.radix.len > 0) {
            if (size < dense_limit) {
                const i: usize = @intCast(size >> radix_shift);
                return findSizeIn(t.sizes, t.radix[i], t.radix[i + 1], size);
            }
            return findSizeIn(t.sizes, t.radix[t.radix.len - 1], t.sizes.len, size);
        }
        return findSizeIn(t.sizes, 0, t.sizes.len, size);
    }

    fn searchRange(t: Table, start: u32, end: u32, key: u32, digest: []const u8) ?u32 {
        var lo: usize = start;
        var hi: usize = end;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.keys[mid] < key) lo = mid + 1 else hi = mid;
        }
        // Several digests can share a prefix: confirm each candidate against the rest.
        const tail = digest[key_len..];
        while (lo < end and t.keys[lo] == key) : (lo += 1) {
            const row = t.cold[lo * t.row_len ..][0..t.row_len];
            if (std.mem.eql(u8, row[0..tail.len], tail)) return std.mem.readInt(u32, row[tail.len..][0..4], .little);
        }
        return null;
    }
};

fn findSizeIn(sizes: []const u64, first: usize, last: usize, size: u64) ?usize {
    var lo: usize = first;
    var hi: usize = last;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (sizes[mid] < size) lo = mid + 1 else hi = mid;
    }
    return if (lo < sizes.len and sizes[lo] == size) lo else null;
}

/// The hot-tier key: the first 4 digest bytes as a big-endian integer, so key order is digest order.
pub fn prefix(digest: []const u8) u32 {
    return std.mem.readInt(u32, digest[0..4], .big);
}

// ---------------------------------------------------------------------------------------------
// SIGMETA and NAME_POOL
// ---------------------------------------------------------------------------------------------

/// How a name was split (ir.NameTokens): verbatim, `Family-N` or `Family-N-R`.
pub const NameShape = enum(u2) { verbatim = 0, number = 1, number_revision = 2, _ };

pub const max_families: u32 = 1 << 24;
/// Numbers from here on are stored verbatim (E0: the largest is 10,060,800).
pub const max_number: u32 = 1 << 24;

pub const MetaHeader = extern struct {
    magic: [4]u8 = "META".*,
    version: u32 = 2,
    count: u32,
    family_count: u32,
};

/// One signature, 8 bytes: `a` = family id (bits 0-23), source (24-27), PUA (28), shape (29-30);
/// `b` = number (bits 0-23), revision (24-31).
pub const MetaRecord = extern struct {
    a: u32,
    b: u32,

    pub fn pack(family_id: u32, source_kind: ir.Source, flag_bits: ir.Flags, name_shape: NameShape, num: u32, rev: u8) MetaRecord {
        std.debug.assert(family_id < max_families and num < max_number);
        return .{
            .a = family_id | @as(u32, @backingInt(source_kind)) << 24 | @as(u32, @intFromBool(flag_bits.pua)) << 28 | @as(u32, @backingInt(name_shape)) << 29,
            .b = num | @as(u32, rev) << 24,
        };
    }

    pub fn family(r: MetaRecord) u32 {
        return r.a & 0xff_ffff;
    }
    pub fn source(r: MetaRecord) u8 {
        return @intCast(r.a >> 24 & 0xf);
    }
    pub fn pua(r: MetaRecord) bool {
        return r.a >> 28 & 1 != 0;
    }
    pub fn shape(r: MetaRecord) NameShape {
        return @fromBackingInt(@intCast(@as(u2, @intCast(r.a >> 29 & 3))));
    }
    pub fn number(r: MetaRecord) u32 {
        return r.b & 0xff_ffff;
    }
    pub fn revision(r: MetaRecord) u8 {
        return @intCast(r.b >> 24);
    }
};

comptime {
    std.debug.assert(@sizeOf(MetaHeader) == 16);
    std.debug.assert(@sizeOf(MetaRecord) == 8);
    std.debug.assert(@typeInfo(ir.Source).@"enum".field_names.len <= 16);
}

/// Signature metadata: one 8-byte record per signature id and a table of family offsets into a
/// deduplicated pool; a name is rebuilt only when a detection is reported. Records are checked
/// when they are read, so loading touches only the family table.
pub const SigMeta = struct {
    records: []const MetaRecord,
    /// `family_count + 1` offsets into `pool`, non-decreasing.
    families: []const u32,
    pool: []const u8,

    pub const Error = error{BadSigMeta};

    pub fn init(section: []const u8, pool: []const u8) Error!SigMeta {
        if (section.len < @sizeOf(MetaHeader) or @intFromPtr(section.ptr) % 4 != 0) return error.BadSigMeta;
        const h: *const MetaHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "META") or h.version != 2 or h.family_count > max_families) return error.BadSigMeta;
        const body = section.len - @sizeOf(MetaHeader);
        const records_len = @as(usize, h.count) * @sizeOf(MetaRecord);
        const families_len = (@as(usize, h.family_count) + 1) * 4;
        if (body < records_len or body - records_len < families_len) return error.BadSigMeta;
        const r: [*]const MetaRecord = @ptrCast(@alignCast(section.ptr + @sizeOf(MetaHeader)));
        const f: [*]const u32 = @ptrCast(@alignCast(section.ptr + @sizeOf(MetaHeader) + records_len));
        const meta: SigMeta = .{ .records = r[0..h.count], .families = f[0 .. h.family_count + 1], .pool = pool };
        if (meta.families[0] != 0 or meta.families[h.family_count] > pool.len) return error.BadSigMeta;
        for (meta.families[1..], meta.families[0..h.family_count]) |next, prev| if (next < prev) return error.BadSigMeta;
        return meta;
    }

    pub fn count(meta: SigMeta) usize {
        return meta.records.len;
    }

    pub fn flags(meta: SigMeta, sig: u32) ir.Flags {
        if (sig >= meta.records.len) return .{};
        return .{ .pua = meta.records[sig].pua() };
    }

    /// The signature's full name, written into `out`.
    pub fn name(meta: SigMeta, sig: u32, out: []u8) ![]const u8 {
        if (sig >= meta.records.len) return error.BadSigMeta;
        const rec = meta.records[sig];
        const fam = rec.family();
        if (fam + 1 >= meta.families.len) return error.BadSigMeta;
        const tokens: ir.NameTokens = .{
            .family = meta.pool[meta.families[fam]..meta.families[fam + 1]],
            .number = switch (rec.shape()) {
                .verbatim => null,
                .number, .number_revision => rec.number(),
                _ => return error.BadSigMeta,
            },
            .revision = if (rec.shape() == .number_revision) rec.revision() else null,
        };
        return tokens.format(out);
    }
};
