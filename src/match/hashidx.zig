//! Hash signature lookup over mapped `.zavdb` sections (docs/DESIGN.md section 3.3).
//!
//! The scan path asks two questions per file, both answered from read-only mapped bytes with no
//! allocation:
//! 1. `NeedMap.mask(scope, size)`: which algorithms have any signature for this exact size (or
//!    for any size)? A zero mask means the file is not hashed at all.
//! 2. `Table.lookup(size, digest)`: binary search the sorted sizes, then the 8-byte digest
//!    prefixes inside that size's bucket (the hot tier), and confirm a prefix hit against the full
//!    digest (the cold tier). A prefix collision can never become a detection.
//!
//! Layouts are little-endian and offset based; the builder lives in `compile/hash_build.zig`.
const std = @import("std");
const ir = @import("../compile/ir.zig");

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

/// Sizes below this use the dense two-level map; larger sizes use a sorted list.
pub const dense_limit: u64 = 1 << 24;
/// Sizes covered by one 4 KiB block of 4-bit entries.
pub const block_sizes: u64 = 8192;
pub const top_entries: usize = dense_limit / block_sizes;

pub const NeedHeader = extern struct {
    magic: [4]u8 = "NEED".*,
    version: u32 = 1,
    /// Algorithms with at least one any-size signature: those always have to run.
    sizeless_mask: u8 = 0,
    _pad: [3]u8 = @splat(0),
    block_count: u32 = 0,
    large_count: u32 = 0,
    _reserved: [44]u8 = @splat(0),
};

pub const LargeEntry = extern struct {
    size: u64,
    mask: u8,
    _pad: [7]u8 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(NeedHeader) == 64);
    std.debug.assert(@sizeOf(LargeEntry) == 16);
}

/// Layout of one need-map section: header, top table ([top_entries]u32, block number plus one or
/// zero), blocks (4096 bytes each, two sizes per byte, low nibble first), sorted large entries.
pub const NeedMap = struct {
    header: *const NeedHeader,
    top: *const [top_entries]u32,
    blocks: []const u8,
    large: []const LargeEntry,

    pub const Error = error{BadNeedMap};

    pub fn init(bytes: []const u8) Error!NeedMap {
        if (bytes.len < @sizeOf(NeedHeader) + top_entries * 4) return error.BadNeedMap;
        const header: *const NeedHeader = @ptrCast(@alignCast(bytes.ptr));
        if (!std.mem.eql(u8, &header.magic, "NEED") or header.version != 1) return error.BadNeedMap;
        const blocks_at = @sizeOf(NeedHeader) + top_entries * 4;
        const blocks_len = @as(usize, header.block_count) * 4096;
        const large_at = blocks_at + blocks_len;
        if (bytes.len < large_at + @as(usize, header.large_count) * @sizeOf(LargeEntry)) return error.BadNeedMap;
        const top: *const [top_entries]u32 = @ptrCast(@alignCast(bytes.ptr + @sizeOf(NeedHeader)));
        for (top) |entry| if (entry > header.block_count) return error.BadNeedMap;
        const large: [*]const LargeEntry = @ptrCast(@alignCast(bytes.ptr + large_at));
        return .{
            .header = header,
            .top = top,
            .blocks = bytes[blocks_at..][0..blocks_len],
            .large = large[0..header.large_count],
        };
    }

    /// Algorithms (need_* bits) to compute for data of this size.
    pub fn mask(map: NeedMap, size: u64) u8 {
        return map.header.sizeless_mask | map.sizedMask(size);
    }

    fn sizedMask(map: NeedMap, size: u64) u8 {
        if (size < dense_limit) {
            const block = map.top[@intCast(size / block_sizes)];
            if (block == 0) return 0;
            const in_block = size % block_sizes;
            const byte = map.blocks[(block - 1) * 4096 + @as(usize, @intCast(in_block / 2))];
            return if (in_block % 2 == 0) byte & 0x0f else byte >> 4;
        }
        var lo: usize = 0;
        var hi: usize = map.large.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (map.large[mid].size < size) lo = mid + 1 else hi = mid;
        }
        return if (lo < map.large.len and map.large[lo].size == size) map.large[lo].mask else 0;
    }
};

pub const TableHeader = extern struct {
    magic: [4]u8 = "HASH".*,
    version: u32 = 1,
    algo: u8,
    scope: u8,
    _pad: [2]u8 = @splat(0),
    /// Distinct sizes with signatures.
    size_count: u32,
    /// Entries with an exact size, grouped by size, prefix sorted within each group.
    sized_count: u32,
    /// Entries for any size, prefix sorted.
    sizeless_count: u32,
    _reserved: [40]u8 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(TableHeader) == 64);
}

/// Hot section: header, sizes [size_count]u64, starts [size_count + 1]u32, then prefix keys
/// [sized_count + sizeless_count]u64 (sized first). Cold section: one row per key in the same
/// order, the full digest followed by a little-endian u32 signature id.
pub const Table = struct {
    header: *const TableHeader,
    algo: Algo,
    sizes: []const u64,
    starts: []const u32,
    keys: []const u64,
    cold: []const u8,
    row_len: usize,

    pub const Error = error{BadHashTable};

    pub fn init(hot: []const u8, cold: []const u8) Error!Table {
        if (hot.len < @sizeOf(TableHeader)) return error.BadHashTable;
        const h: *const TableHeader = @ptrCast(@alignCast(hot.ptr));
        if (!std.mem.eql(u8, &h.magic, "HASH") or h.version != 1 or h.algo > 2 or h.scope > 2) return error.BadHashTable;
        const algo: Algo = @fromBackingInt(@intCast(h.algo));
        const sizes_at = @sizeOf(TableHeader);
        const starts_at = sizes_at + @as(usize, h.size_count) * 8;
        const keys_at = std.mem.alignForward(usize, starts_at + (@as(usize, h.size_count) + 1) * 4, 8);
        const total_keys = @as(usize, h.sized_count) + h.sizeless_count;
        if (hot.len < keys_at + total_keys * 8) return error.BadHashTable;
        const row_len = algo.digestLen() + 4;
        if (cold.len < total_keys * row_len) return error.BadHashTable;

        const sizes: [*]const u64 = @ptrCast(@alignCast(hot.ptr + sizes_at));
        const starts: [*]const u32 = @ptrCast(@alignCast(hot.ptr + starts_at));
        const keys: [*]const u64 = @ptrCast(@alignCast(hot.ptr + keys_at));
        const t: Table = .{
            .header = h,
            .algo = algo,
            .sizes = sizes[0..h.size_count],
            .starts = starts[0 .. h.size_count + 1],
            .keys = keys[0..total_keys],
            .cold = cold[0 .. total_keys * row_len],
            .row_len = row_len,
        };
        // Starts must be monotonic and end at sized_count, or lookups could index out of bounds.
        if (t.starts[0] != 0 or t.starts[h.size_count] != h.sized_count) return error.BadHashTable;
        for (t.starts[1..], t.starts[0..h.size_count]) |next, prev| if (next < prev) return error.BadHashTable;
        return t;
    }

    /// Signature id for data of `size` with this `digest`, or null.
    pub fn lookup(t: Table, size: u64, digest: []const u8) ?u32 {
        std.debug.assert(digest.len == t.algo.digestLen());
        const key = prefix(digest);
        if (findSize(t.sizes, size)) |i| {
            if (t.searchRange(t.starts[i], t.starts[i + 1], key, digest)) |sig| return sig;
        }
        const sized = t.header.sized_count;
        return t.searchRange(sized, sized + t.header.sizeless_count, key, digest);
    }

    fn searchRange(t: Table, start: u32, end: u32, key: u64, digest: []const u8) ?u32 {
        var lo: usize = start;
        var hi: usize = end;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.keys[mid] < key) lo = mid + 1 else hi = mid;
        }
        // Several digests can share a prefix: confirm each candidate against the full digest.
        while (lo < end and t.keys[lo] == key) : (lo += 1) {
            const row = t.cold[lo * t.row_len ..][0..t.row_len];
            if (std.mem.eql(u8, row[0..digest.len], digest)) return std.mem.readInt(u32, row[digest.len..][0..4], .little);
        }
        return null;
    }
};

fn findSize(sizes: []const u64, size: u64) ?usize {
    var lo: usize = 0;
    var hi: usize = sizes.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (sizes[mid] < size) lo = mid + 1 else hi = mid;
    }
    return if (lo < sizes.len and sizes[lo] == size) lo else null;
}

/// The hot-tier key: the first 8 digest bytes as a big-endian integer, so key order is digest order.
pub fn prefix(digest: []const u8) u64 {
    return std.mem.readInt(u64, digest[0..8], .big);
}

pub const MetaRecord = extern struct {
    family_offset: u32,
    family_len: u16,
    flags: u8,
    source: u8,
    /// 0xffffffff when the name has no number.
    number: u32,
    revision: u8,
    _pad: [3]u8 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(MetaRecord) == 16);
}

pub const no_number: u32 = 0xffff_ffff;

/// Signature metadata: one 16-byte record per signature id, names rebuilt from a deduplicated pool
/// only when a detection is reported.
pub const SigMeta = struct {
    records: []const MetaRecord,
    pool: []const u8,

    pub const Error = error{BadSigMeta};

    pub fn init(records: []const u8, pool: []const u8) Error!SigMeta {
        if (records.len % @sizeOf(MetaRecord) != 0) return error.BadSigMeta;
        const r: [*]const MetaRecord = @ptrCast(@alignCast(records.ptr));
        const meta: SigMeta = .{ .records = r[0 .. records.len / @sizeOf(MetaRecord)], .pool = pool };
        for (meta.records) |rec| if (@as(usize, rec.family_offset) + rec.family_len > pool.len) return error.BadSigMeta;
        return meta;
    }

    pub fn flags(meta: SigMeta, sig: u32) ir.Flags {
        return @bitCast(meta.records[sig].flags);
    }

    /// The signature's full name, written into `out`.
    pub fn name(meta: SigMeta, sig: u32, out: []u8) ![]const u8 {
        const rec = meta.records[sig];
        const tokens: ir.NameTokens = .{
            .family = meta.pool[rec.family_offset..][0..rec.family_len],
            .number = if (rec.number == no_number) null else rec.number,
            .revision = if (rec.number == no_number) null else rec.revision,
        };
        return tokens.format(out);
    }
};
