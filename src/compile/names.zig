//! Signature names, interned while parsing: one id per distinct (PUA flag, name), the first source
//! that used it, and the name split into family, number and revision (`ir.NameTokens`). The table
//! is the SIGMETA and NAME_POOL sections under construction (layout in match/hashidx.zig), so no
//! name text is kept anywhere else during a compile.
//!
//! Both indexes are hash sets of 4-byte ids whose hashing and equality look into the records and
//! the pool, so 3.6 million signatures cost about 8 bytes of record plus about 5 bytes of index
//! each, and families (E0: 308,730 for 3.6 million names) are stored once.
const std = @import("std");
const ir = @import("ir.zig");
const hashidx = @import("../match/hashidx.zig");

const MetaRecord = hashidx.MetaRecord;

pub const Error = error{TooManyFamilies} || std.mem.Allocator.Error;

pub const NameTable = struct {
    gpa: std.mem.Allocator,
    records: std.ArrayList(MetaRecord) = .empty,
    /// Start of each family in `pool`.
    family_starts: std.ArrayList(u32) = .empty,
    pool: std.ArrayList(u8) = .empty,
    families: std.HashMapUnmanaged(u32, void, FamilyContext, 80) = .empty,
    sigs: std.HashMapUnmanaged(u32, void, SigContext, 80) = .empty,

    pub fn init(gpa: std.mem.Allocator) NameTable {
        return .{ .gpa = gpa };
    }

    pub fn deinit(t: *NameTable) void {
        t.records.deinit(t.gpa);
        t.family_starts.deinit(t.gpa);
        t.pool.deinit(t.gpa);
        t.families.deinit(t.gpa);
        t.sigs.deinit(t.gpa);
        t.* = undefined;
    }

    pub fn count(t: *const NameTable) u32 {
        return @intCast(t.records.items.len);
    }

    fn family(t: *const NameTable, id: u32) []const u8 {
        const start = t.family_starts.items[id];
        const end = if (id + 1 < t.family_starts.items.len) t.family_starts.items[id + 1] else t.pool.items.len;
        return t.pool.items[start..end];
    }

    /// The signature id for `name`, adding it the first time it is seen.
    pub fn intern(t: *NameTable, name: []const u8, flags: ir.Flags, source: ir.Source) Error!u32 {
        var tokens = ir.NameTokens.parse(name);
        // Numbers that do not fit the record are kept in the family text.
        if (tokens.number) |n| if (n >= hashidx.max_number) {
            tokens = .{ .family = name };
        };
        const fam = try t.internFamily(tokens.family);
        const key: Key = .{
            .family = fam,
            .number = tokens.number orelse 0,
            .revision = tokens.revision orelse 0,
            .shape = if (tokens.number == null) .verbatim else if (tokens.revision == null) .number else .number_revision,
            .pua = flags.pua,
        };
        const gop = try t.sigs.getOrPutContextAdapted(t.gpa, key, KeyAdapter{ .table = t }, .{ .table = t });
        if (gop.found_existing) return gop.key_ptr.*;
        const id: u32 = @intCast(t.records.items.len);
        t.records.append(t.gpa, MetaRecord.pack(fam, source, flags, key.shape, key.number, key.revision)) catch |err| {
            t.sigs.removeByPtr(gop.key_ptr);
            return err;
        };
        gop.key_ptr.* = id;
        return id;
    }

    fn internFamily(t: *NameTable, text: []const u8) Error!u32 {
        const gop = try t.families.getOrPutContextAdapted(t.gpa, text, FamilyAdapter{ .table = t }, .{ .table = t });
        if (gop.found_existing) return gop.key_ptr.*;
        const id: u32 = @intCast(t.family_starts.items.len);
        if (id >= hashidx.max_families or t.pool.items.len + text.len > std.math.maxInt(u32)) {
            t.families.removeByPtr(gop.key_ptr);
            return error.TooManyFamilies;
        }
        try t.family_starts.append(t.gpa, @intCast(t.pool.items.len));
        try t.pool.appendSlice(t.gpa, text);
        gop.key_ptr.* = id;
        return id;
    }

    /// The SIGMETA section (header, records, family offsets); `out` is allocated with `gpa`.
    pub fn sigmeta(t: *const NameTable, gpa: std.mem.Allocator) ![]align(8) u8 {
        const header: hashidx.MetaHeader = .{ .count = t.count(), .family_count = @intCast(t.family_starts.items.len) };
        const records = std.mem.sliceAsBytes(t.records.items);
        const fams = std.mem.sliceAsBytes(t.family_starts.items);
        const out = try gpa.alignedAlloc(u8, .@"8", @sizeOf(hashidx.MetaHeader) + records.len + fams.len + 4);
        var at: usize = 0;
        for ([_][]const u8{ std.mem.asBytes(&header), records, fams }) |part| {
            @memcpy(out[at..][0..part.len], part);
            at += part.len;
        }
        std.mem.writeInt(u32, out[at..][0..4], @intCast(t.pool.items.len), .little);
        return out;
    }

    /// The NAME_POOL section, valid until the table changes.
    pub fn namePool(t: *const NameTable) []const u8 {
        return t.pool.items;
    }

    const Key = struct {
        family: u32,
        number: u32,
        revision: u8,
        shape: hashidx.NameShape,
        pua: bool,

        fn hash(k: Key) u64 {
            const packed_key = @as(u64, k.family) | @as(u64, k.number) << 24 | @as(u64, k.revision) << 48 |
                @as(u64, @backingInt(k.shape)) << 56 | @as(u64, @intFromBool(k.pua)) << 58;
            return std.hash.int(packed_key);
        }

        fn of(r: MetaRecord) Key {
            return .{ .family = r.family(), .number = r.number(), .revision = r.revision(), .shape = r.shape(), .pua = r.pua() };
        }
    };

    const SigContext = struct {
        table: *const NameTable,
        pub fn hash(c: SigContext, id: u32) u64 {
            return Key.of(c.table.records.items[id]).hash();
        }
        pub fn eql(_: SigContext, a: u32, b: u32) bool {
            return a == b;
        }
    };

    const KeyAdapter = struct {
        table: *const NameTable,
        pub fn hash(_: KeyAdapter, k: Key) u64 {
            return k.hash();
        }
        pub fn eql(c: KeyAdapter, k: Key, id: u32) bool {
            return std.meta.eql(k, Key.of(c.table.records.items[id]));
        }
    };

    const FamilyContext = struct {
        table: *const NameTable,
        pub fn hash(c: FamilyContext, id: u32) u64 {
            return std.hash.Wyhash.hash(0, c.table.family(id));
        }
        pub fn eql(_: FamilyContext, a: u32, b: u32) bool {
            return a == b;
        }
    };

    const FamilyAdapter = struct {
        table: *const NameTable,
        pub fn hash(_: FamilyAdapter, text: []const u8) u64 {
            return std.hash.Wyhash.hash(0, text);
        }
        pub fn eql(c: FamilyAdapter, text: []const u8, id: u32) bool {
            return std.mem.eql(u8, text, c.table.family(id));
        }
    };
};

test "interning dedupes names, keeps PUA apart and rebuilds every name" {
    const gpa = std.testing.allocator;
    var t = NameTable.init(gpa);
    defer t.deinit();
    const names = [_][]const u8{ "Win.Trojan.Agent-1234567-0", "Win.Trojan.Agent-1234568-0", "Win.Trojan.VB-1770", "Eicar-Test-Signature", "Win.X-01", "Big.Number-99999999-1", "Win.Trojan.VB-1770-0" };
    var ids: [names.len]u32 = undefined;
    for (names, &ids) |n, *id| id.* = try t.intern(n, .{}, .hdb);
    for (names, ids) |n, id| try std.testing.expectEqual(id, try t.intern(n, .{}, .ndb));
    const pua = try t.intern(names[0], .{ .pua = true }, .hdb);
    try std.testing.expect(pua != ids[0]);
    try std.testing.expectEqual(@as(u32, names.len + 1), t.count());
    // Two names of one family share the family text.
    try std.testing.expectEqual(t.records.items[ids[0]].family(), t.records.items[ids[1]].family());

    const section = try t.sigmeta(gpa);
    defer gpa.free(section);
    const meta = try hashidx.SigMeta.init(section, t.namePool());
    var buf: [128]u8 = undefined;
    for (names, ids) |n, id| try std.testing.expectEqualStrings(n, try meta.name(id, &buf));
    try std.testing.expect(meta.flags(pua).pua);
    try std.testing.expect(!meta.flags(ids[0]).pua);
    try std.testing.expectError(error.BadSigMeta, meta.name(1000, &buf));
}

test "corrupt metadata is refused or rejected on read" {
    const gpa = std.testing.allocator;
    var t = NameTable.init(gpa);
    defer t.deinit();
    _ = try t.intern("Win.Trojan.Agent-1-0", .{}, .hdb);
    const section = try t.sigmeta(gpa);
    defer gpa.free(section);
    var prng = std.Random.DefaultPrng.init(5);
    var buf: [128]u8 = undefined;
    for (0..2000) |_| {
        const copy = try gpa.alignedAlloc(u8, .@"8", section.len);
        defer gpa.free(copy);
        @memcpy(copy, section);
        copy[prng.random().uintLessThan(usize, copy.len)] = prng.random().int(u8);
        if (hashidx.SigMeta.init(copy, t.namePool())) |meta| {
            for (0..meta.count()) |i| _ = meta.name(@intCast(i), &buf) catch {};
        } else |_| {}
    }
}
