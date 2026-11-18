//! CDB_TABLE: container metadata signatures, checked once per container member (docs/DESIGN.md
//! section 4.3). The container parsers call `check` for every member they iterate.
//!
//! Layout: a 32-byte header, then [count]CdbRecord (72 bytes). Ranges are inclusive; a field
//! whose flag bit is clear is `*`. Filename regexes need zig-regex; this format version has no
//! regex field, so a compiled database cannot carry one it could not evaluate.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const types = @import("../fmt/types.zig");

pub const CdbHeader = extern struct {
    magic: [4]u8 = "CDBT".*,
    version: u32 = 1,
    count: u32,
    _reserved: [20]u8 = @splat(0),
};

pub const has_container: u16 = 1 << 0;
pub const has_container_size: u16 = 1 << 1;
pub const has_size_in_container: u16 = 1 << 2;
pub const has_size_real: u16 = 1 << 3;
pub const has_encrypted: u16 = 1 << 4;
pub const encrypted_value: u16 = 1 << 5;
pub const has_file_pos: u16 = 1 << 6;
pub const has_crc: u16 = 1 << 7;
pub const known_flags: u16 = (1 << 8) - 1;

pub const CdbRecord = extern struct {
    sig: u32,
    flags: u16,
    container: u16,
    crc: u32,
    _pad: u32 = 0,
    container_size: [2]u64,
    size_in_container: [2]u64,
    size_real: [2]u64,
    /// The position is 1-based; u32 ranges are plenty.
    file_pos: [2]u32,

    pub fn from(sig: u32, r: ir.CdbRule) CdbRecord {
        var rec: CdbRecord = .{ .sig = sig, .flags = 0, .container = 0, .crc = 0, .container_size = .{ 0, 0 }, .size_in_container = .{ 0, 0 }, .size_real = .{ 0, 0 }, .file_pos = .{ 0, 0 } };
        if (r.container) |c| {
            rec.flags |= has_container;
            rec.container = c;
        }
        if (r.container_size) |x| {
            rec.flags |= has_container_size;
            rec.container_size = .{ x.lo, x.hi };
        }
        if (r.size_in_container) |x| {
            rec.flags |= has_size_in_container;
            rec.size_in_container = .{ x.lo, x.hi };
        }
        if (r.size_real) |x| {
            rec.flags |= has_size_real;
            rec.size_real = .{ x.lo, x.hi };
        }
        if (r.encrypted) |e| {
            rec.flags |= has_encrypted;
            if (e) rec.flags |= encrypted_value;
        }
        if (r.file_pos) |x| {
            rec.flags |= has_file_pos;
            rec.file_pos = .{ @intCast(@min(x.lo, std.math.maxInt(u32))), @intCast(@min(x.hi, std.math.maxInt(u32))) };
        }
        if (r.crc) |c| {
            rec.flags |= has_crc;
            rec.crc = c;
        }
        return rec;
    }
};

comptime {
    std.debug.assert(@sizeOf(CdbHeader) == 32);
    std.debug.assert(@sizeOf(CdbRecord) == 72);
}

/// What the container layer knows about one member.
pub const Member = struct {
    container_type: types.ClType,
    container_size: u64,
    name: []const u8,
    /// Stored (usually compressed) size; equal to `size_real` for mail, tar and cpio.
    size_in_container: u64,
    size_real: u64,
    encrypted: bool,
    /// 1-based position in the container.
    position: u32,
    /// The member's CRC, for containers that carry one (ZIP, RAR).
    crc: ?u32 = null,
};

pub const CdbTable = struct {
    records: []const CdbRecord,

    pub const Error = error{BadCdbTable};

    pub fn init(section: []const u8) Error!CdbTable {
        if (section.len < @sizeOf(CdbHeader) or @intFromPtr(section.ptr) % 8 != 0) return error.BadCdbTable;
        const h: *const CdbHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "CDBT") or h.version != 1) return error.BadCdbTable;
        if (@as(usize, h.count) * @sizeOf(CdbRecord) > section.len - @sizeOf(CdbHeader)) return error.BadCdbTable;
        const r: [*]const CdbRecord = @ptrCast(@alignCast(section.ptr + @sizeOf(CdbHeader)));
        const t: CdbTable = .{ .records = r[0..h.count] };
        for (t.records) |rec| {
            if (rec.flags & ~known_flags != 0) return error.BadCdbTable;
            if (rec.container_size[0] > rec.container_size[1] or rec.size_in_container[0] > rec.size_in_container[1] or rec.size_real[0] > rec.size_real[1] or rec.file_pos[0] > rec.file_pos[1]) return error.BadCdbTable;
        }
        return t;
    }

    /// The first signature matching this member, or null. Called once per member.
    pub fn check(t: CdbTable, m: Member) ?u32 {
        for (t.records) |rec| if (matches(rec, m)) return rec.sig;
        return null;
    }
};

fn within(r: [2]u64, v: u64) bool {
    return v >= r[0] and v <= r[1];
}

pub fn matches(rec: CdbRecord, m: Member) bool {
    const f = rec.flags;
    if (f & has_container != 0 and rec.container != @backingInt(m.container_type)) return false;
    if (f & has_container_size != 0 and !within(rec.container_size, m.container_size)) return false;
    if (f & has_size_in_container != 0 and !within(rec.size_in_container, m.size_in_container)) return false;
    if (f & has_size_real != 0 and !within(rec.size_real, m.size_real)) return false;
    if (f & has_encrypted != 0 and m.encrypted != (f & encrypted_value != 0)) return false;
    if (f & has_file_pos != 0 and (m.position < rec.file_pos[0] or m.position > rec.file_pos[1])) return false;
    // Res1 is a CRC for ZIP and RAR and ignored for other containers.
    if (f & has_crc != 0 and (m.container_type == .zip or m.container_type == .rar)) {
        const crc = m.crc orelse return false;
        if (crc != rec.crc) return false;
    }
    return true;
}

pub fn build(gpa: std.mem.Allocator, rules: []const ir.CdbRule, sigs: []const u32) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const h: CdbHeader = .{ .count = @intCast(rules.len) };
    try out.appendSlice(gpa, std.mem.asBytes(&h));
    for (rules, sigs) |r, sig| {
        const rec = CdbRecord.from(sig, r);
        try out.appendSlice(gpa, std.mem.asBytes(&rec));
    }
    return out.toOwnedSlice(gpa);
}

const testing = std.testing;
const cdb = @import("../compile/cdb.zig");

test "member checks: every field, wildcards and the ZIP/RAR CRC rule" {
    var column: u32 = 0;
    const rules = [_]ir.CdbRule{
        try cdb.parseLine("Zip.A-1-0:CL_TYPE_ZIP:100-200:*:50:*:1:2-4:8a4f1c2e:*", &column),
        try cdb.parseLine("Any.B-2-0:*:*:*:*:1000:0:*:*:*", &column),
        try cdb.parseLine("Tar.C-3-0:CL_TYPE_POSIX_TAR:*:*:*:*:*:1:abcdef:*", &column),
    };
    const bytes = try build(testing.allocator, &rules, &.{ 10, 11, 12 });
    defer testing.allocator.free(bytes);
    const image = try testing.allocator.alignedAlloc(u8, .@"8", bytes.len);
    defer testing.allocator.free(image);
    @memcpy(image, bytes);
    const t = try CdbTable.init(image);

    const zip: Member = .{ .container_type = .zip, .container_size = 150, .name = "a.exe", .size_in_container = 50, .size_real = 70, .encrypted = true, .position = 3, .crc = 0x8a4f1c2e };
    try testing.expectEqual(@as(?u32, 10), t.check(zip));
    var m = zip;
    m.crc = 0x1234;
    try testing.expectEqual(@as(?u32, null), t.check(m));
    m = zip;
    m.position = 5;
    try testing.expectEqual(@as(?u32, null), t.check(m));
    m = zip;
    m.encrypted = false;
    try testing.expectEqual(@as(?u32, null), t.check(m));
    m = zip;
    m.container_size = 201;
    try testing.expectEqual(@as(?u32, null), t.check(m));
    // Any container, real size 1000, not encrypted.
    try testing.expectEqual(@as(?u32, 11), t.check(.{ .container_type = .rar, .container_size = 5, .name = "x", .size_in_container = 400, .size_real = 1000, .encrypted = false, .position = 9 }));
    // The CRC field is ignored for tar.
    try testing.expectEqual(@as(?u32, 12), t.check(.{ .container_type = .posix_tar, .container_size = 5, .name = "x", .size_in_container = 1, .size_real = 1, .encrypted = false, .position = 1 }));

    // A corrupted table is refused or still only ever reads its own records.
    for (0..image.len) |i| {
        @memcpy(image, bytes);
        image[i] ^= 0xa5;
        if (CdbTable.init(image)) |bad| _ = bad.check(zip) else |_| {}
    }
}
