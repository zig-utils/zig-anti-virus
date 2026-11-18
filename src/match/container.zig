//! CDB_TABLE: container metadata signatures, checked once per container member (docs/DESIGN.md
//! section 4.3). The container parsers call `check` for every member they iterate.
//!
//! Layout: a 32-byte header, then [count]CdbRecord (72 bytes). Ranges are inclusive; a field
//! whose flag bit is clear is `*`. A filename regex is a program in REGEX_POOL, searched anywhere
//! in the member's name with the worker's zig-regex scratch.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const types = @import("../fmt/types.zig");
const regex = @import("regex");
const regex_pool = @import("regex_pool.zig");

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
pub const has_regex: u16 = 1 << 8;
pub const known_flags: u16 = (1 << 9) - 1;

pub const CdbRecord = extern struct {
    sig: u32,
    flags: u16,
    container: u16,
    crc: u32,
    /// REGEX_POOL index of the filename regex (with `has_regex`).
    regex: u32 = 0,
    container_size: [2]u64,
    size_in_container: [2]u64,
    size_real: [2]u64,
    /// The position is 1-based; u32 ranges are plenty.
    file_pos: [2]u32,

    pub fn from(sig: u32, r: ir.CdbRule, regex_index: ?u32) CdbRecord {
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
        if (regex_index) |i| {
            rec.flags |= has_regex;
            rec.regex = i;
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
    /// Null when the container arrives as a stream of unknown length.
    container_size: ?u64,
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
    regexes: ?regex_pool.RegexPool = null,

    pub const Error = error{BadCdbTable};

    pub fn init(section: []const u8, regexes: ?regex_pool.RegexPool) Error!CdbTable {
        if (section.len < @sizeOf(CdbHeader) or @intFromPtr(section.ptr) % 8 != 0) return error.BadCdbTable;
        const h: *const CdbHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "CDBT") or h.version != 1) return error.BadCdbTable;
        if (@as(usize, h.count) * @sizeOf(CdbRecord) > section.len - @sizeOf(CdbHeader)) return error.BadCdbTable;
        const r: [*]const CdbRecord = @ptrCast(@alignCast(section.ptr + @sizeOf(CdbHeader)));
        const t: CdbTable = .{ .records = r[0..h.count], .regexes = regexes };
        const nregex = if (regexes) |p| p.count() else 0;
        for (t.records) |rec| {
            if (rec.flags & ~known_flags != 0) return error.BadCdbTable;
            if (rec.flags & has_regex != 0 and rec.regex >= nregex) return error.BadCdbTable;
            if (rec.container_size[0] > rec.container_size[1] or rec.size_in_container[0] > rec.size_in_container[1] or rec.size_real[0] > rec.size_real[1] or rec.file_pos[0] > rec.file_pos[1]) return error.BadCdbTable;
        }
        return t;
    }

    /// The first signature matching this member, or null. Called once per member. `scratch`
    /// must fit `regexes.capacity` when any record has a filename regex. A record that cannot
    /// be decided is reported, never taken as no match: `error.RegexBudget` when a regex search
    /// ran out of steps (or there is no scratch), `error.UnknownContainerSize` when a record
    /// constrains the container size and the container is a stream of unknown length.
    pub fn check(t: CdbTable, m: Member, scratch: ?*regex_pool.Scratch) error{ RegexBudget, UnknownContainerSize }!?u32 {
        var limited = false;
        var unknown_size = false;
        for (t.records) |rec| {
            if (rec.flags & has_container_size != 0 and m.container_size == null) {
                var known = rec;
                known.flags &= ~has_container_size;
                if (matches(known, m)) unknown_size = true;
                continue;
            }
            if (!matches(rec, m)) continue;
            if (rec.flags & has_regex != 0) {
                const s = scratch orelse {
                    limited = true;
                    continue;
                };
                const program = t.regexes.?.get(rec.regex);
                const hit = program.isMatch(s, m.name) catch {
                    limited = true;
                    continue;
                };
                if (!hit) continue;
            }
            return rec.sig;
        }
        if (limited) return error.RegexBudget;
        if (unknown_size) return error.UnknownContainerSize;
        return null;
    }
};

fn within(r: [2]u64, v: u64) bool {
    return v >= r[0] and v <= r[1];
}

pub fn matches(rec: CdbRecord, m: Member) bool {
    const f = rec.flags;
    if (f & has_container != 0 and rec.container != @backingInt(m.container_type)) return false;
    if (f & has_container_size != 0) {
        const size = m.container_size orelse return false;
        if (!within(rec.container_size, size)) return false;
    }
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

/// `regex_indices[i]` is rule i's REGEX_POOL program, if it has a filename regex.
pub fn build(gpa: std.mem.Allocator, rules: []const ir.CdbRule, sigs: []const u32, regex_indices: []const ?u32) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const h: CdbHeader = .{ .count = @intCast(rules.len) };
    try out.appendSlice(gpa, std.mem.asBytes(&h));
    for (rules, sigs, regex_indices) |r, sig, ri| {
        const rec = CdbRecord.from(sig, r, ri);
        try out.appendSlice(gpa, std.mem.asBytes(&rec));
    }
    return out.toOwnedSlice(gpa);
}

const testing = std.testing;
const cdb = @import("../compile/cdb.zig");

test "member checks: every field, wildcards, the ZIP/RAR CRC rule and filename regexes" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var column: u32 = 0;
    const rules = [_]ir.CdbRule{
        try cdb.parseLine(arena, "Zip.A-1-0:CL_TYPE_ZIP:100-200:*:50:*:1:2-4:8a4f1c2e:*", &column),
        try cdb.parseLine(arena, "Any.B-2-0:*:*:*:*:1000:0:*:*:*", &column),
        try cdb.parseLine(arena, "Tar.C-3-0:CL_TYPE_POSIX_TAR:*:*:*:*:*:1:abcdef:*", &column),
        try cdb.parseLine(arena, "Rar.D-4-0:CL_TYPE_RAR:*:\\.(scr|pif)$:*:*:*:*:*:*", &column),
    };
    const pool_bytes = try regex_pool.build(gpa, &.{rules[3].filename_program.?});
    defer gpa.free(pool_bytes);
    const pool_image = try gpa.alignedAlloc(u8, .@"8", pool_bytes.len);
    defer gpa.free(pool_image);
    @memcpy(pool_image, pool_bytes);
    const pool = try regex_pool.RegexPool.init(pool_image);
    const bytes = try build(gpa, &rules, &.{ 10, 11, 12, 13 }, &.{ null, null, null, 0 });
    defer gpa.free(bytes);
    const image = try gpa.alignedAlloc(u8, .@"8", bytes.len);
    defer gpa.free(image);
    @memcpy(image, bytes);
    const t = try CdbTable.init(image, pool);
    const mem = try gpa.alignedAlloc(u8, .@"8", pool.scratchBytes(64));
    defer gpa.free(mem);
    var scratch = try regex_pool.Scratch.initBuffer(mem, pool, 64);

    const zip: Member = .{ .container_type = .zip, .container_size = 150, .name = "a.exe", .size_in_container = 50, .size_real = 70, .encrypted = true, .position = 3, .crc = 0x8a4f1c2e };
    try std.testing.expectEqual(@as(?u32, 10), try t.check(zip, &scratch));
    var m = zip;
    m.crc = 0x1234;
    try std.testing.expectEqual(@as(?u32, null), try t.check(m, &scratch));
    m = zip;
    m.position = 5;
    try std.testing.expectEqual(@as(?u32, null), try t.check(m, &scratch));
    m = zip;
    m.encrypted = false;
    try std.testing.expectEqual(@as(?u32, null), try t.check(m, &scratch));
    m = zip;
    m.container_size = 201;
    try std.testing.expectEqual(@as(?u32, null), try t.check(m, &scratch));
    // Any container, real size 1000, not encrypted.
    const rar: Member = .{ .container_type = .rar, .container_size = 5, .name = "x", .size_in_container = 400, .size_real = 1000, .encrypted = false, .position = 9 };
    try std.testing.expectEqual(@as(?u32, 11), try t.check(rar, &scratch));
    // The CRC field is ignored for tar.
    try std.testing.expectEqual(@as(?u32, 12), try t.check(.{ .container_type = .posix_tar, .container_size = 5, .name = "x", .size_in_container = 1, .size_real = 1, .encrypted = false, .position = 1 }, &scratch));
    // Filename regex: searched in the member name.
    m = rar;
    m.size_real = 5;
    m.name = "photos/holiday.scr";
    try std.testing.expectEqual(@as(?u32, 13), try t.check(m, &scratch));
    m.name = "photos/holiday.scr.txt";
    try std.testing.expectEqual(@as(?u32, null), try t.check(m, &scratch));
    // Without a scratch a regex record cannot be decided: a limit, not a miss.
    m.name = "x.pif";
    try std.testing.expectError(error.RegexBudget, t.check(m, null));
    // A regex search that runs out of steps is a limit too.
    scratch.linear.step_budget = 1;
    try std.testing.expectError(error.RegexBudget, t.check(m, &scratch));
    scratch.linear.step_budget = null;

    // A container size the record needs but a stream does not tell: undecided, reported.
    m = zip;
    m.container_size = null;
    try std.testing.expectError(error.UnknownContainerSize, t.check(m, &scratch));

    // A corrupted table is refused or still only ever reads its own records.
    for (0..image.len) |i| {
        @memcpy(image, bytes);
        image[i] ^= 0xa5;
        if (CdbTable.init(image, pool)) |bad| _ = bad.check(zip, &scratch) catch {} else |_| {}
    }
}
