//! `.ftm` file-type magic, from ClamAV's FileTypeMagic documentation:
//!
//!     magictype:offset:magicbytes:name:rtype:type[:min_flevel[:max_flevel]]
//!
//! Magictype 0 compares literal bytes at a fixed offset, 4 does the same for partition types,
//! and 1 matches a body-format pattern at a fixed offset or, with `*`, anywhere (an embedded-type
//! trigger). `rtype` is the type that must already have been detected (`CL_TYPE_ANY` for none).
//! `min_flevel` may be empty when `max_flevel` follows. Every rejected line is recorded with a
//! reason.
const std = @import("std");
const ir = @import("ir.zig");
const hexsig = @import("hexsig.zig");
const ndb = @import("ndb.zig");
const types = @import("../fmt/types.zig");

pub const LineError = error{ FieldCount, EmptyName, BadMagicType, BadOffset, BadMagic, UnknownFileType, BadFlevel } || hexsig.Error;

pub fn reasonOf(err: LineError) ir.Reason {
    return switch (err) {
        error.FieldCount => .field_count,
        error.EmptyName => .empty_name,
        error.BadMagicType => .bad_magic_type,
        error.BadOffset => .bad_offset,
        error.BadMagic => .bad_magic,
        error.UnknownFileType => .unknown_file_type,
        error.BadFlevel => .bad_flevel,
        else => |e| hexsig.reasonOf(@errorCast(e)),
    };
}

pub const Output = struct {
    rules: *std.ArrayList(ir.FtmRule),
    rejected: *std.ArrayList(ir.Rejection),
};

pub fn parse(gpa: std.mem.Allocator, arena: std.mem.Allocator, source_name: []const u8, text: []const u8, out: Output) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_number: u32 = 0;
    while (lines.next()) |raw| {
        line_number += 1;
        const line = std.mem.trimEnd(u8, raw, "\r \t");
        if (line.len == 0 or line[0] == '#') continue;
        var column: u32 = 0;
        if (parseLine(arena, line, &column)) |rule| {
            try out.rules.append(gpa, rule);
        } else |err| {
            try out.rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = reasonOf(err), .column = column });
        }
    }
}

fn clType(text: []const u8) error{UnknownFileType}!u16 {
    return @backingInt(types.ClType.parse(text) orelse return error.UnknownFileType);
}

pub fn parseLine(arena: std.mem.Allocator, line: []const u8, column: *u32) LineError!ir.FtmRule {
    var fields: [8][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, line, ':');
    while (it.next()) |f| {
        if (count == fields.len) return error.FieldCount;
        fields[count] = f;
        count += 1;
    }
    if (count < 6) return error.FieldCount;
    const col = struct {
        fn of(l: []const u8, f: []const u8) u32 {
            return @intCast(@intFromPtr(f.ptr) - @intFromPtr(l.ptr));
        }
    }.of;

    const kind: ir.MagicKind = blk: {
        const k = std.fmt.parseInt(u8, fields[0], 10) catch return error.BadMagicType;
        break :blk switch (k) {
            0 => .bytes,
            1 => .body,
            4 => .partition,
            else => return error.BadMagicType,
        };
    };
    column.* = col(line, fields[1]);
    // Literal magics sit at a fixed offset; body magics also take `n,maxshift` and `EOF-n`.
    var body_offset: ir.Offset = .{};
    const offset: ?u32 = if (kind == .body) blk: {
        body_offset = ndb.parseOffset(fields[1]) catch return error.BadOffset;
        break :blk switch (body_offset.kind) {
            .any => null,
            .absolute, .eof_minus => @intCast(body_offset.a),
            else => return error.BadOffset,
        };
    } else std.fmt.parseInt(u32, fields[1], 10) catch return error.BadOffset;

    if (fields[3].len == 0) {
        column.* = col(line, fields[3]);
        return error.EmptyName;
    }
    column.* = col(line, fields[4]);
    const rtype = try clType(fields[4]);
    column.* = col(line, fields[5]);
    const ty = try clType(fields[5]);

    var flevel_min: u16 = 0;
    var flevel_max: u16 = 0;
    if (count >= 7) {
        column.* = col(line, fields[6]);
        // The minimum may be empty when a maximum follows.
        if (fields[6].len > 0) flevel_min = std.fmt.parseInt(u16, fields[6], 10) catch return error.BadFlevel else if (count == 7) return error.BadFlevel;
    }
    if (count == 8) {
        column.* = col(line, fields[7]);
        flevel_max = std.fmt.parseInt(u16, fields[7], 10) catch return error.BadFlevel;
        if (flevel_max < flevel_min) return error.BadFlevel;
    }

    column.* = col(line, fields[2]);
    var rule: ir.FtmRule = .{ .kind = kind, .offset = offset, .body_offset = body_offset, .name = fields[3], .rtype = rtype, .type = ty, .flevel_min = flevel_min, .flevel_max = flevel_max, .line = line };
    var diag: hexsig.Diag = .{};
    const pattern = hexsig.parse(arena, fields[2], &diag) catch |err| {
        column.* += diag.pos;
        return err;
    };
    if (kind == .body) {
        rule.pattern = pattern;
    } else {
        // Direct comparisons take plain bytes only.
        if (pattern.ops.len != 1 or pattern.ops[0].code != .lit) return error.BadMagic;
        rule.magic = pattern.bytes(pattern.ops[0]);
    }
    column.* = 0;
    return rule;
}

const testing = std.testing;

test "ftm lines: every magic type, offsets, flevels, and rejections" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var column: u32 = 0;
    const pe = try parseLine(a, "0:0:4d5a:DOS/W32 executable:CL_TYPE_ANY:CL_TYPE_MSEXE", &column);
    try testing.expectEqual(ir.MagicKind.bytes, pe.kind);
    try testing.expectEqualSlices(u8, "MZ", pe.magic);
    try testing.expectEqual(@backingInt(types.ClType.msexe), pe.type);
    const sfx = try parseLine(a, "1:*:504b0304:ZIP-SFX:CL_TYPE_MSEXE:CL_TYPE_ZIPSFX:76", &column);
    try testing.expectEqual(@as(?u32, null), sfx.offset);
    try testing.expect(sfx.pattern != null);
    try testing.expectEqual(@as(u16, 76), sfx.flevel_min);
    const part = try parseLine(a, "4:1024:482b0004:HFS+ partition:CL_TYPE_PART_ANY:CL_TYPE_PART_HFSPLUS::150", &column);
    _ = part;
    try testing.expectError(error.UnknownFileType, parseLine(a, "4:1024:482b0004:HFS+:CL_TYPE_BOGUS:CL_TYPE_PART_HFSPLUS", &column));
    const ranged = try parseLine(a, "1:8:6674797068656963:HEIC:CL_TYPE_ANY:CL_TYPE_GRAPHICS::200", &column);
    try testing.expectEqual(@as(u16, 0), ranged.flevel_min);
    try testing.expectEqual(@as(u16, 200), ranged.flevel_max);

    const Bad = struct { []const u8, LineError, u32 };
    for ([_]Bad{
        .{ "0:0:4d5a:X:CL_TYPE_ANY", error.FieldCount, 0 },
        .{ "2:0:4d5a:X:CL_TYPE_ANY:CL_TYPE_MSEXE", error.BadMagicType, 0 },
        .{ "0:*:4d5a:X:CL_TYPE_ANY:CL_TYPE_MSEXE", error.BadOffset, 2 },
        .{ "0:-1:4d5a:X:CL_TYPE_ANY:CL_TYPE_MSEXE", error.BadOffset, 2 },
        .{ "0:0:4d5a::CL_TYPE_ANY:CL_TYPE_MSEXE", error.EmptyName, 9 },
        .{ "0:0:4d??:X:CL_TYPE_ANY:CL_TYPE_MSEXE", error.BadMagic, 4 },
        .{ "0:0:4d5:X:CL_TYPE_ANY:CL_TYPE_MSEXE", error.OddNibble, 6 },
        .{ "0:0:4d5a:X:CL_TYPE_ANY:CL_TYPE_NOPE", error.UnknownFileType, 23 },
        .{ "0:0:4d5a:X:CL_TYPE_ANY:CL_TYPE_MSEXE:x", error.BadFlevel, 37 },
        .{ "0:0:4d5a:X:CL_TYPE_ANY:CL_TYPE_MSEXE:", error.BadFlevel, 37 },
        .{ "0:0:4d5a:X:CL_TYPE_ANY:CL_TYPE_MSEXE:90:80", error.BadFlevel, 40 },
    }) |c| {
        try testing.expectError(c[1], parseLine(a, c[0], &column));
        try testing.expectEqual(c[2], column);
    }
}
