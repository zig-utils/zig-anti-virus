//! `.ndb` extended signatures, from ClamAV's ExtendedSignatures documentation:
//!
//!     MalwareName:TargetType:Offset:HexSignature[:min_flevel[:max_flevel]]
//!
//! Offsets: `*`, `n`, `EOF-n`, and for executables (PE, ELF, Mach-O targets) `EP+n`, `EP-n`,
//! `Sx+n`, `SEx` and `SL+n`. Every form except `*` takes `,maxshift`. Target types 0 to 14 map
//! one to one onto partitions; anything else is rejected, never folded into type 0. The `.ndu`
//! variant holds potentially unwanted applications. Every line that does not become a rule is
//! recorded with a reason and the column of the offending field.
const std = @import("std");
const ir = @import("ir.zig");
const hexsig = @import("hexsig.zig");

pub const max_target: u8 = 14;

/// Target types whose files have an entry point and sections.
pub fn isExecutableTarget(target: u8) bool {
    return target == 1 or target == 6 or target == 9;
}

pub const Output = struct {
    rules: *std.ArrayList(ir.BodyRule),
    rejected: *std.ArrayList(ir.Rejection),
};

/// Parse one `.ndb`/`.ndu` file. Patterns and rules live in `arena`; lists grow with `gpa`.
pub fn parse(gpa: std.mem.Allocator, arena: std.mem.Allocator, source_name: []const u8, text: []const u8, pua: bool, out: Output) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_number: u32 = 0;
    while (lines.next()) |raw| {
        line_number += 1;
        const line = std.mem.trimEnd(u8, raw, "\r \t");
        if (line.len == 0 or line[0] == '#') continue;
        var column: u32 = 0;
        if (parseLine(arena, line, &column)) |rule| {
            var r = rule;
            r.flags.pua = pua;
            try out.rules.append(gpa, r);
        } else |err| {
            try out.rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = reasonOf(err), .column = column });
        }
    }
}

pub const LineError = error{ FieldCount, EmptyName, BadTarget, BadOffset, OffsetNeedsExecutable, VersionInfoUnsupported, BadFlevel, TooShort } || hexsig.Error;

pub fn reasonOf(err: LineError) ir.Reason {
    return switch (err) {
        error.FieldCount => .field_count,
        error.EmptyName => .empty_name,
        error.BadTarget => .bad_target,
        error.BadOffset => .bad_offset,
        error.OffsetNeedsExecutable => .offset_needs_executable,
        error.VersionInfoUnsupported => .version_info_unsupported,
        error.BadFlevel => .bad_flevel,
        error.TooShort => .hex_too_short,
        else => |e| hexsig.reasonOf(@errorCast(e)),
    };
}

/// Parse one line. On error `column` points at the field (or, for a hex body, the construct)
/// that caused it.
pub fn parseLine(arena: std.mem.Allocator, line: []const u8, column: *u32) LineError!ir.BodyRule {
    var fields: [6][]const u8 = undefined;
    var starts: [6]usize = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, line, ':');
    while (it.next()) |f| {
        if (count == fields.len) return error.FieldCount;
        starts[count] = @intFromPtr(f.ptr) - @intFromPtr(line.ptr);
        fields[count] = f;
        count += 1;
    }
    if (count < 4) return error.FieldCount;
    const name = fields[0];
    if (name.len == 0) return error.EmptyName;

    column.* = @intCast(starts[1]);
    const target = std.fmt.parseInt(u8, fields[1], 10) catch return error.BadTarget;
    if (target > max_target) return error.BadTarget;

    column.* = @intCast(starts[2]);
    const offset = try parseOffset(fields[2]);
    if (needsExecutable(offset.kind) and !isExecutableTarget(target)) return error.OffsetNeedsExecutable;

    column.* = @intCast(if (count > 4) starts[4] else line.len);
    const flevel_min: u16 = if (count >= 5) std.fmt.parseInt(u16, fields[4], 10) catch return error.BadFlevel else 0;
    const flevel_max: u16 = if (count >= 6) std.fmt.parseInt(u16, fields[5], 10) catch return error.BadFlevel else 0;
    if (flevel_max != 0 and flevel_max < flevel_min) return error.BadFlevel;

    var diag: hexsig.Diag = .{};
    const pattern = hexsig.parseClamav(arena, fields[3], &diag) catch |err| {
        column.* = @intCast(starts[3] + diag.pos);
        return err;
    };
    // libclamav matches plain literal bodies with Boyer-Moore unless the target type is not 0
    // and the offset is `*`; that matcher refuses bodies under three bytes.
    const plain = for (fields[3]) |ch| {
        if (!std.ascii.isHex(ch)) break false;
    } else true;
    if (plain and fields[3].len < 6 and !(target != 0 and offset.kind == .any)) {
        column.* = @intCast(starts[3]);
        return error.TooShort;
    }
    column.* = 0;
    return .{
        .name = name,
        .target = target,
        .subsig = .{ .pattern = pattern, .offset = offset },
        .flevel_min = flevel_min,
        .flevel_max = flevel_max,
        .source = .ndb,
        .line = line,
    };
}

pub fn needsExecutable(kind: ir.OffsetKind) bool {
    return switch (kind) {
        .entry_point, .section_start, .section_entire, .last_section => true,
        else => false,
    };
}

pub const OffsetError = error{ BadOffset, VersionInfoUnsupported };

/// Parse an offset field (shared with `.ldb` subsignature offsets).
pub fn parseOffset(text: []const u8) OffsetError!ir.Offset {
    if (std.mem.eql(u8, text, "*")) return .{};
    if (std.mem.eql(u8, text, "VI")) return error.VersionInfoUnsupported;
    var base = text;
    var shift: u32 = 0;
    if (std.mem.indexOfScalar(u8, text, ',')) |comma| {
        base = text[0..comma];
        shift = try unsignedValue(u32, text[comma + 1 ..]);
    }
    var off: ir.Offset = .{ .shift = shift };
    if (std.mem.startsWith(u8, base, "EOF-")) {
        off.kind = .eof_minus;
        off.a = try unsignedValue(i32, base[4..]);
    } else if (std.mem.startsWith(u8, base, "EP+") or std.mem.startsWith(u8, base, "EP-")) {
        off.kind = .entry_point;
        const n = try unsignedValue(i32, base[3..]);
        off.a = if (base[2] == '-') -n else n;
    } else if (std.mem.startsWith(u8, base, "SL+")) {
        off.kind = .last_section;
        off.a = try unsignedValue(i32, base[3..]);
    } else if (std.mem.startsWith(u8, base, "SE")) {
        off.kind = .section_entire;
        off.section = try unsignedValue(u16, base[2..]);
    } else if (base.len > 1 and base[0] == 'S') {
        const plus = std.mem.indexOfScalar(u8, base, '+') orelse return error.BadOffset;
        off.kind = .section_start;
        off.section = try unsignedValue(u16, base[1..plus]);
        off.a = try unsignedValue(i32, base[plus + 1 ..]);
    } else {
        off.kind = .absolute;
        off.a = try unsignedValue(i32, base);
    }
    return off;
}

/// A non-negative decimal that fits `T` (signed types keep their sign bit clear).
fn unsignedValue(comptime T: type, text: []const u8) error{BadOffset}!T {
    if (text.len == 0) return error.BadOffset;
    for (text) |c| if (c < '0' or c > '9') return error.BadOffset;
    return std.fmt.parseInt(T, text, 10) catch error.BadOffset;
}

const testing = std.testing;

test "every offset kind and the maxshift form" {
    const Case = struct { []const u8, ir.OffsetKind, i32, u16, u32 };
    for ([_]Case{
        .{ "*", .any, 0, 0, 0 },
        .{ "0", .absolute, 0, 0, 0 },
        .{ "1024", .absolute, 1024, 0, 0 },
        .{ "10,5", .absolute, 10, 0, 5 },
        .{ "EOF-68", .eof_minus, 68, 0, 0 },
        .{ "EOF-10,20", .eof_minus, 10, 0, 20 },
        .{ "EP+0", .entry_point, 0, 0, 0 },
        .{ "EP+12", .entry_point, 12, 0, 0 },
        .{ "EP-7,3", .entry_point, -7, 0, 3 },
        .{ "S0+16", .section_start, 16, 0, 0 },
        .{ "S3+4,8", .section_start, 4, 3, 8 },
        .{ "SE2", .section_entire, 0, 2, 0 },
        .{ "SL+550", .last_section, 550, 0, 0 },
    }) |c| {
        const off = try parseOffset(c[0]);
        try testing.expectEqual(c[1], off.kind);
        try testing.expectEqual(c[2], off.a);
        try testing.expectEqual(c[3], off.section);
        try testing.expectEqual(c[4], off.shift);
    }
    for ([_][]const u8{ "", "-1", "EOF+1", "EOF-", "EP", "EP*3", "S+1", "Sx+1", "S1-2", "SE", "SL-1", "10,", "10,x", "*,5", "99999999999", "1 0" }) |bad| {
        try testing.expectError(error.BadOffset, parseOffset(bad));
    }
    try testing.expectError(error.VersionInfoUnsupported, parseOffset("VI"));
}

test "ndb lines: fields, targets, flevels" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var column: u32 = 0;
    const a = arena.allocator();
    const r = try parseLine(a, "Win.Trojan.Test-1-0:1:EP+0:e8????????5dc3:60:200", &column);
    try testing.expectEqualStrings("Win.Trojan.Test-1-0", r.name);
    try testing.expectEqual(@as(u8, 1), r.target);
    try testing.expectEqual(ir.OffsetKind.entry_point, r.subsig.offset.kind);
    try testing.expectEqual(@as(u16, 60), r.flevel_min);
    try testing.expectEqual(@as(u16, 200), r.flevel_max);
    try testing.expectEqual(ir.Source.ndb, r.source);

    for (0..max_target + 1) |t| {
        var buf: [64]u8 = undefined;
        _ = try parseLine(a, try std.fmt.bufPrint(&buf, "X:{d}:*:deadbeef", .{t}), &column);
    }

    const Bad = struct { []const u8, LineError, u32 };
    for ([_]Bad{
        .{ "X:0:*", error.FieldCount, 0 },
        .{ "X:0:*:aa:1:2:3", error.FieldCount, 0 },
        .{ ":0:*:aabb", error.EmptyName, 0 },
        .{ "X:15:*:aabb", error.BadTarget, 2 },
        .{ "X:-1:*:aabb", error.BadTarget, 2 },
        .{ "X:abc:*:aabb", error.BadTarget, 2 },
        .{ "X:0:EP+0:aabb", error.OffsetNeedsExecutable, 4 },
        .{ "X:7:SL+3:aabb", error.OffsetNeedsExecutable, 4 },
        .{ "X:1:VI:aabb", error.VersionInfoUnsupported, 4 },
        .{ "X:0:Q:aabb", error.BadOffset, 4 },
        .{ "X:0:*:aabb:x", error.BadFlevel, 11 },
        .{ "X:0:*:aabb:90:80", error.BadFlevel, 11 },
        .{ "X:0:*:aabbz", error.BadChar, 10 },
        .{ "X:0:*:*aabb", error.EmptyPart, 6 },
    }) |c| {
        try testing.expectError(c[1], parseLine(a, c[0], &column));
        try testing.expectEqual(c[2], column);
    }
}

test "parse records every rejected line; ndu is PUA" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var rules: std.ArrayList(ir.BodyRule) = .empty;
    defer rules.deinit(testing.allocator);
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    defer rejected.deinit(testing.allocator);
    const text =
        \\Eicar.Pattern:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d
        \\# comment
        \\Bad.Target:20:*:aabb
        \\Bad.Hex:0:*:aa(bb
        \\
    ;
    try parse(testing.allocator, arena.allocator(), "test.ndu", text, true, .{ .rules = &rules, .rejected = &rejected });
    try testing.expectEqual(@as(usize, 1), rules.items.len);
    try testing.expect(rules.items[0].flags.pua);
    try testing.expectEqual(@as(usize, 2), rejected.items.len);
    try testing.expectEqual(ir.Reason.bad_target, rejected.items[0].reason);
    try testing.expectEqual(@as(u32, 3), rejected.items[0].line_number);
    try testing.expectEqual(ir.Reason.hex_bad_alternation, rejected.items[1].reason);
    try testing.expectEqual(@as(u32, 14), rejected.items[1].column);
}
