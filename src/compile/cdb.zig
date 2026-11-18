//! `.cdb` container metadata signatures, from ClamAV's ContainerMetadata documentation:
//!
//!     VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:
//!     IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]
//!
//! `*` means any value; sizes and the position take an exact value or `x-y`; the position counts
//! from 1; IsEncrypted is 1, 0 or `*`; Res1 is the member's CRC (hex) for ZIP and RAR; Res2 is
//! unused. A filename regex other than `*` is compiled to a zig-regex byte-mode program
//! (searched anywhere in the member name, as POSIX regexec does); a regex zig-regex cannot parse
//! is rejected as `regex_syntax`, one that needs its backtracker as `regex_unsupported`.
const std = @import("std");
const ir = @import("ir.zig");
const types = @import("../fmt/types.zig");
const regex = @import("regex");

pub const LineError = error{ FieldCount, EmptyName, BadCdbField, UnknownFileType, BadFlevel, RegexSyntax, RegexUnsupported, OutOfMemory };

pub fn reasonOf(err: LineError) ir.Reason {
    return switch (err) {
        error.FieldCount => .field_count,
        error.EmptyName => .empty_name,
        error.BadCdbField => .bad_cdb_field,
        error.UnknownFileType => .unknown_file_type,
        error.BadFlevel => .bad_flevel,
        error.RegexSyntax => .regex_syntax,
        error.RegexUnsupported => .regex_unsupported,
        error.OutOfMemory => .hex_too_complex,
    };
}

pub const Output = struct {
    rules: *std.ArrayList(ir.CdbRule),
    rejected: *std.ArrayList(ir.Rejection),
};

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
            if (err == error.OutOfMemory) return error.OutOfMemory;
            try out.rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = reasonOf(err), .column = column });
        }
    }
}

fn range(text: []const u8) error{BadCdbField}!?ir.Range {
    if (std.mem.eql(u8, text, "*")) return null;
    if (std.mem.indexOfScalar(u8, text, '-')) |dash| {
        const lo = std.fmt.parseInt(u64, text[0..dash], 10) catch return error.BadCdbField;
        const hi = std.fmt.parseInt(u64, text[dash + 1 ..], 10) catch return error.BadCdbField;
        if (hi < lo) return error.BadCdbField;
        return .{ .lo = lo, .hi = hi };
    }
    const v = std.fmt.parseInt(u64, text, 10) catch return error.BadCdbField;
    return .{ .lo = v, .hi = v };
}

/// Compile a regex to a serialised byte-mode program in `arena`.
pub fn compileRegex(arena: std.mem.Allocator, pattern: []const u8, flags: regex.common.CompileFlags) error{ RegexSyntax, RegexUnsupported, OutOfMemory }![]const u8 {
    var f = flags;
    f.bytes = true;
    const program = regex.Program.compile(arena, pattern, f) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnsupportedByProgram, error.ProgramTooLarge => error.RegexUnsupported,
        else => error.RegexSyntax,
    };
    return program.bytes();
}

/// Parse one line. Rules borrow `line`; a compiled filename program lives in `arena`.
pub fn parseLine(arena: std.mem.Allocator, line: []const u8, column: *u32) LineError!ir.CdbRule {
    var fields: [12][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, line, ':');
    while (it.next()) |f| {
        if (count == fields.len) return error.FieldCount;
        fields[count] = f;
        count += 1;
    }
    if (count < 10) return error.FieldCount;
    if (fields[0].len == 0) return error.EmptyName;
    var rule: ir.CdbRule = .{ .name = fields[0], .line = line };
    const col = struct {
        fn of(l: []const u8, f: []const u8) u32 {
            return @intCast(@intFromPtr(f.ptr) - @intFromPtr(l.ptr));
        }
    }.of;

    column.* = col(line, fields[1]);
    if (!std.mem.eql(u8, fields[1], "*")) rule.container = @backingInt(types.ClType.parse(fields[1]) orelse return error.UnknownFileType);
    column.* = col(line, fields[2]);
    rule.container_size = try range(fields[2]);
    column.* = col(line, fields[4]);
    rule.size_in_container = try range(fields[4]);
    column.* = col(line, fields[5]);
    rule.size_real = try range(fields[5]);
    column.* = col(line, fields[6]);
    rule.encrypted = if (std.mem.eql(u8, fields[6], "*")) null else if (std.mem.eql(u8, fields[6], "1")) true else if (std.mem.eql(u8, fields[6], "0")) false else return error.BadCdbField;
    column.* = col(line, fields[7]);
    rule.file_pos = try range(fields[7]);
    if (rule.file_pos) |p| if (p.lo == 0) return error.BadCdbField;
    column.* = col(line, fields[8]);
    if (!std.mem.eql(u8, fields[8], "*")) rule.crc = std.fmt.parseInt(u32, fields[8], 16) catch return error.BadCdbField;
    column.* = col(line, fields[9]);
    if (!std.mem.eql(u8, fields[9], "*") and fields[9].len != 0) return error.BadCdbField;
    if (count >= 11) {
        column.* = col(line, fields[10]);
        rule.flevel_min = std.fmt.parseInt(u16, fields[10], 10) catch return error.BadFlevel;
    }
    if (count == 12) {
        column.* = col(line, fields[11]);
        rule.flevel_max = std.fmt.parseInt(u16, fields[11], 10) catch return error.BadFlevel;
        if (rule.flevel_max < rule.flevel_min) return error.BadFlevel;
    }
    column.* = col(line, fields[3]);
    if (fields[3].len == 0) return error.BadCdbField;
    if (!std.mem.eql(u8, fields[3], "*")) {
        rule.filename_regex = fields[3];
        rule.filename_program = try compileRegex(arena, fields[3], .{});
    }
    column.* = 0;
    return rule;
}

const testing = std.testing;

test "cdb lines: wildcards, exact values, ranges, and rejections" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var column: u32 = 0;
    const r = try parseLine(arena, "Zip.Exploit.A-1-0:CL_TYPE_ZIP:100-200:*:50:*:1:2-4:8a4f1c2e:*:81:255", &column);
    try testing.expectEqual(@backingInt(types.ClType.zip), r.container.?);
    try testing.expectEqual(ir.Range{ .lo = 100, .hi = 200 }, r.container_size.?);
    try testing.expectEqual(ir.Range{ .lo = 50, .hi = 50 }, r.size_in_container.?);
    try testing.expect(r.size_real == null);
    try testing.expectEqual(@as(?bool, true), r.encrypted);
    try testing.expectEqual(ir.Range{ .lo = 2, .hi = 4 }, r.file_pos.?);
    try testing.expectEqual(@as(?u32, 0x8a4f1c2e), r.crc);
    try testing.expectEqual(@as(u16, 81), r.flevel_min);
    const any = try parseLine(arena, "Any.Container-2-0:*:*:*:*:*:*:*:*:*", &column);
    try testing.expect(any.container == null and any.encrypted == null and any.crc == null);
    const named = try parseLine(arena, "Zip.Scr-3-0:CL_TYPE_ZIP:*:.*\\.scr$:*:*:*:*:*:*", &column);
    try testing.expectEqualStrings(".*\\.scr$", named.filename_regex.?);
    const program = try regex.Program.load(named.filename_program.?);
    var scratch = try regex.Scratch.init(testing.allocator, &program);
    defer scratch.deinit(testing.allocator);
    try testing.expect(try program.isMatch(&scratch, "invoice.pdf.scr"));
    try testing.expect(!try program.isMatch(&scratch, "invoice.scr.pdf"));

    const Bad = struct { []const u8, LineError, u32 };
    for ([_]Bad{
        .{ "X:*:*:*:*:*:*:*:*", error.FieldCount, 0 },
        .{ ":*:*:*:*:*:*:*:*:*", error.EmptyName, 0 },
        .{ "X:CL_TYPE_NOPE:*:*:*:*:*:*:*:*", error.UnknownFileType, 2 },
        .{ "X:*:200-100:*:*:*:*:*:*:*", error.BadCdbField, 4 },
        .{ "X:*:*:*:abc:*:*:*:*:*", error.BadCdbField, 8 },
        .{ "X:*:*:*:*:*:2:*:*:*", error.BadCdbField, 12 },
        .{ "X:*:*:*:*:*:*:0:*:*", error.BadCdbField, 14 },
        .{ "X:*:*:*:*:*:*:*:xyz:*", error.BadCdbField, 16 },
        .{ "X:*:*:*:*:*:*:*:*:7", error.BadCdbField, 18 },
        .{ "X:*:*:*:*:*:*:*:*:*:x", error.BadFlevel, 20 },
        .{ "X:*:*:(a:*:*:*:*:*:*", error.RegexSyntax, 6 },
        .{ "X:*:*:(a)\\1:*:*:*:*:*:*", error.RegexUnsupported, 6 },
    }) |c| {
        try testing.expectError(c[1], parseLine(arena, c[0], &column));
        try testing.expectEqual(c[2], column);
    }
}
