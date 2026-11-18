//! `.ldb` logical signatures, from ClamAV's LogicalSignatures documentation:
//!
//!     SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;...
//!
//! The target description block is `Key:Value` pairs separated by commas: Engine, Target,
//! FileSize, EntryPoint, NumberOfSections, Container and Intermediates are compiled; IconGroup1,
//! IconGroup2 and HandlerType are rejected with their own reasons until icons and rescans exist.
//! The expression compiles to RPN (`ir.RpnOp`); `&` binds tighter than `|`, parentheses group,
//! and `=X`, `>X`, `<X` (each with an optional `,Y` distinct count) apply to the subsig or block
//! before them. Subsignatures are hex bodies with an optional `Offset:` prefix and `::iwfa`
//! modifiers, byte compares (`trigger(>>offset#options#comparisons)`) or PCRE subsigs
//! (`[Offset:]Trigger/Pattern/[Flags]`, compiled to zig-regex byte-mode programs); macro and
//! fuzzy-image subsigs are recognised and rejected with a reason until their matchers land. At
//! most 64 subsigs. `.ldu` holds PUA signatures.
const std = @import("std");
const ir = @import("ir.zig");
const hexsig = @import("hexsig.zig");
const ndb = @import("ndb.zig");
const types = @import("../fmt/types.zig");
const ldb_table = @import("../match/ldb_table.zig");
const cdb = @import("cdb.zig");

pub const LineError = error{
    FieldCount,
    EmptyName,
    BadTdb,
    BadTarget,
    BadFlevel,
    UnknownFileType,
    IconUnsupported,
    HandlerTypeUnsupported,
    BadExpression,
    ExprTrueWithoutHits,
    TooManySubsigs,
    BadOffset,
    OffsetNeedsExecutable,
    VersionInfoUnsupported,
    BadPcre,
    PcreFlagUnsupported,
    RegexSyntax,
    RegexUnsupported,
    MacroUnsupported,
    FuzzyImageUnsupported,
    BadByteCompare,
} || hexsig.Error;

pub fn reasonOf(err: LineError) ir.Reason {
    return switch (err) {
        error.FieldCount => .field_count,
        error.EmptyName => .empty_name,
        error.BadTdb => .bad_tdb,
        error.BadTarget => .bad_target,
        error.BadFlevel => .bad_flevel,
        error.UnknownFileType => .unknown_file_type,
        error.IconUnsupported => .icon_unsupported,
        error.HandlerTypeUnsupported => .handler_type_unsupported,
        error.BadExpression => .bad_expression,
        error.ExprTrueWithoutHits => .expr_true_without_hits,
        error.TooManySubsigs => .too_many_subsigs,
        error.BadOffset => .bad_offset,
        error.OffsetNeedsExecutable => .offset_needs_executable,
        error.VersionInfoUnsupported => .version_info_unsupported,
        error.BadPcre => .bad_pcre,
        error.PcreFlagUnsupported => .pcre_flag_unsupported,
        error.RegexSyntax => .regex_syntax,
        error.RegexUnsupported => .regex_unsupported,
        error.MacroUnsupported => .macro_unsupported,
        error.FuzzyImageUnsupported => .fuzzy_image_unsupported,
        error.BadByteCompare => .bad_byte_compare,
        else => |e| hexsig.reasonOf(@errorCast(e)),
    };
}

pub const Output = struct {
    rules: *std.ArrayList(ir.LogicalRule),
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

fn colOf(line: []const u8, field: []const u8) u32 {
    return @intCast(@intFromPtr(field.ptr) - @intFromPtr(line.ptr));
}

pub fn parseLine(arena: std.mem.Allocator, line: []const u8, column: *u32) LineError!ir.LogicalRule {
    var fields: [3 + ir.max_subsigs + 1][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, line, ';');
    while (it.next()) |f| {
        if (count == fields.len) {
            column.* = colOf(line, f);
            return error.TooManySubsigs;
        }
        fields[count] = f;
        count += 1;
    }
    if (count < 4) return error.FieldCount;
    if (count - 3 > ir.max_subsigs) {
        column.* = colOf(line, fields[3 + ir.max_subsigs]);
        return error.TooManySubsigs;
    }
    if (fields[0].len == 0) return error.EmptyName;

    column.* = colOf(line, fields[1]);
    var flevel_min: u16 = 0;
    var flevel_max: u16 = 0;
    const tdb = try parseTdb(fields[1], &flevel_min, &flevel_max);

    const nsub = count - 3;
    column.* = colOf(line, fields[2]);
    const expr = try parseExpression(arena, fields[2], nsub, nsub);
    var zeros: [ir.max_subsigs]u32 = @splat(0);
    if (ldb_table.evalRpn(expr, zeros[0..nsub])) return error.ExprTrueWithoutHits;

    const subsigs = try arena.alloc(ir.LogicalSubsig, nsub);
    for (fields[3..count], subsigs, 0..) |text, *sub, i| {
        column.* = colOf(line, text);
        sub.* = try parseSubsig(arena, text, i, tdb.target, column);
    }
    // A byte compare's trigger must be a body subsig of this signature.
    for (fields[3..count], subsigs) |text, sub| switch (sub) {
        .byte_compare => |bc| if (bc.trigger >= nsub or subsigs[bc.trigger] != .hex) {
            column.* = colOf(line, text);
            return error.BadByteCompare;
        },
        .hex, .pcre => {},
    };
    column.* = 0;
    return .{
        .name = fields[0],
        .tdb = tdb,
        .expr = expr,
        .subsigs = subsigs,
        .flevel_min = flevel_min,
        .flevel_max = flevel_max,
        .line = line,
    };
}

fn parseRange(text: []const u8) error{BadTdb}!ir.Range {
    if (std.mem.indexOfScalar(u8, text, '-')) |dash| {
        const lo = std.fmt.parseInt(u64, text[0..dash], 10) catch return error.BadTdb;
        const hi = std.fmt.parseInt(u64, text[dash + 1 ..], 10) catch return error.BadTdb;
        if (hi < lo) return error.BadTdb;
        return .{ .lo = lo, .hi = hi };
    }
    const v = std.fmt.parseInt(u64, text, 10) catch return error.BadTdb;
    return .{ .lo = v, .hi = v };
}

fn fileType(text: []const u8) error{UnknownFileType}!u16 {
    const t = types.ClType.parse(text) orelse return error.UnknownFileType;
    return @backingInt(t);
}

pub fn parseTdb(text: []const u8, flevel_min: *u16, flevel_max: *u16) LineError!ir.Tdb {
    var tdb: ir.Tdb = .{};
    var seen: u16 = 0;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |pair| {
        const colon = std.mem.indexOfScalar(u8, pair, ':') orelse return error.BadTdb;
        const key = pair[0..colon];
        const value = pair[colon + 1 ..];
        const keys = [_][]const u8{ "Engine", "Target", "FileSize", "EntryPoint", "NumberOfSections", "Container", "Intermediates", "IconGroup1", "IconGroup2", "HandlerType" };
        const which = for (keys, 0..) |k, i| {
            if (std.mem.eql(u8, k, key)) break i;
        } else return error.BadTdb;
        const bit = @as(u16, 1) << @intCast(which);
        if (seen & bit != 0) return error.BadTdb;
        seen |= bit;
        switch (which) {
            0 => {
                const r = try parseRange(value);
                if (r.hi > std.math.maxInt(u16)) return error.BadFlevel;
                flevel_min.* = @intCast(r.lo);
                flevel_max.* = @intCast(r.hi);
            },
            1 => {
                const t = std.fmt.parseInt(u8, value, 10) catch return error.BadTarget;
                if (t > ndb.max_target) return error.BadTarget;
                tdb.target = t;
            },
            2 => tdb.file_size = try parseRange(value),
            3 => tdb.entry_point = try parseRange(value),
            4 => tdb.sections = try parseRange(value),
            5 => tdb.container = try fileType(value),
            6 => {
                var layers = std.mem.splitScalar(u8, value, '>');
                while (layers.next()) |layer| {
                    if (tdb.intermediate_count == ir.max_intermediates) return error.BadTdb;
                    tdb.intermediates[tdb.intermediate_count] = try fileType(layer);
                    tdb.intermediate_count += 1;
                }
            },
            7, 8 => return error.IconUnsupported,
            9 => return error.HandlerTypeUnsupported,
            else => unreachable,
        }
    }
    if (seen & 0b110_0000 == 0b110_0000) return error.BadTdb; // Container and Intermediates are alternatives
    return tdb;
}

// ---------------------------------------------------------------------------------------------
// Logical expressions
// ---------------------------------------------------------------------------------------------

const ExprParser = struct {
    text: []const u8,
    pos: usize = 0,
    ops: std.ArrayList(ir.RpnOp) = .empty,
    arena: std.mem.Allocator,
    /// Subsig indices must be below this (all subsigs for the main expression, only earlier
    /// ones for a PCRE trigger).
    limit: usize,
    depth: usize = 0,

    fn peek(p: *ExprParser) ?u8 {
        return if (p.pos < p.text.len) p.text[p.pos] else null;
    }

    fn number(p: *ExprParser, max: u64) LineError!u64 {
        const start = p.pos;
        while (p.peek()) |c| {
            if (c < '0' or c > '9') break;
            p.pos += 1;
        }
        if (p.pos == start) return error.BadExpression;
        const v = std.fmt.parseInt(u64, p.text[start..p.pos], 10) catch return error.BadExpression;
        if (v > max) return error.BadExpression;
        return v;
    }

    fn emit(p: *ExprParser, op: ir.RpnOp) LineError!void {
        if (p.ops.items.len >= 4096) return error.BadExpression;
        try p.ops.append(p.arena, op);
    }

    fn orExpr(p: *ExprParser) LineError!void {
        try p.andExpr();
        while (p.peek() == '|') {
            p.pos += 1;
            try p.andExpr();
            try p.emit(.{ .code = .@"or" });
        }
    }

    fn andExpr(p: *ExprParser) LineError!void {
        try p.unary();
        while (p.peek() == '&') {
            p.pos += 1;
            try p.unary();
            try p.emit(.{ .code = .@"and" });
        }
    }

    fn unary(p: *ExprParser) LineError!void {
        const c = p.peek() orelse return error.BadExpression;
        if (c == '(') {
            p.pos += 1;
            p.depth += 1;
            if (p.depth > ir.max_rpn_depth) return error.BadExpression;
            try p.orExpr();
            if (p.peek() != ')') return error.BadExpression;
            p.pos += 1;
            p.depth -= 1;
        } else {
            const i = try p.number(ir.max_subsigs - 1);
            if (i >= p.limit) return error.BadExpression;
            try p.emit(.{ .code = .sub, .index = @intCast(i) });
        }
        const op = p.peek() orelse return;
        const code: ir.RpnCode = switch (op) {
            '=' => .eq,
            '>' => .gt,
            '<' => .lt,
            else => return,
        };
        p.pos += 1;
        const k = try p.number(std.math.maxInt(u32));
        var distinct: u64 = 0;
        if (p.peek() == ',') {
            p.pos += 1;
            distinct = try p.number(ir.max_subsigs);
        }
        try p.emit(.{ .code = code, .k = @intCast(k), .distinct = @intCast(distinct) });
    }
};

/// Compile an expression to RPN. `limit` bounds the subsig indices it may name.
pub fn parseExpression(arena: std.mem.Allocator, text: []const u8, nsub: usize, limit: usize) LineError![]const ir.RpnOp {
    var p: ExprParser = .{ .text = text, .arena = arena, .limit = @min(limit, nsub) };
    try p.orExpr();
    if (p.pos != text.len) return error.BadExpression;
    if (!ldb_table.checkRpn(p.ops.items, nsub)) return error.BadExpression;
    return p.ops.items;
}

// ---------------------------------------------------------------------------------------------
// Subsignatures
// ---------------------------------------------------------------------------------------------

fn isByteCompare(text: []const u8) bool {
    const open = std.mem.indexOfScalar(u8, text, '(') orelse return false;
    if (open == 0 or text[text.len - 1] != ')') return false;
    for (text[0..open]) |c| if (c < '0' or c > '9') return false;
    return std.mem.indexOfScalar(u8, text, '#') != null;
}

fn parseSubsig(arena: std.mem.Allocator, text: []const u8, index: usize, target: u8, column: *u32) LineError!ir.LogicalSubsig {
    if (text.len == 0) return error.FieldCount;
    if (std.mem.startsWith(u8, text, "${")) return error.MacroUnsupported;
    if (std.mem.startsWith(u8, text, "fuzzy_img#")) return error.FuzzyImageUnsupported;
    if (isByteCompare(text)) return .{ .byte_compare = try parseByteCompare(text, index) };
    if (std.mem.indexOfScalar(u8, text, '/')) |slash| {
        return .{ .pcre = try parsePcre(arena, text, slash, index, target) };
    }

    var body = text;
    var mods: ir.Modifiers = .{};
    if (std.mem.lastIndexOf(u8, body, "::")) |m| {
        mods = hexsig.parseModifiers(body[m + 2 ..]) catch return error.BadModifier;
        body = body[0..m];
    }
    var offset: ir.Offset = .{};
    var body_start: usize = 0;
    if (std.mem.indexOfScalar(u8, body, ':')) |colon| {
        offset = try ndb.parseOffset(body[0..colon]);
        if (ndb.needsExecutable(offset.kind) and !ndb.isExecutableTarget(target)) return error.OffsetNeedsExecutable;
        body_start = colon + 1;
    }
    var diag: hexsig.Diag = .{};
    const pattern = hexsig.parse(arena, body[body_start..], &diag) catch |err| {
        column.* += @intCast(body_start + diag.pos);
        return err;
    };
    return .{ .hex = .{ .pattern = pattern, .mods = mods, .offset = offset } };
}

fn numberValue(comptime T: type, text: []const u8) error{BadByteCompare}!T {
    if (text.len == 0) return error.BadByteCompare;
    if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X")) {
        if (text.len == 2) return error.BadByteCompare;
        return std.fmt.parseInt(T, text[2..], 16) catch error.BadByteCompare;
    }
    for (text) |c| if (c < '0' or c > '9') return error.BadByteCompare;
    return std.fmt.parseInt(T, text, 10) catch error.BadByteCompare;
}

/// `trigger(>>offset#[h|d|a|i][l|b][e]width#op value[,op value])`.
pub fn parseByteCompare(text: []const u8, self_index: usize) error{BadByteCompare}!ir.ByteCompare {
    const open = std.mem.indexOfScalar(u8, text, '(') orelse return error.BadByteCompare;
    if (text[text.len - 1] != ')') return error.BadByteCompare;
    const trigger = std.fmt.parseInt(u8, text[0..open], 10) catch return error.BadByteCompare;
    if (trigger == self_index or trigger >= ir.max_subsigs) return error.BadByteCompare;
    var parts = std.mem.splitScalar(u8, text[open + 1 .. text.len - 1], '#');
    const off_text = parts.next() orelse return error.BadByteCompare;
    const opt_text = parts.next() orelse return error.BadByteCompare;
    const cmp_text = parts.next() orelse return error.BadByteCompare;
    if (parts.next() != null) return error.BadByteCompare;

    var bc: ir.ByteCompare = .{ .trigger = trigger, .offset = 0, .kind = .hex, .big_endian = true, .exact = false, .width = 0, .comparison_count = 0 };
    if (off_text.len < 3) return error.BadByteCompare;
    if (std.mem.startsWith(u8, off_text, ">>")) {
        bc.backward = false;
    } else if (std.mem.startsWith(u8, off_text, "<<")) {
        bc.backward = true;
    } else return error.BadByteCompare;
    bc.offset = try numberValue(u32, off_text[2..]);

    var o = opt_text;
    if (o.len == 0) return error.BadByteCompare;
    bc.kind = switch (o[0]) {
        'h' => .hex,
        'd' => .decimal,
        'a' => .auto,
        'i' => .binary,
        else => return error.BadByteCompare,
    };
    o = o[1..];
    var endian_given = false;
    if (o.len > 0 and (o[0] == 'l' or o[0] == 'b')) {
        bc.big_endian = o[0] == 'b';
        endian_given = true;
        o = o[1..];
    }
    if (o.len > 0 and o[0] == 'e') {
        bc.exact = true;
        o = o[1..];
    }
    const width = try numberValue(u8, o);
    switch (bc.kind) {
        // Decimal is big-endian by definition: little-endian decimal is malformed.
        .decimal => if (endian_given and !bc.big_endian) return error.BadByteCompare,
        .binary => {
            bc.exact = true;
            if (!endian_given) bc.big_endian = false;
            if (width != 1 and width != 2 and width != 4 and width != 8) return error.BadByteCompare;
        },
        else => {},
    }
    if (width == 0 or width > ir.max_text_width) return error.BadByteCompare;
    bc.width = width;

    var cmps = std.mem.splitScalar(u8, cmp_text, ',');
    while (cmps.next()) |c| {
        if (bc.comparison_count == 2 or c.len < 2) return error.BadByteCompare;
        const op: ir.CmpOp = switch (c[0]) {
            '<' => .lt,
            '>' => .gt,
            '=' => .eq,
            else => return error.BadByteCompare,
        };
        bc.comparisons[bc.comparison_count] = .{ .op = op, .value = try numberValue(u64, c[1..]) };
        bc.comparison_count += 1;
    }
    if (bc.comparison_count == 0) return error.BadByteCompare;
    return bc;
}

test "byte-compare subsignatures: every encoding, width and endianness option" {
    const Case = struct { []const u8, ir.ByteKind, bool, bool, u8, u32, bool };
    for ([_]Case{
        .{ "0(>>4#hb2#=0x10)", .hex, true, false, 2, 4, false },
        .{ "0(>>0x10#hl4#>1)", .hex, false, false, 4, 16, false },
        .{ "0(<<8#d3#<100)", .decimal, true, false, 3, 8, true },
        .{ "0(>>2#db3#=5)", .decimal, true, false, 3, 2, false },
        .{ "0(>>2#ae6#=5)", .auto, true, true, 6, 2, false },
        .{ "0(>>2#ib1#=5)", .binary, true, true, 1, 2, false },
        .{ "0(>>2#il2#=5)", .binary, false, true, 2, 2, false },
        .{ "0(>>2#i4#=5)", .binary, false, true, 4, 2, false },
        .{ "0(>>2#ib8#=5)", .binary, true, true, 8, 2, false },
        .{ "0(>>2#he0x8#>0x10,<0x20)", .hex, true, true, 8, 2, false },
    }) |c| {
        const bc = try parseByteCompare(c[0], 1);
        try testing.expectEqual(c[1], bc.kind);
        try testing.expectEqual(c[2], bc.big_endian);
        try testing.expectEqual(c[3], bc.exact);
        try testing.expectEqual(c[4], bc.width);
        try testing.expectEqual(c[5], bc.offset);
        try testing.expectEqual(c[6], bc.backward);
    }
    const two = try parseByteCompare("0(>>2#he0x8#>0x10,<0x20)", 1);
    try testing.expectEqual(@as(u8, 2), two.comparison_count);
    try testing.expectEqual(ir.CmpOp.lt, two.comparisons[1].op);
    try testing.expectEqual(@as(u64, 0x20), two.comparisons[1].value);
    for ([_][]const u8{
        "0(>>4#dl2#=1)", // little-endian decimal
        "0(>>4#ib3#=1)", // binary width not 1, 2, 4, 8
        "0(>>4#h0#=1)",
        "0(>>4#h21#=1)",
        "0(>>4#x2#=1)",
        "0(4#h2#=1)",
        "0(>>#h2#=1)",
        "0(>>4#h2#)",
        "0(>>4#h2#=1,=2,=3)",
        "0(>>4#h2#!1)",
        "0(>>4#h2)",
        "0(>>4#h2#=1#x)",
        "1(>>4#h2#=1)", // its own trigger
        "0(>>4#h2#=0x)",
        "0(>>4#h2#=1",
    }) |bad| try testing.expectError(error.BadByteCompare, parseByteCompare(bad, 1));
}

/// `[Offset:]Trigger/Pattern/[Flags]`. The trigger may name only earlier subsigs and must not be
/// true without any hits (sparse evaluation would never run it); the pattern is everything
/// between the first and the last `/`. Flags: `g` count all matches, `r` rolling search from the
/// offset, `e` confine the match to offset..offset+maxshift (needs a maxshift), `A` anchored,
/// and `i s m x` for the regex. `E` (dollar end-only) and `U` (ungreedy) do not change whether
/// or where a match starts, so they are accepted, except `U` with `g`, whose counts depend on
/// match ends.
pub fn parsePcre(arena: std.mem.Allocator, text: []const u8, first_slash: usize, index: usize, target: u8) LineError!ir.PcreSubsig {
    const last = std.mem.lastIndexOfScalar(u8, text, '/').?;
    if (last == first_slash or last == first_slash + 1) return error.BadPcre;
    var trigger_text = text[0..first_slash];
    var pcre: ir.PcreSubsig = .{ .trigger = &.{}, .pattern = text[first_slash + 1 .. last], .program = &.{} };
    if (std.mem.indexOfScalar(u8, trigger_text, ':')) |colon| {
        pcre.offset = ndb.parseOffset(trigger_text[0..colon]) catch |err| return switch (err) {
            error.VersionInfoUnsupported => error.VersionInfoUnsupported,
            else => error.BadPcre,
        };
        if (ndb.needsExecutable(pcre.offset.kind) and !ndb.isExecutableTarget(target)) return error.OffsetNeedsExecutable;
        trigger_text = trigger_text[colon + 1 ..];
    }
    if (index == 0 or trigger_text.len == 0) return error.BadPcre;
    pcre.trigger = parseExpression(arena, trigger_text, index, index) catch return error.BadPcre;
    var zeros: [ir.max_subsigs]u32 = @splat(0);
    if (ldb_table.evalRpn(pcre.trigger, zeros[0..index])) return error.ExprTrueWithoutHits;

    var flags: regex_flags = .{ .bytes = true };
    var ungreedy = false;
    for (text[last + 1 ..]) |c| switch (c) {
        'g' => pcre.flags.global = true,
        'r' => pcre.flags.rolling = true,
        'e' => pcre.flags.encompass = true,
        'A' => pcre.flags.anchored = true,
        'i' => flags.case_insensitive = true,
        's' => flags.dot_all = true,
        'm' => flags.multiline = true,
        'x' => flags.extended = true,
        'E' => {},
        'U' => ungreedy = true,
        else => return error.BadPcre,
    };
    if (pcre.flags.encompass and pcre.offset.shift == 0) return error.BadPcre;
    if (ungreedy and pcre.flags.global) return error.PcreFlagUnsupported;
    pcre.program = try cdb.compileRegex(arena, pcre.pattern, flags);
    return pcre;
}

const regex_flags = @import("regex").common.CompileFlags;

test "pcre subsignatures: offsets, triggers, flags, compile failures" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const p = try parsePcre(a, "200,300:0&1/eval\\(unescape/gie", 11, 2, 0);
    try testing.expectEqual(ir.OffsetKind.absolute, p.offset.kind);
    try testing.expectEqual(@as(u32, 300), p.offset.shift);
    try testing.expect(p.flags.global and p.flags.encompass and !p.flags.rolling);
    try testing.expectEqualStrings("eval\\(unescape", p.pattern);
    try testing.expectEqual(@as(usize, 3), p.trigger.len);
    const q = try parsePcre(a, "0/\\x4d\\x5a.{2}\\x50\\x45/sA", 1, 1, 0);
    try testing.expect(q.flags.anchored);
    // ClamAV's commonest PCRE shapes: repeated alternations and lazy repeats compile.
    for ([_][]const u8{
        "0/(?:\\x90|\\xcc){4,}/",
        "0/(?:%[0-9a-f]{2}|\\\\x[0-9a-f]{2}){8,}/i",
        "0/eval\\((?:unescape|atob|String\\.fromCharCode)\\(/",
        "0/<script.+?>/is",
        "0/a(?:b|c)+?d/",
    }) |pcre| _ = try parsePcre(a, pcre, 1, 1, 0);
    const Bad = struct { []const u8, usize, LineError };
    for ([_]Bad{
        .{ "0//", 1, error.BadPcre },
        .{ "0/abc", 1, error.BadPcre },
        .{ "1/abc/", 1, error.BadPcre }, // names itself
        .{ "/abc/", 1, error.BadPcre },
        .{ "0/abc/q", 1, error.BadPcre },
        .{ "0/abc/e", 1, error.BadPcre }, // e needs a maxshift
        .{ "0/abc/gU", 1, error.PcreFlagUnsupported },
        .{ "0=0/abc/", 1, error.ExprTrueWithoutHits },
        .{ "EP+0:0/abc/", 1, error.OffsetNeedsExecutable },
        .{ "0/(ab/", 1, error.RegexSyntax },
        .{ "0/(a)\\1/", 1, error.RegexUnsupported },
    }) |c| try testing.expectError(c[2], parsePcre(a, c[0], std.mem.indexOfScalar(u8, c[0], '/').?, c[1], 0));
}

const testing = std.testing;

fn exprText(arena: std.mem.Allocator, ops: []const ir.RpnOp) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    for (ops) |op| switch (op.code) {
        .sub => try w.writer.print("{d} ", .{op.index}),
        .@"and" => try w.writer.writeAll("& "),
        .@"or" => try w.writer.writeAll("| "),
        .eq, .gt, .lt => {
            try w.writer.print("{s}{d}", .{ switch (op.code) {
                .eq => "=",
                .gt => ">",
                else => "<",
            }, op.k });
            if (op.distinct != 0) try w.writer.print(",{d}", .{op.distinct});
            try w.writer.writeByte(' ');
        },
        _ => unreachable,
    };
    return w.written();
}

test "expressions compile to RPN with & binding tighter than |" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const Case = struct { []const u8, []const u8 };
    for ([_]Case{
        .{ "0", "0 " },
        .{ "0&1", "0 1 & " },
        .{ "0|1&2", "0 1 2 & | " },
        .{ "(0|1)&2", "0 1 | 2 & " },
        .{ "0=0", "0 =0 " },
        .{ "(0|1|2)>2,2", "0 1 | 2 | >2,2 " },
        .{ "((0&1)=2|2<3)&3", "0 1 & =2 2 <3 | 3 & " },
    }) |c| try testing.expectEqualStrings(c[1], try exprText(a, try parseExpression(a, c[0], 4, 4)));
    for ([_][]const u8{ "", "4", "0&", "(0", "0)", "0>", "0>1,", "a", "0&&1", "0=99999999999", "0>1,65" }) |bad| {
        try testing.expectError(error.BadExpression, parseExpression(a, bad, 4, 4));
    }
    var deep: std.ArrayList(u8) = .empty;
    for (0..ir.max_rpn_depth + 1) |_| try deep.append(a, '(');
    try deep.append(a, '0');
    for (0..ir.max_rpn_depth + 1) |_| try deep.append(a, ')');
    try testing.expectError(error.BadExpression, parseExpression(a, deep.items, 4, 4));
}

test "target description blocks" {
    var lo: u16 = 0;
    var hi: u16 = 0;
    const t = try parseTdb("Engine:81-255,Target:1,FileSize:100-2000,EntryPoint:4096,NumberOfSections:2-5,Container:CL_TYPE_ZIP", &lo, &hi);
    try testing.expectEqual(@as(u16, 81), lo);
    try testing.expectEqual(@as(u16, 255), hi);
    try testing.expectEqual(@as(u8, 1), t.target);
    try testing.expectEqual(ir.Range{ .lo = 100, .hi = 2000 }, t.file_size.?);
    try testing.expectEqual(ir.Range{ .lo = 4096, .hi = 4096 }, t.entry_point.?);
    try testing.expectEqual(@backingInt(types.ClType.zip), t.container.?);
    const i = try parseTdb("Target:0,Intermediates:CL_TYPE_ANY>CL_TYPE_ZIP>CL_TYPE_MSOLE2", &lo, &hi);
    try testing.expectEqual(@as(u8, 3), i.intermediate_count);
    try testing.expectEqual(@backingInt(types.ClType.msole2), i.intermediates[2]);

    const Bad = struct { []const u8, LineError };
    for ([_]Bad{
        .{ "Target", error.BadTdb },
        .{ "Bogus:1", error.BadTdb },
        .{ "Target:1,Target:2", error.BadTdb },
        .{ "Target:15", error.BadTarget },
        .{ "FileSize:200-100", error.BadTdb },
        .{ "FileSize:x", error.BadTdb },
        .{ "Engine:51-99999", error.BadFlevel },
        .{ "Container:CL_TYPE_NOPE", error.UnknownFileType },
        .{ "Container:CL_TYPE_ZIP,Intermediates:CL_TYPE_ZIP", error.BadTdb },
        .{ "Target:1,IconGroup1:EVIL", error.IconUnsupported },
        .{ "HandlerType:CL_TYPE_MSEXE", error.HandlerTypeUnsupported },
    }) |c| try testing.expectError(c[1], parseTdb(c[0], &lo, &hi));
}

test "ldb lines: subsignatures with offsets and modifiers, and every rejection" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var column: u32 = 0;
    const r = try parseLine(a, "Win.Trojan.L-1-0;Engine:81-255,Target:1;0&1&2;EP+0:e8??;6b65726e656c33322e646c6c::iw;aabb{2-4}ccdd", &column);
    try testing.expectEqualStrings("Win.Trojan.L-1-0", r.name);
    try testing.expectEqual(@as(usize, 3), r.subsigs.len);
    try testing.expectEqual(ir.OffsetKind.entry_point, r.subsigs[0].hex.offset.kind);
    try testing.expect(r.subsigs[1].hex.mods.nocase and r.subsigs[1].hex.mods.wide);
    try testing.expectEqual(@as(usize, 2), r.subsigs[2].hex.pattern.partCount());
    try testing.expectEqual(@as(u16, 81), r.flevel_min);

    const Bad = struct { []const u8, LineError, u32 };
    for ([_]Bad{
        .{ "X;Target:0;0", error.FieldCount, 0 },
        .{ ";Target:0;0;aabb", error.EmptyName, 0 },
        .{ "X;Target:0;0&2;aabb;ccdd", error.BadExpression, 11 },
        .{ "X;Target:0;0=0;aabb", error.ExprTrueWithoutHits, 11 },
        .{ "X;Target:0;0|1=0;aabb;ccdd", error.ExprTrueWithoutHits, 11 },
        .{ "X;Target:0;0;EP+0:aabb", error.OffsetNeedsExecutable, 13 },
        .{ "X;Target:1;0;VI:aabb", error.VersionInfoUnsupported, 13 },
        .{ "X;Target:0;0;aabb::q", error.BadModifier, 13 },
        .{ "X;Target:0;0;aa(bb", error.BadAlternation, 15 },
        .{ "X;Target:0;0;10:aa(bb", error.BadAlternation, 18 },
        .{ "X;Target:0;0&1;aabb;1/abc/", error.BadPcre, 20 },
        .{ "X;Target:0;0&1;aabb;0/abc/q", error.BadPcre, 20 },
        .{ "X;Target:0;0&1;aabb;0//", error.BadPcre, 20 },
        .{ "X;Target:0;0&1;aabb;${6-7}12$", error.MacroUnsupported, 20 },
        .{ "X;Target:0;0&1;aabb;0(>>4#ib3#=0x10)", error.BadByteCompare, 20 },
        .{ "X;Target:0;0&1;aabb;1(>>4#ib2#=0x10)", error.BadByteCompare, 20 },
        .{ "X;Target:0;0&1&2;aabb;0(>>4#ib2#=1);1(>>1#d2#=1)", error.BadByteCompare, 36 },
        .{ "X;Target:5;0&1;fuzzy_img#af2ad01ed42993c7#0;aabb", error.FuzzyImageUnsupported, 15 },
        .{ "X;Target:0,IconGroup1:A;0;aabb", error.IconUnsupported, 2 },
    }) |c| {
        try testing.expectError(c[1], parseLine(a, c[0], &column));
        try testing.expectEqual(c[2], column);
    }

    // 64 subsigs is the limit.
    var line: std.ArrayList(u8) = .empty;
    try line.appendSlice(a, "X;Target:0;0");
    for (0..ir.max_subsigs) |_| try line.appendSlice(a, ";aabb");
    _ = try parseLine(a, line.items, &column);
    try line.appendSlice(a, ";aabb");
    try testing.expectError(error.TooManySubsigs, parseLine(a, line.items, &column));
}
