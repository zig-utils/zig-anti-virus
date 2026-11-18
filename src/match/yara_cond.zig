//! YARA_COND: compiled YARA conditions and their evaluator (docs/DESIGN.md section 4.3).
//!
//! A YARA rule is an LDB_TABLE record flagged `flag_yara` (its strings are the record's subsigs,
//! so matches feed the same sparse logical state) plus a condition program here: a small stack
//! machine over 64-bit integers with YARA's "undefined" value. Layout:
//!
//!     YaraHeader (32 bytes)
//!     rules:   [rule_count]YaraRecord (24 bytes)
//!     ops:     [op_count]CondOp (16 bytes)
//!     strings: [string_count]YaraString (8 bytes)   per rule, in string order
//!
//! Strings are verify programs (text and hex) or REGEX_POOL programs (regex strings). Rules whose
//! condition can hold with no string matched at all are flagged `always` and evaluated for every
//! file; every other rule only when one of its strings matched, as ClamAV drives YARA conditions
//! from string matches.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const lt = @import("ldb_table.zig");

pub const CondCode = enum(u8) {
    /// Push `k`.
    push = 1,
    filesize = 2,
    /// Push 1 if string `str` matched, else 0.
    found = 3,
    /// Push `#str`.
    count = 4,
    /// Pop offset; push whether `str` matched starting there.
    at = 5,
    /// Pop hi, then lo; push whether `str` matched starting in [lo, hi].
    in = 6,
    /// Pop i; push `@str[i]` (1-based), undefined when there is no such match.
    offset = 7,
    /// Pop an offset; push the integer read there (`k` holds the width in bytes, `str` is 1 for
    /// big-endian, 2 for signed, 3 for both). Undefined past the end of the data.
    read = 8,
    add = 10,
    sub = 11,
    mul = 12,
    div = 13,
    mod = 14,
    neg = 15,
    bnot = 16,
    band = 17,
    bor = 18,
    bxor = 19,
    shl = 20,
    shr = 21,
    eq = 30,
    ne = 31,
    lt = 32,
    le = 33,
    gt = 34,
    ge = 35,
    land = 40,
    lor = 41,
    lnot = 42,
    _,
};

pub const CondOp = extern struct {
    code: CondCode,
    str: u8 = 0,
    _pad: [6]u8 = @splat(0),
    k: i64 = 0,
};

pub const max_depth = 64;
pub const max_ops = 4096;

pub const YaraHeader = extern struct {
    magic: [4]u8 = "YARA".*,
    version: u32 = 1,
    rule_count: u32,
    op_count: u32,
    string_count: u32,
    _reserved: [12]u8 = @splat(0),
};

pub const flag_always: u8 = 1 << 0;
pub const flag_private: u8 = 1 << 1;

pub const YaraRecord = extern struct {
    /// The LDB_TABLE record holding the rule's strings as subsigs.
    ldb: u32,
    cond_off: u32,
    cond_len: u32,
    str_first: u32,
    nstr: u8,
    flags: u8 = 0,
    _pad: u16 = 0,
    _reserved: u32 = 0,
};

pub const kind_program: u8 = 0;
pub const kind_regex: u8 = 1;

pub const YaraString = extern struct {
    kind: u8,
    _pad: [3]u8 = @splat(0),
    /// REGEX_POOL index for regex strings.
    regex: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(CondOp) == 16);
    std.debug.assert(@sizeOf(YaraHeader) == 32);
    std.debug.assert(@sizeOf(YaraRecord) == 24);
    std.debug.assert(@sizeOf(YaraString) == 8);
}

/// Stack effect: values popped and pushed, or null for an unknown op.
fn effect(code: CondCode) ?struct { pop: u8, push: u8 } {
    return switch (code) {
        .push, .filesize, .found, .count => .{ .pop = 0, .push = 1 },
        .at, .offset, .read, .neg, .bnot, .lnot => .{ .pop = 1, .push = 1 },
        .in => .{ .pop = 2, .push = 1 },
        .add, .sub, .mul, .div, .mod, .band, .bor, .bxor, .shl, .shr, .eq, .ne, .lt, .le, .gt, .ge, .land, .lor => .{ .pop = 2, .push = 1 },
        _ => null,
    };
}

/// Whether `ops` is a well-formed condition over `nstr` strings with a bounded stack.
pub fn check(ops: []const CondOp, nstr: usize) bool {
    if (ops.len == 0 or ops.len > max_ops) return false;
    var depth: usize = 0;
    for (ops) |op| {
        const e = effect(op.code) orelse return false;
        switch (op.code) {
            .found, .count, .at, .in, .offset => if (op.str >= nstr) return false,
            .read => if (!(op.k == 1 or op.k == 2 or op.k == 4) or op.str > 3) return false,
            else => {},
        }
        if (depth < e.pop) return false;
        depth = depth - e.pop + e.push;
        if (depth > max_depth) return false;
    }
    return depth == 1;
}

/// What a condition sees of one string.
pub const StringState = struct {
    count: u32 = 0,
    /// Match starts, ascending; the first ones only when `overflow` is set.
    starts: []const u64 = &.{},
    overflow: bool = false,
};

pub const Input = struct {
    data: []const u8,
    filesize: u64,
    strings: []const StringState,
};

pub const Result = struct {
    matched: bool,
    /// A decision depended on match offsets beyond the ones kept: report a limit.
    limited: bool = false,
};

const Value = struct {
    v: i64 = 0,
    undef: bool = false,
    /// Only in the "without hits" analysis: the value depends on the file.
    unknown: bool = false,

    fn truth(x: Value) bool {
        return !x.undef and !x.unknown and x.v != 0;
    }
};

fn readInt(data: []const u8, off: i64, width: usize, flags: u8) ?i64 {
    if (off < 0) return null;
    const o: u64 = @intCast(off);
    if (o > data.len or data.len - o < width) return null;
    const bytes = data[@intCast(o)..][0..width];
    const big = flags & 1 != 0;
    const signed = flags & 2 != 0;
    const u: u64 = if (big) std.mem.readVarInt(u64, bytes, .big) else std.mem.readVarInt(u64, bytes, .little);
    if (!signed) return @intCast(u);
    const shift: u6 = @intCast(64 - width * 8);
    return @as(i64, @bitCast(u << shift)) >> shift;
}

/// Evaluate a checked condition.
pub fn evaluate(ops: []const CondOp, in_: Input) Result {
    var stack: [max_depth]Value = undefined;
    var sp: usize = 0;
    var limited = false;
    for (ops) |op| {
        switch (op.code) {
            .push => {
                stack[sp] = .{ .v = op.k };
                sp += 1;
            },
            .filesize => {
                stack[sp] = .{ .v = @intCast(@min(in_.filesize, std.math.maxInt(i64))) };
                sp += 1;
            },
            .found, .count => {
                const c = in_.strings[op.str].count;
                stack[sp] = .{ .v = if (op.code == .found) @intFromBool(c > 0) else c };
                sp += 1;
            },
            .at, .in, .offset => {
                const s = in_.strings[op.str];
                var lo: i64 = undefined;
                var hi: i64 = undefined;
                var undef = false;
                if (op.code == .in) {
                    const h = stack[sp - 1];
                    const l = stack[sp - 2];
                    sp -= 2;
                    lo = l.v;
                    hi = h.v;
                    undef = l.undef or h.undef;
                } else {
                    const x = stack[sp - 1];
                    sp -= 1;
                    lo = x.v;
                    hi = x.v;
                    undef = x.undef;
                }
                var out: Value = .{};
                if (undef) {
                    out.undef = true;
                } else if (op.code == .offset) {
                    if (lo >= 1 and lo <= s.starts.len) {
                        out.v = @intCast(s.starts[@intCast(lo - 1)]);
                    } else {
                        out.undef = true;
                        if (s.overflow and lo >= 1 and lo <= s.count) limited = true;
                    }
                } else {
                    const hit = for (s.starts) |st| {
                        if (@as(i64, @intCast(st)) >= lo and @as(i64, @intCast(st)) <= hi) break true;
                    } else false;
                    if (!hit and s.overflow) limited = true;
                    out.v = @intFromBool(hit);
                }
                stack[sp] = out;
                sp += 1;
            },
            .read => {
                const x = stack[sp - 1];
                const width: usize = @intCast(op.k);
                stack[sp - 1] = if (x.undef) .{ .undef = true } else if (readInt(in_.data, x.v, width, op.str)) |v| .{ .v = v } else .{ .undef = true };
            },
            .neg, .bnot, .lnot => {
                const x = stack[sp - 1];
                stack[sp - 1] = switch (op.code) {
                    .neg => .{ .v = -%x.v, .undef = x.undef },
                    .bnot => .{ .v = ~x.v, .undef = x.undef },
                    else => if (x.undef) .{ .undef = true } else .{ .v = @intFromBool(x.v == 0) },
                };
            },
            else => {
                const b = stack[sp - 1];
                const a = stack[sp - 2];
                sp -= 1;
                stack[sp - 1] = binary(op.code, a, b);
            },
        }
    }
    return .{ .matched = stack[0].truth(), .limited = limited };
}

fn binary(code: CondCode, a: Value, b: Value) Value {
    switch (code) {
        .land => {
            if ((!a.undef and !a.unknown and a.v == 0) or (!b.undef and !b.unknown and b.v == 0)) return .{ .v = 0 };
            if (a.unknown or b.unknown) return .{ .unknown = true };
            if (a.undef or b.undef) return .{ .v = 0 };
            return .{ .v = 1 };
        },
        .lor => {
            if (a.truth() or b.truth()) return .{ .v = 1 };
            if (a.unknown or b.unknown) return .{ .unknown = true };
            return .{ .v = 0 };
        },
        else => {},
    }
    if (a.unknown or b.unknown) return .{ .unknown = true };
    if (a.undef or b.undef) return .{ .undef = true };
    const x = a.v;
    const y = b.v;
    return switch (code) {
        .add => .{ .v = x +% y },
        .sub => .{ .v = x -% y },
        .mul => .{ .v = x *% y },
        .div => if (y == 0 or (x == std.math.minInt(i64) and y == -1)) .{ .undef = true } else .{ .v = @divTrunc(x, y) },
        .mod => if (y == 0 or (x == std.math.minInt(i64) and y == -1)) .{ .undef = true } else .{ .v = @rem(x, y) },
        .band => .{ .v = x & y },
        .bor => .{ .v = x | y },
        .bxor => .{ .v = x ^ y },
        .shl => .{ .v = if (y < 0 or y >= 64) 0 else x << @intCast(y) },
        .shr => .{ .v = if (y < 0 or y >= 64) 0 else x >> @intCast(y) },
        .eq => .{ .v = @intFromBool(x == y) },
        .ne => .{ .v = @intFromBool(x != y) },
        .lt => .{ .v = @intFromBool(x < y) },
        .le => .{ .v = @intFromBool(x <= y) },
        .gt => .{ .v = @intFromBool(x > y) },
        .ge => .{ .v = @intFromBool(x >= y) },
        else => .{ .undef = true },
    };
}

/// Whether the condition can hold for some file in which no string matched: every string
/// count is 0 and anything read from the file (its size, integers at offsets) is unknown.
pub fn canMatchWithoutHits(ops: []const CondOp) bool {
    var stack: [max_depth]Value = undefined;
    var sp: usize = 0;
    for (ops) |op| {
        switch (op.code) {
            .push => {
                stack[sp] = .{ .v = op.k };
                sp += 1;
            },
            .filesize => {
                stack[sp] = .{ .unknown = true };
                sp += 1;
            },
            .found, .count => {
                stack[sp] = .{ .v = 0 };
                sp += 1;
            },
            .at, .offset => {
                stack[sp - 1] = if (op.code == .at) .{ .v = 0 } else .{ .undef = true };
            },
            .in => {
                sp -= 1;
                stack[sp - 1] = .{ .v = 0 };
            },
            .read => stack[sp - 1] = .{ .unknown = true },
            .neg, .bnot, .lnot => {
                const x = stack[sp - 1];
                stack[sp - 1] = if (x.unknown) .{ .unknown = true } else switch (op.code) {
                    .neg => .{ .v = -%x.v, .undef = x.undef },
                    .bnot => .{ .v = ~x.v, .undef = x.undef },
                    else => if (x.undef) .{ .undef = true } else .{ .v = @intFromBool(x.v == 0) },
                };
            },
            else => {
                const b = stack[sp - 1];
                const a = stack[sp - 2];
                sp -= 1;
                stack[sp - 1] = binary(op.code, a, b);
            },
        }
    }
    const r = stack[0];
    return r.unknown or r.truth();
}

pub const YaraTable = struct {
    rules: []const YaraRecord,
    ops: []const CondOp,
    strings: []const YaraString,

    pub const Error = error{BadYaraTable};

    /// Validate against the LDB records the rules live in (each must be flagged `flag_yara`
    /// with one subsig per string) and the REGEX_POOL size.
    pub fn init(section: []const u8, records: []const lt.LdbRecord, regex_count: usize) Error!YaraTable {
        if (section.len < @sizeOf(YaraHeader) or @intFromPtr(section.ptr) % 8 != 0) return error.BadYaraTable;
        const h: *const YaraHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "YARA") or h.version != 1) return error.BadYaraTable;
        const rules_at = @sizeOf(YaraHeader);
        const ops_at = std.mem.alignForward(usize, rules_at + @as(usize, h.rule_count) * @sizeOf(YaraRecord), 8);
        const str_at = ops_at + @as(usize, h.op_count) * @sizeOf(CondOp);
        if (str_at + @as(usize, h.string_count) * @sizeOf(YaraString) > section.len) return error.BadYaraTable;
        const r: [*]const YaraRecord = @ptrCast(@alignCast(section.ptr + rules_at));
        const o: [*]const CondOp = @ptrCast(@alignCast(section.ptr + ops_at));
        const st: [*]const YaraString = @ptrCast(@alignCast(section.ptr + str_at));
        const t: YaraTable = .{ .rules = r[0..h.rule_count], .ops = o[0..h.op_count], .strings = st[0..h.string_count] };
        var prev_ldb: i64 = -1;
        for (t.rules) |rule| {
            // Sorted by LDB record so finalize can binary-search.
            if (rule.ldb >= records.len or @as(i64, rule.ldb) <= prev_ldb) return error.BadYaraTable;
            prev_ldb = rule.ldb;
            const rec = records[rule.ldb];
            if (rec.flags & lt.flag_yara == 0 or rule.nstr == 0 or rule.nstr > ir.max_subsigs or rule.nstr != rec.nsub) return error.BadYaraTable;
            if (rule.flags & ~(flag_always | flag_private) != 0) return error.BadYaraTable;
            if (@as(u64, rule.cond_off) + rule.cond_len > h.op_count) return error.BadYaraTable;
            if (!check(t.ops[rule.cond_off..][0..rule.cond_len], rule.nstr)) return error.BadYaraTable;
            if (@as(u64, rule.str_first) + rule.nstr > h.string_count) return error.BadYaraTable;
            for (t.strings[rule.str_first..][0..rule.nstr]) |s| switch (s.kind) {
                kind_program => {},
                kind_regex => if (s.regex >= regex_count) return error.BadYaraTable,
                else => return error.BadYaraTable,
            };
        }
        return t;
    }

    /// The rule stored for LDB record `ldb`.
    pub fn find(t: YaraTable, ldb: u32) ?YaraRecord {
        var lo: usize = 0;
        var hi: usize = t.rules.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.rules[mid].ldb < ldb) lo = mid + 1 else hi = mid;
        }
        return if (lo < t.rules.len and t.rules[lo].ldb == ldb) t.rules[lo] else null;
    }

    pub fn condition(t: YaraTable, rule: YaraRecord) []const CondOp {
        return t.ops[rule.cond_off..][0..rule.cond_len];
    }

    pub fn ruleStrings(t: YaraTable, rule: YaraRecord) []const YaraString {
        return t.strings[rule.str_first..][0..rule.nstr];
    }
};

pub const RuleInput = struct {
    ldb: u32,
    cond: []const CondOp,
    strings: []const YaraString,
    flags: u8,
};

/// Build the section; `rules` must be sorted by `ldb`.
pub fn build(gpa: std.mem.Allocator, rules: []const RuleInput) ![]u8 {
    var op_count: usize = 0;
    var string_count: usize = 0;
    for (rules) |r| {
        op_count += r.cond.len;
        string_count += r.strings.len;
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const h: YaraHeader = .{ .rule_count = @intCast(rules.len), .op_count = @intCast(op_count), .string_count = @intCast(string_count) };
    try out.appendSlice(gpa, std.mem.asBytes(&h));
    var cond_off: u32 = 0;
    var str_first: u32 = 0;
    for (rules) |r| {
        const rec: YaraRecord = .{ .ldb = r.ldb, .cond_off = cond_off, .cond_len = @intCast(r.cond.len), .str_first = str_first, .nstr = @intCast(r.strings.len), .flags = r.flags };
        try out.appendSlice(gpa, std.mem.asBytes(&rec));
        cond_off += @intCast(r.cond.len);
        str_first += @intCast(r.strings.len);
    }
    while (out.items.len % 8 != 0) try out.append(gpa, 0);
    for (rules) |r| try out.appendSlice(gpa, std.mem.sliceAsBytes(r.cond));
    for (rules) |r| try out.appendSlice(gpa, std.mem.sliceAsBytes(r.strings));
    return out.toOwnedSlice(gpa);
}

const testing = std.testing;

fn mk(code: CondCode, str: u8, k: i64) CondOp {
    return .{ .code = code, .str = str, .k = k };
}

test "condition evaluation: counts, offsets, reads, arithmetic and undefined" {
    const data = "MZ\x90\x00\x04\x00\x00\x00PE\x00\x00";
    const starts0 = [_]u64{ 2, 9 };
    const strings = [_]StringState{ .{ .count = 2, .starts = &starts0 }, .{} };
    const in_: Input = .{ .data = data, .filesize = data.len, .strings = &strings };
    const Case = struct { []const CondOp, bool };
    for ([_]Case{
        // uint16(0) == 0x5a4d and #a == 2
        .{ &.{ mk(.push, 0, 0), mk(.read, 0, 2), mk(.push, 0, 0x5a4d), mk(.eq, 0, 0), mk(.count, 0, 0), mk(.push, 0, 2), mk(.eq, 0, 0), mk(.land, 0, 0) }, true },
        // $a at 9, $a at 3
        .{ &.{ mk(.push, 0, 9), mk(.at, 0, 0) }, true },
        .{ &.{ mk(.push, 0, 3), mk(.at, 0, 0) }, false },
        // $a in (3..9)
        .{ &.{ mk(.push, 0, 3), mk(.push, 0, 9), mk(.in, 0, 0) }, true },
        // @a[2] == 9, @a[3] undefined compares false, and so does not (@a[3] == 0)
        .{ &.{ mk(.push, 0, 2), mk(.offset, 0, 0), mk(.push, 0, 9), mk(.eq, 0, 0) }, true },
        .{ &.{ mk(.push, 0, 3), mk(.offset, 0, 0), mk(.push, 0, 0), mk(.eq, 0, 0) }, false },
        .{ &.{ mk(.push, 0, 3), mk(.offset, 0, 0), mk(.push, 0, 0), mk(.eq, 0, 0), mk(.lnot, 0, 0) }, false },
        // uint32(4) + 4 == 8, uint32be(8) == 0x50450000, a read past the end is undefined
        .{ &.{ mk(.push, 0, 4), mk(.read, 0, 4), mk(.push, 0, 4), mk(.add, 0, 0), mk(.push, 0, 8), mk(.eq, 0, 0) }, true },
        .{ &.{ mk(.push, 0, 8), mk(.read, 1, 4), mk(.push, 0, 0x50450000), mk(.eq, 0, 0) }, true },
        .{ &.{ mk(.push, 0, 11), mk(.read, 0, 4), mk(.push, 0, 0), mk(.ne, 0, 0) }, false },
        // int8(2) == -112 (0x90 signed)
        .{ &.{ mk(.push, 0, 2), mk(.read, 2, 1), mk(.push, 0, -112), mk(.eq, 0, 0) }, true },
        // not $b and filesize < 100; ~0 == -1; 7 \ 0 is undefined
        .{ &.{ mk(.found, 1, 0), mk(.lnot, 0, 0), mk(.filesize, 0, 0), mk(.push, 0, 100), mk(.lt, 0, 0), mk(.land, 0, 0) }, true },
        .{ &.{ mk(.push, 0, 0), mk(.bnot, 0, 0), mk(.push, 0, -1), mk(.eq, 0, 0) }, true },
        .{ &.{ mk(.push, 0, 7), mk(.push, 0, 0), mk(.div, 0, 0), mk(.push, 0, 0), mk(.ge, 0, 0) }, false },
    }) |c| {
        try testing.expect(check(c[0], 2));
        try testing.expectEqual(c[1], evaluate(c[0], in_).matched);
    }
    // Offsets past the kept ones: a limit, not a silent false.
    const overflowed = [_]StringState{ .{ .count = 40, .starts = &starts0, .overflow = true }, .{} };
    const r = evaluate(&.{ mk(.push, 0, 1000), mk(.at, 0, 0) }, .{ .data = data, .filesize = data.len, .strings = &overflowed });
    try testing.expect(!r.matched and r.limited);
    // Malformed programs.
    try testing.expect(!check(&.{mk(.land, 0, 0)}, 1));
    try testing.expect(!check(&.{mk(.found, 3, 0)}, 2));
    try testing.expect(!check(&.{ mk(.push, 0, 1), mk(.push, 0, 1) }, 1));
    try testing.expect(!check(&.{ mk(.push, 0, 0), mk(.read, 0, 3) }, 1));
}

test "conditions that can hold without any string match" {
    try testing.expect(!canMatchWithoutHits(&.{mk(.found, 0, 0)}));
    // $a and filesize < 10
    try testing.expect(!canMatchWithoutHits(&.{ mk(.found, 0, 0), mk(.filesize, 0, 0), mk(.push, 0, 10), mk(.lt, 0, 0), mk(.land, 0, 0) }));
    // not $a
    try testing.expect(canMatchWithoutHits(&.{ mk(.found, 0, 0), mk(.lnot, 0, 0) }));
    // $a or uint16(0) == 0x5a4d
    try testing.expect(canMatchWithoutHits(&.{ mk(.found, 0, 0), mk(.push, 0, 0), mk(.read, 0, 2), mk(.push, 0, 0x5a4d), mk(.eq, 0, 0), mk(.lor, 0, 0) }));
    // #a == 0
    try testing.expect(canMatchWithoutHits(&.{ mk(.count, 0, 0), mk(.push, 0, 0), mk(.eq, 0, 0) }));
    // ($a or not $a) runs regardless, as ClamAV's documentation suggests
    try testing.expect(canMatchWithoutHits(&.{ mk(.found, 0, 0), mk(.found, 0, 0), mk(.lnot, 0, 0), mk(.lor, 0, 0) }));
}
