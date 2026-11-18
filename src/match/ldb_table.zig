//! LDB_TABLE: one record per logical signature (docs/DESIGN.md 3.4), plus the RPN evaluator.
//!
//! Layout, little-endian and offset based:
//!
//!     LdbHeader (32 bytes)
//!     records: [count]LdbRecord (32 bytes)   {sig, nsub, flags, expr_len, expr_off, prog range}
//!     rpn:     [rpn_count]ir.RpnOp (8 bytes)
//!     tdbs:    [count]TdbRecord (96 bytes)    record i's target description
//!
//! A record's subsignature programs are a contiguous range of SUBSIG_PROG, each flagged as a
//! logical subsig and pointing back at the record. `LdbTable.init` checks all of that, and that
//! every expression only names its own subsigs and evaluates on a bounded stack.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const prog = @import("prog.zig");

pub const LdbHeader = extern struct {
    magic: [4]u8 = "LDBT".*,
    version: u32 = 1,
    count: u32,
    rpn_count: u32,
    bc_count: u32 = 0,
    _reserved: [12]u8 = @splat(0),
};

/// Record flag: the expression compares counts, so per-subsig counters are needed.
pub const flag_counts: u8 = 1 << 0;

pub const LdbRecord = extern struct {
    /// Signature id (sigmeta).
    sig: u32,
    nsub: u8,
    flags: u8 = 0,
    expr_len: u16,
    expr_off: u32,
    prog_first: u32,
    prog_count: u32,
    /// Byte-compare subsigs (P4.12): range in the byte-compare array.
    bc_first: u32 = 0,
    bc_count: u16 = 0,
    _pad: u16 = 0,
    _reserved: u32 = 0,
};

pub const tdb_file_size: u8 = 1 << 0;
pub const tdb_entry_point: u8 = 1 << 1;
pub const tdb_sections: u8 = 1 << 2;
pub const tdb_container: u8 = 1 << 3;

pub const TdbRecord = extern struct {
    flags: u8 = 0,
    target: u8 = 0,
    intermediate_count: u8 = 0,
    _pad0: u8 = 0,
    container: u16 = 0,
    _pad1: u16 = 0,
    file_size_lo: u64 = 0,
    file_size_hi: u64 = 0,
    entry_point_lo: u64 = 0,
    entry_point_hi: u64 = 0,
    sections_lo: u64 = 0,
    sections_hi: u64 = 0,
    intermediates: [ir.max_intermediates]u16 = @splat(0),
    _reserved: [8]u8 = @splat(0),

    pub fn from(t: ir.Tdb) TdbRecord {
        var r: TdbRecord = .{ .target = t.target, .intermediate_count = t.intermediate_count, .intermediates = t.intermediates };
        if (t.file_size) |x| {
            r.flags |= tdb_file_size;
            r.file_size_lo = x.lo;
            r.file_size_hi = x.hi;
        }
        if (t.entry_point) |x| {
            r.flags |= tdb_entry_point;
            r.entry_point_lo = x.lo;
            r.entry_point_hi = x.hi;
        }
        if (t.sections) |x| {
            r.flags |= tdb_sections;
            r.sections_lo = x.lo;
            r.sections_hi = x.hi;
        }
        if (t.container) |c| {
            r.flags |= tdb_container;
            r.container = c;
        }
        return r;
    }
};

comptime {
    std.debug.assert(@sizeOf(LdbHeader) == 32);
    std.debug.assert(@sizeOf(LdbRecord) == 32);
    std.debug.assert(@sizeOf(TdbRecord) == 96);
    std.debug.assert(@offsetOf(TdbRecord, "file_size_lo") == 8);
}

/// One stack value during evaluation.
const Value = struct {
    count: u32,
    mask: u64,
    truth: bool,
};

/// Evaluate an expression over per-subsig match counts. The expression must have passed
/// `checkRpn` for `counts.len` subsigs.
pub fn evalRpn(ops: []const ir.RpnOp, counts: []const u32) bool {
    var stack: [ir.max_rpn_depth]Value = undefined;
    var sp: usize = 0;
    for (ops) |op| switch (op.code) {
        .sub => {
            const c = counts[op.index];
            stack[sp] = .{ .count = c, .mask = if (c > 0) @as(u64, 1) << @intCast(op.index) else 0, .truth = c > 0 };
            sp += 1;
        },
        .@"and", .@"or" => {
            const b = stack[sp - 1];
            const a = stack[sp - 2];
            sp -= 1;
            stack[sp - 1] = .{
                .count = a.count +| b.count,
                .mask = a.mask | b.mask,
                .truth = if (op.code == .@"and") a.truth and b.truth else a.truth or b.truth,
            };
        },
        .eq, .gt, .lt => {
            const x = &stack[sp - 1];
            const cmp = switch (op.code) {
                .eq => x.count == op.k,
                .gt => x.count > op.k,
                else => x.count < op.k,
            };
            x.truth = cmp and @popCount(x.mask) >= op.distinct;
        },
        _ => unreachable,
    };
    return stack[0].truth;
}

/// Whether `ops` is a well-formed expression over `nsub` subsigs: indices in range, the stack
/// never underflows or passes `max_rpn_depth`, and exactly one value is left.
pub fn checkRpn(ops: []const ir.RpnOp, nsub: usize) bool {
    var depth: usize = 0;
    for (ops) |op| switch (op.code) {
        .sub => {
            if (op.index >= nsub or op.index >= ir.max_subsigs or op.distinct != 0 or op.k != 0) return false;
            depth += 1;
            if (depth > ir.max_rpn_depth) return false;
        },
        .@"and", .@"or" => {
            if (depth < 2 or op.index != 0 or op.distinct != 0 or op.k != 0) return false;
            depth -= 1;
        },
        .eq, .gt, .lt => {
            if (depth < 1 or op.index != 0 or op.distinct > ir.max_subsigs) return false;
        },
        _ => return false,
    };
    return depth == 1;
}

pub fn usesCounts(ops: []const ir.RpnOp) bool {
    for (ops) |op| switch (op.code) {
        .eq, .gt, .lt => return true,
        else => {},
    };
    return false;
}

pub const LdbTable = struct {
    records: []const LdbRecord,
    rpn: []const ir.RpnOp,
    tdbs: []const TdbRecord,

    pub const Error = error{BadLdbTable};

    pub fn init(section: []const u8, programs: ?prog.Programs) Error!LdbTable {
        if (section.len < @sizeOf(LdbHeader) or @intFromPtr(section.ptr) % 8 != 0) return error.BadLdbTable;
        const h: *const LdbHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "LDBT") or h.version != 1) return error.BadLdbTable;
        const records_at = @sizeOf(LdbHeader);
        const rpn_at = records_at + @as(usize, h.count) * @sizeOf(LdbRecord);
        const tdb_at = std.mem.alignForward(usize, rpn_at + @as(usize, h.rpn_count) * @sizeOf(ir.RpnOp), 8);
        const end = tdb_at + @as(usize, h.count) * @sizeOf(TdbRecord);
        if (end > section.len) return error.BadLdbTable;
        const r: [*]const LdbRecord = @ptrCast(@alignCast(section.ptr + records_at));
        const o: [*]const ir.RpnOp = @ptrCast(@alignCast(section.ptr + rpn_at));
        const t: [*]const TdbRecord = @ptrCast(@alignCast(section.ptr + tdb_at));
        const table: LdbTable = .{ .records = r[0..h.count], .rpn = o[0..h.rpn_count], .tdbs = t[0..h.count] };
        const nprog = if (programs) |ps| ps.count() else 0;
        for (table.records, table.tdbs, 0..) |rec, tdb, i| {
            if (rec.nsub == 0 or rec.nsub > ir.max_subsigs) return error.BadLdbTable;
            if (@as(u64, rec.expr_off) + rec.expr_len > h.rpn_count) return error.BadLdbTable;
            if (!checkRpn(table.expr(rec), rec.nsub)) return error.BadLdbTable;
            if ((rec.flags & flag_counts != 0) != usesCounts(table.expr(rec))) return error.BadLdbTable;
            if (tdb.target > 14 or tdb.intermediate_count > ir.max_intermediates) return error.BadLdbTable;
            if (@as(u64, rec.prog_first) + rec.prog_count > nprog) return error.BadLdbTable;
            if (rec.bc_count != 0) return error.BadLdbTable;
            if (programs) |ps| for (rec.prog_first..rec.prog_first + rec.prog_count) |j| {
                const ph = ps.get(j).header;
                if (ph.flags & prog.flag_ldb == 0 or ph.sig != i or ph.subsig >= rec.nsub) return error.BadLdbTable;
            };
        }
        return table;
    }

    pub fn expr(table: LdbTable, rec: LdbRecord) []const ir.RpnOp {
        return table.rpn[rec.expr_off..][0..rec.expr_len];
    }
};

/// What target description predicates are checked against.
pub const FileContext = struct {
    target: u8 = 0,
    size: u64 = 0,
    entry_point: ?u64 = null,
    section_count: ?u64 = null,
    /// The immediate container's type (`fmt.types.ClType` value), 0 at the root.
    container: u16 = 0,
    /// Container types from the outermost down to the immediate container.
    intermediates: []const u16 = &.{},
};

/// Whether a file can satisfy a signature's target description at all.
pub fn tdbMatches(t: TdbRecord, ctx: FileContext) bool {
    if (t.target != 0 and t.target != ctx.target) return false;
    if (t.flags & tdb_file_size != 0 and (ctx.size < t.file_size_lo or ctx.size > t.file_size_hi)) return false;
    if (t.flags & tdb_entry_point != 0) {
        const ep = ctx.entry_point orelse return false;
        if (ep < t.entry_point_lo or ep > t.entry_point_hi) return false;
    }
    if (t.flags & tdb_sections != 0) {
        const n = ctx.section_count orelse return false;
        if (n < t.sections_lo or n > t.sections_hi) return false;
    }
    // CL_TYPE_ANY as the container means the file must be a root object.
    if (t.flags & tdb_container != 0 and t.container != ctx.container) return false;
    if (t.intermediate_count > 0) {
        const want = t.intermediates[0..t.intermediate_count];
        if (ctx.intermediates.len < want.len) return false;
        // The last listed type is the immediate container; CL_TYPE_ANY matches any layer.
        const have = ctx.intermediates[ctx.intermediates.len - want.len ..];
        for (want, have) |w, got| if (w != 0 and w != got) return false;
    }
    return true;
}

const testing = std.testing;

fn rpn(comptime spec: []const struct { ir.RpnCode, u16, u32, u8 }) [spec.len]ir.RpnOp {
    var out: [spec.len]ir.RpnOp = undefined;
    for (spec, &out) |s, *o| o.* = .{ .code = s[0], .index = s[1], .k = s[2], .distinct = s[3] };
    return out;
}

test "rpn evaluation: and, or, counts, distinct counts, negation" {
    // 0&1
    const and01 = rpn(&.{ .{ .sub, 0, 0, 0 }, .{ .sub, 1, 0, 0 }, .{ .@"and", 0, 0, 0 } });
    try testing.expect(checkRpn(&and01, 2));
    try testing.expect(evalRpn(&and01, &.{ 1, 3 }));
    try testing.expect(!evalRpn(&and01, &.{ 1, 0 }));
    // (0|1)>2
    const sum_gt = rpn(&.{ .{ .sub, 0, 0, 0 }, .{ .sub, 1, 0, 0 }, .{ .@"or", 0, 0, 0 }, .{ .gt, 0, 2, 0 } });
    try testing.expect(evalRpn(&sum_gt, &.{ 2, 1 }));
    try testing.expect(!evalRpn(&sum_gt, &.{ 1, 1 }));
    // (0|1|2)>1,2: more than one match and at least two distinct subsigs
    const distinct = rpn(&.{ .{ .sub, 0, 0, 0 }, .{ .sub, 1, 0, 0 }, .{ .@"or", 0, 0, 0 }, .{ .sub, 2, 0, 0 }, .{ .@"or", 0, 0, 0 }, .{ .gt, 0, 1, 2 } });
    try testing.expect(!evalRpn(&distinct, &.{ 5, 0, 0 }));
    try testing.expect(evalRpn(&distinct, &.{ 1, 0, 1 }));
    // 0&1=0: subsig 1 must not match
    const neg = rpn(&.{ .{ .sub, 0, 0, 0 }, .{ .sub, 1, 0, 0 }, .{ .eq, 0, 0, 0 }, .{ .@"and", 0, 0, 0 } });
    try testing.expect(evalRpn(&neg, &.{ 1, 0 }));
    try testing.expect(!evalRpn(&neg, &.{ 1, 1 }));
    // 0<3, 0=2
    try testing.expect(evalRpn(&rpn(&.{ .{ .sub, 0, 0, 0 }, .{ .lt, 0, 3, 0 } }), &.{2}));
    try testing.expect(!evalRpn(&rpn(&.{ .{ .sub, 0, 0, 0 }, .{ .eq, 0, 2, 0 } }), &.{3}));
    // Malformed expressions.
    try testing.expect(!checkRpn(&rpn(&.{.{ .@"and", 0, 0, 0 }}), 2));
    try testing.expect(!checkRpn(&rpn(&.{ .{ .sub, 0, 0, 0 }, .{ .sub, 1, 0, 0 } }), 2));
    try testing.expect(!checkRpn(&rpn(&.{.{ .sub, 2, 0, 0 }}), 2));
    try testing.expect(!checkRpn(&rpn(&.{.{ .gt, 0, 0, 0 }}), 2));
}

test "target description predicates" {
    const t = TdbRecord.from(.{ .target = 1, .file_size = .{ .lo = 100, .hi = 200 }, .entry_point = .{ .lo = 0, .hi = 64 }, .sections = .{ .lo = 2, .hi = 4 } });
    try testing.expect(tdbMatches(t, .{ .target = 1, .size = 150, .entry_point = 10, .section_count = 3 }));
    try testing.expect(!tdbMatches(t, .{ .target = 1, .size = 250, .entry_point = 10, .section_count = 3 }));
    try testing.expect(!tdbMatches(t, .{ .target = 6, .size = 150, .entry_point = 10, .section_count = 3 }));
    try testing.expect(!tdbMatches(t, .{ .target = 1, .size = 150, .section_count = 3 }));
    try testing.expect(!tdbMatches(t, .{ .target = 1, .size = 150, .entry_point = 10, .section_count = 5 }));
    var inter: ir.Tdb = .{ .intermediate_count = 2 };
    inter.intermediates[0] = 0; // any
    inter.intermediates[1] = 7;
    const ti = TdbRecord.from(inter);
    try testing.expect(tdbMatches(ti, .{ .intermediates = &.{ 3, 9, 7 } }));
    try testing.expect(!tdbMatches(ti, .{ .intermediates = &.{ 3, 7, 9 } }));
    try testing.expect(!tdbMatches(ti, .{ .intermediates = &.{7} }));
    const root = TdbRecord.from(.{ .container = 0 });
    try testing.expect(tdbMatches(root, .{}));
    try testing.expect(!tdbMatches(root, .{ .container = 5 }));
}
