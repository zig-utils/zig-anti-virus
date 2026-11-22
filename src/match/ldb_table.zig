//! LDB_TABLE: one record per logical signature (docs/DESIGN.md 3.4), plus the RPN evaluator.
//!
//! Layout, little-endian and offset based:
//!
//!     LdbHeader (32 bytes)
//!     records: [count]LdbRecord (32 bytes)   {sig, nsub, flags, expr_len, expr_off, prog range}
//!     rpn:     [rpn_count]ir.RpnOp (8 bytes)
//!     tdbs:    [tdb_count]TdbRecord (96 bytes) distinct target descriptions
//!     bcs:     [bc_count]BcRecord (32 bytes)  byte-compare subsigs, by record
//!     pcres:   [pcre_count]PcreRecord (24 bytes)  PCRE subsigs, by record, in subsig order
//!     always:  [always_count]u32               records evaluated for every file, ascending
//!     tdb_of:  [count]u32                      record i's target description in `tdbs`
//!
//! Target descriptions are stored once each (version 2): the 322,204 logical signatures of
//! main 63 and daily 28187 have 460 distinct ones, so the table no longer spends 96 bytes on
//! every record.
//!
//! libclamav evaluates a logical signature whose expression holds with no subsig matched
//! (`0=0`, `1<3`) for every file, so those records are listed and the scan gives them state
//! even when nothing touched them.
//!
//! PCRE triggers are RPN expressions in the same pool as the main expressions; PCRE programs
//! are REGEX_POOL entries.
//!
//! A record's subsignature programs are a contiguous range of SUBSIG_PROG, each flagged as a
//! logical subsig and pointing back at the record. `LdbTable.init` checks all of that, and that
//! every expression only names its own subsigs and evaluates on a bounded stack.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const prog = @import("prog.zig");
const regex_pool = @import("regex_pool.zig");

pub const LdbHeader = extern struct {
    magic: [4]u8 = "LDBT".*,
    version: u32 = 2,
    count: u32,
    rpn_count: u32,
    bc_count: u32 = 0,
    pcre_count: u32 = 0,
    /// Records whose expression holds with no subsig matched; listed after the PCRE records.
    always_count: u32 = 0,
    /// Distinct target descriptions.
    tdb_count: u32 = 0,
};

/// Record flag: the expression compares counts, so per-subsig counters are needed.
pub const flag_counts: u8 = 1 << 0;
/// Record flag: a YARA rule. Its condition lives in YARA_COND; the RPN expression is empty and
/// every subsig's match starts are kept for `at`, `in` and `@a[i]`.
pub const flag_yara: u8 = 1 << 1;

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
    /// PCRE subsigs: range in the PCRE array.
    pcre_count: u16 = 0,
    pcre_first: u32 = 0,
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
    /// HandlerType as a `fmt.types.ClType` value, 0 for none.
    handler: u16 = 0,
    file_size_lo: u64 = 0,
    file_size_hi: u64 = 0,
    entry_point_lo: u64 = 0,
    entry_point_hi: u64 = 0,
    sections_lo: u64 = 0,
    sections_hi: u64 = 0,
    intermediates: [ir.max_intermediates]u16 = @splat(0),
    _reserved: [8]u8 = @splat(0),

    pub fn from(t: ir.Tdb) TdbRecord {
        var r: TdbRecord = .{ .target = t.target, .intermediate_count = t.intermediate_count, .intermediates = t.intermediates, .handler = t.handler orelse 0 };
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

/// A byte-compare subsig (docs: LogicalSignatures, Byte Compare Subsignatures).
pub const BcRecord = extern struct {
    /// The subsig index this compare occupies in its signature.
    subsig: u8,
    /// The body subsig whose match starts are the reference points.
    trigger: u8,
    kind: ir.ByteKind,
    /// bit 0 big-endian, bit 1 exact, bit 2 backward offset
    flags: u8,
    width: u8,
    comparison_count: u8,
    ops: [2]ir.CmpOp,
    offset: u32,
    _pad: u32 = 0,
    values: [2]u64,

    pub const big_endian: u8 = 1 << 0;
    pub const exact: u8 = 1 << 1;
    pub const backward: u8 = 1 << 2;
    /// No byte order was written: the compare never holds.
    pub const no_order: u8 = 1 << 3;

    pub fn from(subsig: u8, bc: ir.ByteCompare) BcRecord {
        var r: BcRecord = .{
            .subsig = subsig,
            .trigger = bc.trigger,
            .kind = bc.kind,
            .flags = 0,
            .width = bc.width,
            .comparison_count = bc.comparison_count,
            .ops = .{ .eq, .eq },
            .offset = bc.offset,
            .values = .{ 0, 0 },
        };
        if (bc.big_endian) r.flags |= big_endian;
        if (bc.exact) r.flags |= exact;
        if (bc.backward) r.flags |= backward;
        if (bc.no_order) r.flags |= no_order;
        for (bc.comparisons[0..bc.comparison_count], 0..) |c, i| {
            r.ops[i] = c.op;
            r.values[i] = c.value;
        }
        return r;
    }
};

/// A PCRE subsig (docs: LogicalSignatures, PCRE subsignatures).
pub const PcreRecord = extern struct {
    subsig: u8,
    flags: ir.PcreFlags,
    trigger_len: u16,
    /// The trigger expression's first op in the RPN pool.
    trigger_off: u32,
    /// REGEX_POOL index of the program.
    regex: u32,
    off_kind: ir.OffsetKind,
    _pad: u8 = 0,
    off_section: u16,
    off_a: i32,
    off_shift: u32,

    pub fn offset(r: PcreRecord) ir.Offset {
        return .{ .kind = r.off_kind, .a = r.off_a, .section = r.off_section, .shift = r.off_shift };
    }
};

comptime {
    std.debug.assert(@sizeOf(PcreRecord) == 24);
    std.debug.assert(@sizeOf(BcRecord) == 32);
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
    /// Distinct target descriptions; `tdb(i)` is record i's.
    tdbs: []const TdbRecord,
    tdb_of: []const u32 = &.{},
    bcs: []const BcRecord,
    pcres: []const PcreRecord = &.{},
    regexes: ?regex_pool.RegexPool = null,
    /// YARA conditions for records flagged `flag_yara`; set by the loader after both tables
    /// validate (YaraTable.init needs the records).
    yara: ?@import("yara_cond.zig").YaraTable = null,
    /// Records evaluated for every file (expressions true with no hits).
    always: []const u32 = &.{},

    pub const Error = error{BadLdbTable};

    pub fn init(section: []const u8, programs: ?prog.Programs) Error!LdbTable {
        return initWith(section, programs, null);
    }

    /// Validate against the programs and the regex pool the records refer to.
    pub fn initWith(section: []const u8, programs: ?prog.Programs, regexes: ?regex_pool.RegexPool) Error!LdbTable {
        if (section.len < @sizeOf(LdbHeader) or @intFromPtr(section.ptr) % 8 != 0) return error.BadLdbTable;
        const h: *const LdbHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "LDBT") or h.version != 2) return error.BadLdbTable;
        const records_at = @sizeOf(LdbHeader);
        const rpn_at = records_at + @as(usize, h.count) * @sizeOf(LdbRecord);
        const tdb_at = std.mem.alignForward(usize, rpn_at + @as(usize, h.rpn_count) * @sizeOf(ir.RpnOp), 8);
        const bc_at = tdb_at + @as(usize, h.tdb_count) * @sizeOf(TdbRecord);
        const pcre_at = bc_at + @as(usize, h.bc_count) * @sizeOf(BcRecord);
        const always_at = pcre_at + @as(usize, h.pcre_count) * @sizeOf(PcreRecord);
        const tdb_of_at = always_at + @as(usize, h.always_count) * 4;
        const end = tdb_of_at + @as(usize, h.count) * 4;
        if (end > section.len) return error.BadLdbTable;
        const tof: [*]const u32 = @ptrCast(@alignCast(section.ptr + tdb_of_at));
        const al: [*]const u32 = @ptrCast(@alignCast(section.ptr + always_at));
        const pc: [*]const PcreRecord = @ptrCast(@alignCast(section.ptr + pcre_at));
        const b: [*]const BcRecord = @ptrCast(@alignCast(section.ptr + bc_at));
        const r: [*]const LdbRecord = @ptrCast(@alignCast(section.ptr + records_at));
        const o: [*]const ir.RpnOp = @ptrCast(@alignCast(section.ptr + rpn_at));
        const t: [*]const TdbRecord = @ptrCast(@alignCast(section.ptr + tdb_at));
        const table: LdbTable = .{ .records = r[0..h.count], .rpn = o[0..h.rpn_count], .tdbs = t[0..h.tdb_count], .tdb_of = tof[0..h.count], .bcs = b[0..h.bc_count], .pcres = pc[0..h.pcre_count], .regexes = regexes, .always = al[0..h.always_count] };
        var next_always: usize = 0;
        const nregex = if (regexes) |pool| pool.count() else 0;
        const nprog = if (programs) |ps| ps.count() else 0;
        for (table.tdbs) |t_rec| if (t_rec.target > 14 or t_rec.intermediate_count > ir.max_intermediates) return error.BadLdbTable;
        for (table.records, table.tdb_of, 0..) |rec, tdb_index, i| {
            if (tdb_index >= table.tdbs.len) return error.BadLdbTable;
            if (rec.nsub == 0 or rec.nsub > ir.max_subsigs) return error.BadLdbTable;
            if (@as(u64, rec.expr_off) + rec.expr_len > h.rpn_count) return error.BadLdbTable;
            if (rec.flags & ~(flag_counts | flag_yara) != 0) return error.BadLdbTable;
            const yara = rec.flags & flag_yara != 0;
            if (yara) {
                // Conditions are checked by YaraTable.init; a YARA record counts and has no
                // RPN, byte compares or PCRE.
                if (rec.expr_len != 0 or rec.flags & flag_counts == 0 or rec.bc_count != 0 or rec.pcre_count != 0) return error.BadLdbTable;
            } else {
                if (!checkRpn(table.expr(rec), rec.nsub)) return error.BadLdbTable;
                // Listed exactly when the expression holds with no hits, in ascending order.
                var zeros: [ir.max_subsigs]u32 = @splat(0);
                const listed = next_always < table.always.len and table.always[next_always] == i;
                if (listed != evalRpn(table.expr(rec), zeros[0..rec.nsub])) return error.BadLdbTable;
                if (listed) next_always += 1;
            }
            if (@as(u64, rec.pcre_first) + rec.pcre_count > h.pcre_count) return error.BadLdbTable;
            var counts_needed = usesCounts(table.expr(rec));
            var prev_pcre: i16 = -1;
            for (table.pcres[rec.pcre_first..][0..rec.pcre_count]) |pr| {
                // In subsig order, each trigger naming only earlier subsigs.
                if (pr.subsig >= rec.nsub or @as(i16, pr.subsig) <= prev_pcre) return error.BadLdbTable;
                prev_pcre = pr.subsig;
                if (@as(u64, pr.trigger_off) + pr.trigger_len > h.rpn_count) return error.BadLdbTable;
                const trig = table.rpn[pr.trigger_off..][0..pr.trigger_len];
                if (!checkRpn(trig, pr.subsig)) return error.BadLdbTable;
                if (pr.regex >= nregex) return error.BadLdbTable;
                if (@as(u8, @bitCast(pr.flags)) & 0xe0 != 0) return error.BadLdbTable;
                if (@backingInt(pr.off_kind) > @backingInt(ir.OffsetKind.last_section)) return error.BadLdbTable;
                counts_needed = counts_needed or usesCounts(trig);
            }
            if (!yara and (rec.flags & flag_counts != 0) != counts_needed) return error.BadLdbTable;
            if (@as(u64, rec.prog_first) + rec.prog_count > nprog) return error.BadLdbTable;
            if (@as(u64, rec.bc_first) + rec.bc_count > h.bc_count) return error.BadLdbTable;
            // Subsigs that have programs, and those that are byte compares, never overlap.
            var with_programs: u64 = 0;
            if (programs) |ps| for (rec.prog_first..rec.prog_first + rec.prog_count) |j| {
                const ph = ps.get(j).header;
                if (ph.flags & prog.flag_ldb == 0 or ph.sig != i or ph.subsig >= rec.nsub) return error.BadLdbTable;
                with_programs |= @as(u64, 1) << @intCast(ph.subsig);
            };
            for (table.pcres[rec.pcre_first..][0..rec.pcre_count]) |pr| {
                if (with_programs & (@as(u64, 1) << @intCast(pr.subsig)) != 0) return error.BadLdbTable;
            }
            for (table.bcs[rec.bc_first..][0..rec.bc_count]) |bc| {
                if (!validBc(bc, rec.nsub)) return error.BadLdbTable;
                const own = @as(u64, 1) << @intCast(bc.subsig);
                const trig = @as(u64, 1) << @intCast(bc.trigger);
                if (programs != null and (with_programs & own != 0 or with_programs & trig == 0)) return error.BadLdbTable;
            }
        }
        if (next_always != table.always.len) return error.BadLdbTable;
        return table;
    }

    /// Record `i`'s target description.
    pub fn tdb(table: LdbTable, i: usize) TdbRecord {
        return table.tdbs[table.tdb_of[i]];
    }

    pub fn expr(table: LdbTable, rec: LdbRecord) []const ir.RpnOp {
        return table.rpn[rec.expr_off..][0..rec.expr_len];
    }

    pub fn byteCompares(table: LdbTable, rec: LdbRecord) []const BcRecord {
        return table.bcs[rec.bc_first..][0..rec.bc_count];
    }

    pub fn pcreSubsigs(table: LdbTable, rec: LdbRecord) []const PcreRecord {
        return table.pcres[rec.pcre_first..][0..rec.pcre_count];
    }

    pub fn trigger(table: LdbTable, pr: PcreRecord) []const ir.RpnOp {
        return table.rpn[pr.trigger_off..][0..pr.trigger_len];
    }
};

fn validBc(bc: BcRecord, nsub: u8) bool {
    if (bc.subsig >= nsub or bc.trigger >= nsub or bc.subsig == bc.trigger) return false;
    if (@backingInt(bc.kind) > @backingInt(ir.ByteKind.binary) or bc.flags & ~@as(u8, 15) != 0) return false;
    if (bc.width == 0 or bc.width > ir.max_text_width) return false;
    if (bc.kind == .binary and (bc.flags & BcRecord.exact == 0 or !(bc.width == 1 or bc.width == 2 or bc.width == 4 or bc.width == 8))) return false;
    if (bc.comparison_count == 0 or bc.comparison_count > 2) return false;
    for (bc.ops[0..bc.comparison_count]) |op| if (@backingInt(op) > @backingInt(ir.CmpOp.eq)) return false;
    return true;
}

pub const BcResult = enum { yes, no, out_of_bounds };

fn hexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Read the number a byte compare points at, relative to a trigger match starting at `start`,
/// and compare it. A position outside the data is reported, not silently false.
pub fn evalByteCompare(bc: BcRecord, data: []const u8, start: usize) BcResult {
    const off: usize = bc.offset;
    const pos = if (bc.flags & BcRecord.backward != 0) (if (off > start) return .out_of_bounds else start - off) else start +| off;
    if (pos >= data.len) return .out_of_bounds;
    const exact = bc.flags & BcRecord.exact != 0;
    const big = bc.flags & BcRecord.big_endian != 0;
    if (exact and data.len - pos < bc.width) return .out_of_bounds;
    if (bc.flags & BcRecord.no_order != 0) return .no;
    const field = data[pos..][0..@min(bc.width, data.len - pos)];
    const value: u64 = switch (bc.kind) {
        .binary => if (big) std.mem.readVarInt(u64, field, .big) else std.mem.readVarInt(u64, field, .little),
        .decimal => decimal(field, exact) orelse return .no,
        .hex => hexText(field, exact, big) orelse return .no,
        // libclamav evaluates auto only big-endian.
        .auto => if (!big)
            return .no
        else if (field.len >= 2 and field[0] == '0' and (field[1] == 'x' or field[1] == 'X'))
            hexText(field[2..], exact, true) orelse return .no
        else
            decimal(field, exact) orelse return .no,
        _ => return .no,
    };
    for (bc.ops[0..bc.comparison_count], bc.values[0..bc.comparison_count]) |op, k| {
        const ok = switch (op) {
            .lt => value < k,
            .gt => value > k,
            .eq => value == k,
            _ => false,
        };
        if (!ok) return .no;
    }
    return .yes;
}

fn decimal(field: []const u8, exact: bool) ?u64 {
    var v: u64 = 0;
    var n: usize = 0;
    for (field) |c| {
        if (c < '0' or c > '9') break;
        v = std.math.mul(u64, v, 10) catch return null;
        v = std.math.add(u64, v, c - '0') catch return null;
        n += 1;
    }
    if (n == 0 or (exact and n != field.len)) return null;
    return v;
}

/// Hex digits, most significant first; little-endian swaps the bytes they spell.
fn hexText(field: []const u8, exact: bool, big: bool) ?u64 {
    var v: u64 = 0;
    var n: usize = 0;
    for (field) |c| {
        const d = hexDigit(c) orelse break;
        if (n == 16) return null;
        v = (v << 4) | d;
        n += 1;
    }
    if (n == 0 or (exact and n != field.len)) return null;
    if (big) return v;
    if (n % 2 != 0) return null;
    const bytes = n / 2;
    return @byteSwap(v) >> @intCast(64 - bytes * 8);
}

test "byte compare evaluation: encodings, widths, endianness, bounds" {
    const Case = struct { []const u8, []const u8, usize, BcResult };
    const ldb = @import("../compile/ldb.zig");
    for ([_]Case{
        .{ "0(>>2#hb4#=0x1234)", "ab1234zz", 0, .yes },
        .{ "0(>>2#hl4#=0x3412)", "ab1234zz", 0, .yes },
        .{ "0(>>2#hb4#=0x12)", "ab12zzzz", 0, .yes }, // not exact: stops at the first non-digit
        .{ "0(>>2#hbe4#=0x12)", "ab12zzzz", 0, .no }, // exact needs four digits
        .{ "0(>>2#d3#=123)", "ab123", 0, .yes },
        .{ "0(>>2#de3#=12)", "ab12", 0, .out_of_bounds },
        .{ "0(>>2#d3#>100,<200)", "ab150", 0, .yes },
        .{ "0(>>2#d3#>100,<200)", "ab250", 0, .no },
        .{ "0(>>2#ab6#=0x1f)", "ab0x1f;", 0, .yes },
        .{ "0(>>2#ab6#=31)", "ab31;", 0, .yes },
        // As libclamav: auto little-endian, and hex, auto or binary without a byte order, never hold.
        .{ "0(>>2#al6#=31)", "ab31;", 0, .no },
        .{ "0(>>2#a6#=31)", "ab31;", 0, .no },
        .{ "0(>>2#h4#=0x1234)", "ab1234zz", 0, .no },
        .{ "0(>>1#i2#=0x0201)", "\x00\x01\x02", 0, .no },
        .{ "0(>>1#ib1#=0x7f)", "\x00\x7f", 0, .yes },
        .{ "0(>>1#il2#=0x0201)", "\x00\x01\x02", 0, .yes },
        .{ "0(>>1#ib2#=0x0102)", "\x00\x01\x02", 0, .yes },
        .{ "0(>>0#il4#=0x04030201)", "\x01\x02\x03\x04", 0, .yes },
        .{ "0(>>0#ib8#=0x0102030405060708)", "\x01\x02\x03\x04\x05\x06\x07\x08", 0, .yes },
        .{ "0(>>0#il8#<1)", "\x01\x02\x03", 0, .out_of_bounds },
        .{ "0(<<2#ib1#=0x41)", "xA..", 3, .yes },
        .{ "0(<<9#ib1#=0x41)", "xA..", 3, .out_of_bounds },
        .{ "0(>>9#d1#=1)", "1", 0, .out_of_bounds },
    }) |c| {
        const bc = try ldb.parseByteCompare(c[0], 1);
        try testing.expectEqual(c[3], evalByteCompare(BcRecord.from(1, bc), c[1], c[2]));
    }
}

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
