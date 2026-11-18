//! Writes the LDB_TABLE section (layout in match/ldb_table.zig).
const std = @import("std");
const ir = @import("ir.zig");
const ldb_table = @import("../match/ldb_table.zig");

pub const Entry = struct {
    rule: *const ir.LogicalRule,
    /// Signature id in sigmeta.
    sig: u32,
    /// The rule's programs in SUBSIG_PROG.
    prog_first: u32,
    prog_count: u32,
    /// REGEX_POOL index of the rule's first PCRE program; the rest follow in subsig order.
    regex_first: u32 = 0,
    /// A YARA rule: its condition is in YARA_COND, `rule.expr` is empty and `rule.subsigs`
    /// only gives the string count.
    yara: bool = false,
};

/// The PCRE programs of `rules`, in the order `build` numbers them from each entry's
/// `regex_first`.
pub fn pcrePrograms(rule: *const ir.LogicalRule, out: *std.ArrayList([]const u8), gpa: std.mem.Allocator) !void {
    for (rule.subsigs) |sub| switch (sub) {
        .pcre => |p| try out.append(gpa, p.program),
        else => {},
    };
}

pub fn build(gpa: std.mem.Allocator, entries: []const Entry) ![]u8 {
    var b = Builder.init(gpa);
    defer b.deinit();
    for (entries) |e| try b.add(e);
    return b.finish(gpa);
}

/// LDB_TABLE built one rule at a time, so rules need not stay alive until the table is written.
/// The layout is the one `build` always produced: records, main expressions, PCRE triggers,
/// distinct target descriptions, byte compares, PCRE records, the always-evaluated record list
/// and each record's target description index.
pub const Builder = struct {
    gpa: std.mem.Allocator,
    records: std.ArrayList(ldb_table.LdbRecord) = .empty,
    exprs: std.ArrayList(ir.RpnOp) = .empty,
    triggers: std.ArrayList(ir.RpnOp) = .empty,
    tdbs: std.ArrayList(ldb_table.TdbRecord) = .empty,
    bcs: std.ArrayList(ldb_table.BcRecord) = .empty,
    /// `trigger_off` relative to the trigger pool until `finish`.
    pcres: std.ArrayList(ldb_table.PcreRecord) = .empty,
    /// Records whose expression holds with no hits: evaluated for every file.
    always: std.ArrayList(u32) = .empty,
    /// Each record's target description, an index into `tdbs` (stored once each).
    tdb_of: std.ArrayList(u32) = .empty,
    tdb_ids: std.AutoHashMapUnmanaged([@sizeOf(ldb_table.TdbRecord)]u8, u32) = .empty,

    pub fn init(gpa: std.mem.Allocator) Builder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(b: *Builder) void {
        b.records.deinit(b.gpa);
        b.exprs.deinit(b.gpa);
        b.triggers.deinit(b.gpa);
        b.tdbs.deinit(b.gpa);
        b.bcs.deinit(b.gpa);
        b.pcres.deinit(b.gpa);
        b.always.deinit(b.gpa);
        b.tdb_of.deinit(b.gpa);
        b.tdb_ids.deinit(b.gpa);
        b.* = undefined;
    }

    pub fn count(b: *const Builder) u32 {
        return @intCast(b.records.items.len);
    }

    pub fn add(b: *Builder, e: Entry) !void {
        const gpa = b.gpa;
        var bcs: u16 = 0;
        var pcres: u16 = 0;
        var counts = ldb_table.usesCounts(e.rule.expr);
        const bc_first: u32 = @intCast(b.bcs.items.len);
        const pcre_first: u32 = @intCast(b.pcres.items.len);
        var regex = e.regex_first;
        for (e.rule.subsigs, 0..) |sub, i| switch (sub) {
            .byte_compare => |bc| {
                bcs += 1;
                try b.bcs.append(gpa, ldb_table.BcRecord.from(@intCast(i), bc));
            },
            .pcre => |p| {
                pcres += 1;
                counts = counts or ldb_table.usesCounts(p.trigger);
                try b.pcres.append(gpa, .{
                    .subsig = @intCast(i),
                    .flags = p.flags,
                    .trigger_len = @intCast(p.trigger.len),
                    .trigger_off = @intCast(b.triggers.items.len),
                    .regex = regex,
                    .off_kind = p.offset.kind,
                    .off_section = p.offset.section,
                    .off_a = p.offset.a,
                    .off_shift = p.offset.shift,
                });
                try b.triggers.appendSlice(gpa, p.trigger);
                regex += 1;
            },
            .hex => {},
        };
        try b.records.append(gpa, .{
            .sig = e.sig,
            .nsub = @intCast(e.rule.subsigs.len),
            .flags = if (e.yara) ldb_table.flag_counts | ldb_table.flag_yara else if (counts) ldb_table.flag_counts else 0,
            .expr_len = @intCast(e.rule.expr.len),
            .expr_off = @intCast(b.exprs.items.len),
            .prog_first = e.prog_first,
            .prog_count = e.prog_count,
            .bc_first = bc_first,
            .bc_count = bcs,
            .pcre_first = pcre_first,
            .pcre_count = pcres,
        });
        if (!e.yara) {
            var zeros: [ir.max_subsigs]u32 = @splat(0);
            if (ldb_table.evalRpn(e.rule.expr, zeros[0..e.rule.subsigs.len])) try b.always.append(gpa, @intCast(b.records.items.len - 1));
        }
        try b.exprs.appendSlice(gpa, e.rule.expr);
        const t = ldb_table.TdbRecord.from(e.rule.tdb);
        const gop = try b.tdb_ids.getOrPut(gpa, std.mem.toBytes(t));
        if (!gop.found_existing) {
            gop.value_ptr.* = @intCast(b.tdbs.items.len);
            try b.tdbs.append(gpa, t);
        }
        try b.tdb_of.append(gpa, gop.value_ptr.*);
    }

    /// The section bytes, allocated with `gpa`.
    pub fn finish(b: *Builder, gpa: std.mem.Allocator) ![]u8 {
        const header: ldb_table.LdbHeader = .{
            .count = @intCast(b.records.items.len),
            .rpn_count = @intCast(b.exprs.items.len + b.triggers.items.len),
            .bc_count = @intCast(b.bcs.items.len),
            .pcre_count = @intCast(b.pcres.items.len),
            .always_count = @intCast(b.always.items.len),
            .tdb_count = @intCast(b.tdbs.items.len),
        };
        // PCRE triggers follow the main expressions in the RPN pool.
        const base: u32 = @intCast(b.exprs.items.len);
        for (b.pcres.items) |*r| r.trigger_off += base;
        defer for (b.pcres.items) |*r| {
            r.trigger_off -= base;
        };
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        try out.appendSlice(gpa, std.mem.asBytes(&header));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.records.items));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.exprs.items));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.triggers.items));
        while (out.items.len % 8 != 0) try out.append(gpa, 0);
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.tdbs.items));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.bcs.items));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.pcres.items));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.always.items));
        try out.appendSlice(gpa, std.mem.sliceAsBytes(b.tdb_of.items));
        return out.toOwnedSlice(gpa);
    }
};
