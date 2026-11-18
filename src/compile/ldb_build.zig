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
    var rpn_count: usize = 0;
    var bc_count: usize = 0;
    var pcre_count: usize = 0;
    for (entries) |e| {
        rpn_count += e.rule.expr.len;
        for (e.rule.subsigs) |sub| switch (sub) {
            .byte_compare => bc_count += 1,
            .pcre => |p| {
                pcre_count += 1;
                rpn_count += p.trigger.len;
            },
            .hex => {},
        };
    }
    const header: ldb_table.LdbHeader = .{ .count = @intCast(entries.len), .rpn_count = @intCast(rpn_count), .bc_count = @intCast(bc_count), .pcre_count = @intCast(pcre_count) };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, std.mem.asBytes(&header));
    var expr_off: u32 = 0;
    var bc_first: u32 = 0;
    var pcre_first: u32 = 0;
    for (entries) |e| {
        var bcs: u16 = 0;
        var pcres: u16 = 0;
        var counts = ldb_table.usesCounts(e.rule.expr);
        for (e.rule.subsigs) |sub| switch (sub) {
            .byte_compare => bcs += 1,
            .pcre => |p| {
                pcres += 1;
                counts = counts or ldb_table.usesCounts(p.trigger);
            },
            .hex => {},
        };
        const rec: ldb_table.LdbRecord = .{
            .sig = e.sig,
            .nsub = @intCast(e.rule.subsigs.len),
            .flags = if (counts) ldb_table.flag_counts else 0,
            .expr_len = @intCast(e.rule.expr.len),
            .expr_off = expr_off,
            .prog_first = e.prog_first,
            .prog_count = e.prog_count,
            .bc_first = bc_first,
            .bc_count = bcs,
            .pcre_first = pcre_first,
            .pcre_count = pcres,
        };
        try out.appendSlice(gpa, std.mem.asBytes(&rec));
        expr_off += @intCast(e.rule.expr.len);
        bc_first += bcs;
        pcre_first += pcres;
    }
    for (entries) |e| try out.appendSlice(gpa, std.mem.sliceAsBytes(e.rule.expr));
    // PCRE triggers follow the main expressions, in the same order as the PCRE records.
    var trigger_off: u32 = expr_off;
    for (entries) |e| for (e.rule.subsigs) |sub| switch (sub) {
        .pcre => |p| try out.appendSlice(gpa, std.mem.sliceAsBytes(p.trigger)),
        else => {},
    };
    while (out.items.len % 8 != 0) try out.append(gpa, 0);
    for (entries) |e| {
        const t = ldb_table.TdbRecord.from(e.rule.tdb);
        try out.appendSlice(gpa, std.mem.asBytes(&t));
    }
    for (entries) |e| for (e.rule.subsigs, 0..) |sub, i| switch (sub) {
        .byte_compare => |bc| {
            const r = ldb_table.BcRecord.from(@intCast(i), bc);
            try out.appendSlice(gpa, std.mem.asBytes(&r));
        },
        else => {},
    };
    for (entries) |e| {
        var regex = e.regex_first;
        for (e.rule.subsigs, 0..) |sub, i| switch (sub) {
            .pcre => |p| {
                const r: ldb_table.PcreRecord = .{
                    .subsig = @intCast(i),
                    .flags = p.flags,
                    .trigger_len = @intCast(p.trigger.len),
                    .trigger_off = trigger_off,
                    .regex = regex,
                    .off_kind = p.offset.kind,
                    .off_section = p.offset.section,
                    .off_a = p.offset.a,
                    .off_shift = p.offset.shift,
                };
                try out.appendSlice(gpa, std.mem.asBytes(&r));
                trigger_off += @intCast(p.trigger.len);
                regex += 1;
            },
            else => {},
        };
    }
    return out.toOwnedSlice(gpa);
}
