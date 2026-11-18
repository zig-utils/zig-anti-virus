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
};

pub fn build(gpa: std.mem.Allocator, entries: []const Entry) ![]u8 {
    var rpn_count: usize = 0;
    var bc_count: usize = 0;
    for (entries) |e| {
        rpn_count += e.rule.expr.len;
        for (e.rule.subsigs) |sub| bc_count += @intFromBool(sub == .byte_compare);
    }
    const header: ldb_table.LdbHeader = .{ .count = @intCast(entries.len), .rpn_count = @intCast(rpn_count), .bc_count = @intCast(bc_count) };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, std.mem.asBytes(&header));
    var expr_off: u32 = 0;
    var bc_first: u32 = 0;
    for (entries) |e| {
        var bcs: u16 = 0;
        for (e.rule.subsigs) |sub| bcs += @intFromBool(sub == .byte_compare);
        const rec: ldb_table.LdbRecord = .{
            .sig = e.sig,
            .nsub = @intCast(e.rule.subsigs.len),
            .flags = if (ldb_table.usesCounts(e.rule.expr)) ldb_table.flag_counts else 0,
            .expr_len = @intCast(e.rule.expr.len),
            .expr_off = expr_off,
            .prog_first = e.prog_first,
            .prog_count = e.prog_count,
            .bc_first = bc_first,
            .bc_count = bcs,
        };
        try out.appendSlice(gpa, std.mem.asBytes(&rec));
        expr_off += @intCast(e.rule.expr.len);
        bc_first += bcs;
    }
    for (entries) |e| try out.appendSlice(gpa, std.mem.sliceAsBytes(e.rule.expr));
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
        .hex => {},
    };
    return out.toOwnedSlice(gpa);
}
