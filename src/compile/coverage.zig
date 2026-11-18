//! The coverage report: how many signatures each source contributed and every reason one was not
//! included. It is stored in the database (`coverage_report` section) and printed by `zav coverage`,
//! so the detection lost to unsupported formats is a measured number rather than a guess.
const std = @import("std");
const ir = @import("ir.zig");

const reason_count = @typeInfo(ir.Reason).@"enum".field_names.len;

pub const Coverage = struct {
    included: std.StringArrayHashMapUnmanaged(u64) = .empty,
    skipped: std.StringArrayHashMapUnmanaged([reason_count]u64) = .empty,

    pub fn deinit(c: *Coverage, gpa: std.mem.Allocator) void {
        c.included.deinit(gpa);
        c.skipped.deinit(gpa);
    }

    pub fn include(c: *Coverage, gpa: std.mem.Allocator, source: []const u8, n: u64) !void {
        const gop = try c.included.getOrPut(gpa, source);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += n;
    }

    pub fn skip(c: *Coverage, gpa: std.mem.Allocator, source: []const u8, reason: ir.Reason) !void {
        const gop = try c.skipped.getOrPut(gpa, source);
        if (!gop.found_existing) gop.value_ptr.* = @splat(0);
        gop.value_ptr.*[@backingInt(reason)] += 1;
    }

    pub fn totals(c: *const Coverage) struct { included: u64, skipped: u64 } {
        var inc: u64 = 0;
        for (c.included.values()) |v| inc += v;
        var sk: u64 = 0;
        for (c.skipped.values()) |row| for (row) |v| {
            sk += v;
        };
        return .{ .included = inc, .skipped = sk };
    }

    /// Plain-text report, one line per source and reason, stable order.
    pub fn render(c: *const Coverage, w: *std.Io.Writer) !void {
        const t = c.totals();
        try w.print("zav coverage: {d} included, {d} skipped\n", .{ t.included, t.skipped });
        for (c.included.keys(), c.included.values()) |source, n| try w.print("  {s}: {d} included\n", .{ source, n });
        for (c.skipped.keys(), c.skipped.values()) |source, row| {
            for (row, 0..) |n, r| if (n > 0) try w.print("  {s}: {d} skipped ({t})\n", .{ source, n, @as(ir.Reason, @fromBackingInt(@intCast(r))) });
        }
    }
};

test "renders included and skipped counts" {
    const gpa = std.testing.allocator;
    var c: Coverage = .{};
    defer c.deinit(gpa);
    try c.include(gpa, "main.hdb", 10);
    try c.skip(gpa, "main.hdb", .bad_hash);
    try c.skip(gpa, "bytecode.cbc", .bytecode);
    try c.skip(gpa, "bytecode.cbc", .bytecode);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try c.render(&w);
    const text = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "10 included, 3 skipped") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "bytecode.cbc: 2 skipped (bytecode)") != null);
}
