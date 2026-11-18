//! A child assembled from pieces: the decoded body of a MIME part, a PDF stream after its
//! filters, the hex of an RTF object. Push parsers produce these a slice at a time, so they cannot
//! hand the walker a reader; the bytes are collected first and then scanned as one child.
//!
//! Bytes go to a scratch buffer reserved when the collector is made (so a parser may mark and
//! release scratch around its own work while collecting), then to an unlinked spill file. Past
//! MaxFileSize the rest is dropped and the file_size limit is reported once; what was collected
//! is still scanned.
const std = @import("std");
const container = @import("../engine/container.zig");
const source_mod = @import("../engine/source.zig");
const Walker = container.Walker;
const Source = source_mod.Source;
const Spill = source_mod.Spill;

/// Scratch bytes a collector reserves by default; larger children spill.
pub const default_capacity: usize = 1024 * 1024;

pub const Collector = struct {
    w: *Walker,
    buf: []u8 = &.{},
    len: usize = 0,
    spill: ?Spill = null,
    /// Bytes past MaxFileSize, or storage failed: the rest of this child is dropped.
    full: bool = false,

    /// Reserve `default_capacity` (at most memory_child_max) of scratch now.
    pub fn init(w: *Walker) Collector {
        return initCapacity(w, default_capacity);
    }

    pub fn initCapacity(w: *Walker, capacity: usize) Collector {
        const cap: usize = @intCast(@min(capacity, w.options.memory_child_max, w.tracker.limits.max_file_size));
        const buf: []u8 = w.scratch.allocator().alloc(u8, cap) catch &[_]u8{};
        return .{ .w = w, .buf = buf };
    }

    /// Bytes collected so far.
    pub fn size(c: *const Collector) u64 {
        return if (c.spill) |s| s.len else c.len;
    }

    pub fn append(c: *Collector, bytes: []const u8) void {
        if (c.full or bytes.len == 0) return;
        const w = c.w;
        const max = w.tracker.limits.max_file_size;
        var take = bytes;
        if (c.size() + take.len > max) {
            take = take[0..@intCast(max -| c.size())];
            c.full = true;
            w.limit(.file_size);
        }
        if (c.spill == null and c.len + take.len > c.buf.len) {
            // Past the reserved buffer: move to a spill file.
            var s = Spill.create(w.io, w.spill_dir) catch return c.fail();
            s.append(w.io, c.buf[0..c.len]) catch {
                s.close(w.io);
                return c.fail();
            };
            c.spill = s;
            c.len = 0;
        }
        if (c.spill) |*s| {
            s.append(w.io, take) catch c.fail();
            return;
        }
        @memcpy(c.buf[c.len..][0..take.len], take);
        c.len += take.len;
    }

    fn fail(c: *Collector) void {
        c.full = true;
        c.w.limit(.memory);
    }

    pub fn source(c: *const Collector) Source {
        if (c.spill) |*s| return s.source();
        return .{ .memory = c.buf[0..c.len] };
    }

    /// Scan what was collected as a child, then start over (the scratch buffer is kept).
    pub fn emit(c: *Collector, name: []const u8, kind: container.Kind) container.Error!void {
        defer c.reset();
        try c.w.child(name, c.source(), kind);
    }

    pub fn reset(c: *Collector) void {
        if (c.spill) |*s| s.close(c.w.io);
        c.spill = null;
        c.len = 0;
        c.full = false;
    }

    pub fn deinit(c: *Collector) void {
        c.reset();
    }
};

test "collects in scratch, then spills, and stops at MaxFileSize" {
    var rig: @import("scan.zig").TestRig = undefined;
    try rig.init(.{ .max_file_size = 300 * 1024 });
    defer rig.deinit();
    const mark = rig.scratch.mark();
    var c: Collector = .initCapacity(&rig.walker, 128 * 1024);
    defer c.deinit();
    var block: [1000]u8 = undefined;
    for (&block, 0..) |*b, i| b.* = @truncate(i);
    for (0..100) |_| c.append(&block);
    try std.testing.expect(c.spill == null);
    try std.testing.expectEqual(@as(u64, 100_000), c.size());
    for (0..400) |_| c.append(&block);
    try std.testing.expect(c.spill != null);
    try std.testing.expect(c.full);
    try std.testing.expectEqual(@as(u64, 300 * 1024), c.size());
    try std.testing.expect(rig.rec.hasLimit(.file_size));
    var got: [1000]u8 = undefined;
    try c.source().readAllAt(std.testing.io, 99_000, &got);
    try std.testing.expectEqualSlices(u8, &block, &got);
    c.reset();
    c.append("abc");
    try std.testing.expectEqualStrings("abc", c.source().memory);
    rig.scratch.release(mark);
}
