//! Per-worker scratch memory. A large region is reserved as anonymous virtual memory; pages are
//! only backed (and only count as private memory) once touched. Everything a scan needs comes from
//! here, so the hot loop never calls the heap. After a burst the worker trims back to a small
//! resident size with madvise, returning the pages to the system.
const std = @import("std");
const vm = @import("../rt/vm.zig");

pub const default_reservation: usize = 64 * 1024 * 1024;
/// Bytes kept resident after an idle trim.
pub const default_keep: usize = 2 * 1024 * 1024;

pub const Scratch = struct {
    region: []align(std.heap.page_size_min) u8,
    fba: std.heap.FixedBufferAllocator,
    high_water: usize = 0,

    pub fn init(reservation: usize) !Scratch {
        const region = try vm.reserve(reservation);
        return .{ .region = region, .fba = .init(region) };
    }

    pub fn deinit(s: *Scratch) void {
        vm.release(s.region);
    }

    /// Allocator for one scan's working set. Freed all at once by `reset`.
    pub fn allocator(s: *Scratch) std.mem.Allocator {
        return s.fba.allocator();
    }

    /// Forget every allocation from the last scan. O(1); keeps pages resident for the next one.
    pub fn reset(s: *Scratch) void {
        s.high_water = @max(s.high_water, s.fba.end_index);
        s.fba.reset();
    }

    /// Return pages above `keep` to the system (call after the worker has been idle a while).
    pub fn trim(s: *Scratch, keep: usize) void {
        s.reset();
        const start = std.mem.alignForward(usize, keep, std.heap.pageSize());
        if (s.high_water <= start) return;
        const len = std.mem.alignForward(usize, s.high_water, std.heap.pageSize()) - start;
        vm.discard(@alignCast(s.region[start..][0..len]));
        s.high_water = start;
    }
};

test "scratch allocates without the heap and resets in place" {
    var s = try Scratch.init(4 * 1024 * 1024);
    defer s.deinit();
    const a = s.allocator();
    const buf = try a.alloc(u8, 1024 * 1024);
    @memset(buf, 0xab);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 8 * 1024 * 1024));
    s.reset();
    const again = try a.alloc(u8, 3 * 1024 * 1024);
    try std.testing.expectEqual(@intFromPtr(buf.ptr), @intFromPtr(again.ptr));
    @memset(again, 1);
    s.trim(64 * 1024);
    // Memory is still usable after a trim; trimmed pages come back zeroed or as they were.
    const after = try a.alloc(u8, 2 * 1024 * 1024);
    @memset(after, 2);
    try std.testing.expectEqual(@as(u8, 2), after[after.len - 1]);
}
