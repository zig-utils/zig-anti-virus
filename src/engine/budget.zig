//! The global big-window budget. Decoders whose window exceeds 1 MiB (zstd, xz/LZMA, large
//! spills) take tokens from one process-wide pool, default 64 MiB, so peak memory stays bounded no
//! matter how many workers hit such members at once. Without a token a member is reported with
//! the big_window_budget limit event instead of being decoded.
const std = @import("std");

pub const default_capacity: u64 = 64 * 1024 * 1024;
/// Windows at or below this size need no token.
pub const small_window: u64 = 1024 * 1024;

pub const Budget = struct {
    capacity: u64,
    used: std.atomic.Value(u64) = .init(0),

    pub fn init(capacity: u64) Budget {
        return .{ .capacity = capacity };
    }

    pub const Token = struct {
        budget: ?*Budget,
        bytes: u64,

        pub fn release(token: Token) void {
            if (token.budget) |b| _ = b.used.fetchSub(token.bytes, .release);
        }
    };

    /// A token for a window of `bytes`, or null if the pool cannot cover it right now.
    pub fn tryAcquire(b: *Budget, bytes: u64) ?Token {
        if (bytes <= small_window) return .{ .budget = null, .bytes = 0 };
        var current = b.used.load(.monotonic);
        while (true) {
            if (current + bytes > b.capacity) return null;
            current = b.used.cmpxchgWeak(current, current + bytes, .acquire, .monotonic) orelse return .{ .budget = b, .bytes = bytes };
        }
    }
};

test "small windows are free, large ones share the pool" {
    var b = Budget.init(10 * 1024 * 1024);
    const small = b.tryAcquire(512 * 1024).?;
    try std.testing.expectEqual(@as(u64, 0), b.used.load(.monotonic));
    const a = b.tryAcquire(8 * 1024 * 1024).?;
    try std.testing.expectEqual(@as(?Budget.Token, null), b.tryAcquire(8 * 1024 * 1024));
    a.release();
    const c = b.tryAcquire(8 * 1024 * 1024).?;
    c.release();
    small.release();
    try std.testing.expectEqual(@as(u64, 0), b.used.load(.monotonic));
}
