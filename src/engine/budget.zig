//! The global big-window budget. Decoders whose window exceeds 1 MiB (zstd, xz/LZMA, large
//! spills) take tokens from one process-wide pool, default 64 MiB, so peak memory stays bounded no
//! matter how many workers hit such members at once. Without a token a member is reported with
//! the big_window_budget limit event instead of being decoded.
const std = @import("std");
const Io = std.Io;

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

    /// Like `tryAcquire`, but waits up to `wait_ms` for other workers to release tokens before
    /// giving up. Null means the caller reports the big_window_budget limit event.
    pub fn acquire(b: *Budget, io: Io, bytes: u64, wait_ms: u32) ?Token {
        if (b.tryAcquire(bytes)) |t| return t;
        if (bytes > b.capacity) return null;
        var waited: u32 = 0;
        while (waited < wait_ms) : (waited += 1) {
            io.sleep(.fromMilliseconds(1), .awake) catch return null;
            if (b.tryAcquire(bytes)) |t| return t;
        }
        return null;
    }
};

test "acquire waits briefly, then gives up" {
    var b = Budget.init(4 * 1024 * 1024);
    const held = b.acquire(std.testing.io, 3 * 1024 * 1024, 0).?;
    try std.testing.expectEqual(@as(?Budget.Token, null), b.acquire(std.testing.io, 3 * 1024 * 1024, 2));
    try std.testing.expectEqual(@as(?Budget.Token, null), b.acquire(std.testing.io, 5 * 1024 * 1024, 2));
    held.release();
    (b.acquire(std.testing.io, 3 * 1024 * 1024, 2) orelse return error.TestUnexpectedResult).release();
}

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
