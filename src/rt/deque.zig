//! Bounded Chase-Lev deque. One owner pushes and pops; any worker may steal.
//! Slots are atomic because a losing thief can load a slot as it is reused.
//! The indices and the last-item CAS determine which worker owns each job.
const std = @import("std");

pub fn Deque(comptime Job: type, comptime capacity: usize) type {
    if (capacity == 0 or !std.math.isPowerOfTwo(capacity)) @compileError("deque capacity must be a nonzero power of two");
    return struct {
        const Self = @This();
        const Index = std.atomic.Value(i64);
        const Slot = std.atomic.Value(?*Job);

        // Keep the owner and thief indices on separate 128-byte cache lines.
        top: Index align(128) = .init(0),
        bottom: Index align(128) = .init(0),
        slots: [capacity]Slot align(128) = @splat(.init(null)),

        /// Owner only. The caller keeps ownership when the buffer is full.
        pub fn push(q: *Self, job: *Job) bool {
            const bottom = q.bottom.load(.monotonic);
            const top = q.top.load(.acquire);
            if (bottom - top >= capacity) return false;
            q.slots[slot(bottom)].store(job, .monotonic);
            q.bottom.store(bottom + 1, .release);
            return true;
        }

        /// Owner only. Pop the newest job, competing with thieves for the last one.
        pub fn pop(q: *Self) ?*Job {
            const bottom = q.bottom.load(.monotonic) - 1;
            // Publish the new bottom before looking at top. This ordering also
            // pairs with steal's top-then-bottom order on weakly ordered CPUs.
            q.bottom.store(bottom, .seq_cst);
            const top = q.top.load(.seq_cst);
            if (top < bottom) return q.slots[slot(bottom)].load(.monotonic);
            defer q.bottom.store(bottom + 1, .monotonic);
            if (top != bottom) return null;

            const job = q.slots[slot(bottom)].load(.monotonic);
            if (q.top.cmpxchgStrong(top, top + 1, .seq_cst, .monotonic) != null) return null;
            return job;
        }

        /// Steal the oldest job. A failed race can be reported as no work.
        pub fn steal(q: *Self) ?*Job {
            const top = q.top.load(.seq_cst);
            const bottom = q.bottom.load(.seq_cst);
            if (top >= bottom) return null;

            const job = q.slots[slot(top)].load(.monotonic);
            if (q.top.cmpxchgStrong(top, top + 1, .seq_cst, .monotonic) != null) return null;
            return job;
        }

        /// Approximate owner-side size for decisions such as splitting a walk.
        pub fn len(q: *const Self) usize {
            const bottom = q.bottom.load(.monotonic);
            return @intCast(@max(0, bottom - q.top.load(.acquire)));
        }

        fn slot(index: i64) usize {
            return @intCast(@as(u64, @intCast(index)) & (capacity - 1));
        }
    };
}

test "owner pops newest, a thief steals oldest, and a full deque refuses work" {
    var q: Deque(u8, 2) = .{};
    var a: u8 = 1;
    var b: u8 = 2;
    var c: u8 = 3;
    try std.testing.expectEqual(null, q.pop());
    try std.testing.expectEqual(null, q.steal());
    try std.testing.expect(q.push(&a));
    try std.testing.expect(q.push(&b));
    try std.testing.expect(!q.push(&c));
    try std.testing.expectEqual(@as(usize, 2), q.len());
    try std.testing.expectEqual(&b, q.pop().?);
    try std.testing.expect(q.push(&c));
    try std.testing.expectEqual(&a, q.steal().?);
    try std.testing.expectEqual(&c, q.pop().?);
    try std.testing.expectEqual(@as(usize, 0), q.len());
    try std.testing.expectEqual(null, q.steal());
}

test "owner and thieves process every job once through repeated slot reuse" {
    const Run = struct {
        const job_count = 50_000;
        const Job = std.atomic.Value(u32);
        queue: Deque(Job, 16) = .{},
        done: std.atomic.Value(bool) = .init(false),

        fn mark(job: *Job) void {
            _ = job.fetchAdd(1, .monotonic);
        }

        fn thief(run: *@This()) void {
            while (!run.done.load(.acquire)) {
                if (run.queue.steal()) |job| mark(job) else std.Thread.yield() catch {};
            }
        }
    };

    var run: Run = .{};
    const jobs = try std.testing.allocator.alloc(Run.Job, Run.job_count);
    defer std.testing.allocator.free(jobs);
    @memset(jobs, .init(0));
    var thieves: [3]std.Thread = undefined;
    var started: usize = 0;
    defer {
        run.done.store(true, .release);
        for (thieves[0..started]) |thread| thread.join();
    }
    for (&thieves) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Run.thief, .{&run});
        started += 1;
    }
    for (jobs, 0..) |*job, i| {
        while (!run.queue.push(job)) {
            if (run.queue.pop()) |pending| Run.mark(pending);
        }
        if (i % 7 == 0) if (run.queue.pop()) |pending| Run.mark(pending);
    }
    while (run.queue.pop()) |job| Run.mark(job);
    run.done.store(true, .release);
    for (thieves) |thread| thread.join();
    started = 0;
    for (jobs) |job| try std.testing.expectEqual(@as(u32, 1), job.load(.monotonic));
}
