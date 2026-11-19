//! Scheduling for directory traversal. Directory enumeration belongs to the I/O layer.
const std = @import("std");
const pool = @import("pool.zig");

/// Keep long local queues bounded by visiting additional subdirectories inline.
/// The caller gives the job the same lifetime for either scheduling path.
pub fn visitSubdirectory(worker: *pool.Worker, job: *pool.Job) void {
    if (worker.queue.len() <= 64 and worker.trySpawn(job)) return;
    job.run(worker, job);
}

test "a directory with queued siblings visits the rest inline" {
    const Walk = struct {
        children: [72]pool.Job = undefined,
        inline_visits: usize = 0,
        visits: usize = 0,

        fn parent(worker: *pool.Worker, job: *pool.Job) void {
            const walk: *@This() = @ptrCast(@alignCast(job.context));
            for (&walk.children) |*child| visitSubdirectory(worker, child);
            walk.inline_visits = walk.visits;
        }

        fn leaf(_: *pool.Worker, job: *pool.Job) void {
            const walk: *@This() = @ptrCast(@alignCast(job.context));
            walk.visits += 1;
        }
    };
    var walk: Walk = .{};
    for (&walk.children) |*child| child.* = .{ .run = Walk.leaf, .context = &walk };
    var parent: pool.Job = .{ .run = Walk.parent, .context = &walk };
    const workers = try pool.Pool.init(std.testing.allocator, std.testing.io, .{ .workers = 1 });
    defer workers.deinit();
    try std.testing.expectEqual(pool.Submit.accepted, workers.trySubmit(&parent));
    workers.drain();
    try std.testing.expectEqual(@as(usize, 7), walk.inline_visits);
    try std.testing.expectEqual(@as(usize, 72), walk.visits);
    try std.testing.expectEqual(@as(usize, 65), workers.workers[0].stats.queue_high_water);
}
