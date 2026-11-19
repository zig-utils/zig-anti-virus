//! Work-stealing workers and a bounded external queue. Producers retain ownership
//! when submission reports backpressure. The pool drains accepted work on close.
const std = @import("std");
const builtin = @import("builtin");
const deque = @import("deque.zig");
const topology = @import("topology.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Job = struct {
    run: *const fn (*Worker, *Job) void,
    context: *anyopaque,
};

pub const Submit = enum { accepted, full, closed };

pub const Options = struct {
    workers: ?usize = null,
    pin: bool = false,
};

pub const Stats = struct {
    jobs: usize = 0,
    steals: usize = 0,
    parks: usize = 0,
    queue_high_water: usize = 0,
};

pub const Worker = struct {
    const Startup = enum(u32) { pending, ready, pin_failed };

    pool: *Pool,
    id: usize,
    thread: ?std.Thread = null,
    cpu: ?u16 = null,
    startup: std.atomic.Value(Startup) = .init(.pending),
    queue: deque.Deque(Job, 128) = .{},
    random: std.Random.DefaultPrng,
    stats: Stats align(128) = .{},

    /// Owner only, from a job callback. An unsuccessful submission is still
    /// the caller's job, which may be processed inline with the same worker.
    pub fn trySpawn(worker: *Worker, job: *Job) bool {
        const pool = worker.pool;
        const queued = worker.queue.len();
        _ = pool.outstanding.fetchAdd(1, .monotonic);
        if (!worker.queue.push(job)) {
            _ = pool.outstanding.fetchSub(1, .monotonic);
            return false;
        }
        worker.stats.queue_high_water = @max(worker.stats.queue_high_water, queued + 1);
        pool.wake(1);
        return true;
    }

    fn findWork(worker: *Worker) ?*Job {
        if (worker.queue.pop()) |job| return job;
        const pool = worker.pool;
        if (pool.takeInjected()) |job| return job;
        const first = worker.random.random().uintLessThan(usize, pool.workers.len);
        var victim = first;
        for (0..pool.workers.len) |_| {
            if (victim != worker.id) if (pool.workers[victim].queue.steal()) |job| {
                worker.stats.steals += 1;
                return job;
            };
            victim += 1;
            if (victim == pool.workers.len) victim = 0;
        }
        return null;
    }

    fn run(worker: *Worker) void {
        const pool = worker.pool;
        if (worker.cpu) |cpu| {
            const startup: Startup = if (topology.pinCurrent(cpu)) |_| .ready else |_| .pin_failed;
            worker.startup.store(startup, .release);
            pool.io.futexWake(Startup, &worker.startup.raw, 1);
            if (startup == .pin_failed) return;
        }
        while (true) {
            // Observe the generation before looking for work. A producer racing
            // with the search changes it before waking, so the futex cannot miss
            // a submission between the empty check and the wait.
            const generation = pool.generation.load(.acquire);
            if (worker.findWork()) |job| {
                worker.stats.jobs += 1;
                job.run(worker, job);
                if (pool.outstanding.fetchSub(1, .acq_rel) == 1) pool.wakeAll();
                continue;
            }
            if (pool.closing.load(.acquire) and pool.outstanding.load(.acquire) == 0) return;
            worker.stats.parks += 1;
            pool.io.futexWaitUncancelable(u32, &pool.generation.raw, generation);
        }
    }
};

pub const Pool = struct {
    gpa: Allocator,
    io: Io,
    workers: []Worker,
    generation: std.atomic.Value(u32) align(128) = .init(0),
    outstanding: std.atomic.Value(usize) align(128) = .init(0),
    closing: std.atomic.Value(bool) = .init(false),
    lock: Io.Mutex align(128) = .init,
    injector: []*Job,
    head: usize = 0,
    queued: usize = 0,

    pub fn init(gpa: Allocator, io: Io, options: Options) !*Pool {
        if (options.pin and builtin.os.tag != .linux) return error.CpuPinningUnavailable;
        const selection = if (options.workers == null or options.pin) try topology.discover(gpa, io) else null;
        const worker_count = options.workers orelse selection.?.cores;
        if (worker_count == 0) return error.InvalidWorkerCount;
        if (options.pin and worker_count > selection.?.logical) return error.CpuPinningUnavailable;
        const capacity = try std.math.mul(usize, worker_count, 4);
        const pool = try gpa.create(Pool);
        errdefer gpa.destroy(pool);
        const workers = try gpa.alloc(Worker, worker_count);
        errdefer gpa.free(workers);
        const injector = try gpa.alloc(*Job, capacity);
        errdefer gpa.free(injector);
        pool.* = .{ .gpa = gpa, .io = io, .workers = workers, .injector = injector };
        for (workers, 0..) |*worker, id| worker.* = .{
            .pool = pool,
            .id = id,
            .cpu = if (options.pin) selection.?.cpus[id] else null,
            .random = .init(id),
        };
        errdefer pool.drain();
        for (workers) |*worker| {
            worker.thread = try std.Thread.spawn(.{}, Worker.run, .{worker});
            if (options.pin) {
                while (true) switch (worker.startup.load(.acquire)) {
                    .pending => io.futexWaitUncancelable(Worker.Startup, &worker.startup.raw, .pending),
                    .ready => break,
                    .pin_failed => return error.CpuPinningUnavailable,
                };
            }
        }
        return pool;
    }

    /// Multiple producers can call this concurrently. Accepted jobs remain valid
    /// until their callbacks take ownership. A full queue never allocates.
    pub fn trySubmit(pool: *Pool, job: *Job) Submit {
        {
            pool.lock.lockUncancelable(pool.io);
            defer pool.lock.unlock(pool.io);
            if (pool.closing.load(.monotonic)) return .closed;
            if (pool.queued == pool.injector.len) return .full;
            const tail = (pool.head + pool.queued) % pool.injector.len;
            pool.injector[tail] = job;
            pool.queued += 1;
            _ = pool.outstanding.fetchAdd(1, .monotonic);
        }
        pool.wake(1);
        return .accepted;
    }

    fn takeInjected(pool: *Pool) ?*Job {
        pool.lock.lockUncancelable(pool.io);
        defer pool.lock.unlock(pool.io);
        if (pool.queued == 0) return null;
        const job = pool.injector[pool.head];
        pool.head = (pool.head + 1) % pool.injector.len;
        pool.queued -= 1;
        return job;
    }

    fn wake(pool: *Pool, count: u32) void {
        _ = pool.generation.fetchAdd(1, .release);
        pool.io.futexWake(u32, &pool.generation.raw, count);
    }

    fn wakeAll(pool: *Pool) void {
        pool.wake(@intCast(@min(pool.workers.len, std.math.maxInt(u32))));
    }

    /// Stop accepting external jobs and join all workers after the queue drains.
    /// Call from the pool's owner, outside job callbacks. Stats are stable after return.
    pub fn drain(pool: *Pool) void {
        pool.lock.lockUncancelable(pool.io);
        pool.closing.store(true, .release);
        pool.lock.unlock(pool.io);
        pool.wakeAll();
        for (pool.workers) |*worker| {
            if (worker.thread) |thread| thread.join();
            worker.thread = null;
        }
    }

    /// Call after external producers have stopped using the pool.
    pub fn deinit(pool: *Pool) void {
        pool.drain();
        const gpa = pool.gpa;
        gpa.free(pool.injector);
        gpa.free(pool.workers);
        gpa.destroy(pool);
    }
};

fn testResidentPages(io: Io) ?usize {
    if (builtin.os.tag != .linux) return null;
    var buf: [256]u8 = undefined;
    const data = Io.Dir.cwd().readFile(io, "/proc/self/statm", &buf) catch return null;
    var columns = std.mem.tokenizeScalar(u8, data, ' ');
    _ = columns.next();
    return std.fmt.parseInt(usize, columns.next() orelse return null, 10) catch null;
}

test "external queue refuses work once four jobs per worker are waiting" {
    const io = std.testing.io;
    const Gate = struct {
        io: Io,
        opened: std.atomic.Value(u32) = .init(0),
        entered: std.atomic.Value(u32) = .init(0),
        completed: u32 = 0,

        fn wait(_: *Worker, job: *Job) void {
            const gate: *@This() = @ptrCast(@alignCast(job.context));
            gate.entered.store(1, .release);
            gate.io.futexWake(u32, &gate.entered.raw, 1);
            while (gate.opened.load(.acquire) == 0) gate.io.futexWaitUncancelable(u32, &gate.opened.raw, 0);
        }

        fn count(_: *Worker, job: *Job) void {
            const gate: *@This() = @ptrCast(@alignCast(job.context));
            gate.completed += 1;
        }

        fn open(gate: *@This()) void {
            gate.opened.store(1, .release);
            gate.io.futexWake(u32, &gate.opened.raw, 1);
        }
    };

    var gate: Gate = .{ .io = io };
    var wait_job: Job = .{ .run = Gate.wait, .context = &gate };
    var queued: [5]Job = @splat(.{ .run = Gate.count, .context = &gate });
    const pool = try Pool.init(std.testing.allocator, io, .{ .workers = 1 });
    defer pool.deinit();
    defer gate.open();
    try std.testing.expectEqual(Submit.accepted, pool.trySubmit(&wait_job));
    while (gate.entered.load(.acquire) == 0) io.futexWaitUncancelable(u32, &gate.entered.raw, 0);
    for (queued[0..4]) |*job| try std.testing.expectEqual(Submit.accepted, pool.trySubmit(job));
    const resident_start = testResidentPages(io);
    var resident_high = resident_start orelse 0;
    for (0..10) |_| {
        for (0..100_000) |_| try std.testing.expectEqual(Submit.full, pool.trySubmit(&queued[4]));
        resident_high = @max(resident_high, testResidentPages(io) orelse 0);
    }
    if (resident_start) |pages| std.debug.print("runtime injector: one million full offers, {d} resident pages before, {d} peak\n", .{ pages, resident_high });
    gate.open();
    pool.drain();
    try std.testing.expectEqual(Submit.closed, pool.trySubmit(&queued[4]));
    try std.testing.expectEqual(@as(u32, 4), gate.completed);
}

test "workers drain external jobs and recursively scheduled children exactly once" {
    const Item = struct {
        job: Job,
        next: ?*Job,
        ran: std.atomic.Value(u32) = .init(0),

        fn run(worker: *Worker, job: *Job) void {
            const item: *@This() = @ptrCast(@alignCast(job.context));
            _ = item.ran.fetchAdd(1, .monotonic);
            if (item.next) |next| @import("walk.zig").visitSubdirectory(worker, next);
        }

        fn submit(pool: *Pool, items: []@This()) void {
            var i: usize = 0;
            while (i < items.len) : (i += 2) {
                while (true) switch (pool.trySubmit(&items[i].job)) {
                    .accepted => break,
                    .full => std.Thread.yield() catch {},
                    .closed => unreachable,
                };
            }
        }
    };
    const gpa = std.testing.allocator;
    const stress = try std.testing.environ.contains(gpa, "ZAV_RUNTIME_STRESS");
    const count: usize = if (stress) 10_000_000 else 8192;
    const items = try gpa.alloc(Item, count);
    defer gpa.free(items);
    const pool = try Pool.init(gpa, std.testing.io, .{ .workers = if (stress) null else 4 });
    defer pool.deinit();
    for (items, 0..) |*item, i| item.* = .{
        .job = .{ .run = Item.run, .context = item },
        .next = if (i % 2 == 0) &items[i + 1].job else null,
    };
    const middle = items.len / 2;
    const producer = try std.Thread.spawn(.{}, Item.submit, .{ pool, items[0..middle] });
    Item.submit(pool, items[middle..]);
    producer.join();
    pool.drain();
    for (items) |item| try std.testing.expectEqual(@as(u32, 1), item.ran.load(.monotonic));
    if (stress) {
        var steals: usize = 0;
        for (pool.workers) |worker| steals += worker.stats.steals;
        if (pool.workers.len > 1) try std.testing.expect(steals > 0);
        std.debug.print("runtime stress: {d} jobs, {d} workers, {d} steals\n", .{ count, pool.workers.len, steals });
    }
}

test "default worker count follows native core topology" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const selection = topology.discover(gpa, io) catch |err| switch (err) {
        error.CpuTopologyUnavailable => return error.SkipZigTest,
        else => return err,
    };
    const pool = try Pool.init(gpa, io, .{});
    defer pool.deinit();
    try std.testing.expect(selection.cores > 0);
    try std.testing.expectEqual(selection.cores, pool.workers.len);
    if (builtin.os.tag == .linux) {
        const pinned = try Pool.init(gpa, io, .{ .workers = 1, .pin = true });
        defer pinned.deinit();
        try std.testing.expectEqual(selection.cpus[0], pinned.workers[0].cpu.?);
        try std.testing.expectEqual(Worker.Startup.ready, pinned.workers[0].startup.load(.acquire));
    }
}
