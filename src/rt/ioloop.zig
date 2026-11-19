//! One caller-owned reactor per listener group. The loop owns socket and
//! connection state and hands complete commands to workers.
const std = @import("std");
const builtin = @import("builtin");
const jobs = @import("pool.zig");
const vm = @import("vm.zig");

const c = std.c;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Fd = c.fd_t;
const Tick = i96;
const none = std.math.maxInt(u32);
const buffer_size = 64 * 1024;
const timer_interval_ms = 100;
pub const supported = builtin.os.tag == .linux or builtin.os.tag == .macos;

pub const Options = struct {
    max_connections: u32 = 64,
    idle_timeout_ms: u32 = 60_000,
    command_timeout_ms: u32 = 30_000,
};

pub const Handler = struct {
    context: *anyopaque,
    /// Runs on the loop. Return a complete prefix length, null for a partial
    /// request, or an error to close the connection.
    frame: *const fn (*anyopaque, []const u8) anyerror!?usize,
    /// Runs on a pool worker. Replace the request prefix with the response and
    /// return its length. The tail containing later frames is kept separately
    /// inside the same allocation and is excluded from the writable slice.
    execute: *const fn (*anyopaque, *jobs.Worker, []u8, usize) anyerror!usize,
};

const Phase = enum { free, reading, pending, running, writing };
const Interest = enum { none, read, write };

const Conn = struct {
    fd: Fd = -1,
    generation: u32 = 0,
    slot: u32 = undefined,
    next: u32 = none,
    interest: Interest = .none,
    phase: Phase = .free,
    deadline: Tick = 0,
    received: usize = 0,
    request_len: usize = 0,
    tail_len: usize = 0,
    sent: usize = 0,
    job: jobs.Job = undefined,

    // Workers write the result and append under the completion lock.
    loop: *Loop = undefined,
    response_len: ?usize = null,
    completed_next: ?*Conn = null,

    fn execute(worker: *jobs.Worker, job: *jobs.Job) void {
        const conn: *Conn = @ptrCast(@alignCast(job.context));
        const loop = conn.loop;
        const handler = loop.handler;
        const buffer = loop.bufferFor(conn.slot)[0 .. buffer_size - conn.tail_len];
        conn.response_len = handler.execute(handler.context, worker, buffer, conn.request_len) catch null;
        loop.completion_lock.lockUncancelable(loop.pool.io);
        if (loop.completed_tail) |tail| tail.completed_next = conn else loop.completed_head = conn;
        loop.completed_tail = conn;
        loop.working -= 1;
        if (loop.working == 0) loop.work_done.signal(loop.pool.io);
        loop.wake();
        loop.completion_lock.unlock(loop.pool.io);
    }
};

pub const Loop = struct {
    allocator: Allocator,
    pool: *jobs.Pool,
    handler: Handler,
    options: Options,
    poller: Poller,
    wake_fds: [2]Fd,
    listeners: std.ArrayList(Listener) = .empty,
    conns: []Conn,
    buffers: vm.Region,
    free_head: u32 = 0,
    active: usize = 0,
    stop: std.atomic.Value(bool) = .init(false),
    stopping: bool = false,
    pressure: bool = false,
    pending: ?u32 = null,
    next_sweep: Tick,
    waiter: jobs.SpaceWaiter,

    completion_lock: std.Io.Mutex = .init,
    work_done: std.Io.Condition = .init,
    working: usize = 0,
    completed_head: ?*Conn = null,
    completed_tail: ?*Conn = null,

    const Listener = struct { fd: Fd, interest: Interest = .none };

    /// The pool and handler context must outlive the loop. Only requestStop
    /// may be called concurrently by a thread other than the loop owner.
    pub fn init(allocator: Allocator, pool: *jobs.Pool, handler: Handler, options: Options) !*Loop {
        if (!supported) return error.EventLoopUnavailable;
        if (options.max_connections == 0 or options.max_connections == none or
            options.idle_timeout_ms == 0 or options.command_timeout_ms == 0)
            return error.InvalidLoopOptions;
        const loop = try allocator.create(Loop);
        errdefer allocator.destroy(loop);
        const conns = try allocator.alloc(Conn, options.max_connections);
        errdefer allocator.free(conns);
        // Reserve one 64 KiB slice per slot. The kernel backs only touched
        // pages, so accepting an idle socket requires no buffer allocation.
        const buffers = try vm.reserve(try std.math.mul(usize, options.max_connections, buffer_size));
        errdefer vm.release(buffers);
        for (conns, 0..) |*conn, i| conn.* = .{ .next = if (i + 1 == conns.len) none else @intCast(i + 1) };
        const poller = try Poller.init();
        errdefer close(poller.fd);
        var wake_fds: [2]Fd = undefined;
        if (builtin.os.tag == .linux) {
            const result = linux.pipe2(&wake_fds, .{ .NONBLOCK = true, .CLOEXEC = true });
            if (linux.errno(result) != .SUCCESS) return std.posix.unexpectedErrno(linux.errno(result));
        } else try check(c.pipe(&wake_fds));
        errdefer for (wake_fds) |fd| close(fd);
        if (builtin.os.tag != .linux) for (wake_fds) |fd| try configure(fd);
        try poller.interest(wake_fds[0], 0, .none, .read);
        loop.* = .{
            .allocator = allocator,
            .pool = pool,
            .handler = handler,
            .options = options,
            .poller = poller,
            .wake_fds = wake_fds,
            .conns = conns,
            .buffers = buffers,
            .next_sweep = std.Io.Clock.awake.now(pool.io).nanoseconds + ms(timer_interval_ms),
            .waiter = .{ .context = loop, .wake = wakeWaiter },
        };
        pool.watchSpace(&loop.waiter);
        return loop;
    }

    /// Add an already bound and listening Unix or TCP socket. Ownership
    /// transfers only on success.
    pub fn addListener(loop: *Loop, fd: Fd) !void {
        if (loop.stopping or loop.stop.load(.acquire)) return error.LoopStopping;
        if (loop.listeners.items.len == none) return error.TooManyListeners;
        for (loop.listeners.items) |listener| if (listener.fd == fd) return error.DuplicateListener;
        try loop.listeners.ensureUnusedCapacity(loop.allocator, 1);
        try configure(fd);
        const interest: Interest = if (loop.free_head == none) .none else .read;
        try loop.poller.interest(fd, loop.listeners.items.len + 1, .none, interest);
        loop.listeners.appendAssumeCapacity(.{ .fd = fd, .interest = interest });
    }

    pub fn connectionCount(loop: *const Loop) usize {
        return loop.active;
    }

    pub fn requestStop(loop: *Loop) void {
        loop.stop.store(true, .release);
        loop.wake();
    }

    /// Close the reactor after run returns, or abandon sockets and wait for
    /// already admitted workers if the loop exits with an I/O error.
    pub fn deinit(loop: *Loop) void {
        loop.pool.unwatchSpace(&loop.waiter);
        for (loop.listeners.items) |listener| close(listener.fd);
        for (loop.conns) |*conn| close(conn.fd);
        loop.completion_lock.lockUncancelable(loop.pool.io);
        while (loop.working != 0) loop.work_done.waitUncancelable(loop.pool.io, &loop.completion_lock);
        loop.completion_lock.unlock(loop.pool.io);
        vm.release(loop.buffers);
        for (loop.wake_fds) |fd| close(fd);
        close(loop.poller.fd);
        loop.listeners.deinit(loop.allocator);
        loop.allocator.free(loop.conns);
        loop.allocator.destroy(loop);
    }

    pub fn run(loop: *Loop) !void {
        while (try loop.step(std.math.maxInt(u31))) {}
    }

    /// Process one readiness batch. Return false after graceful shutdown.
    pub fn step(loop: *Loop, max_wait_ms: u31) !bool {
        try loop.observeStop();
        if (loop.stopping and loop.active == 0) return false;
        if (!loop.stopping and !loop.pressure and loop.pool.injectorFull()) try loop.pauseReads();
        const wait_ms: u31 = if (loop.active == 0) max_wait_ms else blk: {
            const until_sweep = @divTrunc(@max(0, loop.next_sweep - loop.now()) + ms(1) - 1, ms(1));
            break :blk @intCast(@min(max_wait_ms, until_sweep));
        };
        var ready: [128]Event = undefined;
        const count = try loop.poller.wait(&ready, wait_ms);
        try loop.observeStop();
        const timestamp = loop.now();
        for (ready[0..count]) |event| {
            if (event.key == 0) {
                try loop.onWake(timestamp);
            } else if (event.key >> 32 == 0) {
                if (!loop.stopping and loop.free_head != none)
                    try loop.accept(loop.listeners.items[@intCast(event.key - 1)].fd, timestamp);
            } else {
                const slot: u32 = @intCast(@as(u32, @truncate(event.key)) - 1);
                const conn = &loop.conns[slot];
                if (conn.fd < 0 or event.key != key(conn, slot)) continue;
                switch (conn.interest) {
                    .read => if (event.read) try loop.receive(conn, slot, timestamp),
                    .write => if (event.write) try loop.send(conn, slot, timestamp),
                    .none => {},
                }
            }
        }
        if (timestamp >= loop.next_sweep) {
            loop.next_sweep = timestamp + ms(timer_interval_ms);
            for (loop.conns, 0..) |*conn, i| {
                if (conn.fd >= 0 and timestamp >= conn.deadline) try loop.drop(conn, @intCast(i));
            }
            try loop.resumeReads();
        }
        return !loop.stopping or loop.active != 0;
    }

    fn observeStop(loop: *Loop) !void {
        if (loop.stopping or !loop.stop.load(.acquire)) return;
        loop.stopping = true;
        for (loop.listeners.items) |*listener| {
            close(listener.fd);
            listener.fd = -1;
        }
        for (loop.conns, 0..) |*conn, i| switch (conn.phase) {
            .reading, .pending => try loop.drop(conn, @intCast(i)),
            else => {},
        };
    }

    fn accept(loop: *Loop, listener: Fd, timestamp: Tick) !void {
        for (0..64) |_| {
            if (loop.free_head == none) return;
            const fd = acceptSocket(listener) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                else => return err,
            } orelse return;
            const slot = loop.free_head;
            const conn = &loop.conns[slot];
            loop.free_head = conn.next;
            conn.* = .{
                .fd = fd,
                .generation = @max(1, conn.generation +% 1),
                .slot = slot,
                .phase = .reading,
                .deadline = timestamp + ms(loop.options.idle_timeout_ms),
                .loop = loop,
            };
            loop.active += 1;
            try loop.syncInterest(conn, slot);
            if (loop.free_head == none) try loop.syncListeners();
        }
    }

    fn receive(loop: *Loop, conn: *Conn, slot: u32, timestamp: Tick) !void {
        if (loop.pressure or loop.stopping or conn.phase != .reading) return;
        if (timestamp >= conn.deadline) return loop.drop(conn, slot);
        const buffer = loop.bufferFor(slot);
        while (true) {
            const count = c.recv(conn.fd, buffer[conn.received..].ptr, buffer.len - conn.received, 0);
            switch (std.posix.errno(count)) {
                .SUCCESS => {
                    if (count == 0) return loop.drop(conn, slot);
                    if (conn.received == 0) conn.deadline = timestamp + ms(loop.options.command_timeout_ms);
                    conn.received += @intCast(count);
                    return loop.frame(conn, slot);
                },
                .INTR => continue,
                .AGAIN => return,
                else => return loop.drop(conn, slot),
            }
        }
    }

    fn frame(loop: *Loop, conn: *Conn, slot: u32) !void {
        const buffer = loop.bufferFor(slot);
        const result = loop.handler.frame(loop.handler.context, buffer[0..conn.received]) catch return loop.drop(conn, slot);
        const length = result orelse {
            if (conn.received == buffer.len) return loop.drop(conn, slot);
            return loop.syncInterest(conn, slot);
        };
        if (length == 0 or length > conn.received) return loop.drop(conn, slot);
        conn.tail_len = conn.received - length;
        conn.request_len = length;
        const tail = buffer[buffer.len - conn.tail_len ..];
        std.mem.copyBackwards(u8, tail, buffer[length..conn.received]);
        conn.job = .{ .context = conn, .run = Conn.execute };
        try loop.submit(conn, slot);
    }

    fn submit(loop: *Loop, conn: *Conn, slot: u32) !void {
        loop.completion_lock.lockUncancelable(loop.pool.io);
        loop.working += 1;
        const result = loop.pool.trySubmit(&conn.job);
        if (result != .accepted) loop.working -= 1;
        loop.completion_lock.unlock(loop.pool.io);
        switch (result) {
            .accepted => {
                conn.phase = .running;
                if (loop.pending == slot) loop.pending = null;
                try loop.syncInterest(conn, slot);
                if (!loop.pressure and loop.pool.injectorFull()) try loop.pauseReads();
            },
            .full => {
                conn.phase = .pending;
                loop.pending = slot;
                try loop.syncInterest(conn, slot);
                try loop.pauseReads();
            },
            .closed => try loop.drop(conn, slot),
        }
    }

    fn pauseReads(loop: *Loop) !void {
        if (loop.pressure) return;
        loop.pressure = true;
        for (loop.conns, 0..) |*conn, i| if (conn.phase == .reading) try loop.syncInterest(conn, @intCast(i));
    }

    fn resumeReads(loop: *Loop) !void {
        if (!loop.pressure or loop.stopping or loop.pending != null or loop.pool.injectorFull()) return;
        loop.pressure = false;
        for (loop.conns) |*conn| {
            if (loop.pressure) break;
            if (conn.phase != .reading) continue;
            if (conn.received == 0) try loop.syncInterest(conn, conn.slot) else try loop.frame(conn, conn.slot);
        }
    }

    fn onWake(loop: *Loop, timestamp: Tick) !void {
        var buffer: [128]u8 = undefined;
        while (true) {
            const count = c.read(loop.wake_fds[0], &buffer, buffer.len);
            switch (std.posix.errno(count)) {
                .SUCCESS => if (count == 0) return error.LoopWakeFailed,
                .INTR => continue,
                .AGAIN => break,
                else => return error.LoopWakeFailed,
            }
        }
        try loop.observeStop();
        loop.completion_lock.lockUncancelable(loop.pool.io);
        var ready = loop.completed_head;
        loop.completed_head = null;
        loop.completed_tail = null;
        loop.completion_lock.unlock(loop.pool.io);
        while (ready) |conn| {
            ready = conn.completed_next;
            conn.completed_next = null;
            const slot = conn.slot;
            conn.phase = .writing;
            const len = conn.response_len orelse {
                try loop.drop(conn, slot);
                continue;
            };
            if (conn.fd < 0 or len > buffer_size - conn.tail_len or timestamp >= conn.deadline) {
                try loop.drop(conn, slot);
                continue;
            }
            conn.sent = 0;
            try loop.send(conn, slot, timestamp);
        }
        if (loop.pending) |slot| {
            const conn = &loop.conns[slot];
            if (timestamp >= conn.deadline) try loop.drop(conn, slot) else try loop.submit(conn, slot);
        }
        try loop.resumeReads();
    }

    fn send(loop: *Loop, conn: *Conn, slot: u32, timestamp: Tick) !void {
        if (timestamp >= conn.deadline) return loop.drop(conn, slot);
        const buffer = loop.bufferFor(slot);
        const length = conn.response_len.?;
        while (conn.sent < length) {
            const bytes = buffer[conn.sent..length];
            const count = c.send(conn.fd, bytes.ptr, bytes.len, if (builtin.os.tag == .linux) c.MSG.NOSIGNAL else 0);
            switch (std.posix.errno(count)) {
                .SUCCESS => {
                    if (count == 0) return loop.drop(conn, slot);
                    conn.sent += @intCast(count);
                },
                .INTR => continue,
                .AGAIN => return loop.syncInterest(conn, slot),
                else => return loop.drop(conn, slot),
            }
        }
        if (loop.stopping) return loop.drop(conn, slot);
        conn.phase = .reading;
        conn.received = conn.tail_len;
        conn.deadline = timestamp + ms(if (conn.received == 0) loop.options.idle_timeout_ms else loop.options.command_timeout_ms);
        if (conn.received == 0) return loop.syncInterest(conn, slot);
        std.mem.copyForwards(u8, buffer[0..conn.received], buffer[buffer.len - conn.received ..]);
        // A completed response may contain pipelined bytes while another
        // connection is waiting for queue space. Resume them in order.
        if (loop.pressure) return loop.syncInterest(conn, slot);
        try loop.frame(conn, slot);
    }

    fn syncInterest(loop: *Loop, conn: *Conn, slot: u32) !void {
        if (conn.fd < 0) return;
        const next: Interest = switch (conn.phase) {
            .reading => if (loop.pressure or loop.stopping) .none else .read,
            .writing => .write,
            else => .none,
        };
        try loop.poller.interest(conn.fd, key(conn, slot), conn.interest, next);
        conn.interest = next;
    }

    fn syncListeners(loop: *Loop) !void {
        if (loop.stopping) return;
        const next: Interest = if (loop.free_head == none) .none else .read;
        for (loop.listeners.items, 1..) |*listener, i| {
            try loop.poller.interest(listener.fd, i, listener.interest, next);
            listener.interest = next;
        }
    }

    fn drop(loop: *Loop, conn: *Conn, slot: u32) !void {
        close(conn.fd);
        conn.fd = -1;
        conn.interest = .none;
        if (conn.phase == .running) return; // The worker still holds the buffer.
        if (loop.pending == slot) loop.pending = null;
        const was_full = loop.free_head == none;
        conn.* = .{ .generation = conn.generation, .next = loop.free_head };
        loop.free_head = slot;
        loop.active -= 1;
        if (was_full) try loop.syncListeners();
    }

    fn wakeWaiter(context: *anyopaque) void {
        const loop: *Loop = @ptrCast(@alignCast(context));
        loop.wake();
    }

    fn wake(loop: *Loop) void {
        while (std.posix.errno(c.write(loop.wake_fds[1], "w", 1)) == .INTR) {}
    }

    fn now(loop: *const Loop) Tick {
        return std.Io.Clock.awake.now(loop.pool.io).nanoseconds;
    }

    fn bufferFor(loop: *Loop, slot: u32) *[buffer_size]u8 {
        return loop.buffers[@as(usize, slot) * buffer_size ..][0..buffer_size];
    }
};

fn key(conn: *const Conn, slot: u32) u64 {
    return (@as(u64, conn.generation) << 32) | (@as(u64, slot) + 1);
}

fn ms(value: u32) Tick {
    return @as(Tick, value) * std.time.ns_per_ms;
}

fn check(result: c_int) !void {
    switch (std.posix.errno(result)) {
        .SUCCESS => {},
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn close(fd: Fd) void {
    if (fd >= 0) _ = c.close(fd);
}

fn configure(fd: Fd) !void {
    const flags = c.fcntl(fd, c.F.GETFL);
    try check(flags);
    const nonblock: c.O = .{ .NONBLOCK = true };
    try check(c.fcntl(fd, c.F.SETFL, flags | @as(c_int, @bitCast(nonblock))));
    try check(c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC)));
}

fn acceptSocket(listener: Fd) !?Fd {
    while (true) {
        const fd = if (builtin.os.tag == .linux)
            c.accept4(listener, null, null, c.SOCK.NONBLOCK | c.SOCK.CLOEXEC)
        else
            c.accept(listener, null, null);
        switch (std.posix.errno(fd)) {
            .SUCCESS => {
                errdefer close(fd);
                if (builtin.os.tag == .macos) {
                    try configure(fd);
                    const one: c_int = 1;
                    try check(c.setsockopt(fd, c.SOL.SOCKET, c.SO.NOSIGPIPE, &one, @sizeOf(c_int)));
                }
                return fd;
            },
            .INTR => continue,
            .AGAIN => return null,
            .CONNABORTED => return error.ConnectionAborted,
            else => |err| {
                // Linux can report errors from the new TCP socket on accept.
                if (builtin.os.tag == .linux) switch (err) {
                    .PROTO, .NETDOWN, .NOPROTOOPT, .HOSTDOWN, .NONET, .HOSTUNREACH, .OPNOTSUPP, .NETUNREACH => return error.ConnectionAborted,
                    else => {},
                };
                return std.posix.unexpectedErrno(err);
            },
        }
    }
}

const Event = struct { key: u64, read: bool, write: bool };

const Poller = struct {
    fd: Fd,

    fn init() !Poller {
        const fd = if (builtin.os.tag == .linux) c.epoll_create1(linux.EPOLL.CLOEXEC) else c.kqueue();
        try check(fd);
        errdefer close(fd);
        if (builtin.os.tag == .macos) try check(c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC)));
        return .{ .fd = fd };
    }

    fn interest(poller: Poller, fd: Fd, token: u64, old: Interest, new: Interest) !void {
        if (old == new) return;
        if (builtin.os.tag == .linux) {
            const operation: c_uint = if (old == .none) linux.EPOLL.CTL_ADD else if (new == .none) linux.EPOLL.CTL_DEL else linux.EPOLL.CTL_MOD;
            var event: linux.epoll_event = .{
                .events = switch (new) {
                    .none => 0,
                    .read => linux.EPOLL.IN | linux.EPOLL.RDHUP,
                    .write => linux.EPOLL.OUT,
                },
                .data = .{ .u64 = token },
            };
            try check(c.epoll_ctl(poller.fd, operation, fd, &event));
        } else {
            var changes: [2]c.Kevent = undefined;
            var count: usize = 0;
            if (old != .none) {
                changes[count] = change(fd, token, old, c.EV.DELETE);
                count += 1;
            }
            if (new != .none) {
                changes[count] = change(fd, token, new, c.EV.ADD);
                count += 1;
            }
            var unused: [0]c.Kevent = .{};
            while (true) switch (std.posix.errno(c.kevent(poller.fd, &changes, @intCast(count), &unused, 0, null))) {
                .SUCCESS => break,
                .INTR => continue,
                else => |err| return std.posix.unexpectedErrno(err),
            };
        }
    }

    fn change(fd: Fd, token: u64, mode: Interest, flags: u16) c.Kevent {
        return .{
            .ident = @intCast(fd),
            .filter = if (mode == .read) c.EVFILT.READ else c.EVFILT.WRITE,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = @intCast(token),
        };
    }

    fn wait(poller: Poller, out: *[128]Event, timeout_ms: u31) !usize {
        if (builtin.os.tag == .linux) {
            var events: [out.len]linux.epoll_event = undefined;
            const count = c.epoll_wait(poller.fd, &events, events.len, timeout_ms);
            try checkWait(count);
            if (count < 0) return 0;
            for (events[0..@intCast(count)], out[0..@intCast(count)]) |event, *dst| {
                const hangup = event.events & (linux.EPOLL.ERR | linux.EPOLL.HUP) != 0;
                dst.* = .{
                    .key = event.data.u64,
                    .read = hangup or event.events & (linux.EPOLL.IN | linux.EPOLL.RDHUP) != 0,
                    .write = hangup or event.events & linux.EPOLL.OUT != 0,
                };
            }
            return @intCast(count);
        } else {
            var events: [out.len]c.Kevent = undefined;
            const timeout: c.timespec = .{ .sec = timeout_ms / 1000, .nsec = @as(isize, timeout_ms % 1000) * std.time.ns_per_ms };
            const count = c.kevent(poller.fd, &.{}, 0, &events, events.len, &timeout);
            try checkWait(count);
            if (count < 0) return 0;
            for (events[0..@intCast(count)], out[0..@intCast(count)]) |event, *dst| {
                dst.* = .{ .key = event.udata, .read = event.filter == c.EVFILT.READ, .write = event.filter == c.EVFILT.WRITE };
            }
            return @intCast(count);
        }
    }

    fn checkWait(result: c_int) !void {
        switch (std.posix.errno(result)) {
            .SUCCESS, .INTR => {},
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
};
