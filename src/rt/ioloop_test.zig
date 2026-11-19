const std = @import("std");
const builtin = @import("builtin");
const rt = @import("ioloop.zig");
const jobs = @import("pool.zig");

const c = std.c;
const testing = std.testing;
const Fd = c.fd_t;

const Endpoint = union(enum) {
    tcp: c.sockaddr.in,
    unix: c.sockaddr.un,

    fn address(endpoint: *const Endpoint) *const c.sockaddr {
        return switch (endpoint.*) {
            inline else => |*addr| @ptrCast(addr),
        };
    }

    fn size(endpoint: *const Endpoint) c.socklen_t {
        return switch (endpoint.*) {
            inline else => |addr| @sizeOf(@TypeOf(addr)),
        };
    }

    fn bind(endpoint: *Endpoint, loop: *rt.Loop) !void {
        const socket = c.socket(endpoint.address().family, c.SOCK.STREAM, 0);
        try check(socket);
        errdefer close(socket);
        try check(c.bind(socket, endpoint.address(), endpoint.size()));
        try check(c.listen(socket, 128));
        if (endpoint.* == .tcp) {
            var len = endpoint.size();
            try check(c.getsockname(socket, @ptrCast(&endpoint.tcp), &len));
        }
        try loop.addListener(socket);
    }

    fn connect(endpoint: *const Endpoint) !Fd {
        const socket = c.socket(endpoint.address().family, c.SOCK.STREAM, 0);
        try check(socket);
        errdefer close(socket);
        try check(c.connect(socket, endpoint.address(), endpoint.size()));
        const flags: c.O = .{ .NONBLOCK = true };
        try check(c.fcntl(socket, c.F.SETFL, @as(c_int, @bitCast(flags))));
        return socket;
    }

    fn localTcp() Endpoint {
        return .{ .tcp = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) } };
    }

    fn localUnix(tmp: testing.TmpDir) !Endpoint {
        var addr: c.sockaddr.un = .{ .path = @splat(0) };
        _ = try std.fmt.bufPrint(addr.path[0 .. addr.path.len - 1], ".zig-cache/tmp/{s}/sock", .{tmp.sub_path});
        return .{ .unix = addr };
    }
};

const Echo = struct {
    entered: std.atomic.Value(bool) = .init(false),
    release: std.Io.Event = .unset,

    fn handler(echo: *Echo) rt.Handler {
        return .{ .context = echo, .frame = frame, .execute = execute };
    }

    fn frame(_: *anyopaque, bytes: []const u8) !?usize {
        const end = std.mem.indexOfScalar(u8, bytes, '\n') orelse return null;
        return end + 1;
    }

    fn execute(ptr: *anyopaque, worker: *jobs.Worker, buffer: []u8, length: usize) !usize {
        const echo: *Echo = @ptrCast(@alignCast(ptr));
        if (std.mem.eql(u8, buffer[0..length], "block\n")) {
            echo.entered.store(true, .release);
            echo.release.waitUncancelable(worker.pool.io);
        }
        return length;
    }
};

fn check(value: c_int) !void {
    switch (std.posix.errno(value)) {
        .SUCCESS => {},
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn close(fd: Fd) void {
    _ = c.close(fd);
}

fn send(fd: Fd, bytes: []const u8) !void {
    try testing.expectEqual(@as(isize, @intCast(bytes.len)), c.send(fd, bytes.ptr, bytes.len, 0));
}

fn receive(loop: *rt.Loop, fd: Fd, expected: []const u8) !void {
    var buffer: [128]u8 = undefined;
    var received: usize = 0;
    for (0..100) |_| {
        const running = try loop.step(20);
        const count = c.recv(fd, buffer[received..].ptr, expected.len - received, 0);
        switch (std.posix.errno(count)) {
            .SUCCESS => {
                if (count == 0) return error.UnexpectedEof;
                received += @intCast(count);
                if (received == expected.len) return testing.expectEqualStrings(expected, buffer[0..received]);
            },
            .AGAIN, .INTR => if (!running) try waitForClient(fd),
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    return error.EchoTimeout;
}

fn waitForClient(fd: Fd) !void {
    var events = [_]c.pollfd{.{ .fd = fd, .events = c.POLL.IN }};
    const count = c.poll(&events, events.len, 20);
    if (std.posix.errno(count) != .INTR) try check(count);
}

fn waitForWorker(loop: *rt.Loop, echo: *Echo) !void {
    for (0..100) |_| {
        if (echo.entered.load(.acquire)) return;
        _ = try loop.step(20);
    }
    return error.WorkerTimeout;
}

fn expectClosed(loop: *rt.Loop, fd: Fd) !void {
    var byte: [1]u8 = undefined;
    for (0..100) |_| {
        const count = c.recv(fd, &byte, byte.len, 0);
        switch (std.posix.errno(count)) {
            .SUCCESS => return testing.expectEqual(@as(isize, 0), count),
            .CONNRESET => return,
            .AGAIN, .INTR => if (!try loop.step(20)) try waitForClient(fd),
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    return error.ConnectionStillOpen;
}

test "event loop echoes fragmented and pipelined commands over TCP and Unix" {
    if (!rt.supported) return error.SkipZigTest;
    const pool = try jobs.Pool.init(testing.allocator, testing.io, .{ .workers = 1 });
    defer pool.deinit();
    var echo: Echo = .{};
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const loop = try rt.Loop.init(testing.allocator, pool, echo.handler(), .{ .max_connections = 1 });
    defer loop.deinit();

    var tcp = Endpoint.localTcp();
    try tcp.bind(loop);
    var unix = try Endpoint.localUnix(tmp);
    try unix.bind(loop);
    for ([_]Endpoint{ tcp, unix }) |endpoint| {
        const client = try endpoint.connect();
        defer close(client);
        try send(client, "on");
        _ = try loop.step(20);
        _ = try loop.step(20);
        try send(client, "e\ntwo\n");
        try receive(loop, client, "one\ntwo\n");
    }
    loop.requestStop();
    try loop.run();
}

test "event loop pauses socket reads while the injector is full then drains admitted work" {
    if (!rt.supported) return error.SkipZigTest;
    const pool = try jobs.Pool.init(testing.allocator, testing.io, .{ .workers = 1 });
    defer pool.deinit();
    var echo: Echo = .{};
    var queued: [4]jobs.Job = undefined;
    const loop = try rt.Loop.init(testing.allocator, pool, echo.handler(), .{});
    defer loop.deinit();
    defer echo.release.set(testing.io);
    var endpoint = Endpoint.localTcp();
    try endpoint.bind(loop);
    const first = try endpoint.connect();
    defer close(first);
    const second = try endpoint.connect();
    defer close(second);
    try send(first, "block\n");
    try waitForWorker(loop, &echo);
    const Noop = struct {
        fn run(_: *jobs.Worker, _: *jobs.Job) void {}
    };
    for (&queued) |*job| {
        job.* = .{ .run = Noop.run, .context = &echo };
        try testing.expectEqual(.accepted, pool.trySubmit(job));
    }
    try send(second, "pending\n");
    _ = try loop.step(0);
    try testing.expect(loop.pressure);
    for (loop.conns) |*conn| if (conn.phase == .reading) try testing.expectEqual(@as(usize, 0), conn.received);
    echo.release.set(testing.io);
    try receive(loop, first, "block\n");
    try receive(loop, second, "pending\n");
    try testing.expect(!loop.pressure);

    echo.release.reset();
    echo.entered.store(false, .release);
    try send(first, "block\nignored\n");
    try waitForWorker(loop, &echo);
    loop.requestStop();
    try testing.expect(try loop.step(0));
    try testing.expectEqual(@as(usize, 1), loop.connectionCount());
    echo.release.set(testing.io);
    try receive(loop, first, "block\n");
    try testing.expect(!(try loop.step(0)));
    try expectClosed(loop, first);
}

test "event loop expires idle and partial command connections" {
    if (!rt.supported) return error.SkipZigTest;
    const pool = try jobs.Pool.init(testing.allocator, testing.io, .{ .workers = 1 });
    defer pool.deinit();
    var echo: Echo = .{};
    const loop = try rt.Loop.init(testing.allocator, pool, echo.handler(), .{ .idle_timeout_ms = 500, .command_timeout_ms = 10 });
    defer loop.deinit();
    var endpoint = Endpoint.localTcp();
    try endpoint.bind(loop);
    const idle = try endpoint.connect();
    defer close(idle);
    const partial = try endpoint.connect();
    defer close(partial);
    try send(partial, "incomplete");
    _ = try loop.step(20);
    try testing.expectEqual(@as(usize, 2), loop.connectionCount());
    for (0..20) |_| {
        if (loop.connectionCount() == 1) break;
        _ = try loop.step(20);
    }
    try testing.expectEqual(@as(usize, 1), loop.connectionCount());
    try expectClosed(loop, partial);
    for (0..50) |_| {
        if (loop.connectionCount() == 0) break;
        _ = try loop.step(20);
    }
    try testing.expectEqual(@as(usize, 0), loop.connectionCount());
    try expectClosed(loop, idle);
}

const Usage = struct {
    rss: u64,
    threads: usize,

    fn sample() !Usage {
        if (builtin.os.tag == .linux) {
            var buffer: [4096]u8 = undefined;
            const data = try std.Io.Dir.cwd().readFile(testing.io, "/proc/self/status", &buffer);
            return .{
                .rss = try value(data, "VmRSS:\t") * 1024,
                .threads = @intCast(try value(data, "Threads:\t")),
            };
        } else {
            const task = c.mach_task_self();
            var info: c.mach_task_basic_info = undefined;
            var len: c.mach_msg_type_number_t = c.MACH.TASK.BASIC.INFO_COUNT;
            if (c.task_info(task, c.MACH.TASK.BASIC.INFO, @ptrCast(&info), &len) != 0) return error.TaskInfo;
            var thread_list: [*]c.thread_act_t = undefined;
            var thread_count: c.mach_msg_type_number_t = 0;
            if (c.task_threads(task, &thread_list, &thread_count) != 0) return error.TaskThreads;
            for (thread_list[0..thread_count]) |thread| _ = c.mach_port_deallocate(task, thread);
            _ = c.vm_deallocate(task, @intFromPtr(thread_list), thread_count * @sizeOf(c.thread_act_t));
            return .{ .rss = info.resident_size, .threads = thread_count };
        }
    }

    fn value(data: []const u8, field: []const u8) !u64 {
        const start = (std.mem.indexOf(u8, data, field) orelse return error.MissingProcessInfo) + field.len;
        var tokens = std.mem.tokenizeAny(u8, data[start..], " \t\n");
        return std.fmt.parseInt(u64, tokens.next() orelse return error.MissingProcessInfo, 10);
    }
};

test "event loop holds 10000 idle connections without creating threads" {
    if (!rt.supported) return error.SkipZigTest;
    const count = 10_000;
    var limits: c.rlimit = undefined;
    try check(c.getrlimit(.NOFILE, &limits));
    const required = count * 2 + 100;
    var raised = false;
    if (limits.cur < required) {
        if (limits.max < required or c.setrlimit(.NOFILE, &.{ .cur = required, .max = limits.max }) != 0)
            return error.SkipZigTest;
        raised = true;
    }
    defer if (raised) check(c.setrlimit(.NOFILE, &limits)) catch unreachable;

    const pool = try jobs.Pool.init(testing.allocator, testing.io, .{ .workers = 1 });
    defer pool.deinit();
    var echo: Echo = .{};
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const before = try Usage.sample();
    const loop = try rt.Loop.init(testing.allocator, pool, echo.handler(), .{ .max_connections = count });
    defer loop.deinit();
    var endpoint = try Endpoint.localUnix(tmp);
    try endpoint.bind(loop);
    const clients = try testing.allocator.alloc(Fd, count);
    defer testing.allocator.free(clients);
    var connected: usize = 0;
    defer for (clients[0..connected]) |fd| close(fd);
    while (connected < count) {
        clients[connected] = try endpoint.connect();
        connected += 1;
        if (connected % 32 == 0) _ = try loop.step(0);
    }
    for (0..100) |_| {
        if (loop.connectionCount() == count) break;
        _ = try loop.step(20);
    }
    try testing.expectEqual(@as(usize, count), loop.connectionCount());
    _ = try loop.step(100);
    try testing.expectEqual(@as(usize, count), loop.connectionCount());
    const after = try Usage.sample();
    const growth = after.rss -| before.rss;
    std.debug.print("event loop: {d} idle sockets, RSS +{d} bytes, threads {d} before / {d} after\n", .{ count, growth, before.threads, after.threads });
    try testing.expect(growth < 1_000_000_000);
    try testing.expectEqual(before.threads, after.threads);
    loop.requestStop();
    try loop.run();
}
