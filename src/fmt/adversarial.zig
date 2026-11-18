//! The adversarial corpus (P5.17): bombs, nesting past every limit and pathological markup and
//! archives, each scanned positionally and as a stream with a declared wall-time bound and a
//! scratch-memory bound. A case passes when the walk ends inside both bounds, with every
//! big-window token returned and every scratch byte released, having reported the limit it was
//! built to hit. Bounds are generous for Debug builds on CI runners; the point is "bounded",
//! the benchmark gate (A1) measures "fast".
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const limits = @import("../engine/limits.zig");
const Scratch = @import("../engine/scratch.zig").Scratch;
const Budget = @import("../engine/budget.zig").Budget;
const scan = @import("scan.zig");
const fixtures = @import("fixtures/fixtures.zig");

/// Counts bytes and remembers which notices it saw; allocates nothing.
const Counter = struct {
    bytes: u64 = 0,
    objects: u64 = 0,
    max_depth: u8 = 0,
    events: std.EnumSet(limits.Event) = .empty,
    kinds: std.EnumSet(std.meta.Tag(container.Notice.What)) = .empty,

    fn visitor(c: *Counter) container.Visitor {
        return .{ .ptr = c, .vtable = &.{ .enter = enter, .data = data, .leave = leave, .notice = notice } };
    }
    fn enter(ptr: *anyopaque, obj: *const container.Object) error{Stop}!void {
        const c: *Counter = @ptrCast(@alignCast(ptr));
        c.objects += 1;
        c.max_depth = @max(c.max_depth, obj.depth);
    }
    fn data(ptr: *anyopaque, _: *const container.Object, bytes: []const u8) error{Stop}!void {
        const c: *Counter = @ptrCast(@alignCast(ptr));
        c.bytes += bytes.len;
    }
    fn leave(_: *anyopaque, _: *const container.Object) void {}
    fn notice(ptr: *anyopaque, n: container.Notice) void {
        const c: *Counter = @ptrCast(@alignCast(ptr));
        c.kinds.insert(n.what);
        if (n.what == .limit) c.events.insert(n.what.limit);
    }
};

const Expect = union(enum) {
    limit: limits.Event,
    notice: std.meta.Tag(container.Notice.What),
    nothing,
};

const Case = struct {
    name: []const u8,
    bytes: []const u8,
    expect: Expect,
    max_ms: i64,
    max_scratch: usize = 40 * 1024 * 1024,
    lim: limits.Limits = .{},
};

fn run(case: Case) !void {
    const io = std.testing.io;
    var scratch = try Scratch.init(64 * 1024 * 1024);
    defer scratch.deinit();
    var budget = Budget.init(64 * 1024 * 1024);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_]bool{ true, false }) |positional| {
        var tracker = limits.Tracker.init(case.lim);
        var counter: Counter = .{};
        var w: container.Walker = .{
            .io = io,
            .scratch = &scratch,
            .tracker = &tracker,
            .budget = &budget,
            .spill_dir = tmp.dir,
            .visitor = counter.visitor(),
            .parse = scan.parse,
            .options = .{ .budget_wait_ms = 0 },
        };
        scratch.high_water = 0;
        const start = Io.Clock.awake.now(io);
        if (positional) {
            w.scan(.{ .memory = case.bytes }, case.name) catch {};
        } else {
            var r: Io.Reader = .fixed(case.bytes);
            w.scan(.{ .stream = .{ .reader = &r } }, case.name) catch {};
        }
        const ms = @divTrunc(start.durationTo(Io.Clock.awake.now(io)).nanoseconds, std.time.ns_per_ms);
        scratch.reset();
        const ok_time = ms <= case.max_ms;
        const ok_mem = scratch.high_water <= case.max_scratch;
        const ok_expect = switch (case.expect) {
            .limit => |e| counter.events.contains(e),
            .notice => |k| counter.kinds.contains(k),
            .nothing => true,
        };
        if (!ok_time or !ok_mem or !ok_expect or budget.used.load(.monotonic) != 0) {
            std.debug.print("adversarial {s} ({s}): {d} ms (bound {d}), scratch {d} (bound {d}), expect {any} met={}, events {any}\n", .{
                case.name, if (positional) "positional" else "stream", ms, case.max_ms, scratch.high_water, case.max_scratch, case.expect, ok_expect, counter.events,
            });
            return error.AdversarialBoundExceeded;
        }
        // Output never runs past the scan-wide limits.
        try std.testing.expect(counter.bytes <= case.lim.max_scan_size + container.block_len);
    }
}

fn archive(name: []const u8) []const u8 {
    for (fixtures.archives) |a| if (std.mem.eql(u8, a.name, name)) return a.bytes;
    unreachable;
}

/// Tighter than clamd's defaults so Debug runs stay short; the cases scale with the limits.
const tight: limits.Limits = .{ .max_scan_size = 64 * 1024 * 1024, .max_total_output = 32 * 1024 * 1024, .max_files = 2000 };

test "bombs and nesting stop at their limits within bounds" {
    const cases = [_]Case{
        // 42.zip style: 16^4 leaves of 64 MiB each.
        .{ .name = "nested-bomb.zip", .bytes = archive("nested-bomb.zip"), .expect = .{ .limit = .ratio }, .max_ms = 20_000, .lim = tight },
        .{ .name = "overlap-bomb.zip", .bytes = archive("overlap-bomb.zip"), .expect = .{ .notice = .overlap }, .max_ms = 10_000, .lim = tight },
        .{ .name = "same-entry-bomb.zip", .bytes = archive("same-entry-bomb.zip"), .expect = .{ .notice = .overlap }, .max_ms = 10_000, .lim = tight },
        .{ .name = "deep-40.zip", .bytes = archive("deep-40.zip"), .expect = .{ .limit = .recursion }, .max_ms = 5_000, .lim = tight },
        .{ .name = "deep-40.gz", .bytes = archive("deep-40.gz"), .expect = .{ .limit = .recursion }, .max_ms = 5_000, .lim = tight },
        // ISO 9660: 24 levels of directories, each listing the next twice (2^24 paths).
        .{ .name = "dag-bomb.iso", .bytes = archive("dag-bomb.iso"), .expect = .{ .notice = .overlap }, .max_ms = 2_000, .lim = tight },
        // A cabinet folder of 2048 MSZIP blocks, 64 MiB of zeros.
        .{ .name = "zeros-bomb.cab", .bytes = archive("zeros-bomb.cab"), .expect = .{ .limit = .ratio }, .max_ms = 5_000, .lim = tight },
    };
    for (cases) |c| try run(c);
    for (fixtures.bomb_vectors) |v| try run(.{ .name = v.name, .bytes = v.compressed, .expect = .{ .limit = .ratio }, .max_ms = 10_000, .lim = tight });
}

test "pathological markup and archives stay linear" {
    const gpa = std.testing.allocator;
    const size = 2 * 1024 * 1024;
    const patterns = [_][]const u8{
        "<", // every byte opens a tag
        "<a href=\"", // attribute values that never close
        "&#", // entity starts that never finish
        "<div>", // deep nesting
        "<!-", // comment starts that never complete
        "<script>x<", // script bodies with false terminators
    };
    for (patterns) |p| {
        const buf = try gpa.alloc(u8, size);
        defer gpa.free(buf);
        @memcpy(buf[0..6], "<html>");
        for (buf[6..], 0..) |*b, i| b.* = p[i % p.len];
        try run(.{ .name = "p.html", .bytes = buf, .expect = .nothing, .max_ms = 10_000, .lim = tight });
    }
    // 5000 one-byte tar members: MaxFiles (2000 here), reported once.
    {
        const n = 5000;
        const buf = try gpa.alloc(u8, (2 * n + 2) * 512);
        defer gpa.free(buf);
        @memset(buf, 0);
        for (0..n) |i| {
            tarHeader(buf[2 * i * 512 ..][0..512], i, 1);
            buf[(2 * i + 1) * 512] = 'x';
        }
        try run(.{ .name = "many.tar", .bytes = buf, .expect = .{ .limit = .files }, .max_ms = 10_000, .lim = tight });
    }
    // A tar member claiming 4 GiB in a 1 KiB file: scanned as far as it goes.
    {
        var buf: [1024]u8 = @splat(0);
        tarHeader(buf[0..512], 0, 4 * 1024 * 1024 * 1024 - 1);
        try run(.{ .name = "huge.tar", .bytes = &buf, .expect = .{ .notice = .malformed }, .max_ms = 2_000, .lim = tight });
    }
}

fn tarHeader(h: *[512]u8, i: usize, size: u64) void {
    _ = std.fmt.bufPrint(h[0..100], "f{d}", .{i}) catch unreachable;
    @memcpy(h[100..108], "0000644\x00");
    _ = std.fmt.bufPrint(h[124..136], "{o:0>11}\x00", .{size}) catch unreachable;
    h[156] = '0';
    @memcpy(h[257..265], "ustar\x0000");
    @memset(h[148..156], ' ');
    var sum: u32 = 0;
    for (h) |c| sum += c;
    _ = std.fmt.bufPrint(h[148..156], "{o:0>6}\x00 ", .{sum}) catch unreachable;
}
