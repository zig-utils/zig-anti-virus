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
    /// Formats only recognised on positional sources (disk images, by their trailer).
    positional_only: bool = false,
};

fn run(case: Case) !void {
    const io = std.testing.io;
    var scratch = try Scratch.init(64 * 1024 * 1024);
    defer scratch.deinit();
    var budget = Budget.init(64 * 1024 * 1024);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_]bool{ true, false }) |positional| {
        if (!positional and case.positional_only) continue;
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
        // A disk image partition of 64 zlib chunks, 64 MiB of zeros (positional only: a disk image
        // is found by its trailer).
        .{ .name = "zeros-bomb.dmg", .bytes = archive("zeros-bomb.dmg"), .expect = .{ .limit = .ratio }, .max_ms = 5_000, .lim = tight, .positional_only = true },
    };
    for (cases) |c| try run(c);
    // A zip quine (fixtures/documents.ts): its member is the zip itself, all the way down.
    for (@import("fixtures/docs.zig").docs) |d| if (std.mem.eql(u8, d.name, "quine.zip")) {
        try run(.{ .name = "quine.zip", .bytes = d.bytes, .expect = .{ .limit = .recursion }, .max_ms = 5_000, .lim = tight });
    };
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

/// A zlib stream of `n` zero bytes: one literal, then fixed-Huffman matches of 258 at distance
/// 1 (13 bits each), so 64 MiB costs about 420 KB.
fn zlibZeros(gpa: std.mem.Allocator, n: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, &.{ 0x78, 0x01 });
    var bits: u64 = 0;
    var nbits: u6 = 0;
    const W = struct {
        fn put(o: *std.ArrayList(u8), g: std.mem.Allocator, b: *u64, nb: *u6, v: u64, len: u6) !void {
            b.* |= v << nb.*;
            nb.* += len;
            while (nb.* >= 8) {
                try o.append(g, @truncate(b.*));
                b.* >>= 8;
                nb.* -= 8;
            }
        }
        /// Huffman codes go most significant bit first.
        fn code(o: *std.ArrayList(u8), g: std.mem.Allocator, b: *u64, nb: *u6, v: u64, len: u6) !void {
            var r: u64 = 0;
            for (0..len) |i| r |= ((v >> @intCast(i)) & 1) << @intCast(len - 1 - i);
            try put(o, g, b, nb, r, len);
        }
    };
    try W.put(&out, gpa, &bits, &nbits, 1, 1); // final
    try W.put(&out, gpa, &bits, &nbits, 1, 2); // fixed Huffman
    try W.code(&out, gpa, &bits, &nbits, 0x30, 8); // literal 0
    var left = n - 1;
    while (left >= 258) : (left -= 258) {
        try W.code(&out, gpa, &bits, &nbits, 0xc5, 8); // length 258
        try W.code(&out, gpa, &bits, &nbits, 0, 5); // distance 1
    }
    try W.code(&out, gpa, &bits, &nbits, 0, 7); // end of block
    if (nbits > 0) try out.append(gpa, @truncate(bits));
    return out.toOwnedSlice(gpa);
}

test "pathological PDFs stay within bounds" {
    const gpa = std.testing.allocator;
    // A 64 MiB zero bomb in one stream: the ratio guard stops it.
    {
        const z = try zlibZeros(gpa, 64 * 1024 * 1024);
        defer gpa.free(z);
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try b.print(gpa, "%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode /Length {d} >>\nstream\n", .{z.len});
        try b.appendSlice(gpa, z);
        try b.appendSlice(gpa, "\nendstream\nendobj\n%%EOF\n");
        try run(.{ .name = "bomb.pdf", .bytes = b.items, .expect = .{ .limit = .ratio }, .max_ms = 10_000, .lim = tight });
    }
    // 200,000 nested dictionaries in one object.
    {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try b.appendSlice(gpa, "%PDF-1.7\n1 0 obj\n");
        try b.appendNTimes(gpa, '<', 400_000);
        try b.appendSlice(gpa, "\nendobj\n");
        try run(.{ .name = "deep.pdf", .bytes = b.items, .expect = .{ .notice = .malformed }, .max_ms = 10_000, .lim = tight });
    }
    // More objects than the table holds.
    {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try b.appendSlice(gpa, "%PDF-1.7\n");
        for (0..pdf.max_objects + 1000) |i| try b.print(gpa, "{d} 0 obj null endobj\n", .{i + 1});
        try run(.{ .name = "many.pdf", .bytes = b.items, .expect = .{ .notice = .malformed }, .max_ms = 20_000, .lim = tight });
    }
    // A thousand chained filters.
    {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try b.appendSlice(gpa, "%PDF-1.7\n1 0 obj\n<< /Filter [");
        for (0..1000) |_| try b.appendSlice(gpa, "/AHx ");
        try b.appendSlice(gpa, "] /Length 4 >>\nstream\n4142\nendstream\nendobj\n");
        try run(.{ .name = "chain.pdf", .bytes = b.items, .expect = .{ .notice = .unsupported }, .max_ms = 5_000, .lim = tight });
    }
    // 20,000 streams that never end, lying lengths that refer to themselves, unclosed strings
    // and unresolvable JavaScript references: linear, not quadratic.
    {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try b.appendSlice(gpa, "%PDF-1.7\n");
        for (0..20_000) |i| try b.print(gpa, "{d} 0 obj << /Length {d} 0 R /JS {d} 0 R >> stream\n((((( data\n", .{ i + 1, i + 1, i + 900_000 });
        try run(.{ .name = "unterminated.pdf", .bytes = b.items, .expect = .nothing, .max_ms = 10_000, .lim = tight });
    }
}

const pdf = @import("pdf.zig");

test "pathological scripts stay linear in the JavaScript normaliser" {
    const gpa = std.testing.allocator;
    const size = 2 * 1024 * 1024;
    const patterns = [_][]const u8{
        "var v", // more declarations than the name table holds (each "var vvar v..." word differs)
        "'a'+", // one endless fold
        "unescape('%u", // call folds that never complete
        "String.fromCharCode(1,", // argument lists past the cap
        "/[", // regex classes that never close
        "((((", // deep nesting
    };
    for (patterns) |p| {
        const buf = try gpa.alloc(u8, size);
        defer gpa.free(buf);
        @memcpy(buf[0..8], "<script>");
        for (buf[8..], 0..) |*b, i| b.* = p[i % p.len];
        try run(.{ .name = "s.html", .bytes = buf, .expect = .nothing, .max_ms = 10_000, .lim = tight });
    }
    // Distinct identifiers: v0, v1, ... past the table.
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);
    try b.appendSlice(gpa, "<script>");
    for (0..200_000) |i| try b.print(gpa, "var v{d}=v{d};", .{ i, i / 2 });
    try run(.{ .name = "names.html", .bytes = b.items, .expect = .nothing, .max_ms = 10_000, .lim = tight });
}

test "pathological RTF stays linear" {
    const gpa = std.testing.allocator;
    const size = 2 * 1024 * 1024;
    const Pat = struct { []const u8, Expect };
    for ([_]Pat{
        .{ "{", .nothing }, // nesting
        .{ "{\\*\\objdata 41}", .{ .limit = .files } }, // more objects than MaxFiles
        .{ "\\bin99999999 ", .nothing }, // \bin lengths past the end
        .{ "\\objdata 0", .nothing }, // one object that never closes
    }) |c| {
        const buf = try gpa.alloc(u8, size);
        defer gpa.free(buf);
        @memcpy(buf[0..6], "{\\rtf1");
        for (buf[6..], 0..) |*b, i| b.* = c[0][i % c[0].len];
        try run(.{ .name = "a.rtf", .bytes = buf, .expect = c[1], .max_ms = 10_000, .lim = tight });
    }
}

/// A 7z archive of one folder (`coder` id, packed bytes) holding `files` files of the given
/// sizes, built from 7zFormat.txt.
fn sevenZip(gpa: std.mem.Allocator, coder: []const u8, packed_bytes: []const u8, unpack: u64, sizes: []const u64) ![]u8 {
    var h: std.ArrayList(u8) = .empty;
    defer h.deinit(gpa);
    const num = struct {
        fn put(l: *std.ArrayList(u8), g: std.mem.Allocator, v: u64) !void {
            // Always the 9-byte form: simple and valid.
            try l.append(g, 0xff);
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, v, .little);
            try l.appendSlice(g, &b);
        }
    }.put;
    try h.appendSlice(gpa, &.{ 0x01, 0x04, 0x06 });
    try num(&h, gpa, 0);
    try num(&h, gpa, 1);
    try h.append(gpa, 0x09);
    try num(&h, gpa, packed_bytes.len);
    try h.appendSlice(gpa, &.{ 0x00, 0x07, 0x0b });
    try num(&h, gpa, 1);
    try h.append(gpa, 0);
    try num(&h, gpa, 1);
    try h.append(gpa, @intCast(coder.len));
    try h.appendSlice(gpa, coder);
    try h.append(gpa, 0x0c);
    try num(&h, gpa, unpack);
    try h.appendSlice(gpa, &.{ 0x00, 0x08, 0x0d });
    try num(&h, gpa, sizes.len);
    try h.append(gpa, 0x09);
    for (sizes[0 .. sizes.len - 1]) |s| try num(&h, gpa, s);
    try h.appendSlice(gpa, &.{ 0x00, 0x00, 0x00 });
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "7z\xbc\xaf\x27\x1c\x00\x04\x00\x00\x00\x00");
    var tail: [16]u8 = undefined;
    std.mem.writeInt(u64, tail[0..8], packed_bytes.len, .little);
    std.mem.writeInt(u64, tail[8..16], h.items.len, .little);
    try out.appendSlice(gpa, &tail);
    try out.appendSlice(gpa, "\x00\x00\x00\x00");
    try out.appendSlice(gpa, packed_bytes);
    try out.appendSlice(gpa, h.items);
    return out.toOwnedSlice(gpa);
}

test "pathological 7z archives stay within bounds" {
    const gpa = std.testing.allocator;
    // A Deflate bomb: 64 MiB of zeros in one file.
    {
        const z = try zlibZeros(gpa, 64 * 1024 * 1024);
        defer gpa.free(z);
        const a = try sevenZip(gpa, "\x04\x01\x08", z[2..], 64 * 1024 * 1024, &.{64 * 1024 * 1024});
        defer gpa.free(a);
        try run(.{ .name = "bomb.7z", .bytes = a, .expect = .{ .limit = .ratio }, .max_ms = 10_000, .lim = tight });
    }
    // 5000 one-byte files in one stored folder: MaxFiles (2000 here).
    {
        const data = try gpa.alloc(u8, 5000);
        defer gpa.free(data);
        @memset(data, 'x');
        const sizes = try gpa.alloc(u64, 5000);
        defer gpa.free(sizes);
        @memset(sizes, 1);
        const a = try sevenZip(gpa, "\x00", data, 5000, sizes);
        defer gpa.free(a);
        try run(.{ .name = "many.7z", .bytes = a, .expect = .{ .limit = .files }, .max_ms = 10_000, .lim = tight });
    }
    // Sizes that claim far more than the folder holds.
    {
        const a = try sevenZip(gpa, "\x00", "abc", 1 << 40, &.{ 1 << 39, 1 << 39 });
        defer gpa.free(a);
        try run(.{ .name = "lies.7z", .bytes = a, .expect = .nothing, .max_ms = 5_000, .lim = tight });
    }
}
