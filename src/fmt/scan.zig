//! The format dispatcher: the `ParseFn` a `Walker` calls for every object. It detects the format
//! from the first bytes, hands the raw bytes to the visitor, and recurses into children.
//!
//! Positional sources are fed raw with positional reads, then parsed positionally (members of a
//! stored archive become slices, never copies). Streams are fed through a `Tee` while they are
//! parsed, so one pass both scans and parses them; a stream whose format needs random access is
//! materialised first (scratch up to 8 MiB, spill file beyond).
const std = @import("std");
const Io = std.Io;
const engine = struct {
    const container = @import("../engine/container.zig");
    const source = @import("../engine/source.zig");
};
const container = engine.container;
const Walker = container.Walker;
const Object = container.Object;
const Source = engine.source.Source;
const Error = container.Error;
const detect = @import("detect.zig");
const Format = detect.Format;
const decode = @import("decode.zig");

pub fn parse(w: *Walker, obj: *Object, src: Source) Error!void {
    switch (src) {
        .stream => |st| return parseStream(w, obj, st),
        else => return parsePositional(w, obj, src),
    }
}

fn parsePositional(w: *Walker, obj: *Object, src: Source) Error!void {
    var head: [detect.head_len]u8 = undefined;
    const n = src.readAt(w.io, 0, &head) catch 0;
    obj.format = detect.detect(head[0..n]);
    try w.begin(obj);
    try w.feedSource(obj, src);
    switch (obj.format) {
        .gzip, .bzip2, .xz, .zstd => {
            const buf = w.alloc(u8, container.block_len) orelse return;
            var sr: container.SourceReader = .init(w.io, src, buf);
            try decompress(w, obj, &sr.interface, &sr.pulled);
        },
        else => {},
    }
}

fn parseStream(w: *Walker, obj: *Object, st: Source.Stream) Error!void {
    const r = st.reader;
    r.fill(@min(detect.head_len, r.buffer.len)) catch |e| switch (e) {
        error.EndOfStream => {},
        error.ReadFailed => return if (w.halt != null) error.Halted else {},
    };
    obj.format = detect.detect(r.buffered());
    try w.begin(obj);
    const tee_buf = w.alloc(u8, container.block_len) orelse return w.drain(r);
    var tee: container.Tee = .init(w, obj, r, tee_buf);
    defer tee.interface = undefined;
    switch (obj.format) {
        .gzip, .bzip2, .xz, .zstd => try decompress(w, obj, &tee.interface, &tee.pulled),
        else => {},
    }
    try w.drain(&tee.interface);
}

/// Name for a compression wrapper's output: the parent's name without its extension.
fn innerName(name: []const u8, format: Format) []const u8 {
    const exts: []const []const u8 = switch (format) {
        .gzip => &.{ ".gz", ".tgz", ".z" },
        .bzip2 => &.{ ".bz2", ".tbz2", ".tbz" },
        .xz => &.{ ".xz", ".txz" },
        .zstd => &.{ ".zst", ".zstd", ".tzst" },
        else => &.{},
    };
    const base = if (std.mem.lastIndexOfScalar(u8, name, '/')) |i| name[i + 1 ..] else name;
    for (exts) |e| {
        if (base.len > e.len and std.ascii.endsWithIgnoreCase(base, e)) {
            return base[0 .. base.len - e.len];
        }
    }
    return @tagName(format);
}

/// Decode a compression wrapper read from `in` and scan its output as one stream child.
fn decompress(w: *Walker, obj: *const Object, in: *Io.Reader, pulled: *const u64) Error!void {
    const codec: decode.Codec = switch (obj.format) {
        .gzip => .gzip,
        .bzip2 => .bzip2,
        .xz => .xz,
        .zstd => .zstd,
        else => unreachable,
    };
    try decode.childFrom(w, codec, in, pulled, innerName(obj.name, obj.format), null, .decompressed);
}

// ---------------------------------------------------------------------------------------------
// Test support: a walker over the real dispatcher with a recording visitor.

pub const TestRig = struct {
    scratch: @import("../engine/scratch.zig").Scratch,
    tracker: @import("../engine/limits.zig").Tracker,
    budget: @import("../engine/budget.zig").Budget,
    rec: container.Recorder,
    tmp: std.testing.TmpDir,
    walker: Walker,

    pub fn init(rig: *TestRig, lim: @import("../engine/limits.zig").Limits) !void {
        rig.scratch = try .init(64 * 1024 * 1024);
        rig.tracker = .init(lim);
        rig.budget = .init(64 * 1024 * 1024);
        rig.rec = .{ .gpa = std.testing.allocator };
        rig.tmp = std.testing.tmpDir(.{});
        rig.walker = .{
            .io = std.testing.io,
            .scratch = &rig.scratch,
            .tracker = &rig.tracker,
            .budget = &rig.budget,
            .spill_dir = rig.tmp.dir,
            .visitor = rig.rec.visitor(),
            .parse = parse,
            .options = .{ .budget_wait_ms = 1 },
        };
    }

    pub fn deinit(rig: *TestRig) void {
        rig.rec.deinit();
        rig.tmp.cleanup();
        rig.scratch.deinit();
    }

    /// Scan `bytes` as a memory source, and again as a forward-only stream.
    pub fn scanBoth(rig: *TestRig, bytes: []const u8, name: []const u8) !void {
        rig.walker.scan(.{ .memory = bytes }, name) catch |e| if (rig.walker.halt == null) return e;
        rig.tracker.reset();
        var r: Io.Reader = .fixed(bytes);
        rig.walker.scan(.{ .stream = .{ .reader = &r } }, name) catch |e| if (rig.walker.halt == null) return e;
    }
};

const fixtures = @import("fixtures/fixtures.zig");

test "every compression vector scans end to end, positional and streamed" {
    inline for (.{ "gzip", "bzip2", "xz", "zstd" }) |group| {
        for (@field(fixtures, group ++ "_vectors")) |v| {
            var rig: TestRig = undefined;
            try rig.init(.{});
            defer rig.deinit();
            const name = group ++ ".bin";
            try rig.scanBoth(v.compressed, name);
            const limited = std.mem.eql(u8, v.name, "dict-64m") or std.mem.eql(u8, v.name, "window-128m");
            const unsupported = std.mem.eql(u8, v.name, "bcj-x86");
            var children: usize = 0;
            for (rig.rec.objects.items) |e| {
                if (e.kind != .decompressed) continue;
                children += 1;
                try std.testing.expectEqualStrings(name ++ "/" ++ group, e.path);
                try std.testing.expectEqual(@as(u64, v.plain_len), e.bytes);
                try std.testing.expectEqual(v.plain_crc, e.crc);
            }
            if (limited) {
                try std.testing.expect(rig.rec.hasLimit(.window_size));
                try std.testing.expectEqual(@as(usize, 0), children);
            } else if (unsupported) {
                try std.testing.expect(rig.rec.has(.unsupported));
            } else {
                if (rig.rec.notices.items.len != 0) {
                    std.debug.print("{s} {s}:\n", .{ group, v.name });
                    rig.rec.dump();
                }
                try std.testing.expectEqual(@as(usize, 0), rig.rec.notices.items.len);
                try std.testing.expectEqual(@as(usize, 2), children);
            }
            try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
        }
    }
}

test "nested wrappers: a gzip stream inside a zstd frame" {
    // The zstd frame stores the gzip vector in one raw block, so the gzip decoder reads from
    // the zstd decoder's output stream.
    const gz = fixtures.gzip_vectors[0];
    var rig: TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    // A raw zstd frame of the gzip bytes, stored as one raw block (frame header with
    // single-segment content size, then a raw last block).
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;
    try frame.appendSlice(gpa, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x60 }); // FHD: single segment, 2-byte FCS
    var fcs: [2]u8 = undefined;
    std.mem.writeInt(u16, &fcs, @intCast(gz.compressed.len - 256), .little);
    try frame.appendSlice(gpa, &fcs);
    const bh: u24 = @intCast((gz.compressed.len << 3) | 1); // raw block, last
    var bhb: [3]u8 = undefined;
    std.mem.writeInt(u24, &bhb, bh, .little);
    try frame.appendSlice(gpa, &bhb);
    try frame.appendSlice(gpa, gz.compressed);
    try rig.scanBoth(frame.items, "x.tar.gz.zst");
    const inner = rig.rec.find("x.tar.gz.zst/x.tar.gz/x.tar") orelse {
        rig.rec.dump();
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u64, gz.plain_len), inner.bytes);
    try std.testing.expectEqual(@as(u8, 2), inner.depth);
}

test "a decompression bomb of each format stops at the ratio limit with an event" {
    for (fixtures.bomb_vectors) |v| {
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        rig.scanBoth(v.compressed, "bomb.bin") catch |e| {
            std.debug.print("bomb {s}: {t}\n", .{ v.name, e });
            return e;
        };
        try std.testing.expect(rig.rec.hasLimit(.ratio));
        // Stopped once output passed 100x the compressed bytes read (the whole small file is read
        // in the first block), not at 64 MiB.
        const bound = 100 * @max(v.compressed.len, 1024 * 1024 / 100) + 2 * container.block_len;
        for (rig.rec.objects.items) |e| if (e.kind == .decompressed) try std.testing.expect(e.bytes <= bound);
    }
}
