//! Bounded-memory building blocks for the compiler (docs/DESIGN.md section 4): append-only byte
//! sinks for large sections, and an external merge sort for fixed-size records.
//!
//! With a spill directory, a sink's bytes go to a temporary file that is mapped read-only when
//! the section is finished, and a sorter writes sorted runs of at most `budget` bytes and merges
//! them. Mapped pages are clean file pages: the kernel can drop them under pressure, and they are
//! not counted as the process's private memory. Without a spill directory (tests, small inputs)
//! everything stays on the heap and behaves the same.
//!
//! Temporary files are deleted when their owner is deinitialised; the caller deletes the spill
//! directory itself once the compile is done.
const std = @import("std");
const Io = std.Io;
const vm = @import("../rt/vm.zig");

pub const Spill = struct {
    io: Io,
    dir: Io.Dir,
    next: u32 = 0,

    pub fn init(io: Io, dir: Io.Dir) Spill {
        return .{ .io = io, .dir = dir };
    }

    const Name = struct {
        buf: [24]u8,
        len: u8,

        fn slice(n: *const Name) []const u8 {
            return n.buf[0..n.len];
        }
    };

    fn create(sp: *Spill) !struct { file: Io.File, name: Name } {
        var name: Name = undefined;
        const text = try std.fmt.bufPrint(&name.buf, "spill-{d}", .{sp.next});
        name.len = @intCast(text.len);
        sp.next += 1;
        const file = try sp.dir.createFile(sp.io, text, .{ .read = true, .truncate = true });
        return .{ .file = file, .name = name };
    }

    fn remove(sp: *Spill, file: Io.File, name: *const Name) void {
        file.close(sp.io);
        sp.dir.deleteFile(sp.io, name.slice()) catch {};
    }
};

const write_buffer = 256 * 1024;

/// An append-only section under construction.
pub const Sink = struct {
    gpa: std.mem.Allocator,
    spill: ?*Spill,
    mem: std.array_list.Aligned(u8, .@"8") = .empty,
    file: ?Io.File = null,
    name: Spill.Name = undefined,
    buf: []u8 = &.{},
    buffered: usize = 0,
    /// Bytes already in the file.
    written: u64 = 0,
    len: u64 = 0,
    mapping: ?vm.Mapping = null,

    pub fn init(gpa: std.mem.Allocator, spill: ?*Spill) Sink {
        return .{ .gpa = gpa, .spill = spill };
    }

    pub fn deinit(s: *Sink) void {
        if (s.mapping) |m| vm.unmapFile(m);
        if (s.file) |f| s.spill.?.remove(f, &s.name);
        s.gpa.free(s.buf);
        s.mem.deinit(s.gpa);
        s.* = undefined;
    }

    pub fn append(s: *Sink, bytes: []const u8) !void {
        std.debug.assert(s.mapping == null);
        s.len += bytes.len;
        const sp = s.spill orelse return s.mem.appendSlice(s.gpa, bytes);
        if (s.file == null) {
            const created = try sp.create();
            s.file = created.file;
            s.name = created.name;
            s.buf = try s.gpa.alloc(u8, write_buffer);
        }
        var rest = bytes;
        while (rest.len > 0) {
            if (s.buffered == s.buf.len) try s.flush();
            const n = @min(rest.len, s.buf.len - s.buffered);
            @memcpy(s.buf[s.buffered..][0..n], rest[0..n]);
            s.buffered += n;
            rest = rest[n..];
        }
    }

    /// Zero bytes up to a multiple of `alignment` (relative to the sink's start).
    pub fn alignTo(s: *Sink, alignment: usize) !void {
        const zeros: [64]u8 = @splat(0);
        const pad = std.mem.alignForward(u64, s.len, alignment) - s.len;
        try s.append(zeros[0..@intCast(pad)]);
    }

    fn flush(s: *Sink) !void {
        try s.file.?.writePositionalAll(s.spill.?.io, s.buf[0..s.buffered], s.written);
        s.written += s.buffered;
        s.buffered = 0;
    }

    /// The finished bytes, valid until `deinit`. The sink accepts no more appends.
    pub fn finish(s: *Sink) ![]const u8 {
        if (s.mapping) |m| return m[0..@intCast(s.len)];
        if (s.file == null) return s.mem.items;
        if (s.buffered > 0) try s.flush();
        s.gpa.free(s.buf);
        s.buf = &.{};
        if (s.len == 0) return &.{};
        s.mapping = try vm.mapFile(s.file.?.handle, @intCast(s.len));
        return s.mapping.?;
    }
};

/// External merge sort of fixed-size records. `add` buffers up to `budget` bytes of records; with
/// a spill directory each full buffer is sorted and written as a run, and `merge` streams the
/// runs back in order. Ties keep no particular order.
pub fn Sorter(comptime Rec: type, comptime lessThan: fn (void, Rec, Rec) bool) type {
    return struct {
        const Self = @This();
        const rec_size = @sizeOf(Rec);

        gpa: std.mem.Allocator,
        spill: ?*Spill,
        budget_records: usize,
        buf: std.ArrayList(Rec) = .empty,
        runs: std.ArrayList(Run) = .empty,
        count: u64 = 0,

        const Run = struct { file: Io.File, name: Spill.Name, count: u64 };

        pub fn init(gpa: std.mem.Allocator, spill: ?*Spill, budget_bytes: usize) Self {
            return .{ .gpa = gpa, .spill = spill, .budget_records = @max(budget_bytes / rec_size, 1024) };
        }

        pub fn deinit(s: *Self) void {
            for (s.runs.items) |*r| s.spill.?.remove(r.file, &r.name);
            s.runs.deinit(s.gpa);
            s.buf.deinit(s.gpa);
            s.* = undefined;
        }

        pub fn add(s: *Self, rec: Rec) !void {
            if (s.spill != null and s.buf.items.len == s.budget_records) try s.writeRun();
            try s.buf.append(s.gpa, rec);
            s.count += 1;
        }

        fn writeRun(s: *Self) !void {
            const sp = s.spill.?;
            std.mem.sortUnstable(Rec, s.buf.items, {}, lessThan);
            const created = try sp.create();
            errdefer sp.remove(created.file, &created.name);
            try created.file.writePositionalAll(sp.io, std.mem.sliceAsBytes(s.buf.items), 0);
            try s.runs.append(s.gpa, .{ .file = created.file, .name = created.name, .count = s.buf.items.len });
            s.buf.clearRetainingCapacity();
        }

        /// Every record added, in order. The sorter must outlive the iterator.
        pub fn merge(s: *Self) !Merge {
            std.mem.sortUnstable(Rec, s.buf.items, {}, lessThan);
            var m: Merge = .{ .sorter = s };
            if (s.runs.items.len == 0) return m;
            // Spilled before: the in-memory tail is one more (unwritten) source.
            m.heads = try s.gpa.alloc(Head, s.runs.items.len);
            const per = @max(64 * 1024 / rec_size, 16);
            for (m.heads, s.runs.items) |*h, r| {
                h.* = .{ .run = r, .buf = try s.gpa.alloc(Rec, per) };
                try h.refill(s.spill.?.io);
            }
            return m;
        }

        const Head = struct {
            run: Run,
            buf: []Rec,
            /// Records of the run read so far.
            read: u64 = 0,
            pos: usize = 0,
            len: usize = 0,

            fn refill(h: *Head, io: Io) !void {
                const n: usize = @intCast(@min(h.run.count - h.read, h.buf.len));
                h.pos = 0;
                h.len = n;
                if (n == 0) return;
                const bytes = std.mem.sliceAsBytes(h.buf[0..n]);
                if (try h.run.file.readPositionalAll(io, bytes, h.read * rec_size) != bytes.len) return error.Truncated;
                h.read += n;
            }

            fn peek(h: *const Head) ?Rec {
                return if (h.pos < h.len) h.buf[h.pos] else null;
            }
        };

        pub const Merge = struct {
            sorter: *Self,
            heads: []Head = &.{},
            mem_pos: usize = 0,

            pub fn deinit(m: *Merge) void {
                for (m.heads) |h| m.sorter.gpa.free(h.buf);
                m.sorter.gpa.free(m.heads);
            }

            pub fn next(m: *Merge) !?Rec {
                const mem = m.sorter.buf.items;
                var best: ?Rec = if (m.mem_pos < mem.len) mem[m.mem_pos] else null;
                var from: ?usize = null;
                for (m.heads, 0..) |*h, i| {
                    const r = h.peek() orelse continue;
                    if (best == null or lessThan({}, r, best.?)) {
                        best = r;
                        from = i;
                    }
                }
                const rec = best orelse return null;
                if (from) |i| {
                    const h = &m.heads[i];
                    h.pos += 1;
                    if (h.pos == h.len) try h.refill(m.sorter.spill.?.io);
                } else m.mem_pos += 1;
                return rec;
            }
        };
    };
}

test "a sink is the same bytes on the heap and in a spill file" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spill: Spill = .init(io, tmp.dir);
    var heap = Sink.init(gpa, null);
    defer heap.deinit();
    var file = Sink.init(gpa, &spill);
    defer file.deinit();
    var prng = std.Random.DefaultPrng.init(7);
    var chunk: [3000]u8 = undefined;
    for (0..400) |i| {
        prng.random().bytes(&chunk);
        const part = chunk[0 .. i * 7 % chunk.len];
        try heap.append(part);
        try file.append(part);
        if (i % 50 == 0) {
            try heap.alignTo(8);
            try file.alignTo(8);
        }
    }
    try std.testing.expectEqualSlices(u8, try heap.finish(), try file.finish());
    try std.testing.expect(file.mapping != null);
}

test "the external sort matches an in-memory sort across many runs" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spill: Spill = .init(io, tmp.dir);
    const Rec = extern struct { key: u64, tag: u32 };
    const less = struct {
        fn f(_: void, a: Rec, b: Rec) bool {
            return a.key < b.key or (a.key == b.key and a.tag < b.tag);
        }
    }.f;
    var sorter = Sorter(Rec, less).init(gpa, &spill, 1024 * @sizeOf(Rec));
    defer sorter.deinit();
    var want: std.ArrayList(Rec) = .empty;
    defer want.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(11);
    for (0..10_000) |i| {
        const r: Rec = .{ .key = prng.random().int(u16), .tag = @intCast(i) };
        try sorter.add(r);
        try want.append(gpa, r);
    }
    try std.testing.expect(sorter.runs.items.len >= 9);
    std.mem.sortUnstable(Rec, want.items, {}, less);
    var m = try sorter.merge();
    defer m.deinit();
    for (want.items) |w| try std.testing.expectEqual(w, (try m.next()).?);
    try std.testing.expectEqual(@as(?Rec, null), try m.next());
}
