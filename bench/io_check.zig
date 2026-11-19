//! Strict acceptance check for the deterministic small-file corpus.
const std = @import("std");
const builtin = @import("builtin");
const zav = @import("zav");
const scan_io = zav.rt.scan_io;

const Mode = enum { pread, uring, bulk, fallback };

const Check = struct {
    io: std.Io,
    seen: std.DynamicBitSet,
    count: usize = 0,

    fn file(ptr: *anyopaque, path: []const u8, source: zav.engine.source.Source, _: ?zav.rt.directory.Volume) !void {
        const check: *Check = @ptrCast(@alignCast(ptr));
        if (path.len != 7 or path[3] != '/') return error.InvalidFixturePath;
        const shard = try decimal(path[0..3]);
        const entry = try decimal(path[4..7]);
        const id = shard * 1000 + entry;
        if (id >= check.seen.capacity() or check.seen.isSet(id)) return error.DuplicateOrUnexpectedFile;
        if (source.len() != @as(?u64, 4096)) return error.WrongFileSize;
        var buffer: [4096]u8 = undefined;
        const bytes = if (source == .memory) source.memory else blk: {
            try source.readAllAt(check.io, 0, &buffer);
            break :blk &buffer;
        };
        var offset: usize = 0;
        while (offset < bytes.len) : (offset += 8) {
            if (std.mem.readInt(u64, bytes[offset..][0..8], .little) != id) return error.WrongFileBytes;
        }
        check.seen.set(id);
        check.count += 1;
    }
};

fn decimal(chars: []const u8) !usize {
    var value: usize = 0;
    for (chars) |c| {
        if (c < '0' or c > '9') return error.InvalidFixturePath;
        value = value * 10 + (c - '0');
    }
    return value;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 4 or args.len > 5) {
        std.debug.print("usage: io-check pread|uring|bulk|fallback ROOT COUNT [discard]\n", .{});
        return error.InvalidArguments;
    }
    const mode = std.meta.stringToEnum(Mode, args[1]) orelse return error.InvalidArguments;
    if (mode == .bulk and builtin.os.tag != .macos) return error.RequiresMacOS;
    const count = try std.fmt.parseInt(usize, args[3], 10);
    if (count == 0 or count > 1_000_000) return error.InvalidFileCount;
    const cache: scan_io.Cache = if (args.len == 4) .keep else if (std.mem.eql(u8, args[4], "discard")) .discard else return error.InvalidArguments;

    var check: Check = .{ .io = init.io, .seen = try .initEmpty(init.gpa, count) };
    defer check.seen.deinit();
    var reader = try scan_io.Reader.init(init.gpa, init.io, .{
        .reads = switch (mode) {
            .pread, .bulk => .positional,
            .uring => .io_uring,
            .fallback => .auto,
        },
        .listing = if (mode == .pread) .portable else .native,
        .cache = cache,
    });
    defer reader.deinit();
    if (mode == .fallback and reader.usingIoUring()) return error.IoUringWasNotBlocked;
    const dir = try std.Io.Dir.cwd().openDir(init.io, args[2], .{ .iterate = true });
    defer dir.close(init.io);
    const begin = std.Io.Clock.awake.now(init.io);
    try reader.walk(dir, .{ .context = &check, .file = Check.file });
    if (check.count != count) return error.MissingFiles;
    if (mode == .uring and reader.stats.io_uring != count) return error.UnexpectedPositionalRetry;
    const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - begin.nanoseconds;
    std.debug.print("{t}: {d} files, {d} bytes verified, {d} io_uring reads, {d} positional reads, {d:.2}s\n", .{
        mode,                                   check.count, check.count * 4096, reader.stats.io_uring, reader.stats.positional,
        @as(f64, @floatFromInt(elapsed)) / 1e9,
    });
}
