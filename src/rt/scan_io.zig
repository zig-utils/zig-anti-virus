//! Worker-owned traversal and file reading. The visitor receives memory for
//! complete small files and a bounded positional source for larger files.
const std = @import("std");
const builtin = @import("builtin");
const directory = @import("directory.zig");
const io_small = @import("io_small.zig");
const uring = @import("uring_files.zig");
const Source = @import("../engine/source.zig").Source;
const Scratch = @import("../engine/scratch.zig").Scratch;

pub const Mode = enum { auto, positional, io_uring };
pub const Cache = enum { keep, discard };

pub const Options = struct {
    reads: Mode = .auto,
    listing: directory.Mode = .native,
    cache: Cache = .keep,
    max_depth: usize = 128,
};

pub const Visitor = struct {
    context: *anyopaque,
    /// The relative path and source are borrowed for the duration of this call.
    file: *const fn (*anyopaque, []const u8, Source, ?directory.Volume) anyerror!void,
};

pub const Stats = struct {
    positional: u64 = 0,
    io_uring: u64 = 0,
};

const LinuxRing = if (builtin.os.tag == .linux) ?uring.Batch else void;
var fallback_logged: std.atomic.Value(bool) = .init(false);

pub const Reader = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    buffer: []u8,
    directory_scratch: Scratch,
    ring: LinuxRing,
    stats: Stats = .{},
    path: [std.fs.max_path_bytes]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: Options) !Reader {
        if (builtin.os.tag != .linux and options.reads == .io_uring)
            return error.IoUringUnavailable;
        const buffer = try allocator.alloc(u8, io_small.file_in_memory_max + 1);
        errdefer allocator.free(buffer);
        var directory_scratch = try Scratch.init(@import("../engine/scratch.zig").default_reservation);
        errdefer directory_scratch.deinit();
        const ring: LinuxRing = if (builtin.os.tag == .linux) switch (options.reads) {
            .positional => null,
            .io_uring => try uring.Batch.init(),
            .auto => uring.Batch.init() catch |err| blk: {
                if (!fallback_logged.swap(true, .monotonic))
                    std.log.info("io_uring initialization failed ({t}); using positional reads", .{err});
                break :blk null;
            },
        } else {};
        return .{ .allocator = allocator, .io = io, .options = options, .buffer = buffer, .directory_scratch = directory_scratch, .ring = ring };
    }

    pub fn deinit(reader: *Reader) void {
        reader.closeRing();
        reader.directory_scratch.deinit();
        reader.allocator.free(reader.buffer);
    }

    pub fn usingIoUring(reader: *const Reader) bool {
        if (builtin.os.tag != .linux) return false;
        return reader.ring != null;
    }

    fn closeRing(reader: *Reader) void {
        if (builtin.os.tag != .linux) return;
        if (reader.ring) |*ring| ring.deinit();
        reader.ring = null;
    }

    /// Walk an open, freshly positioned directory. Symlinks and special
    /// files are skipped. Errors opening an entry are reported to the caller.
    pub fn walk(reader: *Reader, root: std.Io.Dir, visitor: Visitor) !void {
        try walkDir(reader, root, 0, 0, visitor);
    }

    fn walkDir(reader: *Reader, dir: std.Io.Dir, prefix: usize, depth: usize, visitor: Visitor) anyerror!void {
        if (depth > reader.options.max_depth) return error.DirectoryDepthLimit;
        const mark = reader.directory_scratch.mark();
        defer reader.directory_scratch.release(mark);
        const entries = try directory.list(reader.directory_scratch.allocator(), reader.io, dir, reader.options.listing);
        const volume = try directory.volume(dir);
        var batch: [uring.batch_len]directory.Entry = undefined;
        var count: usize = 0;
        const context: Context = .{ .reader = reader, .dir = dir, .prefix = prefix, .volume = volume, .visitor = visitor };
        for (entries) |entry| switch (entry.kind) {
            .file => {
                batch[count] = entry;
                count += 1;
                if (count == batch.len) {
                    try reader.readBatch(context, &batch);
                    count = 0;
                }
            },
            .directory => {
                if (count != 0) {
                    try reader.readBatch(context, batch[0..count]);
                    count = 0;
                }
                const path = try reader.appendName(prefix, entry.name);
                if (path.len == reader.path.len) return error.PathTooLong;
                reader.path[path.len] = '/';
                const child = try dir.openDir(reader.io, entry.name, .{ .iterate = true, .follow_symlinks = false });
                defer child.close(reader.io);
                try reader.walkDir(child, path.len + 1, depth + 1, visitor);
            },
            else => {},
        };
        if (count != 0) try reader.readBatch(context, batch[0..count]);
    }

    fn appendName(reader: *Reader, prefix: usize, name: []const u8) ![]const u8 {
        if (name.len > reader.path.len - prefix) return error.PathTooLong;
        @memcpy(reader.path[prefix..][0..name.len], name);
        return reader.path[0 .. prefix + name.len];
    }

    const Context = struct {
        reader: *Reader,
        dir: std.Io.Dir,
        prefix: usize,
        volume: ?directory.Volume,
        visitor: Visitor,

        fn visit(ctx: Context, entry: directory.Entry, bytes: ?[]const u8, volume: ?directory.Volume) !void {
            const path = try ctx.reader.appendName(ctx.prefix, entry.name);
            if (bytes) |data| {
                ctx.reader.stats.io_uring += 1;
                return ctx.visitor.file(ctx.visitor.context, path, .{ .memory = data }, volume orelse ctx.volume);
            }
            try ctx.reader.readPositional(ctx, entry, path);
        }
    };

    fn readBatch(reader: *Reader, context: Context, entries: []const directory.Entry) !void {
        if (builtin.os.tag == .linux) if (reader.ring) |*ring| {
            errdefer reader.closeRing();
            return ring.read(context.dir.handle, entries, reader.buffer, reader.options.cache == .discard, context, Context.visit);
        };
        for (entries) |entry| try context.visit(entry, null, null);
    }

    fn readPositional(reader: *Reader, context: Context, entry: directory.Entry, path: []const u8) !void {
        const file: std.Io.File = if (builtin.os.tag == .linux or builtin.os.tag == .macos)
            .{ .handle = try std.posix.openatZ(context.dir.handle, entry.name, .{
                .NOFOLLOW = true,
                .NONBLOCK = true,
                .NOCTTY = true,
                .CLOEXEC = true,
            }, 0), .flags = .{ .nonblocking = true } }
        else
            try context.dir.openFile(reader.io, entry.name, .{ .follow_symlinks = false });
        defer file.close(reader.io);
        if (builtin.os.tag == .macos and reader.options.cache == .discard)
            _ = std.c.fcntl(file.handle, std.c.F.NOCACHE, @as(c_int, 1));
        defer if (builtin.os.tag == .linux and reader.options.cache == .discard) {
            _ = std.os.linux.fadvise(file.handle, 0, 0, std.os.linux.POSIX_FADV.DONTNEED);
        };
        const metadata = try fileMetadata(reader.io, file);
        var source: Source = .{ .file = .{ .file = file, .len = metadata.size } };
        if (metadata.size > io_small.file_in_memory_max) io_small.adviseSequential(source.file);
        // A positional retry during a ring wave shares the reader with
        // undelivered completions. Give the visitor the fd-backed source.
        if (!reader.usingIoUring() and metadata.size <= io_small.file_in_memory_max) {
            const bytes = reader.buffer[0..@intCast(metadata.size)];
            try source.readAllAt(reader.io, 0, bytes);
            source = .{ .memory = bytes };
        }
        reader.stats.positional += 1;
        try context.visitor.file(context.visitor.context, path, source, metadata.volume orelse context.volume);
    }
};

const Metadata = struct { size: u64, volume: ?directory.Volume = null };

fn fileMetadata(io: std.Io, file: std.Io.File) !Metadata {
    if (builtin.os.tag == .linux) if (try directory.linuxFdStat(file.handle)) |stat| {
        const linux = std.os.linux;
        if (!stat.mask.TYPE or stat.mode & linux.S.IFMT != linux.S.IFREG) return error.NotRegularFile;
        if (stat.mask.SIZE) return .{ .size = stat.size, .volume = directory.linuxVolume(stat) };
    };
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    return .{ .size = stat.size };
}

test "file I/O reads sorted regular files and retains relative paths" {
    const Check = struct {
        count: usize = 0,
        fn file(ptr: *anyopaque, path: []const u8, source: Source, _: ?directory.Volume) !void {
            const state: *@This() = @ptrCast(@alignCast(ptr));
            if (std.mem.eql(u8, path, "large")) {
                try std.testing.expectEqual(@as(?u64, io_small.file_in_memory_max + 3), source.len());
                try std.testing.expect(source == .file);
                var trailer: [3]u8 = undefined;
                try source.readAllAt(std.testing.io, io_small.file_in_memory_max, &trailer);
                try std.testing.expectEqualStrings("end", &trailer);
            } else if (std.mem.eql(u8, path, "empty")) {
                try std.testing.expectEqual(@as(?u64, 0), source.len());
            } else {
                const expected = if (std.mem.eql(u8, path, "one")) "hello" else if (std.mem.eql(u8, path, "nested/two")) "world" else return error.UnexpectedPath;
                var bytes: [5]u8 = undefined;
                try source.readAllAt(std.testing.io, 0, &bytes);
                try std.testing.expectEqualStrings(expected, &bytes);
            }
            state.count += 1;
        }
    };
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "nested", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "nested/two", .data = "world" });
    try tmp.dir.writeFile(io, .{ .sub_path = "one", .data = "hello" });
    try tmp.dir.writeFile(io, .{ .sub_path = "empty", .data = "" });
    {
        const large = try tmp.dir.createFile(io, "large", .{});
        defer large.close(io);
        try large.writePositionalAll(io, "end", io_small.file_in_memory_max);
    }
    if (builtin.os.tag != .windows)
        try tmp.dir.symLink(io, "one", "ignored", .{});
    for ([_]Mode{ .positional, .auto }) |mode| {
        const dir = try tmp.dir.openDir(io, ".", .{ .iterate = true });
        defer dir.close(io);
        var reader = try Reader.init(std.testing.allocator, io, .{ .reads = mode, .cache = .discard });
        defer reader.deinit();
        var check: Check = .{};
        try reader.walk(dir, .{ .context = &check, .file = Check.file });
        try std.testing.expectEqual(@as(usize, 4), check.count);
        try std.testing.expectEqual(@as(u64, 4), reader.stats.positional + reader.stats.io_uring);
        if (reader.usingIoUring()) try std.testing.expectEqual(@as(u64, 3), reader.stats.io_uring);
    }
}
