//! Worker-owned Linux ring. Dynamic direct-open slots arrive in the open CQEs.
//! statx uses the directory fd and a name because it rejects fixed descriptors.
const std = @import("std");
const linux = std.os.linux;
const directory = @import("directory.zig");

pub const batch_len = 64;
const max_sqes = batch_len * 3;

const Operation = enum(u2) { stat, open, read, close };

const Item = struct {
    stat: linux.Statx = undefined,
    stat_ok: bool = false,
    slot: ?u32 = null,
    offset: usize = 0,
    length: ?usize = null,
    read_ok: bool = false,
};

pub const Batch = struct {
    ring: linux.IoUring,

    pub fn init() !Batch {
        var ring = try linux.IoUring.init(256, 0);
        errdefer ring.deinit();
        try ring.register_files_sparse(batch_len);
        return .{ .ring = ring };
    }

    pub fn deinit(batch: *Batch) void {
        batch.ring.deinit();
    }

    /// Deliver entries in input order. Null bytes ask the caller to open and
    /// stat the file normally. Views of successful reads are callback-scoped.
    /// The owner must tear down the ring if this operation returns an error.
    pub fn read(
        batch: *Batch,
        fd: linux.fd_t,
        entries: []const directory.Entry,
        buffer: []u8,
        discard_cache: bool,
        context: anytype,
        comptime visit: anytype,
    ) !void {
        std.debug.assert(entries.len <= batch_len);
        var scratch: [batch_len]Item = undefined;
        const items = scratch[0..entries.len];
        @memset(items, .{});
        for (entries, items, 0..) |entry, *item, i| {
            const stat = try batch.ring.statx(token(i, .stat), fd, entry.name, linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT, directory.linux_mask, &item.stat);
            stat.flags = linux.IOSQE_IO_LINK;
            _ = try batch.ring.openat_direct(token(i, .open), fd, entry.name, .{ .NOFOLLOW = true, .NONBLOCK = true, .NOCTTY = true }, 0, linux.IORING_FILE_INDEX_ALLOC);
        }
        try batch.complete(items);

        // At most one MiB of file data shares a worker buffer. A batch with
        // many large files can use several read waves without allocating.
        var start: usize = 0;
        while (start < entries.len) {
            var end = start;
            var used: usize = 0;
            while (end < entries.len) : (end += 1) {
                const item = &items[end];
                const slot = item.slot orelse continue;
                if (smallRegular(item, entries[end].inode, buffer.len)) |len| {
                    // Probe one byte beyond the listed size to catch growth.
                    if (len + 1 > buffer.len - used) break;
                    item.offset = used;
                    item.length = len;
                    used += len + 1;
                    const data = buffer[item.offset..used];
                    const sqe = try batch.ring.read(token(end, .read), @intCast(slot), .{ .buffer = data }, 0);
                    sqe.flags = linux.IOSQE_FIXED_FILE | linux.IOSQE_IO_HARDLINK;
                    if (discard_cache) {
                        const advice = try batch.ring.get_sqe();
                        advice.prep_rw(.FADVISE, @intCast(slot), 0, 0, 0);
                        advice.rw_flags = linux.POSIX_FADV.DONTNEED;
                        advice.flags = linux.IOSQE_FIXED_FILE | linux.IOSQE_IO_HARDLINK;
                        advice.user_data = ignored_token;
                    }
                }
                _ = try batch.ring.close_direct(token(end, .close), slot);
            }
            try batch.complete(items);
            // Hard links continue after a completed read failure. If kernel
            // SQE validation broke a chain before execution, close again.
            for (items[start..end], start..) |item, i| if (item.slot) |slot| {
                _ = try batch.ring.close_direct(token(i, .close), slot);
            };
            try batch.complete(items);
            for (entries[start..end], items[start..end]) |entry, item| {
                if (item.slot != null) return error.DirectCloseFailed;
                const bytes = if (item.read_ok) buffer[item.offset..][0..item.length.?] else null;
                try visit(context, entry, bytes, if (item.stat_ok) directory.linuxVolume(item.stat) else null);
            }
            start = end;
        }
    }

    fn complete(batch: *Batch, items: []Item) !void {
        const queued = batch.ring.sq_ready();
        if (queued == 0) return;
        std.debug.assert(queued <= max_sqes);
        // The shared head counts consumed SQEs even when enter is interrupted.
        // If submission fails, drain the accepted work before releasing its
        // pointers. The caller destroys the ring with any unsubmitted SQEs.
        var submit_error: ?anyerror = null;
        while (batch.ring.sq_ready() > 0) {
            _ = batch.ring.submit() catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => {
                    submit_error = err;
                    break;
                },
            };
        }
        var remaining = queued - batch.ring.sq_ready();
        var cqes: [max_sqes]linux.io_uring_cqe = undefined;
        while (remaining != 0) {
            const count = batch.ring.copy_cqes(cqes[0..remaining], remaining) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                error.SystemResources => {
                    std.Thread.yield() catch {};
                    continue;
                },
                else => return err,
            };
            remaining -= count;
            for (cqes[0..count]) |cqe| {
                if (cqe.user_data == ignored_token) continue;
                const item = &items[@intCast(cqe.user_data >> 2)];
                switch (@as(Operation, @fromBackingInt(@intCast(@as(u2, @truncate(cqe.user_data)))))) {
                    .stat => item.stat_ok = cqe.res == 0,
                    .open => if (cqe.res >= 0) {
                        item.slot = @intCast(cqe.res);
                    },
                    .read => item.read_ok = cqe.res >= 0 and cqe.res == item.length.?,
                    .close => if (cqe.res == 0) {
                        item.slot = null;
                    },
                }
            }
        }
        if (submit_error) |err| return err;
    }
};

const ignored_token = std.math.maxInt(u64);

fn token(i: usize, op: Operation) u64 {
    return (@as(u64, @intCast(i)) << 2) | @backingInt(op);
}

fn smallRegular(item: *const Item, inode: u64, capacity: usize) ?usize {
    if (!item.stat_ok) return null;
    const stat = &item.stat;
    if (!stat.mask.TYPE or !stat.mask.SIZE or !stat.mask.INO or stat.ino != inode) return null;
    if (stat.mode & linux.S.IFMT != linux.S.IFREG or stat.size >= capacity) return null;
    return @intCast(stat.size);
}
