//! Shared plumbing for sequential archives (tar, cpio): one cursor over either a positional
//! source or a forward-only stream, and member hand-off. Positional members become slices of the
//! parent, so nothing is copied and nested random-access formats need no materialising; stream
//! members become length-limited streams, and whatever the child leaves unread is skipped.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;

pub const Cursor = struct {
    w: *Walker,
    /// Exactly one of these is set.
    positional: ?Source = null,
    reader: ?*Io.Reader = null,
    off: u64 = 0,

    pub const ReadError = error{ EndOfStream, ReadFailed };

    /// Read exactly `buf.len` bytes.
    pub fn read(c: *Cursor, buf: []u8) ReadError!void {
        if (c.positional) |src| {
            src.readAllAt(c.w.io, c.off, buf) catch |e| return switch (e) {
                error.EndOfStream => error.EndOfStream,
                else => error.ReadFailed,
            };
        } else try c.reader.?.readSliceAll(buf);
        c.off += buf.len;
    }

    pub fn skip(c: *Cursor, n: u64) ReadError!void {
        if (c.positional) |src| {
            const total = src.len().?;
            if (n > total -| c.off) {
                c.off = total;
                return error.EndOfStream;
            }
        } else try c.reader.?.discardAll64(n);
        c.off += n;
    }

    /// Bytes left, when known.
    pub fn remaining(c: *const Cursor) ?u64 {
        const src = c.positional orelse return null;
        return src.len().? -| c.off;
    }

    /// Scan the next `size` bytes as a member named `name` and step past them. A member that runs
    /// past the end of a positional archive is scanned as far as it goes and reported malformed;
    /// false then tells the caller nothing follows.
    pub fn member(c: *Cursor, name: []const u8, size: u64, kind: container.Kind) container.Error!bool {
        if (c.positional) |src| {
            const avail = @min(size, src.len().? -| c.off);
            if (avail < size) c.w.notice(.malformed, "member runs past the end of the archive");
            const body = src.slice(c.off, avail) catch unreachable;
            try c.w.child(name, body, kind);
            c.off += avail;
            return avail == size;
        }
        const r = c.reader.?;
        const limited_buf = c.w.alloc(u8, container.block_len) orelse return false;
        defer c.w.free(limited_buf);
        var limited = r.limited(.limited64(size), limited_buf);
        try c.w.child(name, .{ .stream = .{ .reader = &limited.interface, .len_hint = size } }, kind);
        // Skip what the child did not read (a skipped member, a limit hit); buffered bytes first.
        const left_in_buffer = limited.interface.bufferedLen();
        limited.interface.tossBuffered();
        _ = left_in_buffer;
        const unread = @backingInt(limited.remaining);
        r.discardAll64(unread) catch {};
        c.off += size;
        return true;
    }
};

/// A name from a header field, cut at the first NUL.
pub fn cstr(field: []const u8) []const u8 {
    return field[0 .. std.mem.indexOfScalar(u8, field, 0) orelse field.len];
}
