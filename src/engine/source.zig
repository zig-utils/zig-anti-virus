//! What a scan reads from. A source is a byte range of an open file, a memory slice, a forward-only
//! stream (a decompressor over a parent source, INSTREAM data), or a spill file holding a child
//! that needs random access. Positional reads work on everything except streams; containers that
//! need random access over a stream copy it into memory (small) or a spill file (large) first.
const std = @import("std");
const Io = std.Io;

pub const Source = union(enum) {
    file: FileRange,
    memory: []const u8,
    stream: Stream,

    pub const FileRange = struct {
        file: Io.File,
        offset: u64 = 0,
        len: u64,
    };

    pub const Stream = struct {
        reader: *Io.Reader,
        /// Declared length if known (an untrusted header value; treat as a hint).
        len_hint: ?u64 = null,
    };

    pub const ReadError = error{NotSeekable} || Io.File.ReadPositionalError;

    /// Length in bytes, if known.
    pub fn len(s: Source) ?u64 {
        return switch (s) {
            .file => |f| f.len,
            .memory => |m| m.len,
            .stream => |st| st.len_hint,
        };
    }

    pub fn seekable(s: Source) bool {
        return s != .stream;
    }

    /// Read up to `buf.len` bytes at `offset`; 0 at the end.
    pub fn readAt(s: Source, io: Io, offset: u64, buf: []u8) ReadError!usize {
        switch (s) {
            .memory => |m| {
                if (offset >= m.len) return 0;
                const n = @min(buf.len, m.len - offset);
                @memcpy(buf[0..n], m[@intCast(offset)..][0..n]);
                return n;
            },
            .file => |f| {
                if (offset >= f.len) return 0;
                const want = @min(buf.len, f.len - offset);
                var vec: [1][]u8 = .{buf[0..@intCast(want)]};
                return f.file.readPositional(io, &vec, f.offset + offset);
            },
            .stream => return error.NotSeekable,
        }
    }

    /// Read exactly `buf.len` bytes at `offset`, or error.EndOfStream.
    pub fn readAllAt(s: Source, io: Io, offset: u64, buf: []u8) (ReadError || error{EndOfStream})!void {
        var done: usize = 0;
        while (done < buf.len) {
            const n = try s.readAt(io, offset + done, buf[done..]);
            if (n == 0) return error.EndOfStream;
            done += n;
        }
    }

    /// A sub-range of a seekable source (a container member stored without compression).
    pub fn slice(s: Source, offset: u64, length: u64) error{ NotSeekable, OutOfRange }!Source {
        const total = s.len() orelse return error.NotSeekable;
        if (offset > total or length > total - offset) return error.OutOfRange;
        return switch (s) {
            .memory => |m| .{ .memory = m[@intCast(offset)..][0..@intCast(length)] },
            .file => |f| .{ .file = .{ .file = f.file, .offset = f.offset + offset, .len = length } },
            .stream => error.NotSeekable,
        };
    }
};

/// A temporary file for a large child that needs random access. It is unlinked as soon as it is
/// created, so it never outlives the process and its pages are page cache, not private memory.
pub const Spill = struct {
    file: Io.File,
    len: u64 = 0,

    pub fn create(io: Io, dir: Io.Dir) !Spill {
        var name_buf: [64]u8 = undefined;
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.bufPrint(&name_buf, ".zav-spill-{x}", .{std.mem.readInt(u64, &nonce, .little)});
        const file = try dir.createFile(io, name, .{ .read = true, .exclusive = true });
        dir.deleteFile(io, name) catch {};
        return .{ .file = file };
    }

    pub fn append(sp: *Spill, io: Io, bytes: []const u8) !void {
        try sp.file.writePositionalAll(io, bytes, sp.len);
        sp.len += bytes.len;
    }

    pub fn source(sp: *const Spill) Source {
        return .{ .file = .{ .file = sp.file, .len = sp.len } };
    }

    pub fn close(sp: *Spill, io: Io) void {
        sp.file.close(io);
    }
};

test "memory, file and spill sources read the same bytes" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = "0123456789abcdef";
    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = data });
    const file = try tmp.dir.openFile(io, "f", .{});
    defer file.close(io);

    var spill = try Spill.create(io, tmp.dir);
    defer spill.close(io);
    try spill.append(io, data[0..8]);
    try spill.append(io, data[8..]);

    for ([_]Source{ .{ .memory = data }, .{ .file = .{ .file = file, .len = data.len } }, spill.source() }) |s| {
        var buf: [4]u8 = undefined;
        try s.readAllAt(io, 6, &buf);
        try std.testing.expectEqualStrings("6789", &buf);
        try std.testing.expectEqual(@as(usize, 0), try s.readAt(io, 16, &buf));
        const sub = try s.slice(4, 4);
        try sub.readAllAt(io, 0, &buf);
        try std.testing.expectEqualStrings("4567", &buf);
        try std.testing.expectError(error.OutOfRange, s.slice(10, 10));
    }
    var fixed: Io.Reader = .fixed(data);
    const st: Source = .{ .stream = .{ .reader = &fixed } };
    var b: [1]u8 = undefined;
    try std.testing.expectError(error.NotSeekable, st.readAt(io, 0, &b));
}
