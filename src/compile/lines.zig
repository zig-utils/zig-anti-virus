//! Line-at-a-time reading of signature files from a stream, so a compile or census never holds a
//! whole database member in memory. Lines are bounded: a line longer than `max_line` is an error,
//! never an unbounded allocation (the longest line in current ClamAV databases is about 16 KB).
const std = @import("std");
const Io = std.Io;

pub const default_max_line: usize = 1 << 20;

pub const Error = error{ LineTooLong, ReadFailed } || std.mem.Allocator.Error;

pub const LineReader = struct {
    gpa: std.mem.Allocator,
    reader: *Io.Reader,
    buf: []u8 = &.{},
    start: usize = 0,
    end: usize = 0,
    /// Bytes from `start` already searched for a newline.
    scanned: usize = 0,
    eof: bool = false,
    max_line: usize = default_max_line,
    /// Number of the line most recently returned, from 1.
    line_number: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, reader: *Io.Reader) LineReader {
        return .{ .gpa = gpa, .reader = reader };
    }

    pub fn deinit(lr: *LineReader) void {
        lr.gpa.free(lr.buf);
        lr.* = undefined;
    }

    /// The next line without its `\n`, valid until the next call; null at the end of the stream.
    pub fn next(lr: *LineReader) Error!?[]const u8 {
        while (true) {
            const pending = lr.buf[lr.start + lr.scanned .. lr.end];
            if (std.mem.indexOfScalar(u8, pending, '\n')) |i| {
                const line = lr.buf[lr.start .. lr.start + lr.scanned + i];
                lr.start += lr.scanned + i + 1;
                lr.scanned = 0;
                lr.line_number += 1;
                return line;
            }
            lr.scanned = lr.end - lr.start;
            if (lr.eof) {
                if (lr.start == lr.end) return null;
                const line = lr.buf[lr.start..lr.end];
                lr.start = lr.end;
                lr.scanned = 0;
                lr.line_number += 1;
                return line;
            }
            try lr.fill();
        }
    }

    fn fill(lr: *LineReader) Error!void {
        if (lr.start > 0) {
            const live = lr.end - lr.start;
            std.mem.copyForwards(u8, lr.buf[0..live], lr.buf[lr.start..lr.end]);
            lr.start = 0;
            lr.end = live;
        }
        if (lr.end == lr.buf.len) {
            if (lr.buf.len > lr.max_line) return error.LineTooLong;
            const grown = @min(@max(lr.buf.len * 2, 64 * 1024), lr.max_line + 1);
            lr.buf = try lr.gpa.realloc(lr.buf, grown);
        }
        const n = lr.reader.readSliceShort(lr.buf[lr.end..]) catch return error.ReadFailed;
        lr.end += n;
        if (n == 0 or lr.end < lr.buf.len) lr.eof = true;
    }
};

test "lines across refills, a final line without a newline, CRLF left to the caller" {
    const gpa = std.testing.allocator;
    const xs = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (0..5000) |i| try text.print(gpa, "line-{d}-{s}\r\n", .{ i, xs });
    try text.appendSlice(gpa, "last");
    var r: Io.Reader = .fixed(text.items);
    var lr = LineReader.init(gpa, &r);
    defer lr.deinit();
    var n: usize = 0;
    while (try lr.next()) |line| : (n += 1) {
        if (n < 5000) {
            var want_buf: [64]u8 = undefined;
            const want = try std.fmt.bufPrint(&want_buf, "line-{d}-{s}\r", .{ n, xs });
            try std.testing.expectEqualStrings(want, line);
        } else try std.testing.expectEqualStrings("last", line);
    }
    try std.testing.expectEqual(@as(usize, 5001), n);
    try std.testing.expectEqual(@as(u32, 5001), lr.line_number);
}

test "an over-long line is refused, empty input has no lines" {
    const gpa = std.testing.allocator;
    var long: [303]u8 = @splat('a');
    long[300] = '\n';
    long[301] = 'b';
    long[302] = '\n';
    var r: Io.Reader = .fixed(&long);
    var lr = LineReader.init(gpa, &r);
    defer lr.deinit();
    lr.max_line = 100;
    try std.testing.expectError(error.LineTooLong, lr.next());

    var empty: Io.Reader = .fixed("");
    var le = LineReader.init(gpa, &empty);
    defer le.deinit();
    try std.testing.expectEqual(@as(?[]const u8, null), try le.next());
}
