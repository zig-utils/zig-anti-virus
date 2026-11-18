//! PDF stream filters (ISO 32000-1 section 7.4) as chainable readers: ASCIIHexDecode,
//! ASCII85Decode, RunLengthDecode, LZWDecode and the TIFF and PNG predictors that follow
//! FlateDecode and LZWDecode. FlateDecode itself is our inflater (inflate.zig) in zlib mode.
//!
//! Each filter is an `Io.Reader` over the one before it, so a chain decodes in one streaming
//! pass with fixed memory. Like readers of damaged PDFs, the filters are tolerant: stray bytes
//! in ASCII filters are skipped, a missing end-of-data marker ends the stream at the end of its
//! input, and an invalid LZW code ends the stream with what was decoded so far (`err` is set).
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");

pub const Error = error{ InvalidCode, BadPredictor };

fn takeOrEnd(in: *Io.Reader) Io.Reader.Error!?u8 {
    return in.takeByte() catch |e| switch (e) {
        error.EndOfStream => null,
        error.ReadFailed => error.ReadFailed,
    };
}

fn isSpace(c: u8) bool {
    return switch (c) {
        0, '\t', '\n', 0x0c, '\r', ' ' => true,
        else => false,
    };
}

pub const AsciiHex = struct {
    in: *Io.Reader,
    done: bool = false,
    high: ?u8 = null,
    interface: Io.Reader,

    pub fn init(in: *Io.Reader, buffer: []u8) AsciiHex {
        return .{ .in = in, .interface = .{ .vtable = container.fillVTable(AsciiHex), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(d: *AsciiHex, dest: []u8) Io.Reader.Error!usize {
        var n: usize = 0;
        while (n < dest.len) {
            if (d.done) {
                // An odd final digit is followed by an implied 0.
                if (d.high) |h| {
                    dest[n] = h << 4;
                    n += 1;
                    d.high = null;
                }
                break;
            }
            const c = try takeOrEnd(d.in) orelse {
                d.done = true;
                continue;
            };
            if (c == '>') {
                d.done = true;
                continue;
            }
            const v = std.fmt.charToDigit(c, 16) catch continue;
            if (d.high) |h| {
                dest[n] = h << 4 | v;
                n += 1;
                d.high = null;
            } else d.high = v;
        }
        return n;
    }
};

pub const Ascii85 = struct {
    in: *Io.Reader,
    done: bool = false,
    out: [4]u8 = undefined,
    out_pos: u8 = 0,
    out_len: u8 = 0,
    interface: Io.Reader,

    pub fn init(in: *Io.Reader, buffer: []u8) Ascii85 {
        return .{ .in = in, .interface = .{ .vtable = container.fillVTable(Ascii85), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(d: *Ascii85, dest: []u8) Io.Reader.Error!usize {
        var n: usize = 0;
        while (n < dest.len) {
            if (d.out_pos < d.out_len) {
                dest[n] = d.out[d.out_pos];
                d.out_pos += 1;
                n += 1;
                continue;
            }
            if (d.done) break;
            try d.group();
        }
        return n;
    }

    /// Decode the next group of five characters (or one 'z') into `out`.
    fn group(d: *Ascii85) Io.Reader.Error!void {
        var tuple: u64 = 0;
        var count: u8 = 0;
        d.out_pos = 0;
        d.out_len = 0;
        while (count < 5) {
            const c = try takeOrEnd(d.in) orelse {
                d.done = true;
                break;
            };
            switch (c) {
                '!'...'u' => {
                    tuple = tuple * 85 + (c - '!');
                    count += 1;
                },
                'z' => if (count == 0) {
                    d.out = @splat(0);
                    d.out_len = 4;
                    return;
                },
                '~' => {
                    d.done = true;
                    break;
                },
                else => {}, // white space and stray bytes
            }
        }
        if (count == 0) return;
        // A final partial group of n characters is padded with 'u' and gives n - 1 bytes.
        const got = count;
        while (count < 5) : (count += 1) tuple = tuple * 85 + 84;
        std.mem.writeInt(u32, &d.out, @truncate(tuple), .big);
        d.out_len = if (got == 5) 4 else got - 1;
    }
};

pub const RunLength = struct {
    in: *Io.Reader,
    done: bool = false,
    /// Bytes left to copy literally, or to repeat `byte`.
    copy: u8 = 0,
    repeat: u16 = 0,
    byte: u8 = 0,
    interface: Io.Reader,

    pub fn init(in: *Io.Reader, buffer: []u8) RunLength {
        return .{ .in = in, .interface = .{ .vtable = container.fillVTable(RunLength), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(d: *RunLength, dest: []u8) Io.Reader.Error!usize {
        var n: usize = 0;
        while (n < dest.len) {
            if (d.repeat > 0) {
                const k = @min(d.repeat, dest.len - n);
                @memset(dest[n..][0..k], d.byte);
                n += k;
                d.repeat -= @intCast(k);
                continue;
            }
            if (d.copy > 0) {
                const c = try takeOrEnd(d.in) orelse {
                    d.done = true;
                    d.copy = 0;
                    break;
                };
                dest[n] = c;
                n += 1;
                d.copy -= 1;
                continue;
            }
            if (d.done) break;
            const len = try takeOrEnd(d.in) orelse {
                d.done = true;
                break;
            };
            if (len == 128) {
                d.done = true;
            } else if (len < 128) {
                d.copy = len + 1;
            } else {
                d.byte = try takeOrEnd(d.in) orelse {
                    d.done = true;
                    break;
                };
                d.repeat = 257 - @as(u16, len);
            }
        }
        return n;
    }
};

pub const Lzw = struct {
    in: *Io.Reader,
    t: *Table,
    early: u1,
    done: bool = false,
    err: ?Error = null,
    bits: u32 = 0,
    nbits: u5 = 0,
    code_len: u4 = 9,
    next: u16 = 258,
    prev: ?u16 = null,
    /// Decoded string waiting to be read: `t.stack[pos..]`.
    pos: u16 = 4096,
    interface: Io.Reader,

    pub const Table = struct {
        prefix: [4096]u16,
        suffix: [4096]u8,
        first: [4096]u8,
        len: [4096]u16,
        stack: [4096]u8,
    };

    pub fn init(in: *Io.Reader, t: *Table, early_change: bool, buffer: []u8) Lzw {
        for (0..256) |i| {
            t.suffix[i] = @intCast(i);
            t.first[i] = @intCast(i);
            t.len[i] = 1;
        }
        return .{ .in = in, .t = t, .early = @intFromBool(early_change), .interface = .{ .vtable = container.fillVTable(Lzw), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(d: *Lzw, dest: []u8) Io.Reader.Error!usize {
        var n: usize = 0;
        while (n < dest.len) {
            if (d.pos < 4096) {
                const k = @min(4096 - d.pos, dest.len - n);
                @memcpy(dest[n..][0..k], d.t.stack[d.pos..][0..k]);
                d.pos += @intCast(k);
                n += k;
                continue;
            }
            if (d.done) break;
            try d.step();
        }
        return n;
    }

    fn readCode(d: *Lzw) Io.Reader.Error!?u16 {
        while (d.nbits < d.code_len) {
            const c = try takeOrEnd(d.in) orelse return null;
            d.bits = d.bits << 8 | c;
            d.nbits += 8;
        }
        d.nbits -= d.code_len;
        return @intCast((d.bits >> d.nbits) & ((@as(u32, 1) << d.code_len) - 1));
    }

    fn step(d: *Lzw) Io.Reader.Error!void {
        const code = try d.readCode() orelse {
            d.done = true;
            return;
        };
        const t = d.t;
        if (code == 256) {
            d.next = 258;
            d.code_len = 9;
            d.prev = null;
            return;
        }
        if (code == 257) {
            d.done = true;
            return;
        }
        const prev = d.prev orelse {
            if (code > 255) return d.fail();
            d.emit(code);
            d.prev = code;
            return;
        };
        var first: u8 = undefined;
        if (code < d.next) {
            first = t.first[code];
            d.emit(code);
        } else if (code == d.next and d.next < 4096) {
            first = t.first[prev];
        } else return d.fail();
        if (d.next < 4096) {
            const e = d.next;
            t.prefix[e] = prev;
            t.suffix[e] = first;
            t.first[e] = t.first[prev];
            t.len[e] = @min(t.len[prev] + 1, 4096);
            d.next += 1;
            if (code == e) d.emit(e);
            if (d.next + d.early >= (@as(u32, 1) << d.code_len) and d.code_len < 12) d.code_len += 1;
        }
        d.prev = code;
    }

    /// Put the string for `code` in the output stack.
    fn emit(d: *Lzw, code: u16) void {
        const t = d.t;
        var c = code;
        var p: usize = 4096;
        const len = t.len[c];
        while (p > 4096 - @as(usize, len)) {
            p -= 1;
            t.stack[p] = t.suffix[c];
            if (c < 256) break;
            c = t.prefix[c];
        }
        d.pos = @intCast(p);
    }

    fn fail(d: *Lzw) void {
        d.err = error.InvalidCode;
        d.done = true;
    }
};

pub const Predictor = struct {
    in: *Io.Reader,
    kind: Kind,
    bpp: usize,
    row: []u8,
    prev: []u8,
    /// Decoded bytes of `row` not yet read.
    pos: usize,
    done: bool = false,
    interface: Io.Reader,

    pub const Kind = enum { tiff, png };

    pub const Params = struct {
        predictor: i64 = 1,
        colors: i64 = 1,
        bpc: i64 = 8,
        columns: i64 = 1,
        /// LZWDecode's /EarlyChange (default 1).
        early_change: bool = true,

        /// Bytes per row, or null when the parameters are out of range.
        pub fn rowLen(p: Params) ?usize {
            if (p.colors < 1 or p.colors > 32 or p.columns < 1 or p.columns > 1 << 24) return null;
            switch (p.bpc) {
                1, 2, 4, 8, 16 => {},
                else => return null,
            }
            const bits = @as(u64, @intCast(p.colors)) * @as(u64, @intCast(p.bpc)) * @as(u64, @intCast(p.columns));
            const len = (bits + 7) / 8;
            return if (len > max_row) null else @intCast(len);
        }

        pub fn bytesPerPixel(p: Params) usize {
            return @max(1, @as(usize, @intCast(p.colors * p.bpc)) / 8);
        }
    };

    pub const max_row = 1 << 20;

    /// `rows` holds 2 * row length bytes.
    pub fn init(in: *Io.Reader, kind: Kind, params: Params, rows: []u8, buffer: []u8) Predictor {
        const len = rows.len / 2;
        @memset(rows, 0);
        return .{
            .in = in,
            .kind = kind,
            .bpp = params.bytesPerPixel(),
            .row = rows[0..len],
            .prev = rows[len..],
            .pos = len,
            .interface = .{ .vtable = container.fillVTable(Predictor), .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    pub fn fill(d: *Predictor, dest: []u8) Io.Reader.Error!usize {
        var n: usize = 0;
        while (n < dest.len) {
            if (d.pos < d.row.len) {
                const k = @min(d.row.len - d.pos, dest.len - n);
                @memcpy(dest[n..][0..k], d.row[d.pos..][0..k]);
                d.pos += k;
                n += k;
                continue;
            }
            if (d.done) break;
            try d.nextRow();
        }
        return n;
    }

    fn nextRow(d: *Predictor) Io.Reader.Error!void {
        var filter: u8 = 0;
        if (d.kind == .png) filter = try takeOrEnd(d.in) orelse {
            d.done = true;
            return;
        };
        std.mem.swap([]u8, &d.row, &d.prev);
        // Read a whole row; a short final row is decoded as far as it goes.
        var got: usize = 0;
        while (got < d.row.len) {
            const k = container.readSome(d.in, d.row[got..]) catch |e| switch (e) {
                error.EndOfStream => break,
                error.ReadFailed => return error.ReadFailed,
            };
            got += k;
        }
        if (got < d.row.len) d.done = true;
        const row = d.row[0..got];
        const prev = d.prev;
        const bpp = d.bpp;
        switch (d.kind) {
            .tiff => for (row[@min(bpp, row.len)..], bpp..) |*b, i| {
                b.* +%= row[i - bpp];
            },
            .png => switch (filter) {
                0 => {},
                1 => for (row[@min(bpp, row.len)..], bpp..) |*b, i| {
                    b.* +%= row[i - bpp];
                },
                2 => for (row, 0..) |*b, i| {
                    b.* +%= prev[i];
                },
                3 => for (row, 0..) |*b, i| {
                    const left: u16 = if (i >= bpp) row[i - bpp] else 0;
                    b.* +%= @intCast((left + prev[i]) / 2);
                },
                4 => for (row, 0..) |*b, i| {
                    const a: i16 = if (i >= bpp) row[i - bpp] else 0;
                    const up: i16 = prev[i];
                    const c: i16 = if (i >= bpp) prev[i - bpp] else 0;
                    const p = a + up - c;
                    const pa = @abs(p - a);
                    const pb = @abs(p - up);
                    const pc = @abs(p - c);
                    const pred: i16 = if (pa <= pb and pa <= pc) a else if (pb <= pc) up else c;
                    b.* +%= @intCast(pred);
                },
                // An unknown row filter: the row is passed on as it is.
                else => {},
            },
        }
        d.pos = d.row.len - got;
        if (got < d.row.len) {
            // Move the short row to the end so `pos..` is exactly its bytes.
            std.mem.copyBackwards(u8, d.row[d.row.len - got ..], row);
        }
    }
};

// ---------------------------------------------------------------------------------------------

fn decodeAll(r: *Io.Reader, out: []u8) ![]u8 {
    var n: usize = 0;
    while (n < out.len) {
        const k = container.readSome(r, out[n..]) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        n += k;
    }
    return out[0..n];
}

test "ASCIIHex with white space, stray bytes and an odd final digit" {
    var in: Io.Reader = .fixed("48 65\n6c6C6f2 >trailing");
    var buf: [16]u8 = undefined;
    var d = AsciiHex.init(&in, &buf);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Hello ", try decodeAll(&d.interface, &out));
}

test "ASCII85 groups, z, partial final group and the end marker" {
    // "Man is d" encodes as 9jqo^BlbD-; then a z group for four zeros, then "Ma" as a partial group.
    var in: Io.Reader = .fixed("9jqo^\nBl bD-z9jn~>ignored");
    var buf: [3]u8 = undefined;
    var d = Ascii85.init(&in, &buf);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "Man is d\x00\x00\x00\x00Ma", try decodeAll(&d.interface, &out));
}

test "RunLength literal and repeated runs" {
    var in: Io.Reader = .fixed("\x02abc\xfdx\x80zz");
    var buf: [2]u8 = undefined;
    var d = RunLength.init(&in, &buf);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("abcxxxx", try decodeAll(&d.interface, &out));
}

/// A plain LZW encoder (9 to 12 bits, early change) for the round-trip test.
fn lzwEncode(gpa: std.mem.Allocator, data: []const u8, early: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var dict: std.StringHashMapUnmanaged(u16) = .empty;
    defer dict.deinit(gpa);
    var bits: u64 = 0;
    var nbits: u6 = 0;
    var code_len: u4 = 9;
    var next: u32 = 258;
    const e: u32 = @intFromBool(early);
    const put = struct {
        fn f(o: *std.ArrayList(u8), g: std.mem.Allocator, b: *u64, nb: *u6, code: u32, len: u4) !void {
            b.* = b.* << len | code;
            nb.* += len;
            while (nb.* >= 8) {
                nb.* -= 8;
                try o.append(g, @truncate(b.* >> nb.*));
            }
        }
    }.f;
    try put(&out, gpa, &bits, &nbits, 256, code_len);
    var w_start: usize = 0;
    var w_len: usize = 0;
    var w_code: u32 = 0;
    for (data, 0..) |c, i| {
        if (w_len == 0) {
            w_start = i;
            w_len = 1;
            w_code = c;
            continue;
        }
        const cand = data[w_start .. i + 1];
        if (dict.get(cand)) |code| {
            w_len += 1;
            w_code = code;
            continue;
        }
        try put(&out, gpa, &bits, &nbits, w_code, code_len);
        if (next < 4096) {
            try dict.put(gpa, cand, @intCast(next));
            next += 1;
            // The decoder adds each entry one code later, so it widens one code later too.
            if (next + e > (@as(u32, 1) << code_len) and code_len < 12) code_len += 1;
        }
        w_start = i;
        w_len = 1;
        w_code = c;
    }
    if (w_len > 0) {
        try put(&out, gpa, &bits, &nbits, w_code, code_len);
        // The decoder adds an entry for this last code as well.
        if (next < 4096) {
            next += 1;
            if (next + e > (@as(u32, 1) << code_len) and code_len < 12) code_len += 1;
        }
    }
    try put(&out, gpa, &bits, &nbits, 257, code_len);
    if (nbits > 0) try out.append(gpa, @truncate(bits << (8 - @as(u4, @intCast(nbits)))));
    return out.toOwnedSlice(gpa);
}

test "LZW round trip, both early-change settings, past the 12-bit table" {
    const gpa = std.testing.allocator;
    var data: [20000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    for (&data, 0..) |*b, i| b.* = if (i % 7 == 0) prng.random().int(u8) else "abcab"[i % 5];
    const t = try gpa.create(Lzw.Table);
    defer gpa.destroy(t);
    for ([_]bool{ true, false }) |early| {
        const enc = try lzwEncode(gpa, &data, early);
        defer gpa.free(enc);
        var in: Io.Reader = .fixed(enc);
        var buf: [100]u8 = undefined;
        var d = Lzw.init(&in, t, early, &buf);
        const out = try gpa.alloc(u8, data.len + 10);
        defer gpa.free(out);
        try std.testing.expectEqualSlices(u8, &data, try decodeAll(&d.interface, out));
        try std.testing.expect(d.err == null);
    }
    // The classic example from the PDF reference: 80 1B 88 64 A5 ... decodes "-----A---B".
    var in: Io.Reader = .fixed("\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01");
    var buf: [8]u8 = undefined;
    var d = Lzw.init(&in, t, true, &buf);
    var out: [32]u8 = undefined;
    try std.testing.expectEqualStrings("-----A---B", try decodeAll(&d.interface, &out));
}

test "PNG predictors: every row filter" {
    // Two rows of 3 bytes, 1 byte per pixel: Sub then Up, then Average and Paeth.
    const enc = "\x01\x01\x01\x01" ++ "\x02\x01\x01\x01" ++ "\x03\x05\x05\x05" ++ "\x04\x01\x00\x00" ++ "\x00\x09\x08";
    var in: Io.Reader = .fixed(enc);
    var rows: [6]u8 = undefined;
    var buf: [4]u8 = undefined;
    var d = Predictor.init(&in, .png, .{ .predictor = 12, .columns = 3 }, &rows, &buf);
    var out: [32]u8 = undefined;
    const got = try decodeAll(&d.interface, &out);
    // Sub: 1 2 3; Up: 2 3 4; Average: 5+(0+2)/2=6, 5+(6+3)/2=9, 5+(9+4)/2=11;
    // Paeth: 6+1=7, 9+0=9 (pred up), 11+0=11; short last row "\x09\x08" with filter 0.
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 2, 3, 4, 6, 9, 11, 7, 9, 11, 9, 8 }, got);
}
