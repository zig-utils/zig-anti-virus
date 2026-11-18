//! NSIS installer data, written from the layout in NSIS's fileform.h: the firstheader (flags,
//! the 0xDEADBEEF signature, "NullsoftInst", the header's length and the length of everything
//! that follows) at the start of the installer stub's overlay, then the data in one of two
//! layouts:
//! - non-solid: length-prefixed blocks, each compressed on its own (bit 31 of the length) or
//!   stored; the first is the install script header;
//! - solid: one compressed stream holding length-prefixed items, the header first.
//! Compression is deflate without a zlib header, LZMA (five property bytes, optionally behind a
//! BCJ filter flag) or NSIS's bzip2 variant (bzip2.zig `initNsis`). The method and layout are
//! not recorded, so they are recognised from the first bytes, as NSIS itself would try them.
//!
//! Children are "header" and "data/<n>" in order; the install script is not interpreted, so
//! file names are not recovered. The firstheader's length bounds the data; item lengths are
//! checked against it (non-solid) or bounded by the decoder's metered output (solid).
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const Budget = @import("../engine/budget.zig").Budget;
const inflate = @import("inflate.zig");
const bzip2 = @import("bzip2.zig");
const lzma = @import("lzma.zig");

pub const firstheader_len = 28;
const flag_no_crc = 4;

/// The firstheader's signature, at offset 4.
pub fn isFirstHeader(head: []const u8) bool {
    return head.len >= 20 and std.mem.eql(u8, head[4..20], "\xef\xbe\xad\xdeNullsoftInst");
}

const Method = enum { deflate, lzma, bzip2 };
const Layout = struct { method: Method, solid: bool, filter_flag: bool = false };

/// LZMA properties as NSIS writes them: lc=3, lp=0, pb=2, a power-of-two dictionary.
fn isLzma(p: []const u8) bool {
    if (p.len < 5 or p[0] != 0x5d) return false;
    const dict = std.mem.readInt(u32, p[1..5], .little);
    return dict >= 4096 and std.math.isPowerOfTwo(dict);
}

fn detectLayout(p: []const u8) Layout {
    if (isLzma(p)) return .{ .method = .lzma, .solid = true };
    if (p.len > 1 and p[0] <= 1 and isLzma(p[1..])) return .{ .method = .lzma, .solid = true, .filter_flag = true };
    if (p.len >= 4 and p[3] & 0x80 != 0) {
        const q = p[4..];
        if (isLzma(q)) return .{ .method = .lzma, .solid = false };
        if (q.len > 1 and q[0] <= 1 and isLzma(q[1..])) return .{ .method = .lzma, .solid = false, .filter_flag = true };
        if (q.len > 0 and q[0] == 0x31) return .{ .method = .bzip2, .solid = false };
        return .{ .method = .deflate, .solid = false };
    }
    if (p.len > 0 and p[0] == 0x31) return .{ .method = .bzip2, .solid = true };
    return .{ .method = .deflate, .solid = true };
}

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len().?;
    var fh: [firstheader_len]u8 = undefined;
    src.readAllAt(w.io, 0, &fh) catch return w.notice(.malformed, "nsis: truncated firstheader");
    const flags = le32(fh[0..]);
    const declared = le32(fh[24..]);
    var end: u64 = declared;
    if (end > total) {
        w.notice(.malformed, "nsis: installer data runs past the end of the file");
        end = total;
    } else if (flags & flag_no_crc == 0 and end >= firstheader_len + 4) end -= 4; // the CRC-32
    if (end <= firstheader_len) return;
    const data = src.slice(firstheader_len, end - firstheader_len) catch return;
    var head: [9]u8 = @splat(0);
    const n = data.readAt(w.io, 0, &head) catch 0;
    const layout = detectLayout(head[0..n]);
    if (layout.filter_flag and head[if (layout.solid) 0 else 4] == 1) w.notice(.unsupported, "nsis: BCJ filter (data scanned unfiltered)");
    var codec: Codec = .{ .w = w, .method = layout.method };
    defer codec.deinit();
    if (!codec.prepare(data, layout)) return;
    if (layout.solid) try solid(w, data, &codec, layout) else try blocks(w, data, &codec, layout);
}

/// Decoder state for one method, allocated once and reused for every block.
const Codec = struct {
    w: *Walker,
    method: Method,
    token: ?Budget.Token = null,
    work: []u8 = &.{},
    tt: []u32 = &.{},
    tables: ?*bzip2.Decoder.TablesType = null,
    probs: []u16 = &.{},
    dict_buf: []u8 = &.{},
    dict: lzma.Dict = undefined,
    header: lzma.Alone.Header = undefined,
    in_buf: []u8 = &.{},
    sr: container.SourceReader = undefined,
    inf: inflate.Inflate = undefined,
    bz: bzip2.Decoder = undefined,
    lz: lzma.Alone = undefined,
    /// Why the last stream stopped early, when it did.
    failure: ?[]const u8 = null,

    fn deinit(c: *Codec) void {
        if (c.token) |t| t.release();
    }

    fn prepare(c: *Codec, data: Source, layout: Layout) bool {
        const w = c.w;
        c.in_buf = w.alloc(u8, container.block_len) orelse return false;
        switch (c.method) {
            .deflate => c.work = w.alloc(u8, inflate.work_len) orelse return false,
            .bzip2 => {
                c.token = w.window(bzip2.workingSet(9), 0) orelse return false;
                c.tt = w.alloc(u32, 900_000) orelse return false;
                c.tables = w.scratch.allocator().create(bzip2.Decoder.TablesType) catch {
                    w.limit(.memory);
                    return false;
                };
            },
            .lzma => {
                var props: [5]u8 = undefined;
                const at: u64 = (if (layout.solid) @as(u64, 0) else 4) + @intFromBool(layout.filter_flag);
                data.readAllAt(w.io, at, &props) catch return false;
                c.header = lzma.Alone.parseHeader(&props) catch {
                    w.notice(.malformed, "nsis: LZMA properties");
                    return false;
                };
                const dict_len: u64 = @max(c.header.dict_size, 4096);
                const probs_len = c.header.props.probCount();
                c.token = w.window(dict_len, probs_len * 2) orelse return false;
                c.dict_buf = w.alloc(u8, @intCast(dict_len)) orelse return false;
                c.probs = w.alloc(u16, probs_len) orelse return false;
            },
        }
        return true;
    }

    /// A decoder over `comp` (one block, or the whole solid stream); null when it cannot start.
    fn open(c: *Codec, comp: Source, filter_flag: bool) ?*Io.Reader {
        c.failure = null;
        c.sr = .init(c.w.io, comp, c.in_buf);
        const in = &c.sr.interface;
        switch (c.method) {
            .deflate => {
                c.inf = .init(in, .raw, c.work);
                return &c.inf.interface;
            },
            .bzip2 => {
                c.bz = bzip2.Decoder.initNsis(in, c.tt, c.tables.?, &.{}) catch return null;
                return &c.bz.interface;
            },
            .lzma => {
                in.discardAll(@as(usize, @intFromBool(filter_flag)) + 5) catch return null;
                c.dict = .{ .buf = c.dict_buf };
                c.lz = lzma.Alone.init(in, c.header, null, c.probs, &c.dict, &.{}) catch return null;
                return &c.lz.interface;
            },
        }
    }

    /// Whether the decoder stopped on damaged data (as opposed to its input simply ending, which
    /// is how NSIS's LZMA blocks without an end marker finish).
    fn damaged(c: *const Codec) bool {
        return switch (c.method) {
            .deflate => if (c.inf.err) |e| e != error.EndOfStream else false,
            .bzip2 => if (c.bz.err) |e| e != error.EndOfStream else false,
            .lzma => if (c.lz.err) |e| e != error.EndOfStream else false,
        };
    }
};

/// Output metering for a decoder: the ratio guard and the scan's output budget, over the bytes
/// actually produced (MaxFileSize applies to each item, through its length).
const Guard = struct {
    w: *Walker,
    inner: *Io.Reader,
    pulled: *const u64,
    out: u64 = 0,
    tripped: bool = false,
    interface: Io.Reader,

    pub fn fill(g: *Guard, dest: []u8) Io.Reader.Error!usize {
        if (g.tripped) return error.ReadFailed;
        const n = container.readSome(g.inner, dest) catch |e| switch (e) {
            error.EndOfStream => return 0,
            error.ReadFailed => return error.ReadFailed,
        };
        const t = g.w.tracker;
        t.addOutput(g.pulled.*, g.out, n) catch {
            g.tripped = true;
            g.w.limit(t.last.?);
            return error.ReadFailed;
        };
        g.out += n;
        return n;
    }
};

fn itemName(buf: *[24]u8, index: u32) []const u8 {
    if (index == 0) return "header";
    return std.fmt.bufPrint(buf, "data/{d}", .{index}) catch unreachable;
}

/// Non-solid: [length][block] until the data ends.
fn blocks(w: *Walker, data: Source, codec: *Codec, layout: Layout) Error!void {
    const total = data.len().?;
    var off: u64 = 0;
    var index: u32 = 0;
    var name_buf: [24]u8 = undefined;
    const guard_buf = w.alloc(u8, container.block_len) orelse return;
    while (off + 4 <= total) : (index += 1) {
        if (w.halt != null) return error.Halted;
        var lb: [4]u8 = undefined;
        data.readAllAt(w.io, off, &lb) catch break;
        const raw = le32(&lb);
        const compressed = raw & 0x80000000 != 0;
        const len: u64 = raw & 0x7fffffff;
        off += 4;
        const name = itemName(&name_buf, index);
        if (len > total - off) {
            w.path.push(name);
            w.notice(.malformed, "nsis: block runs past the end of the data");
            w.path.pop();
        }
        const avail = @min(len, total - off);
        const body = data.slice(off, avail) catch unreachable;
        off += avail;
        if (avail == 0) continue;
        if (!compressed) {
            try w.child(name, body, .member);
            continue;
        }
        const r = codec.open(body, layout.filter_flag) orelse {
            w.path.push(name);
            w.notice(.malformed, "nsis: block does not start a stream");
            w.path.pop();
            continue;
        };
        var guard: Guard = .{ .w = w, .inner = r, .pulled = &codec.sr.pulled, .interface = .{ .vtable = container.fillVTable(Guard), .buffer = guard_buf, .seek = 0, .end = 0 } };
        try w.child(name, .{ .stream = .{ .reader = &guard.interface } }, .member);
        if (!guard.tripped and codec.damaged()) {
            w.path.push(name);
            w.notice(.malformed, "nsis: damaged compressed block");
            w.path.pop();
        }
    }
}

/// Solid: one stream of [length][item].
fn solid(w: *Walker, data: Source, codec: *Codec, layout: Layout) Error!void {
    const r = codec.open(data, layout.filter_flag) orelse return w.notice(.malformed, "nsis: data does not start a stream");
    const guard_buf = w.alloc(u8, container.block_len) orelse return;
    var guard: Guard = .{ .w = w, .inner = r, .pulled = &codec.sr.pulled, .interface = .{ .vtable = container.fillVTable(Guard), .buffer = guard_buf, .seek = 0, .end = 0 } };
    const stream = &guard.interface;
    const limited_buf = w.alloc(u8, container.block_len) orelse return;
    var name_buf: [24]u8 = undefined;
    var index: u32 = 0;
    while (true) : (index += 1) {
        if (w.halt != null) return error.Halted;
        const lb = stream.takeArray(4) catch |e| {
            if (e == error.ReadFailed and !guard.tripped and codec.damaged()) w.notice(.malformed, "nsis: damaged solid stream");
            return;
        };
        const len: u64 = le32(lb) & 0x7fffffff;
        const name = itemName(&name_buf, index);
        if (len > w.tracker.limits.max_file_size) {
            w.path.push(name);
            w.limit(.file_size);
            w.path.pop();
            stream.discardAll64(len) catch return;
            continue;
        }
        var limited = stream.limited(.limited64(len), limited_buf);
        try w.child(name, .{ .stream = .{ .reader = &limited.interface, .len_hint = len } }, .member);
        limited.interface.tossBuffered();
        stream.discardAll64(@backingInt(limited.remaining)) catch {
            if (!guard.tripped) {
                w.path.push(name);
                w.notice(.malformed, "nsis: item runs past the end of the solid stream");
                w.path.pop();
            }
            return;
        };
    }
}

fn le32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .little);
}

test "layout detection from the first bytes" {
    try std.testing.expectEqual(Layout{ .method = .lzma, .solid = true }, detectLayout("\x5d\x00\x00\x80\x00\x00\x00\x00\x00"));
    try std.testing.expectEqual(Layout{ .method = .lzma, .solid = true, .filter_flag = true }, detectLayout("\x01\x5d\x00\x00\x80\x00\x00\x00\x00"));
    try std.testing.expectEqual(Layout{ .method = .lzma, .solid = false }, detectLayout("\x10\x00\x00\x80\x5d\x00\x00\x10\x00"));
    try std.testing.expectEqual(Layout{ .method = .bzip2, .solid = false }, detectLayout("\x10\x00\x00\x80\x31\x00\x00\x10\x00"));
    try std.testing.expectEqual(Layout{ .method = .deflate, .solid = false }, detectLayout("\x10\x00\x00\x80\xed\x00\x00\x10\x00"));
    try std.testing.expectEqual(Layout{ .method = .bzip2, .solid = true }, detectLayout("\x31\x00\x00\x00\x00\x00\x00\x00\x00"));
    try std.testing.expectEqual(Layout{ .method = .deflate, .solid = true }, detectLayout("\xed\x00\x00\x00\x00\x00\x00\x00\x00"));
}
