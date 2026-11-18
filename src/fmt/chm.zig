//! Compiled HTML Help (.chm), the ITSF container, written from its public descriptions (the
//! format notes behind chmlib and libmspack): the ITSF header (versions 2 and 3), the ITSP
//! directory of PMGL listing chunks whose entries are ENCINT-coded (name, section, offset,
//! length), content section 0 (stored) and section 1 ("MSCompressed": LZX, lzx.zig, with the
//! reset interval and window from its ControlData and the output length from its ResetTable).
//!
//! Files in section 0 are slices of the file. Section 1 is decoded once, forward, and its files
//! are cut from the output in offset order; a file starting inside one already scanned is
//! reported as `overlap` and skipped, so work is bounded by the section's size. Internal
//! "::DataSpace" entries are not scanned as members (their bytes are part of the file's own raw
//! scan). Directory chunks, entry counts and every offset and length are bounded by the file.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const Budget = @import("../engine/budget.zig").Budget;
const lzx = @import("lzx.zig");

pub const max_name = 1024;
const max_chunks = 65536;
const ms_prefix = "::DataSpace/Storage/MSCompressed/";

const Entry = struct {
    name_off: u64,
    name_len: u16,
    section: u32,
    off: u64,
    len: u64,
};

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len().?;
    var h: [0x60]u8 = undefined;
    src.readAllAt(w.io, 0, h[0..0x58]) catch return w.notice(.malformed, "chm: truncated header");
    const version = le32(h[4..]);
    const dir_off = le64(h[0x48..]);
    const dir_len = le64(h[0x50..]);
    var content_off = dir_off +| dir_len;
    if (version >= 3) {
        src.readAllAt(w.io, 0, &h) catch return w.notice(.malformed, "chm: truncated header");
        content_off = le64(h[0x58..]);
    }
    var itsp: [0x54]u8 = undefined;
    src.readAllAt(w.io, dir_off, &itsp) catch return w.notice(.malformed, "chm: directory outside the file");
    if (!std.mem.eql(u8, itsp[0..4], "ITSP")) return w.notice(.malformed, "chm: bad directory header");
    const itsp_len = le32(itsp[8..]);
    const chunk_size = le32(itsp[16..]);
    const nchunks = le32(itsp[44..]);
    if (chunk_size < 32 or chunk_size > 1 << 20 or nchunks > max_chunks) return w.notice(.malformed, "chm: bad directory geometry");
    const chunks_off = dir_off + itsp_len;

    // Collect entries: members, plus the section 1 control files.
    const cap: usize = @as(usize, w.tracker.limits.max_files) + 16;
    const entries = w.alloc(Entry, cap) orelse return;
    var n: usize = 0;
    var control: ?Entry = null;
    var reset_table: ?Entry = null;
    var content: ?Entry = null;
    const chunk = w.alloc(u8, chunk_size) orelse return;
    var listed: usize = 0;
    var ci: u32 = 0;
    while (ci < nchunks) : (ci += 1) {
        if (w.halt != null) return error.Halted;
        src.readAllAt(w.io, chunks_off + @as(u64, ci) * chunk_size, chunk) catch {
            w.notice(.malformed, "chm: directory chunk outside the file");
            break;
        };
        if (!std.mem.eql(u8, chunk[0..4], "PMGL")) continue; // index chunks (PMGI) and junk
        const free = le32(chunk[4..]);
        const end = chunk_size -| free;
        var p: usize = 20;
        while (p < end) {
            const name_len = encint(chunk[0..end], &p) orelse break;
            if (name_len == 0 or name_len > max_name or name_len > end - p) break;
            const name_at = p;
            p += @intCast(name_len);
            const section = encint(chunk[0..end], &p) orelse break;
            const off = encint(chunk[0..end], &p) orelse break;
            const len = encint(chunk[0..end], &p) orelse break;
            const e: Entry = .{
                .name_off = chunks_off + @as(u64, ci) * chunk_size + name_at,
                .name_len = @intCast(name_len),
                .section = @intCast(@min(section, std.math.maxInt(u32))),
                .off = off,
                .len = len,
            };
            const name = chunk[name_at..][0..@intCast(name_len)];
            listed += 1;
            if (std.mem.startsWith(u8, name, ms_prefix)) {
                const rest = name[ms_prefix.len..];
                if (std.mem.eql(u8, rest, "ControlData")) control = e;
                if (std.mem.eql(u8, rest, "Content")) content = e;
                if (std.mem.endsWith(u8, rest, "/ResetTable")) reset_table = e;
                continue;
            }
            if (std.mem.startsWith(u8, name, "::") or name[name.len - 1] == '/' or len == 0) continue;
            if (n < cap) {
                entries[n] = e;
                n += 1;
            }
        }
    }
    if (listed == 0) return w.notice(.malformed, "chm: empty directory");

    // Section 0 members.
    var name_buf: [max_name]u8 = undefined;
    var position: u32 = 0;
    for (entries[0..n]) |e| {
        if (w.halt != null) return error.Halted;
        if (e.section != 0) continue;
        position +|= 1;
        const name = readName(w, src, e, &name_buf);
        const at = content_off +| e.off;
        if (at >= total) {
            w.path.push(name);
            w.notice(.malformed, "chm: file outside the content section");
            w.path.pop();
            continue;
        }
        const avail = @min(e.len, total - at);
        if (avail < e.len) {
            w.path.push(name);
            w.notice(.malformed, "chm: file runs past the end");
            w.path.pop();
        }
        checkCdb(w, src, name, e, position);
        try w.child(name, src.slice(at, avail) catch unreachable, .member);
    }

    // Section 1.
    var any1 = false;
    for (entries[0..n]) |e| if (e.section == 1) {
        any1 = true;
        break;
    };
    for (entries[0..n]) |e| if (e.section > 1) {
        w.notice(.unsupported, "chm: content section beyond MSCompressed");
        break;
    };
    if (!any1) return;
    const ctl = control orelse return w.notice(.malformed, "chm: compressed files without control data");
    const cnt = content orelse return w.notice(.malformed, "chm: compressed files without content");
    try section1(w, src, content_off, ctl, cnt, reset_table, entries[0..n], &position);
}

fn readName(w: *Walker, src: Source, e: Entry, buf: *[max_name]u8) []const u8 {
    const name = buf[0..e.name_len];
    src.readAllAt(w.io, e.name_off, name) catch return "?";
    // Names are absolute ("/index.html"); the member path drops the leading slash.
    return if (name.len > 1 and name[0] == '/') name[1..] else name;
}

fn checkCdb(w: *Walker, src: Source, name: []const u8, e: Entry, position: u32) void {
    const hook = w.options.cdb orelse return;
    w.path.push(name);
    defer w.path.pop();
    hook.check(w, .{
        .container_type = .mschm,
        .container_size = src.len().?,
        .name = name,
        .size_in_container = e.len,
        .size_real = e.len,
        .encrypted = false,
        .position = position,
    });
}

/// Read a whole section 0 file of at most `max` bytes into `buf`.
fn readSmall(w: *Walker, src: Source, content_off: u64, e: Entry, buf: []u8) ?[]u8 {
    if (e.len > buf.len or e.section != 0) return null;
    const b = buf[0..@intCast(e.len)];
    src.readAllAt(w.io, content_off +| e.off, b) catch return null;
    return b;
}

fn section1(w: *Walker, src: Source, content_off: u64, ctl: Entry, cnt: Entry, rt: ?Entry, entries: []const Entry, position: *u32) Error!void {
    var cbuf: [32]u8 = undefined;
    const c = readSmall(w, src, content_off, ctl, &cbuf) orelse return w.notice(.malformed, "chm: bad control data");
    if (c.len < 24 or !std.mem.eql(u8, c[4..8], "LZXC")) return w.notice(.unsupported, "chm: compression other than LZX");
    const cver = le32(c[8..]);
    var reset = le32(c[12..]);
    var window = le32(c[16..]);
    // Version 2 counts in 32 KiB frames, version 1 in bytes.
    if (cver != 2 and cver != 3) {
        reset /= lzx.frame_len;
        window /= lzx.frame_len;
    }
    // Window in frames -> bits: 1 frame is 2^15.
    if (window == 0 or !std.math.isPowerOfTwo(window)) return w.notice(.unsupported, "chm: LZX window size");
    const bits = 15 + @as(u32, std.math.log2_int(u32, window));
    if (bits < lzx.min_window_bits or bits > lzx.max_window_bits) return w.notice(.unsupported, "chm: LZX window size");
    // The section's uncompressed length: from the reset table, else as far as the files reach.
    var out_len: u64 = 0;
    if (rt) |r| {
        var rbuf: [40]u8 = undefined;
        if (r.len >= 40 and r.section == 0) {
            if (src.readAllAt(w.io, content_off +| r.off, &rbuf)) |_| out_len = le64(rbuf[16..]) else |_| {}
        }
    }
    if (out_len == 0) for (entries) |e| if (e.section == 1) {
        out_len = @max(out_len, e.off +| e.len);
    };
    const total = src.len().?;
    const cat = content_off +| cnt.off;
    if (cnt.section != 0 or cat > total) return w.notice(.malformed, "chm: compressed content outside the file");
    const comp = src.slice(cat, @min(cnt.len, total - cat)) catch unreachable;

    const window_len = lzx.Lzx.windowLen(@intCast(bits));
    const token = w.window(window_len, @sizeOf(lzx.Lzx.Tables)) orelse return;
    defer token.release();
    const win = w.alloc(u8, window_len) orelse return;
    const tables = w.scratch.allocator().create(lzx.Lzx.Tables) catch return w.limit(.memory);
    const in_buf = w.alloc(u8, container.block_len) orelse return;
    var sr: container.SourceReader = .init(w.io, comp, in_buf);
    const out_buf = w.alloc(u8, container.block_len) orelse return;
    var sec: SectionReader = .{
        .w = w,
        .sr = &sr,
        .dec = lzx.Lzx.init(&sr.interface, @intCast(bits), win, tables, reset),
        .remaining = out_len,
        .interface = .{ .vtable = container.fillVTable(SectionReader), .buffer = out_buf, .seek = 0, .end = 0 },
    };

    // Section 1 files in offset order.
    var count: usize = 0;
    for (entries) |e| {
        if (e.section == 1) count += 1;
    }
    const order = w.alloc(u32, count) orelse return;
    var k: usize = 0;
    for (entries, 0..) |e, i| if (e.section == 1) {
        order[k] = @intCast(i);
        k += 1;
    };
    std.sort.block(u32, order, entries, struct {
        fn lt(es: []const Entry, a: u32, b: u32) bool {
            return es[a].off < es[b].off;
        }
    }.lt);
    const limited_buf = w.alloc(u8, container.block_len) orelse return;
    var name_buf: [max_name]u8 = undefined;
    var cursor: u64 = 0;
    var reported_overlap = false;
    for (order) |i| {
        if (w.halt != null) return error.Halted;
        const e = entries[i];
        position.* +|= 1;
        const name = readName(w, src, e, &name_buf);
        if (e.off < cursor) {
            if (!reported_overlap) {
                w.path.push(name);
                w.notice(.overlap, "chm: files share compressed data");
                w.path.pop();
            }
            reported_overlap = true;
            continue;
        }
        if (e.off > out_len or e.len > out_len - e.off) {
            w.path.push(name);
            w.notice(.malformed, "chm: file runs past the end of the compressed section");
            w.path.pop();
        }
        checkCdb(w, src, name, e, position.*);
        sec.interface.discardAll64(e.off - cursor) catch return sec.finish();
        cursor = e.off;
        if (e.len > w.tracker.limits.max_file_size) {
            w.path.push(name);
            w.limit(.file_size);
            w.path.pop();
        } else {
            var limited = sec.interface.limited(.limited64(e.len), limited_buf);
            try w.child(name, .{ .stream = .{ .reader = &limited.interface, .len_hint = e.len } }, .member);
            limited.interface.tossBuffered();
            sec.interface.discardAll64(@backingInt(limited.remaining)) catch return sec.finish();
        }
        cursor += e.len;
    }
    sec.finish();
}

/// The decompressed section 1, frame by frame, metered.
const SectionReader = struct {
    w: *Walker,
    sr: *container.SourceReader,
    dec: lzx.Lzx,
    frame: []const u8 = &.{},
    remaining: u64,
    out: u64 = 0,
    failed: bool = false,
    limited: bool = false,
    interface: Io.Reader,

    pub fn fill(s: *SectionReader, dest: []u8) Io.Reader.Error!usize {
        if (s.failed or s.limited) return error.ReadFailed;
        if (s.frame.len == 0) {
            if (s.remaining == 0) return 0;
            const len: u32 = @intCast(@min(lzx.frame_len, s.remaining));
            s.frame = s.dec.frame(len) catch {
                s.failed = true;
                return error.ReadFailed;
            };
            s.remaining -= len;
        }
        const n = @min(dest.len, s.frame.len);
        @memcpy(dest[0..n], s.frame[0..n]);
        s.frame = s.frame[n..];
        const t = s.w.tracker;
        t.addOutput(s.sr.pulled, s.out, n) catch {
            s.limited = true;
            s.w.limit(t.last.?);
            return error.ReadFailed;
        };
        s.out += n;
        return n;
    }

    fn finish(s: *SectionReader) void {
        if (s.failed) s.w.notice(.malformed, "chm: LZX data is malformed");
        s.failed = false;
    }
};

/// A CHM variable-length integer: 7 bits per byte, most significant first, high bit = more.
fn encint(b: []const u8, p: *usize) ?u64 {
    var v: u64 = 0;
    var i: usize = 0;
    while (p.* < b.len and i < 9) : (i += 1) {
        const c = b[p.*];
        p.* += 1;
        v = (v << 7) | (c & 0x7f);
        if (c & 0x80 == 0) return v;
    }
    return null;
}

fn le32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .little);
}

fn le64(b: []const u8) u64 {
    return std.mem.readInt(u64, b[0..8], .little);
}

test "encint" {
    var p: usize = 0;
    try std.testing.expectEqual(@as(?u64, 0x7f), encint(&.{0x7f}, &p));
    p = 0;
    try std.testing.expectEqual(@as(?u64, 0x81), encint(&.{ 0x81, 0x01 }, &p));
    p = 0;
    try std.testing.expectEqual(@as(?u64, null), encint(&.{0x81}, &p));
}
