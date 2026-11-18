//! Apple disk images (UDIF), written from the publicly documented layout: the 512-byte "koly"
//! trailer, the XML property list it points at, and the "mish" block tables carried base64 in
//! its `resource-fork` / `blkx` array. Each blkx entry is one partition (an MBR, an HFS+ or APFS
//! volume, a FAT volume) described as a run of chunks; each partition becomes one stream child,
//! "partition/<n>", decoded chunk by chunk.
//!
//! Chunk types: zero fill (0) and ignored (2) as zeros, raw (1), ADC (0x80000004, Apple Data
//! Compression), zlib (0x80000005), bzip2 (0x80000006), LZFSE (0x80000007, lzfse.zig) and xz
//! (0x80000008, ULMO). Images whose block tables live only in a resource fork (no XML) and
//! unknown chunk types are reported as unsupported.
//!
//! Bounds: the trailer's offsets are checked against the image; the property list is read with
//! a bounded streaming tokenizer; a block table holds at most `max_mish` bytes; a partition
//! larger than MaxFileSize is reported and skipped; every chunk's output is cut or zero-padded
//! to exactly the sectors it claims; chunks that run backwards are skipped; compressed output is
//! metered against the ratio guard and the scan's output budget (zero fill counts as stored, so
//! a sparse image does not trip the ratio guard but still spends the output budget).
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const Budget = @import("../engine/budget.zig").Budget;
const xml = @import("xml");
const inflate = @import("inflate.zig");
const bzip2 = @import("bzip2.zig");
const xz = @import("xz.zig");
const lzma = @import("lzma.zig");
const lzfse = @import("lzfse.zig");

pub const trailer_len = 512;
/// The largest block table accepted (about 100,000 chunks).
pub const max_mish = 4 * 1024 * 1024;
/// Chunks decoded whole (ADC, LZFSE) and their input are held in scratch up to this size.
pub const max_chunk = 8 * 1024 * 1024;
const sector = 512;

/// Whether the last 512 bytes are a UDIF trailer. Positional sources only: a stream cannot be
/// read from its end, so disk images are recognised when scanned as files or stored members.
pub fn hasTrailer(w: *Walker, src: Source) bool {
    const total = src.len() orelse return false;
    if (total < trailer_len) return false;
    var magic: [8]u8 = undefined;
    src.readAllAt(w.io, total - trailer_len, &magic) catch return false;
    return std.mem.eql(u8, &magic, "koly\x00\x00\x00\x04");
}

const Koly = struct {
    data_off: u64,
    data_len: u64,
    xml_off: u64,
    xml_len: u64,
};

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len().?;
    var t: [trailer_len]u8 = undefined;
    src.readAllAt(w.io, total - trailer_len, &t) catch return;
    const k: Koly = .{
        .data_off = be64(t[24..]),
        .data_len = be64(t[32..]),
        .xml_off = be64(t[216..]),
        .xml_len = be64(t[224..]),
    };
    const body = total - trailer_len;
    if (k.data_off > body or k.data_len > body - k.data_off) w.notice(.malformed, "dmg: data fork outside the image");
    if (k.xml_len == 0) return w.notice(.unsupported, "dmg: no XML property list (resource-fork block tables)");
    if (k.xml_off > body or k.xml_len > body - k.xml_off) return w.notice(.malformed, "dmg: property list outside the image");
    const plist = src.slice(k.xml_off, k.xml_len) catch return;
    const data = src.slice(@min(k.data_off, body), @min(k.data_len, body - @min(k.data_off, body))) catch return;
    try readPlist(w, plist, data);
}

/// Stream the property list, decoding each blkx entry's Data as it closes and scanning the
/// partition it describes.
fn readPlist(w: *Walker, plist: Source, data: Source) Error!void {
    const in_buf = w.alloc(u8, container.block_len) orelse return;
    var sr: container.SourceReader = .init(w.io, plist, in_buf);
    var tok = xml.Reader.initStream(w.scratch.allocator(), &sr.interface, .{ .buffer_size = 64 * 1024 }) catch return w.limit(.memory);
    const mish_cap: usize = @intCast(@min(max_mish, plist.len().?));
    const mish = w.alloc(u8, mish_cap) orelse return;
    var key_buf: [16]u8 = undefined;
    var key_len: usize = 0;
    var in_key = false;
    var in_data = false;
    var blkx_depth: ?usize = null;
    var depth: usize = 0;
    var b64: Base64 = .{ .out = mish };
    var have_data = false;
    var index: u32 = 0;
    while (true) {
        if (w.halt != null) return error.Halted;
        const ev = tok.next() catch |e| {
            if (e != error.ReadFailed) w.notice(.malformed, "dmg: property list");
            return;
        } orelse return;
        switch (ev) {
            .open => |el| {
                depth += 1;
                if (std.mem.eql(u8, el.name, "key")) {
                    in_key = true;
                    key_len = 0;
                } else if (std.mem.eql(u8, el.name, "array") and blkx_depth == null and keyIs(&key_buf, key_len, "blkx")) {
                    blkx_depth = depth;
                } else if (std.mem.eql(u8, el.name, "dict") and blkx_depth != null and depth == blkx_depth.? + 1) {
                    have_data = false;
                    b64 = .{ .out = mish };
                } else if (std.mem.eql(u8, el.name, "data") and blkx_depth != null and keyIs(&key_buf, key_len, "Data")) {
                    in_data = true;
                    b64 = .{ .out = mish };
                }
            },
            .close => |name| {
                if (in_key and std.mem.eql(u8, name, "key")) in_key = false;
                if (in_data and std.mem.eql(u8, name, "data")) {
                    in_data = false;
                    have_data = !b64.overflow;
                    if (b64.overflow) w.notice(.unsupported, "dmg: block table too large");
                }
                if (blkx_depth) |bd| {
                    if (std.mem.eql(u8, name, "dict") and depth == bd + 1 and have_data) {
                        const mark = w.scratch.mark();
                        defer w.scratch.release(mark);
                        try partition(w, data, mish[0..b64.len], index);
                        index += 1;
                        have_data = false;
                    }
                    if (std.mem.eql(u8, name, "array") and depth == bd) blkx_depth = null;
                }
                depth -|= 1;
            },
            .text => |text| {
                if (in_key) {
                    const take = @min(text.len, key_buf.len - key_len);
                    @memcpy(key_buf[key_len..][0..take], text[0..take]);
                    key_len += take;
                    if (text.len > take) key_len = key_buf.len; // too long to be a key we want
                } else if (in_data) b64.feed(text);
            },
            else => {},
        }
    }
}

fn keyIs(buf: []const u8, len: usize, want: []const u8) bool {
    return len == want.len and std.mem.eql(u8, buf[0..len], want);
}

/// Incremental base64 (the property list's <data>), whitespace ignored.
const Base64 = struct {
    out: []u8,
    len: usize = 0,
    quad: [4]u8 = undefined,
    q: u8 = 0,
    overflow: bool = false,

    fn feed(b: *Base64, text: []const u8) void {
        for (text) |c| {
            const v: u8 = switch (c) {
                'A'...'Z' => c - 'A',
                'a'...'z' => c - 'a' + 26,
                '0'...'9' => c - '0' + 52,
                '+' => 62,
                '/' => 63,
                '=' => 64,
                else => continue,
            };
            b.quad[b.q] = v;
            b.q += 1;
            if (b.q == 4) {
                b.q = 0;
                const n: usize = if (b.quad[2] == 64) 1 else if (b.quad[3] == 64) 2 else 3;
                const word = (@as(u32, b.quad[0] & 63) << 18) | (@as(u32, b.quad[1] & 63) << 12) | (@as(u32, b.quad[2] & 63) << 6) | (b.quad[3] & 63);
                const bytes = [3]u8{ @truncate(word >> 16), @truncate(word >> 8), @truncate(word) };
                if (b.len + n > b.out.len) {
                    b.overflow = true;
                    return;
                }
                @memcpy(b.out[b.len..][0..n], bytes[0..n]);
                b.len += n;
            }
        }
    }
};

const Chunk = struct {
    type: u32,
    sector: u64,
    count: u64,
    off: u64,
    len: u64,

    fn at(mish: []const u8, i: usize) Chunk {
        const c = mish[204 + 40 * i ..][0..40];
        return .{ .type = be32(c[0..]), .sector = be64(c[8..]), .count = be64(c[16..]), .off = be64(c[24..]), .len = be64(c[32..]) };
    }
};

const t_zero = 0x00000000;
const t_raw = 0x00000001;
const t_ignore = 0x00000002;
const t_adc = 0x80000004;
const t_zlib = 0x80000005;
const t_bzip2 = 0x80000006;
const t_lzfse = 0x80000007;
const t_xz = 0x80000008;
const t_comment = 0x7ffffffe;
const t_end = 0xffffffff;

fn partition(w: *Walker, data: Source, mish: []const u8, index: u32) Error!void {
    var name_buf: [24]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "partition/{d}", .{index}) catch unreachable;
    if (mish.len < 204 or !std.mem.eql(u8, mish[0..4], "mish")) {
        w.path.push(name);
        defer w.path.pop();
        return w.notice(.malformed, "dmg: bad block table");
    }
    const sectors = be64(mish[16..]);
    const base = be64(mish[24..]);
    const nchunks: usize = @intCast(@min(be32(mish[200..]), (mish.len - 204) / 40));
    if (sectors == 0) return;
    if (sectors > w.tracker.limits.max_file_size / sector) {
        w.path.push(name);
        defer w.path.pop();
        return w.limit(.file_size);
    }
    var pr: PartitionReader = .{ .w = w, .data = data, .mish = mish, .nchunks = nchunks, .base = base, .size = sectors * sector, .interface = undefined };
    var tokens: [2]?Budget.Token = .{ null, null };
    defer for (tokens) |tk| if (tk) |x| x.release();
    if (!pr.prepare(&tokens)) return;
    const buf = w.alloc(u8, container.block_len) orelse return;
    pr.interface = .{ .vtable = container.fillVTable(PartitionReader), .buffer = buf, .seek = 0, .end = 0 };
    if (w.options.cdb) |hook| {
        w.path.push(name);
        defer w.path.pop();
        hook.check(w, .{
            .container_type = .dmg,
            .container_size = null,
            .name = name,
            .size_in_container = pr.size,
            .size_real = pr.size,
            .encrypted = false,
            .position = index + 1,
        });
    }
    try w.child(name, .{ .stream = .{ .reader = &pr.interface, .len_hint = pr.size } }, .member);
    w.path.push(name);
    defer w.path.pop();
    if (pr.bad) |why| w.notice(.malformed, why);
    if (pr.unsupported) |why| w.notice(.unsupported, why);
}

/// One partition's bytes: chunks decoded in order, gaps filled with zeros.
const PartitionReader = struct {
    w: *Walker,
    data: Source,
    mish: []const u8,
    nchunks: usize,
    base: u64,
    size: u64,
    produced: u64 = 0,
    next_chunk: usize = 0,
    /// Bytes of the current chunk still to deliver, and how they are produced.
    left: u64 = 0,
    mode: enum { zeros, stream, buffer } = .zeros,
    stream: *Io.Reader = undefined,
    buffered: []const u8 = &.{},
    /// Compressed bytes read and output that counts as stored (zero fill), for the meter.
    pulled: u64 = 0,
    free_out: u64 = 0,
    out: u64 = 0,
    bad: ?[]const u8 = null,
    unsupported: ?[]const u8 = null,
    limited: bool = false,
    interface: Io.Reader,

    // Decoder state, set up once per partition in `prepare` and reused for every chunk.
    in_buf: []u8 = &.{},
    sr: container.SourceReader = undefined,
    limited_in: Io.Reader.Limited = undefined,
    limited_buf: []u8 = &.{},
    zlib_work: []u8 = &.{},
    zlib: inflate.Inflate = undefined,
    bz_tt: []u32 = &.{},
    bz_tables: ?*bzip2.Decoder.TablesType = null,
    bz: bzip2.Decoder = undefined,
    xz_dict: []u8 = &.{},
    xz_probs: []u16 = &.{},
    xz: xz.Decoder = undefined,
    chunk_out: []u8 = &.{},
    chunk_in: []u8 = &.{},
    lzfse_scratch: ?*lzfse.Scratch = null,

    /// Allocate the decoders the chunk types need, sized from the table. False when there is
    /// nothing to scan (already reported).
    fn prepare(pr: *PartitionReader, tokens: *[2]?Budget.Token) bool {
        const w = pr.w;
        var need_zlib = false;
        var need_bz = false;
        var xz_max: u64 = 0;
        var whole_out: u64 = 0;
        var whole_in: u64 = 0;
        var need_lzfse = false;
        for (0..pr.nchunks) |i| {
            const c = Chunk.at(pr.mish, i);
            const out = c.count *| sector;
            switch (c.type) {
                t_zlib => need_zlib = true,
                t_bzip2 => need_bz = true,
                t_xz => xz_max = @max(xz_max, out),
                t_adc, t_lzfse => {
                    if (out <= max_chunk and c.len <= max_chunk) {
                        whole_out = @max(whole_out, out);
                        whole_in = @max(whole_in, c.len);
                    }
                    if (c.type == t_lzfse) need_lzfse = true;
                },
                else => {},
            }
        }
        pr.in_buf = w.alloc(u8, container.block_len) orelse return false;
        pr.limited_buf = w.alloc(u8, container.block_len) orelse return false;
        if (need_zlib) pr.zlib_work = w.alloc(u8, inflate.work_len) orelse return false;
        if (need_bz) {
            tokens[0] = w.window(bzip2.workingSet(9), 0) orelse return false;
            pr.bz_tt = w.alloc(u32, 900_000) orelse return false;
            pr.bz_tables = w.scratch.allocator().create(bzip2.Decoder.TablesType) catch {
                w.limit(.memory);
                return false;
            };
        }
        const xz_dict: u64 = if (xz_max == 0) 0 else @max(@min(xz_max, w.tracker.limits.max_window), 4096);
        if (xz_dict + whole_out + whole_in > 0) {
            tokens[1] = w.window(xz_dict + whole_out + whole_in, if (xz_dict > 0) lzma.Lzma2.probs_len * 2 else 0) orelse return false;
        }
        if (xz_dict > 0) {
            pr.xz_dict = w.alloc(u8, @intCast(xz_dict)) orelse return false;
            pr.xz_probs = w.alloc(u16, lzma.Lzma2.probs_len) orelse return false;
        }
        if (whole_out > 0) {
            pr.chunk_out = w.alloc(u8, @intCast(whole_out)) orelse return false;
            pr.chunk_in = w.alloc(u8, @intCast(whole_in)) orelse return false;
        }
        if (need_lzfse) pr.lzfse_scratch = w.scratch.allocator().create(lzfse.Scratch) catch {
            w.limit(.memory);
            return false;
        };
        return true;
    }

    fn note(pr: *PartitionReader, why: []const u8) void {
        if (pr.bad == null) pr.bad = why;
    }

    pub fn fill(pr: *PartitionReader, dest: []u8) Io.Reader.Error!usize {
        if (pr.limited) return error.ReadFailed;
        while (pr.left == 0) {
            if (pr.produced >= pr.size) return 0;
            if (!try pr.nextChunk()) {
                // No more chunks: the rest of the partition is zeros.
                pr.mode = .zeros;
                pr.left = pr.size - pr.produced;
            }
        }
        const want: usize = @intCast(@min(dest.len, pr.left));
        const n: usize = switch (pr.mode) {
            .zeros => blk: {
                @memset(dest[0..want], 0);
                pr.free_out += want;
                break :blk want;
            },
            .buffer => blk: {
                const m = @min(want, pr.buffered.len);
                @memcpy(dest[0..m], pr.buffered[0..m]);
                pr.buffered = pr.buffered[m..];
                break :blk m;
            },
            .stream => blk: {
                const m = container.readSome(pr.stream, dest[0..want]) catch |e| {
                    if (e == error.ReadFailed and pr.w.halt != null) return error.ReadFailed;
                    // The chunk decoded short (or failed): the rest of its sectors are zeros.
                    pr.note("dmg: chunk decodes to less than its sectors");
                    pr.mode = .zeros;
                    @memset(dest[0..want], 0);
                    pr.free_out += want;
                    break :blk want;
                };
                break :blk m;
            },
        };
        const t = pr.w.tracker;
        t.addOutput(pr.pulled + pr.free_out, pr.out, n) catch {
            pr.limited = true;
            pr.w.limit(t.last.?);
            return error.ReadFailed;
        };
        pr.out += n;
        pr.left -= n;
        pr.produced += n;
        return n;
    }

    /// Set up the next chunk (or the zeros before it). False when the table is done.
    fn nextChunk(pr: *PartitionReader) error{ReadFailed}!bool {
        const w = pr.w;
        while (pr.next_chunk < pr.nchunks) {
            const c = Chunk.at(pr.mish, pr.next_chunk);
            if (c.type == t_end) {
                pr.next_chunk = pr.nchunks;
                return false;
            }
            if (c.type == t_comment) {
                pr.next_chunk += 1;
                continue;
            }
            const start = c.sector *| sector;
            if (start > pr.produced) {
                // A gap before this chunk: zeros, then the chunk.
                pr.mode = .zeros;
                pr.left = @min(start, pr.size) - pr.produced;
                return true;
            }
            pr.next_chunk += 1;
            if (start < pr.produced) {
                pr.note("dmg: chunks overlap");
                continue;
            }
            const out = @min(c.count *| sector, pr.size - pr.produced);
            if (out == 0) continue;
            pr.left = out;
            const off = pr.base +| c.off;
            const total = pr.data.len().?;
            const in_range = off <= total and c.len <= total - off;
            if (!in_range and c.type != t_zero and c.type != t_ignore) {
                pr.note("dmg: chunk data outside the data fork");
                pr.mode = .zeros;
                return true;
            }
            switch (c.type) {
                t_zero, t_ignore => pr.mode = .zeros,
                t_raw, t_zlib, t_bzip2, t_xz => {
                    const comp = pr.data.slice(off, c.len) catch unreachable;
                    pr.sr = .init(w.io, comp, pr.in_buf);
                    pr.pulled += c.len;
                    pr.mode = .stream;
                    switch (c.type) {
                        t_raw => pr.stream = &pr.sr.interface,
                        t_zlib => {
                            pr.zlib = .init(&pr.sr.interface, .zlib, pr.zlib_work);
                            pr.stream = &pr.zlib.interface;
                        },
                        t_bzip2 => {
                            pr.bz = bzip2.Decoder.init(&pr.sr.interface, pr.bz_tt, pr.bz_tables.?, &.{}) catch {
                                pr.note("dmg: bad bzip2 chunk");
                                pr.mode = .zeros;
                                return true;
                            };
                            pr.stream = &pr.bz.interface;
                        },
                        t_xz => {
                            pr.xz = .init(&pr.sr.interface, pr.xz_dict, pr.xz_probs, &.{}, &.{});
                            pr.xz.output_bound = out;
                            pr.stream = &pr.xz.interface;
                        },
                        else => unreachable,
                    }
                    // Never more than the chunk's sectors.
                    pr.limited_in = pr.stream.limited(.limited64(out), pr.limited_buf);
                    pr.stream = &pr.limited_in.interface;
                },
                t_adc, t_lzfse => {
                    if (out > pr.chunk_out.len or c.len > pr.chunk_in.len) {
                        pr.unsupported = "dmg: chunk too large to decode";
                        pr.mode = .zeros;
                        return true;
                    }
                    const src = pr.chunk_in[0..@intCast(c.len)];
                    pr.data.readAllAt(w.io, off, src) catch {
                        pr.note("dmg: chunk data outside the data fork");
                        pr.mode = .zeros;
                        return true;
                    };
                    pr.pulled += c.len;
                    const dst = pr.chunk_out[0..@intCast(out)];
                    const n = if (c.type == t_adc) adc(src, dst) else lzfse.decode(src, dst, pr.lzfse_scratch.?) catch |e| blk: {
                        switch (e) {
                            error.Unsupported => pr.unsupported = "dmg: LZFSE v1 block",
                            else => pr.note("dmg: bad LZFSE chunk"),
                        }
                        break :blk 0;
                    };
                    if (n < dst.len) {
                        if (c.type == t_adc) pr.note("dmg: bad ADC chunk");
                        @memset(dst[n..], 0);
                    }
                    pr.buffered = dst;
                    pr.mode = .buffer;
                },
                else => {
                    pr.unsupported = "dmg: chunk type";
                    pr.mode = .zeros;
                },
            }
            return true;
        }
        return false;
    }
};

/// Apple Data Compression: literal runs (high bit set, 1-128 bytes), and matches of 3-18 bytes
/// at distances up to 1024 or of 4-67 bytes at distances up to 65536. Returns the bytes written;
/// stops early (short) on damaged input.
pub fn adc(src: []const u8, dst: []u8) usize {
    var p: usize = 0;
    var o: usize = 0;
    while (p < src.len and o < dst.len) {
        const b = src[p];
        if (b & 0x80 != 0) {
            const n: usize = (b & 0x7f) + 1;
            if (src.len - p - 1 < n) return o;
            const m = @min(n, dst.len - o);
            @memcpy(dst[o..][0..m], src[p + 1 ..][0..m]);
            o += m;
            p += 1 + n;
            continue;
        }
        var len: usize = undefined;
        var dist: usize = undefined;
        if (b & 0x40 != 0) {
            if (src.len - p < 3) return o;
            len = (b & 0x3f) + 4;
            dist = (@as(usize, src[p + 1]) << 8 | src[p + 2]) + 1;
            p += 3;
        } else {
            if (src.len - p < 2) return o;
            len = ((b >> 2) & 0x0f) + 3;
            dist = ((@as(usize, b) & 3) << 8 | src[p + 1]) + 1;
            p += 2;
        }
        if (dist > o) return o;
        const m = @min(len, dst.len - o);
        for (0..m) |i| dst[o + i] = dst[o + i - dist];
        o += m;
    }
    return o;
}

fn be32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .big);
}

fn be64(b: []const u8) u64 {
    return std.mem.readInt(u64, b[0..8], .big);
}

test "adc: literals and both match forms" {
    // 2 literals "ab", a short match (len 3, dist 2), a long match (len 4, dist 1).
    const src = [_]u8{ 0x81, 'a', 'b', 0x00 | (0 << 2) | 0, 0x01, 0x40, 0x00, 0x00 };
    var dst: [9]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 9), adc(&src, &dst));
    try std.testing.expectEqualStrings("ababaaaaa", &dst);
    // A distance before the start stops decoding.
    try std.testing.expectEqual(@as(usize, 0), adc(&.{ 0x00, 0x05 }, &dst));
}

test "damaged images and images without a property list are reported" {
    const fixtures = @import("fixtures/fixtures.zig");
    const TestRig = @import("scan.zig").TestRig;
    for ([_][]const u8{ "damaged.dmg", "no-xml.dmg" }, [_]std.meta.Tag(container.Notice.What){ .malformed, .unsupported }) |name, what| {
        const a = for (fixtures.archives) |x| {
            if (std.mem.eql(u8, x.name, name)) break x;
        } else unreachable;
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.walker.scan(.{ .memory = a.bytes }, name);
        try std.testing.expectEqual(container.Format.dmg, rig.rec.objects.items[0].format);
        try std.testing.expect(rig.rec.has(what));
    }
}
