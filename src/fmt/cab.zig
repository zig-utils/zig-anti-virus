//! Microsoft cabinet files, written from [MS-CAB]: CFHEADER (with reserved areas and the
//! previous/next cabinet names), CFFOLDER, CFFILE and CFDATA, including the CFDATA checksum.
//! Folders compressed with MSZIP ([MS-MCI]: one deflate stream per CFDATA block, each block
//! using the previous 32 KiB as its history) and LZX (lzx.zig) are decoded; Quantum and anything
//! else is reported as unsupported.
//!
//! A folder is one compressed stream holding its files back to back. It is decoded once, in a
//! single forward pass, and each file becomes a stream child cut from it in offset order:
//! - Files that overlap one already scanned (the same range named again, or a range starting
//!   inside an earlier one) are reported as `overlap` and skipped, so the work is bounded by
//!   the folder's size, not by the file count.
//! - The folder's output is counted against the ratio guard and the scan's output budget as it
//!   is produced, including bytes no file claims.
//! - Every count and offset is checked against the cabinet; CFDATA blocks claim at most 32 KiB.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const lzx = @import("lzx.zig");
const flate = std.compress.flate;

pub const max_name = 256;
const header_len = 36;
const flag_prev = 1;
const flag_next = 2;
const flag_reserve = 4;

const Folder = struct {
    data_off: u32,
    blocks: u16,
    type: u16,
};

const File = struct {
    size: u32,
    off: u32,
    folder: u16,
    /// Where the name starts in the cabinet, and its length (without the NUL).
    name_off: u32,
    name_len: u16,
};

const Le = struct {
    fn u16at(b: []const u8, off: usize) u16 {
        return std.mem.readInt(u16, b[off..][0..2], .little);
    }
    fn u32at(b: []const u8, off: usize) u32 {
        return std.mem.readInt(u32, b[off..][0..4], .little);
    }
};

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len().?;
    var h: [header_len + 4]u8 = undefined;
    src.readAllAt(w.io, 0, h[0..header_len]) catch return w.notice(.malformed, "cab: truncated header");
    if (!std.mem.eql(u8, h[0..4], "MSCF")) return w.notice(.malformed, "cab: bad signature");
    const files_off = Le.u32at(&h, 16);
    const nfolders = Le.u16at(&h, 26);
    const nfiles = Le.u16at(&h, 28);
    const flags = Le.u16at(&h, 30);
    var off: u64 = header_len;
    var folder_reserve: u8 = 0;
    var data_reserve: u8 = 0;
    if (flags & flag_reserve != 0) {
        src.readAllAt(w.io, off, h[header_len..][0..4]) catch return w.notice(.malformed, "cab: truncated header");
        folder_reserve = h[header_len + 2];
        data_reserve = h[header_len + 3];
        off += 4 + @as(u64, Le.u16at(&h, header_len));
    }
    // Previous and next cabinet and disk names: NUL-terminated strings.
    var strings: u8 = 0;
    if (flags & flag_prev != 0) strings += 2;
    if (flags & flag_next != 0) strings += 2;
    for (0..strings) |_| off = skipString(w, src, off) orelse return w.notice(.malformed, "cab: truncated header");
    if (flags & (flag_prev | flag_next) != 0) w.notice(.unsupported, "cab: cabinet set (files spanning cabinets are not reassembled)");

    const folders = w.alloc(Folder, nfolders) orelse return;
    defer w.free(folders);
    var rec: [8]u8 = undefined;
    for (folders) |*f| {
        src.readAllAt(w.io, off, &rec) catch return w.notice(.malformed, "cab: truncated folder table");
        f.* = .{ .data_off = Le.u32at(&rec, 0), .blocks = Le.u16at(&rec, 4), .type = Le.u16at(&rec, 6) };
        off += 8 + @as(u64, folder_reserve);
    }

    const cap: usize = @min(nfiles, @as(usize, w.tracker.limits.max_files) + 1);
    const files = w.alloc(File, cap) orelse return;
    defer w.free(files);
    var n: usize = 0;
    off = files_off;
    var fr: [16]u8 = undefined;
    while (n < cap) {
        src.readAllAt(w.io, off, &fr) catch {
            w.notice(.malformed, "cab: truncated file table");
            break;
        };
        const name_off = off + 16;
        const end = skipString(w, src, name_off) orelse {
            w.notice(.malformed, "cab: truncated file name");
            break;
        };
        files[n] = .{
            .size = Le.u32at(&fr, 0),
            .off = Le.u32at(&fr, 4),
            .folder = Le.u16at(&fr, 8),
            .name_off = @intCast(@min(name_off, std.math.maxInt(u32))),
            .name_len = @intCast(end - 1 - name_off),
        };
        n += 1;
        off = end;
        if (off > total) break;
    }
    const listed = files[0..n];

    // Files grouped by folder, in offset order (stable, so equal ranges keep table order).
    const order = w.alloc(u32, listed.len) orelse return;
    defer w.free(order);
    for (order, 0..) |*o, i| o.* = @intCast(i);
    std.sort.block(u32, order, listed, struct {
        fn lt(fs: []const File, a: u32, b: u32) bool {
            const x = fs[a];
            const y = fs[b];
            return if (x.folder != y.folder) x.folder < y.folder else x.off < y.off;
        }
    }.lt);

    var reported_overlap = false;
    var reported_span = false;
    var i: usize = 0;
    while (i < order.len) {
        if (w.halt != null) return error.Halted;
        const fi = listed[order[i]].folder;
        var j = i;
        while (j < order.len and listed[order[j]].folder == fi) j += 1;
        const group = order[i..j];
        i = j;
        if (fi >= 0xFFFD) {
            // Continued from a previous cabinet: the start of the data is elsewhere.
            if (!reported_span) w.notice(.unsupported, "cab: file continued from another cabinet");
            reported_span = true;
            continue;
        }
        if (fi >= folders.len) {
            w.notice(.malformed, "cab: file names a folder that does not exist");
            continue;
        }
        try scanFolder(w, src, folders[fi], data_reserve, listed, group, &reported_overlap);
    }
}

/// Offset just past the NUL ending the string at `off` (at most `max_name` bytes).
fn skipString(w: *Walker, src: Source, off: u64) ?u64 {
    var buf: [max_name]u8 = undefined;
    const got = src.readAt(w.io, off, &buf) catch return null;
    const nul = std.mem.indexOfScalar(u8, buf[0..got], 0) orelse return null;
    return off + nul + 1;
}

fn scanFolder(w: *Walker, src: Source, folder: Folder, data_reserve: u8, files: []const File, group: []const u32, reported_overlap: *bool) Error!void {
    const method: Method = switch (folder.type & 0x0f) {
        0 => .stored,
        1 => .mszip,
        3 => .lzx,
        2 => return w.notice(.unsupported, "cab: Quantum"),
        else => return w.notice(.unsupported, "cab: compression type"),
    };
    var fr: FolderReader = .{ .w = w, .src = src, .next_off = folder.data_off, .blocks_left = folder.blocks, .reserve = data_reserve, .method = method, .interface = undefined };
    const plan = fr.plan() orelse return;
    if (plan.uncompressed == 0) return;
    fr.block = w.alloc(u8, 0xFFFF + 2) orelse return;
    const out_buf = w.alloc(u8, container.block_len) orelse return;
    fr.interface = .{ .vtable = container.fillVTable(FolderReader), .buffer = out_buf, .seek = 0, .end = 0 };
    fr.remaining_out = plan.uncompressed;
    var payload: PayloadReader = .{ .fr = &fr, .interface = undefined };
    var token: ?@import("../engine/budget.zig").Budget.Token = null;
    defer if (token) |t| t.release();
    switch (method) {
        .stored => {},
        .mszip => {
            const window = w.alloc(u8, flate.max_window_len) orelse return;
            fr.inflate = flate.Decompress.init(&fr.block_reader, .raw, window);
        },
        .lzx => {
            const bits: u5 = @intCast((folder.type >> 8) & 0x1f);
            if (bits < lzx.min_window_bits or bits > lzx.max_window_bits) return w.notice(.unsupported, "cab: LZX window size");
            const window_len = lzx.Lzx.windowLen(bits);
            token = w.window(window_len, @sizeOf(lzx.Lzx.Tables)) orelse return;
            const window = w.alloc(u8, window_len) orelse return;
            const tables = w.scratch.allocator().create(lzx.Lzx.Tables) catch return w.limit(.memory);
            const in_buf = w.alloc(u8, 4096) orelse return;
            payload.interface = .{ .vtable = container.fillVTable(PayloadReader), .buffer = in_buf, .seek = 0, .end = 0 };
            fr.lzx = lzx.Lzx.init(&payload.interface, bits, window, tables, 0);
        },
    }

    const limited_buf = w.alloc(u8, container.block_len) orelse return;
    var name_buf: [max_name]u8 = undefined;
    var cursor: u64 = 0;
    for (group) |idx| {
        if (w.halt != null) return error.Halted;
        const f = files[idx];
        const name = readName(w, src, f, &name_buf);
        if (f.off > plan.uncompressed or f.size > plan.uncompressed - f.off) {
            w.path.push(name);
            w.notice(.malformed, "cab: file runs past the end of its folder");
            w.path.pop();
        }
        if (f.off < cursor) {
            if (!reported_overlap.*) {
                w.path.push(name);
                w.notice(.overlap, "cab: files share folder data");
                w.path.pop();
            }
            reported_overlap.* = true;
            continue;
        }
        if (w.options.cdb) |hook| {
            w.path.push(name);
            defer w.path.pop();
            hook.check(w, .{
                .container_type = .mscab,
                .container_size = src.len().?,
                .name = name,
                .size_in_container = f.size,
                .size_real = f.size,
                .encrypted = false,
                .position = idx + 1,
            });
        }
        // Skip what lies between the previous file and this one.
        fr.interface.discardAll64(f.off - cursor) catch |e| return fr.finish(e);
        cursor = f.off;
        if (f.size == 0) continue;
        if (f.size > w.tracker.limits.max_file_size) {
            w.path.push(name);
            w.limit(.file_size);
            w.path.pop();
        } else {
            var limited = fr.interface.limited(.limited64(f.size), limited_buf);
            try w.child(name, .{ .stream = .{ .reader = &limited.interface, .len_hint = f.size } }, .member);
            limited.interface.tossBuffered();
            const unread = @backingInt(limited.remaining);
            fr.interface.discardAll64(unread) catch |e| return fr.finish(e);
        }
        cursor += f.size;
    }
    fr.finish(null) catch {};
}

fn readName(w: *Walker, src: Source, f: File, buf: *[max_name]u8) []const u8 {
    const name = buf[0..@min(f.name_len, max_name)];
    src.readAllAt(w.io, f.name_off, name) catch return "?";
    for (name) |*c| {
        if (c.* == '\\') c.* = '/';
    }
    return name;
}

const Method = enum { stored, mszip, lzx };

/// One folder's output as a stream: CFDATA blocks read in order, checksums verified, payloads
/// decoded with the folder's method, and the output metered against the ratio guard and the
/// scan's output budget.
const FolderReader = struct {
    w: *Walker,
    src: Source,
    next_off: u64,
    blocks_left: u16,
    reserve: u8,
    method: Method,
    block: []u8 = &.{},
    payload: []const u8 = &.{},
    /// The current block's declared output size.
    block_uncomp: u32 = 0,
    block_out: u32 = 0,
    block_reader: Io.Reader = .fixed(&.{}),
    inflate: flate.Decompress = undefined,
    inflating: bool = false,
    lzx: lzx.Lzx = undefined,
    frame: []const u8 = &.{},
    remaining_out: u64 = 0,
    pulled: u64 = 0,
    out: u64 = 0,
    failure: ?[]const u8 = null,
    limited: bool = false,
    bad_checksum: bool = false,
    interface: Io.Reader,

    const Plan = struct { uncompressed: u64 };

    /// Walk the CFDATA headers once: the folder's output size, and a check that the chain
    /// stays inside the cabinet. Blocks past a broken one are dropped (reported).
    fn plan(fr: *FolderReader) ?Plan {
        const w = fr.w;
        const total = fr.src.len().?;
        var off = fr.next_off;
        var sum: u64 = 0;
        var k: u16 = 0;
        var head: [8]u8 = undefined;
        while (k < fr.blocks_left) : (k += 1) {
            fr.src.readAllAt(w.io, off, &head) catch break;
            const cb = Le.u16at(&head, 4);
            const ub = Le.u16at(&head, 6);
            const next = off + 8 + fr.reserve + cb;
            if (next > total or ub > lzx.frame_len) break;
            sum += ub;
            off = next;
        }
        if (k < fr.blocks_left) {
            w.notice(.malformed, "cab: data blocks run past the end of the cabinet");
            fr.blocks_left = k;
        }
        return .{ .uncompressed = sum };
    }

    /// Read the next CFDATA block into `block`; false when the folder has no more.
    fn nextBlock(fr: *FolderReader) bool {
        const w = fr.w;
        if (fr.blocks_left == 0) return false;
        var head: [8 + 255]u8 = undefined;
        const hl = 8 + @as(usize, fr.reserve);
        fr.src.readAllAt(w.io, fr.next_off, head[0..hl]) catch return false;
        const csum = Le.u32at(&head, 0);
        const cb = Le.u16at(&head, 4);
        fr.block_uncomp = Le.u16at(&head, 6);
        fr.src.readAllAt(w.io, fr.next_off + hl, fr.block[0..cb]) catch return false;
        fr.payload = fr.block[0..cb];
        if (csum != 0 and checksum(head[4..hl], checksum(fr.payload, 0)) != csum) fr.bad_checksum = true;
        fr.next_off += hl + cb;
        fr.blocks_left -= 1;
        fr.pulled += cb;
        fr.block_out = 0;
        return true;
    }

    fn fail(fr: *FolderReader, why: []const u8) error{ReadFailed} {
        if (fr.failure == null and !fr.limited) fr.failure = why;
        return error.ReadFailed;
    }

    pub fn fill(fr: *FolderReader, dest: []u8) Io.Reader.Error!usize {
        if (fr.failure != null or fr.limited) return error.ReadFailed;
        if (fr.remaining_out == 0) return 0;
        const want = @min(dest.len, fr.remaining_out);
        const n = switch (fr.method) {
            .stored => try fr.fillStored(dest[0..@intCast(want)]),
            .mszip => try fr.fillMszip(dest[0..@intCast(want)]),
            .lzx => try fr.fillLzx(dest[0..@intCast(want)]),
        };
        if (n == 0) return fr.fail("cab: folder data ends early");
        const t = fr.w.tracker;
        t.addOutput(fr.pulled, fr.out, n) catch {
            fr.limited = true;
            fr.w.limit(t.last.?);
            return error.ReadFailed;
        };
        fr.out += n;
        fr.remaining_out -= n;
        return n;
    }

    fn fillStored(fr: *FolderReader, dest: []u8) error{ReadFailed}!usize {
        while (fr.payload.len == 0) {
            if (!fr.nextBlock()) return 0;
            if (fr.payload.len != fr.block_uncomp) return fr.fail("cab: stored block sizes disagree");
        }
        const n = @min(dest.len, fr.payload.len);
        @memcpy(dest[0..n], fr.payload[0..n]);
        fr.payload = fr.payload[n..];
        return n;
    }

    fn fillMszip(fr: *FolderReader, dest: []u8) error{ReadFailed}!usize {
        while (true) {
            if (fr.inflating) {
                const n = container.readSome(&fr.inflate.reader, dest) catch |e| switch (e) {
                    error.EndOfStream => 0,
                    error.ReadFailed => return fr.fail("cab: MSZIP block is not valid deflate"),
                };
                if (n != 0) {
                    fr.block_out += @intCast(n);
                    if (fr.block_out > fr.block_uncomp) return fr.fail("cab: MSZIP block larger than declared");
                    return n;
                }
                if (fr.block_out != fr.block_uncomp) return fr.fail("cab: MSZIP block smaller than declared");
                fr.inflating = false;
            }
            if (!fr.nextBlock()) return 0;
            if (fr.payload.len < 2 or fr.payload[0] != 'C' or fr.payload[1] != 'K') return fr.fail("cab: MSZIP block without its CK signature");
            // A new deflate stream, keeping the window: the previous block's output is its
            // history (std's decoder holds that history in its reader buffer).
            fr.block_reader = .fixed(fr.payload[2..]);
            fr.inflate.input = &fr.block_reader;
            fr.inflate.consumed_bits = 0;
            fr.inflate.final_block = false;
            fr.inflate.state = .block_header;
            fr.inflate.err = null;
            fr.inflating = true;
        }
    }

    fn fillLzx(fr: *FolderReader, dest: []u8) error{ReadFailed}!usize {
        if (fr.frame.len == 0) {
            const len: u32 = @intCast(@min(lzx.frame_len, fr.remaining_out));
            fr.frame = fr.lzx.frame(len) catch |e| return switch (e) {
                error.ReadFailed => if (fr.failure != null or fr.limited) error.ReadFailed else fr.fail("cab: read error"),
                else => fr.fail("cab: LZX data is malformed"),
            };
        }
        const n = @min(dest.len, fr.frame.len);
        @memcpy(dest[0..n], fr.frame[0..n]);
        fr.frame = fr.frame[n..];
        return n;
    }

    /// Report how the folder ended. `e` is the error a discard saw, if any.
    fn finish(fr: *FolderReader, e: ?Io.Reader.Error) Error!void {
        const w = fr.w;
        if (fr.bad_checksum) w.notice(.malformed, "cab: data block checksum mismatch");
        fr.bad_checksum = false;
        if (fr.failure) |why| w.notice(.malformed, why);
        fr.failure = null;
        if (e != null and w.halt != null) return error.Halted;
    }
};

/// LZX input: the payloads of the folder's CFDATA blocks, end to end.
const PayloadReader = struct {
    fr: *FolderReader,
    interface: Io.Reader,

    pub fn fill(p: *PayloadReader, dest: []u8) Io.Reader.Error!usize {
        const fr = p.fr;
        while (fr.payload.len == 0) {
            if (!fr.nextBlock()) return 0;
        }
        const n = @min(dest.len, fr.payload.len);
        @memcpy(dest[0..n], fr.payload[0..n]);
        fr.payload = fr.payload[n..];
        return n;
    }
};

/// The CFDATA checksum ([MS-CAB] 2.6): XOR of little-endian 32-bit words, the last partial word
/// assembled most significant byte first.
pub fn checksum(data: []const u8, seed: u32) u32 {
    var csum = seed;
    var i: usize = 0;
    while (i + 4 <= data.len) : (i += 4) csum ^= std.mem.readInt(u32, data[i..][0..4], .little);
    var ul: u32 = 0;
    for (data[i..]) |b| ul = (ul << 8) | b;
    return csum ^ ul;
}

test "checksum tail bytes are assembled high byte first" {
    try std.testing.expectEqual(@as(u32, 0x04030201), checksum(&.{ 1, 2, 3, 4 }, 0));
    try std.testing.expectEqual(@as(u32, 0x00010203), checksum(&.{ 1, 2, 3 }, 0));
    try std.testing.expectEqual(@as(u32, 0x04030201 ^ 0x0506), checksum(&.{ 1, 2, 3, 4, 5, 6 }, 0));
}
