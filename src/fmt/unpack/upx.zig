//! UPX unpacking, written from the packed-file layout as it can be observed in UPX output and
//! UPX's public documentation (no UPX source is used): the l_info / p_info / b_info block chain of
//! ELF and Mach-O executables, the PackHeader of PE executables, the NRV2B, NRV2D and NRV2E
//! bit streams (8-bit, 16-bit and 32-bit little-endian bit buffers), UPX's two-byte LZMA header,
//! and the x86 (0x49: E8, E9 and 0F 8x with a CTO byte; 0x24 to 0x26: E8 and/or E9) and ARM64
//! (0x52: B and BL) call filters.
//!
//! - ELF and Mach-O: the original file is rebuilt exactly. The first block holds the original
//!   headers; each loadable segment's bytes follow in order (split into blocks of at most
//!   p_blocksize), then the holes between and after them, as UPX wrote them. The rebuilt file is
//!   the child "upx", byte-identical to `upx -d` output for the formats tested (i386, amd64 and
//!   arm64 ELF, amd64 Mach-O; NRV2B, NRV2E and LZMA).
//! - PE: the compressed image is decompressed and unfiltered (the sections' bytes laid out from
//!   the lowest section address, then UPX's import records, relocation stream and the original
//!   PE header). From it the original file is rebuilt as the child "upx", reading the image
//!   and writing a new buffer: header, section layout, imports and relocations, byte-identical
//!   to `upx -d` for the amd64 sample (PE32+, NRV2B, filter 0x49, with TLS and exception data).
//!   Only what that sample shows is accepted: PE32, an overlay on the packed or the original
//!   file, ordinal or other import records, relocation prefixes other than 0xf0, odd relocation
//!   blocks, overlapping sections, a record written over non-zero image bytes, or a layout that
//!   differs in any checked field leave the image unrebuilt, scanned as the child "upx/image"
//!   with a notice. Resources, exports and
//!   load configuration are copied as unpacked, with a notice. When image bytes outside the
//!   original sections' raw data are not all zero, the image is scanned as well.
//! Bounds: the output size is the header's claim, capped by MaxFileSize and taken as a decoder
//! window from the big-window budget; every block must decompress to exactly its declared size
//! inside the output; decoders stop at their input or output end. A rebuilt PE file is a second
//! window, taken only once its size equals the end of the original sections; every write into
//! it is checked against one section's raw data, and every record read against the image range
//! that holds its kind of record.
const std = @import("std");
const container = @import("../../engine/container.zig");
const Source = @import("../../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const Format = container.Format;
const lzma = @import("../lzma.zig");
const pe = @import("../pe.zig");

pub const DecodeError = error{ Corrupt, Unsupported };

pub const Method = enum(u8) {
    nrv2b_le32 = 2,
    nrv2b_8 = 3,
    nrv2b_le16 = 4,
    nrv2d_le32 = 5,
    nrv2d_8 = 6,
    nrv2d_le16 = 7,
    nrv2e_le32 = 8,
    nrv2e_8 = 9,
    nrv2e_le16 = 10,
    lzma = 14,
    _,
};

const Bits = struct {
    src: []const u8,
    ip: usize = 0,
    width: u6,
    bb: u32 = 0,
    bc: u6 = 0,

    fn bit(b: *Bits) DecodeError!u32 {
        if (b.bc == 0) {
            const n: usize = b.width / 8;
            if (b.src.len - b.ip < n) return error.Corrupt;
            b.bb = switch (b.width) {
                32 => std.mem.readInt(u32, b.src[b.ip..][0..4], .little),
                16 => std.mem.readInt(u16, b.src[b.ip..][0..2], .little),
                else => b.src[b.ip],
            };
            b.ip += n;
            b.bc = b.width;
        }
        b.bc -= 1;
        return (b.bb >> @intCast(b.bc)) & 1;
    }

    fn byte(b: *Bits) DecodeError!u32 {
        if (b.ip >= b.src.len) return error.Corrupt;
        b.ip += 1;
        return b.src[b.ip - 1];
    }

    /// An Elias-gamma style number: bits until a terminating 1 (b) or a 2-bit step (d, e).
    fn gamma(b: *Bits, start: u32) DecodeError!u32 {
        var v = start;
        while (true) {
            if (v > 0x7fffffff) return error.Corrupt;
            v = v * 2 + try b.bit();
            if (try b.bit() == 1) return v;
        }
    }
};

/// Decompress an NRV2B/D/E stream into `dst` (exactly filled).
pub fn nrv(src: []const u8, dst: []u8, method: Method) DecodeError!void {
    const kind: u8, const width: u6 = switch (method) {
        .nrv2b_le32 => .{ 'b', 32 },
        .nrv2b_8 => .{ 'b', 8 },
        .nrv2b_le16 => .{ 'b', 16 },
        .nrv2d_le32 => .{ 'd', 32 },
        .nrv2d_8 => .{ 'd', 8 },
        .nrv2d_le16 => .{ 'd', 16 },
        .nrv2e_le32 => .{ 'e', 32 },
        .nrv2e_8 => .{ 'e', 8 },
        .nrv2e_le16 => .{ 'e', 16 },
        else => return error.Unsupported,
    };
    var b: Bits = .{ .src = src, .width = width };
    var o: usize = 0;
    var last: u32 = 1;
    while (true) {
        while (try b.bit() == 1) {
            if (o >= dst.len) return error.Corrupt;
            dst[o] = @intCast(try b.byte());
            o += 1;
        }
        var off: u32 = 1;
        if (kind == 'b') {
            off = try b.gamma(1);
        } else while (true) {
            if (off > 0x3fffffff) return error.Corrupt;
            off = off * 2 + try b.bit();
            if (try b.bit() == 1) break;
            off = (off - 1) * 2 + try b.bit();
        }
        var len: u32 = 0;
        if (off == 2) {
            off = last;
            if (kind != 'b') len = try b.bit();
        } else {
            if (off - 3 > 0xffffff) return error.Corrupt;
            const full = ((off - 3) << 8) | try b.byte();
            if (full == 0xffffffff) break;
            if (kind == 'b') {
                off = full + 1;
            } else {
                len = (full ^ 0xffffffff) & 1;
                off = (full >> 1) + 1;
            }
            last = off;
        }
        switch (kind) {
            'b' => {
                len = try b.bit();
                len = len * 2 + try b.bit();
                if (len == 0) len = (try b.gamma(1)) + 2;
                len += @intFromBool(off > 0xd00);
            },
            'd' => {
                len = len * 2 + try b.bit();
                if (len == 0) len = (try b.gamma(1)) + 2;
                len += @intFromBool(off > 0x500);
            },
            else => {
                if (len != 0) {
                    len = 1 + try b.bit();
                } else if (try b.bit() == 1) {
                    len = 3 + try b.bit();
                } else len = (try b.gamma(1)) + 3;
                len += @intFromBool(off > 0x500);
            },
        }
        const n: usize = @as(usize, len) + 1;
        if (off > o or n > dst.len - o) return error.Corrupt;
        for (0..n) |i| dst[o + i] = dst[o + i - off];
        o += n;
    }
    if (o != dst.len) return error.Corrupt;
}

/// UPX's LZMA: two bytes of lc/lp/pb, then a raw LZMA stream of exactly `dst.len` bytes.
fn upxLzma(w: *Walker, src: []const u8, dst: []u8) DecodeError!void {
    if (src.len < 2) return error.Corrupt;
    const pb = src[0] & 7;
    const lp = src[1] >> 4;
    const lc = src[1] & 15;
    if (pb > 4 or lp > 4 or lc > 8 or lc + lp > 8) return error.Corrupt;
    const props = lzma.Props.decode((pb * 5 + lp) * 9 + lc) catch return error.Corrupt;
    const mark = w.scratch.mark();
    defer w.scratch.release(mark);
    const probs = w.alloc(u16, props.probCount()) orelse return error.Unsupported;
    // The output is the dictionary: a match can only reach bytes already written.
    var dict: lzma.Dict = .{ .buf = dst };
    var in: std.Io.Reader = .fixed(src[2..]);
    var a = lzma.Alone.init(&in, .{ .props = props, .dict_size = @intCast(dst.len) }, dst.len, probs, &dict, &.{}) catch return error.Corrupt;
    var scratch_out: [4096]u8 = undefined;
    var o: usize = 0;
    while (o < dst.len) {
        const n = container.readSome(&a.interface, scratch_out[0..@min(scratch_out.len, dst.len - o)]) catch return error.Corrupt;
        o += n;
    }
}

fn decompress(w: *Walker, method: Method, src: []const u8, dst: []u8) DecodeError!void {
    if (method == .lzma) {
        // The dictionary doubles as the output buffer, so decode into a copy target.
        return upxLzma(w, src, dst);
    }
    return nrv(src, dst, method);
}

/// Undo UPX's call filters. 0x49: E8, E9 and 0F 8x followed by the CTO byte hold a big-endian
/// 24-bit absolute target (0x24, 0x25 and 0x26: the same for E8, E9, or both, without the
/// conditional jumps); 0x52: ARM64 B and BL hold an absolute word index.
pub fn unfilter(buf: []u8, id: u8, cto: u8) bool {
    switch (id) {
        0 => {},
        0x24, 0x25, 0x26, 0x49 => {
            var i: usize = 0;
            while (i + 5 <= buf.len) {
                const op = buf[i];
                const call = switch (id) {
                    0x24 => op == 0xe8,
                    0x25 => op == 0xe9,
                    0x26 => op == 0xe8 or op == 0xe9,
                    else => op == 0xe8 or op == 0xe9 or (i > 0 and buf[i - 1] == 0x0f and op & 0xf0 == 0x80),
                };
                if (call and buf[i + 1] == cto) {
                    const abs: u32 = (@as(u32, buf[i + 2]) << 16) | (@as(u32, buf[i + 3]) << 8) | buf[i + 4];
                    const rel = abs -% @as(u32, @truncate(i + 1));
                    std.mem.writeInt(u32, buf[i + 1 ..][0..4], rel, .little);
                    i += 5;
                    continue;
                }
                i += 1;
            }
        },
        0x52 => {
            var i: usize = 0;
            while (i + 4 <= buf.len) : (i += 4) {
                const insn = std.mem.readInt(u32, buf[i..][0..4], .little);
                const op = insn >> 26;
                if (op != 0x05 and op != 0x25) continue;
                const imm = ((insn & 0x3ffffff) -% @as(u32, @truncate(i / 4))) & 0x3ffffff;
                std.mem.writeInt(u32, buf[i..][0..4], (insn & 0xfc000000) | imm, .little);
            }
        },
        else => return false,
    }
    return true;
}

/// Try to unpack a UPX-packed executable; does nothing for anything else.
pub fn walk(w: *Walker, src: Source, format: Format) Error!void {
    switch (format) {
        .elf, .macho => try walkChain(w, src, format),
        .pe => try walkPe(w, src),
        else => {},
    }
}

const BInfo = struct { unc: u32, cpr: u32, method: Method, ftid: u8, cto: u8 };

fn readBInfo(w: *Walker, src: Source, off: u64) ?BInfo {
    var b: [12]u8 = undefined;
    src.readAllAt(w.io, off, &b) catch return null;
    return .{
        .unc = std.mem.readInt(u32, b[0..4], .little),
        .cpr = std.mem.readInt(u32, b[4..8], .little),
        .method = @fromBackingInt(@intCast(b[8])),
        .ftid = b[9],
        .cto = b[10],
    };
}

const Region = struct { off: u64, len: u64 };

/// The ELF / Mach-O block chain: l_info at `p_info - 12`, located through the file's last word.
fn walkChain(w: *Walker, src: Source, format: Format) Error!void {
    const total = src.len().?;
    if (total < 64) return;
    var tail: [4]u8 = undefined;
    src.readAllAt(w.io, total - 4, &tail) catch return;
    var pinfo: u64 = std.mem.readInt(u32, &tail, .little);
    if (!hasLInfo(w, src, pinfo)) {
        // Mach-O does not keep the trailer word: look for l_info in the first 4 KiB.
        pinfo = findLInfo(w, src) orelse return;
    }
    var p: [12]u8 = undefined;
    src.readAllAt(w.io, pinfo, &p) catch return;
    const filesize: u64 = std.mem.readInt(u32, p[4..8], .little);
    const blocksize: u64 = std.mem.readInt(u32, p[8..12], .little);
    w.path.push("upx");
    defer w.path.pop();
    if (filesize < 64 or filesize > w.tracker.limits.max_file_size) return w.limit(.file_size);
    const token = w.window(filesize, 0) orelse return;
    defer token.release();
    const mark = w.scratch.mark();
    defer w.scratch.release(mark);
    const out = w.alloc(u8, @intCast(filesize)) orelse return;
    @memset(out, 0);
    const in_buf = w.alloc(u8, @intCast(@max(@min(blocksize, filesize), 4096) + 64)) orelse return;
    var cur = pinfo + 12;

    // The first block: the original headers.
    const first = readBInfo(w, src, cur) orelse return;
    if (first.unc < 64 or first.unc > filesize) return w.notice(.malformed, "upx: bad first block");
    try block(w, src, &cur, first, out[0..first.unc], in_buf) orelse return;
    var regions_buf: [64]Region = undefined;
    const regions = segments(out[0..first.unc], format, filesize, &regions_buf) orelse return w.notice(.unsupported, "upx: original headers not understood");
    var covered: u64 = first.unc;
    var unsupported_filter = false;
    for (regions) |r| {
        // A hole before this segment: UPX stores it inline when it is not all zeros.
        if (r.off > covered) {
            if (readBInfo(w, src, cur)) |bi| if (bi.unc == r.off - covered) {
                try block(w, src, &cur, bi, out[@intCast(covered)..@intCast(r.off)], in_buf) orelse return;
            };
        }
        var at = @max(r.off, covered);
        const end = r.off + r.len;
        while (at < end) {
            const bi = readBInfo(w, src, cur) orelse return w.notice(.malformed, "upx: block chain ends early");
            if (bi.unc == 0 or bi.unc > end - at) return w.notice(.malformed, "upx: block does not fit its segment");
            const dst = out[@intCast(at)..@intCast(at + bi.unc)];
            try block(w, src, &cur, bi, dst, in_buf) orelse return;
            if (!unfilter(dst, bi.ftid, bi.cto)) unsupported_filter = true;
            at += bi.unc;
        }
        covered = @max(covered, end);
    }
    // Holes after the segments: stored in order (Mach-O), or the rest of the file after the
    // decompression stub, just before the end marker (ELF).
    var holes = Holes{ .regions = regions, .first = first.unc, .filesize = filesize };
    while (holes.next()) |h| {
        const bi = readBInfo(w, src, cur) orelse break;
        if (bi.unc != h.len or bi.cpr > bi.unc or bi.cpr == 0) break;
        try block(w, src, &cur, bi, out[@intCast(h.off)..@intCast(h.off + h.len)], in_buf) orelse return;
        holes.done = h.off + h.len;
    }
    if (holes.tail()) |h| {
        if (findTail(w, src, h.len)) |off| {
            var c = off;
            const bi = readBInfo(w, src, c).?;
            try block(w, src, &c, bi, out[@intCast(h.off)..], in_buf) orelse return;
        }
    }
    if (unsupported_filter) w.notice(.unsupported, "upx: filter (scanned filtered)");
    w.path.pop();
    defer w.path.push("upx");
    try w.child("upx", .{ .memory = out }, .unpacked);
}

/// Decompress the block at `cur.*` into `dst` (exactly `bi.unc` bytes) and step past it. Null
/// when the block is damaged (reported).
fn block(w: *Walker, src: Source, cur: *u64, bi: BInfo, dst: []u8, in_buf: []u8) Error!?void {
    if (bi.cpr > in_buf.len or bi.cpr > bi.unc or dst.len != bi.unc) {
        w.notice(.malformed, "upx: block sizes");
        return null;
    }
    const data = in_buf[0..bi.cpr];
    src.readAllAt(w.io, cur.* + 12, data) catch {
        w.notice(.malformed, "upx: block beyond the end of the file");
        return null;
    };
    cur.* += 12 + bi.cpr;
    if (bi.cpr == bi.unc) {
        @memcpy(dst, data);
        return {};
    }
    decompress(w, bi.method, data, dst) catch |e| {
        w.notice(if (e == error.Unsupported) .unsupported else .malformed, if (e == error.Unsupported) "upx: compression method" else "upx: damaged block");
        return null;
    };
    return {};
}

fn hasLInfo(w: *Walker, src: Source, pinfo: u64) bool {
    if (pinfo < 12 or pinfo > (src.len().? -| 24)) return false;
    var m: [4]u8 = undefined;
    src.readAllAt(w.io, pinfo - 8, &m) catch return false;
    return std.mem.eql(u8, &m, "UPX!");
}

fn findLInfo(w: *Walker, src: Source) ?u64 {
    var head: [4096]u8 = undefined;
    const n = src.readAt(w.io, 0, &head) catch return null;
    const at = std.mem.indexOf(u8, head[0..n], "UPX!") orelse return null;
    if (at < 4) return null;
    return at + 8;
}

/// The tail block: it ends at the end marker (a b_info of size 0 whose next word is "UPX!"),
/// which sits right before the PackHeader near the end of the file.
fn findTail(w: *Walker, src: Source, unc: u64) ?u64 {
    const total = src.len().?;
    var buf: [256]u8 = undefined;
    const from = total -| buf.len;
    const n = src.readAt(w.io, from, &buf) catch return null;
    // The PackHeader is the last "UPX!"; the marker comes before it.
    const ph = std.mem.lastIndexOf(u8, buf[0..n], "UPX!") orelse return null;
    var i: usize = ph -| 7;
    const marker: u64 = while (i > 0) {
        i -= 1;
        if (std.mem.readInt(u32, buf[i..][0..4], .little) == 0 and std.mem.eql(u8, buf[i + 4 ..][0..4], "UPX!")) break from + i;
    } else return null;
    // b_info{unc, cpr} at p with p + 12 + cpr == marker: scan the bytes before the marker.
    const mark = w.scratch.mark();
    defer w.scratch.release(mark);
    const span: u64 = @min(unc + 12, marker, 1 << 20);
    const win = w.alloc(u8, @intCast(span)) orelse return null;
    src.readAllAt(w.io, marker - span, win) catch return null;
    var cpr: u64 = 1;
    while (cpr <= unc and cpr + 12 <= span) : (cpr += 1) {
        const at: usize = @intCast(span - 12 - cpr);
        if (std.mem.readInt(u32, win[at..][0..4], .little) == unc and std.mem.readInt(u32, win[at + 4 ..][0..4], .little) == cpr) return marker - 12 - cpr;
    }
    return null;
}

const Holes = struct {
    regions: []const Region,
    first: u64,
    filesize: u64,
    done: u64 = 0,

    /// The next uncovered range at or after `done`.
    fn next(h: *const Holes) ?Region {
        var at = @max(h.done, h.first);
        while (at < h.filesize) {
            var moved = false;
            for (h.regions) |r| if (at >= r.off and at < r.off + r.len) {
                at = r.off + r.len;
                moved = true;
            };
            if (!moved) break;
        }
        if (at >= h.filesize) return null;
        var end = h.filesize;
        for (h.regions) |r| if (r.off > at and r.off < end) {
            end = r.off;
        };
        return .{ .off = at, .len = end - at };
    }

    /// The uncovered range that runs to the end of the file, if any.
    fn tail(h: *const Holes) ?Region {
        var probe = h.*;
        while (probe.next()) |r| {
            if (r.off + r.len == h.filesize) return r;
            probe.done = r.off + r.len;
        }
        return null;
    }
};

/// The original file's segments, from its headers: ELF PT_LOAD, Mach-O LC_SEGMENT(_64); file
/// order, empty ones dropped.
fn segments(hdr: []const u8, format: Format, filesize: u64, out: *[64]Region) ?[]Region {
    var n: usize = 0;
    switch (format) {
        .elf => {
            if (hdr.len < 52 or hdr[5] != 1) return null; // little-endian only
            const is64 = hdr[4] == 2;
            const phoff: u64 = if (is64) std.mem.readInt(u64, hdr[0x20..][0..8], .little) else std.mem.readInt(u32, hdr[0x1c..][0..4], .little);
            const phnum = std.mem.readInt(u16, hdr[if (is64) 0x38 else 0x2c..][0..2], .little);
            const entsize: u64 = if (is64) 56 else 32;
            for (0..phnum) |i| {
                const at = phoff + i * entsize;
                if (at + entsize > hdr.len) return null;
                const ph = hdr[@intCast(at)..][0..@intCast(entsize)];
                if (std.mem.readInt(u32, ph[0..4], .little) != 1) continue;
                const off: u64 = if (is64) std.mem.readInt(u64, ph[8..16], .little) else std.mem.readInt(u32, ph[4..8], .little);
                const len: u64 = if (is64) std.mem.readInt(u64, ph[32..40], .little) else std.mem.readInt(u32, ph[16..20], .little);
                if (len == 0) continue;
                if (n == out.len or off > filesize or len > filesize - off) return null;
                out[n] = .{ .off = off, .len = len };
                n += 1;
            }
        },
        .macho => {
            if (hdr.len < 28) return null;
            const magic = std.mem.readInt(u32, hdr[0..4], .little);
            const is64 = magic == 0xfeedfacf;
            if (!is64 and magic != 0xfeedface) return null;
            const ncmds = std.mem.readInt(u32, hdr[16..20], .little);
            var at: usize = if (is64) 32 else 28;
            for (0..@min(ncmds, 512)) |_| {
                if (at + 8 > hdr.len) return null;
                const cmd = std.mem.readInt(u32, hdr[at..][0..4], .little);
                const size = std.mem.readInt(u32, hdr[at + 4 ..][0..4], .little);
                if (size < 8 or at + size > hdr.len) return null;
                if ((cmd == 0x19 and size >= 72) or (cmd == 0x1 and size >= 56)) {
                    const off: u64 = if (cmd == 0x19) std.mem.readInt(u64, hdr[at + 40 ..][0..8], .little) else std.mem.readInt(u32, hdr[at + 32 ..][0..4], .little);
                    const len: u64 = if (cmd == 0x19) std.mem.readInt(u64, hdr[at + 48 ..][0..8], .little) else std.mem.readInt(u32, hdr[at + 36 ..][0..4], .little);
                    if (len != 0) {
                        if (n == out.len or off > filesize or len > filesize - off) return null;
                        out[n] = .{ .off = off, .len = len };
                        n += 1;
                    }
                }
                at += size;
            }
        },
        else => return null,
    }
    return out[0..n];
}

/// PE: the PackHeader sits in the headers, the compressed image right after it.
fn walkPe(w: *Walker, src: Source) Error!void {
    var head: [1024]u8 = undefined;
    const n = src.readAt(w.io, 0, &head) catch return;
    const ph = std.mem.indexOf(u8, head[0..n], "UPX!") orelse return;
    if (n - ph < 32) return;
    const h = head[ph..][0..32];
    if (h[4] < 10) return; // older PackHeaders are laid out differently
    const method: Method = @fromBackingInt(@intCast(h[6]));
    const u_len = std.mem.readInt(u32, h[16..20], .little);
    const c_len = std.mem.readInt(u32, h[20..24], .little);
    const file_len = std.mem.readInt(u32, h[24..28], .little);
    const filter = h[28];
    const cto = h[29];
    w.path.push("upx");
    defer w.path.pop();
    if (u_len == 0 or c_len == 0 or c_len > u_len) return w.notice(.malformed, "upx: PackHeader sizes");
    if (u_len > w.tracker.limits.max_file_size) return w.limit(.file_size);
    const total = src.len().?;
    const start: u64 = ph + 32;
    if (start + c_len > total) return w.notice(.malformed, "upx: compressed image beyond the end of the file");
    const token = w.window(u_len, c_len) orelse return;
    defer token.release();
    const mark = w.scratch.mark();
    defer w.scratch.release(mark);
    const comp = w.alloc(u8, c_len) orelse return;
    src.readAllAt(w.io, start, comp) catch return;
    const out = w.alloc(u8, u_len) orelse return;
    // The image ends with UPX's own import and relocation records; decode to the declared size.
    decompress(w, method, comp, out) catch |e| {
        return w.notice(if (e == error.Unsupported) .unsupported else .malformed, if (e == error.Unsupported) "upx: compression method" else "upx: damaged image");
    };
    const unfiltered = unfilter(out, filter, cto);
    if (!unfiltered) w.notice(.unsupported, "upx: filter (scanned filtered)");
    // The file is rebuilt only from an image whose filter was undone.
    const rebuilt = if (unfiltered) rebuildPe(w, src, out, file_len) else null;
    defer if (rebuilt) |r| r.token.release();
    w.path.pop();
    defer w.path.push("upx");
    if (rebuilt) |r| {
        try w.child("upx", .{ .memory = r.file }, .unpacked);
        // Image bytes that no section of the original file maps are not in the file.
        if (!r.unmapped_zero) try w.child("upx/image", .{ .memory = out }, .unpacked);
        return;
    }
    try w.child("upx/image", .{ .memory = out }, .unpacked);
}

fn readU16(b: []const u8, at: usize) ?u16 {
    if (at > b.len or b.len - at < 2) return null;
    return std.mem.readInt(u16, b[at..][0..2], .little);
}

fn readU32(b: []const u8, at: usize) ?u32 {
    if (at > b.len or b.len - at < 4) return null;
    return std.mem.readInt(u32, b[at..][0..4], .little);
}

const dir_reloc = 5;
const dir_load_config = 10;
const dir_iat = 12;
/// The Windows loader's limit on sections.
const max_pe_sections = 96;

/// A PE32+ image as UPX leaves it, in the one layout this was written from (UPX 5.3 output, an
/// amd64 sample). The section bytes run to the original SizeOfImage; then come the import
/// records, the relocation stream, and the original PE header with its section table, each
/// right after the other, and a 17-byte trailer: the import records' offset, a zero word, the
/// relocation stream's offset, a zero byte, and the header's offset.
const PeImage = struct {
    img: []const u8,
    /// Where the section bytes end (the import records' offset).
    end: usize,
    relocs_at: usize,
    header_at: usize,
    header_len: usize,
    image_base: u64,
    size_of_headers: u32,
    /// Offset of the data directories in the header, and how many there are.
    dirs_at: usize,
    ndirs: u32,
    nsections: u16,
    sections_at: usize,
    /// The lowest section address of the packed file: image offset 0.
    rvamin: u32,

    const Section = struct { va: u32, raw_len: u32, raw_off: u32 };

    const ParseError = error{ Layout, Pe32 };

    fn parse(img: []const u8, rvamin: u32) ParseError!PeImage {
        const n = img.len;
        if (n < 17 + 24) return error.Layout;
        const tail = n - 17;
        const imports_at: usize = readU32(img, tail).?;
        const relocs_at: usize = readU32(img, tail + 8).?;
        const header_at: usize = readU32(img, tail + 13).?;
        if (readU32(img, tail + 4).? != 0 or img[tail + 12] != 0) return error.Layout;
        if (!(imports_at < relocs_at and relocs_at < header_at and header_at < tail)) return error.Layout;
        if (tail - header_at < 24 + 112 or !std.mem.eql(u8, img[header_at..][0..4], "PE\x00\x00")) return error.Layout;
        const nsections = readU16(img, header_at + 6).?;
        const opt_size = readU16(img, header_at + 20).?;
        switch (readU16(img, header_at + 24).?) {
            0x20b => {},
            0x10b => return error.Pe32,
            else => return error.Layout,
        }
        const dirs_off: usize = 112;
        const header_len = 24 + @as(usize, opt_size) + 40 * @as(usize, nsections);
        if (opt_size < dirs_off or nsections == 0 or nsections > max_pe_sections) return error.Layout;
        if (header_len != tail - header_at) return error.Layout;
        const o = header_at + 24;
        const size_of_image = readU32(img, o + 56).?;
        if (size_of_image < rvamin or size_of_image - rvamin != imports_at) return error.Layout;
        return .{
            .img = img,
            .end = imports_at,
            .relocs_at = relocs_at,
            .header_at = header_at,
            .header_len = header_len,
            .image_base = std.mem.readInt(u64, img[o + 24 ..][0..8], .little),
            .size_of_headers = readU32(img, o + 60).?,
            .dirs_at = 24 + dirs_off,
            .ndirs = @min(readU32(img, o + dirs_off - 4).?, (opt_size - dirs_off) / 8, 16),
            .nsections = nsections,
            .sections_at = 24 + @as(usize, opt_size),
            .rvamin = rvamin,
        };
    }

    fn dir(p: *const PeImage, i: usize) pe.DataDir {
        if (i >= p.ndirs) return .{};
        const at = p.header_at + p.dirs_at + i * 8;
        return .{ .rva = readU32(p.img, at).?, .size = readU32(p.img, at + 4).? };
    }

    fn section(p: *const PeImage, k: usize) Section {
        const s = p.header_at + p.sections_at + 40 * k;
        return .{ .va = readU32(p.img, s + 12).?, .raw_len = readU32(p.img, s + 16).?, .raw_off = readU32(p.img, s + 20).? };
    }

    /// Image offset of `len` bytes at `rva`, when they lie inside the section bytes.
    fn span(p: *const PeImage, rva: u64, len: usize) ?usize {
        if (rva < p.rvamin) return null;
        const off = rva - p.rvamin;
        if (off > p.end or p.end - off < len) return null;
        return @intCast(off);
    }

    /// File offset of `len` bytes at `rva` in the rebuilt file: inside one section's raw data.
    fn fileSpan(p: *const PeImage, rva: u64, len: usize) ?usize {
        for (0..p.nsections) |k| {
            const s = p.section(k);
            if (rva < s.va or rva - s.va > s.raw_len or s.raw_len - (rva - s.va) < len) continue;
            return @intCast(s.raw_off + (rva - s.va));
        }
        return null;
    }

    /// Whether the image holds zeros for `len` bytes at `rva`. A record may only be written
    /// over bytes UPX zeroed (as every one in the sample is), so the file never drops image
    /// data the scan would otherwise see.
    fn zeroAt(p: *const PeImage, rva: u64, len: usize) bool {
        const at = p.span(rva, len) orelse return false;
        return std.mem.allEqual(u8, p.img[at..][0..len], 0);
    }
};

const Rebuilt = struct {
    file: []u8,
    token: @import("../../engine/budget.zig").Budget.Token,
    /// Every image byte outside the original sections' raw data is zero. The file then holds
    /// all of the image: sections do not overlap in the file, and records are written only over
    /// zeros.
    unmapped_zero: bool,
};

/// Rebuild the original PE file from the unpacked image as `upx -d` writes it: the packed
/// file's DOS header and stub, the original PE header and section table with the IAT directory
/// cleared, each section's raw bytes at its file offset, and then the import and relocation
/// records applied to that file. The image is only read. Null when the image does not have the
/// layout this was written from, or is damaged (each with a notice), or a limit stops it (the
/// limit is reported); the caller then scans the image as it is.
fn rebuildPe(w: *Walker, src: Source, img: []const u8, file_len: u32) ?Rebuilt {
    var sections: [16]pe.Section = undefined;
    const packed_info = pe.parse(w.io, src, &sections) catch {
        w.notice(.malformed, "upx: packed PE headers");
        return null;
    };
    if (packed_info.sections.len == 0 or packed_info.nsections > sections.len) {
        w.notice(.unsupported, "upx: packed PE section table");
        return null;
    }
    if (packed_info.overlay_off < packed_info.file_size) {
        w.notice(.unsupported, "upx: packed PE with an overlay");
        return null;
    }
    var rvamin: u32 = std.math.maxInt(u32);
    for (packed_info.sections) |s| rvamin = @min(rvamin, s.va);
    const p = PeImage.parse(img, rvamin) catch |e| {
        w.notice(.unsupported, if (e == error.Pe32) "upx: PE32 rebuild (no sample to check it against)" else "upx: PE records not laid out as in the sample");
        return null;
    };
    const pel = packed_info.pe_offset;
    if (p.size_of_headers > file_len or pel > p.size_of_headers or p.header_len > p.size_of_headers - pel) {
        w.notice(.malformed, "upx: original PE header does not fit");
        return null;
    }
    // Each section's raw data comes from inside the section bytes and lands inside the file;
    // the file ends where the last one does (an overlay was not seen, so none is accepted).
    var layout_end: u64 = p.size_of_headers;
    var mapped: [max_pe_sections]Region = undefined;
    var placed: [max_pe_sections]Region = undefined;
    var nmapped: usize = 0;
    for (0..p.nsections) |k| {
        const s = p.section(k);
        if (s.raw_len == 0) continue;
        const from = p.span(s.va, s.raw_len) orelse {
            w.notice(.malformed, "upx: original section outside the image");
            return null;
        };
        if (s.raw_off < p.size_of_headers or s.raw_off > file_len or s.raw_len > file_len - s.raw_off) {
            w.notice(.malformed, "upx: original section outside the file");
            return null;
        }
        layout_end = @max(layout_end, @as(u64, s.raw_off) + s.raw_len);
        mapped[nmapped] = .{ .off = from, .len = s.raw_len };
        placed[nmapped] = .{ .off = s.raw_off, .len = s.raw_len };
        nmapped += 1;
    }
    sortRegions(placed[0..nmapped]);
    for (1..nmapped) |k| if (placed[k].off < placed[k - 1].off + placed[k - 1].len) {
        w.notice(.unsupported, "upx: original sections overlap in the file");
        return null;
    };
    if (layout_end != file_len) {
        w.notice(.unsupported, "upx: PE file size other than its sections' end (overlay)");
        return null;
    }
    if (file_len > w.tracker.limits.max_file_size) {
        w.limit(.file_size);
        return null;
    }
    const token = w.window(file_len, 0) orelse return null;
    const out = w.alloc(u8, file_len) orelse {
        token.release();
        return null;
    };
    @memset(out, 0);
    const done = fill(w, src, &p, &packed_info, out);
    if (done) |unsupported| {
        if (unsupported) w.notice(.unsupported, "upx: PE records not understood") else w.notice(.malformed, "upx: PE records point outside the file");
        // The last scratch allocation, so this returns it.
        w.free(out);
        token.release();
        return null;
    }
    if (p.dir(pe.dir_resource).rva != 0 or p.dir(pe.dir_export).rva != 0 or p.dir(dir_load_config).rva != 0)
        w.notice(.unsupported, "upx: PE resources, exports and load configuration are copied, not rebuilt");
    return .{ .file = out, .token = token, .unmapped_zero = unmappedZero(img[0..p.end], mapped[0..nmapped]) };
}

/// Whether every byte of `img` outside `mapped` is zero.
fn sortRegions(r: []Region) void {
    std.sort.insertion(Region, r, {}, struct {
        fn lt(_: void, a: Region, b: Region) bool {
            return a.off < b.off;
        }
    }.lt);
}

fn unmappedZero(img: []const u8, mapped: []Region) bool {
    sortRegions(mapped);
    var at: u64 = 0;
    for (mapped) |r| {
        if (r.off > at and std.mem.indexOfNone(u8, img[@intCast(at)..@intCast(r.off)], &.{0}) != null) return false;
        at = @max(at, r.off + r.len);
    }
    return at >= img.len or std.mem.indexOfNone(u8, img[@intCast(at)..], &.{0}) == null;
}

/// Lay the file out and apply the records. Null when done; otherwise whether the failure was a
/// record that was not understood (true) or one that points outside the file (false).
fn fill(w: *Walker, src: Source, p: *const PeImage, packed_info: *const pe.Info, out: []u8) ?bool {
    const img = p.img;
    const pel = packed_info.pe_offset;
    src.readAllAt(w.io, 0, out[0..pel]) catch return false;
    @memcpy(out[pel..][0..p.header_len], img[p.header_at..][0..p.header_len]);
    if (p.ndirs > dir_iat) @memset(out[pel + p.dirs_at + dir_iat * 8 ..][0..8], 0);
    for (0..p.nsections) |k| {
        const s = p.section(k);
        if (s.raw_len == 0) continue;
        @memcpy(out[s.raw_off..][0..s.raw_len], img[s.va - p.rvamin ..][0..s.raw_len]);
    }
    if (fillImports(w, src, p, packed_info, out)) |e| return e;
    return fillRelocs(p, out);
}

/// The import records: per DLL, the offset of its name in the packed file's import data and
/// its IAT's image offset, then one record per function (1 and the name), ended by 0; a zero
/// name offset ends the list, and the relocation stream follows at once. The descriptors and
/// the thunks are still in the image; each descriptor's IAT field, the DLL names and the
/// hint/name entries (hint 0) are written, each over zeros in the image. Ordinals, any other
/// record, and more DLLs than the import directory holds were not seen, so they are refused.
fn fillImports(w: *Walker, src: Source, p: *const PeImage, packed_info: *const pe.Info, out: []u8) ?bool {
    const img = p.img[0..p.relocs_at];
    const import_dir = p.dir(pe.dir_import);
    const dir_rva = import_dir.rva;
    const names_rva = packed_info.dir(pe.dir_import).rva;
    var q = p.end;
    var functions: usize = 0;
    var k: usize = 0;
    while (true) : (k += 1) {
        const name_off = readU32(img, q) orelse return true;
        q += 4;
        if (name_off == 0) break;
        // The directory ends with a zero descriptor, which no record fills.
        if (dir_rva == 0 or k >= import_dir.size / 20 -| 1 or k == pe.max_import_descriptors) return true;
        const iat = readU32(img, q) orelse return true;
        q += 4;
        const desc_rva = @as(u64, dir_rva) + 20 * k;
        const desc = p.span(desc_rva, 20) orelse return false;
        var name_buf: [256]u8 = undefined;
        const at = packed_info.rvaToOffset(@as(u64, names_rva) + name_off) orelse return false;
        const got = src.readAt(w.io, at, &name_buf) catch return false;
        const name_len = std.mem.indexOfScalar(u8, name_buf[0..got], 0) orelse return true;
        const iat_rva = @as(u64, iat) + p.rvamin;
        if (iat_rva > std.math.maxInt(u32)) return false;
        const ft = p.fileSpan(desc_rva + 16, 4) orelse return false;
        const name_rva = readU32(p.img, desc + 12).?;
        const name_at = p.fileSpan(name_rva, name_len + 1) orelse return false;
        if (!p.zeroAt(desc_rva + 16, 4) or !p.zeroAt(name_rva, name_len + 1)) return true;
        std.mem.writeInt(u32, out[ft..][0..4], @intCast(iat_rva), .little);
        @memcpy(out[name_at..][0..name_len], name_buf[0..name_len]);
        out[name_at + name_len] = 0;
        var thunk = iat_rva;
        while (true) : (thunk += 8) {
            if (q >= img.len) return true;
            const tag = img[q];
            q += 1;
            if (tag == 0) break;
            if (tag != 1) return true;
            const end = std.mem.indexOfScalarPos(u8, img, q, 0) orelse return true;
            const fname = img[q..end];
            q = end + 1;
            functions += 1;
            if (functions > pe.max_imports or fname.len > 4096) return true;
            const t = p.span(thunk, 8) orelse return false;
            const target = std.mem.readInt(u64, p.img[t..][0..8], .little);
            const entry = p.fileSpan(target, 2 + fname.len + 1) orelse return false;
            if (!p.zeroAt(target, 2 + fname.len + 1)) return true;
            out[entry] = 0;
            out[entry + 1] = 0;
            @memcpy(out[entry + 2 ..][0..fname.len], fname);
            out[entry + 2 + fname.len] = 0;
        }
    }
    if (q != p.relocs_at) return true;
    return null;
}

/// The relocation stream: deltas from `rvamin - 4` to each site, one byte each, or 0xf0 and a
/// 16-bit delta; 0 ends it, and the header follows at once. Each site holds its target as a
/// big-endian 64-bit offset from the image base plus `rvamin` (all sites are DIR64, at least 8
/// bytes apart). The table written at the relocation directory, over zeros in the image, has
/// one block per 4 KiB page and must fill the directory exactly. The sample's blocks all have an
/// even number of entries; an odd one (which the PE format pads) was not seen and is refused.
fn fillRelocs(p: *const PeImage, out: []u8) ?bool {
    const img = p.img;
    const reloc_dir = p.dir(dir_reloc);
    // Pass one: the sites, and the table's size.
    var q = p.relocs_at;
    var pos: u64 = @as(u64, p.rvamin) -% 4;
    var table: usize = 0;
    var entries: usize = 0;
    // Never a page address: those have the low 12 bits clear.
    var page: u64 = std.math.maxInt(u64);
    while (true) {
        const delta = nextDelta(img[0..p.header_at], &q) orelse return true;
        if (delta == 0) break;
        // The first delta reaches the first site from rvamin - 4; later sites do not overlap.
        if (delta < 8 and entries + table != 0) return true;
        pos +%= delta;
        if (pos > std.math.maxInt(u32)) return false;
        const site = p.span(pos, 8) orelse return false;
        const to = p.fileSpan(pos, 8) orelse return false;
        const v = std.mem.readInt(u64, img[site..][0..8], .big) +% p.image_base +% p.rvamin;
        std.mem.writeInt(u64, out[to..][0..8], v, .little);
        if (page != pos & ~@as(u64, 0xfff)) {
            if (entries % 2 != 0) return true;
            table += blockLen(entries);
            entries = 0;
            page = pos & ~@as(u64, 0xfff);
        }
        entries += 1;
    }
    if (entries % 2 != 0) return true;
    table += blockLen(entries);
    if (q != p.header_at or table != reloc_dir.size) return true;
    if (table == 0) return null;
    const at = p.fileSpan(reloc_dir.rva, table) orelse return false;
    if (!p.zeroAt(reloc_dir.rva, table)) return true;
    // Pass two: the table. The stream was checked in pass one.
    q = p.relocs_at;
    pos = @as(u64, p.rvamin) -% 4;
    var head: ?usize = null;
    var o = at;
    while (true) {
        const delta = nextDelta(img[0..p.header_at], &q).?;
        if (delta == 0) break;
        pos +%= delta;
        if (head == null or page != pos & ~@as(u64, 0xfff)) {
            if (head) |b| o = closeBlock(out, b, o);
            page = pos & ~@as(u64, 0xfff);
            head = o;
            std.mem.writeInt(u32, out[o..][0..4], @intCast(page), .little);
            o += 8;
        }
        std.mem.writeInt(u16, out[o..][0..2], 0xa000 | @as(u16, @intCast(pos & 0xfff)), .little);
        o += 2;
    }
    _ = closeBlock(out, head.?, o);
    return null;
}

/// The next relocation delta (0 at the end of the stream), or null for a prefix that was not
/// seen (only 0xf0 with a 16-bit delta was) or a stream that runs out.
fn nextDelta(stream: []const u8, q: *usize) ?u64 {
    if (q.* >= stream.len) return null;
    const c = stream[q.*];
    q.* += 1;
    if (c < 0xf0) return c;
    if (c != 0xf0) return null;
    const d = readU16(stream, q.*) orelse return null;
    q.* += 2;
    if (d == 0) return null;
    return d;
}

fn blockLen(entries: usize) usize {
    if (entries == 0) return 0;
    return 8 + 2 * (entries + entries % 2);
}

fn closeBlock(out: []u8, at: usize, end: usize) usize {
    var o = end;
    if ((o - at) % 4 != 0) {
        std.mem.writeInt(u16, out[o..][0..2], 0, .little);
        o += 2;
    }
    std.mem.writeInt(u32, out[at + 4 ..][0..4], @intCast(o - at), .little);
    return o;
}

test "nrv: a stream that runs out of input or output is an error" {
    var dst: [2]u8 = undefined;
    // Bits 1, 1, ...: a literal 'a', then a second literal with no byte left.
    try std.testing.expectError(error.Corrupt, nrv(&.{ 0xff, 'a' }, &dst, .nrv2b_8));
    try std.testing.expectError(error.Corrupt, nrv(&.{}, &dst, .nrv2e_le32));
    try std.testing.expectError(error.Unsupported, nrv(&.{0}, &dst, @fromBackingInt(@intCast(1))));
}

test "x86 call filter round trip" {
    // A call at 0 to relative 0x10 becomes absolute 0x11 with CTO 0x07.
    var buf = [_]u8{ 0xe8, 0x07, 0x00, 0x00, 0x11, 0x90, 0x90 };
    try std.testing.expect(unfilter(&buf, 0x49, 0x07));
    try std.testing.expectEqual(@as(u32, 0x10), std.mem.readInt(u32, buf[1..5], .little));
}

const fixtures = @import("../fixtures/fixtures.zig");

fn exe(name: []const u8) []const u8 {
    for (fixtures.exes) |e| if (std.mem.eql(u8, e.name, name)) return e.bytes;
    unreachable;
}

/// Collects the bytes of the unpacked child.
const Capture = struct {
    list: std.ArrayList(u8) = .empty,
    notices: usize = 0,

    fn visitor(c: *Capture) container.Visitor {
        return .{ .ptr = c, .vtable = &.{ .enter = enter, .data = data, .leave = leave, .notice = notice } };
    }
    fn enter(_: *anyopaque, _: *const container.Object) error{Stop}!void {}
    fn data(ptr: *anyopaque, obj: *const container.Object, bytes: []const u8) error{Stop}!void {
        const c: *Capture = @ptrCast(@alignCast(ptr));
        if (obj.kind == .unpacked) c.list.appendSlice(std.testing.allocator, bytes) catch return error.Stop;
    }
    fn leave(_: *anyopaque, _: *const container.Object) void {}
    fn notice(ptr: *anyopaque, _: container.Notice) void {
        const c: *Capture = @ptrCast(@alignCast(ptr));
        c.notices += 1;
    }
};

test "PE: the rebuilt file is what upx -d writes" {
    const packed_pe = exe("upx-amd64-pe");
    const unpacked_pe = exe("upx-amd64-pe-d");
    var rig: @import("../scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    var cap: Capture = .{};
    defer cap.list.deinit(std.testing.allocator);
    rig.walker.visitor = cap.visitor();
    try rig.walker.scan(.{ .memory = packed_pe }, "upx-amd64-pe");
    try std.testing.expectEqual(@as(usize, 0), cap.notices);
    // The rebuilt file is the only unpacked child: every image byte outside it is zero.
    try std.testing.expectEqualSlices(u8, unpacked_pe, cap.list.items);
}

/// The sample's decompressed, unfiltered image (caller frees).
fn sampleImage() !struct { img: []u8, file_len: u32 } {
    const packed_pe = exe("upx-amd64-pe");
    const ph = std.mem.indexOf(u8, packed_pe[0..1024], "UPX!").?;
    const h = packed_pe[ph..][0..32];
    const img = try std.testing.allocator.alloc(u8, std.mem.readInt(u32, h[16..20], .little));
    errdefer std.testing.allocator.free(img);
    try nrv(packed_pe[ph + 32 ..][0..std.mem.readInt(u32, h[20..24], .little)], img, .nrv2b_le32);
    try std.testing.expect(unfilter(img, h[28], h[29]));
    return .{ .img = img, .file_len = std.mem.readInt(u32, h[24..28], .little) };
}

test "PE: records that were never seen are refused, and the image is only read" {
    const packed_pe = exe("upx-amd64-pe");
    const sample = try sampleImage();
    const img = sample.img;
    defer std.testing.allocator.free(img);
    const before = try std.testing.allocator.dupe(u8, img);
    defer std.testing.allocator.free(before);
    const p = try PeImage.parse(img, 0x1000);
    var rig: @import("../scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();

    // The first DLL's first function record: tag 1 (by name). Any other tag is refused.
    const tag_at = p.end + 8;
    try std.testing.expectEqual(@as(u8, 1), img[tag_at]);
    img[tag_at] = 2;
    try std.testing.expect(rebuildPe(&rig.walker, .{ .memory = packed_pe }, img, sample.file_len) == null);
    try std.testing.expect(rig.rec.has(.unsupported));
    img[tag_at] = 1;

    // The first relocation delta is 0xf0 and a 16-bit delta; 0xf1 was never seen.
    try std.testing.expectEqual(@as(u8, 0xf0), img[p.relocs_at]);
    img[p.relocs_at] = 0xf1;
    try std.testing.expect(rebuildPe(&rig.walker, .{ .memory = packed_pe }, img, sample.file_len) == null);
    img[p.relocs_at] = 0xf0;

    // A trailer whose zero fields are set, or that names no PE header.
    img[img.len - 13] = 1;
    try std.testing.expectError(error.Layout, PeImage.parse(img, 0x1000));
    img[img.len - 13] = 0;
    img[img.len - 5] = 1;
    try std.testing.expectError(error.Layout, PeImage.parse(img, 0x1000));
    img[img.len - 5] = 0;
    img[img.len - 4] ^= 1;
    try std.testing.expectError(error.Layout, PeImage.parse(img, 0x1000));
    img[img.len - 4] ^= 1;

    // PE32 has no sample to check against.
    img[p.header_at + 24] = 0x0b;
    img[p.header_at + 25] = 0x01;
    try std.testing.expectError(error.Pe32, PeImage.parse(img, 0x1000));
    img[p.header_at + 25] = 0x02;

    // A file size past the sections' end would need an overlay, which was not seen.
    try std.testing.expect(rebuildPe(&rig.walker, .{ .memory = packed_pe }, img, sample.file_len + 512) == null);

    // A hint/name entry aimed at non-zero image bytes (the first thunk pointed into .text).
    const thunk_at = readU32(img, p.end + 4).?;
    const thunk_was = std.mem.readInt(u64, img[thunk_at..][0..8], .little);
    std.mem.writeInt(u64, img[thunk_at..][0..8], 0x1100, .little);
    try std.testing.expect(rebuildPe(&rig.walker, .{ .memory = packed_pe }, img, sample.file_len) == null);
    std.mem.writeInt(u64, img[thunk_at..][0..8], thunk_was, .little);

    // Sections that overlap in the file (.rdata moved onto .text).
    const rdata_raw = p.header_at + p.sections_at + 40 + 20;
    const rdata_was = readU32(img, rdata_raw).?;
    std.mem.writeInt(u32, img[rdata_raw..][0..4], 0x400, .little);
    try std.testing.expect(rebuildPe(&rig.walker, .{ .memory = packed_pe }, img, sample.file_len) == null);
    std.mem.writeInt(u32, img[rdata_raw..][0..4], rdata_was, .little);

    // A rebuild reads the image and writes only the file.
    const r = rebuildPe(&rig.walker, .{ .memory = packed_pe }, img, sample.file_len).?;
    defer r.token.release();
    try std.testing.expect(r.unmapped_zero);
    try std.testing.expectEqualSlices(u8, before, img);
    try std.testing.expectEqualSlices(u8, exe("upx-amd64-pe-d"), r.file);
}

test "PE: non-zero image bytes outside the original sections mark the image for scanning too" {
    const packed_pe = exe("upx-amd64-pe");
    const sample = try sampleImage();
    defer std.testing.allocator.free(sample.img);
    var rig: @import("../scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    // Between .text's raw data (0x9a00 bytes from offset 0) and .rdata (offset 0xa000).
    sample.img[0x9a00 + 5] = 1;
    const r = rebuildPe(&rig.walker, .{ .memory = packed_pe }, sample.img, sample.file_len).?;
    defer r.token.release();
    try std.testing.expect(!r.unmapped_zero);
}

test "PE: a PackHeader file size that does not match the sections leaves the image as the child" {
    const bytes = try std.testing.allocator.dupe(u8, exe("upx-amd64-pe"));
    defer std.testing.allocator.free(bytes);
    const ph = std.mem.indexOf(u8, bytes[0..1024], "UPX!").?;
    // A huge claim must not stop the image from being decoded and scanned.
    std.mem.writeInt(u32, bytes[ph + 24 ..][0..4], 100 << 20, .little);
    var rig: @import("../scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.walker.scan(.{ .memory = bytes }, "f");
    try std.testing.expect(rig.rec.find("f/upx/image") != null);
    try std.testing.expect(rig.rec.find("f/upx") == null);
    try std.testing.expect(rig.rec.has(.unsupported));
}

test "a damaged block is reported, not decoded past its bounds" {
    const src = exe("upx-amd64-elf");
    const bytes = try std.testing.allocator.dupe(u8, src);
    defer std.testing.allocator.free(bytes);
    // Corrupt the first compressed block (it follows l_info and p_info).
    const tail = std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little);
    for (bytes[tail + 24 ..][0..40]) |*b| b.* ^= 0x5a;
    var rig: @import("../scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.walker.scan(.{ .memory = bytes }, "bad");
    try std.testing.expect(rig.rec.has(.malformed));
    try std.testing.expect(rig.rec.find("bad/upx") == null);
}
