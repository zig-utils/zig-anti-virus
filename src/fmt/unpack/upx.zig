//! UPX unpacking, written from the packed-file layout as it can be observed in UPX output and
//! UPX's public documentation (no UPX source is used): the l_info / p_info / b_info block chain of
//! ELF and Mach-O executables, the PackHeader of PE executables, the NRV2B, NRV2D and NRV2E
//! bit streams (8-bit, 16-bit and 32-bit little-endian bit buffers), UPX's two-byte LZMA header,
//! and the x86 (0x49: E8, E9 and 0F 8x with a CTO byte) and ARM64 (0x52: B and BL) call filters.
//!
//! - ELF and Mach-O: the original file is rebuilt exactly. The first block holds the original
//!   headers; each loadable segment's bytes follow in order (split into blocks of at most
//!   p_blocksize), then the holes between and after them, as UPX wrote them. The rebuilt file is
//!   the child "upx", byte-identical to `upx -d` output for the formats tested (i386, amd64 and
//!   arm64 ELF, amd64 Mach-O; NRV2B, NRV2E and LZMA).
//! - PE: the compressed image is decompressed and unfiltered into the child "upx/image": the
//!   sections' bytes laid out from the first section's address. `upx -d` also rebuilds the PE
//!   header, imports, relocations and resources; that is not done here, so the child is not a
//!   PE file, but its section bytes match `upx -d` output where UPX did not rewrite them.
//!
//! Bounds: the output size is the header's claim, capped by MaxFileSize and taken as a decoder
//! window from the big-window budget; every block must decompress to exactly its declared size
//! inside the output; decoders stop at their input or output end.
const std = @import("std");
const container = @import("../../engine/container.zig");
const Source = @import("../../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const Format = container.Format;
const lzma = @import("../lzma.zig");

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
/// 24-bit absolute target; 0x52: ARM64 B and BL hold an absolute word index.
pub fn unfilter(buf: []u8, id: u8, cto: u8) bool {
    switch (id) {
        0 => {},
        0x49 => {
            var i: usize = 0;
            while (i + 5 <= buf.len) {
                const op = buf[i];
                const call = op == 0xe8 or op == 0xe9 or (i > 0 and buf[i - 1] == 0x0f and op & 0xf0 == 0x80);
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
    if (!unfilter(out, filter, cto)) w.notice(.unsupported, "upx: filter (scanned filtered)");
    w.path.pop();
    defer w.path.push("upx");
    try w.child("upx/image", .{ .memory = out }, .unpacked);
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

test "PE: the unpacked image's code section is what upx -d writes" {
    const pe = @import("../pe.zig");
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
    var ps: [16]pe.Section = undefined;
    const pinfo = try pe.parse(std.testing.io, .{ .memory = packed_pe }, &ps);
    const rvamin = pinfo.sections[0].va;
    var ds: [16]pe.Section = undefined;
    const dinfo = try pe.parse(std.testing.io, .{ .memory = unpacked_pe }, &ds);
    const text = for (dinfo.sections) |*sec| {
        if (std.mem.eql(u8, sec.nameSlice(), ".text")) break sec;
    } else return error.TestUnexpectedResult;
    const at: usize = @intCast(text.va - rvamin);
    const want = unpacked_pe[@intCast(text.raw_off)..][0..@intCast(text.raw_size)];
    try std.testing.expectEqualSlices(u8, want, cap.list.items[at..][0..want.len]);
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
