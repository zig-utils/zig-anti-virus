//! zip, written from PKWARE's APPNOTE.TXT (6.3.10): end of central directory (with zip64 locator
//! and record), central directory entries with zip64 extra fields, local headers, data
//! descriptors, and the methods store (0), deflate (8), bzip2 (12), LZMA (14), zstd (93) and
//! xz (95). Deflate64 (9), PPMd (98) and others are reported as unsupported.
//!
//! What malware does to zips is the point of this parser:
//! - The central directory is read first; when it is missing or damaged the local headers are
//!   walked from the start instead.
//! - With a central directory, the local headers are walked as well, and any local entry the
//!   directory does not list is scanned too (the two views disagreeing is reported).
//! - Entries whose data overlaps another's (Fifield's overlapping-file bombs, or many directory
//!   entries naming one local entry) are reported as `overlap` and their shared bytes are
//!   decoded once, so the work is bounded by the archive's size, not the entry count.
//! - Encrypted entries are reported, not decrypted.
//! - Every size and offset is untrusted: bounded by the archive, and decoded output is bounded by
//!   the ratio guard and member size limits, never by header claims.
const std = @import("std");
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const decode = @import("decode.zig");
const ooxml = @import("ooxml.zig");

const sig_local = 0x04034b50;
const sig_central = 0x02014b50;
const sig_eocd = 0x06054b50;
const sig_eocd64 = 0x06064b50;
const sig_locator64 = 0x07064b50;
const sig_descriptor = 0x08074b50;

pub const max_name = 1024;
const eocd_len = 22;
const max_comment = 65535;

const Entry = struct {
    /// Offset of the central directory record (to re-read the name).
    cd_off: u64,
    local_off: u64,
    /// Data range, filled when the local header is read.
    data_off: u64 = 0,
    csize: u64,
    usize: u64,
    method: u16,
    flags: u16,
    name_len: u16,
    crc: u32 = 0,
    skip: bool = false,
};

const Le = struct {
    fn u16at(b: []const u8, off: usize) u16 {
        return std.mem.readInt(u16, b[off..][0..2], .little);
    }
    fn u32at(b: []const u8, off: usize) u32 {
        return std.mem.readInt(u32, b[off..][0..4], .little);
    }
    fn u64at(b: []const u8, off: usize) u64 {
        return std.mem.readInt(u64, b[off..][0..8], .little);
    }
};

const Directory = struct {
    /// Where offsets in the archive are counted from: non-zero when data was prepended (a
    /// self-extractor stub) and the recorded offsets are relative to the zip proper.
    base: u64,
    cd_off: u64,
    cd_size: u64,
    entries: u64,
};

/// Walk a zip held in a positional source.
pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len().?;
    // One buffer for the end-record search and extra fields, from scratch: zips nest, and
    // 64 KiB per level is too much stack.
    const buf = w.alloc(u8, eocd_len + max_comment) orelse return;
    const dir = findDirectory(w, src, total, buf);
    var listed: []Entry = &.{};
    if (dir) |d| {
        listed = readDirectory(w, src, d, total, buf) orelse &.{};
    } else if (total > 0) {
        // No usable central directory: the local headers are all there is.
        w.notice(.malformed, "zip: no central directory, walking local headers");
    }
    if (listed.len > 0) try scanListed(w, src, listed, buf);
    try walkLocal(w, src, listed, total, if (dir) |d| d.base else 0, buf);
}

fn findDirectory(w: *Walker, src: Source, total: u64, tail: []u8) ?Directory {
    if (total < eocd_len) return null;
    const tail_len: usize = @intCast(@min(total, tail.len));
    const tail_off = total - tail_len;
    src.readAllAt(w.io, tail_off, tail[0..tail_len]) catch return null;
    // The last EOCD signature whose comment length reaches the end of the file exactly, or
    // failing that the last signature at all.
    var i: usize = tail_len - eocd_len + 1;
    var fallback: ?usize = null;
    const found: usize = while (i > 0) {
        i -= 1;
        if (Le.u32at(tail, i) != sig_eocd) continue;
        if (fallback == null) fallback = i;
        if (i + eocd_len + Le.u16at(tail, i + 20) == tail_len) break i;
    } else fallback orelse return null;
    const e = tail[found..][0..eocd_len];
    const eocd_pos = tail_off + found;
    var d: Directory = .{
        .base = 0,
        .entries = Le.u16at(e, 10),
        .cd_size = Le.u32at(e, 12),
        .cd_off = Le.u32at(e, 16),
    };
    // zip64: a locator right before the EOCD points at the zip64 EOCD record.
    if (eocd_pos >= 20) {
        var loc: [20]u8 = undefined;
        if (src.readAllAt(w.io, eocd_pos - 20, &loc)) |_| {
            if (Le.u32at(&loc, 0) == sig_locator64) {
                const rec_off = Le.u64at(&loc, 8);
                var rec: [56]u8 = undefined;
                const ok = rec_off < total and if (src.readAllAt(w.io, rec_off, &rec)) |_| true else |_| false;
                if (ok and Le.u32at(&rec, 0) == sig_eocd64) {
                    d.entries = Le.u64at(&rec, 32);
                    d.cd_size = Le.u64at(&rec, 40);
                    d.cd_off = Le.u64at(&rec, 48);
                } else w.notice(.malformed, "zip: bad zip64 end of central directory");
            }
        } else |_| {}
    }
    // Where the directory really starts: as recorded, or (prepended data) right before the EOCD.
    if (d.cd_off <= total and d.cd_size <= total - d.cd_off and sigAt(w, src, d.cd_off) == sig_central) return d;
    if (d.cd_size <= eocd_pos) {
        const guess = eocd_pos - d.cd_size;
        // zip64 archives have the zip64 record and locator between the directory and the EOCD.
        for ([_]u64{ guess, guess -| 76 }) |start| {
            if (sigAt(w, src, start) == sig_central and start >= d.cd_off) {
                d.base = start - d.cd_off;
                d.cd_off = start;
                return d;
            }
        }
    }
    if (d.entries == 0 and d.cd_size == 0) return d; // an empty archive
    w.notice(.malformed, "zip: central directory not where the end record says");
    return null;
}

/// Whether the last 4 KiB hold an end-of-central-directory record whose comment reaches the end
/// exactly: a cheap test for a zip appended to other data.
pub fn hasTrailer(w: *Walker, src: Source) bool {
    const total = src.len() orelse return false;
    if (total < eocd_len) return false;
    var tail: [4096]u8 = undefined;
    const n: usize = @intCast(@min(total, tail.len));
    src.readAllAt(w.io, total - n, tail[0..n]) catch return false;
    var i: usize = n - eocd_len + 1;
    while (i > 0) {
        i -= 1;
        if (Le.u32at(&tail, i) == sig_eocd and i + eocd_len + Le.u16at(&tail, i + 20) == n) return true;
    }
    return false;
}

fn sigAt(w: *Walker, src: Source, off: u64) u32 {
    var b: [4]u8 = undefined;
    src.readAllAt(w.io, off, &b) catch return 0;
    return std.mem.readInt(u32, &b, .little);
}

/// Read the central directory into scratch. Null when it is unreadable (reported).
fn readDirectory(w: *Walker, src: Source, d: Directory, total: u64, extra: []u8) ?[]Entry {
    // Every record is at least 46 bytes, so the directory size bounds the entry count, and
    // MaxFiles bounds what is worth keeping.
    const by_size = d.cd_size / 46;
    const cap: usize = @intCast(@min(by_size, @as(u64, w.tracker.limits.max_files) + 1));
    const entries = w.alloc(Entry, cap) orelse return null;
    var n: usize = 0;
    var off = d.cd_off;
    const end = @min(d.cd_off +| d.cd_size, total);
    var rec: [46]u8 = undefined;
    while (off +| 46 <= end and n < cap) {
        src.readAllAt(w.io, off, &rec) catch break;
        if (Le.u32at(&rec, 0) != sig_central) {
            w.notice(.malformed, "zip: bad central directory record");
            break;
        }
        const name_len = Le.u16at(&rec, 28);
        const extra_len = Le.u16at(&rec, 30);
        const comment_len = Le.u16at(&rec, 32);
        var e: Entry = .{
            .cd_off = off,
            .flags = Le.u16at(&rec, 8),
            .method = Le.u16at(&rec, 10),
            .crc = Le.u32at(&rec, 16),
            .csize = Le.u32at(&rec, 20),
            .usize = Le.u32at(&rec, 24),
            .local_off = Le.u32at(&rec, 42),
            .name_len = name_len,
        };
        if (e.csize == 0xFFFFFFFF or e.usize == 0xFFFFFFFF or e.local_off == 0xFFFFFFFF) {
            const x = extra[0..extra_len];
            src.readAllAt(w.io, off +| (46 + @as(u64, name_len)), x) catch break;
            applyZip64(x, &e.usize, &e.csize, &e.local_off);
        }
        e.local_off +|= d.base;
        entries[n] = e;
        n += 1;
        off += 46 + @as(u64, name_len) + extra_len + comment_len;
    }
    if (n < cap and n < d.entries and off +| 46 > end) w.notice(.malformed, "zip: central directory shorter than its entry count");
    return entries[0..n];
}

/// zip64 extended information (0x0001): the 64-bit values of whichever fields were 0xFFFFFFFF,
/// in the order uncompressed size, compressed size, local header offset.
fn applyZip64(extra: []const u8, usize_v: *u64, csize: *u64, local_off: *u64) void {
    var p: usize = 0;
    while (p + 4 <= extra.len) {
        const id = Le.u16at(extra, p);
        const len = Le.u16at(extra, p + 2);
        if (p + 4 + len > extra.len) return;
        if (id == 0x0001) {
            var q = p + 4;
            const end = q + len;
            inline for (.{ usize_v, csize, local_off }) |field| {
                if (field.* == 0xFFFFFFFF and q + 8 <= end) {
                    field.* = Le.u64at(extra, q);
                    q += 8;
                }
            }
            return;
        }
        p += 4 + len;
    }
}

const Local = struct {
    flags: u16,
    method: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    name_len: u16,
    extra_len: u16,
    /// Offset of the data after this header.
    data_off: u64,
};

fn readLocal(w: *Walker, src: Source, off: u64, extra: []u8) ?Local {
    var h: [30]u8 = undefined;
    src.readAllAt(w.io, off, &h) catch return null;
    if (Le.u32at(&h, 0) != sig_local) return null;
    var l: Local = .{
        .flags = Le.u16at(&h, 6),
        .method = Le.u16at(&h, 8),
        .crc = Le.u32at(&h, 14),
        .csize = Le.u32at(&h, 18),
        .usize = Le.u32at(&h, 22),
        .name_len = Le.u16at(&h, 26),
        .extra_len = Le.u16at(&h, 28),
        .data_off = off +| (30 + @as(u64, Le.u16at(&h, 26)) + Le.u16at(&h, 28)),
    };
    if (l.csize == 0xFFFFFFFF or l.usize == 0xFFFFFFFF) {
        const x = extra[0..l.extra_len];
        src.readAllAt(w.io, off +| (30 + @as(u64, l.name_len)), x) catch return l;
        var dummy: u64 = 0;
        applyZip64(x, &l.usize, &l.csize, &dummy);
    }
    return l;
}

/// Scan the entries the central directory lists, decoding overlapping data only once.
fn scanListed(w: *Walker, src: Source, entries: []Entry, buf: []u8) Error!void {
    const total = src.len().?;
    // Resolve each entry's data range from its local header.
    for (entries) |*e| {
        const l = readLocal(w, src, e.local_off, buf) orelse {
            e.skip = true;
            continue;
        };
        e.data_off = l.data_off;
        if (l.method != e.method) w.notice(.mismatch, "zip: method differs between local header and directory");
        if (e.data_off > total) e.skip = true;
    }
    markOverlaps(w, entries);
    var name_buf: [max_name]u8 = undefined;
    var position: u32 = 0;
    for (entries) |*e| {
        if (w.halt != null) return error.Halted;
        const name = name_buf[0..@min(e.name_len, max_name)];
        src.readAllAt(w.io, e.cd_off +| 46, name) catch continue;
        if (!isDirectory(name, e.csize)) position +|= 1;
        if (e.skip) {
            if (e.data_off > total or e.data_off == 0) w.notice(.malformed, "zip: entry has no readable local header");
            continue;
        }
        try member(w, src, name, e.data_off, e.csize, e.usize, e.method, e.flags, .{ .crc = e.crc, .position = position });
    }
}

/// Entries whose data range starts inside an earlier entry's range are overlaps: reported once,
/// and skipped (the earlier entry already covers those bytes).
fn markOverlaps(w: *Walker, entries: []Entry) void {
    const order = w.alloc(u32, entries.len) orelse return;
    defer w.free(order);
    for (order, 0..) |*o, i| o.* = @intCast(i);
    // Stable, so entries naming the same local header keep directory order.
    std.sort.block(u32, order, entries, struct {
        fn lt(es: []Entry, a: u32, b: u32) bool {
            return es[a].local_off < es[b].local_off;
        }
    }.lt);
    var reach: u64 = 0;
    var reported = false;
    for (order) |i| {
        const e = &entries[i];
        if (e.skip) continue;
        if (e.local_off < reach) {
            e.skip = true;
            if (!reported) w.notice(.overlap, "zip: entries share data (overlapping files)");
            reported = true;
            continue;
        }
        reach = @max(reach, e.data_off +| e.csize);
    }
}

/// Walk local headers from the start. Entries the directory listed are stepped over; anything
/// else is scanned (and, when a directory exists, reported as a mismatch).
fn walkLocal(w: *Walker, src: Source, listed: []const Entry, total: u64, base: u64, buf: []u8) Error!void {
    var off: u64 = base;
    var name_buf: [max_name]u8 = undefined;
    var unlisted_reported = false;
    var unlisted: usize = 0;
    var steps: usize = 0;
    while (off +| 30 <= total) : (steps += 1) {
        if (w.halt != null) return error.Halted;
        if (steps > @as(usize, w.tracker.limits.max_files) * 2 + 16) return;
        const sig = sigAt(w, src, off);
        if (sig != sig_local) {
            if (sig == sig_central or sig == sig_eocd or sig == sig_eocd64) return;
            // Junk between entries: look for the next local header.
            off = findSig(w, src, off +| 1, total) orelse return;
            continue;
        }
        const l = readLocal(w, src, off, buf) orelse return;
        const listed_entry = for (listed) |*e| {
            if (e.local_off == off) break e;
        } else null;
        var csize = l.csize;
        if (listed_entry) |e| csize = e.csize;
        const known = listed_entry != null or (l.flags & 8 == 0);
        if (!known) {
            // A data descriptor follows and the local header has no sizes: the data runs to the
            // next signature.
            const next = findSig(w, src, l.data_off, total) orelse total;
            csize = next -| l.data_off;
        }
        if (listed_entry == null) {
            if (listed.len > 0 and !unlisted_reported) {
                w.notice(.mismatch, "zip: local entry missing from the central directory");
                unlisted_reported = true;
            }
            const name = name_buf[0..@min(l.name_len, max_name)];
            src.readAllAt(w.io, off +| 30, name) catch return;
            if (!isDirectory(name, l.csize)) unlisted += 1;
            try member(w, src, name, l.data_off, @min(csize, total -| l.data_off), if (known) l.usize else 0, l.method, l.flags, .{ .crc = l.crc, .position = @intCast(@min(listed.len + unlisted, std.math.maxInt(u32))) });
        }
        off = l.data_off +| csize;
        if (l.flags & 8 != 0) off +|= descriptorLen(w, src, off);
    }
}

/// A data descriptor: optional signature, CRC, then 32-bit (or zip64 64-bit) sizes.
fn descriptorLen(w: *Walker, src: Source, off: u64) u64 {
    var b: [24]u8 = undefined;
    src.readAllAt(w.io, off, b[0..16]) catch return 0;
    const has_sig = Le.u32at(&b, 0) == sig_descriptor;
    const base_len: u64 = if (has_sig) 16 else 12;
    // A zip64 descriptor is 8 bytes longer; tell by what follows.
    const after32 = sigAt(w, src, off +| base_len);
    if (after32 == sig_local or after32 == sig_central) return base_len;
    const after64 = sigAt(w, src, off +| (base_len + 8));
    if (after64 == sig_local or after64 == sig_central) return base_len + 8;
    return base_len;
}

/// Offset of the next "PK\x03\x04", "PK\x01\x02", "PK\x05\x06" or "PK\x07\x08" at or after
/// `from`, searched in blocks.
fn findSig(w: *Walker, src: Source, from: u64, total: u64) ?u64 {
    var block: [4096]u8 = undefined;
    var off = from;
    while (off < total) {
        const n = src.readAt(w.io, off, &block) catch return null;
        if (n < 4) return null;
        var i: usize = 0;
        while (std.mem.indexOfPos(u8, block[0..n], i, "PK")) |p| : (i = p + 1) {
            if (p + 4 > n) break;
            const s = Le.u32at(&block, p);
            if (s == sig_local or s == sig_central or s == sig_eocd or s == sig_descriptor) return off + p;
        }
        off += n - 3;
    }
    return null;
}

/// What a member contributes to `.cdb` checks beyond its sizes and flags.
const Meta = struct {
    crc: u32,
    /// 1-based among the files (directories do not count), in central directory order;
    /// local entries the directory does not list follow.
    position: u32,
};

fn isDirectory(name: []const u8, csize: u64) bool {
    return name.len > 0 and name[name.len - 1] == '/' and csize == 0;
}

fn member(w: *Walker, src: Source, name: []const u8, data_off: u64, csize: u64, usize_v: u64, method: u16, flags: u16, meta: Meta) Error!void {
    if (isDirectory(name, csize)) return;
    if (w.options.cdb) |hook| {
        w.path.push(name);
        defer w.path.pop();
        hook.check(w, .{
            .container_type = .zip,
            .container_size = src.len().?,
            .name = name,
            .size_in_container = csize,
            .size_real = usize_v,
            .encrypted = flags & 1 != 0 or method == 99,
            .position = meta.position,
            .crc = meta.crc,
        });
    }
    if (flags & 1 != 0 or method == 99) {
        w.path.push(name);
        defer w.path.pop();
        return w.notice(.encrypted, "zip: encrypted entry");
    }
    const total = src.len().?;
    const avail = @min(csize, total -| data_off);
    if (avail < csize) {
        w.path.push(name);
        w.notice(.malformed, "zip: entry runs past the end of the archive");
        w.path.pop();
    }
    const data = src.slice(data_off, avail) catch return;
    const hint: ?u64 = if (usize_v != 0) usize_v else null;
    // OOXML package parts declare macros, external targets and embedded objects.
    ooxml.inspect(w, name, data, method, usize_v);
    switch (method) {
        0 => try w.child(name, data, .member),
        8 => try decode.child(w, .deflate_raw, data, name, hint),
        12 => try decode.child(w, .bzip2, data, name, hint),
        14 => try decode.child(w, .lzma_zip, data, name, hint),
        93 => try decode.child(w, .zstd, data, name, hint),
        95 => try decode.child(w, .xz, data, name, hint),
        else => {
            w.path.push(name);
            w.notice(.unsupported, switch (method) {
                9 => "zip: deflate64",
                98 => "zip: PPMd",
                else => "zip: compression method",
            });
            w.path.pop();
            // The raw member bytes are still scanned.
            try w.child(name, data, .member);
        },
    }
}

test "a zip quine stops at the recursion limit" {
    try @import("pdf.zig").checkDocs(".zip");
}
