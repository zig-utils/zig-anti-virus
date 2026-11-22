//! Container sub-types clamscan 1.5.4 reports in its `--gen-json` metadata, measured black-box
//! (docs/clean-room.md, "File typing"):
//!
//! - OLE2 compound files (MS-CFB) become MSWORD, MSXL or MSPPT from their directory: the stream
//!   entries named `WordDocument`, `Workbook` or `PowerPoint Document` (ASCII case ignored), and
//!   the last such stream in a walk of the directory tree that visits an entry, then its child
//!   subtree, then its right sibling, then its left sibling.
//! - ZIP archives become OOXML_WORD, OOXML_XL, OOXML_PPT or OOXML_HWP from the names of their
//!   first three local file headers not under `docProps/` (`word/`, `xl/`, `ppt/` prefixes,
//!   `Contents/content.hpf`), the first that names one winning, for headers that start at most
//!   30221 bytes in. Once `[Content_Types].xml` is among those, an archive with an end of
//!   central directory record is looked through without the three-member limit.
//! - Binary data whose first 512 bytes are a tar header with a valid unsigned checksum is
//!   OLD_TAR.
const std = @import("std");
const types = @import("types.zig");

/// A tar header with a valid checksum (unsigned byte sum, checksum field read as spaces).
pub fn isOldTar(data: []const u8) bool {
    if (data.len < 512) return false;
    const h = data[0..512];
    var sum: u32 = 0;
    for (h, 0..) |b, i| sum += if (i >= 148 and i < 156) ' ' else b;
    var i: usize = 148;
    while (i < 156 and h[i] == ' ') i += 1;
    var value: u32 = 0;
    var digits: usize = 0;
    while (i < 156 and h[i] >= '0' and h[i] <= '7') : (i += 1) {
        value = value * 8 + (h[i] - '0');
        digits += 1;
    }
    return digits > 0 and value == sum;
}

/// The OOXML flavour of a ZIP archive, from its leading local file headers. Each header is
/// found by searching for its signature after the previous header's name and extra field
/// (data descriptors and junk between members do not matter, a signature inside member data
/// counts); `docProps/` members are not counted against the three looked at.
pub fn zipType(data: []const u8) ?types.ClType {
    var pos: usize = 0;
    var counted: usize = 0;
    // Once `[Content_Types].xml` is among the members looked at, an archive with an end of
    // central directory record is looked through without the three-member limit.
    var unlimited = false;
    const eocd = hasEocd(data);
    while (unlimited or counted < 3) {
        const i = std.mem.indexOfPos(u8, data, pos, "PK\x03\x04") orelse return null;
        if (i > 30221 or data.len < i + 30) return null;
        const h = data[i..][0..30];
        const name_len = std.mem.readInt(u16, h[26..28], .little);
        const extra_len = std.mem.readInt(u16, h[28..30], .little);
        const name = data[i + 30 ..][0..@min(name_len, data.len - i - 30)];
        if (std.mem.startsWith(u8, name, "word/")) return .ooxml_word;
        if (std.mem.startsWith(u8, name, "xl/")) return .ooxml_xl;
        if (std.mem.startsWith(u8, name, "ppt/")) return .ooxml_ppt;
        if (std.mem.eql(u8, name, "Contents/content.hpf")) return .ooxml_hwp;
        if (eocd and std.mem.eql(u8, name, "[Content_Types].xml")) unlimited = true;
        if (!std.mem.startsWith(u8, name, "docProps/")) counted += 1;
        pos = i + 30 + name_len + extra_len;
    }
    return null;
}

fn hasEocd(data: []const u8) bool {
    const tail = data[data.len - @min(data.len, 65557) ..];
    return std.mem.lastIndexOf(u8, tail, "PK\x05\x06") != null;
}

const free_sect: u32 = 0xffff_ffff;
const end_of_chain: u32 = 0xffff_fffe;
const max_dir_entries = 65536;

/// The Office flavour of an OLE2 compound file, from its directory.
pub fn ole2Type(data: []const u8) ?types.ClType {
    if (data.len < 512) return null;
    const shift = std.mem.readInt(u16, data[0x1e..0x20], .little);
    if (shift < 7 or shift > 16) return null;
    const sec: usize = @as(usize, 1) << @intCast(shift);
    const dir_start = std.mem.readInt(u32, data[0x30..0x34], .little);
    const reader: Reader = .{ .data = data, .sec = sec };
    // Read the directory chain into entry slots, bounded.
    var walker: TreeWalk = .{ .r = reader, .dir_start = dir_start };
    return walker.run();
}

const Reader = struct {
    data: []const u8,
    sec: usize,

    fn sector(r: Reader, s: u32) ?[]const u8 {
        const off = (@as(u64, s) + 1) * r.sec;
        if (off + r.sec > r.data.len) return null;
        return r.data[@intCast(off)..][0..r.sec];
    }

    /// FAT entry `s`, through the header DIFAT and the DIFAT chain.
    fn fat(r: Reader, s: u32) ?u32 {
        const per = r.sec / 4;
        const fat_index = s / per;
        const fat_sec = r.fatSector(fat_index) orelse return null;
        const bytes = r.sector(fat_sec) orelse return null;
        const i = (s % per) * 4;
        return std.mem.readInt(u32, bytes[i..][0..4], .little);
    }

    fn fatSector(r: Reader, index: usize) ?u32 {
        if (index < 109) {
            const v = std.mem.readInt(u32, r.data[0x4c + index * 4 ..][0..4], .little);
            return if (v == free_sect or v == end_of_chain) null else v;
        }
        var rest = index - 109;
        var difat = std.mem.readInt(u32, r.data[0x44..0x48], .little);
        const per = r.sec / 4 - 1;
        var hops: usize = 0;
        while (hops < 4096) : (hops += 1) {
            const bytes = r.sector(difat) orelse return null;
            if (rest < per) return std.mem.readInt(u32, bytes[rest * 4 ..][0..4], .little);
            rest -= per;
            difat = std.mem.readInt(u32, bytes[per * 4 ..][0..4], .little);
        }
        return null;
    }
};

const TreeWalk = struct {
    r: Reader,
    dir_start: u32,
    found: ?types.ClType = null,
    visited: std.StaticBitSet(max_dir_entries) = .empty,

    fn entry(t: *TreeWalk, id: u32) ?[]const u8 {
        const per = t.r.sec / 128;
        var s = t.dir_start;
        var hops = id / per;
        while (hops > 0) : (hops -= 1) {
            s = t.r.fat(s) orelse return null;
            if (s == end_of_chain or s == free_sect) return null;
        }
        const bytes = t.r.sector(s) orelse return null;
        return bytes[(id % per) * 128 ..][0..128];
    }

    fn run(t: *TreeWalk) ?types.ClType {
        const root = t.entry(0) orelse return null;
        const child = std.mem.readInt(u32, root[0x4c..0x50], .little);
        // An explicit stack: entries are pushed in reverse visiting order.
        var stack: [256]u32 = undefined;
        var top: usize = 0;
        stack[0] = child;
        top = 1;
        var steps: usize = 0;
        while (top > 0 and steps < max_dir_entries) : (steps += 1) {
            top -= 1;
            const id = stack[top];
            if (id >= max_dir_entries or t.visited.isSet(id)) continue;
            t.visited.set(id);
            const e = t.entry(id) orelse continue;
            t.visit(e);
            const left = std.mem.readInt(u32, e[0x44..0x48], .little);
            const right = std.mem.readInt(u32, e[0x48..0x4c], .little);
            const sub = std.mem.readInt(u32, e[0x4c..0x50], .little);
            // Visit order: child subtree, right sibling, left sibling.
            for ([_]u32{ left, right, sub }) |next| {
                if (next == free_sect or top == stack.len) continue;
                stack[top] = next;
                top += 1;
            }
        }
        return t.found;
    }

    fn visit(t: *TreeWalk, e: []const u8) void {
        if (e[0x42] != 2) return;
        const name_bytes = std.mem.readInt(u16, e[0x40..0x42], .little);
        if (name_bytes < 2 or name_bytes > 64) return;
        var name: [32]u8 = undefined;
        const units = name_bytes / 2 - 1;
        for (0..units) |i| {
            const u = std.mem.readInt(u16, e[i * 2 ..][0..2], .little);
            name[i] = if (u < 0x80) std.ascii.toLower(@intCast(u)) else 0xff;
        }
        const n = name[0..units];
        if (std.mem.eql(u8, n, "worddocument")) t.found = .msword;
        if (std.mem.eql(u8, n, "workbook")) t.found = .msxl;
        if (std.mem.eql(u8, n, "powerpoint document")) t.found = .msppt;
    }
};

const testing = std.testing;

test "old tar headers need a valid checksum" {
    var h: [1024]u8 = @splat(0);
    @memcpy(h[0..5], "hello");
    @memset(h[148..156], ' ');
    var sum: u32 = 0;
    for (h[0..512]) |b| sum += b;
    _ = try std.fmt.bufPrint(h[148..156], "{o:0>6}\x00 ", .{sum});
    try testing.expect(isOldTar(&h));
    h[0] = 'j';
    try testing.expect(!isOldTar(&h));
}

test "zip flavours come from the first local headers" {
    const lh = "PK\x03\x04" ++ "\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ "\x01\x00\x00\x00\x01\x00\x00\x00" ++ "\x0f\x00\x00\x00" ++ "xl/workbook.xml" ++ "x";
    try testing.expectEqual(types.ClType.ooxml_xl, zipType(lh).?);
    try testing.expect(zipType("PK\x03\x04") == null);
}
