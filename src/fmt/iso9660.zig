//! ISO 9660 images, written from ECMA-119 (4th edition), the Joliet specification (UCS-2 names in a
//! supplementary volume descriptor), SUSP/Rock Ridge (IEEE P1281/P1282, NM names only) and El
//! Torito (the boot catalog's initial entry). Every file extent becomes a positional child, a
//! slice of the image, so nothing is copied.
//!
//! What a hostile image can do and what bounds it:
//! - Directory trees are walked with an explicit stack capped at `max_depth`; a directory whose
//!   extent was already walked (a loop back to an ancestor, or a DAG that lists one directory
//!   many times) is skipped and reported, so the walk is linear in the number of distinct
//!   directories, never exponential.
//! - Directory bytes read per tree are capped at the image size, and distinct directories at
//!   `max_dirs`.
//! - Many records naming one extent (hard links, or an amplification bomb) scan it once.
//! - Both the Joliet and the primary tree are walked, so a file hidden from one view is still
//!   scanned; files the two share are scanned once.
const std = @import("std");
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;

/// Where the volume descriptors start: sector 16 of 2048 bytes (detect.zig probes the magic).
pub const descriptors_off = 16 * 2048;
pub const max_depth = 32;
pub const max_dirs = 16 * 1024;
const max_descriptors = 64;
const max_name = 255 * 3;

const Tree = struct { lba: u32, size: u32, joliet: bool };

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len().?;
    var vd: [2048]u8 = undefined;
    var trees: [2]?Tree = .{ null, null }; // Joliet first: its names are the readable ones.
    var block: u32 = 2048;
    var catalog: ?u32 = null;
    var terminated = false;
    var i: u32 = 0;
    while (i < max_descriptors) : (i += 1) {
        src.readAllAt(w.io, descriptors_off + @as(u64, i) * 2048, &vd) catch break;
        if (!std.mem.eql(u8, vd[1..6], "CD001")) break;
        switch (vd[0]) {
            0 => if (std.mem.startsWith(u8, vd[7..], "EL TORITO SPECIFICATION")) {
                catalog = le32(vd[0x47..]);
            },
            1 => if (trees[1] == null) {
                const bs = le16(vd[128..]);
                if (bs == 512 or bs == 1024 or bs == 2048) block = bs;
                trees[1] = rootOf(vd[156..190], false);
            },
            2 => if (trees[0] == null and isJoliet(vd[88..120])) {
                trees[0] = rootOf(vd[156..190], true);
            },
            255 => {
                terminated = true;
                break;
            },
            else => {},
        }
    }
    if (!terminated) w.notice(.malformed, "iso9660: no volume descriptor set terminator");
    const seen = Seen.init(w, max_dirs + @as(usize, w.tracker.limits.max_files) + 1) orelse return;
    var walker: TreeWalker = .{ .w = w, .src = src, .total = total, .block = block, .seen = seen };
    for (trees) |t| if (t) |tree| try walker.walkTree(tree);
    if (catalog) |c| try bootImages(w, src, total, block, c);
}

fn isJoliet(esc: []const u8) bool {
    // "%/@", "%/C" or "%/E": UCS-2 levels 1 to 3.
    return esc[0] == 0x25 and esc[1] == 0x2f and (esc[2] == 0x40 or esc[2] == 0x43 or esc[2] == 0x45);
}

fn rootOf(rec: []const u8, joliet: bool) ?Tree {
    if (rec[0] < 34) return null;
    return .{ .lba = le32(rec[2..]), .size = le32(rec[10..]), .joliet = joliet };
}

/// An open-addressing set of extent start blocks: directories walked and files scanned, so each
/// is visited once per image. Sized from scratch at the start of the walk.
const Seen = struct {
    slots: []u32,
    used: usize = 0,

    fn init(w: *Walker, want: usize) ?Seen {
        const cap = std.math.ceilPowerOfTwo(usize, @max(want * 2, 64)) catch return null;
        const slots = w.alloc(u32, cap) orelse return null;
        @memset(slots, empty);
        return .{ .slots = slots };
    }

    const empty = std.math.maxInt(u32);

    /// True when `key` was new (and is now recorded). A full set reports everything as seen.
    fn add(s: *Seen, key: u32, tag: u32) bool {
        if (s.used * 2 >= s.slots.len) return false;
        // Directories and files share the table, kept apart by the top bit.
        const k = (key & 0x7fffffff) | (tag << 31);
        if (k == empty) return false;
        var h = (k *% 0x9E3779B1) & @as(u32, @intCast(s.slots.len - 1));
        while (true) {
            if (s.slots[h] == k) return false;
            if (s.slots[h] == empty) {
                s.slots[h] = k;
                s.used += 1;
                return true;
            }
            h = (h + 1) & @as(u32, @intCast(s.slots.len - 1));
        }
    }
};

const Frame = struct {
    lba: u32,
    size: u32,
    pos: u32 = 0,
    /// Length of the path prefix (this directory's name) in `TreeWalker.path`.
    path_len: u16,
};

const TreeWalker = struct {
    w: *Walker,
    src: Source,
    total: u64,
    block: u32,
    seen: Seen,
    path: [container.max_path_len]u8 = undefined,
    stack: [max_depth]Frame = undefined,
    sector: [2048]u8 = undefined,
    sector_at: ?u64 = null,
    reported_depth: bool = false,
    reported_dag: bool = false,
    position: u32 = 0,

    fn walkTree(t: *TreeWalker, tree: Tree) Error!void {
        const w = t.w;
        if (!t.seen.add(tree.lba, 0)) return; // the other tree shares this root
        var depth: usize = 1;
        t.stack[0] = .{ .lba = tree.lba, .size = tree.size, .path_len = 0 };
        // Directory bytes read in this tree: at most the image size.
        var budget: u64 = t.total;
        var name_buf: [max_name]u8 = undefined;
        while (depth > 0) {
            if (w.halt != null) return error.Halted;
            const f = &t.stack[depth - 1];
            if (f.pos >= f.size) {
                depth -= 1;
                continue;
            }
            const sec_in_dir = f.pos / t.block;
            const in_sec = f.pos % t.block;
            const sec_off = (@as(u64, f.lba) + sec_in_dir) * t.block;
            if (t.sector_at != sec_off) {
                if (budget < t.block) {
                    w.notice(.malformed, "iso9660: directories larger than the image");
                    return;
                }
                budget -= t.block;
                t.src.readAllAt(w.io, sec_off, t.sector[0..t.block]) catch {
                    w.notice(.malformed, "iso9660: directory beyond the end of the image");
                    f.pos = f.size;
                    continue;
                };
                t.sector_at = sec_off;
            }
            const rest = t.sector[in_sec..t.block];
            const len = rest[0];
            // A zero length pads to the next sector; a record never crosses one.
            if (len == 0 or len < 34 or len > rest.len or 33 + @as(usize, rest[32]) > len) {
                if (len != 0) w.notice(.malformed, "iso9660: bad directory record");
                f.pos = (sec_in_dir + 1) *| t.block;
                continue;
            }
            f.pos += len;
            const rec = rest[0..len];
            const id = rec[33..][0..rec[32]];
            if (id.len == 1 and (id[0] == 0 or id[0] == 1)) continue; // "." and ".."
            const flags = rec[25];
            const lba = le32(rec[2..]);
            const size = le32(rec[10..]);
            const name = recordName(rec, id, tree.joliet, &name_buf);
            const parent_len = f.path_len;
            if (flags & 2 != 0) {
                if (depth >= max_depth) {
                    if (!t.reported_depth) w.notice(.malformed, "iso9660: directory tree deeper than 32 levels");
                    t.reported_depth = true;
                    continue;
                }
                if (!t.seen.add(lba, 0)) {
                    if (onStack(t.stack[0..depth], lba)) {
                        w.notice(.malformed, "iso9660: directory loop");
                    } else if (!t.reported_dag) {
                        w.notice(.overlap, "iso9660: a directory listed more than once");
                        t.reported_dag = true;
                    }
                    continue;
                }
                t.stack[depth] = .{ .lba = lba, .size = size, .path_len = t.join(parent_len, name) };
                depth += 1;
                continue;
            }
            if (flags & 4 != 0) continue; // associated file (a resource fork)
            if (size == 0 or !t.seen.add(lba, 1)) continue;
            const full_len = t.join(parent_len, name);
            try t.file(t.path[0..full_len], lba, size, flags & 0x80 != 0);
        }
    }

    /// Append `name` to the path prefix of length `base`; the new length.
    fn join(t: *TreeWalker, base: u16, name: []const u8) u16 {
        var n: usize = base;
        if (n != 0 and n < t.path.len) {
            t.path[n] = '/';
            n += 1;
        }
        const take = @min(name.len, t.path.len - n);
        @memcpy(t.path[n..][0..take], name[0..take]);
        return @intCast(n + take);
    }

    fn file(t: *TreeWalker, name: []const u8, lba: u32, size: u32, multi_extent: bool) Error!void {
        const w = t.w;
        _ = multi_extent; // each extent of a multi-extent file is its own slice, under the same name
        const off = @as(u64, lba) * t.block;
        t.position +|= 1;
        if (w.options.cdb) |hook| {
            w.path.push(name);
            defer w.path.pop();
            hook.check(w, .{
                .container_type = .iso9660,
                .container_size = t.total,
                .name = name,
                .size_in_container = size,
                .size_real = size,
                .encrypted = false,
                .position = t.position,
            });
        }
        if (off >= t.total) {
            w.path.push(name);
            defer w.path.pop();
            return w.notice(.malformed, "iso9660: file extent beyond the end of the image");
        }
        const avail = @min(size, t.total - off);
        if (avail < size) {
            w.path.push(name);
            w.notice(.malformed, "iso9660: file runs past the end of the image");
            w.path.pop();
        }
        try w.child(name, t.src.slice(off, avail) catch unreachable, .member);
    }
};

fn onStack(stack: []const Frame, lba: u32) bool {
    for (stack) |f| if (f.lba == lba) return true;
    return false;
}

/// A record's name: Rock Ridge NM when present (primary tree), else the identifier with its
/// ";version" and a bare trailing dot removed. Joliet identifiers are UCS-2 big-endian, written
/// out as UTF-8.
fn recordName(rec: []const u8, id: []const u8, joliet: bool, out: []u8) []const u8 {
    if (joliet) {
        var n: usize = 0;
        var i: usize = 0;
        while (i + 1 < id.len) : (i += 2) {
            const c: u21 = std.mem.readInt(u16, id[i..][0..2], .big);
            if (c == ';') break;
            const cp: u21 = if (c >= 0xd800 and c <= 0xdfff) '?' else c;
            if (n + 3 > out.len) break;
            n += std.unicode.utf8Encode(cp, out[n..]) catch break;
        }
        return out[0..n];
    }
    if (rockRidgeName(rec, id.len, out)) |nm| return nm;
    var name = id;
    if (std.mem.lastIndexOfScalar(u8, name, ';')) |semi| name = name[0..semi];
    if (name.len > 1 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    return name;
}

/// The NM entries in a record's system use area (continuation areas are not followed).
fn rockRidgeName(rec: []const u8, id_len: usize, out: []u8) ?[]const u8 {
    var p: usize = 33 + id_len + @intFromBool(id_len % 2 == 0);
    var n: usize = 0;
    var found = false;
    while (p + 4 <= rec.len) {
        const len = rec[p + 2];
        if (len < 4 or p + len > rec.len) break;
        if (rec[p] == 'N' and rec[p + 1] == 'M' and len >= 5) {
            const flags = rec[p + 4];
            // Flags 2 and 4 are "." and ".."; the rest of the name follows.
            if (flags & 6 == 0) {
                const part = rec[p + 5 .. p + len];
                const take = @min(part.len, out.len - n);
                @memcpy(out[n..][0..take], part[0..take]);
                n += take;
                found = true;
            }
            if (flags & 1 == 0 and found) break; // no continuation
        }
        if (rec[p] == 'S' and rec[p + 1] == 'T') break;
        p += len;
    }
    return if (found and n > 0) out[0..n] else null;
}

/// El Torito: the boot catalog's initial entry (and section entries) name boot images. Images
/// are children named "boot/<n>".
fn bootImages(w: *Walker, src: Source, total: u64, block: u32, catalog: u32) Error!void {
    var cat: [2048]u8 = undefined;
    src.readAllAt(w.io, @as(u64, catalog) * block, cat[0..block]) catch return w.notice(.malformed, "iso9660: boot catalog beyond the end of the image");
    if (cat[0] != 1 or cat[30] != 0x55 or cat[31] != 0xaa) return w.notice(.malformed, "iso9660: bad boot catalog validation entry");
    var sum: u16 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 2) sum +%= le16(cat[i..]);
    if (sum != 0) w.notice(.malformed, "iso9660: boot catalog checksum");
    var n: u32 = 0;
    var e: usize = 32;
    var name_buf: [16]u8 = undefined;
    while (e + 32 <= block and n < 64) : (e += 32) {
        const entry = cat[e..][0..32];
        // 0x88 bootable, 0x00 not bootable (still an image); 0x90/0x91 are section headers.
        if (entry[0] == 0x90 or entry[0] == 0x91) continue;
        if (entry[0] != 0x88 and entry[0] != 0x00) break;
        const lba = le32(entry[8..]);
        if (lba == 0) continue;
        const size: u64 = switch (entry[1] & 0x0f) {
            1 => 1200 * 1024,
            2 => 1440 * 1024,
            3 => 2880 * 1024,
            // No emulation and hard-disk emulation: the sector count, in 512-byte units.
            else => @as(u64, @max(le16(entry[6..]), 1)) * 512,
        };
        const off = @as(u64, lba) * block;
        if (off >= total) continue;
        const name = std.fmt.bufPrint(&name_buf, "boot/{d}", .{n}) catch unreachable;
        n += 1;
        try w.child(name, src.slice(off, @min(size, total - off)) catch unreachable, .member);
    }
}

fn le16(b: []const u8) u16 {
    return std.mem.readInt(u16, b[0..2], .little);
}

fn le32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .little);
}

test "joliet names, version suffixes and rock ridge names" {
    var out: [64]u8 = undefined;
    const j = [_]u8{ 0, 'a', 0, '.', 0, 't', 0, ';', 0, '1' };
    var rec: [64]u8 = @splat(0);
    try std.testing.expectEqualStrings("a.t", recordName(&rec, &j, true, &out));
    try std.testing.expectEqualStrings("README.TXT", recordName(&rec, "README.TXT;1", false, &out));
    try std.testing.expectEqualStrings("FILE", recordName(&rec, "FILE.;1", false, &out));
    // A record with an NM entry after a 3-byte identifier (no pad byte).
    rec[32] = 3;
    @memcpy(rec[33..36], "A.;");
    @memcpy(rec[36..47], &[_]u8{ 'N', 'M', 11, 1, 0, 'l', 'o', 'n', 'g', '.', 'x' });
    try std.testing.expectEqualStrings("long.x", recordName(rec[0..47], rec[33..36], false, &out));
}

const fixtures = @import("fixtures/fixtures.zig");
const TestRig = @import("scan.zig").TestRig;

fn fixture(name: []const u8) []const u8 {
    for (fixtures.archives) |a| if (std.mem.eql(u8, a.name, name)) return a.bytes;
    unreachable;
}

test "hostile trees: loops, duplicate records and directory DAGs are walked once" {
    var rig: TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(fixture("loop.iso"), "loop.iso");
    try std.testing.expect(rig.rec.has(.malformed));
    // 50 records name readme.txt's extent: scanned once per pass.
    var members: usize = 0;
    for (rig.rec.objects.items) |e| if (e.depth == 1) {
        members += 1;
    };
    try std.testing.expectEqual(@as(usize, 6), members);

    var rig2: TestRig = undefined;
    try rig2.init(.{});
    defer rig2.deinit();
    try rig2.scanBoth(fixture("dag-bomb.iso"), "dag-bomb.iso");
    try std.testing.expect(rig2.rec.has(.overlap));
    try std.testing.expect(rig2.rec.find("dag-bomb.iso/x.txt") != null);
}

test "joliet image: names from the joliet tree, the boot image, and the primary-only names" {
    var rig: TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(fixture("joliet.iso"), "joliet.iso");
    try std.testing.expectEqual(container.Format.iso9660, rig.rec.objects.items[0].format);
    try std.testing.expect(rig.rec.find("joliet.iso/tools/eicar.com") != null);
    try std.testing.expect(rig.rec.find("joliet.iso/boot/0") != null);
    try std.testing.expect(rig.rec.find("joliet.iso/TOOLS/EICAR.COM") == null);
    try std.testing.expectEqual(@as(usize, 0), rig.rec.notices.items.len);
}
