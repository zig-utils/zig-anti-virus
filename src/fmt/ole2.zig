//! OLE2 compound files, written from [MS-CFB]: the header, the FAT (located through the header's
//! DIFAT array and the DIFAT chain), the mini FAT and mini stream, and the directory's red-black
//! trees. Every stream becomes a child, read by following its sector chain, so nothing is copied
//! whole. VBA projects (a "VBA" storage with a "dir" stream) also yield each module's source,
//! decompressed with MS-OVBA (vba.zig), as a derived child.
//!
//! Chains are untrusted: every walk is bounded by the number of sectors the file can hold, so a
//! loop ends; directory traversal is bounded by entry count and depth and marks visited entries.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const vba = @import("vba.zig");
const Walker = container.Walker;
const Error = container.Error;

pub const magic = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
const end_of_chain: u32 = 0xfffffffe;
const free_sect: u32 = 0xffffffff;
const no_stream: u32 = 0xffffffff;

pub const max_entries = 65536;
const max_depth = 32;
const max_modules = 256;

pub const Header = struct {
    sector_shift: u5,
    mini_shift: u5,
    dir_start: u32,
    mini_cutoff: u32,
    minifat_start: u32,
    difat_start: u32,
    num_difat: u32,
    difat: [109]u32,

    fn sectorSize(h: Header) u64 {
        return @as(u64, 1) << h.sector_shift;
    }
};

pub fn parseHeader(b: *const [512]u8) error{BadHeader}!Header {
    if (!std.mem.eql(u8, b[0..8], magic)) return error.BadHeader;
    const shift = std.mem.readInt(u16, b[30..32], .little);
    const mini = std.mem.readInt(u16, b[32..34], .little);
    if (shift != 9 and shift != 12) return error.BadHeader;
    if (mini >= shift or mini == 0) return error.BadHeader;
    var h: Header = .{
        .sector_shift = @intCast(shift),
        .mini_shift = @intCast(mini),
        .dir_start = std.mem.readInt(u32, b[48..52], .little),
        .mini_cutoff = std.mem.readInt(u32, b[56..60], .little),
        .minifat_start = std.mem.readInt(u32, b[60..64], .little),
        .difat_start = std.mem.readInt(u32, b[68..72], .little),
        .num_difat = std.mem.readInt(u32, b[72..76], .little),
        .difat = undefined,
    };
    for (&h.difat, 0..) |*d, i| d.* = std.mem.readInt(u32, b[76 + i * 4 ..][0..4], .little);
    return h;
}

/// Sector-chain navigation with a one-sector cache for FAT and DIFAT reads.
pub const File = struct {
    io: Io,
    src: Source,
    h: Header,
    sectors: u64,
    fat_cache: []u8,
    fat_cache_id: u32 = free_sect,
    difat_cache: []u8,
    difat_cache_id: u32 = free_sect,
    root_start: u32 = end_of_chain,
    root_size: u64 = 0,

    fn sectorOffset(f: *const File, s: u32) u64 {
        return (@as(u64, s) + 1) << f.h.sector_shift;
    }

    /// The sector number of the i-th FAT sector.
    fn fatSector(f: *File, i: u64) ?u32 {
        if (i < 109) return f.h.difat[@intCast(i)];
        const per = f.h.sectorSize() / 4 - 1;
        var k = (i - 109) / per;
        var s = f.h.difat_start;
        var steps: u64 = 0;
        while (k > 0) : (k -= 1) {
            s = f.difatEntry(s, per) orelse return null; // the chain pointer is the last entry
            steps += 1;
            if (steps > f.sectors) return null;
        }
        return f.difatEntry(s, (i - 109) % per);
    }

    fn difatEntry(f: *File, s: u32, idx: u64) ?u32 {
        if (s >= f.sectors) return null;
        if (f.difat_cache_id != s) {
            f.src.readAllAt(f.io, f.sectorOffset(s), f.difat_cache) catch return null;
            f.difat_cache_id = s;
        }
        return std.mem.readInt(u32, f.difat_cache[@intCast(idx * 4)..][0..4], .little);
    }

    /// The next sector in a FAT chain.
    pub fn next(f: *File, s: u32) ?u32 {
        const per = f.h.sectorSize() / 4;
        const fs = f.fatSector(s / per) orelse return null;
        if (fs >= f.sectors) return null;
        if (f.fat_cache_id != fs) {
            f.src.readAllAt(f.io, f.sectorOffset(fs), f.fat_cache) catch return null;
            f.fat_cache_id = fs;
        }
        return std.mem.readInt(u32, f.fat_cache[@intCast((s % per) * 4)..][0..4], .little);
    }
};

/// Reads a stream by following its chain: through the FAT for regular streams, or through the
/// mini FAT inside the root's mini stream for streams under the cutoff.
pub const ChainReader = struct {
    f: *File,
    mini: bool,
    sector: u32,
    left: u64,
    steps: u64 = 0,
    /// For mini streams: the mini-stream reader state (mini stream is itself a FAT chain).
    err: bool = false,
    interface: Io.Reader,

    pub fn init(f: *File, start: u32, size: u64, mini: bool, buffer: []u8) ChainReader {
        return .{ .f = f, .mini = mini, .sector = start, .left = size, .interface = .{ .vtable = container.fillVTable(ChainReader), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(c: *ChainReader, dest: []u8) Io.Reader.Error!usize {
        if (c.left == 0) return 0;
        // A valid chain visits each sector once: more steps than sectors is a loop.
        const bound = if (c.mini) c.f.root_size >> c.f.h.mini_shift else c.f.sectors;
        if (c.sector == end_of_chain or c.steps > bound) {
            c.err = true; // chain shorter than the declared size, or a loop
            return 0;
        }
        const f = c.f;
        if (!c.mini) {
            if (c.sector >= f.sectors) {
                c.err = true;
                return 0;
            }
            const n: usize = @intCast(@min(dest.len, f.h.sectorSize(), c.left));
            f.src.readAllAt(f.io, f.sectorOffset(c.sector), dest[0..n]) catch {
                c.err = true;
                return 0;
            };
            c.left -= n;
            c.sector = f.next(c.sector) orelse end_of_chain;
            c.steps += 1;
            return n;
        }
        // Mini sector: find its offset in the mini stream, then that position in the FAT chain.
        const mss: u64 = @as(u64, 1) << f.h.mini_shift;
        const pos = @as(u64, c.sector) * mss;
        if (pos >= f.root_size) {
            c.err = true;
            return 0;
        }
        const off = miniStreamOffset(f, pos) orelse {
            c.err = true;
            return 0;
        };
        const n: usize = @intCast(@min(dest.len, mss, c.left));
        f.src.readAllAt(f.io, off, dest[0..n]) catch {
            c.err = true;
            return 0;
        };
        c.left -= n;
        c.sector = miniNext(f, c.sector) orelse end_of_chain;
        c.steps += 1;
        return n;
    }
};

/// File offset of byte `pos` of the mini stream (walks the root chain; mini streams are small).
fn miniStreamOffset(f: *File, pos: u64) ?u64 {
    const ss = f.h.sectorSize();
    var s = f.root_start;
    var k = pos / ss;
    var steps: u64 = 0;
    while (k > 0) : (k -= 1) {
        s = f.next(s) orelse return null;
        steps += 1;
        if (steps > f.sectors or s >= f.sectors) return null;
    }
    if (s >= f.sectors) return null;
    return f.sectorOffset(s) + pos % ss;
}

/// The next mini sector, from the mini FAT (itself a FAT chain of regular sectors).
fn miniNext(f: *File, ms: u32) ?u32 {
    const per = f.h.sectorSize() / 4;
    var s = f.h.minifat_start;
    var k = ms / per;
    var steps: u64 = 0;
    while (k > 0) : (k -= 1) {
        s = f.next(s) orelse return null;
        steps += 1;
        if (steps > f.sectors or s >= f.sectors) return null;
    }
    if (s >= f.sectors) return null;
    var b: [4]u8 = undefined;
    f.src.readAllAt(f.io, f.sectorOffset(s) + (ms % per) * 4, &b) catch return null;
    return std.mem.readInt(u32, &b, .little);
}

const Entry = struct {
    name: [64]u8,
    name_len: usize,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
};

fn readEntry(f: *File, id: u32, dir_cache: *DirCursor) ?Entry {
    var b: [128]u8 = undefined;
    dir_cache.read(f, id, &b) orelse return null;
    var e: Entry = .{
        .name = undefined,
        .name_len = 0,
        .kind = b[66],
        .left = std.mem.readInt(u32, b[68..72], .little),
        .right = std.mem.readInt(u32, b[72..76], .little),
        .child = std.mem.readInt(u32, b[76..80], .little),
        .start = std.mem.readInt(u32, b[116..120], .little),
        .size = std.mem.readInt(u64, b[120..128], .little),
    };
    if (f.h.sector_shift == 9) e.size &= 0xffffffff; // version 3: high half is undefined
    // UTF-16LE name (length in bytes including the terminator) to UTF-8.
    const nbytes = @min(std.mem.readInt(u16, b[64..66], .little), 64);
    var i: usize = 0;
    while (i + 1 < nbytes) : (i += 2) {
        const cu = std.mem.readInt(u16, b[i..][0..2], .little);
        if (cu == 0) break;
        var tmp: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(if (cu >= 0xd800 and cu <= 0xdfff) 0xfffd else cu, &tmp) catch 1;
        if (e.name_len + n > e.name.len) break;
        @memcpy(e.name[e.name_len..][0..n], tmp[0..n]);
        e.name_len += n;
    }
    return e;
}

/// Directory entries live in a FAT chain; reaching entry `id` walks it from the start, so the
/// cursor remembers the last sector it reached.
const DirCursor = struct {
    index: u64 = 0,
    sector: u32,

    fn read(c: *DirCursor, f: *File, id: u32, out: *[128]u8) ?void {
        const per = f.h.sectorSize() / 128;
        const want = id / per;
        if (want < c.index) {
            c.index = 0;
            c.sector = f.h.dir_start;
        }
        var steps: u64 = 0;
        while (c.index < want) {
            c.sector = f.next(c.sector) orelse return null;
            c.index += 1;
            steps += 1;
            if (steps > f.sectors or c.sector >= f.sectors) return null;
        }
        if (c.sector >= f.sectors) return null;
        f.src.readAllAt(f.io, f.sectorOffset(c.sector) + (id % per) * 128, out) catch return null;
    }
};

/// Walk a compound file held in a positional source.
pub fn walk(w: *Walker, src: Source) Error!void {
    var hb: [512]u8 = undefined;
    src.readAllAt(w.io, 0, &hb) catch return w.notice(.malformed, "ole2: truncated header");
    const h = parseHeader(&hb) catch return w.notice(.malformed, "ole2: header");
    const total = src.len().?;
    const ss = h.sectorSize();
    const fat_cache = w.alloc(u8, @intCast(ss)) orelse return;
    const difat_cache = w.alloc(u8, @intCast(ss)) orelse return;
    var f: File = .{ .io = w.io, .src = src, .h = h, .sectors = (total / ss) -| 1, .fat_cache = fat_cache, .difat_cache = difat_cache };
    var dir: DirCursor = .{ .sector = h.dir_start };
    const root = readEntry(&f, 0, &dir) orelse return w.notice(.malformed, "ole2: no root entry");
    if (root.kind != 5) w.notice(.malformed, "ole2: first entry is not the root");
    f.root_start = root.start;
    f.root_size = root.size;

    const visited = w.alloc(u64, max_entries / 64) orelse return;
    @memset(visited, 0);
    const buf = w.alloc(u8, container.block_len) orelse return;
    var ctx: Ctx = .{ .w = w, .f = &f, .dir = &dir, .visited = visited, .buf = buf };
    _ = ctx.mark(0);
    try ctx.storage(root.child, 0, 0, false);
    if (ctx.damaged) w.notice(.malformed, "ole2: broken chain or directory");
}

const Ctx = struct {
    w: *Walker,
    f: *File,
    dir: *DirCursor,
    visited: []u64,
    buf: []u8,
    entries: usize = 0,
    damaged: bool = false,

    /// Visit a storage's children (a red-black tree rooted at `id`), iteratively in-order
    /// with an explicit bounded stack.
    fn storage(c: *Ctx, id: u32, storage_id: u32, depth: u8, is_vba: bool) Error!void {
        if (depth >= max_depth) return;
        var stack: [64]u32 = undefined;
        var sp: usize = 0;
        var cur = id;
        // The "dir" stream of a VBA storage is read after its siblings are known.
        var vba_dir: ?Entry = null;
        while (cur != no_stream or sp > 0) {
            while (cur != no_stream) {
                if (!c.mark(cur)) {
                    cur = no_stream;
                    break;
                }
                if (sp == stack.len) {
                    c.damaged = true;
                    return;
                }
                stack[sp] = cur;
                sp += 1;
                const e = readEntry(c.f, cur, c.dir) orelse {
                    c.damaged = true;
                    cur = no_stream;
                    sp -= 1;
                    break;
                };
                cur = e.left;
            }
            if (sp == 0) break;
            sp -= 1;
            const eid = stack[sp];
            const e = readEntry(c.f, eid, c.dir) orelse {
                c.damaged = true;
                break;
            };
            try c.entry(eid, e, depth, is_vba, &vba_dir);
            cur = e.right;
        }
        if (vba_dir) |d| try c.vbaProject(d, storage_id);
    }

    fn mark(c: *Ctx, id: u32) bool {
        if (id >= max_entries) {
            c.damaged = true;
            return false;
        }
        const bit = @as(u64, 1) << @intCast(id % 64);
        if (c.visited[id / 64] & bit != 0) {
            c.damaged = true; // a cycle in the tree
            return false;
        }
        c.visited[id / 64] |= bit;
        c.entries += 1;
        return true;
    }

    fn entry(c: *Ctx, eid: u32, e: Entry, depth: u8, is_vba: bool, vba_dir: *?Entry) Error!void {
        const name = e.name[0..e.name_len];
        switch (e.kind) {
            1 => {
                c.w.path.push(name);
                defer c.w.path.pop();
                try c.storage(e.child, eid, depth + 1, std.ascii.eqlIgnoreCase(name, "VBA"));
            },
            2 => {
                if (is_vba and std.ascii.eqlIgnoreCase(name, "dir")) vba_dir.* = e;
                try c.stream(e, name);
            },
            else => {},
        }
    }

    fn stream(c: *Ctx, e: Entry, name: []const u8) Error!void {
        if (e.size == 0) return;
        const mini = e.size < c.f.h.mini_cutoff;
        var reader: ChainReader = .init(c.f, e.start, e.size, mini, c.buf);
        try c.w.child(name, .{ .stream = .{ .reader = &reader.interface, .len_hint = e.size } }, .member);
        // Whatever the child left unread (a limit, a skip) does not matter: the reader is ours.
        if (reader.err) c.damaged = true;
    }

    /// A VBA project: decompress the dir stream, then each module's source from its stream.
    fn vbaProject(c: *Ctx, dir_entry: Entry, storage_id: u32) Error!void {
        const w = c.w;
        // The dir stream decompresses to a few KiB; cap it.
        const dir_out = w.alloc(u8, 1024 * 1024) orelse return;
        defer w.free(dir_out);
        const rbuf = w.alloc(u8, 4096) orelse return;
        defer w.free(rbuf);
        var r: ChainReader = .init(c.f, dir_entry.start, dir_entry.size, dir_entry.size < c.f.h.mini_cutoff, rbuf);
        var d = vba.Decompressor.init(&r.interface);
        var n: usize = 0;
        while (n < dir_out.len) {
            const got = d.fill(dir_out[n..]) catch break;
            if (got == 0) break;
            n += got;
        }
        if (d.err != null) w.notice(.malformed, "vba: dir stream");
        var mods: [max_modules]vba.Module = undefined;
        const modules = vba.parseDir(dir_out[0..n], &mods);
        for (modules) |m| try c.module(m, storage_id);
    }

    fn module(c: *Ctx, m: vba.Module, storage_id: u32) Error!void {
        const e = c.findChild(storage_id, m.stream_name) orelse return c.w.notice(.malformed, "vba: module stream missing");
        if (m.text_offset >= e.size) return c.w.notice(.malformed, "vba: module offset");
        const rbuf = c.w.alloc(u8, 4096) orelse return;
        defer c.w.free(rbuf);
        var r: ChainReader = .init(c.f, e.start, e.size, e.size < c.f.h.mini_cutoff, rbuf);
        r.interface.discardAll64(m.text_offset) catch return c.w.notice(.malformed, "vba: module offset");
        var dec = vba.Decompressor.init(&r.interface);
        var name_buf: [96]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "macro/{s}", .{m.name[0..@min(m.name.len, 64)]}) catch "macro";
        var obj: container.Object = undefined;
        try c.w.beginDerived(&obj, name, .script);
        defer c.w.endDerived(&obj);
        var out: [4096]u8 = undefined;
        var total: u64 = 0;
        while (true) {
            const got = dec.fill(&out) catch break;
            if (got == 0) break;
            total += got;
            if (total > c.w.tracker.limits.max_script_normalize) return c.w.limit(.script_normalize);
            try c.w.feed(&obj, out[0..got]);
        }
        if (dec.err != null) c.w.notice(.malformed, "vba: module source");
    }

    /// Find a child stream of storage `storage_id` by name (case-insensitive), walking the tree
    /// iteratively; bounded by the entry cap.
    fn findChild(c: *Ctx, storage_id: u32, name: []const u8) ?Entry {
        const parent = readEntry(c.f, storage_id, c.dir) orelse return null;
        var stack: [64]u32 = undefined;
        var sp: usize = 0;
        if (parent.child != no_stream) {
            stack[0] = parent.child;
            sp = 1;
        }
        var steps: usize = 0;
        while (sp > 0 and steps < max_entries) : (steps += 1) {
            sp -= 1;
            const e = readEntry(c.f, stack[sp], c.dir) orelse continue;
            if (e.kind == 2 and std.ascii.eqlIgnoreCase(e.name[0..e.name_len], name)) return e;
            for ([_]u32{ e.left, e.right }) |s| if (s != no_stream and sp < stack.len) {
                stack[sp] = s;
                sp += 1;
            };
        }
        return null;
    }
};
