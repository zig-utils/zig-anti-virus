//! OLE2 compound files, written from [MS-CFB]: the header, the FAT (located through the header's
//! DIFAT array and the DIFAT chain), the mini FAT and mini stream, and the directory's red-black
//! trees. Every stream becomes a child, read by following its sector chain, so nothing is copied
//! whole. VBA projects (a "VBA" storage with a "dir" stream) also yield each module's source,
//! decompressed with MS-OVBA (vba.zig), as a derived child. Ole10Native streams also expose
//! their native data and documented Packager payloads as recursively parsed children.
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

/// Benign reproducible Packager seed shared by public-interface tests and fmt.ole2 fuzzing.
pub const native_fixture = @embedFile("fixtures/archive-native.doc.bin");

pub const magic = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
const end_of_chain: u32 = 0xfffffffe;
const free_sect: u32 = 0xffffffff;
const no_stream: u32 = 0xffffffff;
// OLE1 Package CLSID {0003000C-0000-0000-C000-000000000046}, in CFB byte order.
// Primary interoperability reference: Apache POI's ClassIDPredefined.OLE_V1_PACKAGE:
// https://github.com/apache/poi/blob/trunk/poi/src/main/java/org/apache/poi/hpsf/ClassIDPredefined.java
const package_clsid = [_]u8{ 0x0c, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46 };

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
    sector_pos: u64 = 0,
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
            const n: usize = @intCast(@min(dest.len, f.h.sectorSize() - c.sector_pos, c.left));
            f.src.readAllAt(f.io, f.sectorOffset(c.sector) + c.sector_pos, dest[0..n]) catch {
                c.err = true;
                return 0;
            };
            c.left -= n;
            c.sector_pos += n;
            if (c.sector_pos == f.h.sectorSize()) {
                c.sector = f.next(c.sector) orelse end_of_chain;
                c.sector_pos = 0;
                c.steps += 1;
            }
            return n;
        }
        // Mini sector: find its offset in the mini stream, then that position in the FAT chain.
        const mss: u64 = @as(u64, 1) << f.h.mini_shift;
        const pos = @as(u64, c.sector) * mss + c.sector_pos;
        if (pos >= f.root_size) {
            c.err = true;
            return 0;
        }
        const off = miniStreamOffset(f, pos) orelse {
            c.err = true;
            return 0;
        };
        const n: usize = @intCast(@min(dest.len, mss - c.sector_pos, c.left, f.root_size - pos));
        f.src.readAllAt(f.io, off, dest[0..n]) catch {
            c.err = true;
            return 0;
        };
        c.left -= n;
        c.sector_pos += n;
        if (c.sector_pos == mss) {
            c.sector = miniNext(f, c.sector) orelse end_of_chain;
            c.sector_pos = 0;
            c.steps += 1;
        }
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
    package: bool,
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
        .package = std.mem.eql(u8, b[80..96], &package_clsid),
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
    try ctx.storage(root.child, 0, 0, false, root.package);
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
    fn storage(c: *Ctx, id: u32, storage_id: u32, depth: u8, is_vba: bool, is_package: bool) Error!void {
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
            try c.entry(eid, e, depth, is_vba, is_package, &vba_dir);
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

    fn entry(c: *Ctx, eid: u32, e: Entry, depth: u8, is_vba: bool, is_package: bool, vba_dir: *?Entry) Error!void {
        const name = e.name[0..e.name_len];
        switch (e.kind) {
            1 => {
                c.w.path.push(name);
                defer c.w.path.pop();
                try c.storage(e.child, eid, depth + 1, std.ascii.eqlIgnoreCase(name, "VBA"), e.package);
            },
            2 => {
                if (is_vba and std.ascii.eqlIgnoreCase(name, "dir")) vba_dir.* = e;
                try c.stream(e, name, is_package);
            },
            else => {},
        }
    }

    fn stream(c: *Ctx, e: Entry, name: []const u8, is_package: bool) Error!void {
        if (e.size == 0 and !std.ascii.eqlIgnoreCase(name, "\x01Ole10Native")) return;
        const mini = e.size < c.f.h.mini_cutoff;
        var reader: ChainReader = .init(c.f, e.start, e.size, mini, c.buf);
        try c.w.child(name, .{ .stream = .{ .reader = &reader.interface, .len_hint = e.size } }, .member);
        // Whatever the child left unread (a limit, a skip) does not matter: the reader is ours.
        if (reader.err) c.damaged = true;
        if (std.ascii.eqlIgnoreCase(name, "\x01Ole10Native") and e.size <= c.w.tracker.limits.max_file_size) {
            c.w.path.push(name);
            defer c.w.path.pop();
            try c.native(e, is_package);
        }
    }

    /// [MS-OLEDS] 2.3.6: NativeDataSize:u32le followed by exactly that many native bytes.
    /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oleds/cc825ec3-f0ed-4023-97f6-13c323ac1172
    fn native(c: *Ctx, e: Entry, is_package: bool) Error!void {
        const w = c.w;
        var reader: ChainReader = .init(c.f, e.start, e.size, e.size < c.f.h.mini_cutoff, c.buf);
        const size = reader.interface.takeInt(u32, .little) catch return w.notice(.malformed, "ole2: native size header");
        if (e.size < 4 or size > e.size - 4) return w.notice(.malformed, "ole2: native size exceeds stream");
        const buf = w.alloc(u8, 4096) orelse return;
        defer w.free(buf);
        var native_reader = reader.interface.limited(.limited64(size), buf);
        w.notice(.embedded, "ole2: native data");
        try w.child("native", .{ .stream = .{ .reader = &native_reader.interface, .len_hint = size } }, .member);
        if (reader.err) c.damaged = true;

        // [MS-OLEDS] 1.3.3: the owner storage CLSID identifies the creating application.
        // NativeData is application-specific. Structurally valid Packager data is extracted
        // even with a changed CLSID; failed optional recognition is malformed only for a
        // declared Package. Header-work exhaustion remains an explicit limit in either case.
        reader = .init(c.f, e.start, e.size, e.size < c.f.h.mini_cutoff, c.buf);
        reader.interface.discardAll(4) catch return;
        native_reader = reader.interface.limited(.limited64(size), buf);
        var header: PackageHeader = .{ .reader = &native_reader.interface, .left = size };
        const marker = header.int(u16) catch return if (is_package) w.notice(.malformed, "ole2: truncated Packager marker");
        if (marker != 2) return;
        const package = header.parse() catch |err| return switch (err) {
            error.HeaderLimit => w.limit(.container_header),
            error.Malformed => if (is_package) w.notice(.malformed, "ole2: Packager header or payload size"),
        };
        const payload_buf = w.alloc(u8, 4096) orelse return;
        defer w.free(payload_buf);
        var payload = native_reader.interface.limited(.limited64(package.size), payload_buf);
        try w.child(package.name(), .{ .stream = .{ .reader = &payload.interface, .len_hint = package.size } }, .member);
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

/// Packager's variable header is described in Microsoft's Office extraction sample README:
/// https://github.com/microsoftarchive/msdn-code-gallery-microsoft/blob/master/OneCodeTeam/Extract%20embedded%20files%20from%20Office%20documents%20%28CSOfficeDocumentFileExtractor%29/README.md
/// Implemented from the field descriptions, without copying sample code. Optional Unicode
/// names after the payload are not used; they remain covered by the raw and native scans.
const PackageHeader = struct {
    reader: *Io.Reader,
    left: u64,
    const ParseError = error{ Malformed, HeaderLimit };
    const max_string = 4096;
    const Package = struct {
        label: [256]u8 = undefined,
        label_len: usize = 0,
        size: u32 = 0,

        fn name(p: *const Package) []const u8 {
            const label = p.label[0..p.label_len];
            const start = if (std.mem.lastIndexOfAny(u8, label, "/\\")) |i| i + 1 else 0;
            const base = label[start..];
            return if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) "package" else base;
        }
    };

    fn int(h: *PackageHeader, comptime T: type) ParseError!T {
        if (h.left < @sizeOf(T)) return error.Malformed;
        const result = h.reader.takeInt(T, .little) catch return error.Malformed;
        h.left -= @sizeOf(T);
        return result;
    }

    /// Scan a NUL-terminated ANSI string with a fixed work cap; only the label needs keeping.
    fn string(h: *PackageHeader, label: ?*Package) ParseError!void {
        for (0..max_string) |_| {
            const b = try h.int(u8);
            if (b == 0) return;
            if (label) |p| if (p.label_len < p.label.len) {
                p.label[p.label_len] = b;
                p.label_len += 1;
            };
        }
        return error.HeaderLimit;
    }

    fn parse(h: *PackageHeader) ParseError!Package {
        var p: Package = .{};
        try h.string(&p);
        try h.string(null);
        _ = try h.int(u32); // Unknown field, ignored.
        const path_size = try h.int(u32);
        if (path_size > h.left) return error.Malformed;
        if (path_size > max_string) return error.HeaderLimit;
        if (path_size == 0) return error.Malformed;
        const path = h.reader.take(@intCast(path_size)) catch return error.Malformed;
        h.left -= path_size;
        if (path[path.len - 1] != 0) return error.Malformed;
        p.size = try h.int(u32);
        if (p.size > h.left) return error.Malformed;
        return p;
    }
};

// Synthetic CFB fixtures use one FAT and directory sector, followed by a regular stream.
// mini_cutoff=0 keeps tiny malformed vectors on the same regular-chain path.
fn nativeFixture(native: []const u8) ![]u8 {
    const gpa = std.testing.allocator;
    const sectors = (native.len + 511) / 512;
    const bytes = try gpa.alloc(u8, (3 + sectors) * 512);
    @memset(bytes, 0);
    @memcpy(bytes[0..8], magic);
    std.mem.writeInt(u16, bytes[30..32], 9, .little);
    std.mem.writeInt(u16, bytes[32..34], 6, .little);
    std.mem.writeInt(u32, bytes[48..52], 1, .little);
    std.mem.writeInt(u32, bytes[60..64], end_of_chain, .little);
    std.mem.writeInt(u32, bytes[68..72], end_of_chain, .little);
    @memset(bytes[76..512], 0xff);
    std.mem.writeInt(u32, bytes[76..80], 0, .little);
    @memset(bytes[512..1024], 0xff);
    std.mem.writeInt(u32, bytes[512..516], 0xfffffffd, .little);
    std.mem.writeInt(u32, bytes[516..520], end_of_chain, .little);
    for (0..sectors) |i| std.mem.writeInt(u32, bytes[520 + i * 4 ..][0..4], if (i + 1 == sectors) end_of_chain else @intCast(i + 3), .little);
    const names = [_][]const u8{ "Root Entry", "\x01Ole10Native" };
    for (names, 0..) |name, i| {
        const entry = bytes[1024 + i * 128 ..][0..128];
        for (name, 0..) |b, j| std.mem.writeInt(u16, entry[j * 2 ..][0..2], b, .little);
        std.mem.writeInt(u16, entry[64..66], @intCast((name.len + 1) * 2), .little);
        entry[66] = if (i == 0) 5 else 2;
        if (i == 0) @memcpy(entry[80..96], &package_clsid);
        std.mem.writeInt(u32, entry[68..72], no_stream, .little);
        std.mem.writeInt(u32, entry[72..76], no_stream, .little);
        std.mem.writeInt(u32, entry[76..80], if (i == 0) 1 else no_stream, .little);
        std.mem.writeInt(u32, entry[116..120], if (i == 0) end_of_chain else 2, .little);
        std.mem.writeInt(u64, entry[120..128], if (i == 0) 0 else native.len, .little);
    }
    @memcpy(bytes[1536..][0..native.len], native);
    return bytes;
}

fn nativeEnvelope(data: []const u8) ![]u8 {
    const out = try std.testing.allocator.alloc(u8, data.len + 4);
    std.mem.writeInt(u32, out[0..4], @intCast(data.len), .little);
    @memcpy(out[4..], data);
    return out;
}

test "OLE native data becomes a recursively parsed child, preserving the raw stream" {
    const gz = @import("fixtures/fixtures.zig").gzip_vectors[0];
    const native = try nativeEnvelope(gz.compressed);
    defer std.testing.allocator.free(native);
    const doc = try nativeFixture(native);
    defer std.testing.allocator.free(doc);
    var rig: @import("scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(doc, "embedded.doc");
    const raw = rig.rec.find("embedded.doc/?Ole10Native") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(native.len, raw.bytes);
    try std.testing.expectEqual(std.hash.Crc32.hash(native), raw.crc);
    const child = rig.rec.find("embedded.doc/?Ole10Native/native/gzip") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(gz.plain_len, child.bytes);
    try std.testing.expectEqual(gz.plain_crc, child.crc);
    try std.testing.expect(!rig.rec.has(.malformed));
    try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
}

fn packageEnvelope(data: []const u8, label: []const u8) ![]u8 {
    const gpa = std.testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, "\x02\x00");
    try body.appendSlice(gpa, label);
    try body.appendSlice(gpa, "\x00source\x00\x00\x00\x00\x00\x05\x00\x00\x00temp\x00");
    var size: [4]u8 = undefined;
    std.mem.writeInt(u32, &size, @intCast(data.len), .little);
    try body.appendSlice(gpa, &size);
    try body.appendSlice(gpa, data);
    // The optional Unicode-name trailer must never leak into the payload child.
    try body.appendSlice(gpa, "\x00\x00\x00\x00trailer");
    return nativeEnvelope(body.items);
}

fn nativeMiniFixture(native: []const u8) ![]u8 {
    const regular = try nativeFixture(native);
    defer std.testing.allocator.free(regular);
    const bytes = try std.testing.allocator.alloc(u8, regular.len + 512);
    @memcpy(bytes[0..regular.len], regular);
    const minifat_sector: u32 = @intCast(regular.len / 512 - 1);
    std.mem.writeInt(u32, bytes[56..60], 4096, .little);
    std.mem.writeInt(u32, bytes[60..64], minifat_sector, .little);
    std.mem.writeInt(u32, bytes[512 + minifat_sector * 4 ..][0..4], end_of_chain, .little);
    std.mem.writeInt(u32, bytes[1024 + 116 ..][0..4], 2, .little);
    std.mem.writeInt(u64, bytes[1024 + 120 ..][0..8], (native.len + 63) / 64 * 64, .little);
    std.mem.writeInt(u32, bytes[1152 + 116 ..][0..4], 0, .little);
    const mini_count = (native.len + 63) / 64;
    @memset(bytes[regular.len..], 0xff);
    for (0..mini_count) |i| std.mem.writeInt(u32, bytes[regular.len + i * 4 ..][0..4], if (i + 1 == mini_count) end_of_chain else @intCast(i + 1), .little);
    return bytes;
}

test "OLE native Packager payload has exact bounds in regular and mini FAT streams" {
    const gz = @import("fixtures/fixtures.zig").gzip_vectors[0];
    const native = try packageEnvelope(gz.compressed, "..\\unsafe/native.gz");
    defer std.testing.allocator.free(native);
    for ([_]bool{ false, true }) |mini| {
        const doc = if (mini) try nativeMiniFixture(native) else try nativeFixture(native);
        defer std.testing.allocator.free(doc);
        var rig: @import("scan.zig").TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(doc, "package.doc");
        const raw = rig.rec.find("package.doc/?Ole10Native") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(std.hash.Crc32.hash(native), raw.crc);
        const payload = rig.rec.find("package.doc/?Ole10Native/native.gz") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(gz.compressed.len, payload.bytes);
        try std.testing.expectEqual(std.hash.Crc32.hash(gz.compressed), payload.crc);
        const child = rig.rec.find("package.doc/?Ole10Native/native.gz/native") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(gz.plain_len, child.bytes);
        try std.testing.expectEqual(gz.plain_crc, child.crc);
        try std.testing.expect(!rig.rec.has(.malformed));
        try std.testing.expect(rig.rec.has(.embedded));
    }
}

test "OLE native malformed sizes and truncated Packager fields preserve raw scanning" {
    const native = try packageEnvelope("benign package payload", "payload.bin");
    defer std.testing.allocator.free(native);
    const header_len = native.len - "benign package payload".len - 11;
    // Every header cut, including each byte of the outer DWORD, ASCIIZ strings,
    // temporary-path length/string and final data-size DWORD.
    for (0..header_len) |cut| {
        const truncated = try std.testing.allocator.dupe(u8, native[0..cut]);
        defer std.testing.allocator.free(truncated);
        if (cut >= 4) std.mem.writeInt(u32, truncated[0..4], @intCast(cut - 4), .little);
        const doc = try nativeFixture(truncated);
        defer std.testing.allocator.free(doc);
        var rig: @import("scan.zig").TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(doc, "truncated.doc");
        const raw = rig.rec.find("truncated.doc/?Ole10Native") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(cut, raw.bytes);
        try std.testing.expect(rig.rec.has(.malformed));
        try std.testing.expect(rig.rec.find("truncated.doc/?Ole10Native/payload.bin") == null);
    }
    // Outer length cannot reach into sector padding; checked by subtraction, no wraparound.
    const bad = try std.testing.allocator.dupe(u8, native);
    defer std.testing.allocator.free(bad);
    for ([_]u32{ @intCast(native.len - 3), 0xffffffff }) |size| {
        std.mem.writeInt(u32, bad[0..4], size, .little);
        const doc = try nativeFixture(bad);
        defer std.testing.allocator.free(doc);
        var rig: @import("scan.zig").TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(doc, "oversize.doc");
        try std.testing.expect(rig.rec.has(.malformed));
        try std.testing.expect(rig.rec.find("oversize.doc/?Ole10Native/native") == null);
    }
    for ([_]u32{ @intCast(native.len - header_len + 1), 0xffffffff }) |size| {
        @memcpy(bad, native);
        std.mem.writeInt(u32, bad[header_len - 4 ..][0..4], size, .little);
        const doc = try nativeFixture(bad);
        defer std.testing.allocator.free(doc);
        var rig: @import("scan.zig").TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(doc, "bad-payload.doc");
        try std.testing.expect(rig.rec.has(.malformed));
        try std.testing.expect(rig.rec.find("bad-payload.doc/?Ole10Native/native") != null);
        try std.testing.expect(rig.rec.find("bad-payload.doc/?Ole10Native/payload.bin") == null);
    }
}

test "OLE native hostile header lengths raise an explicit header limit" {
    const gpa = std.testing.allocator;
    const oversized = try gpa.alloc(u8, 2 + PackageHeader.max_string + 1);
    defer gpa.free(oversized);
    @memset(oversized, 'a');
    oversized[0] = 2;
    oversized[1] = 0;
    oversized[oversized.len - 1] = 0;
    const long_label = try nativeEnvelope(oversized);
    defer gpa.free(long_label);
    const ordinary = try packageEnvelope("benign", "x");
    defer gpa.free(ordinary);
    const path_offset = 19;
    const long_path = try gpa.alloc(u8, ordinary.len + 4097 - 5);
    defer gpa.free(long_path);
    @memcpy(long_path[0..path_offset], ordinary[0..path_offset]);
    std.mem.writeInt(u32, long_path[path_offset..][0..4], 4097, .little);
    @memset(long_path[path_offset + 4 ..][0..4097], 't');
    long_path[path_offset + 4 + 4096] = 0;
    @memcpy(long_path[path_offset + 4 + 4097 ..], ordinary[path_offset + 4 + 5 ..]);
    std.mem.writeInt(u32, long_path[0..4], @intCast(long_path.len - 4), .little);
    for ([_][]const u8{ long_label, long_path }) |bytes| {
        const doc = try nativeFixture(bytes);
        defer gpa.free(doc);
        // Unknown application data still reports an exhausted marker-2 header work budget.
        if (bytes.ptr == long_label.ptr) @memset(doc[1024 + 80 ..][0..16], 0);
        var rig: @import("scan.zig").TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(doc, "hostile.doc");
        const raw = rig.rec.find("hostile.doc/?Ole10Native") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(bytes.len, raw.bytes);
        try std.testing.expect(rig.rec.hasLimit(.container_header));
    }
    // A length outside the native object is malformed, before any limit check or skip.
    std.mem.writeInt(u32, ordinary[path_offset..][0..4], 0xffffffff, .little);
    const doc = try nativeFixture(ordinary);
    defer gpa.free(doc);
    var rig: @import("scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(doc, "bad-length.doc");
    try std.testing.expect(rig.rec.has(.malformed));
    try std.testing.expect(!rig.rec.hasLimit(.container_header));
}

test "OLE native children obey recursion and file count limits" {
    const native = try packageEnvelope(@import("fixtures/fixtures.zig").gzip_vectors[0].compressed, "payload.gz");
    defer std.testing.allocator.free(native);
    const doc = try nativeFixture(native);
    defer std.testing.allocator.free(doc);
    const Limits = @import("../engine/limits.zig").Limits;
    for ([_]Limits{ .{ .max_files = 1 }, .{ .max_recursion = 1 } }, 0..) |lim, i| {
        var rig: @import("scan.zig").TestRig = undefined;
        try rig.init(lim);
        defer rig.deinit();
        try rig.scanBoth(doc, "limited.doc");
        try std.testing.expect(rig.rec.find("limited.doc/?Ole10Native") != null);
        try std.testing.expect(rig.rec.hasLimit(if (i == 0) .files else .recursion));
        try std.testing.expect(rig.rec.find("limited.doc/?Ole10Native/payload.gz/payload") == null);
    }
}

test "OLE native nested benign marker reaches the public detection visitor with changed CLSID" {
    const marker = "GUARDIAN_BENIGN_NATIVE_CHILD";
    for ([_]bool{ true, false }) |declared_package| {
        const doc = try std.testing.allocator.dupe(u8, native_fixture);
        defer std.testing.allocator.free(doc);
        if (!declared_package) @memset(doc[1024 + 80 ..][0..16], 0);
        try std.testing.expect(std.mem.indexOf(u8, doc, marker) == null);
        var rig: @import("scan.zig").TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        rig.rec.stop_at = marker;
        try std.testing.expectError(error.Halted, rig.walker.scan(.{ .memory = doc }, "detected.doc"));
        try std.testing.expectEqual(container.Halt.stop, rig.walker.halt.?);
        try std.testing.expect(rig.rec.find("detected.doc/?Ole10Native/payload.gz/payload") != null);
    }
}

test "OLE native short sector reads preserve payload bytes and broken chains are malformed" {
    const data = try std.testing.allocator.alloc(u8, 9001);
    defer std.testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i * 17 + i / 19);
    const native = try nativeEnvelope(data);
    defer std.testing.allocator.free(native);
    const doc = try nativeFixture(native);
    defer std.testing.allocator.free(doc);
    var rig: @import("scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(doc, "sectors.doc");
    const child = rig.rec.find("sectors.doc/?Ole10Native/native") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(data.len, child.bytes);
    try std.testing.expectEqual(std.hash.Crc32.hash(data), child.crc);
    try std.testing.expect(!rig.rec.has(.malformed));

    // The declared stream remains long, but its sector chain ends after the first sector.
    std.mem.writeInt(u32, doc[520..524], end_of_chain, .little);
    var broken: @import("scan.zig").TestRig = undefined;
    try broken.init(.{});
    defer broken.deinit();
    try broken.scanBoth(doc, "broken.doc");
    try std.testing.expect(broken.rec.has(.malformed));
    const prefix = broken.rec.find("broken.doc/?Ole10Native/native") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 508), prefix.bytes);
}

test "OLE native unknown application data beginning with two has no guessed malformed notice" {
    const native = try nativeEnvelope("\x02\x00application-specific native bytes");
    defer std.testing.allocator.free(native);
    const doc = try nativeFixture(native);
    defer std.testing.allocator.free(doc);
    @memset(doc[1024 + 80 ..][0..16], 0);
    var rig: @import("scan.zig").TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(doc, "unknown.doc");
    const child = rig.rec.find("unknown.doc/?Ole10Native/native") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(native.len - 4, child.bytes);
    try std.testing.expect(!rig.rec.has(.malformed));
    try std.testing.expect(!rig.rec.hasLimit(.container_header));
}
