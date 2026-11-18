//! PE/COFF, written from Microsoft's PE Format specification: DOS stub, NT headers, the PE32 and
//! PE32+ optional headers, the section table, entry point mapping, the import table and the
//! resource tree. Every field is untrusted; every read is bounds-checked against the file and
//! damage becomes a `malformed` notice or an anomaly flag, never a crash.
//!
//! What the matcher gets: entry point (RVA and file offset), sections with their file ranges
//! (for EP- and section-relative offsets and .mdb/.msb section hashes), the import hash used by
//! .imp signatures, and the overlay. Overlay data and resources whose bytes start with a known
//! container or executable format are scanned as children; plain data is already covered by the
//! file's own raw scan.
const std = @import("std");
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const detect = @import("detect.zig");
const Walker = container.Walker;
const Io = std.Io;

/// The loader accepts at most 96 sections; tolerate more but cap the table.
pub const max_sections = 1024;
pub const max_import_descriptors = 4096;
pub const max_imports = 65536;
pub const max_resources = 4096;
const max_name = 256;

pub const Error = error{ NotPe, Truncated, BadHeader } || Source.ReadError;

pub const Section = struct {
    name: [8]u8,
    va: u32,
    vsize: u32,
    /// File range, with the loader's alignment applied (raw offset rounded down to 512 when the
    /// file alignment is at least 512, size rounded up to the file alignment) and cut at EOF.
    raw_off: u64,
    raw_size: u64,
    /// SizeOfRawData as stored (what .mdb/.msb signatures are keyed on).
    stored_raw_size: u32,
    characteristics: u32,

    pub const exec: u32 = 0x20000000;
    pub const write: u32 = 0x80000000;
    pub const code: u32 = 0x00000020;

    pub fn nameSlice(s: *const Section) []const u8 {
        return s.name[0 .. std.mem.indexOfScalar(u8, &s.name, 0) orelse 8];
    }
};

pub const DataDir = struct { rva: u32 = 0, size: u32 = 0 };

pub const Anomalies = packed struct(u16) {
    ep_outside_sections: bool = false,
    sections_overlap: bool = false,
    write_exec_section: bool = false,
    raw_beyond_eof: bool = false,
    section_table_truncated: bool = false,
    zero_sections: bool = false,
    bad_alignment: bool = false,
    headers_overlap_sections: bool = false,
    _: u8 = 0,
};

pub const Info = struct {
    pe_offset: u32,
    is64: bool,
    machine: u16,
    /// NumberOfSections as stored.
    nsections: u16,
    characteristics: u16,
    ep_rva: u32,
    ep_offset: ?u64,
    image_base: u64,
    section_align: u32,
    file_align: u32,
    size_of_image: u32,
    size_of_headers: u32,
    dirs: [16]DataDir,
    sections: []Section,
    /// Where data the loader never maps begins (end of the last section's raw data).
    overlay_off: u64,
    file_size: u64,
    anomalies: Anomalies,

    /// File offset of an RVA, or null when no section (or the headers) contain it.
    pub fn rvaToOffset(info: *const Info, rva: u64) ?u64 {
        if (rva < info.size_of_headers and rva < info.file_size) {
            // Inside the headers, unless a section claims it.
            for (info.sections) |s| if (s.va != 0 and rva >= s.va) break else {
                return rva;
            };
        }
        for (info.sections) |s| {
            const span = @max(s.raw_size, 0);
            if (span != 0 and rva >= s.va and rva - s.va < span) return s.raw_off + (rva - s.va);
        }
        return null;
    }

    pub fn dir(info: *const Info, i: usize) DataDir {
        return info.dirs[i];
    }
};

pub const dir_export = 0;
pub const dir_import = 1;
pub const dir_resource = 2;
pub const dir_security = 4;

fn alignmentValid(a: u32) bool {
    return a != 0 and std.math.isPowerOfTwo(a);
}

/// Parse headers and the section table. `sections` is caller storage (`max_sections` entries
/// is always enough).
pub fn parse(io: Io, src: Source, sections: []Section) Error!Info {
    const file_size = src.len() orelse return error.NotPe;
    var dos: [64]u8 = undefined;
    src.readAllAt(io, 0, &dos) catch return error.Truncated;
    if (!std.mem.eql(u8, dos[0..2], "MZ")) return error.NotPe;
    const pe_off = std.mem.readInt(u32, dos[0x3c..0x40], .little);
    if (pe_off > file_size or file_size - pe_off < 24) return error.NotPe;
    var nt: [24]u8 = undefined;
    src.readAllAt(io, pe_off, &nt) catch return error.NotPe;
    if (!std.mem.eql(u8, nt[0..4], "PE\x00\x00")) return error.NotPe;
    const machine = std.mem.readInt(u16, nt[4..6], .little);
    const nsections = std.mem.readInt(u16, nt[6..8], .little);
    const opt_size = std.mem.readInt(u16, nt[20..22], .little);
    const characteristics = std.mem.readInt(u16, nt[22..24], .little);
    const opt_off: u64 = @as(u64, pe_off) + 24;

    var opt: [240]u8 = @splat(0);
    const opt_read = @min(@as(usize, opt_size), opt.len);
    const got = src.readAt(io, opt_off, opt[0..opt_read]) catch return error.Truncated;
    if (got < 2) return error.Truncated;
    const magic = std.mem.readInt(u16, opt[0..2], .little);
    const is64 = switch (magic) {
        0x10b => false,
        0x20b => true,
        else => return error.BadHeader,
    };
    const rd32 = struct {
        fn f(b: []const u8, off: usize) u32 {
            return std.mem.readInt(u32, b[off..][0..4], .little);
        }
    }.f;
    var info: Info = .{
        .pe_offset = pe_off,
        .is64 = is64,
        .machine = machine,
        .nsections = nsections,
        .characteristics = characteristics,
        .ep_rva = rd32(&opt, 16),
        .ep_offset = null,
        .image_base = if (is64) std.mem.readInt(u64, opt[24..32], .little) else rd32(&opt, 28),
        .section_align = rd32(&opt, 32),
        .file_align = rd32(&opt, 36),
        .size_of_image = rd32(&opt, 56),
        .size_of_headers = rd32(&opt, 60),
        .dirs = @splat(.{}),
        .sections = sections[0..0],
        .overlay_off = 0,
        .file_size = file_size,
        .anomalies = .{},
    };
    const ndirs_off: usize = if (is64) 108 else 92;
    const dirs_off: usize = ndirs_off + 4;
    const ndirs = @min(rd32(&opt, ndirs_off), 16);
    for (0..ndirs) |i| {
        const o = dirs_off + i * 8;
        if (o + 8 > opt_read) break;
        info.dirs[i] = .{ .rva = rd32(&opt, o), .size = rd32(&opt, o + 4) };
    }
    if (!alignmentValid(info.file_align) or !alignmentValid(info.section_align) or info.file_align > info.section_align)
        info.anomalies.bad_alignment = true;

    // Section table.
    if (nsections == 0) info.anomalies.zero_sections = true;
    const table_off = opt_off + opt_size;
    const n = @min(@as(usize, nsections), sections.len);
    var raw_align: u64 = 1;
    if (alignmentValid(info.file_align) and info.file_align >= 0x200) raw_align = 0x200;
    const size_align: u64 = if (alignmentValid(info.file_align) and info.file_align <= 0x10000) info.file_align else 1;
    var count: usize = 0;
    var last_end: u64 = 0;
    for (0..n) |i| {
        var sh: [40]u8 = undefined;
        src.readAllAt(io, table_off + i * 40, &sh) catch {
            info.anomalies.section_table_truncated = true;
            break;
        };
        var s: Section = .{
            .name = sh[0..8].*,
            .vsize = rd32(&sh, 8),
            .va = rd32(&sh, 12),
            .stored_raw_size = rd32(&sh, 16),
            .raw_off = rd32(&sh, 20) / raw_align * raw_align,
            .raw_size = 0,
            .characteristics = rd32(&sh, 36),
        };
        const aligned_size = std.mem.alignForward(u64, s.stored_raw_size, size_align);
        if (s.raw_off > file_size or aligned_size > file_size - s.raw_off) info.anomalies.raw_beyond_eof = true;
        s.raw_size = if (s.raw_off >= file_size) 0 else @min(aligned_size, file_size - s.raw_off);
        if (s.characteristics & Section.exec != 0 and s.characteristics & Section.write != 0) info.anomalies.write_exec_section = true;
        if (s.raw_size != 0 and s.raw_off < info.size_of_headers and s.raw_off < table_off + n * 40) info.anomalies.headers_overlap_sections = true;
        if (s.raw_size != 0) last_end = @max(last_end, s.raw_off + s.raw_size);
        sections[count] = s;
        count += 1;
    }
    info.sections = sections[0..count];
    // Overlapping raw ranges (quadratic in a capped count; real files have a handful).
    outer: for (info.sections, 0..) |a, i| {
        if (a.raw_size == 0) continue;
        for (info.sections[i + 1 ..]) |b| {
            if (b.raw_size == 0) continue;
            if (a.raw_off < b.raw_off + b.raw_size and b.raw_off < a.raw_off + a.raw_size) {
                info.anomalies.sections_overlap = true;
                break :outer;
            }
        }
    }
    const headers_end = @min(@max(@as(u64, info.size_of_headers), table_off + count * 40), file_size);
    info.overlay_off = @max(last_end, headers_end);
    info.ep_offset = info.rvaToOffset(info.ep_rva);
    if (info.ep_offset == null or !inSection(&info, info.ep_rva)) info.anomalies.ep_outside_sections = true;
    return info;
}

fn inSection(info: *const Info, rva: u32) bool {
    for (info.sections) |s| {
        const span = @max(s.vsize, @as(u32, @intCast(@min(s.raw_size, std.math.maxInt(u32)))));
        if (rva >= s.va and rva - s.va < span) return true;
    }
    return false;
}

/// The import hash .imp signatures match: MD5 over "dll.function" entries, lowercased, the DLL
/// name without a .dll/.ocx/.sys extension, joined by commas in table order; size is the length
/// of that string. Ordinal imports appear as "ord<number>". Null when there is no import table.
pub const ImportHash = struct { md5: [16]u8, size: u64, functions: u32 };

pub fn importHash(io: Io, src: Source, info: *const Info) ?ImportHash {
    const d = info.dirs[dir_import];
    if (d.rva == 0) return null;
    var off = info.rvaToOffset(d.rva) orelse return null;
    var md5 = std.crypto.hash.Md5.init(.{});
    var size: u64 = 0;
    var functions: u32 = 0;
    var descriptors: usize = 0;
    while (descriptors < max_import_descriptors) : (descriptors += 1) {
        var desc: [20]u8 = undefined;
        src.readAllAt(io, off, &desc) catch break;
        off += 20;
        if (std.mem.allEqual(u8, &desc, 0)) break;
        const oft = std.mem.readInt(u32, desc[0..4], .little);
        const name_rva = std.mem.readInt(u32, desc[12..16], .little);
        const ft = std.mem.readInt(u32, desc[16..20], .little);
        var dll_buf: [max_name]u8 = undefined;
        var dll = readString(io, src, info, name_rva, &dll_buf) orelse continue;
        for (dll) |*c| c.* = std.ascii.toLower(c.*);
        for ([_][]const u8{ ".dll", ".ocx", ".sys" }) |ext| {
            if (std.mem.endsWith(u8, dll, ext)) {
                dll = dll[0 .. dll.len - ext.len];
                break;
            }
        }
        const thunks_rva = if (oft != 0) oft else ft;
        var t_off = info.rvaToOffset(thunks_rva) orelse continue;
        const thunk_len: u64 = if (info.is64) 8 else 4;
        while (functions < max_imports) {
            var tb: [8]u8 = @splat(0);
            src.readAllAt(io, t_off, tb[0..@intCast(thunk_len)]) catch break;
            t_off += thunk_len;
            const thunk = std.mem.readInt(u64, &tb, .little);
            if (thunk == 0) break;
            const ordinal_flag: u64 = if (info.is64) 1 << 63 else 1 << 31;
            var fn_buf: [max_name + 16]u8 = undefined;
            var func: []u8 = undefined;
            if (thunk & ordinal_flag != 0) {
                func = std.fmt.bufPrint(&fn_buf, "ord{d}", .{thunk & 0xffff}) catch unreachable;
            } else {
                // Hint (2 bytes), then the name.
                func = readString(io, src, info, @intCast((thunk & 0x7fffffff) + 2), fn_buf[0..max_name]) orelse break;
            }
            for (func) |*c| c.* = std.ascii.toLower(c.*);
            if (size != 0) md5.update(",");
            md5.update(dll);
            md5.update(".");
            md5.update(func);
            size += @as(u64, @intFromBool(size != 0)) + dll.len + 1 + func.len;
            functions += 1;
        }
    }
    if (functions == 0) return null;
    var out: ImportHash = .{ .md5 = undefined, .size = size, .functions = functions };
    md5.final(&out.md5);
    return out;
}

fn readString(io: Io, src: Source, info: *const Info, rva: u64, buf: []u8) ?[]u8 {
    const off = info.rvaToOffset(rva) orelse return null;
    const n = src.readAt(io, off, buf) catch return null;
    const end = std.mem.indexOfScalar(u8, buf[0..n], 0) orelse return null;
    if (end == 0) return null;
    return buf[0..end];
}

/// Scan a PE: parse it, report damage, and recurse into an overlay or resources that hold
/// another container or executable. The raw bytes were already fed by the dispatcher.
pub fn walk(w: *Walker, src: Source) container.Error!void {
    const sections = w.alloc(Section, max_sections) orelse return;
    const info = parse(w.io, src, sections) catch |e| {
        return switch (e) {
            error.NotPe => {}, // an MZ file that is not PE (DOS executable)
            else => w.notice(.malformed, "pe: headers"),
        };
    };
    if (info.anomalies.section_table_truncated or info.anomalies.raw_beyond_eof) w.notice(.malformed, "pe: section data beyond end of file");
    try resources(w, src, &info);
    if (info.overlay_off < info.file_size) {
        const overlay = src.slice(info.overlay_off, info.file_size - info.overlay_off) catch return;
        if (worthRecursing(w, overlay)) try w.child("overlay", overlay, .slice);
    }
}

/// Only regions that start with a container or executable format become children.
fn worthRecursing(w: *Walker, region: Source) bool {
    var head: [detect.head_len]u8 = undefined;
    const n = region.readAt(w.io, 0, &head) catch return false;
    return switch (detect.detect(head[0..n])) {
        .binary, .text, .html => false,
        else => true,
    };
}

/// Walk the resource tree (type / name / language) to its data entries. Depth is capped at 3
/// levels and the entry count at `max_resources`, which also defeats directory loops.
fn resources(w: *Walker, src: Source, info: *const Info) container.Error!void {
    const d = info.dirs[dir_resource];
    if (d.rva == 0) return;
    const base = info.rvaToOffset(d.rva) orelse return;
    var budget: usize = max_resources;
    var ids: [3]u32 = @splat(0);
    try resourceDir(w, src, info, base, 0, 0, &budget, &ids);
}

fn resourceDir(w: *Walker, src: Source, info: *const Info, base: u64, rel: u64, depth: u8, budget: *usize, ids: *[3]u32) container.Error!void {
    var hdr: [16]u8 = undefined;
    src.readAllAt(w.io, base + rel, &hdr) catch return;
    const count = @as(u32, std.mem.readInt(u16, hdr[12..14], .little)) + std.mem.readInt(u16, hdr[14..16], .little);
    for (0..count) |i| {
        if (budget.* == 0) return;
        budget.* -= 1;
        var e: [8]u8 = undefined;
        src.readAllAt(w.io, base + rel + 16 + i * 8, &e) catch return;
        const id = std.mem.readInt(u32, e[0..4], .little);
        const target = std.mem.readInt(u32, e[4..8], .little);
        ids[@min(depth, 2)] = if (id & 0x80000000 != 0) 0xffffffff else id;
        if (target & 0x80000000 != 0) {
            if (depth >= 2) continue;
            try resourceDir(w, src, info, base, target & 0x7fffffff, depth + 1, budget, ids);
            continue;
        }
        var leaf: [16]u8 = undefined;
        src.readAllAt(w.io, base + target, &leaf) catch continue;
        const data_rva = std.mem.readInt(u32, leaf[0..4], .little);
        const size = std.mem.readInt(u32, leaf[4..8], .little);
        const off = info.rvaToOffset(data_rva) orelse continue;
        if (size == 0 or off >= info.file_size) continue;
        const region = src.slice(off, @min(size, info.file_size - off)) catch continue;
        if (!worthRecursing(w, region)) continue;
        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "resource/{d}/{d}/{d}", .{ ids[0], ids[1], ids[2] }) catch "resource";
        try w.child(name, region, .slice);
    }
}

/// Section hashes for .mdb/.msb: the digest of each section's stored raw data, computed only
/// when `want(stored size)` says some signature has that size. `block` is caller scratch.
pub fn sectionDigest(io: Io, src: Source, s: *const Section, comptime Hash: type, block: []u8) ?[Hash.digest_length]u8 {
    const len = @min(@as(u64, s.stored_raw_size), s.raw_size);
    if (len != s.stored_raw_size) return null; // truncated: no exact digest exists
    var h = Hash.init(.{});
    var off: u64 = 0;
    while (off < len) {
        const want = @min(block.len, len - off);
        src.readAllAt(io, s.raw_off + off, block[0..@intCast(want)]) catch return null;
        h.update(block[0..@intCast(want)]);
        off += want;
    }
    var out: [Hash.digest_length]u8 = undefined;
    h.final(&out);
    return out;
}

const fixtures = @import("fixtures/fixtures.zig");

test "PE fixtures: entry point, sections, import hash, anomalies" {
    var sections: [max_sections]Section = undefined;
    for (fixtures.exes) |e| {
        if (!std.mem.endsWith(u8, e.name, ".exe")) continue;
        const src: Source = .{ .memory = e.bytes };
        const info = try parse(std.testing.io, src, &sections);
        try std.testing.expectEqual(e.entry, info.ep_offset);
        if (!e.malformed) try std.testing.expectEqual(e.sections, info.sections.len);
        if (e.imphash.len != 0) {
            const ih = importHash(std.testing.io, src, &info) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqualStrings(e.imphash, &std.fmt.bytesToHex(ih.md5, .lower));
            try std.testing.expectEqual(e.impsize, ih.size);
            try std.testing.expectEqual(@as(u32, 2), ih.functions);
        }
        if (e.malformed) continue;
        const a = info.anomalies;
        try std.testing.expectEqual(std.mem.eql(u8, e.name, "pe-ep-outside.exe"), a.ep_outside_sections);
        try std.testing.expectEqual(std.mem.eql(u8, e.name, "pe-wx.exe"), a.write_exec_section);
        try std.testing.expectEqual(std.mem.eql(u8, e.name, "pe-overlap.exe"), a.sections_overlap);
    }
    const pe32 = fixtures.exes[0];
    const info = try parse(std.testing.io, .{ .memory = pe32.bytes }, &sections);
    try std.testing.expect(!info.is64);
    try std.testing.expectEqualStrings(".rdata", info.sections[1].nameSlice());
    try std.testing.expectEqual(@as(u64, 0x400), info.sections[1].raw_off);
    try std.testing.expectEqual(@as(u64, 0x1010), info.ep_rva);
    try std.testing.expectEqual(@as(u64, 0x400000), info.image_base);
    try std.testing.expect(info.overlay_off < pe32.bytes.len);
}

test "not PE: a DOS executable and garbage" {
    var sections: [8]Section = undefined;
    var dos: [64]u8 = @splat(0);
    @memcpy(dos[0..2], "MZ");
    try std.testing.expectError(error.NotPe, parse(std.testing.io, .{ .memory = &dos }, &sections));
    try std.testing.expectError(error.Truncated, parse(std.testing.io, .{ .memory = "MZ" }, &sections));
}
