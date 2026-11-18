//! ELF, written from the System V ABI generic ELF specification: 32- and 64-bit, either byte
//! order; the file header, program headers and section headers. The entry point maps to a file
//! offset through the PT_LOAD segment containing it (or, for files without segments, an
//! allocated section). Counts are capped, every range is checked against the file, and damage
//! becomes a malformed notice or an anomaly flag for the heuristics.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const heuristics = @import("../engine/heuristics.zig");

pub const max_headers = 4096;

pub const Error = error{ NotElf, Truncated, BadHeader };

pub const Segment = struct {
    type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,

    pub const load: u32 = 1;
    pub const x: u32 = 1;
    pub const w: u32 = 2;
};

pub const Section = struct {
    name_off: u32,
    type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,

    pub const alloc: u64 = 2;
    pub const nobits: u32 = 8;
};

pub const Anomalies = packed struct(u8) {
    ep_outside_segments: bool = false,
    write_exec_segment: bool = false,
    data_beyond_eof: bool = false,
    headers_truncated: bool = false,
    _: u4 = 0,
};

pub const Info = struct {
    is64: bool,
    endian: std.builtin.Endian,
    type: u16,
    machine: u16,
    entry: u64,
    ep_offset: ?u64,
    segments: []Segment,
    sections: []Section,
    anomalies: Anomalies,

    /// File offset of a virtual address, through PT_LOAD segments, then allocated sections.
    pub fn vaddrToOffset(info: *const Info, addr: u64) ?u64 {
        for (info.segments) |s| {
            if (s.type == Segment.load and addr >= s.vaddr and addr - s.vaddr < s.filesz) return s.offset + (addr - s.vaddr);
        }
        if (info.segments.len == 0) for (info.sections) |s| {
            if (s.flags & Section.alloc != 0 and s.type != Section.nobits and addr >= s.addr and addr - s.addr < s.size) return s.offset + (addr - s.addr);
        };
        return null;
    }
};

const Reader = struct {
    bytes: []const u8,
    endian: std.builtin.Endian,
    fn int(r: Reader, comptime T: type, off: usize) T {
        return std.mem.readInt(T, r.bytes[off..][0..@sizeOf(T)], r.endian);
    }
};

/// Parse an ELF file. `segments` and `sections` are caller storage (`max_headers` each is
/// always enough).
pub fn parse(io: Io, src: Source, segments: []Segment, sections: []Section) Error!Info {
    const file_size = src.len() orelse return error.NotElf;
    var hdr: [64]u8 = undefined;
    const got = src.readAt(io, 0, &hdr) catch return error.Truncated;
    if (got < 16 or !std.mem.eql(u8, hdr[0..4], "\x7fELF")) return error.NotElf;
    const is64 = switch (hdr[4]) {
        1 => false,
        2 => true,
        else => return error.BadHeader,
    };
    const endian: std.builtin.Endian = switch (hdr[5]) {
        1 => .little,
        2 => .big,
        else => return error.BadHeader,
    };
    if (got < @as(usize, if (is64) 64 else 52)) return error.Truncated;
    const r: Reader = .{ .bytes = &hdr, .endian = endian };
    var info: Info = .{
        .is64 = is64,
        .endian = endian,
        .type = r.int(u16, 16),
        .machine = r.int(u16, 18),
        .entry = if (is64) r.int(u64, 24) else r.int(u32, 24),
        .ep_offset = null,
        .segments = segments[0..0],
        .sections = sections[0..0],
        .anomalies = .{},
    };
    const phoff: u64 = if (is64) r.int(u64, 32) else r.int(u32, 28);
    const shoff: u64 = if (is64) r.int(u64, 40) else r.int(u32, 32);
    const phentsize = r.int(u16, if (is64) 54 else 42);
    const phnum = r.int(u16, if (is64) 56 else 44);
    const shentsize = r.int(u16, if (is64) 58 else 46);
    const shnum = r.int(u16, if (is64) 60 else 48);

    // Program headers.
    const ph_len: u16 = if (is64) 56 else 32;
    if (phnum != 0 and phentsize >= ph_len) {
        const n = @min(phnum, segments.len);
        var count: usize = 0;
        for (0..n) |i| {
            var b: [56]u8 = undefined;
            const off = phoff +| @as(u64, i) * phentsize;
            src.readAllAt(io, off, b[0..ph_len]) catch {
                info.anomalies.headers_truncated = true;
                break;
            };
            const p: Reader = .{ .bytes = &b, .endian = endian };
            const s: Segment = if (is64) .{
                .type = p.int(u32, 0),
                .flags = p.int(u32, 4),
                .offset = p.int(u64, 8),
                .vaddr = p.int(u64, 16),
                .filesz = p.int(u64, 32),
                .memsz = p.int(u64, 40),
            } else .{
                .type = p.int(u32, 0),
                .offset = p.int(u32, 4),
                .vaddr = p.int(u32, 8),
                .filesz = p.int(u32, 16),
                .memsz = p.int(u32, 20),
                .flags = p.int(u32, 24),
            };
            if (s.type == Segment.load) {
                if (s.flags & Segment.x != 0 and s.flags & Segment.w != 0) info.anomalies.write_exec_segment = true;
                if (s.offset > file_size or s.filesz > file_size - s.offset) info.anomalies.data_beyond_eof = true;
            }
            segments[count] = s;
            count += 1;
        }
        info.segments = segments[0..count];
    }

    // Section headers.
    const sh_len: u16 = if (is64) 64 else 40;
    if (shnum != 0 and shentsize >= sh_len and shoff != 0) {
        const n = @min(shnum, sections.len);
        var count: usize = 0;
        for (0..n) |i| {
            var b: [64]u8 = undefined;
            const off = shoff +| @as(u64, i) * shentsize;
            src.readAllAt(io, off, b[0..sh_len]) catch {
                info.anomalies.headers_truncated = true;
                break;
            };
            const p: Reader = .{ .bytes = &b, .endian = endian };
            const s: Section = if (is64) .{
                .name_off = p.int(u32, 0),
                .type = p.int(u32, 4),
                .flags = p.int(u64, 8),
                .addr = p.int(u64, 16),
                .offset = p.int(u64, 24),
                .size = p.int(u64, 32),
            } else .{
                .name_off = p.int(u32, 0),
                .type = p.int(u32, 4),
                .flags = p.int(u32, 8),
                .addr = p.int(u32, 12),
                .offset = p.int(u32, 16),
                .size = p.int(u32, 20),
            };
            if (s.type != Section.nobits and (s.offset > file_size or s.size > file_size - s.offset)) info.anomalies.data_beyond_eof = true;
            sections[count] = s;
            count += 1;
        }
        info.sections = sections[0..count];
    }
    if (info.entry != 0) {
        info.ep_offset = info.vaddrToOffset(info.entry);
        if (info.ep_offset == null) info.anomalies.ep_outside_segments = true;
    }
    return info;
}

/// Scan an ELF: parse and report damage. ELF files carry no embedded children worth recursing
/// into; the matcher uses `Info` for EP- and section-relative offsets.
pub fn walk(w: *Walker, src: Source) container.Error!void {
    const segments = w.alloc(Segment, max_headers) orelse return;
    const sections = w.alloc(Section, max_headers) orelse return;
    const info = parse(w.io, src, segments, sections) catch return w.notice(.malformed, "elf: header");
    if (info.anomalies.headers_truncated or info.anomalies.data_beyond_eof) w.notice(.malformed, "elf: headers or data beyond end of file");
    heuristics.reportAll(w, &.{
        .{ info.anomalies.ep_outside_segments, .elf_entry_outside_segments },
        .{ info.anomalies.write_exec_segment, .elf_write_exec_segment },
    });
}

const fixtures = @import("fixtures/fixtures.zig");

test "ELF fixtures: entry point and headers" {
    var segments: [max_headers]Segment = undefined;
    var sections: [max_headers]Section = undefined;
    var seen: usize = 0;
    for (fixtures.exes) |e| {
        if (!std.mem.endsWith(u8, e.name, ".elf")) continue;
        seen += 1;
        const info = try parse(std.testing.io, .{ .memory = e.bytes }, &segments, &sections);
        std.testing.expectEqual(e.entry, info.ep_offset) catch |err| {
            std.debug.print("{s}\n", .{e.name});
            return err;
        };
        if (!e.malformed) try std.testing.expectEqual(e.sections, info.sections.len);
    }
    try std.testing.expect(seen >= 3);
}
