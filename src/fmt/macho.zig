//! Mach-O and fat (universal) binaries, written from Apple's <mach-o/loader.h> and <mach-o/fat.h>
//! layouts: 32- and 64-bit images in either byte order, load commands, segments and their
//! sections, and the entry point from LC_MAIN (a file offset) or LC_UNIXTHREAD (the program
//! counter in the thread state, mapped through the segments). Each slice of a fat binary is
//! scanned as a child. Counts are capped and every command is checked against sizeofcmds.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const heuristics = @import("../engine/heuristics.zig");

pub const max_commands = 4096;
pub const max_segments = 256;
pub const max_sections = 1024;
pub const max_slices = 32;

pub const Error = error{ NotMachO, Truncated, BadHeader };

pub const cpu_x86: u32 = 7;
pub const cpu_arm: u32 = 12;
pub const cpu_ppc: u32 = 18;
pub const cpu_abi64: u32 = 0x01000000;

const lc_segment = 0x1;
const lc_unixthread = 0x5;
const lc_segment_64 = 0x19;
const lc_main = 0x80000028;

pub const Segment = struct {
    name: [16]u8,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u32,
};

pub const Section = struct {
    name: [16]u8,
    segment: [16]u8,
    addr: u64,
    size: u64,
    offset: u32,
};

pub const Anomalies = packed struct(u8) {
    ep_outside_segments: bool = false,
    write_exec_segment: bool = false,
    data_beyond_eof: bool = false,
    commands_truncated: bool = false,
    _: u4 = 0,
};

pub const Info = struct {
    is64: bool,
    endian: std.builtin.Endian,
    cputype: u32,
    filetype: u32,
    ncmds: u32,
    /// Entry point as a file offset within this image, when one is declared and maps.
    ep_offset: ?u64,
    segments: []Segment,
    sections: []Section,
    anomalies: Anomalies,

    pub fn vmToOffset(info: *const Info, addr: u64) ?u64 {
        for (info.segments) |s| {
            if (addr >= s.vmaddr and addr - s.vmaddr < s.filesize) return s.fileoff + (addr - s.vmaddr);
        }
        return null;
    }
};

pub fn parse(io: Io, src: Source, segments: []Segment, sections: []Section) Error!Info {
    const file_size = src.len() orelse return error.NotMachO;
    var hdr: [32]u8 = undefined;
    src.readAllAt(io, 0, hdr[0..28]) catch return error.Truncated;
    const magic_le = std.mem.readInt(u32, hdr[0..4], .little);
    const is64, const endian: std.builtin.Endian = switch (magic_le) {
        0xfeedface => .{ false, .little },
        0xfeedfacf => .{ true, .little },
        0xcefaedfe => .{ false, .big },
        0xcffaedfe => .{ true, .big },
        else => return error.NotMachO,
    };
    const rd = struct {
        fn u32at(b: []const u8, off: usize, e: std.builtin.Endian) u32 {
            return std.mem.readInt(u32, b[off..][0..4], e);
        }
        fn u64at(b: []const u8, off: usize, e: std.builtin.Endian) u64 {
            return std.mem.readInt(u64, b[off..][0..8], e);
        }
    };
    var info: Info = .{
        .is64 = is64,
        .endian = endian,
        .cputype = rd.u32at(&hdr, 4, endian),
        .filetype = rd.u32at(&hdr, 12, endian),
        .ncmds = rd.u32at(&hdr, 16, endian),
        .ep_offset = null,
        .segments = segments[0..0],
        .sections = sections[0..0],
        .anomalies = .{},
    };
    const sizeofcmds = rd.u32at(&hdr, 20, endian);
    const cmds_off: u64 = if (is64) 32 else 28;
    if (cmds_off + sizeofcmds > file_size) info.anomalies.commands_truncated = true;
    const cmds_end = @min(cmds_off + sizeofcmds, file_size);

    var nseg: usize = 0;
    var nsect: usize = 0;
    var main_off: ?u64 = null;
    var thread_pc: ?u64 = null;
    var off = cmds_off;
    var i: u32 = 0;
    while (i < @min(info.ncmds, max_commands)) : (i += 1) {
        if (off + 8 > cmds_end) {
            info.anomalies.commands_truncated = true;
            break;
        }
        var lc: [8]u8 = undefined;
        src.readAllAt(io, off, &lc) catch break;
        const cmd = rd.u32at(&lc, 0, endian);
        const size = rd.u32at(&lc, 4, endian);
        if (size < 8 or off + size > cmds_end) {
            info.anomalies.commands_truncated = true;
            break;
        }
        switch (cmd) {
            lc_segment, lc_segment_64 => {
                const seg64 = cmd == lc_segment_64;
                var b: [72]u8 = undefined;
                const seg_len: usize = if (seg64) 72 else 56;
                if (size < seg_len) {
                    info.anomalies.commands_truncated = true;
                    break;
                }
                src.readAllAt(io, off, b[0..seg_len]) catch break;
                const s: Segment = if (seg64) .{
                    .name = b[8..24].*,
                    .vmaddr = rd.u64at(&b, 24, endian),
                    .vmsize = rd.u64at(&b, 32, endian),
                    .fileoff = rd.u64at(&b, 40, endian),
                    .filesize = rd.u64at(&b, 48, endian),
                    .initprot = rd.u32at(&b, 60, endian),
                } else .{
                    .name = b[8..24].*,
                    .vmaddr = rd.u32at(&b, 24, endian),
                    .vmsize = rd.u32at(&b, 28, endian),
                    .fileoff = rd.u32at(&b, 32, endian),
                    .filesize = rd.u32at(&b, 36, endian),
                    .initprot = rd.u32at(&b, 44, endian),
                };
                if (s.initprot & 2 != 0 and s.initprot & 4 != 0) info.anomalies.write_exec_segment = true;
                if (s.fileoff > file_size or s.filesize > file_size - s.fileoff) info.anomalies.data_beyond_eof = true;
                if (nseg < segments.len) {
                    segments[nseg] = s;
                    nseg += 1;
                }
                const nsects = rd.u32at(&b, if (seg64) 64 else 48, endian);
                const sect_len: u64 = if (seg64) 80 else 68;
                const room = (size - seg_len) / sect_len;
                for (0..@min(nsects, room)) |k| {
                    if (nsect >= sections.len) break;
                    var sb: [80]u8 = undefined;
                    src.readAllAt(io, off + seg_len + k * sect_len, sb[0..@intCast(sect_len)]) catch break;
                    sections[nsect] = if (seg64) .{
                        .name = sb[0..16].*,
                        .segment = sb[16..32].*,
                        .addr = rd.u64at(&sb, 32, endian),
                        .size = rd.u64at(&sb, 40, endian),
                        .offset = rd.u32at(&sb, 48, endian),
                    } else .{
                        .name = sb[0..16].*,
                        .segment = sb[16..32].*,
                        .addr = rd.u32at(&sb, 32, endian),
                        .size = rd.u32at(&sb, 36, endian),
                        .offset = rd.u32at(&sb, 40, endian),
                    };
                    nsect += 1;
                }
            },
            lc_main => {
                var b: [16]u8 = undefined;
                if (size >= 24) {
                    src.readAllAt(io, off + 8, &b) catch break;
                    main_off = rd.u64at(&b, 0, endian);
                }
            },
            lc_unixthread => thread_pc = threadPc(io, src, off, size, info.cputype, endian),
            else => {},
        }
        off += size;
    }
    info.segments = segments[0..nseg];
    info.sections = sections[0..nsect];
    if (main_off) |m| {
        info.ep_offset = if (m < file_size) m else null;
    } else if (thread_pc) |pc| {
        info.ep_offset = info.vmToOffset(pc);
    }
    if ((main_off != null or thread_pc != null) and info.ep_offset == null) info.anomalies.ep_outside_segments = true;
    return info;
}

/// The program counter in an LC_UNIXTHREAD's first thread state.
fn threadPc(io: Io, src: Source, off: u64, size: u32, cputype: u32, endian: std.builtin.Endian) ?u64 {
    // cmd, cmdsize, flavor, count, then the state.
    const state = off + 16;
    const reg = struct {
        fn u32_(i: Io, s: Source, at: u64, e: std.builtin.Endian) ?u64 {
            var b: [4]u8 = undefined;
            s.readAllAt(i, at, &b) catch return null;
            return std.mem.readInt(u32, &b, e);
        }
        fn u64_(i: Io, s: Source, at: u64, e: std.builtin.Endian) ?u64 {
            var b: [8]u8 = undefined;
            s.readAllAt(i, at, &b) catch return null;
            return std.mem.readInt(u64, &b, e);
        }
    };
    const at: u64, const wide = switch (cputype) {
        cpu_x86 => .{ 10 * 4, false }, // i386_thread_state: eax..gs, eip is the 11th word
        cpu_x86 | cpu_abi64 => .{ 16 * 8, true }, // x86_thread_state64: rax..r15, rip
        cpu_arm => .{ 15 * 4, false }, // arm_thread_state: r0..r12, sp, lr, pc
        cpu_arm | cpu_abi64 => .{ 32 * 8, true }, // arm_thread_state64: x0..x28, fp, lr, sp, pc
        cpu_ppc => .{ 0, false }, // ppc_thread_state: srr0 first
        cpu_ppc | cpu_abi64 => .{ 0, true },
        else => return null,
    };
    const width: u64 = if (wide) 8 else 4;
    if (16 + at + width > size) return null;
    return if (wide) reg.u64_(io, src, state + at, endian) else reg.u32_(io, src, state + at, endian);
}

pub const Slice = struct { cputype: u32, offset: u64, size: u64 };

/// The architecture slices of a fat binary (big-endian headers; fat_arch or fat_arch_64).
pub fn slices(io: Io, src: Source, out: []Slice) Error![]Slice {
    var hdr: [8]u8 = undefined;
    src.readAllAt(io, 0, &hdr) catch return error.Truncated;
    const magic = std.mem.readInt(u32, hdr[0..4], .big);
    const wide = switch (magic) {
        0xcafebabe => false,
        0xcafebabf => true,
        else => return error.NotMachO,
    };
    const n = std.mem.readInt(u32, hdr[4..8], .big);
    const entry_len: u64 = if (wide) 32 else 20;
    var count: usize = 0;
    for (0..@min(n, out.len)) |i| {
        var b: [32]u8 = undefined;
        src.readAllAt(io, 8 + i * entry_len, b[0..@intCast(entry_len)]) catch return error.Truncated;
        out[count] = .{
            .cputype = std.mem.readInt(u32, b[0..4], .big),
            .offset = if (wide) std.mem.readInt(u64, b[8..16], .big) else std.mem.readInt(u32, b[8..12], .big),
            .size = if (wide) std.mem.readInt(u64, b[16..24], .big) else std.mem.readInt(u32, b[12..16], .big),
        };
        count += 1;
    }
    return out[0..count];
}

pub fn cpuName(cputype: u32) []const u8 {
    return switch (cputype) {
        cpu_x86 => "i386",
        cpu_x86 | cpu_abi64 => "x86_64",
        cpu_arm => "arm",
        cpu_arm | cpu_abi64 => "arm64",
        cpu_ppc => "ppc",
        cpu_ppc | cpu_abi64 => "ppc64",
        else => "unknown",
    };
}

/// Scan a thin Mach-O: parse and report damage.
pub fn walk(w: *Walker, src: Source) container.Error!void {
    const segments = w.alloc(Segment, max_segments) orelse return;
    const sections = w.alloc(Section, max_sections) orelse return;
    const info = parse(w.io, src, segments, sections) catch return w.notice(.malformed, "macho: header");
    if (info.anomalies.commands_truncated or info.anomalies.data_beyond_eof) w.notice(.malformed, "macho: load commands or data beyond end of file");
    heuristics.reportAll(w, &.{
        .{ info.anomalies.ep_outside_segments, .macho_entry_outside_segments },
        .{ info.anomalies.write_exec_segment, .macho_write_exec_segment },
    });
}

/// Scan a fat binary: every slice becomes a child ("slice/<arch>"), so each architecture is
/// matched on its own.
pub fn walkFat(w: *Walker, src: Source) container.Error!void {
    var buf: [max_slices]Slice = undefined;
    const list = slices(w.io, src, &buf) catch return w.notice(.malformed, "macho: fat header");
    const total = src.len().?;
    for (list, 0..) |s, i| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "slice/{s}", .{cpuName(s.cputype)}) catch "slice";
        _ = i;
        if (s.offset >= total or s.size > total - s.offset) {
            w.path.push(name);
            w.notice(.malformed, "macho: fat slice beyond end of file");
            w.path.pop();
            if (s.offset >= total) continue;
        }
        const body = src.slice(s.offset, @min(s.size, total - s.offset)) catch continue;
        try w.child(name, body, .slice);
    }
}

const fixtures = @import("fixtures/fixtures.zig");

test "Mach-O fixtures: entry points from LC_MAIN and LC_UNIXTHREAD" {
    var segments: [max_segments]Segment = undefined;
    var sections: [max_sections]Section = undefined;
    var seen: usize = 0;
    for (fixtures.exes) |e| {
        if (!std.mem.endsWith(u8, e.name, ".macho")) continue;
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
