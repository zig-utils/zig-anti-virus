//! File-type classification from the FTM_TRIE section (docs/DESIGN.md sections 3.2 and 5).
//!
//! Layout, little-endian and offset based:
//!
//!     FtmHeader (32 bytes)
//!     groups:  [group_count]FtmGroup {offset u32, root u32}: one byte trie per magic offset
//!     nodes:   [node_count]FtmNode {first_edge u32, edge_count u16, entry u16}
//!     edges:   [edge_count]FtmEdge {byte u8, child u32}, sorted by byte within a node
//!     entries: [entry_count]FtmEntry (24 bytes)
//!
//! Literal magics (magictypes 0 and 4) live in the tries; a node's `entry` starts the chain of
//! entries whose magic ends there. Body-format magics (magictype 1) are verify programs in
//! SUBSIG_PROG variant 1. Classification of the first bytes of a file:
//!
//! 1. Every entry whose rtype is CL_TYPE_ANY competes; the longest match wins (the earliest
//!    entry on ties). Fixed-offset body magics compete with their match length.
//! 2. Entries whose rtype is the type found refine it, the same way, up to a few rounds.
//! 3. With no magic at all the head is classified as ASCII text, UTF-8 text or binary data.
//! 4. Body magics with offset `*` whose rtype is ANY or the final type are embedded-type
//!    triggers: each found in the head is reported with its offset for the container layer.
//!
//! Partition magics (magictype 4) only take part when partitions are being classified.
//! ClamAV documents no priority between overlapping magics; longest-wins is zav's rule and is on
//! the differential list against `clamscan --debug`.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const types = @import("types.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");

pub const FtmHeader = extern struct {
    magic: [4]u8 = "FTMT".*,
    version: u32 = 1,
    group_count: u32,
    node_count: u32,
    edge_count: u32,
    entry_count: u32,
    _reserved: [8]u8 = @splat(0),
};

pub const FtmGroup = extern struct { offset: u32, root: u32 };

pub const FtmNode = extern struct {
    first_edge: u32,
    edge_count: u16,
    /// First entry ending at this node, plus one; 0 for none.
    entry: u16,
};

pub const FtmEdge = extern struct {
    byte: u8,
    _pad: [3]u8 = @splat(0),
    child: u32,
};

pub const any_offset: u32 = 0xffff_ffff;
pub const no_prog: u32 = 0xffff_ffff;

pub const FtmEntry = extern struct {
    kind: ir.MagicKind,
    _pad: u8 = 0,
    rtype: u16,
    type: u16,
    magic_len: u16,
    /// Next entry with the same magic, plus one; 0 ends the chain.
    next: u32 = 0,
    /// Body magics: program index in SUBSIG_PROG variant 1.
    prog: u32 = no_prog,
    offset: u32,
    _reserved: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(FtmHeader) == 32);
    std.debug.assert(@sizeOf(FtmGroup) == 8);
    std.debug.assert(@sizeOf(FtmNode) == 8);
    std.debug.assert(@sizeOf(FtmEdge) == 8);
    std.debug.assert(@sizeOf(FtmEntry) == 24);
}

pub const Ftm = struct {
    groups: []const FtmGroup,
    nodes: []const FtmNode,
    edges: []const FtmEdge,
    entries: []const FtmEntry,
    programs: ?prog.Programs,

    pub const Error = error{BadFtm};

    /// Validate: references in range, children after their parents (no cycles), edges sorted,
    /// chains moving forward, body entries pointing at real programs and never into a trie.
    pub fn init(section: []const u8, programs: ?prog.Programs) Error!Ftm {
        if (section.len < @sizeOf(FtmHeader) or @intFromPtr(section.ptr) % 4 != 0) return error.BadFtm;
        const h: *const FtmHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "FTMT") or h.version != 1) return error.BadFtm;
        const g_at = @sizeOf(FtmHeader);
        const n_at = g_at + @as(usize, h.group_count) * @sizeOf(FtmGroup);
        const e_at = n_at + @as(usize, h.node_count) * @sizeOf(FtmNode);
        const en_at = e_at + @as(usize, h.edge_count) * @sizeOf(FtmEdge);
        if (en_at + @as(usize, h.entry_count) * @sizeOf(FtmEntry) > section.len) return error.BadFtm;
        if (h.entry_count > std.math.maxInt(u16)) return error.BadFtm;
        const g: [*]const FtmGroup = @ptrCast(@alignCast(section.ptr + g_at));
        const n: [*]const FtmNode = @ptrCast(@alignCast(section.ptr + n_at));
        const e: [*]const FtmEdge = @ptrCast(@alignCast(section.ptr + e_at));
        const en: [*]const FtmEntry = @ptrCast(@alignCast(section.ptr + en_at));
        const f: Ftm = .{ .groups = g[0..h.group_count], .nodes = n[0..h.node_count], .edges = e[0..h.edge_count], .entries = en[0..h.entry_count], .programs = programs };
        for (f.groups) |grp| if (grp.root >= h.node_count) return error.BadFtm;
        for (f.nodes, 0..) |node, i| {
            if (@as(u64, node.first_edge) + node.edge_count > h.edge_count) return error.BadFtm;
            if (node.entry > h.entry_count) return error.BadFtm;
            if (node.entry != 0 and f.entries[node.entry - 1].kind == .body) return error.BadFtm;
            var prev: i16 = -1;
            for (f.edges[node.first_edge..][0..node.edge_count]) |edge| {
                if (edge.child <= i or edge.child >= h.node_count) return error.BadFtm;
                if (@as(i16, edge.byte) <= prev) return error.BadFtm;
                prev = edge.byte;
            }
        }
        const nprog = if (programs) |ps| ps.count() else 0;
        for (f.entries, 0..) |entry, i| {
            switch (entry.kind) {
                .bytes, .partition => if (entry.prog != no_prog or entry.offset == any_offset) return error.BadFtm,
                .body => if (entry.prog >= nprog) return error.BadFtm,
                _ => return error.BadFtm,
            }
            if (entry.next != 0 and (entry.next - 1 <= i or entry.next > h.entry_count)) return error.BadFtm;
        }
        return f;
    }
};

pub const Trigger = struct { type: types.ClType, offset: usize };
pub const max_triggers = 16;

pub const Classification = struct {
    type: types.ClType,
    /// Whether a magic decided the type (false: the text heuristic did).
    by_magic: bool,
    triggers: [max_triggers]Trigger = undefined,
    trigger_count: u8 = 0,

    pub fn embedded(c: *const Classification) []const Trigger {
        return c.triggers[0..c.trigger_count];
    }
};

pub const Options = struct {
    /// Classify partition types (magictype 4) instead of file types.
    partitions: bool = false,
    /// The whole file's size, when known: EOF-relative magics only apply when the head is
    /// the whole file.
    file_size: ?u64 = null,
};

const Best = struct {
    len: usize = 0,
    entry: ?usize = null,

    fn offer(b: *Best, len: usize, entry: usize) void {
        if (b.entry == null or len > b.len or (len == b.len and entry < b.entry.?)) {
            b.len = len;
            b.entry = entry;
        }
    }
};

fn wanted(entry: FtmEntry, rtype: u16, options: Options) bool {
    if (entry.rtype != rtype) return false;
    return switch (entry.kind) {
        .partition => options.partitions,
        .bytes, .body => !options.partitions,
        _ => false,
    };
}

/// One round: the longest magic among entries requiring `rtype`.
fn round(f: Ftm, head: []const u8, rtype: u16, options: Options, budget: *vm.Budget) ?usize {
    var best: Best = .{};
    for (f.groups) |grp| {
        if (grp.offset >= head.len) continue;
        var node = f.nodes[grp.root];
        var depth: usize = 0;
        while (true) {
            var e = node.entry;
            while (e != 0) : (e = @intCast(f.entries[e - 1].next)) {
                if (wanted(f.entries[e - 1], rtype, options)) best.offer(depth, e - 1);
            }
            const at = grp.offset + depth;
            if (at >= head.len or node.edge_count == 0) break;
            const edges = f.edges[node.first_edge..][0..node.edge_count];
            const next = for (edges) |edge| {
                if (edge.byte == head[at]) break edge.child;
            } else break;
            node = f.nodes[next];
            depth += 1;
        }
    }
    if (f.programs) |ps| for (f.entries, 0..) |entry, i| {
        if (entry.kind != .body or entry.offset == any_offset or !wanted(entry, rtype, options)) continue;
        const p = ps.get(entry.prog);
        // An EOF-relative magic needs the file's end; it applies when the head is the file.
        if (p.offset().kind == .eof_minus and options.file_size != head.len) continue;
        var s = vm.Scanner.init(p, head, .{ .size = head.len }, budget);
        const m = (s.next() catch null) orelse continue;
        best.offer(m.end - m.start, i);
    };
    return best.entry;
}

fn textType(head: []const u8) types.ClType {
    var ascii = true;
    for (head) |b| {
        if (b == 0) return .binary_data;
        if (b < 0x20 and b != '\t' and b != '\n' and b != '\r' and b != 0x0c and b != 0x1b) return .binary_data;
        if (b >= 0x80) ascii = false;
    }
    if (ascii) return .text_ascii;
    return if (std.unicode.utf8ValidateSlice(head)) .text_utf8 else .binary_data;
}

/// A file type's place in libclamav's enum (filetypes.h, CL_TYPENO = 500 onwards). libclamav
/// decides between the type magics matching one buffer by that order, so zav needs it too.
pub fn clamRank(t: types.ClType) u16 {
    return switch (t) {
        .any => 0,
        .text_ascii => 500,
        .text_utf8 => 501,
        .text_utf16le => 502,
        .text_utf16be => 503,
        .binary_data => 504,
        .msexe => 506,
        .elf => 507,
        .macho => 508,
        .macho_unibin => 509,
        .posix_tar => 510,
        .old_tar => 511,
        .cpio_old => 512,
        .cpio_odc => 513,
        .cpio_newc => 514,
        .cpio_crc => 515,
        .gz => 516,
        .zip => 517,
        .bz => 518,
        .rar => 519,
        .arj => 520,
        .msszdd => 521,
        .msole2 => 522,
        .mscab => 523,
        .mschm => 524,
        .sis => 525,
        .screnc => 526,
        .graphics => 527,
        .gif => 528,
        .png => 529,
        .jpeg => 530,
        .tiff => 531,
        .riff => 532,
        .binhex => 533,
        .tnef => 534,
        .cryptff => 535,
        .pdf => 536,
        .uuencoded => 537,
        .script => 538,
        .html_utf16 => 539,
        .rtf => 540,
        .@"7z" => 541,
        .swf => 542,
        .java => 543,
        .xar => 544,
        .xz => 545,
        .ooxml_word => 546,
        .ooxml_ppt => 547,
        .ooxml_xl => 548,
        .internal => 549,
        .hwp3 => 550,
        .ooxml_hwp => 551,
        .ps => 552,
        .egg => 553,
        .onenote => 554,
        .python_compiled => 555,
        .lha_lzh => 556,
        .part_any => 558,
        .part_hfsplus => 559,
        .mbr => 560,
        .html => 561,
        .mail => 562,
        .zipsfx => 564,
        .rarsfx => 565,
        .@"7zsfx" => 566,
        .cabsfx => 567,
        .arjsfx => 568,
        .nulsft => 570,
        .autoit => 571,
        .ishield_msi => 572,
        .iso9660 => 573,
        .dmg => 574,
        .gpt => 575,
        .apm => 576,
        .xdp => 577,
        .xml_word => 578,
        .xml_xl => 579,
        .xml_hwp => 580,
        .hwpole2 => 581,
        .mhtml => 582,
        .lnk => 583,
        .udf => 584,
        .alz => 585,
        .ignored => 587,
        else => 0,
    };
}

const rank_sfx = 563;

/// libclamav's embedded-type re-typing (cli_determine_fmap_type and scanraw): the body magics
/// whose required type is ANY or `base` are searched in `data`, and in the order the matches end
/// a match takes over when its type comes later in libclamav's enum, is an SFX type or later, or
/// is CL_TYPE_MSEXE; CL_TYPE_IGNORED ends the search. Only the last match of each magic matters
/// for that rule, so no list of matches is kept.
///
/// `whole`: `data` is the whole object, so EOF-relative magics apply (scanraw); the head that
/// cli_determine_fmap_type reads (1024 bytes) passes false, since libclamav computes no relative
/// offsets for it. Returns the type the matches settle on (CL_TYPE_ANY when none matched).
pub fn embeddedType(f: Ftm, data: []const u8, base: types.ClType, whole: bool, budget: *vm.Budget) types.ClType {
    const ps = f.programs orelse return .any;
    const Last = struct { end: usize, entry: usize, rank: u16, t: types.ClType };
    var last_sticky: ?Last = null;
    // Up to the last sticky match only the sticky ones decide; after it, larger types still win.
    var best_any: ?Last = null;
    const later = struct {
        fn after(a: Last, b: Last) bool {
            return a.end > b.end or (a.end == b.end and a.entry > b.entry);
        }
    }.after;
    var ends: [256]?Last = @splat(null);
    var count: usize = 0;
    for (f.entries, 0..) |entry, i| {
        if (entry.kind != .body) continue;
        if (entry.rtype != 0 and entry.rtype != @backingInt(base)) continue;
        const p = ps.get(entry.prog);
        switch (p.offset().kind) {
            .any, .absolute => {},
            .eof_minus => if (!whole) continue,
            else => continue,
        }
        var scanner = vm.Scanner.init(p, data, .{ .size = data.len }, budget);
        var end: ?usize = null;
        while (scanner.next() catch null) |m| end = m.end;
        const e = end orelse continue;
        const t: types.ClType = @fromBackingInt(entry.type);
        if (t == .ignored) return .ignored;
        const l: Last = .{ .end = e, .entry = i, .rank = clamRank(t), .t = t };
        if (l.rank >= rank_sfx or t == .msexe) {
            if (last_sticky == null or later(l, last_sticky.?)) last_sticky = l;
        } else if (count < ends.len) {
            ends[count] = l;
            count += 1;
        }
        if (best_any == null or l.rank > best_any.?.rank) best_any = l;
    }
    const s = last_sticky orelse return if (best_any) |b| b.t else .any;
    var result = s;
    if (s.t == .msexe) for (ends[0..count]) |maybe| {
        const l = maybe.?;
        if (later(l, s) and l.rank > result.rank) result = l;
    };
    return result.t;
}

/// cli_determine_fmap_type's correction of a text or binary-data file (`base`) from the first
/// 1024 bytes: the embedded type when one matched and it is not a self-extractor (those are
/// found by the raw scan), else null. HTML is what makes the difference in practice: binary
/// data with an HTML tag near its start is scanned as HTML, so its raw bytes are not matched.
pub fn retype(f: Ftm, data: []const u8, base: types.ClType, budget: *vm.Budget) ?types.ClType {
    const t = embeddedType(f, data[0..@min(data.len, retype_window)], base, false, budget);
    return switch (t) {
        .any, .zipsfx, .arjsfx, .rarsfx, .cabsfx, .@"7zsfx" => null,
        else => t,
    };
}

/// How much of a file cli_determine_fmap_type types (CL_FILE_MBUFF_SIZE).
pub const retype_window = 1024;

/// Classify a file from its first bytes (4 KiB is plenty).
pub fn classify(f: Ftm, head: []const u8, options: Options, budget: *vm.Budget) Classification {
    var c: Classification = .{ .type = .binary_data, .by_magic = false };
    var current: u16 = @backingInt(types.ClType.any);
    // Up to four refinement rounds: ANY, then the type found, and so on.
    for (0..4) |_| {
        const e = round(f, head, current, options, budget) orelse break;
        const next = f.entries[e].type;
        if (next == current) break;
        current = next;
        c.by_magic = true;
    }
    c.type = if (c.by_magic) @fromBackingInt(current) else if (options.partitions) .any else textType(head);

    if (f.programs) |ps| for (f.entries) |entry| {
        if (entry.kind != .body or entry.offset != any_offset) continue;
        if (entry.rtype != 0 and entry.rtype != @backingInt(c.type)) continue;
        if (c.trigger_count == max_triggers) break;
        var scanner = vm.Scanner.init(ps.get(entry.prog), head, .{ .size = head.len }, budget);
        const m = (scanner.next() catch null) orelse continue;
        c.triggers[c.trigger_count] = .{ .type = @fromBackingInt(entry.type), .offset = m.start };
        c.trigger_count += 1;
    };
    return c;
}
