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
        const w = vm.startWindow(p.offset(), .{ .size = head.len }) orelse continue;
        const m = (vm.verify(p, head, w, @intCast(w.lo), budget) catch null) orelse continue;
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
