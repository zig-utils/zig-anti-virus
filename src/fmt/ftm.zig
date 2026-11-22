//! File typing with a database's type magics (`.ftm`). The classification functions were
//! removed pending a clean-room rewrite (docs/clean-room.md); this stub keeps the public
//! interface compiling.
//!
//! FTM_TRIE layout (written by compile/ftm_build.zig): an `FtmHeader`, then `group_count`
//! `FtmGroup`s (one trie root per fixed offset), `node_count` `FtmNode`s, `edge_count`
//! `FtmEdge`s and `entry_count` `FtmEntry`s, all little-endian and 4-byte aligned.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");
const types = @import("types.zig");

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
    /// 1 + the index of the first entry ending at this node, 0 for none.
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
    /// 1 + the index of the next entry ending at the same node, 0 for none.
    next: u32 = 0,
    /// Index of the body program in SUBSIG_PROG variant 1 (body kind), else `no_prog`.
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

    pub fn init(section: []const u8, programs: ?prog.Programs) Error!Ftm {
        if (section.len < @sizeOf(FtmHeader) or @intFromPtr(section.ptr) % 4 != 0) return error.BadFtm;
        const h: *align(1) const FtmHeader = @ptrCast(section.ptr);
        if (!std.mem.eql(u8, &h.magic, "FTMT") or h.version != 1) return error.BadFtm;
        var off: usize = @sizeOf(FtmHeader);
        const groups = try take(FtmGroup, section, &off, h.group_count);
        const nodes = try take(FtmNode, section, &off, h.node_count);
        const edges = try take(FtmEdge, section, &off, h.edge_count);
        const entries = try take(FtmEntry, section, &off, h.entry_count);
        for (groups) |g| if (g.root >= nodes.len) return error.BadFtm;
        for (nodes) |n| {
            if (@as(u64, n.first_edge) + n.edge_count > edges.len) return error.BadFtm;
            if (n.entry > entries.len) return error.BadFtm;
        }
        for (edges) |e| if (e.child >= nodes.len) return error.BadFtm;
        for (entries) |e| {
            if (e.next > entries.len) return error.BadFtm;
            if (e.prog != no_prog) {
                const p = programs orelse return error.BadFtm;
                if (e.prog >= p.count()) return error.BadFtm;
            }
        }
        return .{ .groups = groups, .nodes = nodes, .edges = edges, .entries = entries, .programs = programs };
    }

    fn take(comptime T: type, section: []const u8, off: *usize, count: u32) Error![]const T {
        const bytes = std.math.mul(usize, count, @sizeOf(T)) catch return error.BadFtm;
        if (bytes > section.len - off.*) return error.BadFtm;
        const ptr: [*]const T = @ptrCast(@alignCast(section.ptr + off.*));
        off.* += bytes;
        return ptr[0..count];
    }
};

pub const Trigger = struct { type: types.ClType, offset: usize };
pub const max_triggers = 16;

pub const Classification = struct {
    type: types.ClType,
    by_magic: bool,
    triggers: [max_triggers]Trigger = undefined,
    trigger_count: u8 = 0,

    pub fn embedded(c: *const Classification) []const Trigger {
        return c.triggers[0..c.trigger_count];
    }
};

pub const Options = struct {
    partitions: bool = false,
    file_size: ?u64 = null,
};

pub fn textType(head: []const u8) types.ClType {
    _ = head;
    return .binary_data;
}

pub fn clamRank(t: types.ClType) u16 {
    _ = t;
    return 0;
}

pub fn embeddedType(f: Ftm, data: []const u8, base: types.ClType, whole: bool, budget: *vm.Budget) types.ClType {
    _ = f;
    _ = data;
    _ = whole;
    _ = budget;
    return base;
}

pub const window_len = 128 * 1024;

pub fn retype(f: Ftm, data: []const u8, base: types.ClType, budget: *vm.Budget) ?types.ClType {
    _ = f;
    _ = data;
    _ = base;
    _ = budget;
    return null;
}

pub fn classify(f: Ftm, head: []const u8, options: Options, budget: *vm.Budget) Classification {
    _ = f;
    _ = options;
    _ = budget;
    return .{ .type = textType(head), .by_magic = false };
}
