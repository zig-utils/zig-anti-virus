//! ANCHORED_INDEX: signatures pinned to an offset (absolute, EOF-n, EP+n, Sx+n, SEx, SL+n) are
//! checked where they must start instead of being scanned for (docs/DESIGN.md 3.4, 5).
//!
//! One section per partition (variant = target type). Programs are grouped by their offset
//! (kind, value, section); a group costs one window resolution per file, however many
//! signatures it holds. Inside a group, programs whose first four bytes are literal and whose
//! maxshift is 0 are keyed by those four bytes in a sorted array: one 4-byte read at the offset
//! and a binary search pick the only candidates worth verifying. The rest (a shift window, or a
//! body that does not start with four literal bytes) sit in the group's list and are verified at
//! every start the window allows.
//!
//! Layout:
//!
//!     AnchorHeader (32 bytes)
//!     groups:  [group_count]Group (32 bytes each)
//!     keyed:   [keyed_count]Keyed {key u32, prog u32}, sorted by key inside each group
//!     list:    [list_count]u32 program indices
const std = @import("std");
const ir = @import("../compile/ir.zig");
const prog = @import("prog.zig");
const vm = @import("verify_vm.zig");

pub const AnchorHeader = extern struct {
    magic: [4]u8 = "ANCH".*,
    version: u32 = 1,
    group_count: u32,
    keyed_count: u32,
    list_count: u32,
    _reserved: [12]u8 = @splat(0),
};

pub const Group = extern struct {
    off_kind: ir.OffsetKind,
    _pad: u8 = 0,
    off_section: u16,
    off_a: i32,
    keyed_first: u32,
    keyed_count: u32,
    list_first: u32,
    list_count: u32,
    _reserved: [8]u8 = @splat(0),

    pub fn offset(g: Group) ir.Offset {
        return .{ .kind = g.off_kind, .a = g.off_a, .section = g.off_section };
    }
};

pub const Keyed = extern struct {
    key: u32,
    prog: u32,
};

comptime {
    std.debug.assert(@sizeOf(AnchorHeader) == 32);
    std.debug.assert(@sizeOf(Group) == 32);
    std.debug.assert(@sizeOf(Keyed) == 8);
}

/// The key a program is filed under, or null if it belongs in its group's list.
pub fn keyOf(p: prog.Program) ?u32 {
    // A whole-section offset (SEx) is a window, not a position.
    if (p.header.off_shift != 0 or p.header.off_kind == .section_entire) return null;
    const first = p.pattern.ops[0];
    if (first.code != .lit or first.len < 4 or first.flags & ir.op_nocase != 0) return null;
    return std.mem.readInt(u32, p.pattern.bytes(first)[0..4], .little);
}

pub fn isAnchored(p: prog.Program) bool {
    return p.header.off_kind != .any;
}

pub const Index = struct {
    groups: []const Group,
    keyed: []const Keyed,
    list: []const u32,

    pub const Error = error{BadAnchoredIndex};

    /// Validate against the programs it refers to: every reference in range, every program in
    /// a group carrying that group's offset, keys sorted and equal to the program's own key.
    pub fn init(section: []const u8, programs: prog.Programs) Error!Index {
        if (section.len < @sizeOf(AnchorHeader) or @intFromPtr(section.ptr) % 4 != 0) return error.BadAnchoredIndex;
        const h: *const AnchorHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "ANCH") or h.version != 1) return error.BadAnchoredIndex;
        const groups_at = @sizeOf(AnchorHeader);
        const keyed_at = groups_at + @as(usize, h.group_count) * @sizeOf(Group);
        const list_at = keyed_at + @as(usize, h.keyed_count) * @sizeOf(Keyed);
        const end = list_at + @as(usize, h.list_count) * 4;
        if (end > section.len) return error.BadAnchoredIndex;
        const g: [*]const Group = @ptrCast(@alignCast(section.ptr + groups_at));
        const k: [*]const Keyed = @ptrCast(@alignCast(section.ptr + keyed_at));
        const l: [*]const u32 = @ptrCast(@alignCast(section.ptr + list_at));
        const index: Index = .{ .groups = g[0..h.group_count], .keyed = k[0..h.keyed_count], .list = l[0..h.list_count] };
        for (index.groups) |grp| {
            if (grp.off_kind == .any or @backingInt(grp.off_kind) > @backingInt(ir.OffsetKind.last_section)) return error.BadAnchoredIndex;
            if (@as(u64, grp.keyed_first) + grp.keyed_count > h.keyed_count) return error.BadAnchoredIndex;
            if (@as(u64, grp.list_first) + grp.list_count > h.list_count) return error.BadAnchoredIndex;
            var prev: u32 = 0;
            for (index.keyed[grp.keyed_first..][0..grp.keyed_count], 0..) |e, i| {
                if (i > 0 and e.key < prev) return error.BadAnchoredIndex;
                prev = e.key;
                const p = try member(programs, e.prog, grp);
                if (keyOf(p) != e.key) return error.BadAnchoredIndex;
            }
            for (index.list[grp.list_first..][0..grp.list_count]) |i| _ = try member(programs, i, grp);
        }
        return index;
    }

    fn member(programs: prog.Programs, i: u32, grp: Group) Error!prog.Program {
        if (i >= programs.count()) return error.BadAnchoredIndex;
        const p = programs.get(i);
        const h = p.header;
        if (h.off_kind != grp.off_kind or h.off_a != grp.off_a or h.off_section != grp.off_section) return error.BadAnchoredIndex;
        // Anchored programs verify from the match start: their anchor is in part 0.
        if (h.anchor_part != 0) return error.BadAnchoredIndex;
        return p;
    }

    /// The keyed entries of `grp` equal to `key`.
    pub fn lookup(index: Index, grp: Group, key: u32) []const Keyed {
        const entries = index.keyed[grp.keyed_first..][0..grp.keyed_count];
        var lo: usize = 0;
        var hi: usize = entries.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (entries[mid].key < key) lo = mid + 1 else hi = mid;
        }
        var end = lo;
        while (end < entries.len and entries[end].key == key) end += 1;
        return entries[lo..end];
    }

    pub fn groupList(index: Index, grp: Group) []const u32 {
        return index.list[grp.list_first..][0..grp.list_count];
    }

    /// Whether program `i` (with its offset and key) can be reached through this index.
    pub fn reaches(index: Index, programs: prog.Programs, i: u32) bool {
        const p = programs.get(i);
        for (index.groups) |grp| {
            if (grp.off_kind != p.header.off_kind or grp.off_a != p.header.off_a or grp.off_section != p.header.off_section) continue;
            if (keyOf(p)) |key| {
                for (index.lookup(grp, key)) |e| if (e.prog == i) return true;
            } else for (index.groupList(grp)) |j| if (j == i) return true;
        }
        return false;
    }
};

pub const Hit = struct {
    /// Program index in SUBSIG_PROG.
    prog: u32,
    match: vm.Match,
};

/// Run every group against one file. `sink` is called with each confirmed match and returns
/// false to stop (an `.ndb` detection) or true to continue (logical subsignatures want all).
pub fn scan(index: Index, programs: prog.Programs, data: []const u8, info: vm.FileInfo, budget: *vm.Budget, context: anytype, comptime sink: fn (@TypeOf(context), Hit) bool) vm.Error!void {
    var memo: vm.Memo = undefined;
    for (index.groups) |grp| {
        const window = vm.startWindow(grp.offset(), info) orelse continue;
        if (grp.keyed_count > 0 and window.lo + 4 <= data.len) {
            const at: usize = @intCast(window.lo);
            const key = std.mem.readInt(u32, data[at..][0..4], .little);
            for (index.lookup(grp, key)) |e| {
                const p = programs.get(e.prog);
                const w = vm.startWindow(p.offset(), info).?;
                if (try verifyOne(p, data, w, at, budget)) |m| if (!sink(context, .{ .prog = e.prog, .match = m })) return;
            }
        }
        for (index.groupList(grp)) |i| {
            const p = programs.get(i);
            const w = vm.startWindow(p.offset(), info) orelse continue;
            memo.prepare(p.header.part_count);
            // A literal first byte picks the starts worth verifying inside the window.
            const head = p.pattern.ops[0];
            const head_byte: ?u8 = if (head.code == .lit and head.flags & ir.op_nocase == 0) p.pattern.bytes(head)[0] else null;
            const hi: usize = @intCast(@min(w.hi, data.len));
            var s: usize = @intCast(@min(w.lo, data.len));
            while (s <= hi) : (s += 1) {
                if (head_byte) |b| s = std.mem.indexOfScalarPos(u8, data[0..@min(data.len, hi + 1)], s, b) orelse break;
                const m = vm.verifyMemo(p, data, w, s, budget, &memo) catch |err| {
                    if (budget.used >= budget.per_file) return err;
                    continue;
                };
                if (m) |hit| if (!sink(context, .{ .prog = i, .match = hit })) return;
            }
        }
    }
}

fn verifyOne(p: prog.Program, data: []const u8, w: vm.Window, at: usize, budget: *vm.Budget) vm.Error!?vm.Match {
    return vm.verify(p, data, w, at, budget) catch |err| {
        if (budget.used >= budget.per_file) return err;
        return null;
    };
}
