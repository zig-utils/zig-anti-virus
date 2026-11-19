//! ANCHORED_INDEX: signatures pinned to an offset (absolute, EOF-n, EP+n, Sx+n, SEx, SL+n) are
//! checked where they must start instead of being scanned for (docs/DESIGN.md 3.4, 5).
//!
//! One section per partition (variant = target type). Programs are grouped by their offset
//! (kind, value, section); a group costs one window resolution per file, however many
//! signatures it holds. Inside a group, programs whose first four bytes are literal and whose
//! maxshift is 0 are keyed by those four bytes in a sorted array: one 4-byte read at the offset
//! and a binary search pick the only candidates worth verifying. The rest (a shift window, or a
//! body that does not start with four literal bytes) sit in the group's list and are verified at
//! every start the window allows where their anchor literal occurs (found by a whole-literal
//! search).
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
            var memo_ready = false;
            const hi: usize = @intCast(@min(w.hi, data.len));
            var s: usize = @intCast(@min(w.lo, data.len));
            // The anchor literal (in the first part, at a fixed distance from the start) picks
            // the starts worth verifying inside the window: its first byte found with memchr,
            // then the whole literal compared, where a first byte of 00 or ff alone would stop
            // at most bytes of a PE header. (std.mem.indexOfPos builds a skip table per call,
            // which costs more than the search over the short windows most files give.)
            const h = p.header;
            const anchor: ?ir.Op = if (h.anchor_op != prog.no_anchor) p.pattern.ops[h.anchor_op] else null;
            while (s <= hi) : (s += 1) {
                if (anchor) |o| {
                    const lit = p.pattern.bytes(o);
                    const hay = data[0..@min(data.len, hi + h.anchor_delta + lit.len)];
                    const from = s + h.anchor_delta;
                    if (from + lit.len > hay.len) break;
                    const at = (if (o.flags & ir.op_nocase == 0)
                        findLiteral(hay, from, lit)
                    else
                        std.ascii.findIgnoreCasePos(hay, from, lit)) orelse break;
                    s = at - h.anchor_delta;
                }
                if (!memo_ready) {
                    memo.prepare(p.header.part_count);
                    memo_ready = true;
                }
                const m = vm.verifyMemo(p, data, w, s, budget, &memo) catch |err| {
                    if (budget.used >= budget.per_file) return err;
                    continue;
                };
                if (m) |hit| if (!sink(context, .{ .prog = i, .match = hit })) return;
            }
        }
    }
}

/// The first occurrence of `lit` in `hay` at or after `from`: memchr on its first byte, then a
/// compare.
fn findLiteral(hay: []const u8, from: usize, lit: []const u8) ?usize {
    if (lit.len == 1) return std.mem.findScalarPos(u8, hay, from, lit[0]);
    var at = from;
    while (at + lit.len <= hay.len) : (at += 1) {
        at = std.mem.indexOfScalarPos(u8, hay[0 .. hay.len - lit.len + 1], at, lit[0]) orelse return null;
        if (std.mem.eql(u8, hay[at..][0..lit.len], lit)) return at;
    }
    return null;
}

fn verifyOne(p: prog.Program, data: []const u8, w: vm.Window, at: usize, budget: *vm.Budget) vm.Error!?vm.Match {
    return vm.verify(p, data, w, at, budget) catch |err| {
        if (budget.used >= budget.per_file) return err;
        return null;
    };
}

const testing = std.testing;

const TestHits = struct {
    hits: [2048]Hit = undefined,
    len: usize = 0,

    fn add(out: *TestHits, hit: Hit) bool {
        out.hits[out.len] = hit;
        out.len += 1;
        return true;
    }
};

/// Independently resolve each program's full offset and enumerate its VM matches. Keep the
/// index's observable group/member ordering, but do not use scan's window or literal search.
fn referenceHits(index: Index, programs: prog.Programs, data: []const u8, info: vm.FileInfo, out: *TestHits) !void {
    var budget: vm.Budget = .{};
    for (index.groups) |grp| {
        const window = vm.startWindow(grp.offset(), info) orelse continue;
        if (grp.keyed_count > 0 and window.lo + 4 <= data.len) {
            const at: usize = @intCast(window.lo);
            const key = std.mem.readInt(u32, data[at..][0..4], .little);
            for (index.lookup(grp, key)) |e| {
                var scanner = vm.Scanner.init(programs.get(e.prog), data, info, &budget);
                while (try scanner.next()) |m| _ = TestHits.add(out, .{ .prog = e.prog, .match = m });
            }
        }
        for (index.groupList(grp)) |i| {
            var scanner = vm.Scanner.init(programs.get(i), data, info, &budget);
            while (try scanner.next()) |m| _ = TestHits.add(out, .{ .prog = i, .match = m });
        }
    }
}

test "anchored scan preserves every ordered match across offset windows" {
    const hexsig = @import("../compile/hexsig.zig");
    const prog_build = @import("../compile/prog_build.zig");
    const anchored_build = @import("../compile/anchored_build.zig");
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var inputs: std.ArrayList(prog_build.Input) = .empty;
    const offsets: []const ir.Offset = &.{
        .{ .kind = .absolute, .a = 0 },
        .{ .kind = .absolute, .a = -1 },
        .{ .kind = .absolute, .a = 20 },
        .{ .kind = .eof_minus, .a = 8 },
        .{ .kind = .eof_minus, .a = 21 },
        .{ .kind = .entry_point, .a = -4 },
        .{ .kind = .entry_point, .a = 0 },
        .{ .kind = .section_start, .section = 0, .a = 0 },
        .{ .kind = .section_start, .section = 1, .a = -4 },
        .{ .kind = .section_start, .section = 2, .a = 0 },
        .{ .kind = .section_entire, .section = 0 },
        .{ .kind = .section_entire, .section = 1 },
        .{ .kind = .section_entire, .section = 2 },
        .{ .kind = .last_section, .a = -4 },
        .{ .kind = .last_section, .a = 0 },
    };
    for (offsets) |offset| {
        // The same group has keyed and listed members, and different inclusive shift limits.
        for ([_]u32{ 0, 1, 4, std.math.maxInt(u32) }) |shift| {
            var off = offset;
            off.shift = shift;
            for ([_][]const u8{ "41424344", "41??4344", "??4142" }) |body| {
                var diag: hexsig.Diag = .{};
                try inputs.append(a, .{ .pattern = try hexsig.parse(a, body, &diag), .offset = off, .sig = @intCast(inputs.items.len) });
            }
        }
    }
    const bytes = try prog_build.build(a, inputs.items);
    const aligned = try a.alignedAlloc(u8, .@"4", bytes.len);
    @memcpy(aligned, bytes);
    const programs = try prog.Programs.init(aligned);
    const section = (try anchored_build.build(a, programs, 0)).?;
    const image = try a.alignedAlloc(u8, .@"4", section.len);
    @memcpy(image, section);
    const index = try Index.init(image, programs);
    const data = "ABCDABCDABCDABCDABCD";
    const cases: []const vm.FileInfo = &.{
        .{ .size = data.len, .entry_point = 4, .sections = &.{ .{ .offset = 0, .size = 4 }, .{ .offset = 12, .size = 4 } } },
        .{ .size = data.len }, // Missing EP and sections.
        .{ .size = data.len, .entry_point = 0, .sections = &.{ .{ .offset = 0, .size = 0 }, .{ .offset = 20, .size = 4 } } },
        .{ .size = data.len, .entry_point = 20, .sections = &.{ .{ .offset = 4, .size = std.math.maxInt(u64) }, .{ .offset = 24, .size = 4 } } },
    };
    for (cases) |info| {
        var expected: TestHits = .{};
        try referenceHits(index, programs, data, info, &expected);
        try testing.expect(expected.len > 0);
        var actual: TestHits = .{};
        var budget: vm.Budget = .{};
        try scan(index, programs, data, info, &budget, &actual, TestHits.add);
        try testing.expectEqual(expected.len, actual.len);
        for (expected.hits[0..expected.len], actual.hits[0..actual.len]) |want, got| try testing.expectEqualDeep(want, got);
    }
}
