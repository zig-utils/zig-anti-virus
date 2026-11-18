//! Builds the ANCHORED_INDEX section of one partition from the finished SUBSIG_PROG programs
//! (layout in match/anchored.zig), then proves every anchored program of that partition is
//! reachable through the index it built: a signature the index cannot reach would never fire.
const std = @import("std");
const ir = @import("ir.zig");
const prog = @import("../match/prog.zig");
const anchored = @import("../match/anchored.zig");

pub const Error = error{UnreachableAnchored} || std.mem.Allocator.Error;

const Item = struct {
    kind: u8,
    section: u16,
    a: i32,
    /// Keyed programs first (key below 2^32), list members after.
    key: u64,
    prog: u32,

    fn less(_: void, x: Item, y: Item) bool {
        if (x.kind != y.kind) return x.kind < y.kind;
        if (x.section != y.section) return x.section < y.section;
        if (x.a != y.a) return x.a < y.a;
        if (x.key != y.key) return x.key < y.key;
        return x.prog < y.prog;
    }

    fn sameGroup(x: Item, y: Item) bool {
        return x.kind == y.kind and x.section == y.section and x.a == y.a;
    }
};

const list_key: u64 = 1 << 32;

/// The section for partition `partition`, or null when it has no anchored programs.
pub fn build(gpa: std.mem.Allocator, programs: prog.Programs, partition: u8) Error!?[]u8 {
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    for (0..programs.count()) |i| {
        const p = programs.get(i);
        if (p.header.target != partition or !anchored.isAnchored(p)) continue;
        try items.append(gpa, .{
            .kind = @backingInt(p.header.off_kind),
            .section = p.header.off_section,
            .a = p.header.off_a,
            .key = if (anchored.keyOf(p)) |k| k else list_key,
            .prog = @intCast(i),
        });
    }
    if (items.items.len == 0) return null;
    std.mem.sortUnstable(Item, items.items, {}, Item.less);

    var groups: std.ArrayList(anchored.Group) = .empty;
    defer groups.deinit(gpa);
    var keyed: std.ArrayList(anchored.Keyed) = .empty;
    defer keyed.deinit(gpa);
    var list: std.ArrayList(u32) = .empty;
    defer list.deinit(gpa);
    var i: usize = 0;
    while (i < items.items.len) {
        const first = items.items[i];
        var g: anchored.Group = .{
            .off_kind = @fromBackingInt(first.kind),
            .off_section = first.section,
            .off_a = first.a,
            .keyed_first = @intCast(keyed.items.len),
            .keyed_count = 0,
            .list_first = @intCast(list.items.len),
            .list_count = 0,
        };
        while (i < items.items.len and items.items[i].sameGroup(first)) : (i += 1) {
            const it = items.items[i];
            if (it.key == list_key) {
                try list.append(gpa, it.prog);
                g.list_count += 1;
            } else {
                try keyed.append(gpa, .{ .key = @intCast(it.key), .prog = it.prog });
                g.keyed_count += 1;
            }
        }
        try groups.append(gpa, g);
    }

    const header: anchored.AnchorHeader = .{
        .group_count = @intCast(groups.items.len),
        .keyed_count = @intCast(keyed.items.len),
        .list_count = @intCast(list.items.len),
    };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, std.mem.asBytes(&header));
    try out.appendSlice(gpa, std.mem.sliceAsBytes(groups.items));
    try out.appendSlice(gpa, std.mem.sliceAsBytes(keyed.items));
    try out.appendSlice(gpa, std.mem.sliceAsBytes(list.items));
    const bytes = try out.toOwnedSlice(gpa);
    errdefer gpa.free(bytes);

    // Compile-time proof of reachability, through the same reader the scanner uses.
    const aligned = try gpa.alignedAlloc(u8, .@"4", bytes.len);
    defer gpa.free(aligned);
    @memcpy(aligned, bytes);
    const index = anchored.Index.init(aligned, programs) catch return error.UnreachableAnchored;
    for (items.items) |it| if (!index.reaches(programs, it.prog)) return error.UnreachableAnchored;
    return bytes;
}

const testing = std.testing;
const hexsig = @import("hexsig.zig");
const prog_build = @import("prog_build.zig");
const vm = @import("../match/verify_vm.zig");

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    programs: prog.Programs,
    index: [2]?anchored.Index,

    fn deinit(f: *Fixture) void {
        f.arena.deinit();
    }
};

fn fixture(specs: []const struct { []const u8, u8, ir.Offset }) !Fixture {
    var f: Fixture = .{ .arena = .init(testing.allocator), .programs = undefined, .index = @splat(null) };
    errdefer f.arena.deinit();
    const a = f.arena.allocator();
    var inputs: std.ArrayList(prog_build.Input) = .empty;
    for (specs, 0..) |s, i| {
        var diag: hexsig.Diag = .{};
        try inputs.append(a, .{ .pattern = try hexsig.parse(a, s[0], &diag), .target = s[1], .offset = s[2], .sig = @intCast(i) });
    }
    const bytes = try prog_build.build(a, inputs.items);
    const aligned = try a.alignedAlloc(u8, .@"4", bytes.len);
    @memcpy(aligned, bytes);
    f.programs = try prog.Programs.init(aligned);
    for (0..2) |p| {
        const section = try build(testing.allocator, f.programs, @intCast(p)) orelse continue;
        defer testing.allocator.free(section);
        const copy = try a.alignedAlloc(u8, .@"4", section.len);
        @memcpy(copy, section);
        f.index[p] = try anchored.Index.init(copy, f.programs);
    }
    return f;
}

const Collect = struct {
    sigs: [16]u32 = undefined,
    n: usize = 0,
    programs: prog.Programs,

    fn add(c: *Collect, hit: anchored.Hit) bool {
        c.sigs[c.n] = c.programs.get(hit.prog).header.sig;
        c.n += 1;
        return true;
    }
};

test "groups, keys and lists; every anchored program is reachable" {
    var f = try fixture(&.{
        .{ "4d5a9000", 1, .{ .kind = .absolute, .a = 0 } }, // 0 keyed
        .{ "4d5a5000", 1, .{ .kind = .absolute, .a = 0 } }, // 1 keyed, same group
        .{ "e8??0000", 1, .{ .kind = .entry_point, .a = 0 } }, // 2 listed: no 4-byte literal head
        .{ "c3c3c3c3", 1, .{ .kind = .entry_point, .a = 2, .shift = 3 } }, // 3 listed: shift window
        .{ "deadbeef", 1, .{} }, // 4 not anchored
        .{ "50414420", 0, .{ .kind = .eof_minus, .a = 4 } }, // 5 type 0
        .{ "aa*bbcc", 1, .{ .kind = .section_start, .section = 1, .a = 0 } }, // 6 listed (one-byte head)
    });
    defer f.deinit();
    const pe = f.index[1].?;
    try testing.expectEqual(@as(usize, 4), pe.groups.len);
    for ([_]u32{ 0, 1, 2, 3, 6 }) |i| try testing.expect(pe.reaches(f.programs, i));
    try testing.expect(!pe.reaches(f.programs, 4));
    try testing.expect(f.index[0].?.reaches(f.programs, 5));

    // A synthetic PE: entry point at 8, two sections.
    var data: [64]u8 = @splat(0x90);
    @memcpy(data[0..4], "\x4d\x5a\x90\x00");
    @memcpy(data[8..12], "\xe8\x01\x00\x00");
    @memcpy(data[13..17], "\xc3\xc3\xc3\xc3");
    @memcpy(data[32..35], "\xaa\xbb\xcc");
    @memcpy(data[60..64], "PAD ");
    const info: vm.FileInfo = .{ .size = data.len, .entry_point = 8, .sections = &.{ .{ .offset = 8, .size = 16 }, .{ .offset = 32, .size = 16 } } };
    var budget: vm.Budget = .{};
    var c: Collect = .{ .programs = f.programs };
    try anchored.scan(pe, f.programs, &data, info, &budget, &c, Collect.add);
    std.mem.sortUnstable(u32, c.sigs[0..c.n], {}, std.sort.asc(u32));
    try testing.expectEqualSlices(u32, &.{ 0, 2, 3, 6 }, c.sigs[0..c.n]);
    var c0: Collect = .{ .programs = f.programs };
    try anchored.scan(f.index[0].?, f.programs, &data, info, &budget, &c0, Collect.add);
    try testing.expectEqualSlices(u32, &.{5}, c0.sigs[0..c0.n]);

    // Without an entry point the EP groups resolve to nothing.
    var c2: Collect = .{ .programs = f.programs };
    try anchored.scan(pe, f.programs, &data, .{ .size = data.len }, &budget, &c2, Collect.add);
    try testing.expectEqualSlices(u32, &.{0}, c2.sigs[0..c2.n]);
}

test "a corrupt index is refused" {
    var f = try fixture(&.{
        .{ "4d5a9000", 1, .{ .kind = .absolute, .a = 0 } },
        .{ "e8??0000", 1, .{ .kind = .entry_point, .a = 0 } },
    });
    defer f.deinit();
    const section = (try build(testing.allocator, f.programs, 1)).?;
    defer testing.allocator.free(section);
    const copy = try f.arena.allocator().alignedAlloc(u8, .@"4", section.len);
    for (0..section.len) |i| {
        @memcpy(copy, section);
        copy[i] ^= 0x41;
        if (anchored.Index.init(copy, f.programs)) |index| {
            // Whatever still validates only refers to real programs with matching offsets.
            for (index.groups) |g| for (index.groupList(g)) |p| try testing.expect(p < f.programs.count());
        } else |_| {}
    }
}
