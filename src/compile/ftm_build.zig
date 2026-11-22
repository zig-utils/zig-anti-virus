//! Builds the FTM_TRIE section (layout in fmt/ftm.zig) and the verify programs for body-format
//! magics, which go into SUBSIG_PROG variant 1.
const std = @import("std");
const ir = @import("ir.zig");
const ftm = @import("../fmt/ftm.zig");
const prog_build = @import("prog_build.zig");

pub const Built = struct {
    trie: []u8,
    programs: []prog_build.Input,
};

const TempNode = struct {
    children: std.ArrayList(struct { byte: u8, node: u32 }) = .empty,
    entries: std.ArrayList(u32) = .empty,
};

/// `arena` holds every intermediate; the returned slices live in it too.
pub fn build(arena: std.mem.Allocator, rules: []const ir.FtmRule) !Built {
    var entries: std.ArrayList(ftm.FtmEntry) = .empty;
    var inputs: std.ArrayList(prog_build.Input) = .empty;
    for (rules) |r| {
        var e: ftm.FtmEntry = .{ .kind = r.kind, .rtype = r.rtype, .type = r.type, .magic_len = @intCast(@min(r.magic.len, std.math.maxInt(u16))), .offset = r.offset orelse ftm.any_offset };
        if (r.kind == .body) {
            e.prog = @intCast(inputs.items.len);
            const offset = r.body_offset;
            try inputs.append(arena, .{ .pattern = r.pattern.?, .offset = offset, .sig = @intCast(entries.items.len) });
        }
        try entries.append(arena, e);
    }

    // One temporary trie per distinct offset of the literal magics.
    var offsets: std.ArrayList(u32) = .empty;
    for (rules) |r| if (r.kind != .body) {
        if (std.mem.indexOfScalar(u32, offsets.items, r.offset.?) == null) try offsets.append(arena, r.offset.?);
    };
    std.mem.sortUnstable(u32, offsets.items, {}, std.sort.asc(u32));
    var temp: std.ArrayList(TempNode) = .empty;
    var roots: std.ArrayList(u32) = .empty;
    for (offsets.items) |off| {
        const root: u32 = @intCast(temp.items.len);
        try temp.append(arena, .{});
        try roots.append(arena, root);
        for (rules, 0..) |r, i| {
            if (r.kind == .body or r.offset.? != off) continue;
            var node = root;
            for (r.magic) |b| {
                const found = for (temp.items[node].children.items) |ch| {
                    if (ch.byte == b) break ch.node;
                } else null;
                node = found orelse blk: {
                    const n: u32 = @intCast(temp.items.len);
                    try temp.append(arena, .{});
                    try temp.items[node].children.append(arena, .{ .byte = b, .node = n });
                    break :blk n;
                };
            }
            try temp.items[node].entries.append(arena, @intCast(i));
        }
    }

    // Breadth-first numbering so every child comes after its parent.
    const final = try arena.alloc(u32, temp.items.len);
    var order: std.ArrayList(u32) = .empty;
    for (roots.items) |root| {
        const start = order.items.len;
        try order.append(arena, root);
        var q = start;
        while (q < order.items.len) : (q += 1) {
            const kids = temp.items[order.items[q]].children.items;
            std.mem.sortUnstable(@TypeOf(kids[0]), kids, {}, struct {
                fn less(_: void, x: @TypeOf(kids[0]), y: @TypeOf(kids[0])) bool {
                    return x.byte < y.byte;
                }
            }.less);
            for (kids) |k| try order.append(arena, k.node);
        }
    }
    for (order.items, 0..) |t, i| final[t] = @intCast(i);

    var nodes: std.ArrayList(ftm.FtmNode) = .empty;
    var edges: std.ArrayList(ftm.FtmEdge) = .empty;
    for (order.items) |t| {
        const tn = temp.items[t];
        var node: ftm.FtmNode = .{ .first_edge = @intCast(edges.items.len), .edge_count = @intCast(tn.children.items.len), .entry = 0 };
        for (tn.children.items) |k| try edges.append(arena, .{ .byte = k.byte, .child = final[k.node] });
        if (tn.entries.items.len > 0) {
            node.entry = @intCast(tn.entries.items[0] + 1);
            for (tn.entries.items[0 .. tn.entries.items.len - 1], tn.entries.items[1..]) |a, b| entries.items[a].next = b + 1;
        }
        try nodes.append(arena, node);
    }
    var groups: std.ArrayList(ftm.FtmGroup) = .empty;
    for (offsets.items, roots.items) |off, root| try groups.append(arena, .{ .offset = off, .root = final[root] });

    const header: ftm.FtmHeader = .{
        .group_count = @intCast(groups.items.len),
        .node_count = @intCast(nodes.items.len),
        .edge_count = @intCast(edges.items.len),
        .entry_count = @intCast(entries.items.len),
    };
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, std.mem.asBytes(&header));
    try out.appendSlice(arena, std.mem.sliceAsBytes(groups.items));
    try out.appendSlice(arena, std.mem.sliceAsBytes(nodes.items));
    try out.appendSlice(arena, std.mem.sliceAsBytes(edges.items));
    try out.appendSlice(arena, std.mem.sliceAsBytes(entries.items));
    return .{ .trie = out.items, .programs = inputs.items };
}

const testing = std.testing;
const ftm_parse = @import("ftm.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");
const types = @import("../fmt/types.zig");

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    ftm: ftm.Ftm,

    fn deinit(f: *Fixture) void {
        f.arena.deinit();
    }
};

fn fixture(text: []const u8) !Fixture {
    var f: Fixture = .{ .arena = .init(testing.allocator), .ftm = undefined };
    errdefer f.arena.deinit();
    const a = f.arena.allocator();
    var rules: std.ArrayList(ir.FtmRule) = .empty;
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    try ftm_parse.parse(a, a, "test.ftm", text, .{ .rules = &rules, .rejected = &rejected });
    try testing.expectEqual(@as(usize, 0), rejected.items.len);
    const built = try build(a, rules.items);
    const trie = try a.alignedAlloc(u8, .@"4", built.trie.len);
    @memcpy(trie, built.trie);
    var programs: ?prog.Programs = null;
    if (built.programs.len > 0) {
        const bytes = try prog_build.build(a, built.programs);
        const image = try a.alignedAlloc(u8, .@"4", bytes.len);
        @memcpy(image, bytes);
        programs = try prog.Programs.init(image);
    }
    f.ftm = try ftm.Ftm.init(trie, programs);
    return f;
}

test "the trie builds and loads" {
    var f = try fixture(
        \\0:0:4d5a:DOS executable:CL_TYPE_ANY:CL_TYPE_MSEXE
        \\1:*:504b0304:ZIP-SFX:CL_TYPE_MSEXE:CL_TYPE_ZIPSFX
        \\
    );
    defer f.deinit();
    try testing.expectEqual(@as(usize, 2), f.ftm.entries.len);
    _ = vm;
}
