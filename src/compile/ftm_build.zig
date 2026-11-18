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

fn kind(f: *const Fixture, head: []const u8) types.ClType {
    var budget: vm.Budget = .{};
    return ftm.classify(f.ftm, head, .{}, &budget).type;
}

test "overlapping magics: longest literal wins, rtype refines, body magics re-type" {
    var f = try fixture(
        \\0:0:4d5a:DOS executable:CL_TYPE_ANY:CL_TYPE_MSEXE
        \\0:0:504b0304:ZIP:CL_TYPE_ANY:CL_TYPE_ZIP
        \\0:0:504b:PK short:CL_TYPE_ANY:CL_TYPE_BINARY_DATA
        \\0:0:474946383961:GIF89a:CL_TYPE_ANY:CL_TYPE_GIF
        \\0:0:47494638:GIF8:CL_TYPE_ANY:CL_TYPE_GRAPHICS
        \\0:0:25504446:PDF:CL_TYPE_ANY:CL_TYPE_PDF
        \\0:257:7573746172:POSIX tar:CL_TYPE_ANY:CL_TYPE_POSIX_TAR
        \\0:0:7f454c46:ELF:CL_TYPE_ANY:CL_TYPE_ELF
        \\0:0:7f454c4601:ELF again:CL_TYPE_ANY:CL_TYPE_ELF
        \\1:0:3c68746d6c3e:HTML:CL_TYPE_ANY:CL_TYPE_HTML
        \\1:0:3c68{1}6d:HTML-ish:CL_TYPE_ANY:CL_TYPE_SCRIPT
        \\0:2:4e756c6c736f6674:NSIS in PE:CL_TYPE_MSEXE:CL_TYPE_NULSFT
        \\1:*:504b0304:ZIP-SFX:CL_TYPE_MSEXE:CL_TYPE_ZIPSFX
        \\1:*:255044462d:embedded PDF:CL_TYPE_ANY:CL_TYPE_PDF
        \\
    );
    defer f.deinit();
    try std.testing.expectEqual(types.ClType.zip, kind(&f, "PK\x03\x04rest"));
    try std.testing.expectEqual(types.ClType.binary_data, kind(&f, "PKxx"));
    try std.testing.expectEqual(types.ClType.gif, kind(&f, "GIF89a..."));
    try std.testing.expectEqual(types.ClType.graphics, kind(&f, "GIF87a..."));
    try std.testing.expectEqual(types.ClType.elf, kind(&f, "\x7fELF\x02"));
    // Body magics do not classify; they re-type text and binary data, and when several match
    // the type later in libclamav's order wins (HTML over SCRIPT).
    try std.testing.expectEqual(types.ClType.text_ascii, kind(&f, "<html>"));
    var rb: vm.Budget = .{};
    try std.testing.expectEqual(types.ClType.html, ftm.retype(f.ftm, "<html>", .text_ascii, &rb).?);
    try std.testing.expectEqual(types.ClType.script, ftm.retype(f.ftm, "<hXm", .text_ascii, &rb).?);
    // rtype: NSIS refines a PE, and only a PE.
    try std.testing.expectEqual(types.ClType.nulsft, kind(&f, "MZNullsoft"));
    try std.testing.expectEqual(types.ClType.msexe, kind(&f, "MZ......"));
    var tar: [300]u8 = @splat(0);
    @memcpy(tar[257..262], "ustar");
    try std.testing.expectEqual(types.ClType.posix_tar, kind(&f, &tar));
    // No magic: text or binary.
    try std.testing.expectEqual(types.ClType.text_ascii, kind(&f, "hello\r\nworld\t!"));
    // libclamav's text detection: bytes from 0x80 up are ISO-8859 or extended ASCII, so UTF-8
    // is ASCII text too (its UTF-8 test only runs when the ASCII test failed, on a byte its own
    // ASCII rule also refuses); a NUL with a byte-order mark is UTF-16.
    try std.testing.expectEqual(types.ClType.text_ascii, kind(&f, "gr\xc3\xbc\xc3\x9fe"));
    try std.testing.expectEqual(types.ClType.text_utf16le, kind(&f, "\xff\xfeh\x00i\x00"));
    try std.testing.expectEqual(types.ClType.text_utf16be, kind(&f, "\x00\x01<script>"));
    // Three bytes leave no UTF-16 unit after the first to refuse, so libclamav says UTF-16BE.
    try std.testing.expectEqual(types.ClType.text_utf16be, kind(&f, "\x01\x02\x03"));
    try std.testing.expectEqual(types.ClType.binary_data, kind(&f, "\x00\x01\x00\x02"));

    // Embedded-type triggers, filtered by rtype.
    var budget: vm.Budget = .{};
    const pe = ftm.classify(f.ftm, "MZ......PK\x03\x04....%PDF-1.4", .{}, &budget);
    try std.testing.expectEqual(types.ClType.msexe, pe.type);
    try std.testing.expectEqual(@as(usize, 2), pe.embedded().len);
    try std.testing.expectEqual(types.ClType.zipsfx, pe.embedded()[0].type);
    try std.testing.expectEqual(@as(usize, 8), pe.embedded()[0].offset);
    const txt = ftm.classify(f.ftm, "see PK\x03\x04", .{}, &budget);
    try std.testing.expectEqual(@as(usize, 0), txt.embedded().len);
}

test "partition magics only in partition mode" {
    var f = try fixture(
        \\4:1024:482b0004:HFS+:CL_TYPE_PART_ANY:CL_TYPE_PART_HFSPLUS
        \\4:1024:482b:HFS short:CL_TYPE_ANY:CL_TYPE_PART_HFSPLUS
        \\
    );
    defer f.deinit();
    var disk: [1100]u8 = @splat(0);
    @memcpy(disk[1024..1028], "H+\x00\x04");
    var budget: vm.Budget = .{};
    try std.testing.expectEqual(types.ClType.binary_data, ftm.classify(f.ftm, &disk, .{}, &budget).type);
    try std.testing.expectEqual(types.ClType.part_hfsplus, ftm.classify(f.ftm, &disk, .{ .partitions = true }, &budget).type);
}

test "a corrupt trie is refused" {
    var f = try fixture(
        \\0:0:4d5a:DOS:CL_TYPE_ANY:CL_TYPE_MSEXE
        \\0:0:4d5a90:DOS2:CL_TYPE_ANY:CL_TYPE_MSEXE
        \\0:4:504b:PK:CL_TYPE_ANY:CL_TYPE_ZIP
        \\
    );
    defer f.deinit();
    const a = f.arena.allocator();
    var rules: std.ArrayList(ir.FtmRule) = .empty;
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    try ftm_parse.parse(a, a, "t.ftm", "0:0:4d5a:DOS:CL_TYPE_ANY:CL_TYPE_MSEXE\n0:0:4d5a90:DOS2:CL_TYPE_ANY:CL_TYPE_MSEXE\n", .{ .rules = &rules, .rejected = &rejected });
    const built = try build(a, rules.items);
    const image = try a.alignedAlloc(u8, .@"4", built.trie.len);
    for (0..image.len) |i| {
        @memcpy(image, built.trie);
        image[i] ^= 0x5a;
        if (ftm.Ftm.init(image, null)) |t| {
            var budget: vm.Budget = .{};
            _ = ftm.classify(t, "MZ\x90\x00PK", .{}, &budget);
        } else |_| {}
    }
}

test "embedded types over a whole object: the rule per scan window, the latest type across them" {
    var f = try fixture(
        \\1:*:3c68746d6c3e:HTML:CL_TYPE_ANY:CL_TYPE_HTML
        \\1:*:4d5a50450000:PE:CL_TYPE_ANY:CL_TYPE_MSEXE
        \\
    );
    defer f.deinit();
    const gpa = std.testing.allocator;
    const data = try gpa.alloc(u8, 3 * ftm.window_len);
    defer gpa.free(data);
    @memset(data, 'a');
    var budget: vm.Budget = .{};
    // In one window a later executable header takes over from HTML (CL_TYPE_MSEXE always does).
    @memcpy(data[100..106], "<html>");
    @memcpy(data[200..206], "MZPE\x00\x00");
    try std.testing.expectEqual(types.ClType.msexe, ftm.embeddedType(f.ftm, data, .any, true, &budget));
    // In separate windows the type later in libclamav's order wins: HTML.
    @memset(data[200..206], 'a');
    @memcpy(data[2 * ftm.window_len ..][0..6], "MZPE\x00\x00");
    try std.testing.expectEqual(types.ClType.html, ftm.embeddedType(f.ftm, data, .any, true, &budget));
}
