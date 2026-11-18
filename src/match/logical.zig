//! Sparse per-file logical-signature state (docs/DESIGN.md section 5, "Logical state").
//!
//! A database holds hundreds of thousands of logical subsigs but a file touches a handful, so
//! state is kept only for touched signatures: an 8192-slot open-addressing table of 16-byte
//! slots, a touched list that makes reset O(touched), and a pool of u16 counters handed out to
//! signatures whose expression compares counts. The target description is checked once, on a
//! signature's first touch; a signature that fails it is marked dead and ignores later hits.
//! When the table passes its load limit or the counter pool runs dry, entries spill into a list
//! allocated from the worker's scratch arena: slower, never a failure. Nothing here touches the
//! heap; every byte comes from the scratch allocator handed to `init`.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const lt = @import("ldb_table.zig");

pub const slot_count: usize = 8192;
/// Entries the table takes before new signatures spill (75% load).
pub const table_limit: usize = slot_count / 4 * 3;
pub const counter_pool: usize = 32 * 1024;

pub const Slot = extern struct {
    mask: u64 = 0,
    ldb: u32 = 0,
    /// Index of the first of `nsub` counters in the pool, or `no_counters`.
    cnt_off: u16 = no_counters,
    dead: u8 = 0,
    used: u8 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Slot) == 16);
}

pub const no_counters: u16 = 0xffff;

const Spilled = struct {
    ldb: u32,
    mask: u64 = 0,
    dead: bool,
    /// Counters for this entry (scratch memory), empty when the expression has no counts.
    counts: []u16 = &.{},
};

pub const State = struct {
    scratch: std.mem.Allocator,
    slots: []Slot,
    touched: []u16,
    touched_len: usize = 0,
    counts: []u16,
    counts_used: usize = 0,
    spill: std.ArrayList(Spilled) = .empty,
    /// Every match, or only the first.
    all_match: bool = false,

    /// Reserve the table, touched list and counter pool (about 208 KiB) from `scratch`.
    pub fn init(scratch: std.mem.Allocator) !State {
        const slots = try scratch.alloc(Slot, slot_count);
        @memset(slots, .{});
        return .{
            .scratch = scratch,
            .slots = slots,
            .touched = try scratch.alloc(u16, table_limit),
            .counts = try scratch.alloc(u16, counter_pool),
        };
    }

    /// Forget the last file. Costs one write per touched signature, whatever the database size.
    pub fn reset(s: *State) void {
        for (s.touched[0..s.touched_len]) |i| s.slots[i] = .{};
        s.touched_len = 0;
        s.counts_used = 0;
        // Spilled entries live in scratch; the scratch reset frees them with everything else.
        s.spill = .empty;
    }

    fn hash(ldb: u32) usize {
        return @intCast((@as(u64, ldb) *% 0x9E37_79B9_7F4A_7C15) >> (64 - 13));
    }

    fn find(s: *State, ldb: u32) ?*Slot {
        var i = hash(ldb);
        while (true) : (i = (i + 1) & (slot_count - 1)) {
            const slot = &s.slots[i];
            if (slot.used == 0) return null;
            if (slot.ldb == ldb) return slot;
        }
    }

    fn findSpilled(s: *State, ldb: u32) ?*Spilled {
        for (s.spill.items) |*e| if (e.ldb == ldb) return e;
        return null;
    }

    /// Record a match of subsig `subsig` of logical signature `ldb`.
    pub fn touch(s: *State, table: lt.LdbTable, ctx: lt.FileContext, ldb: u32, subsig: u16) !void {
        const rec = table.records[ldb];
        if (subsig >= rec.nsub) return;
        const bit = @as(u64, 1) << @intCast(subsig);
        if (s.find(ldb)) |slot| {
            if (slot.dead != 0) return;
            slot.mask |= bit;
            if (slot.cnt_off != no_counters) s.counts[slot.cnt_off + subsig] +|= 1;
            return;
        }
        if (s.findSpilled(ldb)) |e| {
            if (e.dead) return;
            e.mask |= bit;
            if (e.counts.len > 0) e.counts[subsig] +|= 1;
            return;
        }
        // First touch: the target description decides whether the signature can match at all.
        const dead = !lt.tdbMatches(table.tdbs[ldb], ctx);
        const wants_counts = rec.flags & lt.flag_counts != 0 and !dead;
        if (s.touched_len < table_limit and (!wants_counts or s.counts_used + rec.nsub <= s.counts.len)) {
            var i = hash(ldb);
            while (s.slots[i].used != 0) i = (i + 1) & (slot_count - 1);
            var slot: Slot = .{ .ldb = ldb, .used = 1, .dead = @intFromBool(dead) };
            if (wants_counts) {
                slot.cnt_off = @intCast(s.counts_used);
                @memset(s.counts[s.counts_used..][0..rec.nsub], 0);
                s.counts_used += rec.nsub;
                s.counts[slot.cnt_off + subsig] = 1;
            }
            if (!dead) slot.mask = bit;
            s.slots[i] = slot;
            s.touched[s.touched_len] = @intCast(i);
            s.touched_len += 1;
            return;
        }
        // Spill: scratch memory, linear lookups.
        var e: Spilled = .{ .ldb = ldb, .dead = dead };
        if (wants_counts) {
            e.counts = try s.scratch.alloc(u16, rec.nsub);
            @memset(e.counts, 0);
            e.counts[subsig] = 1;
        }
        if (!dead) e.mask = bit;
        try s.spill.append(s.scratch, e);
    }

    /// Whether subsig `subsig` of `ldb` has matched (or the signature is dead): the scan can
    /// skip further matches of it when its expression does not count.
    pub fn settled(s: *State, ldb: u32, subsig: u16) bool {
        const bit = @as(u64, 1) << @intCast(subsig);
        if (s.find(ldb)) |slot| return slot.dead != 0 or slot.mask & bit != 0;
        if (s.findSpilled(ldb)) |e| return e.dead or e.mask & bit != 0;
        return false;
    }

    fn countsOf(nsub: usize, mask: u64, counters: ?[]const u16, out: *[ir.max_subsigs]u32) []const u32 {
        for (0..nsub) |i| {
            out[i] = if (counters) |c| c[i] else @intFromBool(mask & (@as(u64, 1) << @intCast(i)) != 0);
        }
        return out[0..nsub];
    }

    /// Evaluate every touched, live signature. Matching record indices go into `out` (the
    /// first only, unless `all_match`); returns how many.
    pub fn finalize(s: *State, table: lt.LdbTable, out: []u32) usize {
        var n: usize = 0;
        var buf: [ir.max_subsigs]u32 = undefined;
        for (s.touched[0..s.touched_len]) |i| {
            const slot = s.slots[i];
            if (slot.dead != 0) continue;
            const rec = table.records[slot.ldb];
            const counters: ?[]const u16 = if (slot.cnt_off != no_counters) s.counts[slot.cnt_off..][0..rec.nsub] else null;
            if (lt.evalRpn(table.expr(rec), countsOf(rec.nsub, slot.mask, counters, &buf))) {
                if (n == out.len) return n;
                out[n] = slot.ldb;
                n += 1;
                if (!s.all_match) return n;
            }
        }
        for (s.spill.items) |e| {
            if (e.dead) continue;
            const rec = table.records[e.ldb];
            const counters: ?[]const u16 = if (e.counts.len > 0) e.counts else null;
            if (lt.evalRpn(table.expr(rec), countsOf(rec.nsub, e.mask, counters, &buf))) {
                if (n == out.len) return n;
                out[n] = e.ldb;
                n += 1;
                if (!s.all_match) return n;
            }
        }
        return n;
    }
};

const testing = std.testing;
const ldb_parse = @import("../compile/ldb.zig");
const ldb_build = @import("../compile/ldb_build.zig");

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    table: lt.LdbTable,

    fn deinit(f: *Fixture) void {
        f.arena.deinit();
    }
};

fn fixture(lines: []const []const u8) !Fixture {
    var f: Fixture = .{ .arena = .init(testing.allocator), .table = undefined };
    errdefer f.arena.deinit();
    const a = f.arena.allocator();
    const rules = try a.alloc(ir.LogicalRule, lines.len);
    const entries = try a.alloc(ldb_build.Entry, lines.len);
    for (lines, rules, entries, 0..) |line, *r, *e, i| {
        var column: u32 = 0;
        r.* = try ldb_parse.parseLine(a, line, &column);
        e.* = .{ .rule = r, .sig = @intCast(100 + i), .prog_first = 0, .prog_count = 0 };
    }
    const bytes = try ldb_build.build(a, entries);
    const image = try a.alignedAlloc(u8, .@"8", bytes.len);
    @memcpy(image, bytes);
    f.table = try lt.LdbTable.init(image, null);
    return f;
}

test "touch, target descriptions, counts, finalize and an O(touched) reset" {
    var f = try fixture(&.{
        "A-1-0;Target:0;0&1;aa;bb", // 0
        "B-2-0;Target:1;0;aa", // 1: PE only
        "C-3-0;Target:0;0>2;aa", // 2: counts
        "D-4-0;Target:0,FileSize:10-20;0;aa", // 3
        "E-5-0;Target:0;(0|1)=2,2;aa;bb", // 4: counts and distinct
    });
    defer f.deinit();
    var mem: [512 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var s = try State.init(fba.allocator());
    const after_init = fba.end_index;
    s.all_match = true;

    const ctx: lt.FileContext = .{ .target = 0, .size = 100 };
    try s.touch(f.table, ctx, 0, 0);
    try s.touch(f.table, ctx, 1, 0); // dead: wrong target
    try s.touch(f.table, ctx, 3, 0); // dead: wrong size
    for (0..3) |_| try s.touch(f.table, ctx, 2, 0);
    try s.touch(f.table, ctx, 4, 0);
    try s.touch(f.table, ctx, 4, 1);
    var out: [8]u32 = undefined;
    var n = s.finalize(f.table, &out);
    std.mem.sortUnstable(u32, out[0..n], {}, std.sort.asc(u32));
    try testing.expectEqualSlices(u32, &.{ 2, 4 }, out[0..n]); // 0 lacks subsig 1
    try testing.expect(s.settled(1, 0)); // dead counts as settled
    try testing.expect(!s.settled(0, 1));

    try s.touch(f.table, ctx, 0, 1);
    try s.touch(f.table, ctx, 4, 0); // three matches now: =2 fails
    n = s.finalize(f.table, &out);
    std.mem.sortUnstable(u32, out[0..n], {}, std.sort.asc(u32));
    try testing.expectEqualSlices(u32, &.{ 0, 2 }, out[0..n]);
    s.all_match = false;
    try testing.expectEqual(@as(usize, 1), s.finalize(f.table, &out));

    // Reset clears exactly the touched slots; no allocation happened in any of this.
    try testing.expectEqual(@as(usize, 5), s.touched_len);
    s.reset();
    try testing.expectEqual(@as(usize, 0), s.touched_len);
    for (s.slots) |slot| try testing.expectEqual(@as(u8, 0), slot.used);
    try testing.expectEqual(after_init, fba.end_index);
    try testing.expectEqual(@as(usize, 0), s.finalize(f.table, &out));
}

test "past the table limit entries spill into scratch and still evaluate" {
    // table_limit + 10 distinct signatures, each "0>0" over one subsig (counts).
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const n_sigs = table_limit + 10;
    var column: u32 = 0;
    const r = try ldb_parse.parseLine(a.allocator(), "S-1-0;Target:0;0>0;aa", &column);
    const entries = try a.allocator().alloc(ldb_build.Entry, n_sigs);
    for (entries, 0..) |*e, i| e.* = .{ .rule = &r, .sig = @intCast(i), .prog_first = 0, .prog_count = 0 };
    const bytes = try ldb_build.build(a.allocator(), entries);
    const image = try a.allocator().alignedAlloc(u8, .@"8", bytes.len);
    @memcpy(image, bytes);
    const table = try lt.LdbTable.init(image, null);

    const mem = try testing.allocator.alloc(u8, 1024 * 1024);
    defer testing.allocator.free(mem);
    var fba: std.heap.FixedBufferAllocator = .init(mem);
    var s = try State.init(fba.allocator());
    s.all_match = true;
    for (0..n_sigs) |i| try s.touch(table, .{}, @intCast(i), 0);
    try testing.expectEqual(@as(usize, 10), s.spill.items.len);
    const out = try a.allocator().alloc(u32, n_sigs);
    try testing.expectEqual(n_sigs, s.finalize(table, out));
    s.reset();
    fba.reset();
}
