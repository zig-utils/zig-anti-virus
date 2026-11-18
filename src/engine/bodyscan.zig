//! The body-signature stage over one in-memory view of a file: every `.ndb` program whose target
//! type is 0 or the file's own type runs through the verify VM's scanner. This is the reference
//! path: it needs no prefilter, so it is what the prefilter stages (atoms, Bloom filters, atom
//! tables) are checked against, and it is what scans until they land. Allocation free.
const std = @import("std");
const db = @import("../db/root.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");
const anchored = @import("../match/anchored.zig");
const limits_mod = @import("limits.zig");

pub const BodyIndex = struct {
    programs: ?prog.Programs = null,
    /// ANCHORED_INDEX per partition (target type).
    anchored: [15]?anchored.Index = @splat(null),

    pub fn load(database: db.reader.Database) !BodyIndex {
        const bytes = database.section(.subsig_prog, 0) orelse return .{};
        var index: BodyIndex = .{ .programs = try .init(bytes) };
        for (&index.anchored, 0..) |*slot, p| {
            if (database.section(.anchored_index, @intCast(p))) |section| slot.* = try .init(section, index.programs.?);
        }
        return index;
    }
};

const FirstHit = struct {
    programs: prog.Programs,
    hit: ?Detection = null,

    fn take(f: *FirstHit, h: anchored.Hit) bool {
        const p = f.programs.get(h.prog);
        if (p.header.flags & prog.flag_ldb != 0) return true;
        f.hit = .{ .sig = p.header.sig, .start = h.match.start, .end = h.match.end };
        return false;
    }
};

pub const Detection = struct {
    /// Signature id; resolve the name through the hash index's sigmeta.
    sig: u32,
    start: usize,
    end: usize,
};

pub const Verdict = union(enum) {
    clean,
    infected: Detection,
    /// No signature matched, but the verify budget ran out somewhere: not a clean result.
    limited: limits_mod.Event,
};

/// Scan `data` (the whole file) of ClamAV target type `target`. `budget` is per file.
pub fn scanBuffer(index: *const BodyIndex, data: []const u8, info: vm.FileInfo, target: u8, budget: *vm.Budget, tracker: *limits_mod.Tracker) Verdict {
    const progs = index.programs orelse return .clean;
    // Signatures pinned to an offset: direct lookups through the file's partition and type 0.
    var first: FirstHit = .{ .programs = progs };
    for ([_]u8{ target, 0 }, 0..) |part, n| {
        if (n == 1 and target == 0) break;
        const a = if (part < index.anchored.len) index.anchored[part] orelse continue else continue;
        anchored.scan(a, progs, data, info, budget, &first, FirstHit.take) catch break;
        if (first.hit) |d| return .{ .infected = d };
    }
    // Everything else is searched for.
    for (0..progs.count()) |i| {
        const p = progs.get(i);
        if (p.header.flags & prog.flag_ldb != 0 or anchored.isAnchored(p)) continue;
        if (p.header.target != 0 and p.header.target != target) continue;
        var scanner = vm.Scanner.init(p, data, info, budget);
        const m = scanner.next() catch break;
        if (m) |hit| return .{ .infected = .{ .sig = p.header.sig, .start = hit.start, .end = hit.end } };
    }
    if (budget.exhausted) {
        tracker.note(.verify_steps);
        return .{ .limited = .verify_steps };
    }
    return .clean;
}

test "compile .ndb signatures and detect them end to end" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Compiler = @import("../compile/compiler.zig").Compiler;
    const hashscan = @import("hashscan.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("test.ndb",
        \\Test.Body.Any-1-0:0:*:4558414d504c45{-8}5041594c4f4144
        \\Test.Body.Pe-2-0:1:EP+0:e8????????5dc3
        \\Test.Body.Html-3-0:3:*:3c736372697074
        \\
    );
    const summary = try c.write(io, tmp.dir, "body.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 3), summary.body_rules);

    const database = try db.reader.open(io, tmp.dir, "body.zavdb", .{ .allow_unsigned = true });
    defer database.close();
    const index = try BodyIndex.load(database);
    const names = try hashscan.HashIndex.load(database);
    var tracker = limits_mod.Tracker.init(.{});
    var name_buf: [64]u8 = undefined;

    var budget: vm.Budget = .{};
    const doc = "header EXAMPLE...PAYLOAD trailer";
    const hit = scanBuffer(&index, doc, .{ .size = doc.len }, 0, &budget, &tracker);
    try std.testing.expectEqualStrings("Test.Body.Any-1-0", try names.meta.?.name(hit.infected.sig, &name_buf));
    try std.testing.expectEqual(@as(usize, 7), hit.infected.start);

    // Target types partition: the HTML signature does not fire on a PE, nor the PE one off EP.
    budget.reset();
    const pe = "MZ<script>\xe8\x01\x02\x03\x04\x5d\xc3";
    try std.testing.expectEqual(Verdict.clean, scanBuffer(&index, pe, .{ .size = pe.len, .entry_point = 3 }, 1, &budget, &tracker));
    budget.reset();
    const at_ep = scanBuffer(&index, pe, .{ .size = pe.len, .entry_point = 10 }, 1, &budget, &tracker);
    try std.testing.expectEqualStrings("Test.Body.Pe-2-0", try names.meta.?.name(at_ep.infected.sig, &name_buf));
    budget.reset();
    try std.testing.expect(scanBuffer(&index, pe, .{ .size = pe.len }, 3, &budget, &tracker) == .infected);

    // A budget that runs out is a limit, not a clean verdict.
    var tiny: vm.Budget = .{ .per_verify = 1, .per_file = 1 };
    const many = "EXAMPLE EXAMPLE EXAMPLE";
    try std.testing.expectEqual(Verdict{ .limited = .verify_steps }, scanBuffer(&index, many, .{ .size = many.len }, 0, &tiny, &tracker));
    try std.testing.expect(tracker.raised.contains(.verify_steps));
}
