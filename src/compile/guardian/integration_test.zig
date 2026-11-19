const std = @import("std");
const guardian = @import("root.zig");
const Compiler = @import("../compiler.zig").Compiler;
const reader = @import("../../db/reader.zig");
const body = @import("../../engine/bodyscan.zig");
const hashscan = @import("../../engine/hashscan.zig");
const logical = @import("../../match/logical.zig");
const vm = @import("../../match/verify_vm.zig");
const limits = @import("../../engine/limits.zig");
const ir = @import("../ir.zig");

test "Guardian public compile signed pack scan fixtures provenance and per-rule coverage" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var dir = try std.Io.Dir.cwd().openDir(io, "rules", .{ .iterate = true });
    defer dir.close(io);
    const pack = try guardian.readDirectory(a, io, dir, 42);
    try std.testing.expectEqual(@as(usize, 14), pack.entries.len);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x27));
    const bytes = try guardian.bundle.encode(a, pack, kp);
    var compiler = Compiler.init(gpa);
    defer compiler.deinit();
    try std.testing.expectError(error.UnknownKey, compiler.addGuardianBundle(bytes, &.{}));
    try std.testing.expectEqual(@as(usize, 0), compiler.yara_rules.items.len);
    try compiler.addGuardianBundle(bytes, &.{.{ .public_key = kp.public_key.toBytes() }});
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const summary = try compiler.write(io, tmp.dir, "guardian.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 7), summary.yara_rules);
    const db = try reader.open(io, tmp.dir, "guardian.zavdb", .{ .allow_unsigned = true });
    defer db.close();
    try std.testing.expectEqual(@as(u32, 42), db.header().sources.guardian_rules);
    const index = try body.BodyIndex.load(db);
    const names = try hashscan.HashIndex.load(db);
    const coverage = db.section(.coverage_report, 0).?;
    var scratch: [2 * 1024 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var state = try logical.State.init(fba.allocator());
    var tracker = limits.Tracker.init(.{});
    var name_buf: [256]u8 = undefined;
    for (pack.entries) |entry| {
        if (!std.mem.endsWith(u8, entry.path, ".yar")) continue;
        const slash = std.mem.indexOfScalar(u8, entry.path, '/').?;
        const family = entry.path[0..slash];
        const stem = entry.path[slash + 1 .. entry.path.len - 4];
        const want = try std.fmt.allocPrint(a, "Guardian.{s}.{s}", .{ family, stem });
        try std.testing.expect(std.mem.indexOf(u8, coverage, want) != null);
        for ([_][]const u8{ "matching", "benign" }) |kind| {
            const fixture_path = try std.fmt.allocPrint(a, "tests/fixtures/guardian/{s}/{s}.txt", .{ family, kind });
            const text = try std.Io.Dir.cwd().readFileAlloc(io, fixture_path, a, .limited(65536));
            state.reset();
            var budget: vm.Budget = .{};
            const verdict = try body.scanBuffer(&index, text, .{ .info = .{ .size = text.len } }, &budget, &tracker, &state);
            if (std.mem.eql(u8, kind, "matching")) {
                try std.testing.expect(verdict == .infected);
                try std.testing.expectEqualStrings(want, try names.meta.?.name(verdict.infected.sig, &name_buf));
                try std.testing.expectEqual(@as(u8, @backingInt(ir.Source.guardian)), names.meta.?.records[verdict.infected.sig].source());
            } else try std.testing.expectEqual(body.Verdict.clean, verdict);
        }
    }
    // A supported ordinary package lockfile is an additional benign corpus member.
    const lock = try std.Io.Dir.cwd().readFileAlloc(io, "tests/fixtures/clean-app/bun.lock", a, .limited(1024 * 1024));
    state.reset();
    var budget: vm.Budget = .{};
    try std.testing.expectEqual(body.Verdict.clean, try body.scanBuffer(&index, lock, .{ .info = .{ .size = lock.len } }, &budget, &tracker, &state));
}

test "Guardian invalid metadata rules and duplicate identifiers cannot partially enter compiler" {
    const rule = "rule Probe { strings: $a = \"suspicious marker\" condition: $a }";
    const valid = [_]guardian.Entry{
        .{ .path = "php/meta.toml", .bytes = guardian.metadata.fixture },
        .{ .path = "php/probe.yar", .bytes = rule },
    };
    var c = Compiler.init(std.testing.allocator);
    defer c.deinit();
    var broken = valid;
    broken[0].bytes = "category = 'webshell'";
    try std.testing.expectError(error.InvalidMetadata, c.addGuardianPack(.{ .version = 1, .entries = &broken }));
    try std.testing.expectEqual(@as(usize, 0), c.yara_rules.items.len);
    broken = valid;
    broken[1].bytes = "rule Bad { condition: true }";
    try std.testing.expectError(error.InvalidGuardianRule, c.addGuardianPack(.{ .version = 1, .entries = &broken }));
    try std.testing.expectEqual(@as(usize, 0), c.yara_rules.items.len);
    try c.addGuardianPack(.{ .version = 1, .entries = &valid });
    try std.testing.expectError(error.DuplicateGuardianRule, c.addGuardianPack(.{ .version = 1, .entries = &valid }));
    try std.testing.expectEqual(@as(usize, 1), c.yara_rules.items.len);
    const duplicates = [_]guardian.Entry{ valid[0], valid[1], .{ .path = "php/second.yar", .bytes = rule } };
    try std.testing.expectError(error.DuplicateGuardianRule, c.addGuardianPack(.{ .version = 1, .entries = &duplicates }));
    try std.testing.expectEqual(@as(usize, 1), c.yara_rules.items.len);
    try std.testing.expectError(error.InvalidPackFamily, c.addGuardianPack(.{ .version = 1, .entries = valid[1..] }));
}

test "Guardian local authoring rejects symlink families and rule files" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.symLink(io, "missing-target", "family", .{ .is_directory = true });
    try std.testing.expectError(error.InvalidPackPath, guardian.readDirectory(arena.allocator(), io, tmp.dir, 1));
    try tmp.dir.deleteFile(io, "family");
    try tmp.dir.createDir(io, "family", .default_dir);
    try tmp.dir.symLink(io, "missing-target", "family/test.yar", .{});
    try std.testing.expectError(error.InvalidPackPath, guardian.readDirectory(arena.allocator(), io, tmp.dir, 1));
}
