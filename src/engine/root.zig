//! Scan pipeline: sources, limits, scratch arenas, budgets, results, scan cache.
//! See docs/DESIGN.md for the design this module implements.

const std = @import("std");

pub const source = @import("source.zig");
pub const scratch = @import("scratch.zig");
pub const limits = @import("limits.zig");
pub const budget = @import("budget.zig");
pub const hashscan = @import("hashscan.zig");
pub const bodyscan = @import("bodyscan.zig");

test {
    _ = source;
    _ = scratch;
    _ = limits;
    _ = budget;
    _ = hashscan;
    _ = bodyscan;
}

test "a file scan's working set comes from scratch, not the heap" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" });
    const file = try tmp.dir.openFile(io, "f", .{});
    defer file.close(io);

    var s = try scratch.Scratch.init(1024 * 1024);
    defer s.deinit();
    // From here on the heap is off limits: any allocation from it fails the test.
    const heap = std.testing.failing_allocator;
    _ = heap;
    const a = s.allocator();
    var tracker = limits.Tracker.init(.{});
    const src: source.Source = .{ .file = .{ .file = file, .len = (try file.stat(io)).size } };
    try tracker.checkFileSize(src.len().?);
    const block = try a.alloc(u8, 64 * 1024);
    var md5 = std.crypto.hash.Md5.init(.{});
    var offset: u64 = 0;
    while (true) {
        const n = try src.readAt(io, offset, block);
        if (n == 0) break;
        try tracker.addScanned(n);
        md5.update(block[0..n]);
        offset += n;
    }
    var digest: [16]u8 = undefined;
    md5.final(&digest);
    try std.testing.expectEqualStrings("44d88612fea8a8f36de82e1278abb02f", &std.fmt.bytesToHex(digest, .lower));
    s.reset();
}
