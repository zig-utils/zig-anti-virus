//! Positional I/O for the synchronous file scan path. Small files can be held in
//! the worker's scratch so both format detection and the scan use one file read.
const std = @import("std");
const builtin = @import("builtin");
const Source = @import("../engine/source.zig").Source;

pub const file_in_memory_max = 1024 * 1024;
pub const stream_block_len = 256 * 1024;

/// Reads a complete small file range into scratch. The caller releases any
/// buffer at the end of its scan. Short, failed or unaffordable reads leave the
/// positional source available so the walker can still process its bytes.
pub fn prepare(io: std.Io, scratch: std.mem.Allocator, src: Source) Source {
    if (src != .file) return src;
    const file = src.file;
    if (file.len > file_in_memory_max) {
        adviseSequential(file);
        return src;
    }
    const buffer = scratch.alloc(u8, @intCast(file.len)) catch return src;
    src.readAllAt(io, 0, buffer) catch {
        scratch.free(buffer);
        return src;
    };
    return .{ .memory = buffer };
}

pub fn adviseSequential(file: Source.FileRange) void {
    if (builtin.os.tag != .linux) return;
    if (file.offset > std.math.maxInt(i64) or file.len > std.math.maxInt(i64)) return;
    const linux = std.os.linux;
    _ = linux.fadvise(file.file.handle, @intCast(file.offset), @intCast(file.len), linux.POSIX_FADV.SEQUENTIAL);
}

test "small positional ranges materialize only the requested bytes" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "data", .data = "prefix content suffix" });
    const file = try tmp.dir.openFile(io, "data", .{});
    defer file.close(io);
    const src: Source = .{ .file = .{ .file = file, .offset = 7, .len = 7 } };
    const prepared = prepare(io, gpa, src);
    try std.testing.expect(prepared == .memory);
    defer gpa.free(prepared.memory);
    try std.testing.expectEqualStrings("content", prepared.memory);
}

test "large files and incomplete small reads keep their positional source" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "data", .data = "short" });
    const file = try tmp.dir.openFile(io, "data", .{});
    defer file.close(io);
    for ([_]u64{ 6, file_in_memory_max + 1 }) |size| {
        const src: Source = .{ .file = .{ .file = file, .len = size } };
        try std.testing.expectEqual(src, prepare(io, std.testing.allocator, src));
    }
}
