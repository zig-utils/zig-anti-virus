//! Build-time test helper: copy IN to OUT with the lowest bit of one byte flipped.
//!
//!   flip_byte IN OUT OFFSET
//!
//! OFFSET counts from the start, or from the end when negative (-1 is the last byte). The CLI
//! tests in build.zig use it to tamper with a signed CVE index.
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) {
        std.debug.print("usage: flip_byte IN OUT OFFSET\n", .{});
        std.process.exit(2);
    }
    const cwd = std.Io.Dir.cwd();
    const bytes = try cwd.readFileAlloc(init.io, args[1], init.gpa, .unlimited);
    defer init.gpa.free(bytes);
    const offset = try std.fmt.parseInt(i64, args[3], 10);
    const index: usize = if (offset < 0) bytes.len - @as(usize, @intCast(-offset)) else @intCast(offset);
    if (index >= bytes.len) return error.OffsetOutOfRange;
    bytes[index] ^= 0x01;
    try cwd.writeFile(init.io, .{ .sub_path = args[2], .data = bytes });
}
