//! `zav`: scan, compile signatures, inspect databases, audit hosts. Commands land with their issues.
const std = @import("std");
const zav = @import("zav");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var buffer: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &buffer);
    const out = &stdout.interface;
    if (args.len > 1 and (std.mem.eql(u8, args[1], "--version") or std.mem.eql(u8, args[1], "version"))) {
        try out.print("zav {f}\n", .{zav.version});
    } else {
        try out.writeAll("usage: zav --version\n(scan, compile, info, coverage, audit and host arrive with their issues)\n");
    }
    try out.flush();
}
