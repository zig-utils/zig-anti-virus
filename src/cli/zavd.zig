//! `zavd`: the scanning daemon (clamd-compatible protocol). The server lands with its issues.
const std = @import("std");
const zav = @import("zav");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var buffer: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &buffer);
    const out = &stdout.interface;
    if (args.len > 1 and (std.mem.eql(u8, args[1], "--version") or std.mem.eql(u8, args[1], "version"))) {
        try out.print("zavd {f}\n", .{zav.version});
    } else {
        try out.writeAll("usage: zavd --version\n");
    }
    try out.flush();
}
