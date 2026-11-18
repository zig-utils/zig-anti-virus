//! `zig build census -- <database files>`: E0, the census of ClamAV databases (P3.02). Every CVD
//! is verified (MD5 and Talos's signature) before a line of it is read; loose signature files are
//! counted as they are. The report is Markdown on stdout and identical for identical inputs.
const std = @import("std");
const zav = @import("zav");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: census <main.cvd> [daily.cvd ...] [file.hdb ...]\n", .{});
        std.process.exit(2);
    }
    var census = zav.compile.census.Census.init(gpa);
    defer census.deinit();
    const cwd = std.Io.Dir.cwd();
    for (args[1..]) |path| {
        if (std.mem.endsWith(u8, path, ".cvd")) {
            _ = try census.addContainer(io, cwd, path, .{});
        } else {
            const file = try cwd.openFile(io, path, .{});
            defer file.close(io);
            var buf: [64 * 1024]u8 = undefined;
            var r = file.reader(io, &buf);
            const size = try file.length(io);
            try census.addMember("loose", std.fs.path.basename(path), size, &r.interface);
        }
    }
    var out_buf: [64 * 1024]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &out_buf);
    try census.render(&out.interface);
    try out.interface.flush();
}
