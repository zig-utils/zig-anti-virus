//! The machine a host scan looks at. Every check reads through a `Host`, whose root is either the
//! real `/` or a fixture tree in a temp directory with a fake `/proc`, `/sys` and `/etc`. Checks
//! write absolute paths ("/proc/1/status"); the host resolves them under its root, so the same
//! code runs live and against fixtures. Syscall probes (kill, bpf, netlink) only describe the
//! real machine and run only when `live` is set.
const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");

pub const Os = enum {
    linux,
    macos,

    pub fn native() ?Os {
        return switch (builtin.os.tag) {
            .linux => .linux,
            .macos => .macos,
            else => null,
        };
    }
};

pub const ReadError = error{ FileNotFound, AccessDenied, IsDir, ReadFailed, OutOfMemory, StreamTooLong };

pub const Host = struct {
    io: std.Io,
    root: std.Io.Dir,
    /// Absolute path of the root without a trailing slash: "" for the real root.
    root_path: []const u8,
    /// The root is this machine's `/`, so pid probes and kernel interfaces describe it.
    live: bool,
    euid: u32,
    os: Os,

    /// The real machine. Fails on systems host checks do not support.
    pub fn openLive(io: std.Io) !Host {
        const os = Os.native() orelse return error.Unsupported;
        return .{
            .io = io,
            .root = try std.Io.Dir.openDirAbsolute(io, "/", .{}),
            .root_path = "",
            .live = true,
            .euid = sys.euid(),
            .os = os,
        };
    }

    /// A fixture tree. `root_path` must be the absolute path of `root` (xattr reads need it).
    pub fn fixture(io: std.Io, root: std.Io.Dir, root_path: []const u8, os: Os) Host {
        return .{ .io = io, .root = root, .root_path = root_path, .live = false, .euid = 0, .os = os };
    }

    pub fn close(h: Host) void {
        if (h.live) h.root.close(h.io);
    }

    /// The path below the root: leading slashes removed, "." for the root itself.
    pub fn rel(path: []const u8) []const u8 {
        const trimmed = std.mem.trimStart(u8, path, "/");
        return if (trimmed.len == 0) "." else trimmed;
    }

    /// The path as the operating system sees it, for xattr calls and messages about fixtures.
    pub fn absPath(h: Host, buf: []u8, path: []const u8) error{NameTooLong}![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ h.root_path, rel(path) }) catch error.NameTooLong;
    }

    /// Read a small file into `buf`; longer content is truncated to the buffer.
    pub fn read(h: Host, path: []const u8, buf: []u8) ReadError![]u8 {
        return h.root.readFile(h.io, rel(path), buf) catch |e| return mapError(e);
    }

    /// `read` that treats every error as absent.
    pub fn readOpt(h: Host, path: []const u8, buf: []u8) ?[]u8 {
        return h.read(path, buf) catch null;
    }

    /// Read a whole file of up to `limit` bytes, to EOF. /proc and /sys files report size 0 in
    /// stat, and `Dir.readFileAlloc` trusts that size (it returns nothing for them), so this reads
    /// in streaming mode, which never consults the size.
    pub fn readAlloc(h: Host, gpa: std.mem.Allocator, path: []const u8, limit: usize) ReadError![]u8 {
        var file = h.root.openFile(h.io, rel(path), .{}) catch |e| return mapError(e);
        defer file.close(h.io);
        var reader = file.readerStreaming(h.io, &.{});
        return reader.interface.allocRemaining(gpa, .limited(limit)) catch |e| switch (e) {
            error.ReadFailed => mapError(reader.err orelse error.ReadFailed),
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => error.StreamTooLong,
        };
    }

    pub fn readLink(h: Host, path: []const u8, buf: []u8) ?[]u8 {
        const n = h.root.readLink(h.io, rel(path), buf) catch return null;
        return buf[0..n];
    }

    pub fn stat(h: Host, path: []const u8, follow: bool) sys.Error!sys.Stat {
        return sys.statAt(h.root, rel(path), follow);
    }

    pub fn exists(h: Host, path: []const u8) bool {
        _ = h.stat(path, false) catch return false;
        return true;
    }

    /// Open a directory for iteration. Null when missing; `error.AccessDenied` when unreadable, so
    /// callers can report reduced coverage.
    pub fn openDir(h: Host, path: []const u8) error{AccessDenied}!?std.Io.Dir {
        return h.root.openDir(h.io, rel(path), .{ .iterate = true, .follow_symlinks = true }) catch |e| switch (e) {
            error.AccessDenied, error.PermissionDenied => error.AccessDenied,
            else => null,
        };
    }

    pub fn getXattr(h: Host, path: []const u8, name: []const u8, out: []u8) sys.Error![]u8 {
        var buf: [4096]u8 = undefined;
        const abs = h.absPath(&buf, path) catch return error.NameTooLong;
        return sys.getXattr(abs, name, out);
    }
};

fn mapError(e: anyerror) ReadError {
    return switch (e) {
        error.FileNotFound, error.NotDir, error.BadPathName, error.NameTooLong, error.SymLinkLoop, error.NoDevice => error.FileNotFound,
        error.AccessDenied, error.PermissionDenied => error.AccessDenied,
        error.IsDir => error.IsDir,
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.StreamTooLong,
        else => error.ReadFailed,
    };
}

/// True when running under CI (GitHub Actions and most others set CI=true). Live tests make
/// clean-machine assertions only there: a developer machine is not a clean image, and other work
/// running on it (agents, launchd jobs being installed) must not make the suite flaky.
pub fn onCi() bool {
    if (builtin.os.tag.isDarwin()) {
        const v = std.c.getenv("CI") orelse return false;
        return std.mem.eql(u8, std.mem.span(v), "true");
    }
    if (builtin.os.tag == .linux) {
        var buf: [64 * 1024]u8 = undefined;
        const env = std.Io.Dir.cwd().readFile(std.testing.io, "/proc/self/environ", &buf) catch return false;
        var it = std.mem.splitScalar(u8, env, 0);
        while (it.next()) |kv| if (std.mem.eql(u8, kv, "CI=true")) return true;
    }
    return false;
}

/// Builds fixture trees for tests: files, directories and symlinks under a temp directory, and
/// a `Host` rooted there.
pub const Fixture = struct {
    tmp: std.testing.TmpDir,
    path_buf: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,

    pub fn init() !Fixture {
        if (builtin.os.tag == .windows) return error.SkipZigTest;
        var f: Fixture = .{ .tmp = std.testing.tmpDir(.{ .iterate = true }) };
        f.path_len = try f.tmp.dir.realPath(std.testing.io, &f.path_buf);
        return f;
    }

    pub fn deinit(f: *Fixture) void {
        f.tmp.cleanup();
    }

    pub fn host(f: *Fixture, os: Os) Host {
        return Host.fixture(std.testing.io, f.tmp.dir, f.path_buf[0..f.path_len], os);
    }

    pub fn file(f: *Fixture, path: []const u8, data: []const u8) !void {
        const io = std.testing.io;
        const r = Host.rel(path);
        if (std.fs.path.dirname(r)) |d| try f.tmp.dir.createDirPath(io, d);
        try f.tmp.dir.writeFile(io, .{ .sub_path = r, .data = data });
    }

    pub fn fileMode(f: *Fixture, path: []const u8, data: []const u8, mode: u32) !void {
        try f.file(path, data);
        try f.chmod(path, mode);
    }

    pub fn chmod(f: *Fixture, path: []const u8, mode: u32) !void {
        if (builtin.os.tag == .windows) return error.SkipZigTest;
        try f.tmp.dir.setFilePermissions(std.testing.io, Host.rel(path), .fromMode(@intCast(mode)), .{});
    }

    pub fn dir(f: *Fixture, path: []const u8) !void {
        try f.tmp.dir.createDirPath(std.testing.io, Host.rel(path));
    }

    pub fn link(f: *Fixture, path: []const u8, target: []const u8) !void {
        const io = std.testing.io;
        const r = Host.rel(path);
        if (std.fs.path.dirname(r)) |d| try f.tmp.dir.createDirPath(io, d);
        try f.tmp.dir.symLink(io, target, r, .{});
    }

    pub fn remove(f: *Fixture, path: []const u8) !void {
        try f.tmp.dir.deleteFile(std.testing.io, Host.rel(path));
    }
};

test "readAlloc reads files whose stat size is zero" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const h = try Host.openLive(std.testing.io);
    defer h.close();
    const text = try h.readAlloc(std.testing.allocator, "/proc/self/status", 1 << 20);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "Pid:") != null);
    const cmdline = try h.readAlloc(std.testing.allocator, "/proc/self/cmdline", 1 << 20);
    defer std.testing.allocator.free(cmdline);
    try std.testing.expect(cmdline.len > 0);
}

test "fixture paths resolve under the root" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/proc/1/comm", "systemd\n");
    try fx.link("/proc/1/exe", "/usr/lib/systemd/systemd");
    const h = fx.host(.linux);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("systemd\n", try h.read("/proc/1/comm", &buf));
    try std.testing.expectEqualStrings("/usr/lib/systemd/systemd", h.readLink("/proc/1/exe", &buf).?);
    try std.testing.expectError(error.FileNotFound, h.read("/proc/2/comm", &buf));
    try std.testing.expect(h.exists("/proc/1"));
    try std.testing.expectEqualStrings("proc", Host.rel("//proc"));
    try std.testing.expectEqualStrings(".", Host.rel("/"));
}
