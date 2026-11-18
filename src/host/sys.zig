//! The few system calls host checks need beyond std.Io: stat with owner and mode, extended
//! attributes, process liveness probes and the effective uid. Linux uses raw syscalls (the test
//! module does not link libc there); macOS goes through libSystem, which every Darwin binary links.
//! Everything else reports `error.Unsupported`.
const std = @import("std");
const builtin = @import("builtin");

const os = builtin.os.tag;
pub const is_linux = os == .linux;
pub const is_darwin = os.isDarwin();

pub const Error = error{ FileNotFound, AccessDenied, NameTooLong, NoData, Unsupported, Unexpected };

pub const Kind = enum { file, directory, sym_link, other };

pub const Stat = struct {
    mode: u32,
    uid: u32,
    gid: u32,
    ino: u64,
    dev: u64,
    nlink: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,

    pub fn kind(s: Stat) Kind {
        return switch (s.mode & 0o170000) {
            0o100000 => .file,
            0o040000 => .directory,
            0o120000 => .sym_link,
            else => .other,
        };
    }
    pub fn isSetuid(s: Stat) bool {
        return s.mode & 0o4000 != 0;
    }
    pub fn isSetgid(s: Stat) bool {
        return s.mode & 0o2000 != 0;
    }
    pub fn worldReadable(s: Stat) bool {
        return s.mode & 0o004 != 0;
    }
    pub fn worldWritable(s: Stat) bool {
        return s.mode & 0o002 != 0;
    }
    pub fn groupReadable(s: Stat) bool {
        return s.mode & 0o040 != 0;
    }
    pub fn executable(s: Stat) bool {
        return s.mode & 0o111 != 0;
    }
};

fn toZ(buf: []u8, path: []const u8) Error![*:0]const u8 {
    if (path.len + 1 > buf.len) return error.NameTooLong;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.FileNotFound;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

/// stat relative to an open directory. `follow` follows a final symlink.
pub fn statAt(dir: std.Io.Dir, path: []const u8, follow: bool) Error!Stat {
    var buf: [4096]u8 = undefined;
    const z = try toZ(&buf, if (path.len == 0) "." else path);
    if (is_linux) {
        const linux = std.os.linux;
        var stx: linux.Statx = undefined;
        const flags: u32 = if (follow) 0 else linux.AT.SYMLINK_NOFOLLOW;
        const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .NLINK = true, .UID = true, .GID = true, .MTIME = true, .CTIME = true, .INO = true, .SIZE = true };
        const rc = linux.statx(dir.handle, z, flags, mask, &stx);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOENT, .NOTDIR, .LOOP => return error.FileNotFound,
            .ACCES, .PERM => return error.AccessDenied,
            .NAMETOOLONG => return error.NameTooLong,
            else => return error.Unexpected,
        }
        return .{
            .mode = stx.mode,
            .uid = stx.uid,
            .gid = stx.gid,
            .ino = stx.ino,
            .dev = (@as(u64, stx.dev_major) << 32) | stx.dev_minor,
            .nlink = stx.nlink,
            .size = stx.size,
            .mtime_ns = @as(i128, stx.mtime.sec) * std.time.ns_per_s + stx.mtime.nsec,
            .ctime_ns = @as(i128, stx.ctime.sec) * std.time.ns_per_s + stx.ctime.nsec,
        };
    } else if (is_darwin) {
        var st: std.c.Stat = undefined;
        const flags: u32 = if (follow) 0 else std.c.AT.SYMLINK_NOFOLLOW;
        if (std.c.fstatat(dir.handle, z, &st, flags) != 0) {
            return switch (std.c.errno(-1)) {
                .NOENT, .NOTDIR, .LOOP => error.FileNotFound,
                .ACCES, .PERM => error.AccessDenied,
                .NAMETOOLONG => error.NameTooLong,
                else => error.Unexpected,
            };
        }
        return .{
            .mode = st.mode,
            .uid = st.uid,
            .gid = st.gid,
            .ino = st.ino,
            .dev = @bitCast(@as(i64, st.dev)),
            .nlink = st.nlink,
            .size = @intCast(@max(st.size, 0)),
            .mtime_ns = @as(i128, st.mtimespec.sec) * std.time.ns_per_s + st.mtimespec.nsec,
            .ctime_ns = @as(i128, st.ctimespec.sec) * std.time.ns_per_s + st.ctimespec.nsec,
        };
    } else return error.Unsupported;
}

extern "c" fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?*anyopaque, size: usize, position: u32, options: c_int) isize;
const XATTR_NOFOLLOW: c_int = 0x0001;

/// Read an extended attribute of an absolute path without following a final symlink. Returns
/// `error.NoData` when the attribute is not set.
pub fn getXattr(abs_path: []const u8, name: []const u8, out: []u8) Error![]u8 {
    var pbuf: [4096]u8 = undefined;
    var nbuf: [256]u8 = undefined;
    const p = try toZ(&pbuf, abs_path);
    const n = try toZ(&nbuf, name);
    if (is_linux) {
        const linux = std.os.linux;
        const rc = linux.lgetxattr(p, n, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => out[0..rc],
            .NODATA, .OPNOTSUPP => error.NoData,
            .NOENT, .NOTDIR => error.FileNotFound,
            .ACCES, .PERM => error.AccessDenied,
            .RANGE => error.NoData,
            else => error.Unexpected,
        };
    } else if (is_darwin) {
        const rc = getxattr(p, n, out.ptr, out.len, 0, XATTR_NOFOLLOW);
        if (rc < 0) return switch (std.c.errno(-1)) {
            .NOATTR, .OPNOTSUPP => error.NoData,
            .NOENT, .NOTDIR => error.FileNotFound,
            .ACCES, .PERM => error.AccessDenied,
            .RANGE => error.NoData,
            else => error.Unexpected,
        };
        return out[0..@intCast(rc)];
    } else return error.Unsupported;
}

pub const Liveness = enum { alive, gone, unknown };

/// kill(pid, 0): ESRCH means no such process; success or EPERM means it exists. This sees pids
/// a readdir hook on /proc hides.
pub fn probePid(pid: u32) Liveness {
    if (pid == 0 or pid > std.math.maxInt(i32)) return .gone;
    if (is_linux) {
        const linux = std.os.linux;
        const rc = linux.kill(@intCast(pid), @fromBackingInt(@intCast(0)));
        return switch (linux.errno(rc)) {
            .SUCCESS, .PERM => .alive,
            .SRCH => .gone,
            else => .unknown,
        };
    } else if (is_darwin) {
        if (std.c.kill(@intCast(pid), @fromBackingInt(@intCast(0))) == 0) return .alive;
        return switch (std.c.errno(-1)) {
            .PERM => .alive,
            .SRCH => .gone,
            else => .unknown,
        };
    } else return .unknown;
}

pub fn euid() u32 {
    if (is_linux) return std.os.linux.geteuid();
    if (is_darwin) return std.c.geteuid();
    return std.math.maxInt(u32);
}

test "stat reports mode bits and kind relative to a directory" {
    if (!is_linux and !is_darwin) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = "abc" });
    try tmp.dir.setFilePermissions(io, "f", .fromMode(0o4755), .{});
    const st = try statAt(tmp.dir, "f", false);
    try std.testing.expectEqual(Kind.file, st.kind());
    try std.testing.expect(st.isSetuid());
    try std.testing.expectEqual(@as(u64, 3), st.size);
    try std.testing.expectEqual(euid(), st.uid);
    try std.testing.expectError(error.FileNotFound, statAt(tmp.dir, "missing", false));
    try std.testing.expectEqual(Liveness.alive, probePid(if (is_linux) @intCast(std.os.linux.getpid()) else @intCast(std.c.getpid())));
}
