//! /proc parsers and the per-scan process snapshot. The parsers are pure functions over bytes
//! (fuzzed in tools/fuzz_host.zig); the snapshot reads every /proc/<pid> once per scan so the
//! process, network, privilege and persistence checks share one view.
const std = @import("std");
const Host = @import("../host.zig").Host;

pub const Status = struct {
    name: []const u8 = "",
    state: u8 = '?',
    tgid: u32 = 0,
    pid: u32 = 0,
    ppid: u32 = 0,
    /// Real, effective, saved, filesystem.
    uid: [4]u32 = @splat(std.math.maxInt(u32)),
    gid: [4]u32 = @splat(std.math.maxInt(u32)),
    cap_eff: u64 = 0,
    cap_prm: u64 = 0,
    cap_bnd: u64 = 0,
    threads: u32 = 0,
    /// Kernel threads have no memory map, so no VmSize line.
    has_vm: bool = false,
};

pub fn parseStatus(text: []const u8) Status {
    var s: Status = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.mem.eql(u8, key, "Name")) {
            s.name = value;
        } else if (std.mem.eql(u8, key, "State")) {
            if (value.len > 0) s.state = value[0];
        } else if (std.mem.eql(u8, key, "Tgid")) {
            s.tgid = std.fmt.parseInt(u32, value, 10) catch 0;
        } else if (std.mem.eql(u8, key, "Pid")) {
            s.pid = std.fmt.parseInt(u32, value, 10) catch 0;
        } else if (std.mem.eql(u8, key, "PPid")) {
            s.ppid = std.fmt.parseInt(u32, value, 10) catch 0;
        } else if (std.mem.eql(u8, key, "Uid")) {
            parseIds(value, &s.uid);
        } else if (std.mem.eql(u8, key, "Gid")) {
            parseIds(value, &s.gid);
        } else if (std.mem.eql(u8, key, "CapEff")) {
            s.cap_eff = std.fmt.parseInt(u64, value, 16) catch 0;
        } else if (std.mem.eql(u8, key, "CapPrm")) {
            s.cap_prm = std.fmt.parseInt(u64, value, 16) catch 0;
        } else if (std.mem.eql(u8, key, "CapBnd")) {
            s.cap_bnd = std.fmt.parseInt(u64, value, 16) catch 0;
        } else if (std.mem.eql(u8, key, "Threads")) {
            s.threads = std.fmt.parseInt(u32, value, 10) catch 0;
        } else if (std.mem.eql(u8, key, "VmSize")) {
            s.has_vm = true;
        }
    }
    return s;
}

fn parseIds(value: []const u8, out: *[4]u32) void {
    var it = std.mem.tokenizeAny(u8, value, " \t");
    var i: usize = 0;
    while (it.next()) |t| : (i += 1) {
        if (i == 4) break;
        out[i] = std.fmt.parseInt(u32, t, 10) catch std.math.maxInt(u32);
    }
}

pub const Stat = struct {
    pid: u32,
    comm: []const u8,
    state: u8,
    ppid: u32,
    utime: u64,
    stime: u64,
    starttime: u64,
};

/// /proc/<pid>/stat. The comm field is parenthesised and may itself contain spaces and
/// parentheses, so fields are counted from the last ')'.
pub fn parseStat(text: []const u8) error{Malformed}!Stat {
    const open = std.mem.indexOfScalar(u8, text, '(') orelse return error.Malformed;
    const close = std.mem.lastIndexOfScalar(u8, text, ')') orelse return error.Malformed;
    if (close < open) return error.Malformed;
    const pid = std.fmt.parseInt(u32, std.mem.trim(u8, text[0..open], " "), 10) catch return error.Malformed;
    var fields = std.mem.tokenizeScalar(u8, text[close + 1 ..], ' ');
    var out: Stat = .{ .pid = pid, .comm = text[open + 1 .. close], .state = '?', .ppid = 0, .utime = 0, .stime = 0, .starttime = 0 };
    // Field 3 is state; utime is 14, stime 15, starttime 22.
    var n: usize = 3;
    while (fields.next()) |f| : (n += 1) {
        switch (n) {
            3 => out.state = if (f.len > 0) f[0] else '?',
            4 => out.ppid = std.fmt.parseInt(u32, f, 10) catch return error.Malformed,
            14 => out.utime = std.fmt.parseInt(u64, f, 10) catch return error.Malformed,
            15 => out.stime = std.fmt.parseInt(u64, f, 10) catch return error.Malformed,
            22 => {
                out.starttime = std.fmt.parseInt(u64, f, 10) catch return error.Malformed;
                return out;
            },
            else => {},
        }
    }
    return error.Malformed;
}

/// NUL-separated arguments of /proc/<pid>/cmdline.
pub const Args = struct {
    rest: []const u8,

    pub fn init(cmdline: []const u8) Args {
        return .{ .rest = std.mem.trimEnd(u8, cmdline, "\x00") };
    }

    pub fn next(a: *Args) ?[]const u8 {
        if (a.rest.len == 0) return null;
        const end = std.mem.indexOfScalar(u8, a.rest, 0) orelse a.rest.len;
        const arg = a.rest[0..end];
        a.rest = if (end < a.rest.len) a.rest[end + 1 ..] else a.rest[a.rest.len..];
        return arg;
    }
};

/// The value of `key` in /proc/<pid>/environ (NUL-separated KEY=value pairs).
pub fn environGet(environ: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, environ, 0);
    while (it.next()) |kv| {
        if (kv.len > key.len and kv[key.len] == '=' and std.mem.startsWith(u8, kv, key)) return kv[key.len + 1 ..];
    }
    return null;
}

pub const Mapping = struct {
    start: u64,
    end: u64,
    read: bool,
    write: bool,
    exec: bool,
    shared: bool,
    offset: u64,
    inode: u64,
    /// Pathname, a pseudo name such as `[heap]` or `[anon:...]`, or empty for anonymous memory.
    path: []const u8,
};

/// One line of /proc/<pid>/maps: `start-end perms offset dev inode path`.
pub fn parseMapsLine(line: []const u8) ?Mapping {
    var fields = std.mem.tokenizeScalar(u8, line, ' ');
    const range = fields.next() orelse return null;
    const perms = fields.next() orelse return null;
    const offset = fields.next() orelse return null;
    _ = fields.next() orelse return null; // dev
    const inode = fields.next() orelse return null;
    const dash = std.mem.indexOfScalar(u8, range, '-') orelse return null;
    if (perms.len < 4) return null;
    var path: []const u8 = fields.rest();
    path = std.mem.trim(u8, path, " ");
    return .{
        .start = std.fmt.parseInt(u64, range[0..dash], 16) catch return null,
        .end = std.fmt.parseInt(u64, range[dash + 1 ..], 16) catch return null,
        .read = perms[0] == 'r',
        .write = perms[1] == 'w',
        .exec = perms[2] == 'x',
        .shared = perms[3] == 's',
        .offset = std.fmt.parseInt(u64, offset, 16) catch return null,
        .inode = std.fmt.parseInt(u64, inode, 10) catch return null,
        .path = path,
    };
}

/// Strip " (deleted)" from a readlink result.
pub fn deletedTarget(link: []const u8) ?[]const u8 {
    const suffix = " (deleted)";
    if (std.mem.endsWith(u8, link, suffix)) return link[0 .. link.len - suffix.len];
    return null;
}

/// A process as seen once per scan.
pub const Process = struct {
    pid: u32,
    ppid: u32,
    uid: u32,
    euid: u32,
    comm: []const u8,
    /// Raw NUL-separated command line; empty for kernel threads and zombies.
    cmdline: []const u8,
    /// readlink of /proc/<pid>/exe, with " (deleted)" removed; null when unreadable.
    exe: ?[]const u8,
    exe_deleted: bool,
    /// The exe link could not be read (another user's process without root).
    exe_denied: bool,
    status: Status,
    utime: u64,
    stime: u64,

    pub fn isKernelThread(p: Process) bool {
        return !p.status.has_vm and p.cmdline.len == 0 and (p.ppid == 2 or p.pid == 2);
    }

    pub fn args(p: Process) Args {
        return Args.init(p.cmdline);
    }

    /// argv[0] basename.
    pub fn argv0(p: Process) []const u8 {
        var a = p.args();
        const first = a.next() orelse return "";
        const slash = std.mem.lastIndexOfScalar(u8, first, '/') orelse return first;
        return first[slash + 1 ..];
    }

    pub fn exeName(p: Process) []const u8 {
        const exe = p.exe orelse return "";
        const slash = std.mem.lastIndexOfScalar(u8, exe, '/') orelse return exe;
        return exe[slash + 1 ..];
    }
};

/// Pids listed by readdir on /proc.
pub fn listPids(gpa: std.mem.Allocator, h: Host, out: *std.ArrayList(u32)) !void {
    var dir = (h.openDir("/proc") catch return) orelse return;
    defer dir.close(h.io);
    var it = dir.iterate();
    while (it.next(h.io) catch null) |entry| {
        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        try out.append(gpa, pid);
    }
}

/// Read one process. Returns null when it exited (or is unreadable) while being read.
pub fn readProcess(arena: std.mem.Allocator, h: Host, pid: u32) !?Process {
    var path_buf: [64]u8 = undefined;
    var buf: [4096]u8 = undefined;
    const status_text = h.read(std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{pid}) catch unreachable, &buf) catch return null;
    const status_copy = try arena.dupe(u8, status_text);
    var status = parseStatus(status_copy);
    if (status.pid == 0) status.pid = pid;

    var stat_buf: [1024]u8 = undefined;
    var utime: u64 = 0;
    var stime: u64 = 0;
    if (h.readOpt(std.fmt.bufPrint(&path_buf, "/proc/{d}/stat", .{pid}) catch unreachable, &stat_buf)) |t| {
        if (parseStat(t)) |st| {
            utime = st.utime;
            stime = st.stime;
        } else |_| {}
    }

    const cmdline = h.readAlloc(arena, std.fmt.bufPrint(&path_buf, "/proc/{d}/cmdline", .{pid}) catch unreachable, 256 * 1024) catch "";

    var exe: ?[]const u8 = null;
    var deleted = false;
    var denied = false;
    var link_buf: [4096]u8 = undefined;
    const exe_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid}) catch unreachable;
    const n = h.root.readLink(h.io, Host.rel(exe_path), &link_buf) catch |e| blk: {
        if (e == error.AccessDenied or e == error.PermissionDenied) denied = true;
        break :blk null;
    };
    if (n) |len| {
        const link = link_buf[0..len];
        if (deletedTarget(link)) |t| {
            deleted = true;
            exe = try arena.dupe(u8, t);
        } else exe = try arena.dupe(u8, link);
    }
    return .{
        .pid = pid,
        .ppid = status.ppid,
        .uid = status.uid[0],
        .euid = status.uid[1],
        .comm = status.name,
        .cmdline = cmdline,
        .exe = exe,
        .exe_deleted = deleted,
        .exe_denied = denied,
        .status = status,
        .utime = utime,
        .stime = stime,
    };
}

/// Read every listed process.
pub fn snapshot(gpa: std.mem.Allocator, arena: std.mem.Allocator, h: Host, out: *std.ArrayList(Process)) !void {
    var pids: std.ArrayList(u32) = .empty;
    defer pids.deinit(gpa);
    try listPids(gpa, h, &pids);
    std.mem.sort(u32, pids.items, {}, std.sort.asc(u32));
    for (pids.items) |pid| if (try readProcess(arena, h, pid)) |p| try out.append(gpa, p);
}

test "status" {
    const s = parseStatus("Name:\txmrig\nUmask:\t0022\nState:\tR (running)\nTgid:\t4242\nPid:\t4242\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nVmSize:\t  2000 kB\nThreads:\t9\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\n");
    try std.testing.expectEqualStrings("xmrig", s.name);
    try std.testing.expectEqual(@as(u32, 1), s.ppid);
    try std.testing.expectEqual(@as(u32, 1000), s.uid[1]);
    try std.testing.expectEqual(@as(u64, 0x1ffffffffff), s.cap_bnd);
    try std.testing.expect(s.has_vm);
    try std.testing.expectEqual(@as(u8, 'R'), s.state);
}

test "stat with a hostile comm" {
    const st = try parseStat("77 (evil) (x 1 2) S 1 77 77 0 -1 4194304 100 0 0 0 1234 56 0 0 20 0 1 0 98765 1000 10 18446744073709551615");
    try std.testing.expectEqualStrings("evil) (x 1 2", st.comm);
    try std.testing.expectEqual(@as(u64, 1234), st.utime);
    try std.testing.expectEqual(@as(u64, 56), st.stime);
    try std.testing.expectEqual(@as(u64, 98765), st.starttime);
    try std.testing.expectEqual(@as(u32, 1), st.ppid);
    try std.testing.expectError(error.Malformed, parseStat("12 (x) S"));
    try std.testing.expectError(error.Malformed, parseStat("x) (12"));
}

test "cmdline, environ and maps" {
    var a = Args.init("/usr/bin/python3\x00-c\x00import os\x00");
    try std.testing.expectEqualStrings("/usr/bin/python3", a.next().?);
    try std.testing.expectEqualStrings("-c", a.next().?);
    try std.testing.expectEqualStrings("import os", a.next().?);
    try std.testing.expect(a.next() == null);
    try std.testing.expectEqualStrings("/tmp/x.so", environGet("PATH=/bin\x00LD_PRELOAD=/tmp/x.so\x00", "LD_PRELOAD").?);
    try std.testing.expect(environGet("LD_PRELOADX=1\x00", "LD_PRELOAD") == null);
    const m = parseMapsLine("7f2c1000-7f2c3000 r-xp 00001000 fd:01 1048602    /usr/lib/x86_64-linux-gnu/libc.so.6").?;
    try std.testing.expect(m.exec and !m.write and m.read);
    try std.testing.expectEqual(@as(u64, 1048602), m.inode);
    try std.testing.expectEqualStrings("/usr/lib/x86_64-linux-gnu/libc.so.6", m.path);
    const anon = parseMapsLine("7f00-8f00 rwxp 00000000 00:00 0 ").?;
    try std.testing.expectEqualStrings("", anon.path);
    try std.testing.expect(parseMapsLine("garbage") == null);
    try std.testing.expectEqualStrings("/tmp/x", deletedTarget("/tmp/x (deleted)").?);
}
