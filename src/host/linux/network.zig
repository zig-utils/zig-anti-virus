//! Network checks from /proc/net and process file descriptors, never `ss`: reverse shells (a
//! shell or interpreter whose stdio is a TCP socket), bind shells and listeners judged by the
//! process that owns them, and sockets the kernel reports over netlink sock_diag that are missing
//! from /proc/net (a rootkit filtering tcp4_seq_show).
//!
//! linux-guardian flagged any listener above port 50000 and any binary named nc; here a listener
//! is judged by who owns it (package ownership, path, what the program is) and by server context.
const std = @import("std");
const builtin = @import("builtin");
const scan = @import("../scan.zig");
const tokens = @import("../tokens.zig");
const procfs = @import("procfs.zig");
const process = @import("process.zig");
const finding = @import("../finding.zig");
const Host = @import("../host.zig").Host;

pub const checks = [_]scan.Check{
    .{ .id = "network.reverse_shell", .category = .malware, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Shells and interpreters whose stdio is a network socket", .run = checkReverseShells },
    .{ .id = "network.listener", .category = .network, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Listening sockets judged by their owning process and server context", .run = checkListeners },
    .{ .id = "network.hidden_socket", .category = .malware, .tier = .deep, .privilege = .none, .os = .linux, .summary = "Sockets in netlink sock_diag but missing from /proc/net", .run = checkHiddenSockets },
};

pub const Proto = enum { tcp, udp, unix };

pub const State = enum(u8) {
    established = 1,
    syn_sent = 2,
    syn_recv = 3,
    fin_wait1 = 4,
    fin_wait2 = 5,
    time_wait = 6,
    close = 7,
    close_wait = 8,
    last_ack = 9,
    listen = 10,
    closing = 11,
    _,
};

pub const Addr = struct {
    family: u8, // 4 or 6
    bytes: [16]u8 = @splat(0),
    port: u16,

    pub fn isLoopback(a: Addr) bool {
        if (a.family == 4) return a.bytes[0] == 127;
        if (std.mem.allEqual(u8, a.bytes[0..15], 0) and a.bytes[15] == 1) return true;
        // IPv4-mapped ::ffff:127.x.x.x
        return std.mem.allEqual(u8, a.bytes[0..10], 0) and a.bytes[10] == 0xff and a.bytes[11] == 0xff and a.bytes[12] == 127;
    }

    pub fn isAny(a: Addr) bool {
        const n: usize = if (a.family == 4) 4 else 16;
        return std.mem.allEqual(u8, a.bytes[0..n], 0);
    }

    pub fn format(a: Addr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (a.family == 4) return w.print("{d}.{d}.{d}.{d}:{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3], a.port });
        try w.writeByte('[');
        var i: usize = 0;
        while (i < 16) : (i += 2) {
            if (i > 0) try w.writeByte(':');
            try w.print("{x}", .{std.mem.readInt(u16, a.bytes[i..][0..2], .big)});
        }
        try w.print("]:{d}", .{a.port});
    }
};

pub const Socket = struct {
    proto: Proto,
    local: Addr,
    remote: Addr,
    state: State,
    uid: u32,
    inode: u64,
};

/// Parse `0100007F:0CEA` (IPv4) or 32 hex digits plus port (IPv6). The kernel prints each 32-bit
/// word in host byte order; zav runs only on little-endian hosts.
pub fn parseAddr(text: []const u8) ?Addr {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return null;
    const hex = text[0..colon];
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 16) catch return null;
    var a: Addr = .{ .family = 0, .port = port };
    if (hex.len == 8) {
        a.family = 4;
        const v = std.fmt.parseInt(u32, hex, 16) catch return null;
        std.mem.writeInt(u32, a.bytes[0..4], v, .little);
    } else if (hex.len == 32) {
        a.family = 6;
        for (0..4) |i| {
            const v = std.fmt.parseInt(u32, hex[i * 8 ..][0..8], 16) catch return null;
            std.mem.writeInt(u32, a.bytes[i * 4 ..][0..4], v, .little);
        }
    } else return null;
    return a;
}

/// One data line of /proc/net/tcp, tcp6, udp or udp6.
pub fn parseInetLine(proto: Proto, line: []const u8) ?Socket {
    var f = std.mem.tokenizeScalar(u8, line, ' ');
    const sl = f.next() orelse return null;
    if (sl.len == 0 or sl[sl.len - 1] != ':') return null;
    const local = parseAddr(f.next() orelse return null) orelse return null;
    const remote = parseAddr(f.next() orelse return null) orelse return null;
    const st = std.fmt.parseInt(u8, f.next() orelse return null, 16) catch return null;
    _ = f.next() orelse return null; // tx:rx queue
    _ = f.next() orelse return null; // timer
    _ = f.next() orelse return null; // retransmits
    const uid = std.fmt.parseInt(u32, f.next() orelse return null, 10) catch return null;
    _ = f.next() orelse return null; // timeout
    const inode = std.fmt.parseInt(u64, f.next() orelse return null, 10) catch return null;
    return .{ .proto = proto, .local = local, .remote = remote, .state = @fromBackingInt(@intCast(st)), .uid = uid, .inode = inode };
}

/// Read /proc/net/{tcp,tcp6,udp,udp6} under `prefix` ("/proc" or "/proc/<pid>").
pub fn readInet(gpa: std.mem.Allocator, h: Host, prefix: []const u8, out: *std.ArrayList(Socket)) !void {
    const files = [_]struct { name: []const u8, proto: Proto }{
        .{ .name = "tcp", .proto = .tcp }, .{ .name = "tcp6", .proto = .tcp }, .{ .name = "udp", .proto = .udp }, .{ .name = "udp6", .proto = .udp },
    };
    var path_buf: [96]u8 = undefined;
    for (files) |file| {
        const path = std.fmt.bufPrint(&path_buf, "{s}/net/{s}", .{ prefix, file.name }) catch continue;
        const text = h.readAlloc(gpa, path, 64 * 1024 * 1024) catch continue;
        defer gpa.free(text);
        var lines = std.mem.splitScalar(u8, text, '\n');
        _ = lines.next(); // header
        while (lines.next()) |line| if (parseInetLine(file.proto, line)) |s| try out.append(gpa, s);
    }
}

/// `socket:[12345]` -> 12345.
pub fn socketInode(link: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, link, "socket:[") or link.len < 10 or link[link.len - 1] != ']') return null;
    return std.fmt.parseInt(u64, link[8 .. link.len - 1], 10) catch null;
}

/// Socket inode -> owning pids, from every readable /proc/<pid>/fd.
pub const Owners = struct {
    map: std.AutoHashMapUnmanaged(u64, std.ArrayList(u32)) = .empty,
    unreadable: usize = 0,

    pub fn deinit(o: *Owners, gpa: std.mem.Allocator) void {
        var it = o.map.valueIterator();
        while (it.next()) |l| l.deinit(gpa);
        o.map.deinit(gpa);
    }

    pub fn build(gpa: std.mem.Allocator, h: Host, procs: []const procfs.Process) !Owners {
        var o: Owners = .{};
        errdefer o.deinit(gpa);
        var path_buf: [64]u8 = undefined;
        var link_buf: [128]u8 = undefined;
        for (procs) |p| {
            const fd_dir = std.fmt.bufPrint(&path_buf, "/proc/{d}/fd", .{p.pid}) catch continue;
            var dir = (h.openDir(fd_dir) catch {
                o.unreadable += 1;
                continue;
            }) orelse continue;
            defer dir.close(h.io);
            var it = dir.iterate();
            while (it.next(h.io) catch null) |entry| {
                const n = dir.readLink(h.io, entry.name, &link_buf) catch continue;
                const inode = socketInode(link_buf[0..n]) orelse continue;
                const gop = try o.map.getOrPut(gpa, inode);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                if (std.mem.indexOfScalar(u32, gop.value_ptr.items, p.pid) == null) try gop.value_ptr.append(gpa, p.pid);
            }
        }
        return o;
    }

    pub fn of(o: *const Owners, inode: u64) []const u32 {
        const l = o.map.get(inode) orelse return &.{};
        return l.items;
    }
};

fn findProc(procs: []const procfs.Process, pid: u32) ?procfs.Process {
    for (procs) |p| if (p.pid == pid) return p;
    return null;
}

/// What kind of program a process is, by its executable (or comm when the exe is unreadable).
pub const Program = enum { shell, interpreter, relay, other };

pub fn programOf(p: procfs.Process) Program {
    const name = if (p.exe != null) p.exeName() else p.comm;
    if (tokens.isShell(name)) return .shell;
    if (tokens.isRelay(name)) return .relay;
    if (tokens.isInterpreter(name)) return .interpreter;
    return .other;
}

fn hasInlineCode(p: procfs.Process) bool {
    var a = p.args();
    _ = a.next();
    while (a.next()) |arg| if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--eval")) return true;
    return false;
}

fn sockByInode(socks: []const Socket, inode: u64) ?Socket {
    for (socks) |s| if (s.inode == inode) return s;
    return null;
}

// Reverse shells --------------------------------------------------------------------------------

fn checkReverseShells(s: *scan.Scan) !void {
    const procs = try s.processes();
    var socks: std.ArrayList(Socket) = .empty;
    defer socks.deinit(s.gpa);
    try readInet(s.gpa, s.host, "/proc", &socks);
    var path_buf: [64]u8 = undefined;
    var link_buf: [128]u8 = undefined;
    var unreadable: usize = 0;
    for (procs) |p| {
        const program = programOf(p);
        if (program == .other) continue;
        // stdin, stdout, stderr.
        var stdio_sock: ?Socket = null;
        var fd: u8 = 0;
        while (fd < 3) : (fd += 1) {
            const link_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/fd/{d}", .{ p.pid, fd }) catch continue;
            const n = s.host.root.readLink(s.host.io, Host.rel(link_path), &link_buf) catch |e| {
                if (e == error.AccessDenied or e == error.PermissionDenied) unreadable += 1;
                continue;
            };
            const inode = socketInode(link_buf[0..n]) orelse continue;
            var sock = sockByInode(socks.items, inode);
            if (sock == null) {
                // The process may live in another network namespace (a container).
                var ns_socks: std.ArrayList(Socket) = .empty;
                defer ns_socks.deinit(s.gpa);
                var prefix_buf: [32]u8 = undefined;
                try readInet(s.gpa, s.host, std.fmt.bufPrint(&prefix_buf, "/proc/{d}", .{p.pid}) catch continue, &ns_socks);
                sock = sockByInode(ns_socks.items, inode);
            }
            if (sock) |so| if (so.proto == .tcp and so.state != .listen) {
                stdio_sock = so;
                break;
            };
        }
        const so = stdio_sock orelse continue;
        if (program == .interpreter and !hasInlineCode(p) and !std.mem.containsAtLeast(u8, p.cmdline, 1, "/dev/tcp")) {
            // An interpreter running a script file on a socket is how inetd-style services
            // work; only inline code (-c, -e) is the reverse-shell shape.
            continue;
        }
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "Reverse shell: shell or interpreter wired to a network socket",
            .description = try s.print("Process {d} ({s}) is a {t} whose standard I/O is a TCP connection {f} -> {f}. Interactive shells talk to terminals; one reading commands from a socket is a reverse or bind shell.", .{ p.pid, p.comm, program, so.local, so.remote }),
            .remediation = try s.print("Capture the connection (remote {f}) and the process tree (parent {d}), kill {d}, block the remote address, and find the vulnerability or credential that let it start.", .{ so.remote, p.ppid, p.pid }),
            .subject = p.exe orelse p.comm,
            .pid = p.pid,
            .details = try s.details(&.{
                .{ .key = "comm", .value = p.comm },
                .{ .key = "local", .value = try s.print("{f}", .{so.local}) },
                .{ .key = "remote", .value = try s.print("{f}", .{so.remote}) },
                .{ .key = "state", .value = @tagName(so.state) },
                .{ .key = "loopback", .value = if (so.remote.isLoopback()) "true" else "false" },
            }),
        });
    }
    if (unreadable > 0) try s.reduced("{d} file descriptors of other users' processes were unreadable without root", .{unreadable});
}

// Listeners -------------------------------------------------------------------------------------

fn checkListeners(s: *scan.Scan) !void {
    const procs = try s.processes();
    var socks: std.ArrayList(Socket) = .empty;
    defer socks.deinit(s.gpa);
    try readInet(s.gpa, s.host, "/proc", &socks);
    var owners = try Owners.build(s.gpa, s.host, procs);
    defer owners.deinit(s.gpa);
    var unowned_sockets: usize = 0;
    for (socks.items) |so| {
        const listening = (so.proto == .tcp and so.state == .listen) or (so.proto == .udp and so.state == .close and so.remote.isAny());
        if (!listening or so.local.isLoopback() or so.inode == 0) continue;
        const pids = owners.of(so.inode);
        if (pids.len == 0) {
            unowned_sockets += 1;
            continue;
        }
        const p = findProc(procs, pids[0]) orelse continue;
        const exe = p.exe orelse p.comm;
        const program = programOf(p);
        const risk = if (p.exe) |e| process.exeRisk(e) else null;
        const memfd = std.mem.startsWith(u8, exe, "/memfd:");

        var severity: ?finding.Severity = null;
        var title: []const u8 = "";
        var why: []const u8 = "";
        if (program == .shell or (program == .relay and hasRelayExec(p))) {
            severity = .critical;
            title = "Bind shell listening on the network";
            why = "a shell, or a relay that hands connections to a program, is listening: anyone who connects gets a shell";
        } else if (memfd or risk != null or p.exe_deleted) {
            severity = .critical;
            title = "Listener from a deleted, fileless or temp-directory program";
            why = "the listening program runs from a location no installed service uses";
        } else if (program == .relay) {
            severity = .high;
            title = "Network relay listening";
            why = "nc, ncat or socat is listening; relays are used to tunnel into networks";
        } else if (!s.owned(exe) and !s.context.expectsPort(so.local.port) and @import("../context.zig").Service.fromComm(p.comm) == null) {
            severity = .low;
            title = "Listener from a program no package owns";
            why = "the program is not package-managed and is not a service this host is known to run";
        }
        const sev = severity orelse continue;
        try s.add(.{
            .severity = sev,
            .category = if (sev == .critical) .malware else .network,
            .title = title,
            .description = try s.print("{s} ({d}, {s}) listens on {t} {f}: {s}.", .{ p.comm, p.pid, exe, so.proto, so.local, why }),
            .remediation = try s.print("Confirm what the service is. If it is not yours, stop process {d}, remove its binary and look for how it was started; otherwise bind it to localhost or firewall the port.", .{p.pid}),
            .subject = exe,
            .pid = p.pid,
            .details = try s.details(&.{
                .{ .key = "comm", .value = p.comm },
                .{ .key = "address", .value = try s.print("{f}", .{so.local}) },
                .{ .key = "protocol", .value = @tagName(so.proto) },
                .{ .key = "owned_by", .value = s.owner(exe) orelse "" },
            }),
        });
    }
    if (owners.unreadable > 0 or (unowned_sockets > 0 and s.host.euid != 0))
        try s.reduced("socket owners of {d} processes were unreadable without root", .{owners.unreadable});
}

fn hasRelayExec(p: procfs.Process) bool {
    var a = p.args();
    while (a.next()) |arg| {
        if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--exec") or std.mem.eql(u8, arg, "--sh-exec")) return true;
        if (std.ascii.startsWithIgnoreCase(arg, "exec:") or std.ascii.startsWithIgnoreCase(arg, "system:")) return true;
    }
    return false;
}

// Hidden sockets ---------------------------------------------------------------------------------

/// Inodes present in `kernel` but absent from `proc` (both unsorted).
pub fn missing(gpa: std.mem.Allocator, kernel: []const u64, proc: []const u64, out: *std.ArrayList(u64)) !void {
    var set: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer set.deinit(gpa);
    for (proc) |i| try set.put(gpa, i, {});
    for (kernel) |i| if (i != 0 and !set.contains(i)) try out.append(gpa, i);
}

fn procInodes(gpa: std.mem.Allocator, h: Host, out: *std.ArrayList(u64)) !void {
    var socks: std.ArrayList(Socket) = .empty;
    defer socks.deinit(gpa);
    try readInet(gpa, h, "/proc", &socks);
    for (socks.items) |so| if (so.proto == .tcp) try out.append(gpa, so.inode);
}

fn checkHiddenSockets(s: *scan.Scan) !void {
    if (!s.host.live or builtin.os.tag != .linux) {
        try s.reduced("netlink sock_diag needs the live host", .{});
        return;
    }
    var kernel: std.ArrayList(u64) = .empty;
    defer kernel.deinit(s.gpa);
    sockDiagTcp(s.gpa, &kernel) catch |e| {
        try s.reduced("netlink sock_diag failed: {t}", .{e});
        return;
    };
    var proc: std.ArrayList(u64) = .empty;
    defer proc.deinit(s.gpa);
    try procInodes(s.gpa, s.host, &proc);
    var gone: std.ArrayList(u64) = .empty;
    defer gone.deinit(s.gpa);
    try missing(s.gpa, kernel.items, proc.items, &gone);
    if (gone.items.len == 0) return;
    // Connections open and close between the two reads; only report what is still missing from a
    // fresh /proc read and still present in a fresh netlink dump.
    kernel.clearRetainingCapacity();
    sockDiagTcp(s.gpa, &kernel) catch return;
    proc.clearRetainingCapacity();
    try procInodes(s.gpa, s.host, &proc);
    var still: std.ArrayList(u64) = .empty;
    defer still.deinit(s.gpa);
    try missing(s.gpa, kernel.items, proc.items, &still);
    for (still.items) |inode| {
        if (std.mem.indexOfScalar(u64, gone.items, inode) == null) continue;
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "TCP socket hidden from /proc/net",
            .description = try s.print("Socket inode {d} is reported by netlink sock_diag but missing from /proc/net/tcp and tcp6, twice in a row. Rootkits hide connections by hooking the /proc/net seq_file output.", .{inode}),
            .remediation = "Treat the host as compromised by a kernel rootkit; capture memory and inspect from a trusted boot medium.",
            .details = try s.details(&.{.{ .key = "inode", .value = try s.print("{d}", .{inode}) }}),
        });
    }
}

/// Dump every IPv4 and IPv6 TCP socket's inode through NETLINK_SOCK_DIAG.
pub fn sockDiagTcp(gpa: std.mem.Allocator, out: *std.ArrayList(u64)) !void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 4); // NETLINK_SOCK_DIAG
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        var req: [72]u8 align(4) = @splat(0);
        std.mem.writeInt(u32, req[0..4], 72, .little); // nlmsg_len
        std.mem.writeInt(u16, req[4..6], 20, .little); // SOCK_DIAG_BY_FAMILY
        std.mem.writeInt(u16, req[6..8], 0x1 | 0x300, .little); // NLM_F_REQUEST | NLM_F_DUMP
        std.mem.writeInt(u32, req[8..12], family, .little); // seq
        req[16] = family;
        req[17] = 6; // IPPROTO_TCP
        std.mem.writeInt(u32, req[20..24], 0xffffffff, .little); // all states
        var addr: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        const sent = linux.sendto(fd, &req, req.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl));
        if (linux.errno(sent) != .SUCCESS) return error.SendFailed;
        var buf: [32 * 1024]u8 align(4) = undefined;
        var done = false;
        var guard: usize = 0;
        while (!done) {
            guard += 1;
            if (guard > 1 << 16) return error.TooManyMessages;
            const n = linux.recvfrom(fd, &buf, buf.len, 0, null, null);
            if (linux.errno(n) != .SUCCESS) return error.RecvFailed;
            if (n == 0) break;
            try parseDiag(gpa, buf[0..n], out, &done);
        }
    }
}

/// Parse a batch of netlink messages carrying inet_diag_msg records.
pub fn parseDiag(gpa: std.mem.Allocator, data: []const u8, out: *std.ArrayList(u64), done: *bool) !void {
    var off: usize = 0;
    while (off + 16 <= data.len) {
        const len = std.mem.readInt(u32, data[off..][0..4], .little);
        const typ = std.mem.readInt(u16, data[off + 4 ..][0..2], .little);
        if (len < 16 or off + len > data.len) return error.Malformed;
        if (typ == 3) { // NLMSG_DONE
            done.* = true;
            return;
        }
        if (typ == 2) return error.NetlinkError; // NLMSG_ERROR
        // inet_diag_msg: family, state, timer, retrans, id[48], expires, rqueue, wqueue, uid, inode.
        if (len >= 16 + 72) {
            const inode = std.mem.readInt(u32, data[off + 16 + 68 ..][0..4], .little);
            if (inode != 0) try out.append(gpa, inode);
        }
        off += std.mem.alignForward(usize, len, 4);
    }
}

// Tests -----------------------------------------------------------------------------------------

test "inet lines, addresses and socket links" {
    const s = parseInetLine(.tcp, "   0: 0100007F:0CEA 0200007F:A2D2 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1").?;
    try std.testing.expectEqual(State.established, s.state);
    try std.testing.expectEqual(@as(u16, 3306), s.local.port);
    try std.testing.expect(s.local.isLoopback());
    try std.testing.expectEqual(@as(u8, 2), s.remote.bytes[3]);
    try std.testing.expectEqual(@as(u64, 12345), s.inode);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1:3306", try std.fmt.bufPrint(&buf, "{f}", .{s.local}));
    const v6 = parseInetLine(.tcp, "   1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1").?;
    try std.testing.expect(v6.local.isLoopback());
    try std.testing.expectEqual(State.listen, v6.state);
    const any6 = parseInetLine(.tcp, "   2: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 998 1").?;
    try std.testing.expect(any6.local.isAny() and !any6.local.isLoopback());
    try std.testing.expect(parseInetLine(.tcp, "  sl  local_address rem_address   st tx_queue") == null);
    try std.testing.expectEqual(@as(u64, 42), socketInode("socket:[42]").?);
    try std.testing.expect(socketInode("pipe:[42]") == null);
}

test "netlink parsing and hidden-socket comparison" {
    var msg: [16 + 72 + 16]u8 = @splat(0);
    std.mem.writeInt(u32, msg[0..4], 16 + 72, .little);
    std.mem.writeInt(u16, msg[4..6], 20, .little);
    std.mem.writeInt(u32, msg[16 + 68 ..][0..4], 777, .little);
    std.mem.writeInt(u32, msg[88..92], 16, .little);
    std.mem.writeInt(u16, msg[92..94], 3, .little);
    var out: std.ArrayList(u64) = .empty;
    defer out.deinit(std.testing.allocator);
    var done = false;
    try parseDiag(std.testing.allocator, &msg, &out, &done);
    try std.testing.expect(done);
    try std.testing.expectEqualSlices(u64, &.{777}, out.items);
    var gone: std.ArrayList(u64) = .empty;
    defer gone.deinit(std.testing.allocator);
    try missing(std.testing.allocator, &.{ 1, 2, 3, 0 }, &.{ 3, 1 }, &gone);
    try std.testing.expectEqualSlices(u64, &.{2}, gone.items);
}

const Fixture = @import("../host.zig").Fixture;

test "fixture: reverse shell, bind shell and quiet normal services" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\nVersion: 1\n\nPackage: bash\nStatus: install ok installed\nVersion: 5\n");
    try fx.file("/var/lib/dpkg/info/openssh-server.list", "/usr/sbin/sshd\n");
    try fx.file("/var/lib/dpkg/info/bash.list", "/usr/bin/bash\n");
    try fx.file("/proc/net/tcp",
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1
        \\   1: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 101 1
        \\   2: 0A00000A:D431 0100000A:115C 01 00000000:00000000 00:00000000 00000000  1000        0 102 1
        \\   3: 00000000:7A69 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 103 1
        \\
    );
    // sshd on 22 (owned), bun app on 3000 (unowned, expected by context), a bash reverse shell
    // to 10.0.0.1:4444, and a shell listening on 31337.
    try process.fakeProcess(&fx, 700, "sshd", 1, "/usr/sbin/sshd", "sshd\x00");
    try fx.link("/proc/700/fd/3", "socket:[100]");
    try process.fakeProcess(&fx, 800, "bun", 1, "/home/app/.bun/bin/bun", "bun\x00run\x00server.ts\x00");
    try fx.link("/proc/800/fd/12", "socket:[101]");
    try process.fakeProcess(&fx, 900, "bash", 1, "/usr/bin/bash", "bash\x00-i\x00");
    try fx.link("/proc/900/fd/0", "socket:[102]");
    try fx.link("/proc/900/fd/1", "socket:[102]");
    try process.fakeProcess(&fx, 950, "sh", 1, "/usr/bin/dash", "sh\x00");
    try fx.link("/proc/950/fd/0", "socket:[103]");
    try fx.link("/proc/950/fd/4", "socket:[103]");

    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{"network"}, .context = .{ .role = .server, .services = .initMany(&.{ .sshd, .bun }) } });
    defer s.deinit();
    try s.runChecks(&checks);
    var reverse = false;
    var bind = false;
    for (s.findings.items) |f| {
        try std.testing.expect(f.pid.? != 700 and f.pid.? != 800);
        if (std.mem.eql(u8, f.check, "network.reverse_shell") and f.pid.? == 900) reverse = true;
        if (std.mem.eql(u8, f.check, "network.listener") and f.pid.? == 950) bind = true;
    }
    try std.testing.expect(reverse and bind);
}

test "live: a reverse shell over a loopback socket is detected" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var listen_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try listen_addr.listen(io, .{});
    defer server.deinit(io);
    const stream = try server.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const file: std.Io.File = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } };
    var child = try std.process.spawn(io, .{ .argv = &.{ "/bin/sh", "-c", "sleep 30; exit 0" }, .stdin = .{ .file = file }, .stdout = .{ .file = file } });
    defer child.kill(io);
    const pid: u32 = @intCast(child.id.?);

    const h = try Host.openLive(io);
    defer h.close();
    var found = false;
    var attempt: usize = 0;
    while (attempt < 50 and !found) : (attempt += 1) {
        var s = scan.Scan.init(gpa, h, .{ .only = &.{"network.reverse_shell"} });
        defer s.deinit();
        try s.runChecks(&checks);
        for (s.findings.items) |f| if (f.pid == pid) {
            found = true;
        };
        if (!found) try io.sleep(.fromMilliseconds(20), .awake);
    }
    try std.testing.expect(found);
}
