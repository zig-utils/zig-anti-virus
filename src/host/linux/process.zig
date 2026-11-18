//! Linux process checks, read straight from /proc so a userland rootkit that patches ps cannot
//! hide from them: cryptominers, executables in temp or hidden directories, deleted and fileless
//! (memfd) executables, processes disguised as kernel threads, anonymous executable memory,
//! processes hidden from the /proc listing, sustained CPU from unowned binaries, and unowned
//! executables scanned through the engine.
//!
//! Names match as tokens (tokens.zig), and package ownership replaces linux-guardian's
//! allowlists: an allowlisted 'sh' there also matched sshd and bash.
const std = @import("std");
const scan = @import("../scan.zig");
const tokens = @import("../tokens.zig");
const procfs = @import("procfs.zig");
const sys = @import("../sys.zig");
const finding = @import("../finding.zig");
const Host = @import("../host.zig").Host;

pub const checks = [_]scan.Check{
    .{ .id = "process.miner", .category = .malware, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Cryptominers by tokenised name, stratum URL, pool domain and miner flags", .run = checkMiners },
    .{ .id = "process.memfd", .category = .malware, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Fileless executables running from memfd", .run = checkMemfd },
    .{ .id = "process.masquerade", .category = .malware, .tier = .fast, .privilege = .none, .os = .linux, .summary = "User processes disguised as kernel threads", .run = checkMasquerade },
    .{ .id = "process.temp_exec", .category = .process, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Executables running from temp, /dev or hidden directories", .run = checkTempExec },
    .{ .id = "process.deleted_exe", .category = .process, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Processes whose unowned executable was deleted", .run = checkDeletedExe },
    .{ .id = "process.malware_exe", .category = .malware, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Unowned running executables scanned with the signature engine", .run = checkMalwareExe },
    .{ .id = "process.anon_exec", .category = .process, .tier = .deep, .privilege = .partial, .os = .linux, .summary = "Anonymous or memfd executable memory outside JIT runtimes", .run = checkAnonExec },
    .{ .id = "process.hidden", .category = .malware, .tier = .deep, .privilege = .none, .os = .linux, .summary = "Processes alive but missing from the /proc listing", .run = checkHidden },
    .{ .id = "process.cpu", .category = .process, .tier = .deep, .privilege = .none, .os = .linux, .summary = "Sustained CPU from unowned executables over a short sampling window", .run = checkCpu },
};

// Miners ---------------------------------------------------------------------------------------

/// Miner program names, as token sequences.
pub const miner_names = [_][]const u8{
    "xmrig",        "xmr stak", "xmrstak",   "minerd",    "cpuminer",     "ccminer",  "ethminer", "nbminer",
    "phoenixminer", "lolminer", "gminer",    "nanominer", "teamredminer", "srbminer", "bminer",   "t rex",
    "kdevtmpfsi",   "kinsing",  "hellminer", "cgminer",   "bfgminer",     "sgminer",  "wildrig",  "xmr miner",
};

/// Mining pool domains; hosts match on a label boundary.
pub const pool_domains = [_][]const u8{
    "supportxmr.com", "minexmr.com",    "hashvault.pro", "moneroocean.stream", "nanopool.org",   "f2pool.com",
    "2miners.com",    "herominers.com", "c3pool.com",    "unmineable.com",     "nicehash.com",   "minergate.com",
    "ethermine.org",  "xmrpool.eu",     "viaxmr.com",    "monerohash.com",     "crypto-pool.fr", "miningpoolhub.com",
    "dwarfpool.com",  "prohashing.com", "zpool.ca",      "kryptex.network",    "woolypooly.com", "flypool.org",
    "antpool.com",    "viabtc.com",     "poolin.com",    "xmrfast.com",        "hashcity.org",   "zergpool.com",
};

/// Flags only miners take.
const miner_flags = [_][]const u8{ "--donate-level", "--donate-over-proxy", "--randomx-mode", "--randomx-1gb-pages", "--cpu-max-threads-hint", "--rig-id", "--nicehash", "--cpu-priority", "--max-cpu-usage" };
/// Mining algorithm names as values of -a / --algo / --coin.
const miner_algos = [_][]const u8{ "rx/0", "rx/wow", "cn/r", "cn/0", "cryptonight", "randomx", "kawpow", "ethash", "autolykos", "monero", "xmr" };

pub const MinerEvidence = struct {
    name: ?[]const u8 = null,
    stratum: ?[]const u8 = null,
    pool: ?[]const u8 = null,
    flags: u8 = 0,
    algo: ?[]const u8 = null,

    pub fn isMiner(e: MinerEvidence) bool {
        return e.name != null or e.stratum != null or e.pool != null or e.flags >= 2 or (e.flags >= 1 and e.algo != null);
    }
};

/// The host of a URL-ish argument (`stratum+tcp://host:port`, `host:port`), or null.
fn argHost(arg: []const u8) ?[]const u8 {
    var rest = arg;
    if (std.mem.indexOf(u8, rest, "://")) |i| rest = rest[i + 3 ..];
    if (std.mem.indexOfScalar(u8, rest, '@')) |i| rest = rest[i + 1 ..];
    const end = std.mem.indexOfAny(u8, rest, ":/") orelse rest.len;
    const host = rest[0..end];
    if (host.len == 0 or std.mem.indexOfScalar(u8, host, '.') == null) return null;
    return host;
}

pub fn minerEvidence(p: procfs.Process) MinerEvidence {
    var e: MinerEvidence = .{};
    for ([_][]const u8{ p.comm, p.exeName(), p.argv0() }) |name| {
        if (name.len == 0) continue;
        if (tokens.firstMatch(name, &miner_names)) |m| e.name = m;
    }
    var args = p.args();
    var expect_algo = false;
    while (args.next()) |raw| {
        // `--url=stratum+tcp://...` and `-o stratum+tcp://...` alike.
        const value = if (std.mem.indexOfScalar(u8, raw, '=')) |i| raw[i + 1 ..] else raw;
        const key = if (std.mem.indexOfScalar(u8, raw, '=')) |i| raw[0..i] else raw;
        if (expect_algo) {
            for (miner_algos) |a| if (std.ascii.eqlIgnoreCase(raw, a)) {
                e.algo = a;
            };
            expect_algo = false;
        }
        if (std.mem.indexOf(u8, value, "://")) |i| {
            if (tokens.hasToken(value[0..i], "stratum") or tokens.hasToken(value[0..i], "stratum1") or tokens.hasToken(value[0..i], "stratum2")) e.stratum = value;
        }
        if (argHost(value)) |host| for (pool_domains) |d| if (tokens.domainMatches(host, d)) {
            e.pool = d;
        };
        for (miner_flags) |f| if (std.mem.eql(u8, key, f)) {
            e.flags +|= 1;
        };
        if (std.mem.eql(u8, key, "-a") or std.mem.eql(u8, key, "--algo") or std.mem.eql(u8, key, "--coin")) {
            if (key.len == raw.len) expect_algo = true else for (miner_algos) |a| if (std.ascii.eqlIgnoreCase(value, a)) {
                e.algo = a;
            };
        }
    }
    return e;
}

fn processDetails(s: *scan.Scan, p: procfs.Process, extra: []const finding.Detail) ![]const finding.Detail {
    var list: std.ArrayList(finding.Detail) = .empty;
    const a = s.arena();
    try list.append(a, .{ .key = "comm", .value = p.comm });
    try list.append(a, .{ .key = "uid", .value = try s.print("{d}", .{p.uid}) });
    try list.append(a, .{ .key = "ppid", .value = try s.print("{d}", .{p.ppid}) });
    if (p.exe) |exe| try list.append(a, .{ .key = "exe", .value = exe });
    if (p.exe_deleted) try list.append(a, .{ .key = "exe_deleted", .value = "true" });
    try list.append(a, .{ .key = "cmdline", .value = try cmdlineString(s, p) });
    try list.appendSlice(a, extra);
    return list.items;
}

fn cmdlineString(s: *scan.Scan, p: procfs.Process) ![]const u8 {
    const limit = @min(p.cmdline.len, 1024);
    const copy = try s.arena().dupe(u8, std.mem.trimEnd(u8, p.cmdline[0..limit], "\x00"));
    for (copy) |*c| if (c.* == 0) {
        c.* = ' ';
    } else if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    return copy;
}

fn subject(p: procfs.Process) ?[]const u8 {
    return p.exe orelse if (p.comm.len > 0) p.comm else null;
}

fn noteDenied(s: *scan.Scan, procs: []const procfs.Process) !void {
    var denied: usize = 0;
    for (procs) |p| if (p.exe_denied) {
        denied += 1;
    };
    if (denied > 0) try s.reduced("{d} processes belong to other users; their executables are unreadable without root", .{denied});
}

fn checkMiners(s: *scan.Scan) !void {
    const procs = try s.processes();
    for (procs) |p| {
        if (p.isKernelThread()) continue;
        const e = minerEvidence(p);
        if (!e.isMiner()) continue;
        var why: std.ArrayList(u8) = .empty;
        const a = s.arena();
        if (e.name) |n| try why.print(a, "miner name '{s}'; ", .{n});
        if (e.stratum) |u| try why.print(a, "stratum URL {s}; ", .{u});
        if (e.pool) |d| try why.print(a, "mining pool {s}; ", .{d});
        if (e.flags > 0) try why.print(a, "{d} miner-only flags; ", .{e.flags});
        if (e.algo) |al| try why.print(a, "mining algorithm {s}; ", .{al});
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "Cryptominer running",
            .description = try s.print("Process {d} ({s}) is a cryptominer: {s}Miners are the most common payload after a server compromise.", .{ p.pid, p.comm, why.items }),
            .remediation = try s.print("Preserve evidence (cp /proc/{d}/exe and cmdline), then kill -9 {d}. Find how it started: check cron, systemd units, shell rc files and SSH keys, and rotate credentials.", .{ p.pid, p.pid }),
            .subject = subject(p),
            .pid = p.pid,
            .details = try processDetails(s, p, &.{}),
        });
    }
    try noteDenied(s, procs);
}

// Paths ----------------------------------------------------------------------------------------

pub const PathRisk = enum {
    temp,
    dev,
    hidden,

    pub fn describe(r: PathRisk) []const u8 {
        return switch (r) {
            .temp => "a world-writable temp directory",
            .dev => "/dev, where no executables belong",
            .hidden => "a hidden directory",
        };
    }
};

fn onlyDotsAndSpaces(name: []const u8) bool {
    for (name) |c| if (c != '.' and c != ' ') return false;
    return true;
}

/// Why an executable path is suspicious, if it is. Hidden directories count inside temp dirs,
/// in system locations, or when named only with dots and spaces ("...", ". "); dot directories
/// in home directories (~/.local, ~/.cargo, ~/.bun) are where developer tools live.
pub fn exeRisk(path: []const u8) ?PathRisk {
    if (tokens.isTempPath(path)) return .temp;
    if (std.mem.startsWith(u8, path, "/dev/")) return .dev;
    const system = [_][]const u8{ "/usr/", "/bin/", "/sbin/", "/lib", "/etc/", "/var/lib/", "/boot/", "/opt/", "/root/." };
    var in_system = false;
    for (system) |p| if (std.mem.startsWith(u8, path, p)) {
        in_system = true;
    };
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or part[0] != '.') continue;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) continue;
        if (onlyDotsAndSpaces(part) or in_system) return .hidden;
        if (part.len > 0 and part[part.len - 1] == ' ') return .hidden;
    }
    return null;
}

fn checkTempExec(s: *scan.Scan) !void {
    const procs = try s.processes();
    for (procs) |p| {
        const exe = p.exe orelse continue;
        if (std.mem.startsWith(u8, exe, "/memfd:")) continue; // process.memfd
        const risk = exeRisk(exe) orelse continue;
        if (s.owned(exe)) continue;
        const orphan = p.ppid == 1;
        try s.add(.{
            .severity = if (orphan) .critical else .high,
            .category = .process,
            .title = if (orphan) "Daemon running from a suspicious directory" else "Process running from a suspicious directory",
            .description = try s.print("Process {d} ({s}) runs {s}{s} from {s}.{s} Legitimate software is installed under package-managed paths; droppers stage payloads in temp and hidden directories.", .{ p.pid, p.comm, exe, if (p.exe_deleted) " (since deleted)" else "", risk.describe(), if (orphan) " It has been reparented to init, the shape of a detached backdoor or miner." else "" }),
            .remediation = try s.print("Inspect it (ls -la /proc/{d}/exe; cat /proc/{d}/cmdline), copy the binary for analysis, then kill {d} and remove the file. Look for the persistence that started it.", .{ p.pid, p.pid, p.pid }),
            .subject = exe,
            .pid = p.pid,
            .details = try processDetails(s, p, &.{.{ .key = "path_risk", .value = @tagName(risk) }}),
        });
    }
    try noteDenied(s, procs);
}

fn checkDeletedExe(s: *scan.Scan) !void {
    const procs = try s.processes();
    for (procs) |p| {
        if (!p.exe_deleted) continue;
        const exe = p.exe orelse continue;
        if (std.mem.startsWith(u8, exe, "/memfd:")) continue;
        if (exeRisk(exe) != null) continue; // reported by process.temp_exec
        // A package upgrade replaces binaries under running services; that path is still owned.
        if (s.owned(exe)) continue;
        try s.add(.{
            .severity = .high,
            .category = .process,
            .title = "Process running a deleted executable",
            .description = try s.print("Process {d} ({s}) runs {s}, which has been deleted and is not owned by any package. Deleting the binary after start is a common way to hide a miner or implant from file scans.", .{ p.pid, p.comm, exe }),
            .remediation = try s.print("Recover the binary with cp /proc/{d}/exe /root/evidence.bin and analyse it, then stop the process.", .{p.pid}),
            .subject = exe,
            .pid = p.pid,
            .details = try processDetails(s, p, &.{}),
        });
    }
    try noteDenied(s, procs);
}

fn checkMemfd(s: *scan.Scan) !void {
    const procs = try s.processes();
    for (procs) |p| {
        const exe = p.exe orelse continue;
        if (!std.mem.startsWith(u8, exe, "/memfd:")) continue;
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "Fileless executable running from memfd",
            .description = try s.print("Process {d} ({s}) executes {s}: code loaded from an anonymous memory file that never touched disk. This is how fileless malware avoids file scanners.", .{ p.pid, p.comm, exe }),
            .remediation = try s.print("Dump the code with cp /proc/{d}/exe /root/memfd-{d}.bin, record the parent process ({d}), then kill the process and investigate how it was launched.", .{ p.pid, p.pid, p.ppid }),
            .subject = exe,
            .pid = p.pid,
            .details = try processDetails(s, p, &.{}),
        });
    }
    try noteDenied(s, procs);
}

/// Kernel thread name prefixes. A process with user memory under one of these names, or an
/// argv[0] in `[brackets]`, is disguising itself.
const kthread_prefixes = [_][]const u8{ "kworker", "ksoftirqd", "kthreadd", "kswapd", "migration/", "watchdog/", "rcu_", "khugepaged", "kdevtmpfs", "kblockd", "kcompactd", "jbd2/", "irq/", "cpuhp/", "kauditd", "oom_reaper" };

pub fn looksLikeKernelThread(name: []const u8) bool {
    if (name.len >= 2 and name[0] == '[' and name[name.len - 1] == ']') return true;
    for (kthread_prefixes) |k| if (std.mem.startsWith(u8, name, k)) return true;
    return false;
}

fn checkMasquerade(s: *scan.Scan) !void {
    for (try s.processes()) |p| {
        if (!p.status.has_vm) continue; // real kernel threads have no user memory
        var args = p.args();
        const arg0 = args.next() orelse "";
        const disguised = looksLikeKernelThread(p.comm) or looksLikeKernelThread(arg0);
        if (!disguised) continue;
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "User process disguised as a kernel thread",
            .description = try s.print("Process {d} calls itself '{s}' (argv[0] '{s}') but has user memory{s}{s}. Kernel threads have no executable; miners such as kdevtmpfsi and kinsing hide this way.", .{ p.pid, p.comm, arg0, if (p.exe != null) " and runs " else "", p.exe orelse "" }),
            .remediation = try s.print("Inspect /proc/{d}/exe and /proc/{d}/cmdline, preserve the binary, then kill {d} and look for its persistence.", .{ p.pid, p.pid, p.pid }),
            .subject = subject(p),
            .pid = p.pid,
            .details = try processDetails(s, p, &.{}),
        });
    }
}

fn checkMalwareExe(s: *scan.Scan) !void {
    const scanner = s.options.scanner orelse {
        try s.reduced("no signature database loaded; executables were not scanned", .{});
        return;
    };
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(s.gpa);
    var path_buf: [64]u8 = undefined;
    for (try s.processes()) |p| {
        const exe = p.exe orelse continue;
        if (!p.exe_deleted and !std.mem.startsWith(u8, exe, "/memfd:") and s.owned(exe)) continue;
        if ((try seen.getOrPut(s.gpa, exe)).found_existing) continue;
        // /proc/<pid>/exe opens the running image, even when the file was deleted.
        const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{p.pid}) catch continue;
        const name = scanner.scan(s.host, path) orelse continue;
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "Known malware running",
            .description = try s.print("Process {d} ({s}) runs {s}, detected as {s}.", .{ p.pid, p.comm, exe, name }),
            .remediation = try s.print("Preserve /proc/{d}/exe, kill the process, remove the file and investigate the intrusion.", .{p.pid}),
            .subject = exe,
            .pid = p.pid,
            .details = try processDetails(s, p, &.{.{ .key = "signature", .value = try s.dupe(name) }}),
        });
    }
}

// Memory ---------------------------------------------------------------------------------------

/// Runtimes that legitimately map anonymous executable memory, by executable name.
const jit_names = [_][]const u8{ "node", "nodejs", "bun", "deno", "java", "chrome", "chromium", "electron", "code", "firefox", "dotnet", "mono", "luajit", "julia", "beam.smp", "php", "php-fpm", "ruby", "pypy", "pypy3", "qemu-system-x86_64", "qemu-system-aarch64", "wine", "wine64", "Xorg", "gnome-shell" };
/// Libraries whose presence in the map means a JIT is expected.
const jit_libraries = [_][]const u8{ "libcoreclr.so", "libjvm.so", "libmonosgen", "libv8", "libnode.so", "libluajit", "libjulia", "libclrjit.so", "libmozjs", "libjavascriptcoregtk", "libwebkit2gtk", "libQt5Qml", "libQt6Qml", "libpcre2-8.so", "libLLVM" };

pub const AnonExec = struct { anon: usize = 0, memfd: usize = 0, jit_hint: bool = false };

pub fn classifyMaps(maps: []const u8) AnonExec {
    var r: AnonExec = .{};
    var lines = std.mem.splitScalar(u8, maps, '\n');
    while (lines.next()) |line| {
        const m = procfs.parseMapsLine(line) orelse continue;
        for (jit_libraries) |lib| if (std.mem.indexOf(u8, m.path, lib) != null) {
            r.jit_hint = true;
        };
        if (!m.exec) continue;
        if (std.mem.startsWith(u8, m.path, "/memfd:")) {
            r.memfd += 1;
        } else if (m.path.len == 0 or std.mem.startsWith(u8, m.path, "[anon")) {
            r.anon += 1;
        }
    }
    return r;
}

fn checkAnonExec(s: *scan.Scan) !void {
    var path_buf: [64]u8 = undefined;
    var unreadable: usize = 0;
    for (try s.processes()) |p| {
        if (p.isKernelThread()) continue;
        const exe = p.exe orelse continue;
        if (std.mem.startsWith(u8, exe, "/memfd:")) continue; // process.memfd
        const name = p.exeName();
        var jit = false;
        for (jit_names) |j| if (std.mem.eql(u8, name, j) or (std.mem.startsWith(u8, name, j) and name.len > j.len and (std.ascii.isDigit(name[j.len]) or name[j.len] == '.'))) {
            jit = true;
        };
        if (jit or s.owned(exe)) continue;
        const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/maps", .{p.pid}) catch continue;
        const maps = s.host.readAlloc(s.gpa, path, 16 * 1024 * 1024) catch |e| {
            if (e == error.AccessDenied) unreadable += 1;
            continue;
        };
        defer s.gpa.free(maps);
        const c = classifyMaps(maps);
        if (c.jit_hint or (c.anon == 0 and c.memfd == 0)) continue;
        try s.add(.{
            .severity = if (c.memfd > 0) .high else .medium,
            .category = .process,
            .title = if (c.memfd > 0) "Executable memfd mapping in an unowned process" else "Anonymous executable memory in an unowned process",
            .description = try s.print("Process {d} ({s}, {s}) has {d} anonymous and {d} memfd executable mappings and no known JIT runtime. Injected shellcode and reflectively loaded libraries look like this.", .{ p.pid, p.comm, exe, c.anon, c.memfd }),
            .remediation = try s.print("Review /proc/{d}/maps; if the program is not a JIT runtime you know, dump the regions (gcore {d}) for analysis and stop it.", .{ p.pid, p.pid }),
            .subject = exe,
            .pid = p.pid,
            .details = try processDetails(s, p, &.{
                .{ .key = "anon_exec_mappings", .value = try s.print("{d}", .{c.anon}) },
                .{ .key = "memfd_exec_mappings", .value = try s.print("{d}", .{c.memfd}) },
            }),
        });
    }
    if (unreadable > 0) try s.reduced("{d} processes' memory maps were unreadable without root", .{unreadable});
}

// Hidden processes ---------------------------------------------------------------------------

/// Pids `probe` reports alive that `listed` (sorted) lacks.
pub fn unlistedAlive(gpa: std.mem.Allocator, listed: []const u32, pid_max: u32, probe: *const fn (u32) sys.Liveness, out: *std.ArrayList(u32)) !void {
    var i: usize = 0;
    var pid: u32 = 1;
    while (pid < pid_max) : (pid += 1) {
        while (i < listed.len and listed[i] < pid) i += 1;
        if (i < listed.len and listed[i] == pid) continue;
        if (probe(pid) == .alive) try out.append(gpa, pid);
    }
}

fn checkHidden(s: *scan.Scan) !void {
    if (!s.host.live) {
        try s.reduced("pid probing needs the live host", .{});
        return;
    }
    var buf: [32]u8 = undefined;
    const pid_max_text = s.host.readOpt("/proc/sys/kernel/pid_max", &buf) orelse "32768";
    const pid_max = @min(std.fmt.parseInt(u32, std.mem.trim(u8, pid_max_text, " \n"), 10) catch 32768, 4 * 1024 * 1024);

    var listed: std.ArrayList(u32) = .empty;
    defer listed.deinit(s.gpa);
    try procfs.listPids(s.gpa, s.host, &listed);
    std.mem.sort(u32, listed.items, {}, std.sort.asc(u32));
    var candidates: std.ArrayList(u32) = .empty;
    defer candidates.deinit(s.gpa);
    try unlistedAlive(s.gpa, listed.items, pid_max, sys.probePid, &candidates);
    if (candidates.items.len == 0) return;

    // Threads are not listed in /proc but answer kill(tid, 0); a pid whose Tgid differs is a
    // thread. Re-list and re-probe before reporting, since processes start and exit meanwhile.
    listed.clearRetainingCapacity();
    try procfs.listPids(s.gpa, s.host, &listed);
    std.mem.sort(u32, listed.items, {}, std.sort.asc(u32));
    var path_buf: [64]u8 = undefined;
    var status_buf: [2048]u8 = undefined;
    for (candidates.items) |pid| {
        if (std.sort.binarySearch(u32, listed.items, pid, struct {
            fn order(a: u32, b: u32) std.math.Order {
                return std.math.order(a, b);
            }
        }.order) != null) continue;
        if (sys.probePid(pid) != .alive) continue;
        const status_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{pid}) catch continue;
        const text = s.host.readOpt(status_path, &status_buf) orelse continue;
        const st = procfs.parseStatus(text);
        if (st.tgid != 0 and st.tgid != pid) continue;
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "Process hidden from the /proc listing",
            .description = try s.print("Pid {d} ({s}) is alive and readable at /proc/{d} but missing from the /proc directory listing. Rootkits hide processes by filtering getdents on /proc.", .{ pid, st.name, pid }),
            .remediation = "Treat the host as compromised: a kernel or LD_PRELOAD rootkit is filtering directory listings. Image memory and disk from a trusted boot medium before cleaning.",
            .subject = try s.dupe(st.name),
            .pid = pid,
        });
    }
}

// CPU ------------------------------------------------------------------------------------------

/// Share of one core used between two cumulative tick readings over `elapsed_ms`.
pub fn cpuShare(before_ticks: u64, after_ticks: u64, elapsed_ms: u64, hz: u64) f64 {
    if (elapsed_ms == 0 or after_ticks < before_ticks) return 0;
    const used_ms = @as(f64, @floatFromInt(after_ticks - before_ticks)) * 1000.0 / @as(f64, @floatFromInt(hz));
    return used_ms / @as(f64, @floatFromInt(elapsed_ms));
}

fn checkCpu(s: *scan.Scan) !void {
    const procs = try s.processes();
    const start = std.Io.Clock.awake.now(s.host.io);
    // A fresh first reading: the snapshot may be seconds old by now.
    var before = try s.gpa.alloc(u64, procs.len);
    defer s.gpa.free(before);
    var path_buf: [64]u8 = undefined;
    var stat_buf: [1024]u8 = undefined;
    for (procs, 0..) |p, i| before[i] = readTicks(s.host, p.pid, &path_buf, &stat_buf) orelse std.math.maxInt(u64);
    if (s.host.live) try s.host.io.sleep(.fromMilliseconds(s.options.cpu_sample_ms), .awake);
    const elapsed: u64 = @intCast(@max(1, start.durationTo(std.Io.Clock.awake.now(s.host.io)).toMilliseconds()));
    for (procs, 0..) |p, i| {
        if (before[i] == std.math.maxInt(u64)) continue;
        const after = readTicks(s.host, p.pid, &path_buf, &stat_buf) orelse continue;
        const share = cpuShare(before[i], after, if (s.host.live) elapsed else s.options.cpu_sample_ms, 100);
        if (share < 0.9) continue;
        const exe = p.exe orelse continue;
        if (s.owned(exe)) continue;
        try s.add(.{
            .severity = .low,
            .category = .process,
            .title = "Sustained CPU from an unowned executable",
            .description = try s.print("Process {d} ({s}, {s}) used {d:.0}% of a core over a {d} ms window and its executable belongs to no package. Unknown programs pinning a core are worth a look for mining.", .{ p.pid, p.comm, exe, share * 100, s.options.cpu_sample_ms }),
            .remediation = try s.print("Identify the program behind /proc/{d}/exe; if you do not recognise it, inspect its parent and network connections before killing it.", .{p.pid}),
            .subject = exe,
            .pid = p.pid,
            .details = try processDetails(s, p, &.{.{ .key = "cpu_share", .value = try s.print("{d:.2}", .{share}) }}),
        });
    }
}

fn readTicks(h: Host, pid: u32, path_buf: []u8, stat_buf: []u8) ?u64 {
    const path = std.fmt.bufPrint(path_buf, "/proc/{d}/stat", .{pid}) catch return null;
    const st = procfs.parseStat(h.readOpt(path, stat_buf) orelse return null) catch return null;
    return st.utime + st.stime;
}

// Tests ----------------------------------------------------------------------------------------

const Fixture = @import("../host.zig").Fixture;

/// Write a fake /proc/<pid> with status, stat, cmdline and an exe link.
pub fn fakeProcess(fx: *Fixture, pid: u32, comm: []const u8, ppid: u32, exe: ?[]const u8, cmdline: []const u8) !void {
    var path: [64]u8 = undefined;
    var body: [512]u8 = undefined;
    try fx.file(try std.fmt.bufPrint(&path, "/proc/{d}/status", .{pid}), try std.fmt.bufPrint(&body, "Name:\t{s}\nState:\tS (sleeping)\nTgid:\t{d}\nPid:\t{d}\nPPid:\t{d}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nVmSize:\t 1000 kB\nCapEff:\t0000000000000000\n", .{ comm, pid, pid, ppid }));
    try fx.file(try std.fmt.bufPrint(&path, "/proc/{d}/stat", .{pid}), try std.fmt.bufPrint(&body, "{d} ({s}) S {d} 1 1 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 100 0 0", .{ pid, comm, ppid }));
    try fx.file(try std.fmt.bufPrint(&path, "/proc/{d}/comm", .{pid}), comm);
    try fx.file(try std.fmt.bufPrint(&path, "/proc/{d}/cmdline", .{pid}), cmdline);
    if (exe) |e| try fx.link(try std.fmt.bufPrint(&path, "/proc/{d}/exe", .{pid}), e);
}

fn runFixture(fx: *Fixture, only: []const []const u8, tier: finding.Tier) !scan.Scan {
    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = only, .tier = tier, .context = .{ .role = .server } });
    try s.runChecks(&checks);
    return s;
}

fn hasFinding(s: *const scan.Scan, check: []const u8, pid: u32) bool {
    for (s.findings.items) |f| if (std.mem.eql(u8, f.check, check) and f.pid == pid) return true;
    return false;
}

test "miner evidence is token based" {
    const mk = struct {
        fn p(comm: []const u8, exe: ?[]const u8, cmdline: []const u8) procfs.Process {
            return .{ .pid = 1, .ppid = 1, .uid = 0, .euid = 0, .comm = comm, .cmdline = cmdline, .exe = exe, .exe_deleted = false, .exe_denied = false, .status = .{ .has_vm = true }, .utime = 0, .stime = 0 };
        }
    }.p;
    try std.testing.expect(minerEvidence(mk("xmrig", "/opt/xmrig-6.21/xmrig", "xmrig\x00")).isMiner());
    try std.testing.expect(minerEvidence(mk("sysupdate", "/var/tmp/sysupdate", "sysupdate\x00-o\x00stratum+tcp://45.9.148.21:3333\x00")).stratum != null);
    try std.testing.expect(minerEvidence(mk("x", null, "x\x00--url=pool.supportxmr.com:443\x00")).pool != null);
    try std.testing.expect(minerEvidence(mk("x", null, "x\x00--donate-level\x001\x00-a\x00rx/0\x00")).isMiner());
    // Not miners: substrings, wallets, a single generic flag.
    try std.testing.expect(!minerEvidence(mk("minerva", "/usr/bin/minerva", "minerva\x00")).isMiner());
    try std.testing.expect(!minerEvidence(mk("monero-wallet-gui", "/opt/monero/monero-wallet-gui", "monero-wallet-gui\x00")).isMiner());
    try std.testing.expect(!minerEvidence(mk("curl", "/usr/bin/curl", "curl\x00https://notsupportxmr.com/\x00")).isMiner());
    try std.testing.expect(!minerEvidence(mk("x", null, "x\x00--rig-id\x00a\x00")).isMiner());
}

test "exe path risk" {
    try std.testing.expectEqual(PathRisk.temp, exeRisk("/dev/shm/.x/kworker").?);
    try std.testing.expectEqual(PathRisk.dev, exeRisk("/dev/.udev/x").?);
    try std.testing.expectEqual(PathRisk.hidden, exeRisk("/usr/lib/.cache/sshd").?);
    try std.testing.expectEqual(PathRisk.hidden, exeRisk("/home/u/.../x").?);
    try std.testing.expectEqual(PathRisk.hidden, exeRisk("/home/u/. /x").?);
    try std.testing.expect(exeRisk("/home/u/.cargo/bin/rg") == null);
    try std.testing.expect(exeRisk("/home/u/.bun/bin/bun") == null);
    try std.testing.expect(exeRisk("/usr/bin/bash") == null);
    try std.testing.expect(looksLikeKernelThread("[kworker/0:1]"));
    try std.testing.expect(looksLikeKernelThread("kswapd0"));
    try std.testing.expect(!looksLikeKernelThread("kubelet"));
}

test "fixture /proc: miner, temp exec, deleted, memfd, masquerade and clean processes" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try packages_fixture(&fx);
    try fakeProcess(&fx, 1, "systemd", 0, "/usr/lib/systemd/systemd", "/sbin/init\x00");
    try fakeProcess(&fx, 700, "sshd", 1, "/usr/sbin/sshd", "sshd: /usr/sbin/sshd -D\x00");
    // A renamed miner in /dev/shm, detached to init.
    try fakeProcess(&fx, 4242, "dbus-helper", 1, "/dev/shm/.x/dbus-helper", "dbus-helper\x00-o\x00stratum+tcp://pool.example:3333\x00");
    // Upgraded sshd still running (owned, deleted): no finding.
    try fakeProcess(&fx, 701, "sshd", 700, "/usr/sbin/sshd (deleted)", "sshd: session\x00");
    // Unowned deleted binary outside temp.
    try fakeProcess(&fx, 800, "agent", 1, "/opt/agent/agent (deleted)", "/opt/agent/agent\x00");
    try fakeProcess(&fx, 900, "x", 1, "/memfd:payload (deleted)", "x\x00");
    try fakeProcess(&fx, 950, "kworker/0:2", 1, "/usr/local/bin/kw", "[kworker/0:2]\x00");
    // Kernel thread: no exe, no VM.
    try fx.file("/proc/2/status", "Name:\tkthreadd\nPid:\t2\nPPid:\t0\n");
    try fx.file("/proc/2/cmdline", "");

    var s = try runFixture(&fx, &.{"process"}, .fast);
    defer s.deinit();
    try std.testing.expect(hasFinding(&s, "process.miner", 4242));
    try std.testing.expect(hasFinding(&s, "process.temp_exec", 4242));
    try std.testing.expect(hasFinding(&s, "process.deleted_exe", 800));
    try std.testing.expect(hasFinding(&s, "process.memfd", 900));
    try std.testing.expect(hasFinding(&s, "process.masquerade", 950));
    for (s.findings.items) |f| {
        try std.testing.expect(f.pid != 1 and f.pid != 700 and f.pid != 701 and f.pid != 2);
    }
    for (s.findings.items) |f| if (f.pid == 4242 and std.mem.eql(u8, f.check, "process.temp_exec")) {
        try std.testing.expectEqual(finding.Severity.critical, f.severity); // orphaned
    };
}

fn packages_fixture(fx: *Fixture) !void {
    try fx.file("/var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.6p1\n\nPackage: systemd\nStatus: install ok installed\nVersion: 255\n");
    try fx.file("/var/lib/dpkg/info/openssh-server.list", "/usr/sbin/sshd\n");
    try fx.file("/var/lib/dpkg/info/systemd.list", "/usr/lib/systemd/systemd\n");
}

test "maps classification and hidden-pid comparison" {
    const c = classifyMaps("400000-401000 r-xp 0 08:01 12 /opt/x/x\n7f00-7f10 rwxp 0 00:00 0 \n7f20-7f30 r-xp 0 00:01 9 /memfd:jit (deleted)\n");
    try std.testing.expectEqual(@as(usize, 1), c.anon);
    try std.testing.expectEqual(@as(usize, 1), c.memfd);
    try std.testing.expect(!c.jit_hint);
    try std.testing.expect(classifyMaps("7f-8f r-xp 0 08:01 3 /usr/lib/jvm/lib/server/libjvm.so\n").jit_hint);

    const probe = struct {
        fn alive(pid: u32) sys.Liveness {
            return if (pid == 3 or pid == 7 or pid == 9) .alive else .gone;
        }
    }.alive;
    var out: std.ArrayList(u32) = .empty;
    defer out.deinit(std.testing.allocator);
    try unlistedAlive(std.testing.allocator, &.{ 3, 9 }, 20, probe, &out);
    try std.testing.expectEqualSlices(u32, &.{7}, out.items);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), cpuShare(100, 125, 500, 100), 1e-9);
}

test "live: no subprocesses, and a renamed miner in /dev/shm is reported" {
    const builtin = @import("builtin");
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    // Stage a shell copy named like a miner in /dev/shm and keep it alive with a stratum URL in
    // its arguments.
    var dir_buf: [64]u8 = undefined;
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    const dir = try std.fmt.bufPrint(&dir_buf, "/dev/shm/zav-test-{x}", .{rnd});
    std.Io.Dir.createDirAbsolute(io, dir, .default_dir) catch return error.SkipZigTest;
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var exe_buf: [96]u8 = undefined;
    const exe = try std.fmt.bufPrint(&exe_buf, "{s}/xmrig", .{dir});
    std.Io.Dir.copyFileAbsolute("/bin/sh", exe, io, .{}) catch return error.SkipZigTest;
    // A command list, so the shell cannot exec sleep in its own place. /dev/shm is noexec in
    // containers; skip there.
    var child = std.process.spawn(io, .{ .argv = &.{ exe, "-c", "sleep 30; exit 0", "stratum+tcp://pool.supportxmr.com:3333" } }) catch return error.SkipZigTest;
    defer {
        child.kill(io);
    }
    const pid: u32 = @intCast(child.id.?);
    // Wait until the child has exec'd into the copy.
    var tries: usize = 0;
    var link_buf: [256]u8 = undefined;
    var path_buf: [64]u8 = undefined;
    while (tries < 200) : (tries += 1) {
        const n = std.Io.Dir.cwd().readLink(io, try std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid}), &link_buf) catch 0;
        if (n > 0 and std.mem.startsWith(u8, link_buf[0..n], dir)) break;
        try io.sleep(.fromMilliseconds(10), .awake);
    }

    var before: linux.rusage = undefined;
    _ = linux.getrusage(linux.rusage.CHILDREN, &before);
    const h = try Host.openLive(io);
    defer h.close();
    var s = scan.Scan.init(gpa, h, .{ .only = &.{"process"} });
    defer s.deinit();
    try s.runChecks(&checks);
    var after: linux.rusage = undefined;
    _ = linux.getrusage(linux.rusage.CHILDREN, &after);
    // Any reaped child adds its page faults; a zombie would show in the children list.
    try std.testing.expectEqual(before.minflt, after.minflt);
    var children_buf: [4096]u8 = undefined;
    var tid_path: [64]u8 = undefined;
    const children = std.Io.Dir.cwd().readFile(io, try std.fmt.bufPrint(&tid_path, "/proc/self/task/{d}/children", .{linux.gettid()}), &children_buf) catch children_buf[0..0];
    var child_pids = std.mem.tokenizeScalar(u8, children, ' ');
    while (child_pids.next()) |c| try std.testing.expectEqual(pid, try std.fmt.parseInt(u32, std.mem.trim(u8, c, "\n"), 10));

    try std.testing.expect(hasFinding(&s, "process.miner", pid));
    try std.testing.expect(hasFinding(&s, "process.temp_exec", pid));
    // Everything else on a clean CI image is quiet in the fast tier (developer machines are not
    // clean images, so only CI asserts it).
    for (s.findings.items) |f| if (f.pid != pid and @import("../host.zig").onCi()) {
        std.debug.print("unexpected finding on a clean host: {s} {s} {?s}\n", .{ f.check, f.title, f.subject });
        return error.TestUnexpectedResult;
    };
}

test "no check spawns a process: host and CVE sources never name a process-spawning API" {
    const sources = [_][]const u8{
        @embedFile("process.zig"), @embedFile("procfs.zig"),     @embedFile("packages.zig"), @embedFile("integrity.zig"),
        @embedFile("../scan.zig"), @embedFile("../context.zig"), @embedFile("../host.zig"),  @embedFile("../sys.zig"),
    };
    const forbidden = [_][]const u8{ "process.spawn", "process.run(", "Child.init", "execve", "posix_spawn", "fork(", "system(" };
    for (sources) |src| {
        // Tests may spawn harness processes; only code before the test section counts.
        const code = if (std.mem.indexOf(u8, src, "\ntest \"")) |i| src[0..i] else src;
        for (forbidden) |f| if (std.mem.indexOf(u8, code, f) != null) {
            std.debug.print("forbidden call {s} in host check code\n", .{f});
            return error.TestUnexpectedResult;
        };
    }
}
