//! Kernel and boot integrity: loaded modules compared across two independent views
//! (/proc/modules, the module list, against /sys/module, the kobject tree; linux-guardian
//! compared lsmod with /proc/modules, which reads the same list twice), taint flags, module
//! origin and appended signatures read from the module files (not modinfo), suspicious module
//! names and parameters as tokens, eBPF tracing programs and who holds them, and changes to the
//! kernel command line and bootloader configuration since the last baseline.
const std = @import("std");
const builtin = @import("builtin");
const scan = @import("../scan.zig");
const tokens = @import("../tokens.zig");
const procfs = @import("procfs.zig");
const finding = @import("../finding.zig");
const Host = @import("../host.zig").Host;

pub const checks = [_]scan.Check{
    .{ .id = "kernel.modules_hidden", .category = .kernel, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Modules in /sys/module but not /proc/modules, and the reverse", .run = checkHiddenModules },
    .{ .id = "kernel.taint", .category = .kernel, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Kernel taint flags: forced loads, unsigned and out-of-tree modules", .run = checkTaint },
    .{ .id = "kernel.module_origin", .category = .kernel, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Loaded modules missing from /lib/modules or unsigned", .run = checkModuleOrigin },
    .{ .id = "kernel.module_names", .category = .kernel, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Rootkit module names and hiding parameters, as tokens", .run = checkModuleNames },
    .{ .id = "kernel.module_signature", .category = .kernel, .tier = .deep, .privilege = .none, .os = .linux, .summary = "Appended signatures on the module files of loaded modules", .run = checkModuleSignatures },
    .{ .id = "kernel.ebpf", .category = .kernel, .tier = .fast, .privilege = .root, .os = .linux, .summary = "eBPF tracing programs not held by package-owned or known tooling", .run = checkEbpf },
    .{ .id = "kernel.cmdline", .category = .boot, .tier = .fast, .privilege = .none, .os = .linux, .summary = "Kernel command line options that weaken security, and changes since baseline", .run = checkCmdline },
    .{ .id = "boot.bootloader", .category = .boot, .tier = .fast, .privilege = .partial, .os = .linux, .summary = "Bootloader configuration changed since baseline", .run = checkBootloader },
};

// Modules ---------------------------------------------------------------------------------------

pub const Module = struct {
    name: []const u8,
    state: []const u8,
    /// Per-module taint letters from the trailing "(POE)", empty when none.
    taint: []const u8,
};

/// `name size refcount deps state address [(taint)]`
pub fn parseModulesLine(line: []const u8) ?Module {
    var f = std.mem.tokenizeScalar(u8, line, ' ');
    const name = f.next() orelse return null;
    _ = f.next() orelse return null; // size
    _ = f.next() orelse return null; // refcount
    _ = f.next() orelse return null; // deps
    const state = f.next() orelse return null;
    _ = f.next(); // address
    var taint: []const u8 = "";
    if (f.next()) |t| if (t.len >= 2 and t[0] == '(' and t[t.len - 1] == ')') {
        taint = t[1 .. t.len - 1];
    };
    if (name.len == 0 or name.len > 64) return null;
    return .{ .name = name, .state = state, .taint = taint };
}

fn readModules(s: *scan.Scan, out: *std.ArrayList(Module)) !bool {
    const text = s.host.readAlloc(s.arena(), "/proc/modules", 4 * 1024 * 1024) catch return false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| if (parseModulesLine(line)) |m| try out.append(s.gpa, m);
    return true;
}

/// Module names compare with '-' and '_' as the same character, as the kernel does.
pub fn normalize(buf: []u8, name: []const u8) []const u8 {
    const n = @min(buf.len, name.len);
    for (name[0..n], 0..) |c, i| buf[i] = if (c == '-') '_' else c;
    return buf[0..n];
}

fn checkHiddenModules(s: *scan.Scan) !void {
    var mods: std.ArrayList(Module) = .empty;
    defer mods.deinit(s.gpa);
    if (!try readModules(s, &mods)) {
        try s.reduced("/proc/modules unreadable", .{});
        return;
    }
    var listed: std.StringHashMapUnmanaged(void) = .empty;
    defer listed.deinit(s.gpa);
    for (mods.items) |m| try listed.put(s.gpa, m.name, {});

    var path_buf: [128]u8 = undefined;
    // Listed but no kobject.
    for (mods.items) |m| {
        const p = std.fmt.bufPrint(&path_buf, "/sys/module/{s}", .{m.name}) catch continue;
        if (s.host.exists(p)) continue;
        try s.add(.{
            .severity = .high,
            .category = .kernel,
            .title = "Module listed in /proc/modules has no /sys/module entry",
            .description = try s.print("Module {s} appears in /proc/modules but /sys/module/{s} does not exist. The two views should always agree; a module that removed its kobject is hiding.", .{ m.name, m.name }),
            .remediation = "Investigate from a trusted kernel: reboot from known-good media and compare the module list.",
            .subject = m.name,
        });
    }
    // A loadable module's kobject has `initstate`; built-in ones do not. A live loadable module
    // missing from /proc/modules unlinked itself from the module list: the classic LKM rootkit.
    var dir = (s.host.openDir("/sys/module") catch {
        try s.reduced("/sys/module unreadable", .{});
        return;
    }) orelse return;
    defer dir.close(s.host.io);
    var it = dir.iterate();
    var buf: [32]u8 = undefined;
    while (it.next(s.host.io) catch null) |entry| {
        const p = std.fmt.bufPrint(&path_buf, "/sys/module/{s}/initstate", .{entry.name}) catch continue;
        const state = std.mem.trim(u8, s.host.readOpt(p, &buf) orelse continue, " \n");
        if (!std.mem.eql(u8, state, "live")) continue;
        if (listed.contains(entry.name)) continue;
        try s.add(.{
            .severity = .critical,
            .category = .malware,
            .title = "Kernel module hidden from /proc/modules",
            .description = try s.print("Module {s} is live in /sys/module but missing from /proc/modules. Loadable kernel module rootkits (Diamorphine, Reptile) unlink themselves from the module list this way.", .{entry.name}),
            .remediation = "Treat the host as compromised at kernel level. Capture memory, then rebuild from trusted media; a hidden module cannot be trusted to unload.",
            .subject = try s.dupe(entry.name),
        });
    }
}

pub const Taint = struct {
    bit: u5,
    letter: u8,
    meaning: []const u8,
    severity: ?finding.Severity,
};

/// The bits of /proc/sys/kernel/tainted that say something about integrity. Reliability bits
/// (machine checks, warnings, soft lockups) are left to monitoring.
pub const taints = [_]Taint{
    .{ .bit = 0, .letter = 'P', .meaning = "a proprietary module was loaded", .severity = null },
    .{ .bit = 1, .letter = 'F', .meaning = "a module was force-loaded, bypassing version checks", .severity = .high },
    .{ .bit = 3, .letter = 'R', .meaning = "a module was force-unloaded", .severity = .high },
    .{ .bit = 10, .letter = 'C', .meaning = "a staging driver was loaded", .severity = .low },
    .{ .bit = 12, .letter = 'O', .meaning = "an out-of-tree module was loaded", .severity = .low },
    .{ .bit = 13, .letter = 'E', .meaning = "an unsigned module was loaded", .severity = .medium },
    .{ .bit = 15, .letter = 'K', .meaning = "the kernel was live-patched", .severity = null },
};

pub fn secureBoot(h: Host) bool {
    var buf: [16]u8 = undefined;
    const v = h.readOpt("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-e098032b8c4b", &buf) orelse return false;
    return v.len >= 5 and v[4] == 1;
}

fn checkTaint(s: *scan.Scan) !void {
    var buf: [32]u8 = undefined;
    const text = s.host.readOpt("/proc/sys/kernel/tainted", &buf) orelse {
        try s.reduced("/proc/sys/kernel/tainted unreadable", .{});
        return;
    };
    const value = std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10) catch return;
    if (value == 0) return;
    const sb = secureBoot(s.host);
    var top: ?finding.Severity = null;
    var letters: std.ArrayList(u8) = .empty;
    var why: std.ArrayList(u8) = .empty;
    const a = s.arena();
    for (taints) |t| {
        if (value & (@as(u64, 1) << t.bit) == 0) continue;
        var sev = t.severity orelse continue;
        if (t.letter == 'E' and sb) sev = .high;
        top = if (top) |x| x.max(sev) else sev;
        try letters.append(a, t.letter);
        try why.print(a, "{c}: {s}; ", .{ t.letter, t.meaning });
    }
    const severity = top orelse return;
    // Which modules carry the flags.
    var mods: std.ArrayList(Module) = .empty;
    defer mods.deinit(s.gpa);
    _ = try readModules(s, &mods);
    var carriers: std.ArrayList(u8) = .empty;
    for (mods.items) |m| if (m.taint.len > 0) try carriers.print(a, "{s}({s}) ", .{ m.name, m.taint });
    try s.add(.{
        .severity = severity,
        .category = .kernel,
        .title = "Kernel is tainted",
        .description = try s.print("The kernel taint value {d} says {s}{s}", .{ value, why.items, if (sb) "Secure Boot is on, so unsigned code in the kernel is especially unexpected." else "" }),
        .remediation = "Identify the modules responsible (listed in details), confirm each is expected (DKMS drivers such as nvidia or zfs are common), and remove any you cannot account for.",
        .subject = "/proc/sys/kernel/tainted",
        .details = try s.details(&.{
            .{ .key = "tainted", .value = try s.print("{d}", .{value}) },
            .{ .key = "flags", .value = letters.items },
            .{ .key = "modules", .value = std.mem.trimEnd(u8, carriers.items, " ") },
            .{ .key = "secure_boot", .value = if (sb) "on" else "off" },
        }),
    });
}

/// Module name -> path relative to /lib/modules/<release>, from modules.dep.
pub const DepIndex = struct {
    map: std.StringHashMapUnmanaged([]const u8) = .empty,
    release: []const u8 = "",

    pub fn deinit(d: *DepIndex, gpa: std.mem.Allocator) void {
        d.map.deinit(gpa);
    }

    pub fn load(gpa: std.mem.Allocator, arena: std.mem.Allocator, h: Host) !?DepIndex {
        var rel_buf: [128]u8 = undefined;
        const release = std.mem.trim(u8, h.readOpt("/proc/sys/kernel/osrelease", &rel_buf) orelse return null, " \n");
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/lib/modules/{s}/modules.dep", .{release}) catch return null;
        const text = h.readAlloc(arena, path, 32 * 1024 * 1024) catch return null;
        var d: DepIndex = .{ .release = try arena.dupe(u8, release) };
        errdefer d.deinit(gpa);
        try d.parse(gpa, arena, text);
        return d;
    }

    pub fn parse(d: *DepIndex, gpa: std.mem.Allocator, arena: std.mem.Allocator, text: []const u8) !void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const rel = line[0..colon];
            const base = tokens.basename(rel);
            const ko = std.mem.indexOf(u8, base, ".ko") orelse continue;
            var buf: [128]u8 = undefined;
            const name = try arena.dupe(u8, normalize(&buf, base[0..ko]));
            try d.map.put(gpa, name, rel);
        }
    }

    pub fn find(d: *const DepIndex, name: []const u8) ?[]const u8 {
        var buf: [128]u8 = undefined;
        return d.map.get(normalize(&buf, name));
    }
};

fn checkModuleOrigin(s: *scan.Scan) !void {
    var mods: std.ArrayList(Module) = .empty;
    defer mods.deinit(s.gpa);
    if (!try readModules(s, &mods)) return;
    var dep = (try DepIndex.load(s.gpa, s.arena(), s.host)) orelse {
        try s.reduced("modules.dep for the running kernel is missing; module origins not checked", .{});
        return;
    };
    defer dep.deinit(s.gpa);
    const sb = secureBoot(s.host);
    var path_buf: [512]u8 = undefined;
    for (mods.items) |m| {
        const rel = dep.find(m.name) orelse {
            try s.add(.{
                .severity = .high,
                .category = .kernel,
                .title = "Kernel module loaded from outside /lib/modules",
                .description = try s.print("Module {s} is loaded but is not in modules.dep for kernel {s}, so it was inserted from an arbitrary path (insmod /tmp/x.ko) rather than installed.", .{ m.name, dep.release }),
                .remediation = try s.print("Find where it came from (journalctl -k, shell history), then remove it with rmmod {s} if it is not yours and look for the persistence that loads it.", .{m.name}),
                .subject = m.name,
                .details = try s.details(&.{.{ .key = "taint", .value = m.taint }}),
            });
            continue;
        };
        const full = std.fmt.bufPrint(&path_buf, "/lib/modules/{s}/{s}", .{ dep.release, rel }) catch continue;
        const owned = s.owned(full);
        if (std.mem.indexOfScalar(u8, m.taint, 'E') != null) {
            try s.add(.{
                .severity = if (sb) .high else .medium,
                .category = .kernel,
                .title = "Unsigned kernel module loaded",
                .description = try s.print("Module {s} ({s}) carries the E taint: it has no valid signature{s}.", .{ m.name, full, if (sb) " even though Secure Boot is on" else "" }),
                .remediation = "Sign DKMS modules with an enrolled MOK, or remove the module if it is not expected.",
                .subject = try s.dupe(full),
                .details = try s.details(&.{ .{ .key = "taint", .value = m.taint }, .{ .key = "owned_by", .value = s.owner(full) orelse "" } }),
            });
        } else if (std.mem.indexOfScalar(u8, m.taint, 'O') != null and !owned) {
            try s.add(.{
                .severity = .low,
                .category = .kernel,
                .title = "Out-of-tree kernel module not owned by a package",
                .description = try s.print("Module {s} ({s}) was built outside the kernel tree and no package owns its file. DKMS drivers look like this; so do rootkits built on the host.", .{ m.name, full }),
                .remediation = "Confirm the module is a driver you installed (dkms status), otherwise remove it.",
                .subject = try s.dupe(full),
                .details = try s.details(&.{.{ .key = "taint", .value = m.taint }}),
            });
        }
    }
}

/// Rootkit module names (token sequences) and parameter name tokens that only hiding code uses.
pub const rootkit_names = [_][]const u8{ "diamorphine", "reptile", "suterusu", "kovid", "adore", "adore ng", "knark", "rkduck", "nurupo", "rootkit", "brokepkg", "kisni", "bds lkm", "puszek", "singularity", "lkm rootkit", "khook" };
pub const hiding_params = [_][]const u8{ "hide", "hidden", "hidepid", "magic", "backdoor", "rootkit", "invisible", "stealth" };

fn checkModuleNames(s: *scan.Scan) !void {
    var mods: std.ArrayList(Module) = .empty;
    defer mods.deinit(s.gpa);
    if (!try readModules(s, &mods)) return;
    var path_buf: [256]u8 = undefined;
    for (mods.items) |m| {
        if (tokens.firstMatch(m.name, &rootkit_names)) |match| {
            try s.add(.{
                .severity = .critical,
                .category = .malware,
                .title = "Kernel module named like a known rootkit",
                .description = try s.print("Module {s} matches the rootkit name '{s}'.", .{ m.name, match }),
                .remediation = "Treat the host as compromised at kernel level; rebuild from trusted media.",
                .subject = m.name,
            });
            continue;
        }
        const pdir = std.fmt.bufPrint(&path_buf, "/sys/module/{s}/parameters", .{m.name}) catch continue;
        var dir = (s.host.openDir(pdir) catch continue) orelse continue;
        defer dir.close(s.host.io);
        var it = dir.iterate();
        while (it.next(s.host.io) catch null) |entry| {
            var hit: ?[]const u8 = null;
            var toks = tokens.Iterator.init(entry.name);
            while (toks.next()) |t| for (hiding_params) |hp| if (std.mem.eql(u8, t, hp)) {
                hit = hp;
            };
            const word = hit orelse continue;
            try s.add(.{
                .severity = .medium,
                .category = .kernel,
                .title = "Kernel module parameter named for hiding",
                .description = try s.print("Module {s} has a parameter '{s}' (token '{s}'). Rootkit modules expose such switches to hide pids, files or themselves.", .{ m.name, entry.name, word }),
                .remediation = try s.print("Check what module {s} is (its file in /lib/modules and its package) and remove it if unexpected.", .{m.name}),
                .subject = m.name,
                .details = try s.details(&.{.{ .key = "parameter", .value = try s.dupe(entry.name) }}),
            });
        }
    }
}

pub const signature_marker = "~Module signature appended~\n";

/// Whether module bytes (decompressed) end with the appended-signature marker.
pub fn hasSignature(module: []const u8) bool {
    return std.mem.endsWith(u8, module, signature_marker);
}

fn readModuleFile(s: *scan.Scan, path: []const u8) ![]u8 {
    const raw = try s.host.readAlloc(s.gpa, path, 256 * 1024 * 1024);
    if (std.mem.endsWith(u8, path, ".ko")) return raw;
    defer s.gpa.free(raw);
    var in: std.Io.Reader = .fixed(raw);
    if (std.mem.endsWith(u8, path, ".xz")) {
        var d = try std.compress.xz.Decompress.init(&in, s.gpa, &.{});
        defer d.deinit();
        return d.reader.allocRemaining(s.gpa, .limited(512 * 1024 * 1024));
    } else if (std.mem.endsWith(u8, path, ".zst")) {
        const window = try s.gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
        defer s.gpa.free(window);
        var d = std.compress.zstd.Decompress.init(&in, window, .{});
        return d.reader.allocRemaining(s.gpa, .limited(512 * 1024 * 1024));
    } else if (std.mem.endsWith(u8, path, ".gz")) {
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var d = std.compress.flate.Decompress.init(&in, .gzip, &window);
        return d.reader.allocRemaining(s.gpa, .limited(512 * 1024 * 1024));
    }
    return error.UnknownCompression;
}

fn checkModuleSignatures(s: *scan.Scan) !void {
    var mods: std.ArrayList(Module) = .empty;
    defer mods.deinit(s.gpa);
    if (!try readModules(s, &mods)) return;
    var dep = (try DepIndex.load(s.gpa, s.arena(), s.host)) orelse return;
    defer dep.deinit(s.gpa);
    var path_buf: [512]u8 = undefined;
    for (mods.items) |m| {
        if (std.mem.indexOfScalar(u8, m.taint, 'E') != null) continue; // kernel.module_origin
        const rel = dep.find(m.name) orelse continue;
        const full = std.fmt.bufPrint(&path_buf, "/lib/modules/{s}/{s}", .{ dep.release, rel }) catch continue;
        const bytes = readModuleFile(s, full) catch |e| {
            try s.reduced("{s}: {t}", .{ full, e });
            continue;
        };
        defer s.gpa.free(bytes);
        if (hasSignature(bytes)) continue;
        try s.add(.{
            .severity = .medium,
            .category = .kernel,
            .title = "Loaded module's file has no appended signature",
            .description = try s.print("{s} (module {s}) has no '~Module signature appended~' trailer, yet the kernel did not mark the loaded module unsigned. The file on disk may have been replaced after loading.", .{ full, m.name }),
            .remediation = "Reinstall the package that owns the file, or rebuild and sign the module, then reload it.",
            .subject = try s.dupe(full),
        });
    }
}

// eBPF ------------------------------------------------------------------------------------------

pub const ProgType = enum(u32) {
    unspec = 0,
    socket_filter = 1,
    kprobe = 2,
    sched_cls = 3,
    sched_act = 4,
    tracepoint = 5,
    xdp = 6,
    perf_event = 7,
    cgroup_skb = 8,
    raw_tracepoint = 17,
    raw_tracepoint_writable = 24,
    tracing = 26,
    ext = 28,
    lsm = 29,
    _,

    /// Program types that observe or alter kernel behaviour broadly.
    pub fn isTracing(t: ProgType) bool {
        return switch (t) {
            .kprobe, .tracepoint, .perf_event, .raw_tracepoint, .raw_tracepoint_writable, .tracing, .lsm, .ext => true,
            else => false,
        };
    }
};

/// Tracing tools whose programs are expected, by process name.
const bpf_tooling = [_][]const u8{ "systemd", "falco", "tetragon", "cilium-agent", "bpftrace", "tracee", "sysdig", "system-probe", "pixie", "parca-agent", "pyroscope", "kubearmor", "osqueryd", "auditbeat", "falcon-sensor", "falcond", "sentinelone", "elastic-endpoint", "bcc", "perf", "bpftool", "zavd" };

/// `prog_id:` from /proc/<pid>/fdinfo/<fd>.
pub fn fdinfoProgId(text: []const u8) ?u32 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "prog_id:")) continue;
        return std.fmt.parseInt(u32, std.mem.trim(u8, line["prog_id:".len..], " \t"), 10) catch null;
    }
    return null;
}

const BpfProg = struct { id: u32, typ: ProgType, name: [16]u8, uid: u32 };

fn bpfPrograms(gpa: std.mem.Allocator, out: *std.ArrayList(BpfProg)) !void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    var id: u32 = 0;
    var guard: usize = 0;
    while (guard < 1 << 16) : (guard += 1) {
        var attr: [128]u8 align(8) = @splat(0);
        std.mem.writeInt(u32, attr[0..4], id, .little);
        const rc = linux.bpf(@fromBackingInt(@intCast(11)), @ptrCast(&attr), 12); // BPF_PROG_GET_NEXT_ID
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return,
            .PERM, .ACCES => return error.AccessDenied,
            else => return error.BpfFailed,
        }
        id = std.mem.readInt(u32, attr[4..8], .little);
        var fd_attr: [128]u8 align(8) = @splat(0);
        std.mem.writeInt(u32, fd_attr[0..4], id, .little);
        const fd_rc = linux.bpf(@fromBackingInt(@intCast(13)), @ptrCast(&fd_attr), 12); // BPF_PROG_GET_FD_BY_ID
        if (linux.errno(fd_rc) != .SUCCESS) continue;
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);
        var info: [256]u8 align(8) = @splat(0);
        var info_attr: [128]u8 align(8) = @splat(0);
        std.mem.writeInt(u32, info_attr[0..4], @intCast(fd), .little);
        std.mem.writeInt(u32, info_attr[4..8], info.len, .little);
        std.mem.writeInt(u64, info_attr[8..16], @intFromPtr(&info), .little);
        const info_rc = linux.bpf(@fromBackingInt(@intCast(15)), @ptrCast(&info_attr), 16); // BPF_OBJ_GET_INFO_BY_FD
        if (linux.errno(info_rc) != .SUCCESS) continue;
        try out.append(gpa, .{
            .id = id,
            .typ = @fromBackingInt(@intCast(std.mem.readInt(u32, info[0..4], .little))),
            .name = info[64..80].*,
            .uid = std.mem.readInt(u32, info[48..52], .little),
        });
    }
}

fn checkEbpf(s: *scan.Scan) !void {
    if (!s.host.live) {
        try s.reduced("eBPF enumeration needs the live host", .{});
        return;
    }
    var progs: std.ArrayList(BpfProg) = .empty;
    defer progs.deinit(s.gpa);
    bpfPrograms(s.gpa, &progs) catch |e| {
        try s.reduced("bpf(BPF_PROG_GET_NEXT_ID) failed: {t}", .{e});
        return;
    };
    // Program id -> holder pid, from fdinfo of anon_inode:bpf-prog descriptors.
    var holders: std.AutoHashMapUnmanaged(u32, u32) = .empty;
    defer holders.deinit(s.gpa);
    const procs = try s.processes();
    var path_buf: [64]u8 = undefined;
    var link_buf: [64]u8 = undefined;
    var info_buf: [1024]u8 = undefined;
    for (procs) |p| {
        const fd_dir = std.fmt.bufPrint(&path_buf, "/proc/{d}/fd", .{p.pid}) catch continue;
        var dir = (s.host.openDir(fd_dir) catch continue) orelse continue;
        defer dir.close(s.host.io);
        var it = dir.iterate();
        while (it.next(s.host.io) catch null) |entry| {
            const n = dir.readLink(s.host.io, entry.name, &link_buf) catch continue;
            if (!std.mem.eql(u8, link_buf[0..n], "anon_inode:bpf-prog")) continue;
            var info_path: [64]u8 = undefined;
            const ip = std.fmt.bufPrint(&info_path, "/proc/{d}/fdinfo/{s}", .{ p.pid, entry.name }) catch continue;
            const prog_id = fdinfoProgId(s.host.readOpt(ip, &info_buf) orelse continue) orelse continue;
            try holders.put(s.gpa, prog_id, p.pid);
        }
    }
    for (progs.items) |prog| {
        if (!prog.typ.isTracing()) continue;
        const name = std.mem.sliceTo(&prog.name, 0);
        const holder_pid = holders.get(prog.id);
        var holder: ?procfs.Process = null;
        if (holder_pid) |hp| for (procs) |p| if (p.pid == hp) {
            holder = p;
        };
        if (holder) |p| {
            var known = false;
            for (bpf_tooling) |t| if (std.mem.eql(u8, p.comm, t)) {
                known = true;
            };
            if (known or (p.exe != null and s.owned(p.exe.?))) continue;
        }
        try s.add(.{
            .severity = if (holder != null) .high else .medium,
            .category = .kernel,
            .title = if (holder != null) "eBPF tracing program held by an unknown process" else "eBPF tracing program with no holding process",
            .description = try s.print("eBPF program {d} '{s}' of type {t} is attached{s}{s}. Tracing programs can read and alter kernel data; eBPF rootkits (ebpfkit, TripleCross) hide this way.", .{ prog.id, name, prog.typ, if (holder) |_| " and held by " else " (pinned or link-only, no process holds it)", if (holder) |p| p.exe orelse p.comm else "" }),
            .remediation = "List programs with bpftool prog show, identify the loader, and detach anything that no monitoring tool you run accounts for.",
            .subject = if (holder) |p| p.exe orelse p.comm else try s.dupe(name),
            .pid = if (holder) |p| p.pid else null,
            .details = try s.details(&.{
                .{ .key = "prog_id", .value = try s.print("{d}", .{prog.id}) },
                .{ .key = "type", .value = try s.print("{t}", .{prog.typ}) },
                .{ .key = "loaded_by_uid", .value = try s.print("{d}", .{prog.uid}) },
            }),
        });
    }
}

// Command line and bootloader -----------------------------------------------------------------

pub const CmdlineRisk = struct { option: []const u8, severity: finding.Severity, why: []const u8 };

/// Options that weaken the kernel's defences.
pub fn cmdlineRisks(cmdline: []const u8, out: []CmdlineRisk) []CmdlineRisk {
    const table = [_]struct { opt: []const u8, prefix: bool, sev: finding.Severity, why: []const u8 }{
        .{ .opt = "init=/bin/sh", .prefix = false, .sev = .critical, .why = "boots straight into a root shell" },
        .{ .opt = "init=/bin/bash", .prefix = false, .sev = .critical, .why = "boots straight into a root shell" },
        .{ .opt = "init=/usr/bin/bash", .prefix = false, .sev = .critical, .why = "boots straight into a root shell" },
        .{ .opt = "selinux=0", .prefix = false, .sev = .medium, .why = "disables SELinux" },
        .{ .opt = "enforcing=0", .prefix = false, .sev = .medium, .why = "puts SELinux in permissive mode" },
        .{ .opt = "apparmor=0", .prefix = false, .sev = .medium, .why = "disables AppArmor" },
        .{ .opt = "security=none", .prefix = false, .sev = .medium, .why = "disables the Linux security modules" },
        .{ .opt = "module.sig_enforce=0", .prefix = false, .sev = .medium, .why = "allows unsigned modules" },
        .{ .opt = "lockdown=none", .prefix = false, .sev = .low, .why = "disables kernel lockdown" },
        .{ .opt = "mitigations=off", .prefix = false, .sev = .low, .why = "disables CPU vulnerability mitigations" },
        .{ .opt = "nopti", .prefix = false, .sev = .low, .why = "disables page table isolation (Meltdown)" },
        .{ .opt = "nokaslr", .prefix = false, .sev = .low, .why = "disables kernel address randomisation" },
        .{ .opt = "slab_nomerge=0", .prefix = false, .sev = .low, .why = "re-enables slab merging" },
    };
    var n: usize = 0;
    var words = std.mem.tokenizeAny(u8, cmdline, " \n\t");
    while (words.next()) |w| for (table) |t| {
        const hit = if (t.prefix) std.mem.startsWith(u8, w, t.opt) else std.mem.eql(u8, w, t.opt);
        if (hit and n < out.len) {
            out[n] = .{ .option = w, .severity = t.sev, .why = t.why };
            n += 1;
        }
    };
    return out[0..n];
}

fn digestHex(s: *scan.Scan, bytes: []const u8) ![]const u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
    return s.print("{x}", .{&d});
}

fn checkCmdline(s: *scan.Scan) !void {
    var buf: [4096]u8 = undefined;
    const text = std.mem.trim(u8, s.host.readOpt("/proc/cmdline", &buf) orelse {
        try s.reduced("/proc/cmdline unreadable", .{});
        return;
    }, " \n");
    var risks_buf: [16]CmdlineRisk = undefined;
    for (cmdlineRisks(text, &risks_buf)) |r| {
        try s.add(.{
            .check = "kernel.cmdline",
            .severity = r.severity,
            .category = .boot,
            .title = "Kernel command line weakens security",
            .description = try s.print("The running kernel was booted with '{s}', which {s}.", .{ r.option, r.why }),
            .remediation = "Remove the option from the bootloader configuration (GRUB_CMDLINE_LINUX in /etc/default/grub, then update-grub or grub2-mkconfig) and reboot.",
            .subject = "/proc/cmdline",
            .details = try s.details(&.{ .{ .key = "option", .value = try s.dupe(r.option) }, .{ .key = "cmdline", .value = try s.dupe(text) } }),
        });
    }
    // Kernel upgrades change BOOT_IMAGE; compare without it.
    var stable: std.ArrayList(u8) = .empty;
    var words = std.mem.tokenizeScalar(u8, text, ' ');
    while (words.next()) |w| {
        if (std.mem.startsWith(u8, w, "BOOT_IMAGE=") or std.mem.startsWith(u8, w, "initrd=")) continue;
        try stable.print(s.arena(), "{s} ", .{w});
    }
    const changed = s.baseline.hasSubject("kernel.cmdline", "/proc/cmdline");
    if (try s.drift("kernel.cmdline", "/proc/cmdline", stable.items) and changed) {
        try s.add(.{
            .severity = .medium,
            .category = .boot,
            .title = "Kernel command line changed since the baseline",
            .description = try s.print("The kernel was booted with different options than at the last accepted scan: {s}", .{text}),
            .remediation = "Confirm the change was intended (bootloader edits by an administrator), then accept it with zav host --update-baseline.",
            .subject = "/proc/cmdline",
        });
    }
}

const bootloader_files = [_][]const u8{ "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/etc/default/grub", "/boot/efi/EFI/ubuntu/grub.cfg", "/boot/efi/EFI/fedora/grub.cfg", "/boot/loader/loader.conf" };

fn checkBootloader(s: *scan.Scan) !void {
    var denied: usize = 0;
    for (bootloader_files) |path| try bootFile(s, path, &denied);
    if (s.host.openDir("/boot/loader/entries") catch blk: {
        denied += 1;
        break :blk null;
    }) |dir| {
        var d = dir;
        defer d.close(s.host.io);
        var it = d.iterate();
        var path_buf: [512]u8 = undefined;
        while (it.next(s.host.io) catch null) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".conf")) continue;
            const p = std.fmt.bufPrint(&path_buf, "/boot/loader/entries/{s}", .{entry.name}) catch continue;
            try bootFile(s, try s.dupe(p), &denied);
        }
    }
    if (denied > 0) try s.reduced("{d} bootloader files were unreadable without root", .{denied});
}

fn bootFile(s: *scan.Scan, path: []const u8, denied: *usize) !void {
    const bytes = s.host.readAlloc(s.gpa, path, 16 * 1024 * 1024) catch |e| {
        if (e == error.AccessDenied) denied.* += 1;
        return;
    };
    defer s.gpa.free(bytes);
    const known = s.baseline.hasSubject("boot.file", path);
    if (try s.drift("boot.file", path, try digestHex(s, bytes)) and known) {
        try s.add(.{
            .severity = .low,
            .category = .boot,
            .title = "Bootloader configuration changed since the baseline",
            .description = try s.print("{s} differs from the last accepted scan. Kernel updates regenerate it; an attacker edits it to add kernel options or a different init.", .{path}),
            .remediation = "Review the change (kernel options, init=, added entries); if it came from a kernel update, accept it with zav host --update-baseline.",
            .subject = path,
        });
    }
}

// Tests -----------------------------------------------------------------------------------------

const Fixture = @import("../host.zig").Fixture;

test "modules lines, dep index and signatures" {
    const m = parseModulesLine("nvidia 56823808 1 nvidia_modeset, Live 0x0000000000000000 (POE)").?;
    try std.testing.expectEqualStrings("nvidia", m.name);
    try std.testing.expectEqualStrings("POE", m.taint);
    try std.testing.expectEqualStrings("", parseModulesLine("ext4 1003520 1 - Live 0x0000000000000000").?.taint);
    try std.testing.expect(parseModulesLine("x 1") == null);
    var d: DepIndex = .{ .release = "6.8.0" };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    defer d.deinit(std.testing.allocator);
    try d.parse(std.testing.allocator, arena.allocator(), "kernel/drivers/net/wireguard/wireguard.ko.zst: kernel/lib/crypto/libchacha.ko.zst\nkernel/fs/nls/nls-iso8859-1.ko.zst:\n");
    try std.testing.expectEqualStrings("kernel/drivers/net/wireguard/wireguard.ko.zst", d.find("wireguard").?);
    try std.testing.expect(d.find("nls_iso8859_1") != null);
    try std.testing.expect(d.find("nls-iso8859-1") != null);
    try std.testing.expect(hasSignature("ELF...~Module signature appended~\n"));
    try std.testing.expect(!hasSignature("ELF..."));
    try std.testing.expectEqual(@as(?u32, 42), fdinfoProgId("pos:\t0\nflags:\t02000002\nprog_type:\t2\nprog_id:\t42\n"));
    var rb: [8]CmdlineRisk = undefined;
    const risks = cmdlineRisks("BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro mitigations=off init=/bin/sh", &rb);
    try std.testing.expectEqual(@as(usize, 2), risks.len);
    try std.testing.expectEqual(finding.Severity.critical, risks[1].severity);
}

test "fixture: tainted kernel, out-of-tree path and a hidden module produce findings" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/proc/sys/kernel/tainted", "12288\n"); // O (4096) + E (8192)
    try fx.file("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n");
    try fx.file("/proc/modules",
        \\ext4 1003520 1 - Live 0x0000000000000000
        \\evil 16384 0 - Live 0x0000000000000000 (OE)
        \\vboxdrv 696320 0 - Live 0x0000000000000000 (O)
        \\
    );
    try fx.file("/lib/modules/6.8.0-45-generic/modules.dep", "kernel/fs/ext4/ext4.ko.zst: kernel/fs/jbd2/jbd2.ko.zst\nupdates/dkms/vboxdrv.ko.zst:\n");
    try fx.file("/sys/module/ext4/initstate", "live\n");
    try fx.file("/sys/module/evil/initstate", "live\n");
    try fx.file("/sys/module/vboxdrv/initstate", "live\n");
    try fx.file("/sys/module/vboxdrv/parameters/force_async_tsc", "0\n");
    try fx.file("/sys/module/diamorphine/initstate", "live\n");
    try fx.file("/sys/module/sha256_generic/parameters/x", ""); // built-in: no initstate
    try fx.file("/proc/cmdline", "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet\n");

    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .only = &.{ "kernel", "boot" }, .context = .{ .role = .server } });
    defer s.deinit();
    try s.runChecks(&checks);
    var taint = false;
    var outside = false;
    var hidden = false;
    var dkms = false;
    for (s.findings.items) |f| {
        if (std.mem.eql(u8, f.check, "kernel.taint")) taint = true;
        if (std.mem.eql(u8, f.check, "kernel.module_origin") and std.mem.eql(u8, f.subject.?, "evil")) outside = true;
        if (std.mem.eql(u8, f.check, "kernel.module_origin") and std.mem.endsWith(u8, f.subject.?, "vboxdrv.ko.zst")) dkms = true;
        if (std.mem.eql(u8, f.check, "kernel.modules_hidden") and std.mem.eql(u8, f.subject.?, "diamorphine")) hidden = true;
        try std.testing.expect(!std.mem.eql(u8, f.subject orelse "", "ext4"));
        try std.testing.expect(!std.mem.eql(u8, f.subject orelse "", "sha256_generic"));
    }
    try std.testing.expect(taint and outside and hidden and dkms);
}

test "unprivileged runs report reduced coverage for root-only checks" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = fx.host(.linux);
    h.euid = 1000;
    var s = scan.Scan.init(std.testing.allocator, h, .{ .only = &.{"kernel"}, .context = .{ .role = .server } });
    defer s.deinit();
    try s.runChecks(&checks);
    var ebpf_noted = false;
    for (s.coverage.items) |c| if (std.mem.eql(u8, c.check, "kernel.ebpf")) {
        ebpf_noted = true;
    };
    try std.testing.expect(ebpf_noted);
}

test "kernel command line drift against a baseline" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.file("/proc/cmdline", "BOOT_IMAGE=/vmlinuz-6.8 root=/dev/sda1 ro\n");
    try fx.dir("/state");
    var state = try fx.tmp.dir.openDir(std.testing.io, "state", .{});
    defer state.close(std.testing.io);
    const run = struct {
        fn go(f: *Fixture, st: std.Io.Dir) !usize {
            var s = scan.Scan.init(std.testing.allocator, f.host(.linux), .{ .only = &.{"kernel.cmdline"}, .state_dir = st, .context = .{ .role = .server } });
            defer s.deinit();
            try s.runChecks(&checks);
            return s.findings.items.len;
        }
    }.go;
    try std.testing.expectEqual(@as(usize, 0), try run(&fx, state)); // first run records
    try fx.file("/proc/cmdline", "BOOT_IMAGE=/vmlinuz-6.9 root=/dev/sda1 ro\n");
    try std.testing.expectEqual(@as(usize, 0), try run(&fx, state)); // kernel upgrade only
    try fx.file("/proc/cmdline", "BOOT_IMAGE=/vmlinuz-6.9 root=/dev/sda1 ro apparmor=0\n");
    try std.testing.expectEqual(@as(usize, 2), try run(&fx, state)); // weakening + drift
}
