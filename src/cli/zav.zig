//! `zav`: compile signature databases, inspect them, and scan files.
//!
//!   zav compile [--out FILE] [--allow-unverified] [--no-builtin] [--malwarebazaar CSV] SOURCE...
//!   zav info DB
//!   zav coverage DB
//!   zav scan [--db FILE] [--json] PATH...
//!   zav host [--deep] [--json] [--min-severity S] [--category C]... [--config FILE] [--list]
//!   zav audit [--json] [--min-severity S] [--installed] [--cve-index FILE] [--cve-key HEX]... [PATH...]
//!   zav cve fetch [--feeds DIR] [--nvd] [--osv ECOSYSTEM]...    (explicit network access)
//!   zav cve compile [--feeds DIR] [--out FILE] [--signing-key SEEDFILE]
//!
//! scan follows clamscan: 0 clean, 1 something found, 2 an error. host and audit exit 0 when
//! nothing at low or above was found, 11, 12, 13 or 14 for a highest finding of low, medium, high
//! or critical, and 2 on an error. Databases are opened with
//! signature checks; `--allow-unsigned` (or ZAV_ALLOW_UNSIGNED=1) accepts locally compiled,
//! unsigned databases. The CVE index is opened unsigned-tolerant unless `--cve-key` names the
//! trusted keys, which then requires a signature from one of them and a full body check.
const std = @import("std");
const cli = @import("zig_cli");
const zav = @import("zav");

const Command = cli.BaseCommand;
const Option = cli.Option;
const Argument = cli.Argument;

/// Actions are plain functions, so the process state they need lives here.
var app: struct {
    io: std.Io = undefined,
    gpa: std.mem.Allocator = undefined,
    out: *std.Io.Writer = undefined,
    err: *std.Io.Writer = undefined,
} = .{};

pub fn main(init: std.process.Init) !u8 {
    app.io = init.io;
    app.gpa = init.gpa;
    var out_buf: [8192]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    var err_buf: [2048]u8 = undefined;
    var err = std.Io.File.stderr().writerStreaming(init.io, &err_buf);
    app.out = &out.interface;
    app.err = &err.interface;
    defer out.interface.flush() catch {};
    defer err.interface.flush() catch {};

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const root = try buildCommands(init.gpa);
    defer {
        root.deinit();
        init.gpa.destroy(root);
    }
    var version_buf: [32]u8 = undefined;
    const version = try std.fmt.bufPrint(&version_buf, "{f}", .{zav.version});
    return cli.run(init.gpa, root, args[1..], .{ .stdout = app.out, .stderr = app.err, .version = version });
}

fn buildCommands(gpa: std.mem.Allocator) !*Command {
    const root = try Command.init(gpa, "zav", "Low-memory anti-malware engine");
    _ = root.enableJson();

    const compile = try Command.init(gpa, "compile", "Compile signature sources into a .zavdb database");
    _ = try compile.addOption(Option.init("out", "out", "Output database", .string).withShort('o'));
    _ = try compile.addOption(Option.init("allow-unverified", "allow-unverified", "Accept CLD and unsigned containers", .bool));
    _ = try compile.addOption(Option.init("no-builtin", "no-builtin", "Leave out the built-in signatures", .bool));
    _ = try compile.addOption(Option.init("malwarebazaar", "malwarebazaar", "MalwareBazaar CSV export (opt-in feed)", .string).withRepeatable(true));
    _ = try compile.addOption(Option.init("guardian", "guardian", "Local Guardian source directory (explicit authoring trust)", .string));
    _ = try compile.addOption(Option.init("guardian-version", "guardian-version", "Local Guardian pack version (default 1)", .string));
    _ = try compile.addOption(Option.init("guardian-bundle", "guardian-bundle", "Signed Guardian source bundle", .string).withRepeatable(true));
    _ = try compile.addOption(Option.init("guardian-key", "guardian-key", "Trusted distributor Ed25519 public key (64 hex digits)", .string).withRepeatable(true));
    _ = try compile.addArgument(Argument.init("sources", "CVD/CLD containers and signature files", .string).withVariadic(true).withRequired(false));
    _ = compile.setActionWithCode(compileAction);
    _ = try root.addCommand(compile);

    const pack = try Command.init(gpa, "rule-pack", "Sign a Guardian source directory for distribution");
    _ = try pack.addOption(Option.init("source", "source", "Guardian source directory", .string));
    _ = try pack.addOption(Option.init("version", "version", "Positive monotonic pack version", .string));
    _ = try pack.addOption(Option.init("signing-key", "signing-key", "Private Ed25519 seed file (exactly 32 raw bytes)", .string));
    _ = try pack.addOption(Option.init("out", "out", "Output signed source bundle", .string));
    _ = pack.setActionWithCode(rulePackAction);
    _ = try root.addCommand(pack);

    const info = try Command.init(gpa, "info", "Show a database's header, sources and sections");
    _ = try info.addOption(Option.init("allow-unsigned", "allow-unsigned", "Accept an unsigned database", .bool));
    _ = try info.addArgument(Argument.init("db", "Database", .string));
    _ = info.setActionWithCode(infoAction);
    _ = try root.addCommand(info);

    const coverage = try Command.init(gpa, "coverage", "Print what a database includes and what it skipped");
    _ = try coverage.addOption(Option.init("allow-unsigned", "allow-unsigned", "Accept an unsigned database", .bool));
    _ = try coverage.addArgument(Argument.init("db", "Database", .string));
    _ = coverage.setActionWithCode(coverageAction);
    _ = try root.addCommand(coverage);

    const scan = try Command.init(gpa, "scan", "Scan files and directories");
    _ = try scan.addOption(Option.init("db", "db", "Database to scan with", .string));
    _ = try scan.addOption(Option.init("allow-unsigned", "allow-unsigned", "Accept an unsigned database", .bool));
    _ = try scan.addOption(Option.init("keep-cache", "keep-cache", "Keep directory-scan files in the OS cache", .bool));
    _ = try scan.addOption(Option.init("detect-pua", "detect-pua", "Report potentially unwanted applications (signatures from .ndu, .ldu, .hdu and the other u sources); also --detect-pua=yes|no, as clamscan spells it", .bool));
    _ = try scan.addArgument(Argument.init("paths", "Files or directories to scan", .string).withVariadic(true));
    _ = scan.setActionWithCode(scanAction);
    _ = try root.addCommand(scan);

    const host = try Command.init(gpa, "host", "Check this machine: processes, network, kernel, persistence, privileges, hardening");
    try addReportOptions(host);
    _ = try host.addOption(Option.init("deep", "deep", "Run the deep tier too (hashes, full walks, pid probes)", .bool));
    _ = try host.addOption(Option.init("category", "category", "Only this category (repeatable)", .string).withRepeatable(true));
    _ = try host.addOption(Option.init("check", "check", "Only this check id or dotted prefix (repeatable)", .string).withRepeatable(true));
    _ = try host.addOption(Option.init("config", "config", "Suppression config (JSON); default /etc/zav/host.json", .string));
    _ = try host.addOption(Option.init("update-baseline", "update-baseline", "Accept the current state as the new baseline", .bool));
    _ = try host.addOption(Option.init("db", "db", "Signature database to scan unowned executables with", .string));
    _ = try host.addOption(Option.init("allow-unsigned", "allow-unsigned", "Accept an unsigned signature database", .bool));
    _ = try host.addOption(Option.init("list", "list", "List the checks for this system and exit", .bool));
    _ = host.setActionWithCode(hostAction);
    _ = try root.addCommand(host);

    const audit = try Command.init(gpa, "audit", "Match lockfiles, packages and binaries against known vulnerabilities");
    try addReportOptions(audit);
    _ = try audit.addOption(Option.init("installed", "installed", "Also audit installed OS packages, Homebrew, pantry and apps", .bool));
    _ = try audit.addArgument(Argument.init("paths", "Directories or files to audit (default .)", .string).withVariadic(true).withRequired(false));
    _ = audit.setActionWithCode(auditAction);
    _ = try root.addCommand(audit);

    const cve = try Command.init(gpa, "cve", "Fetch vulnerability feeds and compile the .zavcve index");
    const fetch = try Command.init(gpa, "fetch", "Download CISA KEV, OSV exports and (with --nvd) NVD into the feeds directory");
    _ = try fetch.addOption(Option.init("feeds", "feeds", "Feeds directory (default <state>/feeds)", .string));
    _ = try fetch.addOption(Option.init("state", "state", "State directory", .string));
    _ = try fetch.addOption(Option.init("nvd", "nvd", "Sync NVD (initial mirror or incremental; NVD_API_KEY raises the rate limit)", .bool));
    _ = try fetch.addOption(Option.init("osv", "osv", "OSV ecosystem export to fetch (repeatable; default npm, PyPI, Go, crates.io)", .string).withRepeatable(true));
    _ = fetch.setActionWithCode(cveFetchAction);
    _ = try cve.addCommand(fetch);
    const cve_compile = try Command.init(gpa, "compile", "Compile the feeds directory into a .zavcve index");
    _ = try cve_compile.addOption(Option.init("feeds", "feeds", "Feeds directory (default <state>/feeds)", .string));
    _ = try cve_compile.addOption(Option.init("state", "state", "State directory", .string));
    _ = try cve_compile.addOption(Option.init("out", "out", "Output index (default <state>/cve.zavcve)", .string).withShort('o'));
    _ = try cve_compile.addOption(Option.init("signing-key", "signing-key", "Sign the index with this private Ed25519 seed file (exactly 32 raw bytes)", .string));
    _ = cve_compile.setActionWithCode(cveCompileAction);
    _ = try cve.addCommand(cve_compile);
    _ = try root.addCommand(cve);
    return root;
}

fn addReportOptions(cmd: *Command) !void {
    _ = try cmd.addOption(Option.init("min-severity", "min-severity", "Leave out findings below this severity (info, low, medium, high, critical)", .string));
    _ = try cmd.addOption(Option.init("state", "state", "State directory for baselines, caches and the CVE index", .string));
    _ = try cmd.addOption(Option.init("cve-index", "cve-index", "CVE index (default <state>/cve.zavcve)", .string));
    _ = try cmd.addOption(Option.init("cve-key", "cve-key", "Require a CVE index signed by this Ed25519 public key (64 hex digits)", .string).withRepeatable(true));
}

fn flag(ctx: *Command.ParseContext, name: []const u8) bool {
    const value = ctx.getOption(name) orelse return false;
    return std.mem.eql(u8, value, "true");
}

fn allowUnsigned(ctx: *Command.ParseContext) bool {
    if (flag(ctx, "allow-unsigned")) return true;
    const env = std.c.getenv("ZAV_ALLOW_UNSIGNED") orelse return false;
    return std.mem.eql(u8, std.mem.span(env), "1");
}

fn openDb(ctx: *Command.ParseContext, path: []const u8) !zav.db.reader.Database {
    return zav.db.reader.open(app.io, std.Io.Dir.cwd(), path, .{ .allow_unsigned = allowUnsigned(ctx) }) catch |e| {
        try app.err.print("zav: cannot open {s}: {t}\n", .{ path, e });
        return e;
    };
}

fn compileAction(ctx: *Command.ParseContext) !u8 {
    const out_path = ctx.getOption("out") orelse "zav.zavdb";
    const cwd = std.Io.Dir.cwd();

    // Large sections and sort runs go to a temporary directory next to the output (the same
    // filesystem, and never a RAM-backed /tmp), removed when the compile ends.
    var nonce: [8]u8 = undefined;
    app.io.random(&nonce);
    var spill_buf: [std.fs.max_path_bytes]u8 = undefined;
    const spill_path = try std.fmt.bufPrint(&spill_buf, "{s}.spill-{x}", .{ out_path, std.mem.readInt(u64, &nonce, .little) });
    try cwd.createDirPath(app.io, spill_path);
    defer cwd.deleteTree(app.io, spill_path) catch {};
    var spill_dir = try cwd.openDir(app.io, spill_path, .{});
    defer spill_dir.close(app.io);
    var spill = zav.compile.spill.Spill.init(app.io, spill_dir);

    var compiler = zav.compile.compiler.Compiler.initOptions(app.gpa, .{ .spill = &spill });
    defer compiler.deinit();

    // Ignore lists first, wherever they are, so they apply to every signature.
    for (ctx.arguments.items) |path| {
        const ext = std.fs.path.extension(path);
        if (std.mem.eql(u8, ext, ".cvd") or std.mem.eql(u8, ext, ".cld")) {
            const kind: zav.compile.cvd.Kind = if (std.mem.eql(u8, ext, ".cld")) .cld else .cvd;
            compiler.preloadIgnores(app.io, cwd, path, .{ .kind = kind, .allow_unverified = flag(ctx, "allow-unverified") }) catch |e| {
                try app.err.print("zav: {s}: {t}\n", .{ path, e });
                return 2;
            };
        } else if (std.mem.eql(u8, ext, ".ign2")) {
            const text = cwd.readFileAlloc(app.io, path, app.gpa, .limited(64 * 1024 * 1024)) catch |e| {
                try app.err.print("zav: {s}: {t}\n", .{ path, e });
                return 2;
            };
            defer app.gpa.free(text);
            try compiler.addFile(std.fs.path.basename(path), text);
        }
    }
    if (!flag(ctx, "no-builtin")) try compiler.addBuiltin();

    for (ctx.arguments.items) |path| {
        const ext = std.fs.path.extension(path);
        if (std.mem.eql(u8, ext, ".ign2")) continue;
        if (std.mem.eql(u8, ext, ".cvd") or std.mem.eql(u8, ext, ".cld")) {
            const kind: zav.compile.cvd.Kind = if (std.mem.eql(u8, ext, ".cld")) .cld else .cvd;
            _ = compiler.addContainer(app.io, cwd, path, .{ .kind = kind, .allow_unverified = flag(ctx, "allow-unverified") }) catch |e| {
                try app.err.print("zav: {s}: {t}\n", .{ path, e });
                return 2;
            };
        } else {
            const file = cwd.openFile(app.io, path, .{}) catch |e| {
                try app.err.print("zav: {s}: {t}\n", .{ path, e });
                return 2;
            };
            defer file.close(app.io);
            var buf: [64 * 1024]u8 = undefined;
            var r = file.reader(app.io, &buf);
            compiler.addStream(std.fs.path.basename(path), &r.interface) catch |e| {
                try app.err.print("zav: {s}: {t}\n", .{ path, e });
                return 2;
            };
        }
    }
    for (ctx.getOptionValues("malwarebazaar")) |path| {
        const text = try cwd.readFileAlloc(app.io, path, app.gpa, .limited(2 * 1024 * 1024 * 1024));
        defer app.gpa.free(text);
        try compiler.addMalwareBazaar(std.fs.path.basename(path), text, 0);
    }

    if (ctx.getOption("guardian")) |path| {
        var dir = try cwd.openDir(app.io, path, .{ .iterate = true, .follow_symlinks = false });
        defer dir.close(app.io);
        const version = try std.fmt.parseInt(u64, ctx.getOption("guardian-version") orelse "1", 10);
        const pack = try zav.compile.guardian.readDirectory(compiler.arena.allocator(), app.io, dir, version);
        try compiler.addGuardianPack(pack);
    }
    var trusted: std.ArrayList(zav.db.reader.TrustedKey) = .empty;
    defer trusted.deinit(app.gpa);
    trustedKeys(ctx, "guardian-key", &trusted) catch |e| switch (e) {
        error.InvalidPublicKey => return error.InvalidGuardianPublicKey,
        else => return e,
    };
    for (ctx.getOptionValues("guardian-bundle")) |path| {
        const bytes = try cwd.readFileAlloc(app.io, path, app.gpa, .limited(zav.compile.guardian.bundle.max_bytes + 1));
        defer app.gpa.free(bytes);
        try compiler.addGuardianBundle(bytes, trusted.items);
    }

    app.io.random(&nonce);
    const summary = try compiler.write(app.io, cwd, out_path, .{ .db_version = std.mem.readInt(u64, &nonce, .little) >> 1 });
    if (ctx.wantsJson()) {
        try ctx.writeJson(.{ .out = out_path, .signatures = summary.signatures, .hash_rules = summary.hash_rules, .allowlist_rules = summary.allowlist_rules, .duplicates = summary.duplicates });
    } else {
        try app.out.print("{s}: {d} signatures, {d} hash rules, {d} allowlist entries, {d} duplicates dropped\n", .{ out_path, summary.signatures, summary.hash_rules, summary.allowlist_rules, summary.duplicates });
    }
    return 0;
}

fn rulePackAction(ctx: *Command.ParseContext) !u8 {
    const source = ctx.getOption("source") orelse return error.MissingSource;
    const version = try std.fmt.parseInt(u64, ctx.getOption("version") orelse return error.MissingVersion, 10);
    const key_path = ctx.getOption("signing-key") orelse return error.MissingSigningKey;
    const out = ctx.getOption("out") orelse return error.MissingOutput;
    var arena: std.heap.ArenaAllocator = .init(app.gpa);
    defer arena.deinit();
    const cwd = std.Io.Dir.cwd();
    var dir = try cwd.openDir(app.io, source, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(app.io);
    const pack = try zav.compile.guardian.readDirectory(arena.allocator(), app.io, dir, version);
    // Do not sign an invalid YARA pack: validate through the same compiler path as consumers.
    var compiler = zav.compile.compiler.Compiler.init(app.gpa);
    defer compiler.deinit();
    try compiler.addGuardianPack(pack);
    var kp = try loadSigningKey(key_path);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    const bytes = try zav.compile.guardian.bundle.encode(arena.allocator(), pack, kp);
    try cwd.writeFile(app.io, .{ .sub_path = out, .data = bytes });
    try app.out.print("{s}: Guardian pack version {d}, {d} source files\n", .{ out, version, pack.entries.len });
    return 0;
}

/// The one loader for signing keys: a file of exactly 32 raw bytes, the Ed25519 seed. Used by
/// `rule-pack` and `cve compile`, so one distributor key can sign both. Zero the result after use.
fn loadSigningKey(path: []const u8) !std.crypto.sign.Ed25519.KeyPair {
    const seed = try std.Io.Dir.cwd().readFileAlloc(app.io, path, app.gpa, .limited(33));
    defer {
        std.crypto.secureZero(u8, seed);
        app.gpa.free(seed);
    }
    if (seed.len != 32) return error.InvalidSigningKey;
    return std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed[0..32].*);
}

/// Append every `option` value (a public key as 64 hex digits) to `out`.
fn trustedKeys(ctx: *Command.ParseContext, option: []const u8, out: *std.ArrayList(zav.db.reader.TrustedKey)) !void {
    for (ctx.getOptionValues(option)) |hex| {
        var key: [32]u8 = undefined;
        if (hex.len != 64) return error.InvalidPublicKey;
        _ = std.fmt.hexToBytes(&key, hex) catch return error.InvalidPublicKey;
        try out.append(app.gpa, .{ .public_key = key });
    }
}

fn infoAction(ctx: *Command.ParseContext) !u8 {
    const path = ctx.getArgument(0).?;
    const database = openDb(ctx, path) catch return 2;
    defer database.close();
    const h = database.header();
    try app.out.print("{s}\n  format       {d}.{d}\n  db version   {d}\n  size         {d} bytes\n  signed       {s}\n", .{
        path, h.format_major, h.format_minor, h.db_version, h.total_size, if (std.mem.allEqual(u8, &h.key_id, 0)) "no" else "yes",
    });
    try app.out.print("  sources      main {d}, daily {d}, bytecode {d}, guardian {d}, malwarebazaar {d}, flevel {d}\n  sections     {d}\n", .{
        h.sources.clamav_main, h.sources.clamav_daily, h.sources.clamav_bytecode, h.sources.guardian_rules, h.sources.malwarebazaar, h.sources.engine_flevel, h.section_count,
    });
    for (database.sections()) |s| {
        try app.out.print("    {t:<16} variant {d:<3} offset {d:<10} size {d}{s}\n", .{ s.kind, s.variant, s.offset, s.size, if (s.flags.hot) " (hot)" else "" });
    }
    // The byte-pattern prefilter: filter sizes and loads per partition.
    if (database.section(.prefilter, 0)) |section| if (database.section(.subsig_prog, 0)) |progs_bytes| {
        const progs = zav.match.prog.Programs.init(progs_bytes) catch return 0;
        const parts = zav.match.prefilter.loadAll(section, progs) catch |e| {
            try app.out.print("  prefilter    invalid: {t}\n", .{e});
            return 0;
        };
        try app.out.writeAll("  prefilter\n");
        try zav.match.prefilter.describe(&parts, app.out);
    };
    return 0;
}

fn coverageAction(ctx: *Command.ParseContext) !u8 {
    const path = ctx.getArgument(0).?;
    const database = openDb(ctx, path) catch return 2;
    defer database.close();
    const text = database.section(.coverage_report, 0) orelse {
        try app.err.print("zav: {s} has no coverage report\n", .{path});
        return 2;
    };
    try app.out.writeAll(text);
    return 0;
}

const FileScan = struct {
    ctx: *Command.ParseContext,
    index: zav.engine.hashscan.HashIndex,
    block: []u8,
    tracker: zav.engine.limits.Tracker = .init(.{}),
    name_buf: [512]u8 = undefined,
    directory: []const u8 = "",
    found: bool = false,
    failed: bool = false,

    fn readError(scan: *FileScan, path: []const u8, err: anyerror) !void {
        scan.failed = true;
        try app.out.print("{s}: {t} ERROR\n", .{ path, err });
    }

    fn scanSource(scan: *FileScan, path: []const u8, source: zav.engine.source.Source) !void {
        scan.tracker.reset();
        const verdict = zav.engine.hashscan.scanSource(app.io, &scan.index, source, &scan.tracker, scan.block) catch |err|
            return scan.readError(path, err);
        switch (verdict) {
            .clean, .allowed => try report(scan.ctx, path, "OK", null),
            .infected => |sig| {
                scan.found = true;
                const name = if (scan.index.meta) |m| try m.name(sig, &scan.name_buf) else "unknown";
                try report(scan.ctx, path, "FOUND", name);
            },
            .limited => |event| {
                var event_buf: [64]u8 = undefined;
                try report(scan.ctx, path, "LIMITED", try std.fmt.bufPrint(&event_buf, "{t}", .{event}));
            },
        }
    }

    fn visit(ptr: *anyopaque, relative: []const u8, source: zav.engine.source.Source, _: ?zav.rt.directory.Volume) !void {
        const scan: *FileScan = @ptrCast(@alignCast(ptr));
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const separator = if (std.fs.path.isSep(scan.directory[scan.directory.len - 1])) "" else std.fs.path.sep_str;
        const path = try std.fmt.bufPrint(&path_buf, "{s}{s}{s}", .{ scan.directory, separator, relative });
        try scan.scanSource(path, source);
    }
};

fn scanAction(ctx: *Command.ParseContext) !u8 {
    const db_path = ctx.getOption("db") orelse "zav.zavdb";
    const database = openDb(ctx, db_path) catch return 2;
    defer database.close();
    const index = zav.engine.hashscan.HashIndex.load(database) catch |e| {
        try app.err.print("zav: {s}: {t}\n", .{ db_path, e });
        return 2;
    };
    var scratch = try zav.engine.scratch.Scratch.init(zav.engine.scratch.default_reservation);
    defer scratch.deinit();
    var scan: FileScan = .{ .ctx = ctx, .index = index, .block = try scratch.allocator().alloc(u8, 256 * 1024) };
    scan.index.detect_pua = flag(ctx, "detect-pua");
    var reader: ?zav.rt.scan_io.Reader = null;
    defer if (reader) |*worker| worker.deinit();

    for (ctx.arguments.items) |path| {
        const file = std.Io.Dir.cwd().openFile(app.io, path, .{}) catch |err| {
            try scan.readError(path, err);
            continue;
        };
        defer file.close(app.io);
        const stat = file.stat(app.io) catch |err| {
            try scan.readError(path, err);
            continue;
        };
        if (stat.kind == .directory) {
            const dir = std.Io.Dir.cwd().openDir(app.io, path, .{ .iterate = true }) catch |err| {
                try scan.readError(path, err);
                continue;
            };
            defer dir.close(app.io);
            if (reader == null) reader = try .init(app.gpa, app.io, .{
                .cache = if (flag(ctx, "keep-cache")) .keep else .discard,
            });
            scan.directory = path;
            reader.?.walk(dir, .{ .context = &scan, .file = FileScan.visit }) catch |err| try scan.readError(path, err);
        } else {
            const mark = scratch.mark();
            defer scratch.release(mark);
            const source: zav.engine.source.Source = .{ .file = .{ .file = file, .len = stat.size } };
            try scan.scanSource(path, zav.rt.io_small.prepare(app.io, scratch.allocator(), source));
        }
    }
    if (scan.failed) return 2;
    return if (scan.found) 1 else 0;
}

fn report(ctx: *Command.ParseContext, path: []const u8, status: []const u8, detail: ?[]const u8) !void {
    if (ctx.wantsJson()) {
        try ctx.writeJson(.{ .path = path, .status = status, .detail = detail });
    } else if (detail) |d| {
        // clamscan's line format, so existing tooling can parse it.
        if (std.mem.eql(u8, status, "FOUND")) try app.out.print("{s}: {s} FOUND\n", .{ path, d }) else try app.out.print("{s}: {s} ({s})\n", .{ path, status, d });
    } else try app.out.print("{s}: {s}\n", .{ path, status });
}

// Host checks and audits -----------------------------------------------------------------------

/// /var/lib/zav for root, $XDG_STATE_HOME/zav or ~/.local/state/zav otherwise.
fn stateDir(ctx: *Command.ParseContext, buf: []u8) ![]const u8 {
    if (ctx.getOption("state")) |s| return s;
    if (zav.host.sys.euid() == 0) return "/var/lib/zav";
    if (std.c.getenv("XDG_STATE_HOME")) |x| return std.fmt.bufPrint(buf, "{s}/zav", .{std.mem.span(x)});
    const home = std.c.getenv("HOME") orelse return error.NoHome;
    return std.fmt.bufPrint(buf, "{s}/.local/state/zav", .{std.mem.span(home)});
}

fn openState(path: []const u8) ?std.Io.Dir {
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(app.io, path) catch return null;
    return cwd.openDir(app.io, path, .{}) catch null;
}

fn minSeverity(ctx: *Command.ParseContext) !zav.host.Severity {
    const text = ctx.getOption("min-severity") orelse return .info;
    return zav.host.Severity.parse(text) orelse {
        try app.err.print("zav: unknown severity '{s}' (info, low, medium, high, critical)\n", .{text});
        return error.BadArgument;
    };
}

fn openCveIndex(ctx: *Command.ParseContext, state: []const u8, required: bool) !?zav.cve.index.Index {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = ctx.getOption("cve-index") orelse try std.fmt.bufPrint(&buf, "{s}/cve.zavcve", .{state});
    var trusted: std.ArrayList(zav.db.reader.TrustedKey) = .empty;
    defer trusted.deinit(app.gpa);
    trustedKeys(ctx, "cve-key", &trusted) catch |e| {
        try app.err.print("zav: --cve-key: {t} (expected 64 hex digits)\n", .{e});
        return e;
    };
    // Without --cve-key, an index compiled locally from the public feeds (unsigned) is accepted.
    // With it, the index must be signed by one of those keys, its whole body must match the
    // signed BLAKE3 root, and the header bytes outside the signature must be zero
    // (Index.verifyBody). The section table is bound to the signature by xxh3 only, which is not
    // a cryptographic hash, so this is not yet authentication of every byte (see DESIGN.md).
    const options: zav.db.reader.OpenOptions = if (trusted.items.len > 0)
        .{ .trusted_keys = trusted.items, .allow_unsigned = false }
    else
        .{ .allow_unsigned = true };
    const index = zav.cve.index.Index.open(app.io, std.Io.Dir.cwd(), path, options) catch |e| {
        if (!required and e == error.FileNotFound) return null;
        try app.err.print("zav: cannot open CVE index {s}: {t} (run zav cve fetch, then zav cve compile)\n", .{ path, e });
        return e;
    };
    if (trusted.items.len > 0) index.verifyBody() catch |e| {
        index.close();
        try app.err.print("zav: cannot open CVE index {s}: {t}\n", .{ path, e });
        return e;
    };
    return index;
}

/// Scans unowned executables with a signature database for `zav host --db`.
const EngineScanner = struct {
    index: zav.engine.hashscan.HashIndex,
    scratch: zav.engine.scratch.Scratch,
    block: []u8,
    name_buf: [512]u8 = undefined,

    fn scanFn(ctx: *anyopaque, h: zav.host.Host, path: []const u8) ?[]const u8 {
        const self: *EngineScanner = @ptrCast(@alignCast(ctx));
        const file = h.root.openFile(h.io, zav.host.host.Host.rel(path), .{}) catch return null;
        defer file.close(h.io);
        const size = (file.stat(h.io) catch return null).size;
        var tracker = zav.engine.limits.Tracker.init(.{});
        const verdict = zav.engine.hashscan.scanSource(h.io, &self.index, .{ .file = .{ .file = file, .len = size } }, &tracker, self.block) catch return null;
        return switch (verdict) {
            .infected => |sig| if (self.index.meta) |m| (m.name(sig, &self.name_buf) catch "unknown") else "unknown",
            else => null,
        };
    }
};

fn emit(ctx: *Command.ParseContext, s: *zav.host.Scan) !u8 {
    if (ctx.wantsJson()) {
        try s.writeJson(app.out, .{ .whitespace = .indent_2 });
        try app.out.writeByte('\n');
    } else try zav.host.render.writeText(s, app.out);
    return s.exitCode();
}

const all_checks = zav.host.registry ++ zav.cve.registry;

fn hostAction(ctx: *Command.ParseContext) !u8 {
    const h = zav.host.Host.openLive(app.io) catch {
        try app.err.writeAll("zav: host checks support Linux and macOS\n");
        return 2;
    };
    defer h.close();
    if (flag(ctx, "list")) {
        for (all_checks) |c| if (c.os == h.os) try app.out.print("{s:<34} {t:<6} {t:<8} {s}\n", .{ c.id, c.tier, c.privilege, c.summary });
        return 0;
    }
    const min = minSeverity(ctx) catch return 2;
    var cats: ?std.EnumSet(zav.host.Category) = null;
    for (ctx.getOptionValues("category")) |c| {
        const cat = zav.host.Category.parse(c) orelse {
            try app.err.print("zav: unknown category '{s}'\n", .{c});
            return 2;
        };
        if (cats == null) cats = .empty;
        cats.?.insert(cat);
    }
    var cfg: zav.host.suppress.Config = .{};
    defer cfg.deinit();
    const cfg_path = ctx.getOption("config") orelse "/etc/zav/host.json";
    if (std.Io.Dir.cwd().readFileAlloc(app.io, cfg_path, app.gpa, .limited(16 * 1024 * 1024))) |text| {
        defer app.gpa.free(text);
        cfg = zav.host.suppress.Config.parse(app.gpa, text) catch |e| {
            try app.err.print("zav: {s}: {t}\n", .{ cfg_path, e });
            return 2;
        };
    } else |e| if (ctx.getOption("config") != null) {
        try app.err.print("zav: {s}: {t}\n", .{ cfg_path, e });
        return 2;
    }
    var state_buf: [std.fs.max_path_bytes]u8 = undefined;
    const state_path = stateDir(ctx, &state_buf) catch "";
    var state = if (state_path.len > 0) openState(state_path) else null;
    defer if (state) |*d| d.close(app.io);

    var engine: ?EngineScanner = null;
    var database: ?zav.db.reader.Database = null;
    defer if (database) |d| d.close();
    defer if (engine) |*e| e.scratch.deinit();
    if (ctx.getOption("db")) |db_path| {
        database = openDb(ctx, db_path) catch return 2;
        engine = .{ .index = zav.engine.hashscan.HashIndex.load(database.?) catch |e| {
            try app.err.print("zav: {s}: {t}\n", .{ db_path, e });
            return 2;
        }, .scratch = try zav.engine.scratch.Scratch.init(zav.engine.scratch.default_reservation), .block = undefined };
        engine.?.block = try engine.?.scratch.allocator().alloc(u8, 256 * 1024);
    }
    var cve_index = openCveIndex(ctx, state_path, false) catch return 2;
    defer if (cve_index) |i| i.close();

    // pantry's global install root, inventoried for vulnerability.packages.
    var pantry_buf: [std.fs.max_path_bytes]u8 = undefined;
    var pantry_roots: [1][]const u8 = undefined;
    var pantry_n: usize = 0;
    if (std.c.getenv("HOME")) |home| {
        pantry_roots[0] = std.fmt.bufPrint(&pantry_buf, "{s}/.local/share/pantry/global/packages", .{std.mem.span(home)}) catch "";
        pantry_n = 1;
    }
    var s = zav.host.Scan.init(app.gpa, h, .{
        .pantry_roots = pantry_roots[0..pantry_n],
        .tier = if (flag(ctx, "deep")) .deep else .fast,
        .categories = cats,
        .min_severity = min,
        .suppressions = &cfg,
        .only = ctx.getOptionValues("check"),
        .state_dir = state,
        .update_baseline = flag(ctx, "update-baseline"),
        .scanner = if (engine) |*e| .{ .ctx = e, .scanFn = EngineScanner.scanFn } else null,
        .cve_index = if (cve_index) |*i| i else null,
    });
    defer s.deinit();
    s.runChecks(&all_checks) catch |e| {
        try app.err.print("zav: host scan failed: {t}\n", .{e});
        return 2;
    };
    return emit(ctx, &s);
}

fn auditAction(ctx: *Command.ParseContext) !u8 {
    const h = zav.host.Host.openLive(app.io) catch {
        try app.err.writeAll("zav: audit supports Linux and macOS\n");
        return 2;
    };
    defer h.close();
    const min = minSeverity(ctx) catch return 2;
    var state_buf: [std.fs.max_path_bytes]u8 = undefined;
    const state_path = stateDir(ctx, &state_buf) catch "";
    const index = (openCveIndex(ctx, state_path, true) catch return 2).?;
    defer index.close();
    var arena = std.heap.ArenaAllocator.init(app.gpa);
    defer arena.deinit();
    var paths: std.ArrayList([]const u8) = .empty;
    const given: []const []const u8 = if (ctx.arguments.items.len > 0) ctx.arguments.items else &.{"."};
    for (given) |p| {
        const abs = std.Io.Dir.cwd().realPathFileAlloc(app.io, p, arena.allocator()) catch |e| {
            try app.err.print("zav: {s}: {t}\n", .{ p, e });
            return 2;
        };
        try paths.append(arena.allocator(), abs);
    }
    const only: []const []const u8 = if (flag(ctx, "installed")) &.{ "vulnerability.paths", "vulnerability.packages" } else &.{"vulnerability.paths"};
    var pantry_buf: [std.fs.max_path_bytes]u8 = undefined;
    var pantry_roots: [1][]const u8 = undefined;
    var pantry_n: usize = 0;
    if (std.c.getenv("HOME")) |home| {
        pantry_roots[0] = std.fmt.bufPrint(&pantry_buf, "{s}/.local/share/pantry/global/packages", .{std.mem.span(home)}) catch "";
        pantry_n = 1;
    }
    var s = zav.host.Scan.init(app.gpa, h, .{ .only = only, .min_severity = min, .audit_paths = paths.items, .cve_index = &index, .pantry_roots = pantry_roots[0..pantry_n] });
    defer s.deinit();
    s.runChecks(&all_checks) catch |e| {
        try app.err.print("zav: audit failed: {t}\n", .{e});
        return 2;
    };
    return emit(ctx, &s);
}

// CVE feeds ------------------------------------------------------------------------------------

fn feedsDir(ctx: *Command.ParseContext, buf: []u8) !std.Io.Dir {
    var state_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = ctx.getOption("feeds") orelse try std.fmt.bufPrint(buf, "{s}/feeds", .{try stateDir(ctx, &state_buf)});
    return openState(path) orelse {
        try app.err.print("zav: cannot create {s}\n", .{path});
        return error.NoFeedsDir;
    };
}

fn cveFetchAction(ctx: *Command.ParseContext) !u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var dir = feedsDir(ctx, &buf) catch return 2;
    defer dir.close(app.io);
    var http = zav.cve.feeds.HttpFetcher.init(app.gpa, app.io);
    defer http.deinit();
    const f = http.fetcher();
    const now = @divFloor(std.Io.Clock.real.now(app.io).toNanoseconds(), std.time.ns_per_s);
    var failed = false;

    const kev = zav.cve.feeds.fetchFile(app.gpa, app.io, dir, f, zav.cve.feeds.kev_url, "kev/known_exploited_vulnerabilities.json", @intCast(now));
    if (kev) |n| try app.out.print("kev: {d} bytes\n", .{n}) else |e| {
        try app.err.print("zav: KEV: {t}\n", .{e});
        failed = true;
    }
    const default_osv = [_][]const u8{ "npm", "PyPI", "Go", "crates.io" };
    const ecos = if (ctx.getOptionValues("osv").len > 0) ctx.getOptionValues("osv") else &default_osv;
    for (ecos) |eco| {
        var url_buf: [256]u8 = undefined;
        var name_buf: [256]u8 = undefined;
        var enc: std.ArrayList(u8) = .empty;
        defer enc.deinit(app.gpa);
        for (eco) |c| if (c == ' ') try enc.appendSlice(app.gpa, "%20") else try enc.append(app.gpa, c);
        const url = try std.fmt.bufPrint(&url_buf, "{s}/{s}/all.zip", .{ zav.cve.feeds.osv_url, enc.items });
        const name = try std.fmt.bufPrint(&name_buf, "osv/{s}/all.zip", .{eco});
        if (zav.cve.feeds.fetchFile(app.gpa, app.io, dir, f, url, name, @intCast(now))) |n| try app.out.print("osv {s}: {d} bytes\n", .{ eco, n }) else |e| {
            try app.err.print("zav: OSV {s}: {t}\n", .{ eco, e });
            failed = true;
        }
    }
    if (flag(ctx, "nvd")) {
        try dir.createDirPath(app.io, "nvd");
        var nvd = try dir.openDir(app.io, "nvd", .{});
        defer nvd.close(app.io);
        const key = if (std.c.getenv("NVD_API_KEY")) |k| std.mem.span(k) else null;
        if (zav.cve.feeds.syncNvd(app.gpa, app.io, nvd, f, .{ .api_key = key, .now = @intCast(now) })) |r| {
            try app.out.print("nvd: {d} pages, {d} CVEs, synced until {d}\n", .{ r.pages, r.cves, r.state.synced_until });
        } else |e| {
            try app.err.print("zav: NVD: {t} (progress is saved; run again to resume)\n", .{e});
            failed = true;
        }
    }
    return if (failed) 2 else 0;
}

fn cveCompileAction(ctx: *Command.ParseContext) !u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var dir = feedsDir(ctx, &buf) catch return 2;
    defer dir.close(app.io);
    // Load the key before reading the feeds, so a bad key fails at once.
    var key_pair: ?std.crypto.sign.Ed25519.KeyPair = null;
    defer if (key_pair) |*kp| std.crypto.secureZero(u8, std.mem.asBytes(kp));
    if (ctx.getOption("signing-key")) |key_path| key_pair = loadSigningKey(key_path) catch |e| {
        try app.err.print("zav: --signing-key {s}: {t} (expected a file of exactly 32 raw bytes)\n", .{ key_path, e });
        return 2;
    };
    var b = zav.cve.index.Builder.init(app.gpa);
    defer b.deinit();
    b.addFeedsDir(app.io, dir) catch |e| {
        try app.err.print("zav: reading feeds: {t}\n", .{e});
        return 2;
    };
    var state_buf: [std.fs.max_path_bytes]u8 = undefined;
    var out_buf: [std.fs.max_path_bytes]u8 = undefined;
    const out = ctx.getOption("out") orelse try std.fmt.bufPrint(&out_buf, "{s}/cve.zavcve", .{stateDir(ctx, &state_buf) catch "."});
    const now: u64 = @intCast(@divFloor(std.Io.Clock.real.now(app.io).toNanoseconds(), std.time.ns_per_s));
    const summary = b.write(app.io, std.Io.Dir.cwd(), out, .{ .db_version = now, .build_unix_time = now, .key_pair = key_pair }) catch |e| {
        try app.err.print("zav: writing {s}: {t}\n", .{ out, e });
        return 2;
    };
    if (ctx.wantsJson()) {
        try ctx.writeJson(.{ .out = out, .records = summary.records, .kev = summary.kev, .packages = summary.packages, .cpes = summary.cpes, .ranges = summary.ranges, .signed = key_pair != null });
    } else try app.out.print("{s}: {d} vulnerabilities ({d} in KEV), {d} packages, {d} CPEs, {d} ranges, {s}\n", .{ out, summary.records, summary.kev, summary.packages, summary.cpes, summary.ranges, if (key_pair != null) "signed" else "unsigned" });
    return 0;
}
