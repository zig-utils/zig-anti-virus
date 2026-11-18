//! `zav`: compile signature databases, inspect them, and scan files.
//!
//!   zav compile [--out FILE] [--allow-unverified] [--no-builtin] [--malwarebazaar CSV] SOURCE...
//!   zav info DB
//!   zav coverage DB
//!   zav scan [--db FILE] [--json] PATH...
//!
//! Exit codes follow clamscan: 0 clean, 1 something found, 2 an error. Databases are opened with
//! signature checks; `--allow-unsigned` (or ZAV_ALLOW_UNSIGNED=1) accepts locally compiled,
//! unsigned databases.
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
    _ = try compile.addArgument(Argument.init("sources", "CVD/CLD containers and signature files", .string).withVariadic(true).withRequired(false));
    _ = compile.setActionWithCode(compileAction);
    _ = try root.addCommand(compile);

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

    const scan = try Command.init(gpa, "scan", "Scan files");
    _ = try scan.addOption(Option.init("db", "db", "Database to scan with", .string));
    _ = try scan.addOption(Option.init("allow-unsigned", "allow-unsigned", "Accept an unsigned database", .bool));
    _ = try scan.addArgument(Argument.init("paths", "Files to scan", .string).withVariadic(true));
    _ = scan.setActionWithCode(scanAction);
    _ = try root.addCommand(scan);
    return root;
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
    var compiler = zav.compile.compiler.Compiler.init(app.gpa);
    defer compiler.deinit();
    if (!flag(ctx, "no-builtin")) try compiler.addBuiltin();

    const cwd = std.Io.Dir.cwd();
    for (ctx.arguments.items) |path| {
        const ext = std.fs.path.extension(path);
        if (std.mem.eql(u8, ext, ".cvd") or std.mem.eql(u8, ext, ".cld")) {
            const kind: zav.compile.cvd.Kind = if (std.mem.eql(u8, ext, ".cld")) .cld else .cvd;
            _ = compiler.addContainer(app.io, cwd, path, .{ .kind = kind, .allow_unverified = flag(ctx, "allow-unverified") }) catch |e| {
                try app.err.print("zav: {s}: {t}\n", .{ path, e });
                return 2;
            };
        } else {
            const text = cwd.readFileAlloc(app.io, path, app.gpa, .limited(512 * 1024 * 1024)) catch |e| {
                try app.err.print("zav: {s}: {t}\n", .{ path, e });
                return 2;
            };
            defer app.gpa.free(text);
            try compiler.addFile(std.fs.path.basename(path), text);
        }
    }
    for (ctx.getOptionValues("malwarebazaar")) |path| {
        const text = try cwd.readFileAlloc(app.io, path, app.gpa, .limited(2 * 1024 * 1024 * 1024));
        defer app.gpa.free(text);
        try compiler.addMalwareBazaar(std.fs.path.basename(path), text, 0);
    }

    var nonce: [8]u8 = undefined;
    app.io.random(&nonce);
    const summary = try compiler.write(app.io, cwd, out_path, .{ .db_version = std.mem.readInt(u64, &nonce, .little) >> 1 });
    if (ctx.wantsJson()) {
        try ctx.writeJson(.{ .out = out_path, .signatures = summary.signatures, .hash_rules = summary.hash_rules, .allowlist_rules = summary.allowlist_rules, .duplicates = summary.duplicates });
    } else {
        try app.out.print("{s}: {d} signatures, {d} hash rules, {d} allowlist entries, {d} duplicates dropped\n", .{ out_path, summary.signatures, summary.hash_rules, summary.allowlist_rules, summary.duplicates });
    }
    return 0;
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
    const block = try scratch.allocator().alloc(u8, 256 * 1024);
    var tracker = zav.engine.limits.Tracker.init(.{});
    var name_buf: [512]u8 = undefined;
    var found = false;
    var failed = false;

    for (ctx.arguments.items) |path| {
        tracker.reset();
        const file = std.Io.Dir.cwd().openFile(app.io, path, .{}) catch |e| {
            try app.out.print("{s}: {t} ERROR\n", .{ path, e });
            failed = true;
            continue;
        };
        defer file.close(app.io);
        const size = (try file.stat(app.io)).size;
        const verdict = zav.engine.hashscan.scanSource(app.io, &index, .{ .file = .{ .file = file, .len = size } }, &tracker, block) catch |e| {
            try app.out.print("{s}: {t} ERROR\n", .{ path, e });
            failed = true;
            continue;
        };
        switch (verdict) {
            .clean, .allowed => try report(ctx, path, "OK", null),
            .infected => |sig| {
                found = true;
                const name = if (index.meta) |m| try m.name(sig, &name_buf) else "unknown";
                try report(ctx, path, "FOUND", name);
            },
            .limited => |event| {
                var event_buf: [64]u8 = undefined;
                try report(ctx, path, "LIMITED", try std.fmt.bufPrint(&event_buf, "{t}", .{event}));
            },
        }
    }
    if (failed) return 2;
    return if (found) 1 else 0;
}

fn report(ctx: *Command.ParseContext, path: []const u8, status: []const u8, detail: ?[]const u8) !void {
    if (ctx.wantsJson()) {
        try ctx.writeJson(.{ .path = path, .status = status, .detail = detail });
    } else if (detail) |d| {
        // clamscan's line format, so existing tooling can parse it.
        if (std.mem.eql(u8, status, "FOUND")) try app.out.print("{s}: {s} FOUND\n", .{ path, d }) else try app.out.print("{s}: {s} ({s})\n", .{ path, status, d });
    } else try app.out.print("{s}: {s}\n", .{ path, status });
}
