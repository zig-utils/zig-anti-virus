//! Human-readable report: findings grouped by severity, highest first, each with its
//! remediation line, then suppressed and disabled checks and reduced coverage.
const std = @import("std");
const scan = @import("scan.zig");
const finding = @import("finding.zig");

pub fn writeText(s: *const scan.Scan, w: *std.Io.Writer) !void {
    const points = s.score();
    try w.print("zav {s}: {s} {s}, score {d}/100 ({t}), {d} findings\n", .{
        if (s.options.audit_paths.len > 0) "audit" else "host",
        @tagName(s.host.os),
        @tagName(s.context.role),
        points,
        finding.Label.of(points),
        s.findings.items.len,
    });
    var sev: i8 = @backingInt(finding.Severity.critical);
    while (sev >= 0) : (sev -= 1) {
        const level: finding.Severity = @fromBackingInt(@intCast(sev));
        var header = false;
        for (s.findings.items) |f| {
            if (f.severity != level) continue;
            if (!header) {
                try w.print("\n{s}\n", .{upper(level)});
                header = true;
            }
            try w.print("  [{s}] {s}\n", .{ f.check, f.title });
            if (f.subject) |subj| try w.print("    subject: {s}\n", .{subj});
            if (f.pid) |p| try w.print("    pid: {d}\n", .{p});
            if (f.cve.len > 0) {
                try w.writeAll("    cve:");
                for (f.cve) |c| try w.print(" {s}", .{c});
                try w.writeByte('\n');
            }
            try w.print("    {s}\n", .{f.description});
            if (f.downgraded) |d| try w.print("    (downgraded from {t}: {s})\n", .{ d.from, d.reason });
            try w.print("    fix: {s}\n", .{f.remediation});
        }
    }
    if (s.suppressed.items.len > 0) {
        try w.print("\nSUPPRESSED ({d})\n", .{s.suppressed.items.len});
        for (s.suppressed.items) |x| try w.print("  [{s}] {s}: {s}\n", .{ x.finding.check, x.finding.title, x.reason });
    }
    if (s.disabled.items.len > 0) {
        try w.writeAll("\nDISABLED\n");
        for (s.disabled.items) |d| try w.print("  [{s}] {s}\n", .{ d.check, d.reason });
    }
    if (s.coverage.items.len > 0) {
        try w.writeAll("\nREDUCED COVERAGE\n");
        for (s.coverage.items) |c| try w.print("  [{s}] {s}\n", .{ c.check, c.reason });
    }
}

fn upper(s: finding.Severity) []const u8 {
    return switch (s) {
        .critical => "CRITICAL",
        .high => "HIGH",
        .medium => "MEDIUM",
        .low => "LOW",
        .info => "INFO",
    };
}

test "text report groups by severity with remediation lines" {
    const host_mod = @import("host.zig");
    var fx = try host_mod.Fixture.init();
    defer fx.deinit();
    var s = scan.Scan.init(std.testing.allocator, fx.host(.linux), .{ .context = .{ .role = .server } });
    defer s.deinit();
    s.current = "process.miner";
    try s.add(.{ .severity = .critical, .category = .malware, .title = "Cryptominer running", .description = "xmrig", .remediation = "kill it", .subject = "/dev/shm/x", .pid = 7 });
    s.current = "hardening.mac";
    try s.add(.{ .severity = .medium, .category = .hardening, .title = "No MAC", .description = "none", .remediation = "enable AppArmor" });
    try s.finalize();
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeText(&s, &out.writer);
    const text = out.written();
    const crit = std.mem.indexOf(u8, text, "CRITICAL").?;
    const med = std.mem.indexOf(u8, text, "MEDIUM").?;
    try std.testing.expect(crit < med);
    try std.testing.expect(std.mem.indexOf(u8, text, "fix: kill it") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "score 65/100") != null);
}
