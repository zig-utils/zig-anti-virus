//! The host finding model: typed severities and categories, remediation text, CVE links, a 0 to
//! 100 score and the exit code a run ends with.
//!
//! linux-guardian used free-form strings for severity and category, so filters and dashboards had
//! to guess spellings. Here both are enums and the JSON output names them by tag; the committed
//! schema (`report.schema.json`) lists every allowed value and a test validates real output
//! against it.
const std = @import("std");

pub const Severity = enum(u8) {
    info,
    low,
    medium,
    high,
    critical,

    /// Points one finding takes off the 100-point score.
    pub fn penalty(s: Severity) u8 {
        return switch (s) {
            .info => 0,
            .low => 2,
            .medium => 5,
            .high => 15,
            .critical => 30,
        };
    }

    pub fn parse(text: []const u8) ?Severity {
        return std.meta.stringToEnum(Severity, text);
    }

    pub fn atLeast(s: Severity, min: Severity) bool {
        return @backingInt(s) >= @backingInt(min);
    }

    pub fn max(a: Severity, b: Severity) Severity {
        return if (@backingInt(a) >= @backingInt(b)) a else b;
    }
};

pub const Category = enum {
    /// Known or behaviourally obvious malware: miners, fileless code, reverse shells.
    malware,
    /// Suspicious process state that is not malware by itself.
    process,
    network,
    kernel,
    boot,
    persistence,
    /// Remote access: SSH keys, sshd configuration, brute force.
    access,
    credential,
    privilege,
    hardening,
    container,
    /// Package file integrity.
    integrity,
    vulnerability,

    pub fn parse(text: []const u8) ?Category {
        return std.meta.stringToEnum(Category, text);
    }
};

/// Fast checks finish in seconds and are safe to run often. Deep checks hash files, walk large
/// trees or probe every pid.
pub const Tier = enum {
    fast,
    deep,

    pub fn includes(run_tier: Tier, check_tier: Tier) bool {
        return @backingInt(check_tier) <= @backingInt(run_tier);
    }
};

/// What a check needs to see everything it looks at. `partial` checks run unprivileged and
/// report the parts they could not read as reduced coverage.
pub const Privilege = enum { none, partial, root };

pub const Detail = struct {
    key: []const u8,
    value: []const u8,
};

/// A severity lowered by server context, kept so the output shows what changed and why.
pub const Downgrade = struct {
    from: Severity,
    reason: []const u8,
};

pub const Finding = struct {
    /// Stable check identifier, for example `process.miner`. Filled in by the runner when a
    /// check leaves it empty.
    check: []const u8 = "",
    severity: Severity,
    category: Category,
    title: []const u8,
    description: []const u8,
    remediation: []const u8,
    cve: []const []const u8 = &.{},
    /// What the finding is about: a path, or for processes the executable path. Suppression path
    /// patterns match against it.
    subject: ?[]const u8 = null,
    pid: ?u32 = null,
    details: []const Detail = &.{},
    downgraded: ?Downgrade = null,
};

/// A part of a check that did not run or could not see everything, with the reason.
pub const Coverage = struct {
    check: []const u8,
    reason: []const u8,
};

pub const Label = enum {
    excellent,
    good,
    fair,
    poor,
    critical,

    pub fn of(points: u8) Label {
        if (points >= 90) return .excellent;
        if (points >= 75) return .good;
        if (points >= 50) return .fair;
        if (points >= 25) return .poor;
        return .critical;
    }
};

/// Starts at 100 and subtracts each finding's penalty, floored at 0.
pub fn score(findings: []const Finding) u8 {
    var points: u32 = 100;
    for (findings) |f| points -|= f.severity.penalty();
    return @intCast(points);
}

pub fn highest(findings: []const Finding) ?Severity {
    var top: ?Severity = null;
    for (findings) |f| top = if (top) |t| t.max(f.severity) else f.severity;
    return top;
}

/// Exit code for a run: 0 when nothing at low or above was found, 2 for an error (the same code
/// `zav scan` uses), and 10 plus the severity rank otherwise: 11 low, 12 medium, 13 high,
/// 14 critical. Info findings never fail a run.
pub const exit_clean: u8 = 0;
pub const exit_error: u8 = 2;
pub const exit_findings_base: u8 = 10;

pub fn exitCode(findings: []const Finding) u8 {
    const top = highest(findings) orelse return exit_clean;
    if (top == .info) return exit_clean;
    return exitCodeFor(top);
}

pub fn exitCodeFor(severity: Severity) u8 {
    if (severity == .info) return exit_clean;
    return exit_findings_base + @backingInt(severity);
}

/// One finding as a JSON object. `details` becomes an object of strings.
pub fn writeFinding(jw: *std.json.Stringify, f: Finding) !void {
    try jw.beginObject();
    try jw.objectField("check");
    try jw.write(f.check);
    try jw.objectField("severity");
    try jw.write(@tagName(f.severity));
    try jw.objectField("category");
    try jw.write(@tagName(f.category));
    try jw.objectField("title");
    try jw.write(f.title);
    try jw.objectField("description");
    try jw.write(f.description);
    try jw.objectField("remediation");
    try jw.write(f.remediation);
    try jw.objectField("cve");
    try jw.write(f.cve);
    if (f.subject) |s| {
        try jw.objectField("subject");
        try jw.write(s);
    }
    if (f.pid) |p| {
        try jw.objectField("pid");
        try jw.write(p);
    }
    try jw.objectField("details");
    try jw.beginObject();
    for (f.details) |d| {
        try jw.objectField(d.key);
        try jw.write(d.value);
    }
    try jw.endObject();
    if (f.downgraded) |d| {
        try jw.objectField("downgraded");
        try jw.beginObject();
        try jw.objectField("from");
        try jw.write(@tagName(d.from));
        try jw.objectField("reason");
        try jw.write(d.reason);
        try jw.endObject();
    }
    try jw.endObject();
}

test "score subtracts per severity and floors at zero" {
    const f = struct {
        fn mk(s: Severity) Finding {
            return .{ .severity = s, .category = .process, .title = "", .description = "", .remediation = "" };
        }
    }.mk;
    try std.testing.expectEqual(@as(u8, 100), score(&.{}));
    try std.testing.expectEqual(@as(u8, 100), score(&.{f(.info)}));
    try std.testing.expectEqual(@as(u8, 80), score(&.{ f(.high), f(.medium) }));
    try std.testing.expectEqual(@as(u8, 0), score(&.{ f(.critical), f(.critical), f(.critical), f(.critical) }));
    try std.testing.expectEqual(Label.excellent, Label.of(95));
    try std.testing.expectEqual(Label.good, Label.of(80));
    try std.testing.expectEqual(Label.fair, Label.of(50));
    try std.testing.expectEqual(Label.poor, Label.of(25));
    try std.testing.expectEqual(Label.critical, Label.of(24));
}

test "exit codes follow the highest severity" {
    const f = struct {
        fn mk(s: Severity) Finding {
            return .{ .severity = s, .category = .process, .title = "", .description = "", .remediation = "" };
        }
    }.mk;
    try std.testing.expectEqual(@as(u8, 0), exitCode(&.{}));
    try std.testing.expectEqual(@as(u8, 0), exitCode(&.{f(.info)}));
    try std.testing.expectEqual(@as(u8, 11), exitCode(&.{ f(.info), f(.low) }));
    try std.testing.expectEqual(@as(u8, 12), exitCode(&.{f(.medium)}));
    try std.testing.expectEqual(@as(u8, 13), exitCode(&.{ f(.high), f(.low) }));
    try std.testing.expectEqual(@as(u8, 14), exitCode(&.{ f(.medium), f(.critical), f(.high) }));
}
