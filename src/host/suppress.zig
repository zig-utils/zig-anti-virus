//! Suppression config: turn checks off, or silence a check for matching subjects, always with a
//! written reason. The file is JSON:
//!
//! ```json
//! { "suppress": [
//!     { "check": "process.temp_exec", "path": "/tmp/ci-build-*", "reason": "CI runs builds from /tmp" },
//!     { "check": "hardening.disk_encryption", "reason": "encrypted at the SAN" },
//!     { "check": "kernel.*", "reason": "kernel managed by the hosting provider" }
//! ] }
//! ```
//!
//! An entry without `path` turns the check off: it does not run and the report lists it as
//! disabled. An entry with `path` keeps the check running and moves matching findings to the
//! report's `suppressed` list, so nothing disappears silently. `check` is an exact id or a dotted
//! prefix ending in `.*`; `path` is a glob where `*` matches any run of characters (including
//! `/`) and `?` matches one. Entries without a reason are rejected.
const std = @import("std");
const finding = @import("finding.zig");

pub const Entry = struct {
    check: []const u8,
    path: ?[]const u8 = null,
    reason: []const u8,
};

pub const Error = error{ MissingReason, MissingCheck, TooManyEntries, InvalidConfig };

pub const max_entries = 4096;

pub const Config = struct {
    entries: []const Entry = &.{},
    parsed: ?std.json.Parsed(File) = null,

    pub const File = struct { suppress: []const Entry = &.{} };

    pub fn deinit(c: *Config) void {
        if (c.parsed) |*p| p.deinit();
        c.* = .{};
    }

    /// Parse a config. Strings borrow from the parse arena, released by `deinit`.
    pub fn parse(gpa: std.mem.Allocator, text: []const u8) (Error || std.mem.Allocator.Error)!Config {
        const parsed = std.json.parseFromSlice(File, gpa, text, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidConfig,
        };
        errdefer parsed.deinit();
        if (parsed.value.suppress.len > max_entries) return error.TooManyEntries;
        for (parsed.value.suppress) |e| {
            if (std.mem.trim(u8, e.reason, " \t").len == 0) return error.MissingReason;
            if (e.check.len == 0) return error.MissingCheck;
        }
        return .{ .entries = parsed.value.suppress, .parsed = parsed };
    }

    /// The entry that turns a check off entirely, if any.
    pub fn disables(c: Config, check: []const u8) ?Entry {
        for (c.entries) |e| if (e.path == null and checkMatches(e.check, check)) return e;
        return null;
    }

    /// The entry that suppresses this finding, if any.
    pub fn suppresses(c: Config, f: finding.Finding) ?Entry {
        for (c.entries) |e| {
            if (!checkMatches(e.check, f.check)) continue;
            const pattern = e.path orelse return e;
            const subject = f.subject orelse continue;
            if (glob(pattern, subject)) return e;
        }
        return null;
    }
};

pub fn checkMatches(pattern: []const u8, check: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (std.mem.endsWith(u8, pattern, ".*")) {
        const prefix = pattern[0 .. pattern.len - 1]; // keeps the dot
        return std.mem.startsWith(u8, check, prefix) or std.mem.eql(u8, check, pattern[0 .. pattern.len - 2]);
    }
    return std.mem.eql(u8, pattern, check);
}

/// Glob with `*` (any run, including `/`) and `?` (one byte). Iterative with one backtrack
/// point, so it is linear in practice and never recursive.
pub fn glob(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == text[t])) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            mark = t;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

test "glob" {
    try std.testing.expect(glob("/tmp/ci-*", "/tmp/ci-build-1/run"));
    try std.testing.expect(glob("*", ""));
    try std.testing.expect(glob("/opt/?pp/bin", "/opt/app/bin"));
    try std.testing.expect(!glob("/opt/?pp/bin", "/opt/apps/bin"));
    try std.testing.expect(glob("*.so", "/usr/lib/libx.so"));
    try std.testing.expect(!glob("*.so", "/usr/lib/libx.so.1"));
    try std.testing.expect(glob("a*b*c", "aXXbYYc"));
    try std.testing.expect(!glob("a*b*c", "aXXbYY"));
}

test "suppressions by check id and path, with required reasons" {
    const gpa = std.testing.allocator;
    var c = try Config.parse(gpa,
        \\{ "suppress": [
        \\  { "check": "process.temp_exec", "path": "/tmp/ci-*", "reason": "CI builds" },
        \\  { "check": "hardening.disk_encryption", "reason": "SAN encryption" },
        \\  { "check": "kernel.*", "reason": "provider kernel" }
        \\] }
    );
    defer c.deinit();
    const mk = struct {
        fn f(check: []const u8, subject: ?[]const u8) finding.Finding {
            return .{ .check = check, .severity = .high, .category = .process, .title = "", .description = "", .remediation = "", .subject = subject };
        }
    }.f;
    try std.testing.expect(c.suppresses(mk("process.temp_exec", "/tmp/ci-42/node")) != null);
    try std.testing.expect(c.suppresses(mk("process.temp_exec", "/tmp/other")) == null);
    try std.testing.expect(c.suppresses(mk("process.temp_exec", null)) == null);
    try std.testing.expect(c.suppresses(mk("process.miner", "/tmp/ci-1")) == null);
    try std.testing.expect(c.disables("hardening.disk_encryption") != null);
    try std.testing.expect(c.disables("kernel.modules") != null);
    try std.testing.expect(c.disables("kernel") != null);
    try std.testing.expect(c.disables("kernelx.y") == null);
    try std.testing.expect(c.disables("process.temp_exec") == null);

    try std.testing.expectError(error.MissingReason, Config.parse(gpa,
        \\{ "suppress": [ { "check": "process.miner", "reason": "  " } ] }
    ));
    try std.testing.expectError(error.InvalidConfig, Config.parse(gpa,
        \\{ "suppress": [ { "check": "process.miner" } ] }
    ));
    try std.testing.expectError(error.InvalidConfig, Config.parse(gpa, "not json"));
}
