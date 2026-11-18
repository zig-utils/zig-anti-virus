//! Compile-time filtering: `.ign2` ignore lists, functionality levels, and allowlists.
//!
//! Ignoring happens here so it costs nothing at scan time. An `.ign2` line is either a signature
//! name, or `name:md5` where the MD5 is of the whole database line; the second form stops
//! applying as soon as the signature is changed upstream, so a fixed signature is not silently
//! ignored forever. Allowlists (`.fp`, `.sfp`) use the hash database line formats and are kept
//! as full-digest tables consulted only after a detection; their digests are never truncated.
const std = @import("std");
const ir = @import("ir.zig");
const hashsig = @import("hashsig.zig");

/// The functionality level this engine implements for the formats it supports. Rules that need a
/// newer engine (`flevel_min` above it) or are retired before it (`flevel_max` below it) are skipped
/// and counted. Reviewed against the ClamAV databases by the census (P3.02).
pub const engine_flevel: u16 = 220;

pub const IgnoreEntry = struct {
    name: []const u8,
    line_md5: ?[16]u8,
};

/// Parse an `.ign2` file. Slices borrow `text`.
pub fn parseIgnore(gpa: std.mem.Allocator, text: []const u8, out: *std.ArrayList(IgnoreEntry)) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r \t");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.lastIndexOfScalar(u8, line, ':')) |colon| {
            const hex = line[colon + 1 ..];
            if (hex.len == 32) {
                var md5: [16]u8 = undefined;
                if (std.fmt.hexToBytes(&md5, hex)) |_| {
                    try out.append(gpa, .{ .name = line[0..colon], .line_md5 = md5 });
                    continue;
                } else |_| {}
            }
        }
        try out.append(gpa, .{ .name = line, .line_md5 = null });
    }
}

pub const Ignore = struct {
    by_name: std.StringHashMapUnmanaged(?[16]u8) = .empty,

    pub fn init(gpa: std.mem.Allocator, entries: []const IgnoreEntry) !Ignore {
        var ignore: Ignore = .{};
        for (entries) |e| try ignore.by_name.put(gpa, e.name, e.line_md5);
        return ignore;
    }

    pub fn deinit(ignore: *Ignore, gpa: std.mem.Allocator) void {
        ignore.by_name.deinit(gpa);
    }

    pub fn matches(ignore: *const Ignore, name: []const u8, line: []const u8) bool {
        const entry = ignore.by_name.get(name) orelse return false;
        const pinned = entry orelse return true;
        var md5: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(line, &md5, .{});
        return std.mem.eql(u8, &md5, &pinned);
    }
};

/// Why a rule should be skipped, or null to keep it.
pub fn skipReason(rule: *const ir.HashRule, ignore: *const Ignore, flevel: u16) ?ir.Reason {
    if (ignore.matches(rule.name, rule.line)) return .ignored;
    if (rule.flevel_min != 0 and rule.flevel_min > flevel) return .flevel_out_of_range;
    if (rule.flevel_max != 0 and rule.flevel_max < flevel) return .flevel_out_of_range;
    return null;
}

/// Allowlist formats: `.fp` is the `.hdb` line format, `.sfp` the `.hsb` format.
pub fn allowlistFormat(extension: []const u8) ?hashsig.Format {
    if (std.mem.eql(u8, extension, "fp")) return hashsig.formatFor("hdb");
    if (std.mem.eql(u8, extension, "sfp")) return hashsig.formatFor("hsb");
    return null;
}

test "ign2 by name and by pinned line MD5" {
    const gpa = std.testing.allocator;
    var entries: std.ArrayList(IgnoreEntry) = .empty;
    defer entries.deinit(gpa);
    const line = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(line, &md5, .{});
    var text_buf: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&text_buf, "Win.Trojan.Fp-1-0\nEicar-Test-Signature:{x}\n", .{md5});
    try parseIgnore(gpa, text, &entries);
    var ignore = try Ignore.init(gpa, entries.items);
    defer ignore.deinit(gpa);

    try std.testing.expect(ignore.matches("Win.Trojan.Fp-1-0", "anything"));
    try std.testing.expect(ignore.matches("Eicar-Test-Signature", line));
    // The signature changed upstream: the pinned ignore no longer applies.
    try std.testing.expect(!ignore.matches("Eicar-Test-Signature", "44d88612fea8a8f36de82e1278abb02f:69:Eicar-Test-Signature"));
    try std.testing.expect(!ignore.matches("Other", line));
}

test "functionality-level filtering" {
    var ignore: Ignore = .{};
    var rule = try hashsig.parseLine(hashsig.formatFor("hsb").?, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:X:73");
    try std.testing.expectEqual(@as(?ir.Reason, null), skipReason(&rule, &ignore, engine_flevel));
    rule.flevel_min = engine_flevel + 1;
    try std.testing.expectEqual(@as(?ir.Reason, .flevel_out_of_range), skipReason(&rule, &ignore, engine_flevel));
    rule.flevel_min = 0;
    rule.flevel_max = 50;
    try std.testing.expectEqual(@as(?ir.Reason, .flevel_out_of_range), skipReason(&rule, &ignore, engine_flevel));
}
