//! MalwareBazaar (abuse.ch) CSV exports as SHA-256 hash rules. Opt-in: the feed needs an abuse.ch
//! auth key and its terms allow not-for-profit use only, so nothing fetches it by default.
//!
//! Columns are found by name from the header line (`sha256_hash`, `signature`, and `file_size`
//! when an export carries it), so a reordered or extended export still parses. Lines starting with
//! `#` are comments; fields may be double-quoted with `""` escapes.
//!
//! Exports without a size column produce any-size rules, which force SHA-256 over every scanned
//! file. That cost is the reason the feed is off by default; the coverage report and `zav info`
//! show when it is on.
const std = @import("std");
const ir = @import("ir.zig");

pub const Error = error{ MissingHeader, MissingSha256Column };

/// Rule names are `MalwareBazaar.<signature>`, or `MalwareBazaar.Unknown` when the sample has none.
/// Names are allocated from `arena` because they are built, not borrowed.
pub fn parse(gpa: std.mem.Allocator, arena: std.mem.Allocator, source_name: []const u8, text: []const u8, rules: *std.ArrayList(ir.HashRule), rejected: *std.ArrayList(ir.Rejection)) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_number: u32 = 0;
    var columns: ?Columns = null;
    var fields: [32][]const u8 = undefined;
    var scratch: [4096]u8 = undefined;

    while (lines.next()) |raw| {
        line_number += 1;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        // abuse.ch writes the header as a comment line starting with `# "first_seen_utc",...`.
        const is_comment = line[0] == '#';
        const content = if (is_comment) std.mem.trimStart(u8, line[1..], " ") else line;
        if (columns == null) {
            if (std.mem.indexOf(u8, content, "sha256_hash") == null) continue;
            const n = splitCsv(content, &fields, &scratch) orelse return error.MissingHeader;
            columns = try Columns.find(fields[0..n]);
            continue;
        }
        if (is_comment) continue;
        const cols = columns.?;
        const n = splitCsv(content, &fields, &scratch) orelse {
            try rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = .field_count });
            continue;
        };
        if (cols.sha256 >= n) {
            try rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = .field_count });
            continue;
        }
        const hex = std.mem.trim(u8, fields[cols.sha256], " ");
        var digest: [32]u8 = undefined;
        if (hex.len != 64) {
            try rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = .bad_hash });
            continue;
        }
        _ = std.fmt.hexToBytes(&digest, hex) catch {
            try rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = .bad_hash });
            continue;
        };
        const size: ?u64 = if (cols.size) |c| (if (c < n) std.fmt.parseInt(u64, std.mem.trim(u8, fields[c], " "), 10) catch null else null) else null;
        const family = if (cols.signature) |c| (if (c < n) cleanName(fields[c]) else "") else "";
        const name = try std.fmt.allocPrint(arena, "MalwareBazaar.{s}", .{if (family.len == 0) "Unknown" else family});
        try rules.append(gpa, .{
            .algo = .sha256,
            .scope = .file,
            .digest = digest,
            .size = size,
            .name = name,
            // Any-size rules carry the level ClamAV requires for wildcard sizes.
            .flevel_min = if (size == null) 73 else 0,
            .source = .malwarebazaar,
        });
    }
    if (columns == null) return error.MissingHeader;
}

const Columns = struct {
    sha256: usize,
    signature: ?usize,
    size: ?usize,

    fn find(names: []const []const u8) Error!Columns {
        var c: Columns = .{ .sha256 = undefined, .signature = null, .size = null };
        var have_sha = false;
        for (names, 0..) |raw, i| {
            const name = std.mem.trim(u8, raw, " ");
            if (std.mem.eql(u8, name, "sha256_hash")) {
                c.sha256 = i;
                have_sha = true;
            } else if (std.mem.eql(u8, name, "signature")) {
                c.signature = i;
            } else if (std.mem.eql(u8, name, "file_size")) {
                c.size = i;
            }
        }
        if (!have_sha) return error.MissingSha256Column;
        return c;
    }
};

/// Keep a signature family usable inside a ClamAV-style name: letters, digits, `.`, `_`, `-`.
fn cleanName(raw: []const u8) []const u8 {
    const name = std.mem.trim(u8, raw, " ");
    if (std.mem.eql(u8, name, "n/a")) return "";
    for (name) |ch| {
        if (!(std.ascii.isAlphanumeric(ch) or ch == '.' or ch == '_' or ch == '-')) return "";
    }
    return name;
}

/// Split one CSV line. Quoted fields are unescaped into `scratch`. Returns the field count, or
/// null if the line is malformed or does not fit.
fn splitCsv(line: []const u8, fields: [][]const u8, scratch: []u8) ?usize {
    var count: usize = 0;
    var used: usize = 0;
    var i: usize = 0;
    while (true) {
        if (count == fields.len) return null;
        // abuse.ch separates fields with ", ".
        while (i < line.len and line[i] == ' ') i += 1;
        if (i < line.len and line[i] == '"') {
            i += 1;
            const start = used;
            while (true) {
                if (i >= line.len) return null;
                if (line[i] == '"') {
                    if (i + 1 < line.len and line[i + 1] == '"') {
                        if (used == scratch.len) return null;
                        scratch[used] = '"';
                        used += 1;
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                if (used == scratch.len) return null;
                scratch[used] = line[i];
                used += 1;
                i += 1;
            }
            fields[count] = scratch[start..used];
            while (i < line.len and line[i] == ' ') i += 1;
        } else {
            const start = i;
            while (i < line.len and line[i] != ',') i += 1;
            fields[count] = line[start..i];
        }
        count += 1;
        if (i >= line.len) return count;
        if (line[i] != ',') return null;
        i += 1;
    }
}

test "parses a MalwareBazaar export with a commented header" {
    const gpa = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var rules: std.ArrayList(ir.HashRule) = .empty;
    defer rules.deinit(gpa);
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    defer rejected.deinit(gpa);
    const text =
        \\################################################################
        \\# MalwareBazaar full data dump (CSV)
        \\# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent"
        \\"2026-11-01 10:00:00", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "44d88612fea8a8f36de82e1278abb02f", "3395856ce81f2b7382dee72602f798b642f14140", "someone", "eicar.com", "com", "text/plain", "AgentTesla", "n/a", "90"
        \\"2026-11-01 10:00:01", "aa", "", "", "someone", "x", "exe", "application/x-dosexec", "n/a", "n/a", "1"
        \\"2026-11-01 10:00:02", "1111111111111111111111111111111111111111111111111111111111111111", "", "", "a", "say ""hi"".exe", "exe", "x", "n/a", "n/a", "2"
        \\
    ;
    try parse(gpa, arena.allocator(), "full.csv", text, &rules, &rejected);
    try std.testing.expectEqual(@as(usize, 2), rules.items.len);
    try std.testing.expectEqualStrings("MalwareBazaar.AgentTesla", rules.items[0].name);
    try std.testing.expectEqual(@as(?u64, null), rules.items[0].size);
    try std.testing.expectEqual(@as(u16, 73), rules.items[0].flevel_min);
    try std.testing.expectEqualStrings("MalwareBazaar.Unknown", rules.items[1].name);
    try std.testing.expectEqual(@as(usize, 1), rejected.items.len);
    try std.testing.expectEqual(ir.Reason.bad_hash, rejected.items[0].reason);
}

test "uses a size column when the export has one" {
    const gpa = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var rules: std.ArrayList(ir.HashRule) = .empty;
    defer rules.deinit(gpa);
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    defer rejected.deinit(gpa);
    try parse(gpa, arena.allocator(), "x.csv", "sha256_hash,file_size,signature\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,68,Eicar\n", &rules, &rejected);
    try std.testing.expectEqual(@as(?u64, 68), rules.items[0].size);
    try std.testing.expectEqual(@as(u16, 0), rules.items[0].flevel_min);
}

test "refuses input without a sha256 column" {
    const gpa = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var rules: std.ArrayList(ir.HashRule) = .empty;
    defer rules.deinit(gpa);
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    defer rejected.deinit(gpa);
    try std.testing.expectError(error.MissingHeader, parse(gpa, arena.allocator(), "x.csv", "md5,name\nabc,def\n", &rules, &rejected));
}
