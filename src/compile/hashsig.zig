//! Parsers for ClamAV hash databases, from ClamAV's signature documentation:
//!
//! - `.hdb`  `MD5:size:name` (whole file)
//! - `.hsb`  `hash:size:name`, MD5, SHA1 or SHA256 by hex length (whole file)
//! - `.mdb`  `size:MD5:name` (PE section; size and hash are reversed)
//! - `.msb`  `size:hash:name`, hash type by length (PE section)
//! - `.imp`  `MD5:size:name` (PE import table)
//!
//! Each may end with `:min_flevel[:max_flevel]`. A size of `*` means any size and is only valid
//! with a minimum functionality level of 73 or higher. The `u` variants (`.hdu`, `.hsu`, `.mdu`,
//! `.msu`, `.imu`) hold potentially unwanted applications and parse the same way. Every line that
//! does not become a rule is recorded with a reason.
const std = @import("std");
const ir = @import("ir.zig");

pub const Format = struct {
    source: ir.Source,
    scope: ir.HashScope,
    /// Fixed algorithm, or null to infer it from the hash length.
    algo: ?ir.HashAlgo,
    /// Field order `size:hash:name` instead of `hash:size:name`.
    size_first: bool,
    pua: bool,
};

/// The parse format for a database file extension (without the dot), or null if it is not a
/// hash database.
pub fn formatFor(extension: []const u8) ?Format {
    const Entry = struct { []const u8, ir.Source, ir.HashScope, ?ir.HashAlgo, bool };
    const table = [_]Entry{
        .{ "hdb", .hdb, .file, .md5, false },
        .{ "hsb", .hsb, .file, null, false },
        .{ "mdb", .mdb, .pe_section, .md5, true },
        .{ "msb", .msb, .pe_section, null, true },
        .{ "imp", .imp, .pe_import, .md5, false },
    };
    for (table) |e| {
        const base = e[0];
        const is_base = std.mem.eql(u8, extension, base);
        // PUA variant: last letter replaced by `u` (hdu, hsu, mdu, msu, imu).
        const is_pua = extension.len == 3 and std.mem.eql(u8, extension[0..2], base[0..2]) and extension[2] == 'u';
        if (is_base or is_pua) return .{ .source = e[1], .scope = e[2], .algo = e[3], .size_first = e[4], .pua = is_pua };
    }
    return null;
}

pub const Output = struct {
    rules: *std.ArrayList(ir.HashRule),
    rejected: *std.ArrayList(ir.Rejection),
};

/// Parse one hash database. `source_name` labels rejections (for example `main.hdb`).
pub fn parse(gpa: std.mem.Allocator, format: Format, source_name: []const u8, text: []const u8, out: Output) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_number: u32 = 0;
    while (lines.next()) |raw| {
        line_number += 1;
        const line = std.mem.trimEnd(u8, raw, "\r \t");
        if (line.len == 0 or line[0] == '#') continue;
        if (parseLine(format, line)) |rule| {
            try out.rules.append(gpa, rule);
        } else |reason| {
            try out.rejected.append(gpa, .{ .source_name = source_name, .line_number = line_number, .reason = reasonOf(reason) });
        }
    }
}

const LineError = error{ FieldCount, BadHash, BadSize, WildcardNeedsFlevel73, BadFlevel, EmptyName };

fn reasonOf(err: LineError) ir.Reason {
    return switch (err) {
        error.FieldCount => .field_count,
        error.BadHash => .bad_hash,
        error.BadSize => .bad_size,
        error.WildcardNeedsFlevel73 => .wildcard_needs_flevel_73,
        error.BadFlevel => .bad_flevel,
        error.EmptyName => .empty_name,
    };
}

pub fn parseLine(format: Format, line: []const u8) LineError!ir.HashRule {
    var fields: [6][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, line, ':');
    while (it.next()) |f| {
        if (count == fields.len) return error.FieldCount;
        fields[count] = f;
        count += 1;
    }
    if (count < 3 or count > 5) return error.FieldCount;

    const hash_hex = if (format.size_first) fields[1] else fields[0];
    const size_text = if (format.size_first) fields[0] else fields[1];
    const name = fields[2];
    if (name.len == 0) return error.EmptyName;

    const algo = format.algo orelse (ir.HashAlgo.fromHexLen(hash_hex.len) orelse return error.BadHash);
    if (hash_hex.len != algo.digestLen() * 2) return error.BadHash;
    var digest: [32]u8 = @splat(0);
    _ = std.fmt.hexToBytes(digest[0..algo.digestLen()], hash_hex) catch return error.BadHash;

    const flevel_min: u16 = if (count >= 4) std.fmt.parseInt(u16, fields[3], 10) catch return error.BadFlevel else 0;
    const flevel_max: u16 = if (count >= 5) std.fmt.parseInt(u16, fields[4], 10) catch return error.BadFlevel else 0;
    if (flevel_max != 0 and flevel_max < flevel_min) return error.BadFlevel;

    const size: ?u64 = if (std.mem.eql(u8, size_text, "*")) blk: {
        if (flevel_min < 73) return error.WildcardNeedsFlevel73;
        break :blk null;
    } else std.fmt.parseInt(u64, size_text, 10) catch return error.BadSize;

    return .{
        .algo = algo,
        .scope = format.scope,
        .digest = digest,
        .size = size,
        .name = name,
        .flevel_min = flevel_min,
        .flevel_max = flevel_max,
        .source = format.source,
        .flags = .{ .pua = format.pua },
        .line = line,
    };
}

fn parseOne(ext: []const u8, line: []const u8) LineError!ir.HashRule {
    return parseLine(formatFor(ext).?, line);
}

test "hdb: MD5, size, name" {
    const r = try parseOne("hdb", "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature");
    try std.testing.expectEqual(ir.HashAlgo.md5, r.algo);
    try std.testing.expectEqual(@as(?u64, 68), r.size);
    try std.testing.expectEqualStrings("Eicar-Test-Signature", r.name);
    try std.testing.expectEqual(@as(u8, 0x44), r.digestBytes()[0]);
    try std.testing.expectEqual(@as(usize, 16), r.digestBytes().len);
}

test "hsb: algorithm from length, wildcard size needs flevel 73" {
    const sha1 = try parseOne("hsb", "3395856ce81f2b7382dee72602f798b642f14140:68:Eicar-Test-Signature");
    try std.testing.expectEqual(ir.HashAlgo.sha1, sha1.algo);
    const sha256 = try parseOne("hsb", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature");
    try std.testing.expectEqual(ir.HashAlgo.sha256, sha256.algo);
    const any = try parseOne("hsb", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:Eicar-Test-Signature:73");
    try std.testing.expectEqual(@as(?u64, null), any.size);
    try std.testing.expectEqual(@as(u16, 73), any.flevel_min);
    try std.testing.expectError(error.WildcardNeedsFlevel73, parseOne("hsb", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:X"));
    try std.testing.expectError(error.WildcardNeedsFlevel73, parseOne("hsb", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:X:72"));
}

test "mdb and msb put the size first" {
    const m = try parseOne("mdb", "45056:44d88612fea8a8f36de82e1278abb02f:Win.Trojan.X-1-0");
    try std.testing.expectEqual(ir.HashScope.pe_section, m.scope);
    try std.testing.expectEqual(@as(?u64, 45056), m.size);
    const s = try parseOne("msb", "*:3395856ce81f2b7382dee72602f798b642f14140:Win.Trojan.Y-2-0:73");
    try std.testing.expectEqual(ir.HashAlgo.sha1, s.algo);
    try std.testing.expectEqual(@as(?u64, null), s.size);
}

test "imp is MD5 of the import table" {
    const r = try parseOne("imp", "98c88d882f01a3f6ac1e5f7dfd761624:39:clam.exe");
    try std.testing.expectEqual(ir.HashScope.pe_import, r.scope);
    try std.testing.expectEqual(@as(?u64, 39), r.size);
}

test "u variants are PUA" {
    try std.testing.expect((try parseOne("hdu", "44d88612fea8a8f36de82e1278abb02f:68:PUA.Win.Tool.X-1-0")).flags.pua);
    try std.testing.expect(formatFor("msu").?.pua);
    try std.testing.expect(formatFor("imu").?.pua);
    try std.testing.expect(formatFor("ndb") == null);
}

test "malformed lines" {
    try std.testing.expectError(error.FieldCount, parseOne("hdb", "44d88612fea8a8f36de82e1278abb02f:68"));
    try std.testing.expectError(error.FieldCount, parseOne("hdb", "a:b:c:d:e:f"));
    try std.testing.expectError(error.BadHash, parseOne("hdb", "44d88612fea8a8f36de82e1278abb02:68:X"));
    try std.testing.expectError(error.BadHash, parseOne("hdb", "zzd88612fea8a8f36de82e1278abb02f:68:X"));
    try std.testing.expectError(error.BadHash, parseOne("hdb", "3395856ce81f2b7382dee72602f798b642f14140:68:X")); // SHA1 in an MD5 database
    try std.testing.expectError(error.BadHash, parseOne("hsb", "abc:68:X"));
    try std.testing.expectError(error.BadSize, parseOne("hdb", "44d88612fea8a8f36de82e1278abb02f:-1:X"));
    try std.testing.expectError(error.EmptyName, parseOne("hdb", "44d88612fea8a8f36de82e1278abb02f:68:"));
    try std.testing.expectError(error.BadFlevel, parseOne("hdb", "44d88612fea8a8f36de82e1278abb02f:68:X:abc"));
    try std.testing.expectError(error.BadFlevel, parseOne("hdb", "44d88612fea8a8f36de82e1278abb02f:68:X:90:80"));
}

test "parse records every rejected line with its reason" {
    var rules: std.ArrayList(ir.HashRule) = .empty;
    defer rules.deinit(std.testing.allocator);
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    defer rejected.deinit(std.testing.allocator);
    const text =
        \\44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature
        \\# a comment
        \\
        \\not:a:hash
        \\44d88612fea8a8f36de82e1278abb02f:*:Wild
        \\
    ;
    try parse(std.testing.allocator, formatFor("hdb").?, "test.hdb", text, .{ .rules = &rules, .rejected = &rejected });
    try std.testing.expectEqual(@as(usize, 1), rules.items.len);
    try std.testing.expectEqual(@as(usize, 2), rejected.items.len);
    try std.testing.expectEqual(ir.Reason.bad_hash, rejected.items[0].reason);
    try std.testing.expectEqual(@as(u32, 4), rejected.items[0].line_number);
    try std.testing.expectEqual(ir.Reason.wildcard_needs_flevel_73, rejected.items[1].reason);
}
