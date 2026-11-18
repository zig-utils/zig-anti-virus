//! The compiler's rule representation. Parsers turn signature files into these; the layout pass
//! turns them into `.zavdb` sections. Names and digests borrow the source text, which the compiler
//! keeps alive for the whole compile.
const std = @import("std");

/// Where a rule came from, for the coverage report and `zav info`.
pub const Source = enum(u8) {
    hdb,
    hsb,
    mdb,
    msb,
    imp,
    malwarebazaar,
    guardian,
};

pub const HashAlgo = enum(u8) {
    md5,
    sha1,
    sha256,

    pub fn digestLen(algo: HashAlgo) usize {
        return switch (algo) {
            .md5 => 16,
            .sha1 => 20,
            .sha256 => 32,
        };
    }

    /// Hash type from the length of its hex string, as .hsb and .msb do.
    pub fn fromHexLen(len: usize) ?HashAlgo {
        return switch (len) {
            32 => .md5,
            40 => .sha1,
            64 => .sha256,
            else => null,
        };
    }
};

/// What a hash covers.
pub const HashScope = enum(u8) {
    /// The whole file.
    file,
    /// One PE section's raw data.
    pe_section,
    /// The PE import table.
    pe_import,
};

pub const Flags = packed struct(u8) {
    /// Potentially unwanted application (from a `u` database such as .hdu).
    pua: bool = false,
    _: u7 = 0,
};

pub const HashRule = struct {
    algo: HashAlgo,
    scope: HashScope,
    /// First `algo.digestLen()` bytes are meaningful.
    digest: [32]u8,
    /// Exact size of the hashed data, or null for any size (functionality level 73 and above).
    size: ?u64,
    name: []const u8,
    /// Functionality level range the rule needs; 0 means unbounded on that side.
    flevel_min: u16 = 0,
    flevel_max: u16 = 0,
    source: Source,
    flags: Flags = .{},

    pub fn digestBytes(rule: *const HashRule) []const u8 {
        return rule.digest[0..rule.algo.digestLen()];
    }
};

/// Why a line did not become a rule. Every rejection is counted in the coverage report.
pub const Reason = enum(u8) {
    field_count,
    bad_hash,
    bad_size,
    wildcard_needs_flevel_73,
    bad_flevel,
    empty_name,
    unsupported_database,
    ignored,
    flevel_out_of_range,
    bytecode,
};

pub const Rejection = struct {
    source_name: []const u8,
    line_number: u32,
    reason: Reason,
};

/// A ClamAV signature name split for compact storage: `Win.Trojan.Agent-1234567-0` becomes the
/// family `Win.Trojan.Agent`, number 1234567 and revision 0. Names without that shape keep the
/// whole name as the family.
pub const NameTokens = struct {
    family: []const u8,
    number: ?u32 = null,
    revision: ?u8 = null,

    pub fn parse(name: []const u8) NameTokens {
        const last = std.mem.lastIndexOfScalar(u8, name, '-') orelse return .{ .family = name };
        const revision = std.fmt.parseInt(u8, name[last + 1 ..], 10) catch return .{ .family = name };
        const head = name[0..last];
        const second = std.mem.lastIndexOfScalar(u8, head, '-') orelse return .{ .family = name };
        const number = std.fmt.parseInt(u32, head[second + 1 ..], 10) catch return .{ .family = name };
        if (second == 0) return .{ .family = name };
        return .{ .family = head[0..second], .number = number, .revision = revision };
    }

    /// Writes the original name back into `out`.
    pub fn format(tokens: NameTokens, out: []u8) ![]const u8 {
        if (tokens.number) |n| return std.fmt.bufPrint(out, "{s}-{d}-{d}", .{ tokens.family, n, tokens.revision.? });
        if (tokens.family.len > out.len) return error.NoSpaceLeft;
        @memcpy(out[0..tokens.family.len], tokens.family);
        return out[0..tokens.family.len];
    }
};

test "name tokens round-trip" {
    var buf: [128]u8 = undefined;
    for ([_][]const u8{ "Win.Trojan.Agent-1234567-0", "Eicar-Test-Signature", "Doc.Malware.X-1-12", "-1-2", "Plain" }) |name| {
        const t = NameTokens.parse(name);
        try std.testing.expectEqualStrings(name, try t.format(&buf));
    }
    const t = NameTokens.parse("Win.Trojan.Agent-1234567-0");
    try std.testing.expectEqualStrings("Win.Trojan.Agent", t.family);
    try std.testing.expectEqual(@as(?u32, 1234567), t.number);
    try std.testing.expectEqual(@as(?u8, 0), t.revision);
    try std.testing.expectEqual(@as(?u32, null), NameTokens.parse("Eicar-Test-Signature").number);
}
