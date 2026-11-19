//! Guardian family metadata, parsed by the native zig-cli TOML parser.
const std = @import("std");
const Toml = @import("zig_cli").config.TomlParser;
const bundle = @import("bundle.zig");

pub const Metadata = struct {
    category: []const u8,
    severity: []const u8,
    references: []const Toml.Value,
    false_positive_notes: []const u8,
    owner: []const u8,
};

fn string(value: ?Toml.Value) ![]const u8 {
    const v = value orelse return error.InvalidMetadata;
    if (v != .string or v.string.len == 0 or v.string.len > 2048) return error.InvalidMetadata;
    for (v.string) |c| if (c < 0x20 and c != '\n' and c != '\t') return error.InvalidMetadata;
    return v.string;
}

/// Returned data belongs to the caller's arena. Exactly five fields, no silent typos.
pub fn parse(arena: std.mem.Allocator, text: []const u8) !Metadata {
    if (text.len == 0 or text.len > bundle.max_meta_bytes) return error.InvalidMetadata;
    var parser = Toml.init(arena, text);
    const table = parser.parse() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidMetadata,
    };
    if (table.count() != 5) return error.InvalidMetadata;
    const meta: Metadata = .{
        .category = try string(table.get("category")),
        .severity = try string(table.get("severity")),
        .owner = try string(table.get("owner")),
        .false_positive_notes = try string(table.get("false_positive_notes")),
        .references = blk: {
            const refs = table.get("references") orelse return error.InvalidMetadata;
            if (refs != .array or refs.array.len == 0 or refs.array.len > 16) return error.InvalidMetadata;
            for (refs.array) |v| {
                const url = try string(v);
                if (!std.mem.startsWith(u8, url, "https://") or url.len <= 8) return error.InvalidMetadata;
                for (url) |c| if (std.ascii.isWhitespace(c) or c == '\\') return error.InvalidMetadata;
                const uri = std.Uri.parse(url) catch return error.InvalidMetadata;
                if (uri.host == null or uri.host.?.isEmpty() or uri.user != null or uri.password != null) return error.InvalidMetadata;
            }
            break :blk refs.array;
        },
    };
    var valid = false;
    for ([_][]const u8{ "webshell", "skimmer", "npm-install", "miner-dropper", "linux-backdoor" }) |category| {
        if (std.mem.eql(u8, category, meta.category)) valid = true;
    }
    if (!valid) return error.InvalidMetadata;
    valid = false;
    for ([_][]const u8{ "low", "medium", "high", "critical" }) |severity| {
        if (std.mem.eql(u8, severity, meta.severity)) valid = true;
    }
    if (!valid) return error.InvalidMetadata;
    return meta;
}

pub const fixture =
    \\category = "webshell"
    \\severity = "high"
    \\references = ["https://attack.mitre.org/techniques/T1505/003/"]
    \\false_positive_notes = "Review authorized diagnostic scripts."
    \\owner = "Guardian maintainers"
;

test "Guardian metadata rejects missing unknown mistyped duplicate and invalid values" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const meta = try parse(a, fixture);
    try std.testing.expectEqualStrings("webshell", meta.category);
    try std.testing.expectEqualStrings("high", meta.severity);
    for ([_][]const u8{
        "category = 'webshell'",
        "category = [",
        "category = [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
    }) |bad| try std.testing.expectError(error.InvalidMetadata, parse(a, bad));
    for ([_][]const u8{ "\nowner = 'other'", "\nunknown = 'x'", "\n[owner]\nx='y'" }) |suffix| {
        const bad = try std.mem.concat(a, u8, &.{ fixture, suffix });
        try std.testing.expectError(error.InvalidMetadata, parse(a, bad));
    }
}

test "Guardian metadata enforces categories severities references and field types" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][2][]const u8{
        .{ "webshell", "unsupported-category" },
        .{ "high", "urgent" },
        .{ "https://", "http://" },
        .{ "severity = \"high\"", "severity = 5" },
        .{ "owner = \"Guardian maintainers\"", "owner = \"\"" },
        .{ "[\"https://attack.mitre.org/techniques/T1505/003/\"]", "[]" },
    }) |change| {
        const invalid = try std.mem.replaceOwned(u8, a, fixture, change[0], change[1]);
        try std.testing.expectError(error.InvalidMetadata, parse(a, invalid));
    }
}
