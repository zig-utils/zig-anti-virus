//! Lockfile and manifest parsers: bun.lock, package-lock.json (v1 to v3), pnpm-lock.yaml (v5 to
//! v9), pantry.lock, Cargo.lock and Python dist-info METADATA. Each appends (ecosystem, name,
//! version) items. Inputs are hostile: depth and sizes are bounded, malformed entries skipped.
const std = @import("std");
const Item = @import("item.zig").Item;

pub const Error = error{ OutOfMemory, Malformed };

/// JSON with comments and trailing commas (bun.lock) to plain JSON.
pub fn stripJsonc(gpa: std.mem.Allocator, text: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, text.len);
    var i: usize = 0;
    var in_string = false;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (in_string) {
            out.appendAssumeCapacity(c);
            if (c == '\\' and i + 1 < text.len) {
                i += 1;
                out.appendAssumeCapacity(text[i]);
            } else if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') {
            in_string = true;
            out.appendAssumeCapacity(c);
        } else if (c == '/' and i + 1 < text.len and text[i + 1] == '/') {
            while (i < text.len and text[i] != '\n') i += 1;
        } else if (c == '/' and i + 1 < text.len and text[i + 1] == '*') {
            i += 2;
            while (i + 1 < text.len and !(text[i] == '*' and text[i + 1] == '/')) i += 1;
            i += 1;
        } else if (c == ',') {
            // Drop a comma followed only by whitespace and a closing bracket.
            var j = i + 1;
            while (j < text.len and std.ascii.isWhitespace(text[j])) j += 1;
            if (j < text.len and (text[j] == '}' or text[j] == ']')) continue;
            out.appendAssumeCapacity(c);
        } else out.appendAssumeCapacity(c);
    }
    return out.toOwnedSlice(gpa);
}

/// `name@version` with scoped names (`@scope/pkg@1.0.0`).
pub fn splitAt(spec: []const u8) ?struct { name: []const u8, version: []const u8 } {
    if (spec.len < 3) return null;
    const at = std.mem.lastIndexOfScalar(u8, spec[1..], '@') orelse return null;
    const name = spec[0 .. at + 1];
    const ver = spec[at + 2 ..];
    if (name.len == 0 or ver.len == 0) return null;
    return .{ .name = name, .version = ver };
}

/// Registry versions only: workspace, git, file and link specs are not published packages.
fn isRegistryVersion(v: []const u8) bool {
    return v.len > 0 and std.ascii.isDigit(v[0]) and std.mem.indexOfScalar(u8, v, ':') == null and std.mem.indexOfScalar(u8, v, '/') == null;
}

fn add(gpa: std.mem.Allocator, out: *std.ArrayList(Item), eco: []const u8, name: []const u8, ver: []const u8, source: []const u8) !void {
    if (!isRegistryVersion(ver)) return;
    try out.append(gpa, .{ .ecosystem = eco, .name = name, .version = ver, .source = source });
}

/// bun.lock: `"packages": { "<key>": ["name@version", ...] }`.
pub fn bunLock(gpa: std.mem.Allocator, arena: std.mem.Allocator, text: []const u8, source: []const u8, out: *std.ArrayList(Item)) !void {
    const json = try stripJsonc(arena, text);
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch return error.Malformed;
    if (v != .object) return error.Malformed;
    const pkgs = v.object.get("packages") orelse return;
    if (pkgs != .object) return;
    var it = pkgs.object.iterator();
    while (it.next()) |kv| {
        const arr = kv.value_ptr.*;
        if (arr != .array or arr.array.items.len == 0 or arr.array.items[0] != .string) continue;
        const nv = splitAt(arr.array.items[0].string) orelse continue;
        try add(gpa, out, "npm", nv.name, nv.version, source);
    }
}

/// package-lock.json: v2/v3 `packages` keyed by node_modules path, v1 nested `dependencies`.
pub fn packageLock(gpa: std.mem.Allocator, arena: std.mem.Allocator, text: []const u8, source: []const u8, out: *std.ArrayList(Item)) !void {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch return error.Malformed;
    if (v != .object) return error.Malformed;
    if (v.object.get("packages")) |pkgs| if (pkgs == .object) {
        var it = pkgs.object.iterator();
        while (it.next()) |kv| {
            const key = kv.key_ptr.*;
            const i = std.mem.lastIndexOf(u8, key, "node_modules/") orelse continue;
            const entry = kv.value_ptr.*;
            if (entry != .object) continue;
            if (entry.object.get("link")) |l| if (l == .bool and l.bool) continue;
            const ver = entry.object.get("version") orelse continue;
            if (ver != .string) continue;
            try add(gpa, out, "npm", key[i + "node_modules/".len ..], ver.string, source);
        }
        return;
    };
    if (v.object.get("dependencies")) |deps| try lockV1(gpa, deps, source, out, 0);
}

fn lockV1(gpa: std.mem.Allocator, deps: std.json.Value, source: []const u8, out: *std.ArrayList(Item), depth: u32) !void {
    if (deps != .object or depth > 64) return;
    var it = deps.object.iterator();
    while (it.next()) |kv| {
        const e = kv.value_ptr.*;
        if (e != .object) continue;
        if (e.object.get("version")) |ver| if (ver == .string) try add(gpa, out, "npm", kv.key_ptr.*, ver.string, source);
        if (e.object.get("dependencies")) |sub| try lockV1(gpa, sub, source, out, depth + 1);
    }
}

/// pnpm-lock.yaml: keys of the top-level `packages:` map, in every lockfile version's spelling:
/// `/name/1.0.0` (v5), `/name@1.0.0` (v6), `name@1.0.0` and `'@scope/n@1.0.0(peer@2)'` (v9).
pub fn pnpmLock(gpa: std.mem.Allocator, text: []const u8, source: []const u8, out: *std.ArrayList(Item)) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var in_packages = false;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r ");
        if (line.len == 0) continue;
        if (line[0] != ' ') {
            in_packages = std.mem.eql(u8, line, "packages:");
            continue;
        }
        if (!in_packages or line.len < 3 or line[2] == ' ' or line[0] != ' ' or line[1] != ' ') continue;
        var key = std.mem.trim(u8, line, " ");
        if (key.len == 0 or key[key.len - 1] != ':') continue;
        key = std.mem.trim(u8, key[0 .. key.len - 1], "'\"");
        if (key.len > 0 and key[0] == '/') key = key[1..];
        if (std.mem.indexOfScalar(u8, key, '(')) |p| key = key[0..p];
        if (splitAt(key)) |nv| {
            try add(gpa, out, "npm", nv.name, nv.version, source);
        } else if (std.mem.lastIndexOfScalar(u8, key, '/')) |slash| {
            try add(gpa, out, "npm", key[0..slash], key[slash + 1 ..], source);
        }
    }
}

/// pantry.lock (JSON): npm packages and system packages named by their project domain
/// (`curl.se`, `openssl.org`), which map to CPEs through item.zig.
pub fn pantryLock(gpa: std.mem.Allocator, arena: std.mem.Allocator, text: []const u8, source: []const u8, out: *std.ArrayList(Item)) !void {
    const json = try stripJsonc(arena, text);
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch return error.Malformed;
    if (v != .object) return error.Malformed;
    const pkgs = v.object.get("packages") orelse return;
    if (pkgs != .object) return;
    var it = pkgs.object.iterator();
    while (it.next()) |kv| {
        const e = kv.value_ptr.*;
        if (e != .object) continue;
        const name = e.object.get("name") orelse continue;
        const ver = e.object.get("version") orelse continue;
        if (name != .string or ver != .string) continue;
        const src = if (e.object.get("source")) |sv| (if (sv == .string) sv.string else "") else "";
        try add(gpa, out, if (std.mem.eql(u8, src, "pantry")) "pantry" else "npm", name.string, ver.string, source);
    }
}

/// Cargo.lock: `[[package]]` tables with name, version and a registry source.
pub fn cargoLock(gpa: std.mem.Allocator, text: []const u8, source: []const u8, out: *std.ArrayList(Item)) !void {
    var name: ?[]const u8 = null;
    var ver: ?[]const u8 = null;
    var registry = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (true) {
        const raw = lines.next();
        const line = if (raw) |r| std.mem.trim(u8, r, " \r\t") else "[[package]]";
        if (std.mem.eql(u8, line, "[[package]]") or (line.len > 0 and line[0] == '[')) {
            if (name != null and ver != null and registry) try add(gpa, out, "crates.io", name.?, ver.?, source);
            name = null;
            ver = null;
            registry = false;
            if (raw == null) break;
            continue;
        }
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " ");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \"");
        if (std.mem.eql(u8, key, "name")) name = value else if (std.mem.eql(u8, key, "version")) ver = value else if (std.mem.eql(u8, key, "source")) registry = std.mem.startsWith(u8, value, "registry+") or std.mem.startsWith(u8, value, "sparse+");
    }
}

/// Python METADATA or PKG-INFO: `Name:` and `Version:` headers.
pub fn pythonMetadata(gpa: std.mem.Allocator, text: []const u8, source: []const u8, out: *std.ArrayList(Item)) !void {
    var name: ?[]const u8 = null;
    var ver: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) break; // headers end at the first blank line
        if (std.mem.startsWith(u8, line, "Name:")) name = std.mem.trim(u8, line[5..], " ");
        if (std.mem.startsWith(u8, line, "Version:")) ver = std.mem.trim(u8, line[8..], " ");
    }
    if (name != null and ver != null) try add(gpa, out, "PyPI", name.?, ver.?, source);
}

test "bun.lock with trailing commas, scoped names and workspaces" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    try bunLock(gpa, arena.allocator(),
        \\{
        \\  // comment
        \\  "lockfileVersion": 1,
        \\  "workspaces": { "": { "name": "app", "dependencies": { "lodash": "^4.17.20", }, }, },
        \\  "packages": {
        \\    "lodash": ["lodash@4.17.20", "", {}, "sha512-x"],
        \\    "@stacksjs/ai": ["@stacksjs/ai@workspace:storage/framework/core/ai"],
        \\    "@scope/pkg": ["@scope/pkg@1.2.3", "", {}, "sha512-y"],
        \\  },
        \\}
    , "bun.lock", &items);
    try std.testing.expectEqual(@as(usize, 2), items.items.len);
    var lodash = false;
    var scoped = false;
    for (items.items) |i| {
        if (std.mem.eql(u8, i.name, "lodash") and std.mem.eql(u8, i.version, "4.17.20")) lodash = true;
        if (std.mem.eql(u8, i.name, "@scope/pkg") and std.mem.eql(u8, i.version, "1.2.3")) scoped = true;
    }
    try std.testing.expect(lodash and scoped);
}

test "package-lock v3 and v1, pnpm v5/v6/v9, Cargo.lock, METADATA" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    try packageLock(gpa, arena.allocator(), "{\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"a\"},\"node_modules/minimist\":{\"version\":\"1.2.5\"},\"node_modules/x/node_modules/@a/b\":{\"version\":\"2.0.0\"},\"node_modules/l\":{\"link\":true,\"version\":\"9.9.9\"}}}", "package-lock.json", &items);
    try std.testing.expectEqual(@as(usize, 2), items.items.len);
    try std.testing.expectEqualStrings("@a/b", items.items[1].name);
    items.clearRetainingCapacity();
    try packageLock(gpa, arena.allocator(), "{\"lockfileVersion\":1,\"dependencies\":{\"a\":{\"version\":\"1.0.0\",\"dependencies\":{\"b\":{\"version\":\"2.0.0\"}}}}}", "package-lock.json", &items);
    try std.testing.expectEqual(@as(usize, 2), items.items.len);
    items.clearRetainingCapacity();
    try pnpmLock(gpa,
        \\lockfileVersion: '9.0'
        \\importers:
        \\  .:
        \\    dependencies:
        \\      lodash:
        \\packages:
        \\  lodash@4.17.20:
        \\    resolution: {integrity: sha512-x}
        \\  '@scope/x@1.0.0(react@18.0.0)':
        \\    resolution: {}
        \\  /old/2.0.0:
        \\    resolution: {}
        \\snapshots:
        \\  other@1.0.0:
    , "pnpm-lock.yaml", &items);
    try std.testing.expectEqual(@as(usize, 3), items.items.len);
    try std.testing.expectEqualStrings("@scope/x", items.items[1].name);
    try std.testing.expectEqualStrings("old", items.items[2].name);
    items.clearRetainingCapacity();
    try cargoLock(gpa, "version = 3\n\n[[package]]\nname = \"regex\"\nversion = \"1.5.4\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n", "Cargo.lock", &items);
    try std.testing.expectEqual(@as(usize, 1), items.items.len);
    try std.testing.expectEqualStrings("regex", items.items[0].name);
    items.clearRetainingCapacity();
    try pythonMetadata(gpa, "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nlong description Name: no\n", "METADATA", &items);
    try std.testing.expectEqualStrings("2.31.0", items.items[0].version);
}
