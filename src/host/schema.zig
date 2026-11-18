//! A small JSON Schema validator for the committed report schemas. It implements the keywords
//! the schemas use (type, enum, const, required, properties, additionalProperties, items,
//! minimum, maximum, minLength, anyOf and local `#/$defs/...` references) and refuses any other
//! keyword, so a schema can never rely on something the tests silently ignore.
const std = @import("std");
const Value = std.json.Value;

pub const Error = error{ SchemaViolation, UnsupportedKeyword, BadSchema, OutOfMemory };

pub fn validate(gpa: std.mem.Allocator, schema_text: []const u8, doc_text: []const u8) Error!void {
    var schema = std.json.parseFromSlice(Value, gpa, schema_text, .{}) catch return error.BadSchema;
    defer schema.deinit();
    var doc = std.json.parseFromSlice(Value, gpa, doc_text, .{}) catch return error.SchemaViolation;
    defer doc.deinit();
    var path: std.ArrayList(u8) = .empty;
    defer path.deinit(gpa);
    var v: Validator = .{ .root = schema.value, .gpa = gpa, .path = &path };
    try v.check(schema.value, doc.value, 0);
}

/// `validate` that prints where a document breaks the schema.
pub fn expectValid(gpa: std.mem.Allocator, schema_text: []const u8, doc_text: []const u8) !void {
    validate(gpa, schema_text, doc_text) catch |e| {
        std.debug.print("schema validation failed ({t}) for:\n{s}\n", .{ e, doc_text });
        return e;
    };
}

const Validator = struct {
    root: Value,
    gpa: std.mem.Allocator,
    path: *std.ArrayList(u8),
    last_error: []const u8 = "",

    fn fail(v: *Validator, comptime what: []const u8) Error {
        v.last_error = what;
        std.log.debug("schema: {s} at {s}", .{ what, v.path.items });
        return error.SchemaViolation;
    }

    fn check(v: *Validator, schema: Value, doc: Value, depth: u32) Error!void {
        if (depth > 64) return error.BadSchema;
        const obj = switch (schema) {
            .object => |o| o,
            .bool => |b| return if (b) {} else v.fail("false schema"),
            else => return error.BadSchema,
        };
        var it = obj.iterator();
        while (it.next()) |kv| {
            const key = kv.key_ptr.*;
            const sub = kv.value_ptr.*;
            if (std.mem.eql(u8, key, "$schema") or std.mem.eql(u8, key, "$id") or std.mem.eql(u8, key, "title") or
                std.mem.eql(u8, key, "description") or std.mem.eql(u8, key, "$defs"))
            {
                continue;
            } else if (std.mem.eql(u8, key, "$ref")) {
                const ref = switch (sub) {
                    .string => |s| s,
                    else => return error.BadSchema,
                };
                if (!std.mem.startsWith(u8, ref, "#/$defs/")) return error.UnsupportedKeyword;
                const defs = v.root.object.get("$defs") orelse return error.BadSchema;
                const target = defs.object.get(ref["#/$defs/".len..]) orelse return error.BadSchema;
                try v.check(target, doc, depth + 1);
            } else if (std.mem.eql(u8, key, "type")) {
                switch (sub) {
                    .string => |t| if (!typeMatches(t, doc)) return v.fail("type"),
                    .array => |a| {
                        var any = false;
                        for (a.items) |t| if (t == .string and typeMatches(t.string, doc)) {
                            any = true;
                        };
                        if (!any) return v.fail("type");
                    },
                    else => return error.BadSchema,
                }
            } else if (std.mem.eql(u8, key, "enum")) {
                var any = false;
                for (sub.array.items) |e| if (equal(e, doc)) {
                    any = true;
                };
                if (!any) return v.fail("enum");
            } else if (std.mem.eql(u8, key, "const")) {
                if (!equal(sub, doc)) return v.fail("const");
            } else if (std.mem.eql(u8, key, "required")) {
                if (doc != .object) continue;
                for (sub.array.items) |name| if (!doc.object.contains(name.string)) return v.fail("required");
            } else if (std.mem.eql(u8, key, "properties")) {
                if (doc != .object) continue;
                var props = sub.object.iterator();
                while (props.next()) |p| if (doc.object.get(p.key_ptr.*)) |child| try v.check(p.value_ptr.*, child, depth + 1);
            } else if (std.mem.eql(u8, key, "additionalProperties")) {
                if (doc != .object) continue;
                const props = if (obj.get("properties")) |p| p.object else null;
                var fields = doc.object.iterator();
                while (fields.next()) |f| {
                    if (props) |p| if (p.contains(f.key_ptr.*)) continue;
                    try v.check(sub, f.value_ptr.*, depth + 1);
                }
            } else if (std.mem.eql(u8, key, "items")) {
                if (doc != .array) continue;
                for (doc.array.items) |item| try v.check(sub, item, depth + 1);
            } else if (std.mem.eql(u8, key, "minimum") or std.mem.eql(u8, key, "maximum")) {
                const n: f64 = switch (doc) {
                    .integer => |i| @floatFromInt(i),
                    .float => |f| f,
                    else => continue,
                };
                const limit: f64 = switch (sub) {
                    .integer => |i| @floatFromInt(i),
                    .float => |f| f,
                    else => return error.BadSchema,
                };
                if (key[1] == 'i' and n < limit) return v.fail("minimum");
                if (key[1] == 'a' and n > limit) return v.fail("maximum");
            } else if (std.mem.eql(u8, key, "minLength")) {
                if (doc != .string) continue;
                if (doc.string.len < @as(usize, @intCast(sub.integer))) return v.fail("minLength");
            } else if (std.mem.eql(u8, key, "anyOf")) {
                var any = false;
                for (sub.array.items) |alt| {
                    v.check(alt, doc, depth + 1) catch |e| switch (e) {
                        error.SchemaViolation => continue,
                        else => return e,
                    };
                    any = true;
                    break;
                }
                if (!any) return v.fail("anyOf");
            } else return error.UnsupportedKeyword;
        }
    }
};

fn typeMatches(t: []const u8, doc: Value) bool {
    if (std.mem.eql(u8, t, "object")) return doc == .object;
    if (std.mem.eql(u8, t, "array")) return doc == .array;
    if (std.mem.eql(u8, t, "string")) return doc == .string;
    if (std.mem.eql(u8, t, "boolean")) return doc == .bool;
    if (std.mem.eql(u8, t, "null")) return doc == .null;
    if (std.mem.eql(u8, t, "integer")) return doc == .integer;
    if (std.mem.eql(u8, t, "number")) return doc == .integer or doc == .float;
    return false;
}

fn equal(a: Value, b: Value) bool {
    return switch (a) {
        .null => b == .null,
        .bool => |x| b == .bool and b.bool == x,
        .integer => |x| b == .integer and b.integer == x,
        .float => |x| b == .float and b.float == x,
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        else => false,
    };
}

test "validator keywords" {
    const gpa = std.testing.allocator;
    const s =
        \\{ "type": "object", "required": ["a"], "additionalProperties": false,
        \\  "properties": { "a": { "enum": ["x", "y"] }, "n": { "type": "integer", "minimum": 0, "maximum": 3 },
        \\    "l": { "type": "array", "items": { "$ref": "#/$defs/s" } }, "o": { "anyOf": [ { "type": "null" }, { "const": 1 } ] } },
        \\  "$defs": { "s": { "type": "string", "minLength": 1 } } }
    ;
    try validate(gpa, s, "{\"a\":\"x\",\"n\":2,\"l\":[\"q\"],\"o\":null}");
    try validate(gpa, s, "{\"a\":\"y\",\"o\":1}");
    try std.testing.expectError(error.SchemaViolation, validate(gpa, s, "{\"n\":1}"));
    try std.testing.expectError(error.SchemaViolation, validate(gpa, s, "{\"a\":\"z\"}"));
    try std.testing.expectError(error.SchemaViolation, validate(gpa, s, "{\"a\":\"x\",\"n\":4}"));
    try std.testing.expectError(error.SchemaViolation, validate(gpa, s, "{\"a\":\"x\",\"l\":[\"\"]}"));
    try std.testing.expectError(error.SchemaViolation, validate(gpa, s, "{\"a\":\"x\",\"extra\":1}"));
    try std.testing.expectError(error.SchemaViolation, validate(gpa, s, "{\"a\":\"x\",\"o\":2}"));
    try std.testing.expectError(error.UnsupportedKeyword, validate(gpa, "{\"pattern\":\"x\"}", "\"x\""));
}
