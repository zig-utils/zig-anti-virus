//! The YARA subset ClamAV supports (docs: YaraRules): text, hex and regex strings with
//! string-driven conditions, no modules.
//!
//! Strings:
//! - text `"..."` with `nocase`, `wide`, `ascii`, `fullword`, `private` and `xor` / `xor(a-b)`
//!   (expanded into literal variants, at most 16 keys);
//! - hex `{ ... }`, rewritten into the body-signature syntax and parsed into the hex IR (jumps
//!   `[n]`, `[n-m]`, `[n-]`, `[-]`, alternatives, nibble wildcards and `~` negation);
//! - regex `/.../is` with `nocase`, `ascii`, `private`, compiled to zig-regex byte-mode programs.
//!
//! Conditions: `and or not`, comparisons, `+ - * \ % & | ^ ~ << >>`, `$a`, `#a`, `@a[i]`,
//! `$a at e`, `$a in (e..e)`, `N of (...)`, `any/all/none of them`, string sets with `*`,
//! `filesize`, `uint8/16/32[be]`, `int8/16/32[be]`, `true`, `false`, KB and MB suffixes.
//!
//! Rejected with reasons: modules and their identifiers, `global` rules, `include`, `for` loops,
//! `contains` / `matches`, rule references, `!a` lengths, `entrypoint`, `base64` modifiers, wide
//! or fullword regex strings, more than 64 strings, strings shorter than two bytes, rules without
//! strings. A rule that fails to parse is skipped up to the next rule.
const std = @import("std");
const ir = @import("ir.zig");
const hexsig = @import("hexsig.zig");
const cdb = @import("cdb.zig");
const yc = @import("../match/yara_cond.zig");
const regex_flags = @import("regex").common.CompileFlags;

pub const max_strings = ir.max_subsigs;
pub const max_xor_keys = 16;

pub const StringDef = struct {
    /// Patterns to verify, already expanded (wide, nocase, xor) into their variants.
    variants: []const hexsig.Variant = &.{},
    fullword: bool = false,
    /// A regex string's serialised zig-regex program.
    regex: ?[]const u8 = null,
};

pub const Rule = struct {
    name: []const u8,
    strings: []const StringDef,
    cond: []const yc.CondOp,
    private: bool = false,
    /// The condition can hold with no string matched: evaluate it for every file.
    always: bool = false,
    text: []const u8 = "",
};

pub const ParseError = error{
    YaraSyntax,
    YaraUnsupported,
    YaraTooManyStrings,
    YaraShortString,
    YaraNoStrings,
    YaraXorRange,
    RegexSyntax,
    RegexUnsupported,
    OutOfMemory,
} || hexsig.Error;

pub fn reasonOf(err: ParseError) ir.Reason {
    return switch (err) {
        error.YaraSyntax => .yara_syntax,
        error.YaraUnsupported => .yara_unsupported,
        error.YaraTooManyStrings => .too_many_subsigs,
        error.YaraShortString => .yara_short_string,
        error.YaraNoStrings => .yara_no_strings,
        error.YaraXorRange => .yara_xor_range,
        error.RegexSyntax => .regex_syntax,
        error.RegexUnsupported => .regex_unsupported,
        else => |e| hexsig.reasonOf(@errorCast(e)),
    };
}

pub const Output = struct {
    rules: *std.ArrayList(Rule),
    rejected: *std.ArrayList(ir.Rejection),
};

/// Parse a rule file. Every rule that does not compile is recorded with its line and reason.
pub fn parse(gpa: std.mem.Allocator, arena: std.mem.Allocator, source_name: []const u8, text: []const u8, out: Output) !void {
    var p: Parser = .{ .src = text, .arena = arena };
    while (true) {
        p.skip();
        if (p.pos >= p.src.len) break;
        const start = p.pos;
        if (parseTop(&p)) |maybe| {
            if (maybe) |rule| try out.rules.append(gpa, rule);
        } else |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            try out.rejected.append(gpa, .{ .source_name = source_name, .line_number = lineOf(text, start), .reason = reasonOf(err), .column = @intCast(p.err_pos -| lineStart(text, p.err_pos)) });
            p.recover(start);
        }
    }
}

fn lineOf(text: []const u8, pos: usize) u32 {
    return @intCast(1 + std.mem.count(u8, text[0..@min(pos, text.len)], "\n"));
}

fn lineStart(text: []const u8, pos: usize) usize {
    const p = @min(pos, text.len);
    return if (std.mem.lastIndexOfScalar(u8, text[0..p], '\n')) |nl| nl + 1 else 0;
}

/// One top-level item: an import (ignored; module identifiers are rejected where used), an
/// include (rejected) or a rule.
fn parseTop(p: *Parser) ParseError!?Rule {
    const word = p.peekWord();
    if (std.mem.eql(u8, word, "import")) {
        p.pos += word.len;
        p.skip();
        _ = try p.quoted();
        return null;
    }
    if (std.mem.eql(u8, word, "include")) {
        p.err_pos = p.pos;
        p.pos += word.len;
        p.skip();
        _ = p.quoted() catch {};
        return error.YaraUnsupported;
    }
    return try parseRule(p);
}

const Parser = struct {
    src: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,
    err_pos: usize = 0,

    fn fail(p: *Parser, err: ParseError) ParseError {
        p.err_pos = p.pos;
        return err;
    }

    /// Skip whitespace and comments.
    fn skip(p: *Parser) void {
        while (p.pos < p.src.len) {
            const c = p.src[p.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                p.pos += 1;
            } else if (std.mem.startsWith(u8, p.src[p.pos..], "//")) {
                p.pos = std.mem.indexOfScalarPos(u8, p.src, p.pos, '\n') orelse p.src.len;
            } else if (std.mem.startsWith(u8, p.src[p.pos..], "/*")) {
                p.pos = if (std.mem.indexOfPos(u8, p.src, p.pos + 2, "*/")) |e| e + 2 else p.src.len;
            } else break;
        }
    }

    fn isIdent(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '_';
    }

    fn peekWord(p: *Parser) []const u8 {
        var e = p.pos;
        while (e < p.src.len and isIdent(p.src[e])) e += 1;
        return p.src[p.pos..e];
    }

    fn word(p: *Parser) ParseError![]const u8 {
        p.skip();
        const w = p.peekWord();
        if (w.len == 0 or std.ascii.isDigit(w[0])) return p.fail(error.YaraSyntax);
        p.pos += w.len;
        return w;
    }

    fn keyword(p: *Parser, k: []const u8) bool {
        p.skip();
        const w = p.peekWord();
        if (!std.mem.eql(u8, w, k)) return false;
        p.pos += w.len;
        return true;
    }

    fn punct(p: *Parser, s: []const u8) bool {
        p.skip();
        if (!std.mem.startsWith(u8, p.src[p.pos..], s)) return false;
        p.pos += s.len;
        return true;
    }

    fn expect(p: *Parser, s: []const u8) ParseError!void {
        if (!p.punct(s)) return p.fail(error.YaraSyntax);
    }

    fn quoted(p: *Parser) ParseError![]const u8 {
        p.skip();
        if (p.pos >= p.src.len or p.src[p.pos] != '"') return p.fail(error.YaraSyntax);
        var out: std.ArrayList(u8) = .empty;
        var i = p.pos + 1;
        while (i < p.src.len) : (i += 1) {
            const c = p.src[i];
            if (c == '"') {
                p.pos = i + 1;
                return out.items;
            }
            if (c == '\n') break;
            if (c != '\\') {
                try out.append(p.arena, c);
                continue;
            }
            i += 1;
            if (i >= p.src.len) break;
            switch (p.src[i]) {
                '"' => try out.append(p.arena, '"'),
                '\\' => try out.append(p.arena, '\\'),
                't' => try out.append(p.arena, '\t'),
                'n' => try out.append(p.arena, '\n'),
                'r' => try out.append(p.arena, '\r'),
                'x' => {
                    if (i + 2 >= p.src.len) break;
                    const v = std.fmt.parseInt(u8, p.src[i + 1 .. i + 3], 16) catch {
                        p.pos = i;
                        return p.fail(error.YaraSyntax);
                    };
                    try out.append(p.arena, v);
                    i += 2;
                },
                else => {
                    p.pos = i;
                    return p.fail(error.YaraSyntax);
                },
            }
        }
        return p.fail(error.YaraSyntax);
    }

    fn integer(p: *Parser) ParseError!i64 {
        p.skip();
        const start = p.pos;
        var v: i64 = 0;
        if (std.mem.startsWith(u8, p.src[p.pos..], "0x")) {
            p.pos += 2;
            const digits = p.pos;
            while (p.pos < p.src.len and std.ascii.isHex(p.src[p.pos])) p.pos += 1;
            v = std.fmt.parseInt(i64, p.src[digits..p.pos], 16) catch return p.failAt(start, error.YaraSyntax);
        } else {
            while (p.pos < p.src.len and std.ascii.isDigit(p.src[p.pos])) p.pos += 1;
            v = std.fmt.parseInt(i64, p.src[start..p.pos], 10) catch return p.failAt(start, error.YaraSyntax);
        }
        if (std.mem.startsWith(u8, p.src[p.pos..], "KB")) {
            p.pos += 2;
            v = std.math.mul(i64, v, 1024) catch return p.failAt(start, error.YaraSyntax);
        } else if (std.mem.startsWith(u8, p.src[p.pos..], "MB")) {
            p.pos += 2;
            v = std.math.mul(i64, v, 1024 * 1024) catch return p.failAt(start, error.YaraSyntax);
        }
        if (p.pos < p.src.len and isIdent(p.src[p.pos])) return p.failAt(start, error.YaraSyntax);
        return v;
    }

    fn failAt(p: *Parser, at: usize, err: ParseError) ParseError {
        p.err_pos = at;
        return err;
    }

    /// After an error, continue at the next line that starts a rule.
    fn recover(p: *Parser, start: usize) void {
        var i = std.mem.indexOfScalarPos(u8, p.src, start, '\n') orelse p.src.len;
        while (i < p.src.len) {
            const line_start = i + 1;
            var j = line_start;
            while (j < p.src.len and (p.src[j] == ' ' or p.src[j] == '\t')) j += 1;
            const rest = p.src[j..];
            for ([_][]const u8{ "rule ", "private ", "global ", "import ", "include " }) |k| {
                if (std.mem.startsWith(u8, rest, k)) {
                    p.pos = line_start;
                    return;
                }
            }
            i = std.mem.indexOfScalarPos(u8, p.src, line_start, '\n') orelse p.src.len;
        }
        p.pos = p.src.len;
    }
};

const Def = struct { name: []const u8, def: StringDef };

fn parseRule(p: *Parser) ParseError!Rule {
    const rule_start = p.pos;
    var private = false;
    while (true) {
        const w = p.peekWord();
        if (std.mem.eql(u8, w, "private")) {
            p.pos += w.len;
            private = true;
            p.skip();
        } else if (std.mem.eql(u8, w, "global")) {
            return p.fail(error.YaraUnsupported);
        } else break;
    }
    if (!p.keyword("rule")) return p.fail(error.YaraSyntax);
    const name = try p.word();
    if (p.punct(":")) {
        // Tags: identifiers up to the opening brace.
        while (true) {
            p.skip();
            if (p.pos < p.src.len and p.src[p.pos] == '{') break;
            _ = try p.word();
        }
    }
    try p.expect("{");
    var defs: std.ArrayList(Def) = .empty;
    if (p.keyword("meta")) {
        try p.expect(":");
        while (true) {
            p.skip();
            const w = p.peekWord();
            if (w.len == 0 or std.mem.eql(u8, w, "strings") or std.mem.eql(u8, w, "condition")) break;
            p.pos += w.len;
            try p.expect("=");
            p.skip();
            if (p.pos < p.src.len and p.src[p.pos] == '"') {
                _ = try p.quoted();
            } else if (p.keyword("true") or p.keyword("false")) {} else {
                _ = p.punct("-");
                _ = try p.integer();
            }
        }
    }
    if (p.keyword("strings")) {
        try p.expect(":");
        while (true) {
            p.skip();
            if (p.pos >= p.src.len or p.src[p.pos] != '$') break;
            const id_start = p.pos;
            p.pos += 1;
            const id = p.peekWord();
            p.pos += id.len;
            if (id.len == 0) return p.failAt(id_start, error.YaraUnsupported);
            if (defs.items.len == max_strings) return p.failAt(id_start, error.YaraTooManyStrings);
            try p.expect("=");
            const def = try parseString(p);
            try defs.append(p.arena, .{ .name = id, .def = def });
        }
    }
    if (defs.items.len == 0) return p.fail(error.YaraNoStrings);
    if (!p.keyword("condition")) return p.fail(error.YaraSyntax);
    try p.expect(":");
    var c: Cond = .{ .p = p, .defs = defs.items };
    try c.orExpr();
    try p.expect("}");
    if (!yc.check(c.ops.items, defs.items.len)) return p.fail(error.YaraSyntax);

    const strings = try p.arena.alloc(StringDef, defs.items.len);
    for (defs.items, strings) |d, *s| s.* = d.def;
    return .{
        .name = name,
        .strings = strings,
        .cond = c.ops.items,
        .private = private,
        .always = yc.canMatchWithoutHits(c.ops.items),
        .text = p.src[rule_start..p.pos],
    };
}

fn parseString(p: *Parser) ParseError!StringDef {
    p.skip();
    if (p.pos >= p.src.len) return p.fail(error.YaraSyntax);
    switch (p.src[p.pos]) {
        '"' => return parseText(p),
        '{' => return parseHex(p),
        '/' => return parseRegex(p),
        else => return p.fail(error.YaraSyntax),
    }
}

fn hexText(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const out = try arena.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 * i] = digits[b >> 4];
        out[2 * i + 1] = digits[b & 15];
    }
    return out;
}

fn literalPattern(arena: std.mem.Allocator, bytes: []const u8) ParseError!ir.Pattern {
    var diag: hexsig.Diag = .{};
    return hexsig.parse(arena, try hexText(arena, bytes), &diag);
}

fn parseText(p: *Parser) ParseError!StringDef {
    const at = p.pos;
    const bytes = try p.quoted();
    if (bytes.len < 2) return p.failAt(at, error.YaraShortString);
    var mods: ir.Modifiers = .{};
    var xor: ?[2]u8 = null;
    while (true) {
        p.skip();
        const w = p.peekWord();
        if (w.len == 0) break;
        if (std.mem.eql(u8, w, "nocase")) {
            mods.nocase = true;
        } else if (std.mem.eql(u8, w, "wide")) {
            mods.wide = true;
        } else if (std.mem.eql(u8, w, "ascii")) {
            mods.ascii = true;
        } else if (std.mem.eql(u8, w, "fullword")) {
            mods.fullword = true;
        } else if (std.mem.eql(u8, w, "private")) {} else if (std.mem.eql(u8, w, "xor")) {
            p.pos += w.len;
            var range: [2]u8 = .{ 0, 255 };
            if (p.punct("(")) {
                const lo = try p.integer();
                var hi = lo;
                if (p.punct("-")) hi = try p.integer();
                try p.expect(")");
                if (lo < 0 or hi > 255 or hi < lo) return p.failAt(at, error.YaraXorRange);
                range = .{ @intCast(lo), @intCast(hi) };
            }
            xor = range;
            continue;
        } else if (std.mem.eql(u8, w, "base64") or std.mem.eql(u8, w, "base64wide")) {
            return p.fail(error.YaraUnsupported);
        } else break;
        p.pos += w.len;
    }
    // A string with wide and without ascii is wide only; ascii is the default otherwise.
    if (xor) |range| {
        if (mods.nocase) return p.failAt(at, error.YaraUnsupported); // YARA forbids xor with nocase
        if (@as(usize, range[1]) - range[0] + 1 > max_xor_keys) return p.failAt(at, error.YaraXorRange);
        var variants: std.ArrayList(hexsig.Variant) = .empty;
        const encodings: []const bool = if (mods.wide and mods.ascii) &.{ false, true } else if (mods.wide) &.{true} else &.{false};
        for (encodings) |wide| {
            const plain = try p.arena.alloc(u8, if (wide) bytes.len * 2 else bytes.len);
            for (bytes, 0..) |b, i| {
                if (wide) {
                    plain[2 * i] = b;
                    plain[2 * i + 1] = 0;
                } else plain[i] = b;
            }
            var key: usize = range[0];
            while (key <= range[1]) : (key += 1) {
                const x = try p.arena.alloc(u8, plain.len);
                for (plain, x) |b, *o| o.* = b ^ @as(u8, @intCast(key));
                try variants.append(p.arena, .{ .pattern = try literalPattern(p.arena, x), .wide = wide });
            }
        }
        return .{ .variants = variants.items, .fullword = mods.fullword };
    }
    const pattern = try literalPattern(p.arena, bytes);
    return .{ .variants = try hexsig.expand(p.arena, pattern, mods), .fullword = mods.fullword };
}

/// `{ 4D 5A ?? [2-4] (01|02) ~00 }` rewritten into body syntax and parsed into the hex IR.
fn parseHex(p: *Parser) ParseError!StringDef {
    const at = p.pos;
    const close = std.mem.indexOfScalarPos(u8, p.src, p.pos, '}') orelse return p.fail(error.YaraSyntax);
    const inner = p.src[p.pos + 1 .. close];
    var body: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < inner.len) {
        const c = inner[i];
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
            i += 1;
        } else if (std.mem.startsWith(u8, inner[i..], "//")) {
            i = std.mem.indexOfScalarPos(u8, inner, i, '\n') orelse inner.len;
        } else if (std.mem.startsWith(u8, inner[i..], "/*")) {
            i = if (std.mem.indexOfPos(u8, inner, i + 2, "*/")) |e| e + 2 else inner.len;
        } else if (c == '[') {
            const end = std.mem.indexOfScalarPos(u8, inner, i, ']') orelse return p.failAt(at, error.YaraSyntax);
            const jump = std.mem.trim(u8, inner[i + 1 .. end], " \t");
            if (std.mem.eql(u8, jump, "-")) {
                try body.append(p.arena, '*');
            } else {
                try body.append(p.arena, '{');
                for (jump) |j| if (j != ' ' and j != '\t') try body.append(p.arena, j);
                try body.append(p.arena, '}');
            }
            i = end + 1;
        } else {
            try body.append(p.arena, c);
            i += 1;
        }
    }
    p.pos = close + 1;
    var diag: hexsig.Diag = .{};
    const pattern = hexsig.parse(p.arena, body.items, &diag) catch |err| return p.failAt(at, err);
    // ClamAV: a string must amount to at least two bytes.
    var len: usize = 0;
    for (pattern.ops) |o| len += switch (o.code) {
        .lit, .masked => o.len,
        .gapf => o.a,
        else => 1,
    };
    if (len < 2) return p.failAt(at, error.YaraShortString);
    while (true) {
        p.skip();
        const w = p.peekWord();
        if (!std.mem.eql(u8, w, "private")) break;
        p.pos += w.len;
    }
    return .{ .variants = try hexsig.expand(p.arena, pattern, .{}) };
}

fn parseRegex(p: *Parser) ParseError!StringDef {
    const at = p.pos;
    var i = p.pos + 1;
    while (i < p.src.len and p.src[i] != '/') : (i += 1) {
        if (p.src[i] == '\\') i += 1;
        if (i < p.src.len and p.src[i] == '\n') return p.failAt(at, error.YaraSyntax);
    }
    if (i >= p.src.len) return p.failAt(at, error.YaraSyntax);
    const pattern = p.src[p.pos + 1 .. i];
    if (pattern.len == 0) return p.failAt(at, error.YaraSyntax);
    p.pos = i + 1;
    var flags: regex_flags = .{};
    while (p.pos < p.src.len) : (p.pos += 1) switch (p.src[p.pos]) {
        'i' => flags.case_insensitive = true,
        's' => flags.dot_all = true,
        else => break,
    };
    while (true) {
        p.skip();
        const w = p.peekWord();
        if (w.len == 0) break;
        if (std.mem.eql(u8, w, "nocase")) {
            flags.case_insensitive = true;
        } else if (std.mem.eql(u8, w, "ascii") or std.mem.eql(u8, w, "private")) {} else if (std.mem.eql(u8, w, "wide") or std.mem.eql(u8, w, "fullword")) {
            return p.fail(error.YaraUnsupported);
        } else break;
        p.pos += w.len;
    }
    // YARA writes a slash inside a regex as `\/`.
    var unescaped: std.ArrayList(u8) = .empty;
    var j: usize = 0;
    while (j < pattern.len) : (j += 1) {
        if (pattern[j] == '\\' and j + 1 < pattern.len and pattern[j + 1] == '/') continue;
        try unescaped.append(p.arena, pattern[j]);
    }
    const program = cdb.compileRegex(p.arena, unescaped.items, flags) catch |err| return p.failAt(at, err);
    return .{ .regex = program };
}

// ---------------------------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------------------------

const Cond = struct {
    p: *Parser,
    defs: []const Def,
    ops: std.ArrayList(yc.CondOp) = .empty,
    depth: usize = 0,

    fn emit(c: *Cond, code: yc.CondCode, str: u8, k: i64) ParseError!void {
        if (c.ops.items.len >= yc.max_ops) return c.p.fail(error.YaraUnsupported);
        try c.ops.append(c.p.arena, .{ .code = code, .str = str, .k = k });
    }

    fn nest(c: *Cond) ParseError!void {
        c.depth += 1;
        if (c.depth > yc.max_depth) return c.p.fail(error.YaraUnsupported);
    }

    fn orExpr(c: *Cond) ParseError!void {
        try c.nest();
        defer c.depth -= 1;
        try c.andExpr();
        while (c.p.keyword("or")) {
            try c.andExpr();
            try c.emit(.lor, 0, 0);
        }
    }

    fn andExpr(c: *Cond) ParseError!void {
        try c.notExpr();
        while (c.p.keyword("and")) {
            try c.notExpr();
            try c.emit(.land, 0, 0);
        }
    }

    fn notExpr(c: *Cond) ParseError!void {
        if (c.p.keyword("not")) {
            try c.nest();
            defer c.depth -= 1;
            try c.notExpr();
            return c.emit(.lnot, 0, 0);
        }
        try c.relExpr();
    }

    fn relExpr(c: *Cond) ParseError!void {
        try c.bor();
        const ops = [_]struct { []const u8, yc.CondCode }{ .{ "==", .eq }, .{ "!=", .ne }, .{ "<=", .le }, .{ ">=", .ge }, .{ "<", .lt }, .{ ">", .gt } };
        for (ops) |o| {
            c.p.skip();
            // `<<` and `>>` are shifts, handled further down.
            if (std.mem.startsWith(u8, c.p.src[c.p.pos..], "<<") or std.mem.startsWith(u8, c.p.src[c.p.pos..], ">>")) break;
            if (c.p.punct(o[0])) {
                try c.bor();
                return c.emit(o[1], 0, 0);
            }
        }
        for ([_][]const u8{ "contains", "icontains", "matches", "startswith", "endswith", "iequals" }) |k| {
            if (c.p.keyword(k)) return c.p.fail(error.YaraUnsupported);
        }
    }

    fn binaryLevel(c: *Cond, comptime next: fn (*Cond) ParseError!void, comptime ops: anytype) ParseError!void {
        try next(c);
        outer: while (true) {
            inline for (ops) |o| {
                c.p.skip();
                const rest = c.p.src[c.p.pos..];
                // `|`, `&` and `^` alone, never part of `||`-like or comparison tokens.
                if (std.mem.startsWith(u8, rest, o[0]) and !(o[0].len == 1 and rest.len > 1 and (rest[1] == '=' or rest[1] == o[0][0]))) {
                    c.p.pos += o[0].len;
                    try next(c);
                    try c.emit(o[1], 0, 0);
                    continue :outer;
                }
            }
            break;
        }
    }

    fn bor(c: *Cond) ParseError!void {
        try c.binaryLevel(bxor, .{.{ "|", yc.CondCode.bor }});
    }
    fn bxor(c: *Cond) ParseError!void {
        try c.binaryLevel(band, .{.{ "^", yc.CondCode.bxor }});
    }
    fn band(c: *Cond) ParseError!void {
        try c.binaryLevel(shift, .{.{ "&", yc.CondCode.band }});
    }
    fn shift(c: *Cond) ParseError!void {
        try c.binaryLevel(add, .{ .{ "<<", yc.CondCode.shl }, .{ ">>", yc.CondCode.shr } });
    }
    fn add(c: *Cond) ParseError!void {
        try c.binaryLevel(mul, .{ .{ "+", yc.CondCode.add }, .{ "-", yc.CondCode.sub } });
    }
    fn mul(c: *Cond) ParseError!void {
        try c.binaryLevel(unary, .{ .{ "*", yc.CondCode.mul }, .{ "\\", yc.CondCode.div }, .{ "%", yc.CondCode.mod } });
    }

    fn unary(c: *Cond) ParseError!void {
        if (c.p.punct("-")) {
            try c.nest();
            defer c.depth -= 1;
            try c.unary();
            return c.emit(.neg, 0, 0);
        }
        if (c.p.punct("~")) {
            try c.nest();
            defer c.depth -= 1;
            try c.unary();
            return c.emit(.bnot, 0, 0);
        }
        try c.primary();
    }

    fn stringIndex(c: *Cond, name: []const u8) ParseError!u8 {
        for (c.defs, 0..) |d, i| if (std.mem.eql(u8, d.name, name)) return @intCast(i);
        return c.p.fail(error.YaraSyntax);
    }

    fn sigil(c: *Cond, s: u8) ParseError![]const u8 {
        c.p.pos += 1; // the sigil
        const name = c.p.peekWord();
        if (name.len == 0) return c.p.fail(error.YaraUnsupported); // anonymous strings need `for`
        c.p.pos += name.len;
        _ = s;
        return name;
    }

    fn primary(c: *Cond) ParseError!void {
        const p = c.p;
        p.skip();
        if (p.pos >= p.src.len) return p.fail(error.YaraSyntax);
        const ch = p.src[p.pos];
        switch (ch) {
            '(' => {
                p.pos += 1;
                try c.orExpr();
                return p.expect(")");
            },
            '$' => {
                const idx = try c.stringIndex(try c.sigil('$'));
                if (p.keyword("at")) {
                    try c.add();
                    return c.emit(.at, idx, 0);
                }
                if (p.keyword("in")) {
                    try p.expect("(");
                    try c.add();
                    try p.expect("..");
                    try c.add();
                    try p.expect(")");
                    return c.emit(.in, idx, 0);
                }
                return c.emit(.found, idx, 0);
            },
            '#' => {
                const idx = try c.stringIndex(try c.sigil('#'));
                if (p.keyword("in")) return p.fail(error.YaraUnsupported);
                return c.emit(.count, idx, 0);
            },
            '@' => {
                const idx = try c.stringIndex(try c.sigil('@'));
                if (p.punct("[")) {
                    try c.orExpr();
                    try p.expect("]");
                } else try c.emit(.push, 0, 1);
                return c.emit(.offset, idx, 0);
            },
            '!' => return p.fail(error.YaraUnsupported),
            '0'...'9' => {
                const n = try p.integer();
                if (p.keyword("of")) return c.quantifier(.{ .at_least = n });
                return c.emit(.push, 0, n);
            },
            else => {},
        }
        const w = p.peekWord();
        if (w.len == 0) return p.fail(error.YaraSyntax);
        for ([_][]const u8{ "and", "or", "not", "of", "them", "at", "in", "condition", "strings", "meta", "rule" }) |k| {
            if (std.mem.eql(u8, w, k)) return p.fail(error.YaraSyntax);
        }
        const reads = [_]struct { []const u8, i64, u8 }{
            .{ "uint8", 1, 0 },    .{ "uint16", 2, 0 },   .{ "uint32", 4, 0 },
            .{ "uint16be", 2, 1 }, .{ "uint32be", 4, 1 }, .{ "int8", 1, 2 },
            .{ "int16", 2, 2 },    .{ "int32", 4, 2 },    .{ "int16be", 2, 3 },
            .{ "int32be", 4, 3 },  .{ "uint8be", 1, 1 },  .{ "int8be", 1, 3 },
        };
        for (reads) |r| if (std.mem.eql(u8, w, r[0])) {
            p.pos += w.len;
            try p.expect("(");
            try c.orExpr();
            try p.expect(")");
            return c.emit(.read, r[2], r[1]);
        };
        if (std.mem.eql(u8, w, "true") or std.mem.eql(u8, w, "false")) {
            p.pos += w.len;
            return c.emit(.push, 0, @intFromBool(w[0] == 't'));
        }
        if (std.mem.eql(u8, w, "filesize")) {
            p.pos += w.len;
            return c.emit(.filesize, 0, 0);
        }
        if (std.mem.eql(u8, w, "all") or std.mem.eql(u8, w, "any") or std.mem.eql(u8, w, "none")) {
            p.pos += w.len;
            if (!p.keyword("of")) return p.fail(error.YaraSyntax);
            return c.quantifier(switch (w[1]) {
                'l' => .all,
                'n' => .any,
                else => .none,
            });
        }
        // `for` loops, `entrypoint`, module identifiers and references to other rules.
        return p.fail(error.YaraUnsupported);
    }

    const Quant = union(enum) { at_least: i64, all, any, none };

    /// `N of (set)` and friends: the number of strings found, compared.
    fn quantifier(c: *Cond, q: Quant) ParseError!void {
        const p = c.p;
        var set: [max_strings]u8 = undefined;
        var n: usize = 0;
        if (p.keyword("them")) {
            for (c.defs, 0..) |_, i| {
                set[n] = @intCast(i);
                n += 1;
            }
        } else {
            try p.expect("(");
            while (true) {
                p.skip();
                if (p.pos >= p.src.len or p.src[p.pos] != '$') return p.fail(error.YaraUnsupported); // rule sets
                p.pos += 1;
                const name = p.peekWord();
                p.pos += name.len;
                const wildcard = p.punct("*");
                var matched = false;
                for (c.defs, 0..) |d, i| {
                    const hit = if (wildcard) std.mem.startsWith(u8, d.name, name) else std.mem.eql(u8, d.name, name);
                    if (!hit) continue;
                    matched = true;
                    if (std.mem.indexOfScalar(u8, set[0..n], @intCast(i)) == null) {
                        set[n] = @intCast(i);
                        n += 1;
                    }
                }
                if (!matched) return p.fail(error.YaraSyntax);
                if (!p.punct(",")) break;
            }
            try p.expect(")");
        }
        if (p.keyword("at") or p.keyword("in")) return p.fail(error.YaraUnsupported);
        for (set[0..n], 0..) |s, i| {
            try c.emit(.found, s, 0);
            if (i > 0) try c.emit(.add, 0, 0);
        }
        switch (q) {
            .at_least => |k| {
                try c.emit(.push, 0, k);
                try c.emit(.ge, 0, 0);
            },
            .any => {
                try c.emit(.push, 0, 1);
                try c.emit(.ge, 0, 0);
            },
            .all => {
                try c.emit(.push, 0, @intCast(n));
                try c.emit(.eq, 0, 0);
            },
            .none => {
                try c.emit(.push, 0, 0);
                try c.emit(.eq, 0, 0);
            },
        }
    }
};

const testing = std.testing;

fn parseAll(arena: std.mem.Allocator, text: []const u8, rules: *std.ArrayList(Rule), rejected: *std.ArrayList(ir.Rejection)) !void {
    try parse(arena, arena, "test.yar", text, .{ .rules = rules, .rejected = rejected });
}

test "rules with every supported string and condition form compile" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var rules: std.ArrayList(Rule) = .empty;
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    try parseAll(a,
        \\import "pe"
        \\// a comment
        \\rule Text : tag1 tag2 {
        \\  meta:
        \\    author = "x"
        \\    score = 10
        \\    ok = true
        \\  strings:
        \\    $a = "eval(" nocase
        \\    $b = "kernel32" wide ascii fullword
        \\    $c = "\x4dZ\"q" xor(1-3)
        \\  condition:
        \\    $a and #b > 1 and @b[1] < 100 or $c at 0
        \\}
        \\private rule Hex {
        \\  strings:
        \\    $h = { 4D 5A [2-4] 00 (90 | CC ??) ~00 [-] 50 45 /* pe */ }
        \\    $r = /https?:\/\/[a-z]+\.example/i
        \\  condition:
        \\    uint16(0) == 0x5A4D and $h in (0..filesize) and 1 of ($h, $r) and filesize < 2MB
        \\}
        \\rule Sets {
        \\  strings:
        \\    $s1 = "one!" $s2 = "two!" $x = "three"
        \\  condition:
        \\    2 of ($s*) and all of them or none of ($x) and (uint32be(4) & 0xff) == 7 and ~0 == -1
        \\}
        \\rule Always { strings: $a = "zz" condition: $a or not $a }
        \\rule Shapes { strings: $a = /(?:ab|cd)+x/ $b = /<script.+?>/i $c = /(\x90|\xcc){4,}/ condition: any of them }
        \\
    , &rules, &rejected);
    try testing.expectEqual(@as(usize, 0), rejected.items.len);
    try testing.expectEqual(@as(usize, 5), rules.items.len);
    for (rules.items[4].strings) |str| try testing.expect(str.regex != null);
    const t = rules.items[0];
    try testing.expectEqualStrings("Text", t.name);
    try testing.expectEqual(@as(usize, 3), t.strings.len);
    try testing.expectEqual(@as(usize, 2), t.strings[1].variants.len); // ascii and wide
    try testing.expect(t.strings[1].fullword);
    try testing.expectEqual(@as(usize, 3), t.strings[2].variants.len); // three xor keys
    try testing.expectEqual(@as(u8, 0x4c), t.strings[2].variants[0].pattern.data[0]); // 0x4d ^ 1
    try testing.expect(!t.always);
    try testing.expect(rules.items[1].private);
    try testing.expect(rules.items[1].strings[1].regex != null);
    try testing.expect(rules.items[3].always);
}

test "rejections carry reasons and parsing resumes at the next rule" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var rules: std.ArrayList(Rule) = .empty;
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    try parseAll(a,
        \\rule Module { strings: $a = "MZ" condition: $a and pe.number_of_sections > 2 }
        \\global rule Global { strings: $a = "MZ" condition: $a }
        \\rule Loop { strings: $a = "MZ" condition: for any i in (1..#a): (@a[i] > 10) }
        \\rule Ref { strings: $a = "MZ" condition: $a and Module }
        \\rule Short { strings: $a = "M" condition: $a }
        \\rule NoStrings { condition: filesize < 10 }
        \\rule TooManyXor { strings: $a = "MZ" xor condition: $a }
        \\rule Base64 { strings: $a = "MZMZ" base64 condition: $a }
        \\rule WideRegex { strings: $a = /abc/ wide condition: $a }
        \\rule BadRegex { strings: $a = /(ab/ condition: $a }
        \\rule Backref { strings: $a = /(a)\1/ condition: $a }
        \\rule Contains { strings: $a = "MZ" condition: $a contains "x" }
        \\rule BadHex { strings: $a = { 4D ( 5A } condition: $a }
        \\rule Syntax { strings: $a = "MZ" condition: $a and and }
        \\include "other.yar"
        \\rule Good { strings: $a = "MZ" condition: $a }
        \\
    , &rules, &rejected);
    try testing.expectEqual(@as(usize, 1), rules.items.len);
    try testing.expectEqualStrings("Good", rules.items[0].name);
    const want = [_]ir.Reason{
        .yara_unsupported,  .yara_unsupported, .yara_unsupported,    .yara_unsupported, .yara_short_string,
        .yara_no_strings,   .yara_xor_range,   .yara_unsupported,    .yara_unsupported, .regex_syntax,
        .regex_unsupported, .yara_unsupported, .hex_bad_alternation, .yara_syntax,      .yara_unsupported,
    };
    try testing.expectEqual(want.len, rejected.items.len);
    for (want, rejected.items, 1..) |w, r, line| {
        testing.expectEqual(w, r.reason) catch |err| {
            std.debug.print("line {d}\n", .{line});
            return err;
        };
        try testing.expectEqual(@as(u32, @intCast(line)), r.line_number);
    }
}

test "65 strings are too many" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(a, "rule Many { strings: ");
    for (0..max_strings + 1) |i| try text.print(a, "$s{d} = \"ab{d}\" ", .{ i, i });
    try text.appendSlice(a, "condition: any of them }");
    var rules: std.ArrayList(Rule) = .empty;
    var rejected: std.ArrayList(ir.Rejection) = .empty;
    try parseAll(a, text.items, &rules, &rejected);
    try testing.expectEqual(ir.Reason.too_many_subsigs, rejected.items[0].reason);
}
