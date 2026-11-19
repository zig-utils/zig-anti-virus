//! The hex body tokenizer and parser, the printer, and compile-time modifier expansion
//! (docs/DESIGN.md section 4.1). Implemented from ClamAV's body signature format documentation.
//!
//! Grammar, as documented:
//! - `aa` literal byte; `??` any byte; `a?` high nibble; `?a` low nibble.
//! - `~aa`, `~a?`, `~?a`: any byte except that byte or nibble (functionality level 240).
//! - `{n}` below 128 skips n bytes inside a part; `{n}` from 128 on, `{-n}`, `{n-}`, `{n-m}`,
//!   `*` and `[n-m]` (m at most 32) split the body into parts with a gap window between them.
//! - `(aa|bb)` alternation; `!(aa|bb)` negated alternation of equal-length literals; generic
//!   alternatives may differ in length and hold nibble wildcards and `{n}` below 128.
//! - `(B)` word boundary, `(L)` line marker, `(W)` non-alphanumeric byte.
//!
//! Every part must contain a static byte; ClamAV bodies (`parseClamav`) need two consecutive
//! literal bytes outside alternations in every part, as libclamav requires
//! (tests/differential/cases/hex-rules.case). A gap maximum of 0 means no maximum, and a
//! minimum above a nonzero maximum is accepted and never matches, as in libclamav. Every
//! rejection carries the byte position of the construct that caused it.
const std = @import("std");
const ir = @import("ir.zig");
const Allocator = std.mem.Allocator;

pub const Error = error{
    Empty,
    OddNibble,
    BadChar,
    BadRange,
    BadAlternation,
    BadNegation,
    EmptyPart,
    NoStaticByte,
    TooComplex,
    BadModifier,
} || Allocator.Error;

pub fn reasonOf(err: Error) ir.Reason {
    return switch (err) {
        error.Empty => .hex_empty,
        error.OddNibble => .hex_odd_nibble,
        error.BadChar => .hex_bad_char,
        error.BadRange => .hex_bad_range,
        error.BadAlternation => .hex_bad_alternation,
        error.BadNegation => .hex_bad_negation,
        error.EmptyPart => .hex_empty_part,
        error.NoStaticByte => .hex_no_static_byte,
        error.TooComplex => .hex_too_complex,
        error.BadModifier => .bad_modifier,
        error.OutOfMemory => .hex_too_complex,
    };
}

/// Where a rejected construct starts.
pub const Diag = struct { pos: u32 = 0 };

/// Limits that keep every program small and the verify VM's recursion shallow.
pub const limits = struct {
    pub const max_body_len: usize = 1 << 20;
    pub const max_ops: usize = 65535;
    pub const max_parts: usize = 255;
    /// Alternations and character classes in one pattern (each is a VM branch point).
    pub const max_branches: usize = 64;
    pub const max_alternatives: usize = 256;
    pub const max_op_len: usize = 65535;
    pub const max_gap: u32 = 0x7fff_ffff;
};

/// Builds ops and the data area they point into. Literal runs grow in place; masked runs are
/// buffered so values and masks stay contiguous.
const Emitter = struct {
    arena: Allocator,
    ops: std.ArrayList(ir.Op) = .empty,
    data: *std.ArrayList(u8),
    mvals: std.ArrayList(u8) = .empty,
    mmasks: std.ArrayList(u8) = .empty,

    fn flushMasked(e: *Emitter) Allocator.Error!void {
        const n = e.mvals.items.len;
        if (n == 0) return;
        const a: u32 = @intCast(e.data.items.len);
        try e.data.appendSlice(e.arena, e.mvals.items);
        try e.data.appendSlice(e.arena, e.mmasks.items);
        try e.ops.append(e.arena, .{ .code = .masked, .len = @intCast(n), .a = a });
        e.mvals.clearRetainingCapacity();
        e.mmasks.clearRetainingCapacity();
    }

    fn lit(e: *Emitter, byte: u8, flags: u8) Allocator.Error!void {
        try e.flushMasked();
        if (e.ops.items.len > 0) {
            const last = &e.ops.items[e.ops.items.len - 1];
            if (last.code == .lit and last.flags == flags and last.a + last.len == e.data.items.len and last.len < limits.max_op_len) {
                last.len += 1;
                try e.data.append(e.arena, byte);
                return;
            }
        }
        try e.ops.append(e.arena, .{ .code = .lit, .flags = flags, .len = 1, .a = @intCast(e.data.items.len) });
        try e.data.append(e.arena, byte);
    }

    fn masked(e: *Emitter, value: u8, mask: u8) Allocator.Error!void {
        if (e.mvals.items.len == limits.max_op_len) try e.flushMasked();
        try e.mvals.append(e.arena, value & mask);
        try e.mmasks.append(e.arena, mask);
    }

    fn negated(e: *Emitter, value: u8, mask: u8) Allocator.Error!void {
        try e.flushMasked();
        const a: u32 = @intCast(e.data.items.len);
        try e.data.appendSlice(e.arena, &.{ value & mask, mask });
        try e.ops.append(e.arena, .{ .code = .masked, .flags = ir.op_negate, .len = 1, .a = a });
    }

    fn op(e: *Emitter, o: ir.Op) Allocator.Error!void {
        try e.flushMasked();
        try e.ops.append(e.arena, o);
    }

    fn pad(e: *Emitter) Allocator.Error!void {
        while (e.data.items.len % 4 != 0) try e.data.append(e.arena, 0);
    }

    /// Write `subs` (finished emitters sharing this data area) as an alternation table.
    fn altTable(e: *Emitter, code: ir.OpCode, flags: u8, subs: []Emitter) Allocator.Error!void {
        try e.flushMasked();
        var entries: std.ArrayList(ir.AltEntry) = .empty;
        var min_len: u32 = std.math.maxInt(u16);
        var max_len: u32 = 0;
        for (subs) |*s| {
            try s.flushMasked();
            try e.pad();
            const off: u32 = @intCast(e.data.items.len);
            try e.data.appendSlice(e.arena, std.mem.sliceAsBytes(s.ops.items));
            const len = byteLen(s.ops.items);
            min_len = @min(min_len, len);
            max_len = @max(max_len, len);
            try entries.append(e.arena, .{ .ops_off = off, .op_count = @intCast(s.ops.items.len), .byte_len = @intCast(len) });
        }
        try e.pad();
        const table: u32 = @intCast(e.data.items.len);
        try e.data.appendSlice(e.arena, std.mem.sliceAsBytes(entries.items));
        try e.ops.append(e.arena, .{ .code = code, .flags = flags, .len = @intCast(subs.len), .a = table, .b = min_len | max_len << 16 });
    }

    fn finish(e: *Emitter) Allocator.Error!ir.Pattern {
        try e.flushMasked();
        const data = try e.arena.alignedAlloc(u8, .@"4", e.data.items.len);
        @memcpy(data, e.data.items);
        return .{ .ops = e.ops.items, .data = data };
    }
};

/// Bytes a straight-line op list (an alternative) consumes.
fn byteLen(ops: []const ir.Op) u32 {
    var n: u32 = 0;
    for (ops) |o| n += switch (o.code) {
        .lit, .masked => o.len,
        .gapf => o.a,
        else => 0,
    };
    return n;
}

fn nibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn isNibbleChar(c: u8) bool {
    return c == '?' or nibble(c) != null;
}

const Parser = struct {
    body: []const u8,
    pos: usize = 0,
    diag: *Diag,
    emitter: Emitter,
    part_start: usize = 0,
    /// The part holds two consecutive literal bytes (outside alternations), which libclamav
    /// requires of every part.
    part_static: bool = false,
    /// Literal bytes in a row at the end of the current part.
    run_len: usize = 0,
    /// libclamav's rule: a part needs two literal bytes in a row (`Options.literal_pairs`).
    pairs: bool = false,
    strict_brackets: bool = true,
    /// What the part after a `[x-y]` gap must be: the single byte, or a part with static bytes.
    bracket_next: enum { none, single, static } = .none,
    parts: usize = 1,
    branches: usize = 0,

    fn fail(p: *Parser, at: usize, err: Error) Error {
        p.diag.pos = @intCast(at);
        return err;
    }

    fn peek(p: *Parser, ahead: usize) ?u8 {
        return if (p.pos + ahead < p.body.len) p.body[p.pos + ahead] else null;
    }

    /// Two nibble characters at the cursor: value and mask.
    fn byteToken(p: *Parser) Error!struct { value: u8, mask: u8 } {
        const start = p.pos;
        const hi = p.peek(0) orelse return p.fail(start, error.OddNibble);
        const lo = p.peek(1) orelse return p.fail(start, error.OddNibble);
        if (!isNibbleChar(hi)) return p.fail(start, error.BadChar);
        if (!isNibbleChar(lo)) {
            if (isStructural(lo)) return p.fail(start, error.OddNibble);
            return p.fail(start + 1, error.BadChar);
        }
        p.pos += 2;
        const vh = nibble(hi) orelse 0;
        const vl = nibble(lo) orelse 0;
        const mh: u8 = if (hi == '?') 0 else 0xf0;
        const ml: u8 = if (lo == '?') 0 else 0x0f;
        return .{ .value = (vh << 4) | vl, .mask = mh | ml };
    }

    fn number(p: *Parser) Error!u32 {
        const start = p.pos;
        var v: u64 = 0;
        while (p.peek(0)) |c| {
            if (c < '0' or c > '9') break;
            v = v * 10 + (c - '0');
            if (v > limits.max_gap) return p.fail(start, error.BadRange);
            p.pos += 1;
        }
        if (p.pos == start) return p.fail(start, error.BadRange);
        return @intCast(v);
    }

    fn expect(p: *Parser, c: u8, err: Error) Error!void {
        if (p.peek(0) != c) return p.fail(p.pos, err);
        p.pos += 1;
    }

    fn breakPart(p: *Parser, at: usize, min: u32, max: u32, syntax: ir.GapSyntax) Error!void {
        try p.endPart(at);
        if ((syntax == .bracket or syntax == .bracket_one) and p.strict_brackets) {
            // `BYTE[x-y]HEXSIG` or `HEXSIG[x-y]BYTE`: one side is a single literal byte.
            if (p.singleByte()) {
                p.bracket_next = .static;
            } else if (p.part_static) {
                p.bracket_next = .single;
            } else return p.fail(at, error.NoStaticByte);
        } else p.bracket_next = .none;
        if (p.parts == limits.max_parts) return p.fail(at, error.TooComplex);
        try p.emitter.op(.{ .code = .part_end, .flags = @backingInt(syntax), .a = min, .b = max });
        p.parts += 1;
        p.part_start = p.emitter.ops.items.len;
        p.part_static = false;
        p.run_len = 0;
    }

    fn endPart(p: *Parser, at: usize) Error!void {
        try p.emitter.flushMasked();
        if (p.emitter.ops.items.len == p.part_start) return p.fail(at, error.EmptyPart);
        switch (p.bracket_next) {
            .single => if (!p.singleByte()) return p.fail(at, error.BadRange),
            // A single byte after `[x-y]` may itself face another bracket gap.
            .none, .static => if (!p.part_static and !(p.singleByte() and at < p.body.len and p.body[at] == '[')) return p.fail(at, error.NoStaticByte),
        }
    }

    /// The current part is one literal byte.
    fn singleByte(p: *Parser) bool {
        const ops = p.emitter.ops.items[p.part_start..];
        return ops.len == 1 and ops[0].code == .lit and ops[0].len == 1;
    }

    fn branch(p: *Parser, at: usize) Error!void {
        p.branches += 1;
        if (p.branches > limits.max_branches) return p.fail(at, error.TooComplex);
    }

    fn run(p: *Parser) Error!void {
        while (p.pos < p.body.len) {
            const start = p.pos;
            const c = p.body[p.pos];
            switch (c) {
                ' ', '\t' => p.pos += 1,
                '0'...'9', 'a'...'f', 'A'...'F', '?' => {
                    const t = try p.byteToken();
                    if (t.mask == 0xff) {
                        try p.emitter.lit(t.value, 0);
                        p.run_len += 1;
                        if (p.run_len >= 2 or !p.pairs) p.part_static = true;
                    } else {
                        try p.emitter.masked(t.value, t.mask);
                        p.run_len = 0;
                    }
                },
                '~' => {
                    p.run_len = 0;
                    p.pos += 1;
                    const next = p.peek(0) orelse return p.fail(start, error.BadNegation);
                    if (!isNibbleChar(next)) return p.fail(start, error.BadNegation);
                    const t = p.byteToken() catch return p.fail(start, error.BadNegation);
                    if (t.mask == 0) return p.fail(start, error.BadNegation);
                    try p.emitter.negated(t.value, t.mask);
                },
                '*' => {
                    p.pos += 1;
                    try p.breakPart(start, 0, ir.unbounded, .star);
                },
                '{' => {
                    // libclamav reads a maximum of 0 as no maximum: `{0}`, `{-0}` and `{n-0}`
                    // are unbounded. A minimum above a nonzero maximum loads and never matches.
                    p.pos += 1;
                    if (p.peek(0) == '-') {
                        p.pos += 1;
                        const n = try p.number();
                        try p.expect('}', error.BadRange);
                        try p.breakPart(start, 0, if (n == 0) ir.unbounded else n, .upto);
                    } else {
                        const n = try p.number();
                        if (p.peek(0) == '}') {
                            p.pos += 1;
                            if (n == 0) {
                                try p.breakPart(start, 0, ir.unbounded, .exact);
                            } else if (n < ir.inline_gap_limit) {
                                try p.emitter.op(.{ .code = .gapf, .a = n });
                                p.run_len = 0;
                            } else try p.breakPart(start, n, n, .exact);
                        } else {
                            try p.expect('-', error.BadRange);
                            if (p.peek(0) == '}') {
                                p.pos += 1;
                                try p.breakPart(start, n, ir.unbounded, .from);
                            } else {
                                const m = try p.number();
                                try p.expect('}', error.BadRange);
                                try p.breakPart(start, n, if (m == 0) ir.unbounded else m, .range);
                            }
                        }
                    }
                },
                '[' => {
                    // `[n-m]`, or `[n]` for exactly n.
                    p.pos += 1;
                    const n = try p.number();
                    var m = n;
                    var syntax: ir.GapSyntax = .bracket_one;
                    if (p.peek(0) == '-') {
                        p.pos += 1;
                        m = try p.number();
                        syntax = .bracket;
                    }
                    try p.expect(']', error.BadRange);
                    if (m < n or (p.strict_brackets and m > ir.bracket_limit)) return p.fail(start, error.BadRange);
                    try p.breakPart(start, n, m, syntax);
                },
                '(' => {
                    if (p.peek(2) == ')' and p.peek(1) != null) {
                        const class: ?ir.Bound = switch (p.peek(1).?) {
                            'B' => .word,
                            'L' => .line,
                            'W' => .nonalnum,
                            else => null,
                        };
                        if (class) |b| {
                            p.pos += 3;
                            p.run_len = 0;
                            try p.emitter.op(.{ .code = .bound, .flags = @backingInt(b) });
                            continue;
                        }
                    }
                    try p.alternation(start, false);
                    p.run_len = 0;
                },
                '!' => {
                    if (p.peek(1) != '(') return p.fail(start, error.BadAlternation);
                    p.pos += 1;
                    try p.alternation(start, true);
                    p.run_len = 0;
                },
                ')', '|' => return p.fail(start, error.BadAlternation),
                else => return p.fail(start, error.BadChar),
            }
            if (p.emitter.ops.items.len + p.emitter.mvals.items.len > limits.max_ops) return p.fail(start, error.TooComplex);
        }
        try p.endPart(p.body.len);
    }

    fn alternation(p: *Parser, start: usize, negated: bool) Error!void {
        p.pos += 1; // '('
        // A negation is checked in place; only alternations are VM branch points.
        if (!negated) try p.branch(start);
        var subs: std.ArrayList(Emitter) = .empty;
        var all_literal = true;
        var cur: Emitter = .{ .arena = p.emitter.arena, .data = p.emitter.data };
        while (true) {
            const at = p.pos;
            const c = p.peek(0) orelse return p.fail(start, error.BadAlternation);
            switch (c) {
                '|', ')' => {
                    try cur.flushMasked();
                    // An empty alternative makes the alternation optional, except first (where
                    // libclamav refuses it) and in a negation.
                    if (cur.ops.items.len == 0 and (subs.items.len == 0 or negated)) return p.fail(at, error.BadAlternation);
                    if (subs.items.len == limits.max_alternatives) return p.fail(at, error.TooComplex);
                    try subs.append(p.emitter.arena, cur);
                    cur = .{ .arena = p.emitter.arena, .data = p.emitter.data };
                    p.pos += 1;
                    if (c == ')') break;
                },
                '0'...'9', 'a'...'f', 'A'...'F', '?' => {
                    const t = try p.byteToken();
                    if (t.mask == 0xff) try cur.lit(t.value, 0) else {
                        all_literal = false;
                        try cur.masked(t.value, t.mask);
                    }
                },
                '{' => {
                    p.pos += 1;
                    const n = p.number() catch return p.fail(at, error.BadAlternation);
                    p.expect('}', error.BadAlternation) catch return p.fail(at, error.BadAlternation);
                    if (n == 0 or n >= ir.inline_gap_limit) return p.fail(at, error.BadAlternation);
                    all_literal = false;
                    try cur.op(.{ .code = .gapf, .a = n });
                },
                '~' => return p.fail(at, error.BadNegation),
                else => return p.fail(at, error.BadAlternation),
            }
        }
        var equal = true;
        const first_len = byteLen(subs.items[0].ops.items);
        for (subs.items) |s| {
            const len = byteLen(s.ops.items);
            if (len != first_len) equal = false;
            if (len > limits.max_op_len) return p.fail(start, error.TooComplex);
        }
        if (negated) {
            if (!all_literal or !equal) return p.fail(start, error.BadAlternation);
            try p.emitter.altTable(.nalt, 0, subs.items);
        } else {
            try p.emitter.altTable(.alt, 0, subs.items);
            if (all_literal and !p.pairs) p.part_static = true;
        }
    }
};

fn isStructural(c: u8) bool {
    return switch (c) {
        '*', '{', '}', '[', ']', '(', ')', '|', '!', '~' => true,
        else => false,
    };
}

pub const Options = struct {
    /// Require two consecutive literal bytes (outside alternations) in every part, as
    /// libclamav does for .ndb bodies and logical subsignatures; otherwise one static byte (a
    /// literal or an all-literal alternation) is enough.
    literal_pairs: bool = false,
    /// `[x-y]` needs a single literal byte on one side and y at most 32. libclamav drops both
    /// rules for `::w` subsignatures, where `[x-y]` is an ordinary gap.
    strict_brackets: bool = true,
};

/// libclamav's rules for a body with these modifiers: `::w` alone (not `::wa`) widens every
/// literal byte into two, so single bytes satisfy the literal-pair rule, and brackets are gaps.
pub fn clamavOptions(mods: ir.Modifiers) Options {
    const wide_only = mods.wide and !mods.ascii;
    return .{ .literal_pairs = !wide_only, .strict_brackets = !wide_only };
}

/// Parse a hex body. All memory comes from `arena`.
pub fn parse(arena: Allocator, body: []const u8, diag: *Diag) Error!ir.Pattern {
    return parseWith(arena, body, diag, .{});
}

/// Parse a ClamAV body signature (.ndb or logical subsignature), with libclamav's rules.
pub fn parseClamav(arena: Allocator, body: []const u8, diag: *Diag) Error!ir.Pattern {
    return parseWith(arena, body, diag, .{ .literal_pairs = true });
}

pub fn parseWith(arena: Allocator, body: []const u8, diag: *Diag, options: Options) Error!ir.Pattern {
    if (std.mem.trim(u8, body, " \t").len == 0) return error.Empty;
    if (body.len > limits.max_body_len) return error.TooComplex;
    const data = try arena.create(std.ArrayList(u8));
    data.* = .empty;
    var p: Parser = .{ .body = body, .diag = diag, .emitter = .{ .arena = arena, .data = data }, .pairs = options.literal_pairs, .strict_brackets = options.strict_brackets };
    try p.run();
    return p.emitter.finish();
}

// ---------------------------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------------------------

/// Write the pattern back in body syntax (lower-case hex).
pub fn format(p: ir.Pattern, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try formatOps(p, p.ops, w);
}

fn formatOps(p: ir.Pattern, ops: []const ir.Op, w: *std.Io.Writer) std.Io.Writer.Error!void {
    for (ops) |o| switch (o.code) {
        .lit => for (p.bytes(o)) |b| try w.print("{x:0>2}", .{b}),
        .masked => for (p.bytes(o), p.masks(o)) |v, m| {
            if (o.flags & ir.op_negate != 0) try w.writeByte('~');
            try formatMasked(v, m, w);
        },
        .gapf => try w.print("{{{d}}}", .{o.a}),
        .bound => try w.writeAll(switch (@as(ir.Bound, @fromBackingInt(o.flags))) {
            .word => "(B)",
            .line => "(L)",
            .nonalnum => "(W)",
        }),
        .part_end => switch (@as(ir.GapSyntax, @fromBackingInt(o.flags))) {
            .star => try w.writeByte('*'),
            .range => if (o.b == ir.unbounded) try w.print("{{{d}-0}}", .{o.a}) else try w.print("{{{d}-{d}}}", .{ o.a, o.b }),
            .upto => try w.print("{{-{d}}}", .{if (o.b == ir.unbounded) 0 else o.b}),
            .from => try w.print("{{{d}-}}", .{o.a}),
            .exact => try w.print("{{{d}}}", .{o.a}),
            .bracket => try w.print("[{d}-{d}]", .{ o.a, o.b }),
            .bracket_one => try w.print("[{d}]", .{o.a}),
        },
        .alt, .nalt => {
            if (o.code == .nalt) try w.writeByte('!');
            try w.writeByte('(');
            for (p.alternatives(o), 0..) |entry, i| {
                if (i > 0) try w.writeByte('|');
                try formatOps(p, p.altOps(entry), w);
            }
            try w.writeByte(')');
        },
        _ => try w.writeAll("<bad op>"),
    };
}

fn formatMasked(v: u8, m: u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
    const hex = "0123456789abcdef";
    try w.writeByte(if (m & 0xf0 != 0) hex[v >> 4] else '?');
    try w.writeByte(if (m & 0x0f != 0) hex[v & 0xf] else '?');
}

// ---------------------------------------------------------------------------------------------
// Compile-time expansion
// ---------------------------------------------------------------------------------------------

pub const Variant = struct {
    pattern: ir.Pattern,
    /// Some ops still compare case-insensitively: the subsig belongs in a folded partition.
    folded: bool = false,
    /// The `::w` form: literal bytes are 00-interleaved.
    wide: bool = false,
};

/// Most variants one subsignature expands into.
pub const max_variants: usize = 16;

/// Apply modifiers at compile time: wide becomes 00-interleaved literals (`::wa` keeps both
/// forms), nocase becomes up to 16 case variants or folded compares, and small literal
/// alternations become literal variants while the total stays at or under `max_variants`.
pub fn expand(arena: Allocator, pattern: ir.Pattern, mods: ir.Modifiers) Error![]Variant {
    // `wide[i]` says whether `list[i]` is the wide form.
    var list: std.ArrayList(ir.Pattern) = .empty;
    var wide: std.ArrayList(bool) = .empty;
    if (mods.wide) {
        if (mods.ascii) {
            try list.append(arena, pattern);
            try wide.append(arena, false);
        }
        try list.append(arena, try widen(arena, pattern));
        try wide.append(arena, true);
    } else {
        try list.append(arena, pattern);
        try wide.append(arena, false);
    }

    var folded = false;
    if (mods.nocase) {
        const k = alphaLits(pattern);
        if (k <= 4 and (@as(usize, 1) << @intCast(k)) * list.items.len <= max_variants) {
            var cased: std.ArrayList(ir.Pattern) = .empty;
            var cased_wide: std.ArrayList(bool) = .empty;
            for (list.items, wide.items) |p, w| {
                var bits: usize = 0;
                while (bits < (@as(usize, 1) << @intCast(k))) : (bits += 1) {
                    try cased.append(arena, try caseVariant(arena, p, bits));
                    try cased_wide.append(arena, w);
                }
            }
            list = cased;
            wide = cased_wide;
        } else {
            for (list.items) |*p| p.* = try fold(arena, p.*);
        }
        for (list.items) |p| folded = folded or hasNocase(p);
    }

    // Literal alternations, while the product stays small.
    var changed = true;
    while (changed) {
        changed = false;
        var next: std.ArrayList(ir.Pattern) = .empty;
        var next_wide: std.ArrayList(bool) = .empty;
        for (list.items, wide.items, 0..) |p, w, i| {
            const idx = expandableAlt(p) orelse {
                try next.append(arena, p);
                try next_wide.append(arena, w);
                continue;
            };
            const n = p.ops[idx].len;
            if (next.items.len + (list.items.len - i - 1) + n > max_variants) {
                try next.append(arena, p);
                try next_wide.append(arena, w);
                continue;
            }
            for (0..n) |j| {
                try next.append(arena, try pickAlternative(arena, p, idx, j));
                try next_wide.append(arena, w);
            }
            changed = true;
        }
        list = next;
        wide = next_wide;
    }

    const out = try arena.alloc(Variant, list.items.len);
    for (list.items, wide.items, out) |p, w, *v| v.* = .{ .pattern = p, .folded = folded, .wide = w };
    return out;
}

const Mode = enum { copy, widen };

fn newEmitter(arena: Allocator) Allocator.Error!Emitter {
    const data = try arena.create(std.ArrayList(u8));
    data.* = .empty;
    return .{ .arena = arena, .data = data };
}

/// Re-emit `o` from `src` into `e`.
fn copyOp(e: *Emitter, src: ir.Pattern, o: ir.Op, mode: Mode, extra_flags: u8) Error!void {
    switch (o.code) {
        .lit => for (src.bytes(o)) |b| {
            try e.lit(b, o.flags | extra_flags);
            if (mode == .widen) try e.lit(0, o.flags | extra_flags);
        },
        .masked => {
            if (o.flags & ir.op_negate != 0) {
                try e.negated(src.bytes(o)[0], src.masks(o)[0]);
            } else {
                for (src.bytes(o), src.masks(o)) |v, m| try e.masked(v, m);
            }
        },
        .alt, .nalt => {
            if (mode == .widen and o.code == .nalt and (o.b & 0xffff) != 1) return error.BadModifier;
            const entries = src.alternatives(o);
            const subs = try e.arena.alloc(Emitter, entries.len);
            for (entries, subs) |entry, *s| {
                s.* = .{ .arena = e.arena, .data = e.data };
                // Inside an alternation nalt widening keeps the byte set; the 00 follows below.
                const sub_mode: Mode = if (o.code == .nalt) .copy else mode;
                for (src.altOps(entry)) |inner| try copyOp(s, src, inner, sub_mode, 0);
            }
            try e.altTable(o.code, o.flags | extra_flags, subs);
            if (mode == .widen and o.code == .nalt) try e.lit(0, 0);
        },
        else => try e.op(o),
    }
}

fn widen(arena: Allocator, p: ir.Pattern) Error!ir.Pattern {
    var e = try newEmitter(arena);
    for (p.ops) |o| try copyOp(&e, p, o, .widen, 0);
    return e.finish();
}

fn fold(arena: Allocator, p: ir.Pattern) Error!ir.Pattern {
    var e = try newEmitter(arena);
    for (p.ops) |o| {
        const f: u8 = switch (o.code) {
            .lit, .alt, .nalt => ir.op_nocase,
            else => 0,
        };
        try copyOp(&e, p, o, .copy, f);
    }
    return e.finish();
}

fn isAlpha(b: u8) bool {
    return std.ascii.isAlphabetic(b);
}

fn alphaLits(p: ir.Pattern) usize {
    var n: usize = 0;
    for (p.ops) |o| if (o.code == .lit) {
        for (p.bytes(o)) |b| n += @intFromBool(isAlpha(b));
    };
    return n;
}

fn hasNocase(p: ir.Pattern) bool {
    for (p.ops) |o| if (o.flags & ir.op_nocase != 0 and (o.code == .lit or o.code == .alt or o.code == .nalt)) return true;
    return false;
}

/// One case combination of the literal letters; alternations keep a folded compare.
fn caseVariant(arena: Allocator, p: ir.Pattern, bits: usize) Error!ir.Pattern {
    var e = try newEmitter(arena);
    var k: usize = 0;
    for (p.ops) |o| switch (o.code) {
        .lit => for (p.bytes(o)) |b| {
            var out = b;
            if (isAlpha(b)) {
                out = if ((bits >> @intCast(k)) & 1 != 0) std.ascii.toUpper(b) else std.ascii.toLower(b);
                k += 1;
            }
            try e.lit(out, o.flags);
        },
        .alt, .nalt => try copyOp(&e, p, o, .copy, ir.op_nocase),
        else => try copyOp(&e, p, o, .copy, 0),
    };
    return e.finish();
}

fn expandableAlt(p: ir.Pattern) ?usize {
    for (p.ops, 0..) |o, i| {
        if (o.code != .alt or o.flags & ir.op_nocase != 0) continue;
        // Keep optional alternatives in the VM. Expanding an empty arm can remove the
        // whole pattern or a part next to a gap, leaving an invalid verify program.
        var optional = false;
        for (p.alternatives(o)) |entry| optional = optional or entry.op_count == 0;
        if (optional) continue;
        if (allLiteral(p, o)) return i;
    }
    return null;
}

/// Every alternative of an alt or nalt op is a plain literal.
pub fn allLiteral(p: ir.Pattern, o: ir.Op) bool {
    for (p.alternatives(o)) |entry| {
        for (p.altOps(entry)) |inner| if (inner.code != .lit) return false;
    }
    return true;
}

fn pickAlternative(arena: Allocator, p: ir.Pattern, idx: usize, which: usize) Error!ir.Pattern {
    var e = try newEmitter(arena);
    for (p.ops, 0..) |o, i| {
        if (i != idx) {
            try copyOp(&e, p, o, .copy, 0);
            continue;
        }
        const entry = p.alternatives(o)[which];
        for (p.altOps(entry)) |inner| try copyOp(&e, p, inner, .copy, 0);
    }
    return e.finish();
}

/// Parse a modifier string (the part after `::`).
pub fn parseModifiers(text: []const u8) error{BadModifier}!ir.Modifiers {
    var m: ir.Modifiers = .{};
    if (text.len == 0) return error.BadModifier;
    for (text) |c| switch (c) {
        'i' => m.nocase = true,
        'w' => m.wide = true,
        'a' => m.ascii = true,
        'f' => m.fullword = true,
        else => return error.BadModifier,
    };
    return m;
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

const testing = std.testing;

fn roundTrip(body: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diag: Diag = .{};
    const p = try parse(arena.allocator(), body, &diag);
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try format(p, &w);
    // Hex is printed lower case; (B), (L) and (W) keep their capitals.
    const want = try arena.allocator().dupe(u8, body);
    var i: usize = 0;
    while (i < want.len) : (i += 1) {
        if (want[i] == '(' and i + 2 < want.len and want[i + 2] == ')' and std.mem.indexOfScalar(u8, "BLW", want[i + 1]) != null) {
            i += 2;
            continue;
        }
        want[i] = std.ascii.toLower(want[i]);
    }
    try testing.expectEqualStrings(want, w.buffered());
}

fn parseErr(body: []const u8, want: anyerror, pos: u32) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diag: Diag = .{};
    try testing.expectError(want, parse(arena.allocator(), body, &diag));
    try testing.expectEqual(pos, diag.pos);
}

fn parsed(arena: *std.heap.ArenaAllocator, body: []const u8) !ir.Pattern {
    var diag: Diag = .{};
    return parse(arena.allocator(), body, &diag);
}

test "every grammar feature round-trips through print" {
    for ([_][]const u8{
        "deadbeef",
        "DEADBEEF",
        "dead??beef",
        "dead3?beef",
        "dead?3beef",
        "dead*beef",
        "dead{5}beef",
        "dead{200}beef",
        "dead{-10}beef",
        "dead{10-}beef",
        "dead{10-20}beef",
        "dead{7-7}beef",
        "aa[1-32]beef",
        "dead(aa|bb)beef",
        "dead!(aa|bb|cc)beef",
        "dead(aabb|ccdd)beef",
        "dead!(aabb|ccdd)beef",
        "dead(aa|bbcc|d?)beef",
        "dead(aa{3}bb|cc)beef",
        "(B)deadbeef(B)",
        "dead(L)beef",
        "dead(W)beef",
        "dead~aabeef",
        "dead~a?beef",
        "dead~?abeef",
        "6869*6a6b{3-4}6c6d??6e(6f|70)[2-5]71",
    }) |body| try roundTrip(body);
}

test "literal runs, masks and gaps become the documented ops" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const p = try parsed(&arena, "dead3??fbeef{5}cafe");
    try testing.expectEqual(@as(usize, 5), p.ops.len);
    try testing.expectEqual(ir.OpCode.lit, p.ops[0].code);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, p.bytes(p.ops[0]));
    try testing.expectEqual(ir.OpCode.masked, p.ops[1].code);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x0f }, p.bytes(p.ops[1]));
    try testing.expectEqualSlices(u8, &.{ 0xf0, 0x0f }, p.masks(p.ops[1]));
    try testing.expectEqual(ir.OpCode.gapf, p.ops[3].code);
    try testing.expectEqual(@as(u32, 5), p.ops[3].a);
}

test "part breaks carry their windows" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const Case = struct { []const u8, u32, u32 };
    for ([_]Case{
        .{ "aabb*ccdd", 0, ir.unbounded },
        .{ "aabb{-4}ccdd", 0, 4 },
        .{ "aabb{4-}ccdd", 4, ir.unbounded },
        .{ "aabb{4-9}ccdd", 4, 9 },
        .{ "aabb{128}ccdd", 128, 128 },
        .{ "aa[2-3]ccdd", 2, 3 },
    }) |c| {
        const p = try parsed(&arena, c[0]);
        try testing.expectEqual(@as(usize, 2), p.partCount());
        try testing.expectEqual(ir.OpCode.part_end, p.ops[1].code);
        try testing.expectEqual(c[1], p.ops[1].a);
        try testing.expectEqual(c[2], p.ops[1].b);
    }
    // {127} stays inside the part.
    try testing.expectEqual(@as(usize, 1), (try parsed(&arena, "aabb{127}ccdd")).partCount());
}

test "alternations: literal, negated, multi-byte and generic" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const p = try parsed(&arena, "aa(bbcc|d?|{2}ee)ff");
    const alt = p.ops[1];
    try testing.expectEqual(ir.OpCode.alt, alt.code);
    try testing.expectEqual(@as(u16, 3), alt.len);
    try testing.expectEqual(@as(u32, 1), alt.b & 0xffff);
    try testing.expectEqual(@as(u32, 3), alt.b >> 16);
    const entries = p.alternatives(alt);
    try testing.expectEqual(@as(u16, 2), entries[0].byte_len);
    try testing.expectEqual(ir.OpCode.masked, p.altOps(entries[1])[0].code);
    try testing.expectEqual(ir.OpCode.gapf, p.altOps(entries[2])[0].code);

    const n = try parsed(&arena, "aa!(bbcc|ddee)ff");
    try testing.expectEqual(ir.OpCode.nalt, n.ops[1].code);
    try testing.expectEqual(@as(u32, 2), n.ops[1].b & 0xffff);
}

test "negated bytes and nibbles" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const p = try parsed(&arena, "aa~bb~c?~?d");
    for (p.ops[1..]) |o| {
        try testing.expectEqual(ir.OpCode.masked, o.code);
        try testing.expect(o.flags & ir.op_negate != 0);
        try testing.expectEqual(@as(u16, 1), o.len);
    }
    try testing.expectEqual(@as(u8, 0xf0), p.masks(p.ops[2])[0]);
    try testing.expectEqual(@as(u8, 0x0f), p.masks(p.ops[3])[0]);
}

test "rejected constructs report their reason and position" {
    try parseErr("", error.Empty, 0);
    try parseErr("aab", error.OddNibble, 2);
    try parseErr("aa*b", error.OddNibble, 3);
    try parseErr("aaxz", error.BadChar, 2);
    try parseErr("aa b", error.OddNibble, 3);
    try parseErr("*aabb", error.EmptyPart, 0);
    try parseErr("aabb*", error.EmptyPart, 5);
    try parseErr("aabb**ccdd", error.EmptyPart, 5);
    try parseErr("aabb*????", error.NoStaticByte, 9);
    try parseErr("????", error.NoStaticByte, 4);
    try parseErr("aa{x}bb", error.BadRange, 3);
    try parseErr("aa{5bb", error.BadRange, 4);
    try parseErr("aa[1-33]bbcc", error.BadRange, 2);
    try parseErr("aa[3-1]bbcc", error.BadRange, 2);
    try parseErr("aa{99999999999}bb", error.BadRange, 3);
    try parseErr("aa()bb", error.BadAlternation, 3);
    try parseErr("aa(|bb)cc", error.BadAlternation, 3);
    try parseErr("aa!(bb|)cc", error.BadAlternation, 7);
    try parseErr("aa(bb|(cc))dd", error.BadAlternation, 6);
    try parseErr("aa(bb|cc", error.BadAlternation, 2);
    try parseErr("aabb)", error.BadAlternation, 4);
    try parseErr("aa|bb", error.BadAlternation, 2);
    try parseErr("aa!(b?|cc)dd", error.BadAlternation, 2);
    try parseErr("aa!(bb|ccdd)ee", error.BadAlternation, 2);
    try parseErr("aa!bb", error.BadAlternation, 2);
    try parseErr("aa(bb|{200})cc", error.BadAlternation, 6);
    try parseErr("aa(bb|*)cc", error.BadAlternation, 6);
    try parseErr("aa~~00", error.BadNegation, 2);
    try parseErr("aa~??", error.BadNegation, 2);
    try parseErr("aa~", error.BadNegation, 2);
    try parseErr("aa~(bb|cc)", error.BadNegation, 2);
    try parseErr("aa~[1-2]bb", error.BadNegation, 2);
    try parseErr("aa(~bb|cc)", error.BadNegation, 3);
    try parseErr("aa(X)bb", error.BadAlternation, 3);
}

test "complexity limits" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var body: std.ArrayList(u8) = .empty;
    for (0..limits.max_branches + 1) |_| try body.appendSlice(arena.allocator(), "aa(bb|cc)");
    var diag: Diag = .{};
    try testing.expectError(error.TooComplex, parse(arena.allocator(), body.items, &diag));
}

test "modifiers" {
    try testing.expectEqual(ir.Modifiers{ .nocase = true, .wide = true, .ascii = true, .fullword = true }, try parseModifiers("iwaf"));
    try testing.expectError(error.BadModifier, parseModifiers("x"));
    try testing.expectError(error.BadModifier, parseModifiers(""));
}

fn printed(arena: Allocator, p: ir.Pattern) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    try format(p, &w.writer);
    return w.written();
}

test "wide interleaves literal bytes with zeros, not wildcards" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try parsed(&arena, "4142??(43|44)!(45|46){2}47");
    // The widened two-way alternation is literal, so it expands into two variants.
    try testing.expectEqual(@as(usize, 2), (try expand(a, p, .{ .wide = true })).len);
    const v = try expand(a, p, .{ .wide = true, .ascii = true });
    var texts: std.ArrayList([]const u8) = .empty;
    for (v) |x| try texts.append(a, try printed(a, x.pattern));
    try testing.expectEqual(@as(usize, 4), v.len);
    try testing.expectEqualStrings("4142??43!(45|46){2}47", texts.items[0]);
    try testing.expectEqualStrings("4142??44!(45|46){2}47", texts.items[1]);
    try testing.expectEqualStrings("41004200??4300!(45|46)00{2}4700", texts.items[2]);
    try testing.expectEqualStrings("41004200??4400!(45|46)00{2}4700", texts.items[3]);
    try testing.expect(!v[1].wide and v[2].wide and v[3].wide);
    // Multi-byte negations cannot be widened.
    try testing.expectError(error.BadModifier, expand(a, try parsed(&arena, "41!(4243|4445)"), .{ .wide = true }));
}

test "nocase expands up to 16 variants and otherwise folds" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const small = try expand(a, try parsed(&arena, "61623132"), .{ .nocase = true }); // "ab12"
    try testing.expectEqual(@as(usize, 4), small.len);
    try testing.expect(!small[0].folded);
    try testing.expectEqualStrings("61623132", try printed(a, small[0].pattern));
    try testing.expectEqualStrings("41423132", try printed(a, small[3].pattern));

    const big = try expand(a, try parsed(&arena, "6162636465"), .{ .nocase = true }); // 32 combinations
    try testing.expectEqual(@as(usize, 1), big.len);
    try testing.expect(big[0].folded);
    try testing.expect(big[0].pattern.ops[0].flags & ir.op_nocase != 0);

    // wide + ascii + nocase with 3 letters: 2 * 8 = 16 variants, still expanded.
    try testing.expectEqual(@as(usize, 16), (try expand(a, try parsed(&arena, "616263"), .{ .nocase = true, .wide = true, .ascii = true })).len);
}

test "literal alternations expand while the product stays small" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try expand(a, try parsed(&arena, "aa(bb|cc)dd(ee|ff)"), .{});
    try testing.expectEqual(@as(usize, 4), v.len);
    try testing.expectEqualStrings("aabbddee", try printed(a, v[0].pattern));
    try testing.expectEqual(@as(usize, 1), v[0].pattern.ops.len); // merged into one literal
    try testing.expectEqualStrings("aaccddff", try printed(a, v[3].pattern));
    // Generic alternations and oversize products stay as alternations.
    try testing.expectEqual(@as(usize, 1), (try expand(a, try parsed(&arena, "aa(b?|cc)dd"), .{})).len);
    var big: std.ArrayList(u8) = .empty;
    try big.appendSlice(a, "aa(");
    for (0..17) |i| {
        if (i > 0) try big.append(a, '|');
        try big.print(a, "{x:0>2}", .{i});
    }
    try big.append(a, ')');
    try testing.expectEqual(@as(usize, 1), (try expand(a, try parsed(&arena, big.items), .{})).len);
}
