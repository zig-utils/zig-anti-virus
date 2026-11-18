//! The HTML normaliser for target type 3: one byte-level state machine, fed in blocks, with no
//! whole-document buffer. ClamAV's documentation describes the normalised stream as lowercased,
//! whitespace-collapsed HTML with comments removed, tags and attributes normalised and character
//! references decoded; signatures for target 3 are written against it. This produces:
//!
//! - text: lowercased, every whitespace run one space, NUL bytes dropped, entities decoded
//!   (numeric references to UTF-8, a table of common named ones);
//! - tags: `<name attr="value" ...>`, lowercased, one space between attributes, values always
//!   double-quoted, whitespace inside the tag collapsed;
//! - comments (`<!-- ... -->`) removed;
//! - script bodies kept in the normalised stream and, in `scripts` mode, emitted raw one script
//!   at a time for the JavaScript normaliser.
//!
//! Byte-for-byte parity with libclamav is checked differentially (E9), not assumed here.
const std = @import("std");

pub const Mode = enum { normalized, scripts };

pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
    /// Scripts mode: a script body begins (true) or ends (false).
    boundary: ?*const fn (ctx: *anyopaque, begin: bool) error{Stop}!void = null,
};

const State = enum {
    text,
    tag_open,
    tag_name,
    in_tag,
    attr_name,
    after_attr_name,
    before_value,
    value_dq,
    value_sq,
    value_unq,
    bang,
    bang_dash,
    comment,
    comment_dash1,
    comment_dash2,
    script,
};

pub const Normalizer = struct {
    mode: Mode,
    out: Output,
    state: State = .text,
    buf: [4096]u8 = undefined,
    len: usize = 0,
    last_space: bool = true,
    pending_space: bool = false,
    end_tag: bool = false,
    name: [8]u8 = undefined,
    name_len: u8 = 0,
    /// Entity being collected, and the state to return to.
    entity: [32]u8 = undefined,
    entity_len: u8 = 0,
    in_entity: bool = false,
    /// Bytes of a possible "</script" held back inside a script body.
    held: [8]u8 = undefined,
    held_len: u8 = 0,

    pub const Error = error{Stop};

    pub fn init(mode: Mode, out: Output) Normalizer {
        return .{ .mode = mode, .out = out };
    }

    fn put(n: *Normalizer, c: u8) Error!void {
        if (n.len == n.buf.len) try n.flush();
        n.buf[n.len] = c;
        n.len += 1;
    }

    fn putAll(n: *Normalizer, s: []const u8) Error!void {
        for (s) |c| try n.put(c);
    }

    pub fn flush(n: *Normalizer) Error!void {
        if (n.len == 0) return;
        try n.out.write(n.out.ctx, n.buf[0..n.len]);
        n.len = 0;
    }

    /// Emit into the normalised stream (nothing in scripts mode).
    fn emit(n: *Normalizer, c: u8) Error!void {
        if (n.mode != .normalized) return;
        try n.put(c);
        n.last_space = false;
    }

    fn emitStr(n: *Normalizer, s: []const u8) Error!void {
        for (s) |c| try n.emit(c);
    }

    /// Text and script content: lowercased, whitespace collapsed.
    fn emitText(n: *Normalizer, c: u8) Error!void {
        if (n.mode != .normalized) return;
        if (c == 0) return;
        if (isSpace(c)) {
            if (n.last_space) return;
            try n.put(' ');
            n.last_space = true;
            return;
        }
        try n.put(std.ascii.toLower(c));
        n.last_space = false;
    }

    pub fn feed(n: *Normalizer, in: []const u8) Error!void {
        for (in) |c| try n.step(c);
    }

    /// End of input: flush whatever is pending.
    pub fn finish(n: *Normalizer) Error!void {
        if (n.in_entity) try n.abandonEntity();
        if (n.state == .script) {
            if (n.mode == .scripts) {
                try n.putAll(n.held[0..n.held_len]);
                try n.flush();
                if (n.out.boundary) |b| try b(n.out.ctx, false);
            } else for (n.held[0..n.held_len]) |h| try n.emitText(h);
            n.held_len = 0;
        }
        try n.flush();
    }

    fn step(n: *Normalizer, c: u8) Error!void {
        if (n.in_entity) return n.entityByte(c);
        switch (n.state) {
            .text => switch (c) {
                '<' => n.state = .tag_open,
                '&' => n.startEntity(),
                else => try n.emitText(c),
            },
            .tag_open => switch (c) {
                '!' => n.state = .bang,
                '/' => {
                    n.end_tag = true;
                    n.name_len = 0;
                    try n.emitStr("</");
                    n.state = .tag_name;
                },
                'a'...'z', 'A'...'Z' => {
                    n.end_tag = false;
                    n.name_len = 0;
                    try n.emit('<');
                    try n.nameByte(c);
                    n.state = .tag_name;
                },
                else => {
                    // Not a tag: a literal '<'.
                    try n.emitText('<');
                    n.state = .text;
                    try n.step(c);
                },
            },
            .tag_name => switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9', '-', ':', '_' => try n.nameByte(c),
                else => {
                    n.state = .in_tag;
                    try n.step(c);
                },
            },
            .in_tag => switch (c) {
                '>' => try n.closeTag(),
                '/' => try n.emit('/'),
                0 => {},
                else => if (isSpace(c)) {
                    n.pending_space = true;
                } else {
                    if (n.pending_space) try n.emit(' ');
                    n.pending_space = false;
                    try n.emit(std.ascii.toLower(c));
                    n.state = .attr_name;
                },
            },
            .attr_name => switch (c) {
                '=' => {
                    try n.emit('=');
                    n.state = .before_value;
                },
                '>' => try n.closeTag(),
                '/' => {
                    try n.emit('/');
                    n.state = .in_tag;
                },
                0 => {},
                else => if (isSpace(c)) {
                    n.state = .after_attr_name;
                } else try n.emit(std.ascii.toLower(c)),
            },
            .after_attr_name => switch (c) {
                '=' => {
                    try n.emit('=');
                    n.state = .before_value;
                },
                '>' => try n.closeTag(),
                else => if (!isSpace(c)) {
                    n.pending_space = true;
                    n.state = .in_tag;
                    try n.step(c);
                },
            },
            .before_value => switch (c) {
                '"' => {
                    try n.emit('"');
                    n.state = .value_dq;
                },
                '\'' => {
                    try n.emit('"');
                    n.state = .value_sq;
                },
                '>' => {
                    try n.emitStr("\"\"");
                    try n.closeTag();
                },
                else => if (!isSpace(c)) {
                    try n.emit('"');
                    n.state = .value_unq;
                    try n.step(c);
                },
            },
            .value_dq, .value_sq => {
                const close: u8 = if (n.state == .value_dq) '"' else '\'';
                if (c == close) {
                    try n.emit('"');
                    n.state = .in_tag;
                } else if (c == '&') n.startEntity() else try n.valueByte(c);
            },
            .value_unq => switch (c) {
                '>' => {
                    try n.emit('"');
                    try n.closeTag();
                },
                '&' => n.startEntity(),
                else => if (isSpace(c)) {
                    try n.emit('"');
                    n.pending_space = true;
                    n.state = .in_tag;
                } else try n.valueByte(c),
            },
            .bang => if (c == '-') {
                n.state = .bang_dash;
            } else {
                // <!DOCTYPE ...> and friends: kept as a tag.
                try n.emitStr("<!");
                n.end_tag = false;
                n.name_len = 0;
                n.state = .tag_name;
                try n.step(c);
            },
            .bang_dash => if (c == '-') {
                n.state = .comment;
            } else {
                try n.emitStr("<!-");
                n.state = .in_tag;
                try n.step(c);
            },
            .comment => {
                if (c == '-') n.state = .comment_dash1;
            },
            .comment_dash1 => n.state = if (c == '-') .comment_dash2 else .comment,
            .comment_dash2 => switch (c) {
                '>' => n.state = .text,
                '-' => {},
                else => n.state = .comment,
            },
            .script => try n.scriptByte(c),
        }
    }

    fn nameByte(n: *Normalizer, c: u8) Error!void {
        const l = std.ascii.toLower(c);
        if (n.name_len < n.name.len) n.name[n.name_len] = l;
        n.name_len +|= 1;
        try n.emit(l);
    }

    fn valueByte(n: *Normalizer, c: u8) Error!void {
        if (c == 0) return;
        try n.emit(if (isSpace(c)) ' ' else std.ascii.toLower(c));
    }

    fn closeTag(n: *Normalizer) Error!void {
        try n.emit('>');
        n.pending_space = false;
        const is_script = !n.end_tag and n.name_len == 6 and std.mem.eql(u8, n.name[0..6], "script");
        if (is_script) {
            n.state = .script;
            n.held_len = 0;
            if (n.mode == .scripts) if (n.out.boundary) |b| {
                try n.flush();
                try b(n.out.ctx, true);
            };
        } else n.state = .text;
    }

    fn scriptByte(n: *Normalizer, c: u8) Error!void {
        const end = "</script";
        if (n.held_len > 0 or c == '<') {
            if (std.ascii.toLower(c) == end[n.held_len]) {
                n.held[n.held_len] = c;
                n.held_len += 1;
                if (n.held_len == end.len) {
                    n.held_len = 0;
                    if (n.mode == .scripts) {
                        try n.flush();
                        if (n.out.boundary) |b| try b(n.out.ctx, false);
                    }
                    try n.emitStr("</script");
                    n.end_tag = true;
                    n.name_len = 6;
                    @memcpy(n.name[0..6], "script");
                    n.state = .in_tag;
                }
                return;
            }
            // Not the end: release what was held, then handle this byte.
            const held = n.held_len;
            n.held_len = 0;
            for (n.held[0..held]) |h| try n.scriptOut(h);
            if (c == '<') {
                n.held[0] = c;
                n.held_len = 1;
                return;
            }
        }
        try n.scriptOut(c);
    }

    fn scriptOut(n: *Normalizer, c: u8) Error!void {
        if (n.mode == .scripts) return n.put(c);
        try n.emitText(c);
    }

    fn startEntity(n: *Normalizer) void {
        n.in_entity = true;
        n.entity_len = 0;
    }

    fn entityByte(n: *Normalizer, c: u8) Error!void {
        if (c == ';') {
            n.in_entity = false;
            var utf8: [4]u8 = undefined;
            if (decodeEntity(n.entity[0..n.entity_len], &utf8)) |s| {
                for (s) |b| try n.decodedOut(b);
            } else {
                try n.decodedOut('&');
                for (n.entity[0..n.entity_len]) |b| try n.decodedOut(b);
                try n.decodedOut(';');
            }
            return;
        }
        if (n.entity_len < n.entity.len and (std.ascii.isAlphanumeric(c) or (c == '#' and n.entity_len == 0))) {
            n.entity[n.entity_len] = c;
            n.entity_len += 1;
            return;
        }
        try n.abandonEntity();
        try n.step(c);
    }

    /// An '&' that did not form a reference: emit it literally.
    fn abandonEntity(n: *Normalizer) Error!void {
        n.in_entity = false;
        try n.decodedOut('&');
        for (n.entity[0..n.entity_len]) |b| try n.decodedOut(b);
    }

    fn decodedOut(n: *Normalizer, b: u8) Error!void {
        switch (n.state) {
            .value_dq, .value_sq, .value_unq => try n.valueByte(b),
            else => try n.emitText(b),
        }
    }
};

fn isSpace(c: u8) bool {
    return switch (c) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => true,
        else => false,
    };
}

const named = [_]struct { []const u8, u21 }{
    .{ "amp", '&' },      .{ "lt", '<' },       .{ "gt", '>' },        .{ "quot", '"' },
    .{ "apos", '\'' },    .{ "nbsp", 0xa0 },    .{ "copy", 0xa9 },     .{ "reg", 0xae },
    .{ "shy", 0xad },     .{ "laquo", 0xab },   .{ "raquo", 0xbb },    .{ "iexcl", 0xa1 },
    .{ "cent", 0xa2 },    .{ "pound", 0xa3 },   .{ "yen", 0xa5 },      .{ "sect", 0xa7 },
    .{ "deg", 0xb0 },     .{ "plusmn", 0xb1 },  .{ "middot", 0xb7 },   .{ "para", 0xb6 },
    .{ "eacute", 0xe9 },  .{ "egrave", 0xe8 },  .{ "agrave", 0xe0 },   .{ "aacute", 0xe1 },
    .{ "ccedil", 0xe7 },  .{ "uuml", 0xfc },    .{ "ouml", 0xf6 },     .{ "auml", 0xe4 },
    .{ "szlig", 0xdf },   .{ "ntilde", 0xf1 },  .{ "hellip", 0x2026 }, .{ "mdash", 0x2014 },
    .{ "ndash", 0x2013 }, .{ "lsquo", 0x2018 }, .{ "rsquo", 0x2019 },  .{ "ldquo", 0x201c },
    .{ "rdquo", 0x201d }, .{ "bull", 0x2022 },  .{ "euro", 0x20ac },   .{ "trade", 0x2122 },
    .{ "times", 0xd7 },   .{ "divide", 0xf7 },
};

/// A character reference body (between '&' and ';') as UTF-8, or null if it is not one.
pub fn decodeEntity(body: []const u8, out: *[4]u8) ?[]const u8 {
    if (body.len == 0) return null;
    var cp: u21 = undefined;
    if (body[0] == '#') {
        if (body.len < 2) return null;
        const hex = body[1] == 'x' or body[1] == 'X';
        const digits = body[if (hex) 2 else 1..];
        if (digits.len == 0) return null;
        const v = std.fmt.parseInt(u32, digits, if (hex) 16 else 10) catch return null;
        if (v == 0 or v > 0x10ffff or (v >= 0xd800 and v <= 0xdfff)) return null;
        cp = @intCast(v);
    } else {
        cp = for (named) |e| {
            if (std.mem.eql(u8, e[0], body)) break e[1];
        } else return null;
    }
    const n = std.unicode.utf8Encode(cp, out) catch return null;
    return out[0..n];
}

const Collect = struct {
    out: std.ArrayList(u8) = .empty,
    scripts: usize = 0,
    in_script: bool = false,

    fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        c.out.appendSlice(std.testing.allocator, bytes) catch return error.Stop;
    }
    fn boundary(ctx: *anyopaque, begin: bool) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        if (begin) {
            c.scripts += 1;
            c.out.appendSlice(std.testing.allocator, "[") catch return error.Stop;
        } else c.out.appendSlice(std.testing.allocator, "]") catch return error.Stop;
        c.in_script = begin;
    }
};

fn run(mode: Mode, input: []const u8, split: usize) !Collect {
    var c: Collect = .{};
    var n = Normalizer.init(mode, .{ .ctx = &c, .write = Collect.write, .boundary = Collect.boundary });
    var i: usize = 0;
    while (i < input.len) : (i += split) try n.feed(input[i..@min(input.len, i + split)]);
    try n.finish();
    return c;
}

test "normalised stream: case, whitespace, comments, tags, entities" {
    const input =
        \\<!DOCTYPE html>
        \\<HTML>  <Body BGCOLOR = red   onload='Go()'>
        \\  Hello <!-- hidden <script>x</script> --> &AMP;   W&#79;rld &#x41;&nbsp;&bogus; &amp
        \\<A HREF=http://Example.com/Path  target = "_blank">Link</A><br/>
        \\</BODY></HTML>
    ;
    var c = try run(.normalized, input, input.len);
    defer c.out.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "<!doctype html> <html> <body bgcolor=\"red\" onload=\"go()\"> hello &amp; world a\xc2\xa0&bogus; &amp " ++
            "<a href=\"http://example.com/path\" target=\"_blank\">link</a><br/> </body></html>",
        c.out.items,
    );
}

test "scripts mode emits each script body raw" {
    const input = "<p>x</p><SCRIPT type=text/javascript>var A = 1 < 2;\n</scr</SCRIPT ><script>B()</script><!-- <script>no</script> -->";
    var c = try run(.scripts, input, input.len);
    defer c.out.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("[var A = 1 < 2;\n</scr][B()]", c.out.items);
    try std.testing.expectEqual(@as(usize, 2), c.scripts);
}

test "any block split gives the same output" {
    const input = "<Div CLASS='a  b'>T&eacute;st &#x263A; <SCRIPT>if (a<b) x();</ScRiPt> end &lt;tag&gt;</div>";
    var whole = try run(.normalized, input, input.len);
    defer whole.out.deinit(std.testing.allocator);
    var whole_s = try run(.scripts, input, input.len);
    defer whole_s.out.deinit(std.testing.allocator);
    for (1..input.len) |split| {
        var c = try run(.normalized, input, split);
        defer c.out.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(whole.out.items, c.out.items);
        var s = try run(.scripts, input, split);
        defer s.out.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(whole_s.out.items, s.out.items);
    }
}
