//! The HTML normaliser for target type 3: one byte-level state machine, fed in blocks, with no
//! whole-document buffer. The normalised stream is libclamav's `nocomment.html`, as measured
//! byte for byte with `clamscan --leave-temps` (tools/diff/norm.py):
//!
//! - text: ASCII lowercased; a whitespace run is one space, and none right after a `>` or at the
//!   start; references decoded (below);
//! - tags: name and attributes lowercased; whitespace collapsed to one space between attributes and
//!   dropped after `<`, around `=` and before `>`; a value's whitespace runs collapsed; quoted
//!   values double-quoted and `'` inside them written as `"` (libclamav keeps some `'`, by rules not
//!   yet pinned down: #45), unquoted values unquoted;
//! - comments and every other `<!...>` (DOCTYPE) removed;
//! - script and style bodies lowercased, with no whitespace and `'` written as `"`;
//! - references: a numeric one below 256 is that byte (lowercased), from 256 up `&#xHHHH;`; named
//!   ones from a table; unknown or unterminated ones stay as written.
//!
//! In `scripts` mode each script body is emitted raw, one at a time, for the JavaScript
//! normaliser.
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
    declaration,
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
    /// The last byte of the normalised stream.
    last: u8 = 0,
    /// Nothing but tags since the last text byte (and at the start): a space is not written.
    after_tag: bool = true,
    /// Inside a style element (a raw text body like a script's, never emitted in scripts mode).
    style: bool = false,
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
        n.last = c;
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

    /// Text: lowercased, whitespace collapsed, no space after a tag.
    fn emitText(n: *Normalizer, c: u8) Error!void {
        if (n.mode != .normalized) return;
        if (c == 0) return;
        if (isSpace(c)) {
            if (n.last == ' ' or n.after_tag) return;
            try n.put(' ');
            return;
        }
        try n.put(std.ascii.toLower(c));
        n.after_tag = false;
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
                // `< b >` is the tag `<b>`.
                ' ', '\t', '\n', '\r', 0x0b, 0x0c => {},
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
                '/' => {
                    if (n.pending_space) try n.emit(' ');
                    n.pending_space = false;
                    try n.emit('/');
                },
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
                    n.state = .in_tag;
                    try n.step(c);
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
                '>' => try n.closeTag(),
                else => if (!isSpace(c)) {
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
                '>' => try n.closeTag(),
                '&' => n.startEntity(),
                else => if (isSpace(c)) {
                    n.pending_space = true;
                    n.state = .in_tag;
                } else try n.valueByte(c),
            },
            .bang => if (c == '-') {
                n.state = .bang_dash;
            } else {
                // <!DOCTYPE ...> and friends: dropped up to the '>'.
                n.state = .declaration;
                try n.step(c);
            },
            .bang_dash => if (c == '-') {
                n.state = .comment;
            } else {
                n.state = .declaration;
                try n.step(c);
            },
            .declaration => if (c == '>') {
                n.state = .text;
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

    /// Attribute values: lowercased, whitespace runs collapsed, `'` written as `"`.
    fn valueByte(n: *Normalizer, c: u8) Error!void {
        if (c == 0) return;
        if (isSpace(c)) {
            if (n.last != ' ') try n.emit(' ');
            return;
        }
        try n.emit(if (c == '\'') '"' else std.ascii.toLower(c));
    }

    fn closeTag(n: *Normalizer) Error!void {
        try n.emit('>');
        n.after_tag = true;
        n.pending_space = false;
        const is_script = !n.end_tag and n.name_len == 6 and std.mem.eql(u8, n.name[0..6], "script");
        const is_style = !n.end_tag and n.name_len == 5 and std.mem.eql(u8, n.name[0..5], "style");
        if (is_script or is_style) {
            n.state = .script;
            n.style = is_style;
            n.held_len = 0;
            if (n.mode == .scripts and is_script) if (n.out.boundary) |b| {
                try n.flush();
                try b(n.out.ctx, true);
            };
        } else n.state = .text;
    }

    fn scriptByte(n: *Normalizer, c: u8) Error!void {
        const end: []const u8 = if (n.style) "</style" else "</script";
        if (n.held_len > 0 or c == '<') {
            if (std.ascii.toLower(c) == end[n.held_len]) {
                n.held[n.held_len] = c;
                n.held_len += 1;
                if (n.held_len == end.len) {
                    n.held_len = 0;
                    if (n.mode == .scripts and !n.style) {
                        try n.flush();
                        if (n.out.boundary) |b| try b(n.out.ctx, false);
                    }
                    try n.emitStr(end);
                    n.end_tag = true;
                    n.name_len = @intCast(end.len - 2);
                    @memcpy(n.name[0 .. end.len - 2], end[2..]);
                    n.style = false;
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
        if (n.mode == .scripts) return if (n.style) {} else n.put(c);
        // libclamav decodes character references in script and style bodies too.
        if (c == '&') return n.startEntity();
        try n.scriptNormal(c);
    }

    fn scriptNormal(n: *Normalizer, c: u8) Error!void {
        if (c == 0 or isSpace(c)) return;
        try n.put(if (c == '\'') '"' else std.ascii.toLower(c));
    }

    fn startEntity(n: *Normalizer) void {
        n.in_entity = true;
        n.entity_len = 0;
    }

    fn entityByte(n: *Normalizer, c: u8) Error!void {
        if (c == ';') {
            n.in_entity = false;
            var form: [8]u8 = undefined;
            if (clamavEntity(n.entity[0..n.entity_len], &form)) |s| {
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
            .script => try n.scriptNormal(b),
            else => if (b == 0) {
                // A reference to NUL is kept (raw NUL bytes are dropped).
                if (n.mode == .normalized) try n.put(0);
            } else try n.emitText(b),
        }
    }
};

fn isSpace(c: u8) bool {
    return switch (c) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => true,
        else => false,
    };
}

/// The HTML 4.01 named character references (252), as libclamav decodes them.
const named = [_]struct { []const u8, u21 }{
    .{ "AElig", 0xc6 },     .{ "Aacute", 0xc1 },    .{ "Acirc", 0xc2 },    .{ "Agrave", 0xc0 },
    .{ "Alpha", 0x391 },    .{ "Aring", 0xc5 },     .{ "Atilde", 0xc3 },   .{ "Auml", 0xc4 },
    .{ "Beta", 0x392 },     .{ "Ccedil", 0xc7 },    .{ "Chi", 0x3a7 },     .{ "Dagger", 0x2021 },
    .{ "Delta", 0x394 },    .{ "ETH", 0xd0 },       .{ "Eacute", 0xc9 },   .{ "Ecirc", 0xca },
    .{ "Egrave", 0xc8 },    .{ "Epsilon", 0x395 },  .{ "Eta", 0x397 },     .{ "Euml", 0xcb },
    .{ "Gamma", 0x393 },    .{ "Iacute", 0xcd },    .{ "Icirc", 0xce },    .{ "Igrave", 0xcc },
    .{ "Iota", 0x399 },     .{ "Iuml", 0xcf },      .{ "Kappa", 0x39a },   .{ "Lambda", 0x39b },
    .{ "Mu", 0x39c },       .{ "Ntilde", 0xd1 },    .{ "Nu", 0x39d },      .{ "OElig", 0x152 },
    .{ "Oacute", 0xd3 },    .{ "Ocirc", 0xd4 },     .{ "Ograve", 0xd2 },   .{ "Omega", 0x3a9 },
    .{ "Omicron", 0x39f },  .{ "Oslash", 0xd8 },    .{ "Otilde", 0xd5 },   .{ "Ouml", 0xd6 },
    .{ "Phi", 0x3a6 },      .{ "Pi", 0x3a0 },       .{ "Prime", 0x2033 },  .{ "Psi", 0x3a8 },
    .{ "Rho", 0x3a1 },      .{ "Scaron", 0x160 },   .{ "Sigma", 0x3a3 },   .{ "THORN", 0xde },
    .{ "Tau", 0x3a4 },      .{ "Theta", 0x398 },    .{ "Uacute", 0xda },   .{ "Ucirc", 0xdb },
    .{ "Ugrave", 0xd9 },    .{ "Upsilon", 0x3a5 },  .{ "Uuml", 0xdc },     .{ "Xi", 0x39e },
    .{ "Yacute", 0xdd },    .{ "Yuml", 0x178 },     .{ "Zeta", 0x396 },    .{ "aacute", 0xe1 },
    .{ "acirc", 0xe2 },     .{ "acute", 0xb4 },     .{ "aelig", 0xe6 },    .{ "agrave", 0xe0 },
    .{ "alefsym", 0x2135 }, .{ "alpha", 0x3b1 },    .{ "amp", 0x26 },      .{ "and", 0x2227 },
    .{ "ang", 0x2220 },     .{ "aring", 0xe5 },     .{ "asymp", 0x2248 },  .{ "atilde", 0xe3 },
    .{ "auml", 0xe4 },      .{ "bdquo", 0x201e },   .{ "beta", 0x3b2 },    .{ "brvbar", 0xa6 },
    .{ "bull", 0x2022 },    .{ "cap", 0x2229 },     .{ "ccedil", 0xe7 },   .{ "cedil", 0xb8 },
    .{ "cent", 0xa2 },      .{ "chi", 0x3c7 },      .{ "circ", 0x2c6 },    .{ "clubs", 0x2663 },
    .{ "cong", 0x2245 },    .{ "copy", 0xa9 },      .{ "crarr", 0x21b5 },  .{ "cup", 0x222a },
    .{ "curren", 0xa4 },    .{ "dArr", 0x21d3 },    .{ "dagger", 0x2020 }, .{ "darr", 0x2193 },
    .{ "deg", 0xb0 },       .{ "delta", 0x3b4 },    .{ "diams", 0x2666 },  .{ "divide", 0xf7 },
    .{ "eacute", 0xe9 },    .{ "ecirc", 0xea },     .{ "egrave", 0xe8 },   .{ "empty", 0x2205 },
    .{ "emsp", 0x2003 },    .{ "ensp", 0x2002 },    .{ "epsilon", 0x3b5 }, .{ "equiv", 0x2261 },
    .{ "eta", 0x3b7 },      .{ "eth", 0xf0 },       .{ "euml", 0xeb },     .{ "euro", 0x20ac },
    .{ "exist", 0x2203 },   .{ "fnof", 0x192 },     .{ "forall", 0x2200 }, .{ "frac12", 0xbd },
    .{ "frac14", 0xbc },    .{ "frac34", 0xbe },    .{ "frasl", 0x2044 },  .{ "gamma", 0x3b3 },
    .{ "ge", 0x2265 },      .{ "gt", 0x3e },        .{ "hArr", 0x21d4 },   .{ "harr", 0x2194 },
    .{ "hearts", 0x2665 },  .{ "hellip", 0x2026 },  .{ "iacute", 0xed },   .{ "icirc", 0xee },
    .{ "iexcl", 0xa1 },     .{ "igrave", 0xec },    .{ "image", 0x2111 },  .{ "infin", 0x221e },
    .{ "int", 0x222b },     .{ "iota", 0x3b9 },     .{ "iquest", 0xbf },   .{ "isin", 0x2208 },
    .{ "iuml", 0xef },      .{ "kappa", 0x3ba },    .{ "lArr", 0x21d0 },   .{ "lambda", 0x3bb },
    .{ "lang", 0x2329 },    .{ "laquo", 0xab },     .{ "larr", 0x2190 },   .{ "lceil", 0x2308 },
    .{ "ldquo", 0x201c },   .{ "le", 0x2264 },      .{ "lfloor", 0x230a }, .{ "lowast", 0x2217 },
    .{ "loz", 0x25ca },     .{ "lrm", 0x200e },     .{ "lsaquo", 0x2039 }, .{ "lsquo", 0x2018 },
    .{ "lt", 0x3c },        .{ "macr", 0xaf },      .{ "mdash", 0x2014 },  .{ "micro", 0xb5 },
    .{ "middot", 0xb7 },    .{ "minus", 0x2212 },   .{ "mu", 0x3bc },      .{ "nabla", 0x2207 },
    .{ "nbsp", 0xa0 },      .{ "ndash", 0x2013 },   .{ "ne", 0x2260 },     .{ "ni", 0x220b },
    .{ "not", 0xac },       .{ "notin", 0x2209 },   .{ "nsub", 0x2284 },   .{ "ntilde", 0xf1 },
    .{ "nu", 0x3bd },       .{ "oacute", 0xf3 },    .{ "ocirc", 0xf4 },    .{ "oelig", 0x153 },
    .{ "ograve", 0xf2 },    .{ "oline", 0x203e },   .{ "omega", 0x3c9 },   .{ "omicron", 0x3bf },
    .{ "oplus", 0x2295 },   .{ "or", 0x2228 },      .{ "ordf", 0xaa },     .{ "ordm", 0xba },
    .{ "oslash", 0xf8 },    .{ "otilde", 0xf5 },    .{ "otimes", 0x2297 }, .{ "ouml", 0xf6 },
    .{ "para", 0xb6 },      .{ "part", 0x2202 },    .{ "permil", 0x2030 }, .{ "perp", 0x22a5 },
    .{ "phi", 0x3c6 },      .{ "pi", 0x3c0 },       .{ "piv", 0x3d6 },     .{ "plusmn", 0xb1 },
    .{ "pound", 0xa3 },     .{ "prime", 0x2032 },   .{ "prod", 0x220f },   .{ "prop", 0x221d },
    .{ "psi", 0x3c8 },      .{ "quot", 0x22 },      .{ "rArr", 0x21d2 },   .{ "radic", 0x221a },
    .{ "rang", 0x232a },    .{ "raquo", 0xbb },     .{ "rarr", 0x2192 },   .{ "rceil", 0x2309 },
    .{ "rdquo", 0x201d },   .{ "real", 0x211c },    .{ "reg", 0xae },      .{ "rfloor", 0x230b },
    .{ "rho", 0x3c1 },      .{ "rlm", 0x200f },     .{ "rsaquo", 0x203a }, .{ "rsquo", 0x2019 },
    .{ "sbquo", 0x201a },   .{ "scaron", 0x161 },   .{ "sdot", 0x22c5 },   .{ "sect", 0xa7 },
    .{ "shy", 0xad },       .{ "sigma", 0x3c3 },    .{ "sigmaf", 0x3c2 },  .{ "sim", 0x223c },
    .{ "spades", 0x2660 },  .{ "sub", 0x2282 },     .{ "sube", 0x2286 },   .{ "sum", 0x2211 },
    .{ "sup", 0x2283 },     .{ "sup1", 0xb9 },      .{ "sup2", 0xb2 },     .{ "sup3", 0xb3 },
    .{ "supe", 0x2287 },    .{ "szlig", 0xdf },     .{ "tau", 0x3c4 },     .{ "there4", 0x2234 },
    .{ "theta", 0x3b8 },    .{ "thetasym", 0x3d1 }, .{ "thinsp", 0x2009 }, .{ "thorn", 0xfe },
    .{ "tilde", 0x2dc },    .{ "times", 0xd7 },     .{ "trade", 0x2122 },  .{ "uArr", 0x21d1 },
    .{ "uacute", 0xfa },    .{ "uarr", 0x2191 },    .{ "ucirc", 0xfb },    .{ "ugrave", 0xf9 },
    .{ "uml", 0xa8 },       .{ "upsih", 0x3d2 },    .{ "upsilon", 0x3c5 }, .{ "uuml", 0xfc },
    .{ "weierp", 0x2118 },  .{ "xi", 0x3be },       .{ "yacute", 0xfd },   .{ "yen", 0xa5 },
    .{ "yuml", 0xff },      .{ "zeta", 0x3b6 },     .{ "zwj", 0x200d },    .{ "zwnj", 0x200c },
};

/// A character reference body (between '&' and ';') in libclamav's normalised form: one byte for
/// code points below 256, `&#xHHHH;` above; null when it is not a reference.
pub fn clamavEntity(body: []const u8, out: *[8]u8) ?[]const u8 {
    if (body.len == 0) return null;
    var cp: u32 = undefined;
    if (body[0] == '#') {
        if (body.len < 2) return null;
        const hex = body[1] == 'x' or body[1] == 'X';
        const digits = body[if (hex) 2 else 1..];
        if (digits.len == 0) return null;
        cp = std.fmt.parseInt(u32, digits, if (hex) 16 else 10) catch return null;
        if (cp > 0xffff) return null;
    } else {
        cp = for (named) |e| {
            if (std.mem.eql(u8, e[0], body)) break e[1];
        } else return null;
    }
    if (cp < 256) {
        out[0] = @intCast(cp);
        return out[0..1];
    }
    return std.fmt.bufPrint(out, "&#x{x:0>4};", .{cp}) catch null;
}

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
        "<html><body bgcolor=red onload=\"go()\">hello &amp; world a\xa0&bogus; &amp " ++
            "<a href=http://example.com/path target=\"_blank\">link</a><br/></body></html>",
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
