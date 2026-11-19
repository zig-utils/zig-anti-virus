//! The JavaScript normaliser (P5.13): lexical normalisation of scripts from HTML and PDF so that
//! obfuscated code matches signatures written against the normalised form, as libclamav's
//! js-norm describes it. It never evaluates code.
//!
//! What it does, in one streaming pass with fixed memory:
//! - block comments and white space are removed; one space separates two word tokens;
//!   the HTML form drops `//` and normalizes the remaining text as tokens;
//! - string literals are decoded (\xHH, \uHHHH, octal and the single-letter escapes) and written
//!   double-quoted, with `"` and `\` escaped;
//! - adjacent string literals joined with `+` are folded into one (`"ev"+"al"` is `"eval"`);
//! - `unescape("...")` of a literal is decoded (%XX and %uXXXX), and
//!   standalone scripts also fold `String.fromCharCode(n, ...)` with numeric arguments;
//! - identifiers declared with var, function names and function parameters are
//!   numbered in declaration order within their active scope. Property names after `.` keep
//!   their spelling.
//!
//! Bounds: a folded string is flushed at `max_string` bytes, at most `max_names` identifiers are
//! renamed, `String.fromCharCode` folds at most `max_args` arguments, and the caller limits the
//! input to MaxScriptNormalize.
const std = @import("std");

pub const max_string = 64 * 1024;
pub const max_names = 4096;
pub const max_args = 1024;
const max_word = 128;
const max_functions = 64;

pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
};

pub const Error = error{Stop};

const Lex = enum { start, word, number, string, line_comment, block_comment, block_star, regex, regex_class, regex_flags, slash };

const TokKind = enum { word, number, string, punct, regex };

/// Token classes the previous significant token can have, which decide whether `/` starts a
/// regular expression and whether a word is a property name.
const Prev = enum { none, operand, dot, other };

pub const Normalizer = struct {
    out: Output,
    html_output: bool = false,
    // Output buffering.
    obuf: [4096]u8 = undefined,
    olen: usize = 0,
    last_out: TokKind = .punct,
    last_char: u8 = 0,
    // Lexer.
    lex: Lex = .start,
    word: [max_word]u8 = undefined,
    word_len: usize = 0,
    html_number: HtmlNumber = .integer,
    quote: u8 = 0,
    esc: u8 = 0,
    esc_val: u32 = 0,
    esc_digits: u8 = 0,
    sbuf: [max_string]u8 = undefined,
    slen: usize = 0,
    regex_escape: bool = false,
    prev: Prev = .none,
    // Folding: a pending string and whether a `+` followed it.
    pend: [max_string]u8 = undefined,
    pend_len: usize = 0,
    have_pend: bool = false,
    pend_plus: bool = false,
    // Call folding: unescape("...") and String.fromCharCode(...).
    call: Call = .idle,
    call_str: [max_string]u8 = undefined,
    call_str_len: usize = 0,
    args: [max_args]u21 = undefined,
    nargs: usize = 0,
    // Declarations and renaming.
    names: [max_names]Name = undefined,
    nnames: usize = 0,
    /// Open-addressing index over `names`: entry index + 1, 0 for empty.
    slots: [2 * max_names]u16 = @splat(0),
    name_bytes: [max_names * 16]u8 = undefined,
    name_used: usize = 0,
    decl: Decl = .none,
    depth: i32 = 0,
    decl_depth: i32 = 0,
    var_depth: i32 = 0,
    functions: [max_functions]Function = undefined,
    function_count: u8 = 0,
    rename_disabled: bool = false,

    const Name = struct {
        off: u32,
        len: u8,
        level: u8,
        slot: u16,
        previous_value: u16,
        previous_binding: u16,
    };
    const HtmlNumber = enum { integer, fraction, exponent_start, exponent_digits };
    const Decl = enum { none, var_next, var_list, func_name, func_params };
    const Function = struct {
        saved_decl: Decl,
        saved_decl_depth: i32,
        saved_var_depth: i32,
        body_depth: ?i32 = null,
        last_binding: u16 = 0,
    };
    const Call = enum { idle, unescape, unescape_paren, unescape_str, string, string_dot, from_char_code, fcc_paren, fcc_num, fcc_comma };

    pub fn init(out: Output) Normalizer {
        return .{ .out = out };
    }

    /// libclamav's HTML `javascript` file stores ASCII lowercase output.
    pub fn initHtml(out: Output) Normalizer {
        return .{ .out = out, .html_output = true };
    }

    pub fn feed(n: *Normalizer, data: []const u8) Error!void {
        for (data) |c| try n.byte(c);
    }

    pub fn finish(n: *Normalizer) Error!void {
        // A space ends a pending word or number. Not inside a regex body: a script out of HTML
        // ends with its end tag, whose `/script>` lexes as an unterminated regex that must not
        // grow a space (libclamav's file then ends exactly with `</script>`).
        switch (n.lex) {
            .regex, .regex_class => {},
            else => try n.byte(' '),
        }
        switch (n.lex) {
            .string => try n.endString(),
            .regex, .regex_class, .regex_flags => try n.emitRegexEnd(),
            else => {},
        }
        n.lex = .start;
        try n.releaseCall();
        try n.flushPend();
        try n.flushOut();
    }

    // -----------------------------------------------------------------------------------------
    // Lexer.

    fn byte(n: *Normalizer, c: u8) Error!void {
        switch (n.lex) {
            .start => try n.startToken(c),
            .word => {
                if (isWordChar(c)) {
                    if (n.word_len < max_word) {
                        n.word[n.word_len] = c;
                        n.word_len += 1;
                    }
                    return;
                }
                n.lex = .start;
                try n.token(.word, n.word[0..n.word_len]);
                try n.startToken(c);
            },
            .number => {
                const continued = if (n.html_output) n.htmlNumberChar(c) else std.ascii.isAlphanumeric(c) or c == '.' or c == '_';
                if (continued) {
                    if (n.word_len < max_word) {
                        n.word[n.word_len] = c;
                        n.word_len += 1;
                    }
                    return;
                }
                n.lex = .start;
                try n.endNumber();
                try n.startToken(c);
            },
            .string => try n.stringByte(c),
            .slash => {
                if (c == '/') {
                    n.lex = if (n.html_output) .start else .line_comment;
                } else if (c == '*') {
                    n.lex = .block_comment;
                } else if (n.prev == .operand) {
                    n.lex = .start;
                    try n.token(.punct, "/");
                    try n.startToken(c);
                } else {
                    // A regular expression literal: passed through as it is.
                    n.lex = .regex;
                    try n.releaseCall();
                    try n.flushPend();
                    try n.sep(.regex);
                    try n.put('/');
                    n.regex_escape = false;
                    try n.regexByte(c);
                }
            },
            .line_comment => if (c == '\n' or c == '\r') {
                n.lex = .start;
            },
            .block_comment => if (c == '*') {
                n.lex = .block_star;
            },
            .block_star => n.lex = if (c == '/') .start else if (c == '*') .block_star else .block_comment,
            .regex, .regex_class => try n.regexByte(c),
            .regex_flags => {
                if (std.ascii.isAlphabetic(c)) return n.put(c);
                try n.emitRegexEnd();
                n.lex = .start;
                try n.startToken(c);
            },
        }
    }

    /// The HTML lexer recognizes an exponent only after a decimal point.
    fn htmlNumberChar(n: *Normalizer, c: u8) bool {
        if (std.ascii.isDigit(c)) {
            if (n.html_number == .exponent_start) n.html_number = .exponent_digits;
            return true;
        }
        n.html_number = switch (n.html_number) {
            .integer => if (c == '.') .fraction else return false,
            .fraction => if (c == 'e' or c == 'E') .exponent_start else return false,
            .exponent_start => if (c == '+' or c == '-') .exponent_digits else return false,
            .exponent_digits => return false,
        };
        return true;
    }

    fn endNumber(n: *Normalizer) Error!void {
        const text = n.word[0..n.word_len];
        if (!n.html_output) return n.token(.number, text);
        var out: [std.fmt.float.min_buffer_size]u8 = undefined;
        if (n.html_number == .integer) {
            const value = std.fmt.parseInt(i64, text, 10) catch std.math.maxInt(i64);
            const limited: i32 = @truncate(value);
            return n.token(.number, std.fmt.bufPrint(&out, "{d}", .{limited}) catch unreachable);
        }
        const value = std.fmt.parseFloat(f64, text) catch blk: {
            const exponent = std.mem.indexOfAny(u8, text, "eE") orelse return n.token(.number, text);
            break :blk std.fmt.parseFloat(f64, text[0..exponent]) catch return n.token(.number, text);
        };
        return n.token(.number, formatHtmlFloat(value, &out));
    }

    /// libclamav writes floating-point tokens with six significant digits (`%g`).
    fn formatHtmlFloat(value: f64, out: *[std.fmt.float.min_buffer_size]u8) []const u8 {
        var scientific: [std.fmt.float.min_buffer_size]u8 = undefined;
        const repr = std.fmt.float.render(&scientific, value, .{ .precision = 5 }) catch unreachable;
        const e = std.mem.indexOfScalar(u8, repr, 'e') orelse {
            @memcpy(out[0..repr.len], repr);
            return out[0..repr.len];
        };
        const exponent = std.fmt.parseInt(i16, repr[e + 1 ..], 10) catch unreachable;
        if (exponent >= -4 and exponent < 6) {
            const places: usize = @intCast(5 - exponent);
            const decimal = std.fmt.float.render(out, value, .{ .mode = .decimal, .precision = places }) catch unreachable;
            return if (places == 0) decimal else trimDecimal(decimal);
        }
        const sign: u8 = if (exponent < 0) '-' else '+';
        return std.fmt.bufPrint(out, "{s}e{c}{d:0>2}", .{ trimDecimal(repr[0..e]), sign, @abs(exponent) }) catch unreachable;
    }

    fn trimDecimal(text: []const u8) []const u8 {
        return std.mem.trimEnd(u8, std.mem.trimEnd(u8, text, "0"), ".");
    }

    fn regexByte(n: *Normalizer, c: u8) Error!void {
        try n.put(c);
        if (n.regex_escape) {
            n.regex_escape = false;
            return;
        }
        switch (c) {
            '\\' => n.regex_escape = true,
            '[' => n.lex = .regex_class,
            ']' => if (n.lex == .regex_class) {
                n.lex = .regex;
            },
            '/' => if (n.lex == .regex) {
                n.lex = .regex_flags;
            },
            // A line break ends a broken literal.
            '\n' => n.lex = .regex_flags,
            else => {},
        }
    }

    fn emitRegexEnd(n: *Normalizer) Error!void {
        n.last_out = .regex;
        n.prev = .operand;
    }

    fn startToken(n: *Normalizer, c: u8) Error!void {
        switch (c) {
            ' ', '\t', '\n', '\r', 0x0b, 0x0c, 0 => {},
            '#', '@', '\\' => if (!n.html_output) try n.token(.punct, &.{c}),
            '"', '\'', '`' => {
                if (n.html_output and c == '`') return;
                n.lex = .string;
                n.quote = c;
                n.slen = 0;
                n.esc = 0;
            },
            '/' => n.lex = .slash,
            '0'...'9' => {
                n.lex = .number;
                n.html_number = .integer;
                n.word[0] = c;
                n.word_len = 1;
            },
            else => {
                if (isWordStart(c)) {
                    n.lex = .word;
                    n.word[0] = c;
                    n.word_len = 1;
                } else {
                    try n.token(.punct, &.{c});
                }
            },
        }
    }

    fn stringByte(n: *Normalizer, c: u8) Error!void {
        switch (n.esc) {
            0 => {
                if (c == '\\') {
                    n.esc = 1;
                } else if (c == n.quote) {
                    n.lex = .start;
                    try n.endString();
                } else if ((c == '\n' or c == '\r') and n.quote != '`') {
                    // An unterminated literal ends at the line break.
                    n.lex = .start;
                    try n.endString();
                } else n.sput(c);
            },
            1 => {
                n.esc = 0;
                switch (c) {
                    'n' => n.sput('\n'),
                    'r' => n.sput('\r'),
                    't' => n.sput('\t'),
                    'b' => n.sput(8),
                    'f' => n.sput(12),
                    'v' => n.sput(11),
                    '0'...'7' => {
                        n.esc = 'o';
                        n.esc_val = c - '0';
                        n.esc_digits = 1;
                    },
                    'x' => {
                        n.esc = 'x';
                        n.esc_val = 0;
                        n.esc_digits = 0;
                    },
                    'u' => {
                        n.esc = 'u';
                        n.esc_val = 0;
                        n.esc_digits = 0;
                    },
                    '\r', '\n' => {}, // line continuation
                    else => n.sput(c),
                }
            },
            'o' => {
                if (c >= '0' and c <= '7' and n.esc_digits < 3 and n.esc_val * 8 + (c - '0') <= 255) {
                    n.esc_val = n.esc_val * 8 + (c - '0');
                    n.esc_digits += 1;
                    return;
                }
                n.esc = 0;
                n.sput(@intCast(n.esc_val));
                try n.stringByte(c);
            },
            'x', 'u' => {
                const want: u8 = if (n.esc == 'x') 2 else 4;
                if (std.fmt.charToDigit(c, 16)) |v| {
                    n.esc_val = n.esc_val * 16 + v;
                    n.esc_digits += 1;
                    if (n.esc_digits == want) {
                        n.esc = 0;
                        n.sputCode(@intCast(n.esc_val));
                    }
                    return;
                } else |_| {}
                // Not a valid escape: keep the letter, as engines do for \x without digits.
                n.esc = 0;
                n.sput(if (want == 2) 'x' else 'u');
                try n.stringByte(c);
            },
            else => unreachable,
        }
    }

    fn sput(n: *Normalizer, c: u8) void {
        if (n.slen < n.sbuf.len) {
            n.sbuf[n.slen] = c;
            n.slen += 1;
        }
    }

    fn sputCode(n: *Normalizer, cp: u21) void {
        var e: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(if (cp >= 0xd800 and cp <= 0xdfff) 0xfffd else cp, &e) catch return n.sput('?');
        for (e[0..len]) |b| n.sput(b);
    }

    fn endString(n: *Normalizer) Error!void {
        if (n.esc == 'o') n.sput(@intCast(n.esc_val));
        n.esc = 0;
        try n.token(.string, n.sbuf[0..n.slen]);
    }

    // -----------------------------------------------------------------------------------------
    // Tokens: declarations and renaming, then call folding, then string folding, then output.

    fn token(n: *Normalizer, kind: TokKind, text: []const u8) Error!void {
        var t = text;
        var renamed: [8]u8 = undefined;
        if (!n.rename_disabled and kind == .word) {
            if (isKeyword(t)) {
                n.declKeyword(t);
            } else if (n.prev != .dot) {
                const binding = if (n.declaring()) n.declare(t) else n.slots[n.findSlot(t)];
                if (binding != 0) t = std.fmt.bufPrint(&renamed, "n{d:0>3}", .{binding - 1}) catch t;
            }
        } else if (!n.rename_disabled and kind == .punct) n.declPunct(t[0]);
        n.prev = switch (kind) {
            .word => if (isKeyword(text) and !isValueKeyword(text)) .other else .operand,
            .number, .string, .regex => .operand,
            .punct => switch (t[0]) {
                ')', ']', '}' => .operand,
                '.' => .dot,
                else => .other,
            },
        };
        try n.callToken(kind, t);
    }

    fn declaring(n: *const Normalizer) bool {
        return switch (n.decl) {
            .var_next, .func_name => true,
            .func_params => n.depth == n.decl_depth + 1,
            else => false,
        };
    }

    fn declKeyword(n: *Normalizer, t: []const u8) void {
        if (std.mem.eql(u8, t, "var")) {
            n.decl = .var_next;
            n.var_depth = n.depth;
        } else if (std.mem.eql(u8, t, "function")) {
            if (n.function_count == max_functions) {
                n.rename_disabled = true;
                return;
            }
            n.functions[n.function_count] = .{
                .saved_decl = n.decl,
                .saved_decl_depth = n.decl_depth,
                .saved_var_depth = n.var_depth,
            };
            n.function_count += 1;
            n.decl = .func_name;
            n.decl_depth = n.depth;
        }
    }

    fn declPunct(n: *Normalizer, c: u8) void {
        switch (c) {
            '(', '[', '{' => {
                if (n.decl == .func_name and c == '(') n.decl = .func_params;
                n.depth += 1;
                if (c == '{' and n.function_count != 0) {
                    const frame = &n.functions[n.function_count - 1];
                    // The first brace starts the scope body in libclamav's lexer, including
                    // a brace in a default parameter. Its matching brace ends the scope.
                    if (frame.body_depth == null) frame.body_depth = n.depth;
                }
            },
            ')', ']', '}' => {
                const end_function = c == '}' and n.function_count != 0 and
                    n.functions[n.function_count - 1].body_depth == n.depth;
                n.depth -= 1;
                if (end_function) {
                    n.finishFunction();
                    return;
                }
                if (n.decl == .func_params and n.depth == n.decl_depth) n.decl = .none;
                if ((n.decl == .var_list or n.decl == .var_next) and n.depth < n.var_depth) n.decl = .none;
            },
            ',' => if (n.decl == .var_list and n.depth == n.var_depth) {
                n.decl = .var_next;
            },
            ';' => if (n.decl == .var_list or n.decl == .var_next) {
                n.decl = .none;
            },
            else => {},
        }
    }

    fn declare(n: *Normalizer, t: []const u8) u16 {
        if (n.decl == .var_next) n.decl = .var_list;
        if (n.decl == .func_name) n.decl = .func_params; // the name; parameters follow
        const slot = n.findSlot(t);
        const previous = n.slots[slot];
        if (previous != 0 and n.names[previous - 1].level == n.function_count) return previous;
        if (n.nnames == max_names or t.len > 255) return 0;
        const off = if (previous != 0) n.names[previous - 1].off else blk: {
            if (n.name_used + t.len > n.name_bytes.len) return 0;
            const offset: u32 = @intCast(n.name_used);
            @memcpy(n.name_bytes[n.name_used..][0..t.len], t);
            n.name_used += t.len;
            break :blk offset;
        };
        const frame = if (n.function_count == 0) null else &n.functions[n.function_count - 1];
        n.names[n.nnames] = .{
            .off = off,
            .len = @intCast(t.len),
            .level = n.function_count,
            .slot = @intCast(slot),
            .previous_value = previous,
            .previous_binding = if (frame) |f| f.last_binding else 0,
        };
        n.nnames += 1;
        const binding: u16 = @intCast(n.nnames);
        n.slots[slot] = binding;
        if (frame) |f| f.last_binding = binding;
        return binding;
    }

    fn finishFunction(n: *Normalizer) void {
        n.function_count -= 1;
        const frame = n.functions[n.function_count];
        var binding = frame.last_binding;
        // Undo insertions in reverse order to preserve each probe chain.
        while (binding != 0) {
            const name = n.names[binding - 1];
            n.slots[name.slot] = name.previous_value;
            binding = name.previous_binding;
        }
        n.decl = frame.saved_decl;
        n.decl_depth = frame.saved_decl_depth;
        n.var_depth = frame.saved_var_depth;
    }

    fn slotOf(t: []const u8) usize {
        return @intCast(std.hash.Wyhash.hash(0x6a73, t) % (2 * max_names));
    }

    fn findSlot(n: *const Normalizer, t: []const u8) usize {
        // At most half the slots are used, so a probe always reaches an empty one.
        var h = slotOf(t);
        while (n.slots[h] != 0) : (h = (h + 1) % n.slots.len) {
            const i = n.slots[h] - 1;
            const e = n.names[i];
            if (std.mem.eql(u8, n.name_bytes[e.off..][0..e.len], t)) break;
        }
        return h;
    }

    /// Call folding: unescape("...") and String.fromCharCode(numbers).
    fn callToken(n: *Normalizer, kind: TokKind, t: []const u8) Error!void {
        switch (n.call) {
            .idle => {},
            .unescape => if (isPunct(kind, t, '(')) {
                n.call = .unescape_paren;
                return;
            },
            .unescape_paren => if (kind == .string) {
                n.call_str_len = @min(t.len, n.call_str.len);
                @memcpy(n.call_str[0..n.call_str_len], t[0..n.call_str_len]);
                n.call = .unescape_str;
                return;
            },
            .unescape_str => if (isPunct(kind, t, ')')) {
                n.call = .idle;
                // The lexer's string buffer is free: the current token is a ')'.
                return n.foldString(unescape(n.call_str[0..n.call_str_len], &n.sbuf));
            },
            .string => if (isPunct(kind, t, '.')) {
                n.call = .string_dot;
                return;
            },
            .string_dot => if (kind == .word and std.mem.eql(u8, t, "fromCharCode")) {
                n.call = .from_char_code;
                return;
            },
            .from_char_code => if (isPunct(kind, t, '(')) {
                n.call = .fcc_paren;
                n.nargs = 0;
                return;
            },
            .fcc_paren, .fcc_comma => {
                if (kind == .number and n.nargs < max_args) {
                    if (parseNumber(t)) |v| {
                        n.args[n.nargs] = v;
                        n.nargs += 1;
                        n.call = .fcc_num;
                        return;
                    }
                }
                if (n.call == .fcc_paren and isPunct(kind, t, ')')) {
                    n.call = .idle;
                    return n.foldString("");
                }
            },
            .fcc_num => {
                if (isPunct(kind, t, ',')) {
                    n.call = .fcc_comma;
                    return;
                }
                if (isPunct(kind, t, ')')) {
                    n.call = .idle;
                    var buf: [max_args * 4]u8 = undefined;
                    var len: usize = 0;
                    for (n.args[0..n.nargs]) |cp| len += std.unicode.utf8Encode(if (cp >= 0xd800 and cp <= 0xdfff) 0xfffd else cp, buf[len..][0..4]) catch 0;
                    return n.foldString(buf[0..len]);
                }
            },
        }
        // Not (or no longer) a foldable call: release what was held, then this token.
        try n.releaseCall();
        if (kind == .word and std.mem.eql(u8, t, "unescape")) {
            n.call = .unescape;
            return;
        }
        if (!n.html_output and kind == .word and std.mem.eql(u8, t, "String")) {
            n.call = .string;
            return;
        }
        try n.foldToken(kind, t);
    }

    /// Emit the tokens a partial call match held back.
    fn releaseCall(n: *Normalizer) Error!void {
        const state = n.call;
        n.call = .idle;
        switch (state) {
            .idle => {},
            .unescape, .unescape_paren, .unescape_str => {
                try n.foldToken(.word, "unescape");
                if (state == .unescape) return;
                try n.foldToken(.punct, "(");
                if (state == .unescape_str) try n.foldToken(.string, n.call_str[0..n.call_str_len]);
            },
            .string, .string_dot, .from_char_code, .fcc_paren, .fcc_num, .fcc_comma => {
                try n.foldToken(.word, "String");
                if (state == .string) return;
                try n.foldToken(.punct, ".");
                if (state == .string_dot) return;
                try n.foldToken(.word, "fromCharCode");
                if (state == .from_char_code) return;
                try n.foldToken(.punct, "(");
                for (n.args[0..n.nargs], 0..) |v, i| {
                    if (i > 0) try n.foldToken(.punct, ",");
                    var nb: [8]u8 = undefined;
                    try n.foldToken(.number, std.fmt.bufPrint(&nb, "{d}", .{v}) catch "0");
                }
                if (state == .fcc_comma) try n.foldToken(.punct, ",");
            },
        }
    }

    fn foldString(n: *Normalizer, s: []const u8) Error!void {
        try n.foldToken(.string, s);
        n.prev = .operand;
    }

    /// String folding: "a" + "b" becomes "ab".
    fn foldToken(n: *Normalizer, kind: TokKind, t: []const u8) Error!void {
        if (kind == .string) {
            if (n.have_pend and !n.pend_plus) try n.flushPend();
            if (!n.have_pend) {
                n.have_pend = true;
                n.pend_len = 0;
            }
            n.pend_plus = false;
            for (t) |c| {
                if (n.pend_len == n.pend.len) {
                    // Too long to fold further: write it out and continue in a new literal.
                    try n.flushPend();
                    n.have_pend = true;
                    n.pend_len = 0;
                }
                n.pend[n.pend_len] = c;
                n.pend_len += 1;
            }
            return;
        }
        if (n.have_pend and !n.pend_plus and isPunct(kind, t, '+')) {
            n.pend_plus = true;
            return;
        }
        try n.flushPend();
        try n.emit(kind, t);
    }

    fn flushPend(n: *Normalizer) Error!void {
        if (!n.have_pend) return;
        n.have_pend = false;
        try n.sep(.string);
        try n.put('"');
        for (n.pend[0..n.pend_len]) |c| {
            if (c == '"' or c == '\\') try n.put('\\');
            try n.put(c);
        }
        try n.put('"');
        n.last_out = .string;
        if (n.pend_plus) {
            n.pend_plus = false;
            try n.emit(.punct, "+");
        }
    }

    fn emit(n: *Normalizer, kind: TokKind, t: []const u8) Error!void {
        try n.sep(kind);
        // Keep "a - -b" and "a + +b" from becoming decrements and increments.
        if (kind == .punct and (t[0] == '+' or t[0] == '-') and n.last_out == .punct and n.last_char == t[0]) try n.put(' ');
        for (t) |c| try n.put(c);
        n.last_out = kind;
    }

    /// One space between two word-like tokens.
    fn sep(n: *Normalizer, kind: TokKind) Error!void {
        const wordy = kind == .word or kind == .number;
        const last_wordy = n.last_out == .word or n.last_out == .number;
        if (wordy and last_wordy) try n.put(' ');
    }

    fn put(n: *Normalizer, c: u8) Error!void {
        if (n.olen == n.obuf.len) try n.flushOut();
        n.obuf[n.olen] = c;
        n.olen += 1;
        n.last_char = c;
    }

    fn flushOut(n: *Normalizer) Error!void {
        if (n.olen == 0) return;
        const chunk = n.obuf[0..n.olen];
        if (n.html_output) _ = std.ascii.lowerString(chunk, chunk);
        try n.out.write(n.out.ctx, chunk);
        n.olen = 0;
    }
};

fn isPunct(kind: TokKind, t: []const u8, c: u8) bool {
    return kind == .punct and t.len == 1 and t[0] == c;
}

fn isWordStart(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_' or c == '$' or c >= 0x80;
}

fn isWordChar(c: u8) bool {
    return isWordStart(c) or std.ascii.isDigit(c);
}

const keywords = [_][]const u8{
    "break", "case",       "catch",  "class",   "const",   "continue", "debugger", "default", "delete",
    "do",    "else",       "export", "extends", "finally", "for",      "function", "if",      "import",
    "in",    "instanceof", "let",    "new",     "return",  "super",    "switch",   "this",    "throw",
    "try",   "typeof",     "var",    "void",    "while",   "with",     "yield",    "true",    "false",
    "null",  "undefined",  "async",  "await",   "of",
};

fn isKeyword(t: []const u8) bool {
    for (keywords) |k| if (std.mem.eql(u8, t, k)) return true;
    return false;
}

/// Keywords that are values: a `/` after them divides.
fn isValueKeyword(t: []const u8) bool {
    for ([_][]const u8{ "this", "true", "false", "null", "undefined", "super" }) |k| if (std.mem.eql(u8, t, k)) return true;
    return false;
}

/// A numeric literal as a code point for String.fromCharCode (decimal, hex, octal-prefixed).
fn parseNumber(t: []const u8) ?u21 {
    const v: u64 = if (t.len > 2 and t[0] == '0' and (t[1] == 'x' or t[1] == 'X'))
        std.fmt.parseInt(u64, t[2..], 16) catch return null
    else
        std.fmt.parseInt(u64, t, 10) catch return null;
    // fromCharCode takes the value modulo 2^16.
    return @intCast(v & 0xffff);
}

/// JavaScript's unescape(): %XX and %uXXXX, everything else as it is.
pub fn unescape(s: []const u8, out: []u8) []const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < s.len and o + 4 <= out.len) {
        if (s[i] == '%') {
            if (i + 5 < s.len + 0 and (s[i + 1] == 'u' or s[i + 1] == 'U')) {
                if (std.fmt.parseInt(u16, s[i + 2 .. i + 6], 16)) |v| {
                    const cp: u21 = if (v >= 0xd800 and v <= 0xdfff) 0xfffd else v;
                    o += std.unicode.utf8Encode(cp, out[o..][0..4]) catch 0;
                    i += 6;
                    continue;
                } else |_| {}
            }
            if (i + 2 < s.len) {
                if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |v| {
                    out[o] = v;
                    o += 1;
                    i += 3;
                    continue;
                } else |_| {}
            }
        }
        out[o] = s[i];
        o += 1;
        i += 1;
    }
    return out[0..o];
}

// ---------------------------------------------------------------------------------------------

const Capture = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,
    fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const c: *Capture = @ptrCast(@alignCast(ctx));
        @memcpy(c.buf[c.len..][0..bytes.len], bytes);
        c.len += bytes.len;
    }
};

fn normalize(input: []const u8, cap: *Capture) ![]const u8 {
    const n = try std.testing.allocator.create(Normalizer);
    defer std.testing.allocator.destroy(n);
    n.* = .init(.{ .ctx = cap, .write = Capture.write });
    try n.feed(input);
    try n.finish();
    return cap.buf[0..cap.len];
}

test "white space, comments, renaming and folding" {
    const cases = [_][2][]const u8{
        .{ "var foo = 'bar'; alert(foo);", "var n000=\"bar\";alert(n000);" },
        .{ "var  a = \"ev\" + 'al' ; // comment\n/* block */ window[a]('x')", "var n000=\"eval\";window[n000](\"x\")" },
        .{ "function f(x, y) { return x + y; } f(1, 2);", "function n000(n001,n002){return n001+n002;}f(1,2);" },
        .{ "var s = unescape('%61%6C%u0065rt'); var t = String.fromCharCode(0x65, 118, 97, 108);", "var n000=\"alert\";var n001=\"eval\";" },
        .{ "x = \"\\x41\\u0042\\103\\n\\\"\";", "x=\"ABC\n\\\"\";" },
        .{ "var o = {}; o.foo = 1; var foo = o.foo;", "var n000={};n000.foo=1;var n001=n000.foo;" },
        .{ "a = b / c; r = /ab+c\\//gi.test(s);", "a=b/c;r=/ab+c\\//gi.test(s);" },
        .{ "a = 1 - -2 + +3", "a=1- -2+ +3" },
        .{ "var a = 'x' + unescape(y) + 'z';", "var n000=\"x\"+unescape(y)+\"z\";" },
        .{ "return typeof x", "return typeof x" },
        .{ "var a, b = [1, c], d; d = a;", "var n000,n001=[1,c],n002;n002=n000;" },
        .{ "document.write(\"<scr\" + \"ipt>\")", "document.write(\"<script>\")" },
    };
    for (cases) |c| {
        var cap: Capture = .{};
        const got = try normalize(c[0], &cap);
        std.testing.expectEqualStrings(c[1], got) catch |e| {
            std.debug.print("input: {s}\n", .{c[0]});
            return e;
        };
    }
}

test "function scopes reproduce ClamAV declaration numbering" {
    const cases = [_][2][]const u8{
        .{ "var item=0;function first(item){var top=item;return top;}var result=item;report(top,result);", "var n000=0;function n001(n002){var n003=n002;return n003;}var n004=n000;report(top,n004);" },
        .{ "function outer(item){function inner(q){return inner(q);}inner(item);return outer(item);}outer(1);inner(1);", "function n000(n001){function n002(n003){return n002(n003);}inner(n001);return n000(n001);}outer(1);inner(1);" },
        .{ "var a=1, handler=function f(a){return f(a);}, b=a; f(a); use(a,b,handler);", "var n000=1,n001=function n002(n003){return n002(n003);},n004=n000;f(n000);use(n000,n004,n001);" },
        .{ "function a(x=1){return x;} function b(x={}){return x;} function c(x=[1]){return x;} test(x);", "function n000(n001=1){return n001;}function n002(n003={}){return x;}function n004(n005=[1]){return n005;}test(x);" },
    };
    for (cases) |config| {
        var cap: Capture = .{};
        try std.testing.expectEqualStrings(config[1], try normalize(config[0], &cap));
    }
}

test "output is the same for every block split" {
    const input = "var a='he'+\"llo\"; /* c */ function g(p){return unescape('%41')+p;} // x\nb=/[/]x/g;";
    var whole: Capture = .{};
    const want = try normalize(input, &whole);
    for (1..input.len) |split| {
        var cap: Capture = .{};
        const n = try std.testing.allocator.create(Normalizer);
        defer std.testing.allocator.destroy(n);
        n.* = .init(.{ .ctx = &cap, .write = Capture.write });
        try n.feed(input[0..split]);
        try n.feed(input[split..]);
        try n.finish();
        try std.testing.expectEqualStrings(want, cap.buf[0..cap.len]);
    }
}

/// Fuzz inputs (`fmt.js`): pages whose scripts exercise every lexer state and fold.
pub const fuzz_pages = [_][]const u8{
    "<html><script>var a='he'+\"llo\", b = unescape('%u0041%42'); /* c */ function g(p, q){return String.fromCharCode(0x41, 66)+p;} // x\nb=/[/]x\\//g; c = a / 2;</script></html>",
    "<script>eval(\"\\x61\\u0062\\143\" + `tpl` + 'a\\\nb'); var s = \"unterminated\n; x = y - -z + +w; if (a) { var m = {k: 'v'}; m.k = 1 }</script>",
    "<script>document.write(unescape('%3C%73%63%72%69%70%74%3E')); var _0x1a2b=['\\x65\\x76\\x61\\x6c'];window[_0x1a2b[0]](String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
};

const scan = @import("scan.zig");

test "scripts in HTML and PDF reach the normaliser as js children" {
    var rig: scan.TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth("<html><body><script>var P = 'EV' + 'AL'; window[P]('1');</script></body></html>", "p.html");
    const want = "var n000=\"eval\";window[n000](\"1\");";
    var crc = std.hash.Crc32.init();
    crc.update(want);
    var seen: usize = 0;
    // libclamav's `javascript` layout: the script between <script> and its own end tag.
    const want_file = "<script>" ++ want ++ "</script>";
    crc = std.hash.Crc32.init();
    crc.update(want_file);
    for (rig.rec.objects.items) |e| if (std.mem.eql(u8, e.path, "p.html/js")) {
        seen += 1;
        try std.testing.expectEqual(@import("../engine/container.zig").Kind.normalized_js, e.kind);
        try std.testing.expectEqual(@as(u64, want_file.len), e.bytes);
        try std.testing.expectEqual(crc.final(), e.crc);
    };
    try std.testing.expectEqual(@as(usize, 2), seen);

    const docs = @import("fixtures/docs.zig");
    for (docs.docs) |d| if (std.mem.eql(u8, d.name, "js-embedded.pdf")) {
        var rig2: scan.TestRig = undefined;
        try rig2.init(.{});
        defer rig2.deinit();
        try rig2.scanBoth(d.bytes, d.name);
        const js = "app.alert({cMsg:\"zav\",cTitle:\"zav\"});var n000=eval(\"1+1\");";
        var c2 = std.hash.Crc32.init();
        c2.update(js);
        var n: usize = 0;
        for (rig2.rec.objects.items) |e| if (std.mem.eql(u8, e.path, "js-embedded.pdf/js/s0/js")) {
            n += 1;
            try std.testing.expectEqual(@as(u64, js.len), e.bytes);
            try std.testing.expectEqual(c2.final(), e.crc);
        };
        if (n != 2) {
            rig2.rec.dump();
            return error.TestUnexpectedResult;
        }
    };
}
