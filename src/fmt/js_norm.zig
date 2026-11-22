//! The JavaScript normaliser (P5.13): lexical normalisation of scripts from HTML and PDF so that
//! obfuscated code matches signatures written against the normalised form. It never evaluates
//! code. The HTML form reproduces the `javascript` file libclamav writes for a page; its rules
//! were found black-box, from libclamav's outputs only (docs/clean-room.md, tools/diff/js_goldens.py).
//!
//! What it does, in one pass with fixed memory:
//! - block comments and white space are removed; one space separates two word tokens;
//! - string literals are decoded and written double-quoted;
//! - adjacent string literals joined with `+` are folded into one (`"ev"+"al"` is `"eval"`);
//! - `unescape("...")` of a literal is decoded (%XX and %uXXXX); standalone scripts also fold
//!   `String.fromCharCode(n, ...)` with numeric arguments, HTML scripts replace `eval("...")`
//!   by the tokens of its code;
//! - names declared with var, function names (in the function's own scope) and parameters are
//!   numbered in declaration order. A use refers to its scope's entry for the name, which a later
//!   declaration in that scope (or, once the scope ends, in an enclosing one) also numbers, so
//!   the output is held back until the script ends. Property names after `.` keep their spelling.
//!
//! The HTML form differs from the standalone one as libclamav's does: ASCII is lowercased; there
//! are no regular expression literals; a `//` comment ends at the first space or line feed;
//! control bytes, `#`, `@`, the backtick and bytes from 0x80 separate tokens and NUL vanishes;
//! a backslash outside strings separates words with a space; strings end at the first quote not
//! after a backslash, know no octal escapes and are written with their quotes and backslashes
//! as they are; punctuation is written without spaces; and parentheses left open are closed.
//!
//! Bounds: a folded string is flushed at `max_string` bytes, at most `max_names` names are
//! renamed, output beyond `defer_size` is renamed with what is known when it is written,
//! `String.fromCharCode` folds at most `max_args` arguments, and the caller limits the input to
//! MaxScriptNormalize.
const std = @import("std");

pub const max_string = 64 * 1024;
pub const max_names = 4096;
pub const max_args = 1024;
/// Output held back for renaming; a longer script is renamed with what is known when it fills.
pub const defer_size = 256 * 1024;
/// libclamav has no limit on a word; zav keeps this much of one.
const max_word = 64 * 1024;
const max_functions = 64;

pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
};

pub const Error = error{Stop};

const Lex = enum { start, word, number, string, line_comment, block_comment, block_star, regex, regex_class, regex_flags, slash, backslash };

/// `sep` is what a backslash leaves between HTML tokens: " " is a space, "" a space only
/// before a word or number that would not get one, "-" nothing.
const TokKind = enum { word, number, string, punct, regex, sep };

/// Token classes the previous significant token can have, which decide whether `/` starts a
/// regular expression and whether a word is a property name.
const Prev = enum { none, operand, dot, other };

pub const Normalizer = struct {
    out: Output,
    html_output: bool = false,
    // Output. Everything written is held in `dbuf` until the script ends (or the buffer fills),
    // because a name's number is only known once its scope has seen every declaration: a
    // marker byte 0 and a big-endian entry index stand for a name, 0 0xffff for a literal NUL.
    dbuf: [defer_size]u8 = undefined,
    dlen: usize = 0,
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
    /// A backslash ended a number (it then leaves a space whatever follows).
    bs_after_number: bool = false,
    soft_space: bool = false,
    /// White space (or a backslash) came after the last word or number: a backslash then
    /// leaves a space whatever follows.
    ws_after_word: bool = false,
    prev_wordy: bool = false,
    prev_number: bool = false,
    /// The byte before this one in an HTML string: a quote right after a backslash never ends
    /// the string, not even after an escaped backslash (`'\\'` goes on).
    raw_prev: u8 = 0,
    /// The bytes of a \x or \u escape read so far (HTML output).
    esc_buf: [4]u8 = undefined,
    /// Parentheses still open (HTML output): libclamav closes them when the script ends.
    open_parens: u32 = 0,
    prev: Prev = .none,
    // Folding: a pending string and whether a `+` followed it.
    pend: [max_string]u8 = undefined,
    pend_len: usize = 0,
    have_pend: bool = false,
    pend_plus: bool = false,
    // Call folding: unescape("..."), eval("...") and String.fromCharCode(...).
    call: Call = .idle,
    call_dot: bool = false,
    call_str: [max_string]u8 = undefined,
    call_str_len: usize = 0,
    /// `eval(` was held before an `unescape` call that may become its argument.
    eval_open: bool = false,
    /// The entry a held call's first word was declared as (`var unescape('%41')` declares).
    held_entry: u16 = 0,
    /// The same for `unescape` held inside `eval(`.
    held_inner: u16 = 0,
    /// An expanded eval also takes the `;` after its call.
    drop_semicolon: bool = false,
    expanding: bool = false,
    eval_src: [max_string]u8 = undefined,
    /// The word or number an eval's code left unfinished: it waits, unwritten, for the code of
    /// the next eval, which continues it (`eval('c');eval('d=1')` writes `cd=1`).
    eval_lex: Lex = .start,
    eval_number: HtmlNumber = .integer,
    eval_word: [1024]u8 = undefined,
    eval_word_len: usize = 0,
    args: [max_args]u21 = undefined,
    nargs: usize = 0,
    // Declarations and renaming.
    names: [max_names]Name = undefined,
    nnames: usize = 0,
    /// Open-addressing index over the names of the open scopes: entry index + 1, 0 for empty.
    slots: [2 * max_names]u16 = @splat(0),
    name_bytes: [max_names * 16]u8 = undefined,
    name_used: usize = 0,
    next_number: u32 = 0,
    name_dot: bool = false,
    decl: Decl = .none,
    /// Nesting of `{` (never below zero) and of `[`. Parentheses do not matter to declarations.
    curly: i32 = 0,
    square: i32 = 0,
    /// The `[` nesting at the last name of a var list.
    var_level: i32 = 0,
    functions: [max_functions]Function = undefined,
    function_count: u8 = 0,
    rename_disabled: bool = false,

    /// A name in one scope. Every use of a name refers to an entry of its own scope; one that
    /// is never declared there refers on to the enclosing scope's entry when its scope ends.
    const Name = struct {
        off: u32,
        len: u8,
        level: u8,
        slot: u16,
        previous_value: u16,
        previous_binding: u16,
        /// The declaration number + 1 (the latest declaration wins), 0 while undeclared.
        number: u32 = 0,
        /// The enclosing scope's entry (index + 1) for a name its own scope never declared.
        alias: u16 = 0,
    };
    const HtmlNumber = enum { integer, fraction, exponent_start, exponent_digits };
    const Decl = enum { none, var_next, var_list };
    /// A function from its keyword to the end of its body: its scope, and what its header
    /// declares. `function` and the `(` after its name each make the next name a declaration,
    /// until a `{` or `;`; once a parameter is declared, a `,` outside the body's braces makes
    /// the next name one too, and that one survives a `{` (`function(r,{a` declares r and a).
    /// A `)` changes nothing (`function()n` declares n).
    const Function = struct {
        saved_decl: Decl,
        saved_var_level: i32,
        /// The `{` and `[` nesting at the keyword: a var list in the function goes on at it.
        /// The `[` nesting comes back when the function ends.
        base_curly: i32,
        base_square: i32,
        body_curly: ?i32 = null,
        last_binding: u16 = 0,
        expect: enum { none, open, comma } = .open,
        stage: enum { name, params, done } = .name,
        declared_param: bool = false,
    };
    const Call = enum { idle, eval, eval_paren, eval_str, unescape, unescape_paren, unescape_str, string, string_dot, from_char_code, fcc_paren, fcc_num, fcc_comma };

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
        if (n.html_output) return n.finishHtml();
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
        try n.flushPend();
        try n.releaseCall();
        n.closeScopes();
        try n.flushDeferred();
    }

    /// The end of an HTML script: an open string ends where the input does, without the space
    /// that ends a word, and every parenthesis still open is closed.
    fn finishHtml(n: *Normalizer) Error!void {
        switch (n.lex) {
            .string => {
                n.lex = .start;
                try n.endString();
            },
            else => try n.byte(' '),
        }
        n.lex = .start;
        try n.flushPend();
        // A call whose string argument the script's end cut off still folds.
        switch (n.call) {
            .unescape_str, .eval_str => try n.callToken(.punct, ")"),
            else => {},
        }
        try n.releaseCall();
        while (n.open_parens > 0) : (n.open_parens -= 1) try n.emit(.punct, ")");
        n.closeScopes();
        try n.flushDeferred();
    }

    // -----------------------------------------------------------------------------------------
    // Lexer.

    fn byte(n: *Normalizer, c: u8) Error!void {
        // A NUL outside a string is not there at all in libclamav's HTML output: `a\x00b` is `ab`.
        if (n.html_output and c == 0 and n.lex != .string) return;
        switch (n.lex) {
            .start => try n.startToken(c),
            .word => {
                if (n.html_output and c == '\\') {
                    n.lex = .backslash;
                    return;
                }
                if (if (n.html_output) isHtmlWordChar(c) else isWordChar(c)) {
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
                if (n.html_output and c == '\\') {
                    n.word_len = 0;
                    n.bs_after_number = true;
                    n.lex = .backslash;
                    return;
                }
                try n.startToken(c);
            },
            .backslash => try n.backslashByte(c),
            .string => if (n.html_output) try n.htmlStringByte(c) else try n.stringByte(c),
            .slash => {
                if (c == '/') {
                    n.lex = .line_comment;
                } else if (c == '*') {
                    n.lex = .block_comment;
                } else if (n.html_output or n.prev == .operand) {
                    // HTML scripts have no regular expression literals: `/` is an operator
                    // and the pattern's characters are ordinary tokens.
                    n.lex = .start;
                    try n.token(.punct, "/");
                    try n.startToken(c);
                } else {
                    // A regular expression literal: passed through as it is.
                    n.lex = .regex;
                    try n.flushPend();
                    try n.releaseCall();
                    try n.sep(.regex);
                    try n.put('/');
                    n.regex_escape = false;
                    try n.regexByte(c);
                }
            },
            // In HTML a line comment ends at the first space or line feed.
            .line_comment => if (if (n.html_output) c == ' ' or c == '\n' else c == '\n' or c == '\r') {
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

    /// The byte after a backslash in HTML script text. `\u` stays in the word as `\`; any other
    /// backslash ends the word and leaves a space before a word or number (`a\b` is `a b`,
    /// `(\b` is `( b`, `a\(b` is `a(b`), plus a space whatever follows when it comes after a
    /// number, after white space following a word, or before another backslash. Right after a
    /// `.` it leaves nothing (`a.\nb` is `a.nb`). The words on either side are separate names.
    fn backslashByte(n: *Normalizer, c: u8) Error!void {
        if (c == 'u') {
            if (n.word_len < max_word) {
                n.word[n.word_len] = '\\';
                n.word_len += 1;
            }
            n.lex = .word;
            return;
        }
        const after_word = n.word_len > 0;
        const after_dot = !after_word and n.prev == .dot;
        const hard = n.bs_after_number or (!after_word and (n.prev_number or n.ws_after_word));
        n.bs_after_number = false;
        n.lex = .start;
        if (after_word) try n.token(.word, n.word[0..n.word_len]);
        n.word_len = 0;
        if (after_dot) {
            try n.token(.sep, "-");
        } else {
            if (hard) try n.token(.sep, " ");
            try n.token(.sep, if (c == '\\') " " else "");
        }
        // The backslash itself counts as a word for the next one.
        n.prev = .other;
        n.prev_wordy = true;
        n.prev_number = false;
        if (c == '\\') {
            n.lex = .backslash;
            return;
        }
        try n.startToken(c);
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
        if (n.html_output) {
            // Control bytes, space, `#`, `@`, the backtick, DEL and every byte from 0x80 only
            // separate tokens. A backslash is handled by backslashByte.
            if (c <= ' ' or c == '#' or c == '@' or c == '`' or c >= 0x7f) {
                if (n.prev_wordy) n.ws_after_word = true;
                return;
            }
            if (c == '\\') {
                n.lex = .backslash;
                n.word_len = 0;
                return;
            }
        }
        switch (c) {
            ' ', '\t', '\n', '\r', 0x0b, 0x0c, 0 => {},
            '#', '@', '\\' => if (!n.html_output) try n.token(.punct, &.{c}),
            '"', '\'', '`' => {
                if (n.html_output and c == '`') return;
                n.lex = .string;
                n.quote = c;
                n.slen = 0;
                n.raw_prev = 0;
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
                } else if (!n.html_output and (c == '\n' or c == '\r') and n.quote != '`') {
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

    /// String literals in HTML scripts end at the first quote not right after a backslash. \xHH is the byte HH and \uHHHH the code point in UTF-8
    /// (surrogates encoded on their own); a malformed one is 0xFF or U+FFFF. There are no octal
    /// escapes: \0 is NUL and any other escaped character stands for itself. An escape cut off
    /// by the closing quote leaves a backslash, plus the digits read so far after \u.
    fn htmlStringByte(n: *Normalizer, c: u8) Error!void {
        switch (n.esc) {
            0 => {
                if (c == n.quote and n.raw_prev != '\\') {
                    n.lex = .start;
                    return n.endString();
                }
                n.raw_prev = c;
                if (c == '\\') n.esc = 1 else n.sput(c);
            },
            1 => {
                n.esc = 0;
                n.raw_prev = c;
                switch (c) {
                    'n' => n.sput('\n'),
                    'r' => n.sput('\r'),
                    't' => n.sput('\t'),
                    'b' => n.sput(8),
                    'f' => n.sput(12),
                    'v' => n.sput(11),
                    '0' => n.sput(0),
                    'x', 'u' => {
                        n.esc = c;
                        n.esc_digits = 0;
                    },
                    else => n.sput(c),
                }
            },
            'x', 'u' => {
                if (c == n.quote and n.raw_prev != '\\') {
                    n.lex = .start;
                    return n.endString();
                }
                n.raw_prev = c;
                n.esc_buf[n.esc_digits] = c;
                n.esc_digits += 1;
                const want: u8 = if (n.esc == 'x') 2 else 4;
                if (n.esc_digits < want) return;
                const value = std.fmt.parseUnsigned(u16, n.esc_buf[0..want], 16) catch null;
                if (n.esc == 'x') n.sput(if (value) |v| @intCast(v) else 0xff) else n.sputWtf8(value orelse 0xffff);
                n.esc = 0;
            },
            else => unreachable,
        }
    }

    /// UTF-8 for a UTF-16 unit, a lone surrogate included.
    fn sputWtf8(n: *Normalizer, unit: u16) void {
        if (unit < 0x80) return n.sput(@intCast(unit));
        if (unit < 0x800) {
            n.sput(@intCast(0xc0 | unit >> 6));
        } else {
            n.sput(@intCast(0xe0 | unit >> 12));
            n.sput(@intCast(0x80 | (unit >> 6 & 0x3f)));
        }
        n.sput(@intCast(0x80 | (unit & 0x3f)));
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
        if (n.html_output) switch (n.esc) {
            1 => n.sput('\\'),
            'x' => n.sput('\\'),
            'u' => {
                n.sput('\\');
                for (n.esc_buf[0..n.esc_digits]) |b| n.sput(b);
            },
            else => {},
        };
        if (n.esc == 'o') n.sput(@intCast(n.esc_val));
        n.esc = 0;
        try n.token(.string, n.sbuf[0..n.slen]);
    }

    // -----------------------------------------------------------------------------------------
    // Tokens pass four stages: string folding ("a" + "b"), call folding (unescape, eval,
    // String.fromCharCode), declarations and renaming, then output.

    fn token(n: *Normalizer, kind: TokKind, t: []const u8) Error!void {
        if (kind != .sep) {
            n.prev_wordy = kind == .word or kind == .number;
            n.prev_number = kind == .number;
            n.ws_after_word = false;
        }
        // What the next `/` means (a regular expression only follows an operator).
        n.prev = switch (kind) {
            .word => if (isKeyword(t) and !isValueKeyword(t)) .other else .operand,
            .number, .string, .regex => .operand,
            .sep => n.prev,
            .punct => switch (t[0]) {
                ')', ']', '}' => .operand,
                '.' => .dot,
                else => .other,
            },
        };
        try n.foldToken(kind, t);
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
        try n.callToken(kind, t);
    }

    fn flushPend(n: *Normalizer) Error!void {
        if (!n.have_pend) return;
        n.have_pend = false;
        const plus = n.pend_plus;
        n.pend_plus = false;
        try n.callToken(.string, n.pend[0..n.pend_len]);
        if (plus) try n.callToken(.punct, "+");
    }

    /// Call folding: unescape("...") and String.fromCharCode(numbers) become their string, and
    /// in HTML scripts eval("...") becomes the tokens of its argument. A folded string folds no
    /// further with its neighbours.
    fn callToken(n: *Normalizer, kind: TokKind, t: []const u8) Error!void {
        const after_dot = n.call_dot;
        n.call_dot = isPunct(kind, t, '.');
        if (n.drop_semicolon) {
            n.drop_semicolon = false;
            if (isPunct(kind, t, ';')) return;
        }
        if (n.callStep(kind, t)) |next| {
            // Held: the declarations see it now, the output when the call folds or fails.
            if (next != .idle) {
                const entry = n.observe(kind, t);
                if (kind == .word) {
                    if (n.call == .eval_paren) n.held_inner = entry else n.held_entry = entry;
                }
            }
            n.call = next;
            return;
        }
        switch (n.call) {
            .eval_str => if (isPunct(kind, t, ')')) {
                n.call = .idle;
                return n.expandEval();
            },
            .unescape_str => if (isPunct(kind, t, ')')) {
                // The lexer's string buffer is free: the current token is a ')'.
                const s = unescape(n.call_str[0..n.call_str_len], &n.sbuf);
                if (n.eval_open) {
                    n.eval_open = false;
                    n.holdString(s);
                    n.call = .eval_str;
                    return;
                }
                n.call = .idle;
                return n.folded(s);
            },
            .fcc_paren => if (isPunct(kind, t, ')')) {
                n.call = .idle;
                return n.folded("");
            },
            .fcc_num => if (isPunct(kind, t, ')')) {
                n.call = .idle;
                var buf: [max_args * 4]u8 = undefined;
                var len: usize = 0;
                for (n.args[0..n.nargs]) |cp| len += std.unicode.utf8Encode(if (cp >= 0xd800 and cp <= 0xdfff) 0xfffd else cp, buf[len..][0..4]) catch 0;
                return n.folded(buf[0..len]);
            },
            else => {},
        }
        // Not (or no longer) a foldable call: release what was held, then this token.
        try n.releaseCall();
        if (kind == .word and !after_dot) {
            const call: Call = if (n.html_output and !n.expanding and std.mem.eql(u8, t, "eval"))
                .eval
            else if (std.mem.eql(u8, t, "unescape"))
                .unescape
            else if (!n.html_output and std.mem.eql(u8, t, "String"))
                .string
            else
                .idle;
            if (call != .idle) {
                n.held_entry = n.observe(kind, t);
                n.call = call;
                return;
            }
        }
        try n.nameToken(kind, t);
    }

    /// The state a held call moves to with this token, or null when the token does not
    /// continue it (or completes it).
    fn callStep(n: *Normalizer, kind: TokKind, t: []const u8) ?Call {
        switch (n.call) {
            .eval => if (isPunct(kind, t, '(')) return .eval_paren,
            .eval_paren => {
                if (kind == .string) {
                    n.holdString(t);
                    return .eval_str;
                }
                if (kind == .word and std.mem.eql(u8, t, "unescape")) {
                    n.eval_open = true;
                    return .unescape;
                }
            },
            .unescape => if (isPunct(kind, t, '(')) return .unescape_paren,
            .unescape_paren => if (kind == .string) {
                n.holdString(t);
                return .unescape_str;
            },
            .string => if (isPunct(kind, t, '.')) return .string_dot,
            .string_dot => if (kind == .word and std.mem.eql(u8, t, "fromCharCode")) return .from_char_code,
            .from_char_code => if (isPunct(kind, t, '(')) {
                n.nargs = 0;
                return .fcc_paren;
            },
            .fcc_paren, .fcc_comma => if (kind == .number and n.nargs < max_args) {
                if (parseNumber(t)) |v| {
                    n.args[n.nargs] = v;
                    n.nargs += 1;
                    return .fcc_num;
                }
            },
            .fcc_num => if (isPunct(kind, t, ',')) return .fcc_comma,
            else => {},
        }
        return null;
    }

    /// A folded call's string.
    fn folded(n: *Normalizer, s: []const u8) Error!void {
        n.held_entry = 0;
        n.held_inner = 0;
        n.name_dot = false;
        try n.emitToken(.string, s, 0);
    }

    fn holdString(n: *Normalizer, s: []const u8) void {
        n.call_str_len = @min(s.len, n.call_str.len);
        @memcpy(n.call_str[0..n.call_str_len], s[0..n.call_str_len]);
    }

    /// eval("code") is replaced by the tokens of the code, lexed as script text by a lexer of
    /// its own. A word or number the code leaves unfinished is not written here
    /// (`eval('a=1')` gives `a=`) but continued by the next eval's code. A `;` right after the
    /// call goes with it.
    fn expandEval(n: *Normalizer) Error!void {
        const len = n.call_str_len;
        @memcpy(n.eval_src[0..len], n.call_str[0..len]);
        const saved_prev = n.prev;
        n.lex = n.eval_lex;
        n.html_number = n.eval_number;
        n.word_len = n.eval_word_len;
        @memcpy(n.word[0..n.word_len], n.eval_word[0..n.word_len]);
        n.expanding = true;
        defer n.expanding = false;
        for (n.eval_src[0..len]) |c| try n.byte(c);
        switch (n.lex) {
            .word, .number, .backslash => {
                n.eval_lex = n.lex;
                n.eval_number = n.html_number;
                n.eval_word_len = @min(n.word_len, n.eval_word.len);
                @memcpy(n.eval_word[0..n.eval_word_len], n.word[0..n.eval_word_len]);
            },
            else => {
                n.eval_lex = .start;
                n.eval_word_len = 0;
            },
        }
        n.lex = .start;
        n.esc = 0;
        n.word_len = 0;
        n.prev = saved_prev;
        n.drop_semicolon = true;
    }

    /// Emit the tokens a partial call match held back (the declarations saw them already).
    fn releaseCall(n: *Normalizer) Error!void {
        const state = n.call;
        const eval_open = n.eval_open;
        const entry = n.held_entry;
        const inner = n.held_inner;
        n.call = .idle;
        n.eval_open = false;
        n.held_entry = 0;
        n.held_inner = 0;
        switch (state) {
            .idle => {},
            .eval, .eval_paren, .eval_str => {
                try n.emitToken(.word, "eval", entry);
                if (state == .eval) return;
                try n.emitToken(.punct, "(", 0);
                if (state == .eval_str) try n.emitToken(.string, n.call_str[0..n.call_str_len], 0);
            },
            .unescape, .unescape_paren, .unescape_str => {
                if (eval_open) {
                    try n.emitToken(.word, "eval", entry);
                    try n.emitToken(.punct, "(", 0);
                    try n.emitToken(.word, "unescape", inner);
                } else try n.emitToken(.word, "unescape", entry);
                if (state == .unescape) return;
                try n.emitToken(.punct, "(", 0);
                if (state == .unescape_str) try n.emitToken(.string, n.call_str[0..n.call_str_len], 0);
            },
            .string, .string_dot, .from_char_code, .fcc_paren, .fcc_num, .fcc_comma => {
                try n.emitToken(.word, "String", entry);
                if (state == .string) return;
                try n.emitToken(.punct, ".", 0);
                if (state == .string_dot) return;
                try n.emitToken(.word, "fromCharCode", 0);
                if (state == .from_char_code) return;
                try n.emitToken(.punct, "(", 0);
                for (n.args[0..n.nargs], 0..) |v, i| {
                    if (i > 0) try n.emitToken(.punct, ",", 0);
                    var nb: [8]u8 = undefined;
                    try n.emitToken(.number, std.fmt.bufPrint(&nb, "{d}", .{v}) catch "0", 0);
                }
                if (state == .fcc_comma) try n.emitToken(.punct, ",", 0);
            },
        }
    }

    /// Declarations and renaming. Names declared with var, function names (in the function's
    /// own scope) and parameters are numbered in declaration order; a redeclaration takes a new
    /// number for every use of the name in its scope, earlier ones included. Property names after
    /// `.` keep their spelling, and so does a name no scope declares.
    fn nameToken(n: *Normalizer, kind: TokKind, t: []const u8) Error!void {
        try n.emitToken(kind, t, n.observe(kind, t));
    }

    /// The declaration side of a token; for a name, the entry it refers to (0: as written).
    /// The tokens of a call that may fold are observed as they come and emitted later, as
    /// they were or folded; the declarations never see a folded call's `)` (so in
    /// `function f unescape('a') b`, `b` is a parameter).
    fn observe(n: *Normalizer, kind: TokKind, t: []const u8) u16 {
        const after_dot = n.name_dot;
        n.name_dot = isPunct(kind, t, '.');
        if (n.rename_disabled) return 0;
        switch (kind) {
            .word => {
                if (isKeyword(t)) {
                    n.declKeyword(t);
                } else if (!after_dot and t.len != 0) {
                    return if (n.declaring()) n.declare(t) else n.entryFor(t);
                }
            },
            .punct => n.declPunct(t[0]),
            else => {},
        }
        return 0;
    }

    fn emitToken(n: *Normalizer, kind: TokKind, t: []const u8, entry: u16) Error!void {
        if (n.html_output and kind == .punct) switch (t[0]) {
            '(' => n.open_parens += 1,
            ')' => n.open_parens -|= 1,
            else => {},
        };
        if (entry != 0) return n.emitName(entry);
        try n.emit(kind, t);
    }

    fn header(n: *Normalizer) ?*Function {
        return if (n.function_count == 0) null else &n.functions[n.function_count - 1];
    }

    fn baseCurly(n: *Normalizer) i32 {
        return if (n.header()) |f| f.base_curly else 0;
    }

    fn declaring(n: *Normalizer) bool {
        if (n.decl == .var_next) return true;
        const f = n.header() orelse return false;
        return f.expect != .none;
    }

    fn declKeyword(n: *Normalizer, t: []const u8) void {
        if (std.mem.eql(u8, t, "var")) {
            n.decl = .var_next;
            // `var` ends a function header (`function var x(` has no parameters).
            if (n.header()) |h| if (h.body_curly == null and h.stage != .done) {
                h.stage = .done;
            };
        } else if (std.mem.eql(u8, t, "function")) {
            if (n.function_count == max_functions) {
                n.rename_disabled = true;
                return;
            }
            n.functions[n.function_count] = .{
                .saved_decl = n.decl,
                .saved_var_level = n.var_level,
                .base_curly = n.curly,
                .base_square = n.square,
            };
            n.function_count += 1;
            n.decl = .none;
        }
    }

    fn declPunct(n: *Normalizer, c: u8) void {
        const f = n.header();
        switch (c) {
            '(' => if (f) |h| if (h.stage == .name and h.body_curly == null) {
                h.stage = .params;
                h.expect = .open;
            },
            '[' => n.square += 1,
            ']' => n.square = @max(0, n.square - 1),
            '{' => {
                n.curly += 1;
                if (f) |h| {
                    if (h.expect == .open) h.expect = .none;
                    // The first brace starts the scope body, including a brace in a default
                    // parameter. Its matching brace ends the scope.
                    if (h.body_curly == null) h.body_curly = n.curly;
                }
            },
            '}' => {
                // A `}` ends a function that has no body yet: its scope closes and an
                // enclosing function's name may still follow (`function [function }a`).
                const end_function = if (f) |h| (h.body_curly orelse n.curly) == n.curly else false;
                n.curly = @max(0, n.curly - 1);
                if (end_function) n.finishFunction();
            },
            // A `,` continues a var list at the `{` nesting of its function (so in a body only
            // the first name of a list is declared), not inside a `[` opened since the last
            // name: `var a=[b,c],d` declares a and d.
            ',' => {
                const base = n.baseCurly();
                if (n.decl == .var_list and n.curly <= base and n.square <= n.var_level) n.decl = .var_next;
                if (f) |h| if (h.stage == .params and h.declared_param and n.curly <= h.base_curly and n.square <= h.base_square) {
                    h.expect = .comma;
                };
            },
            // A `;` ends a var list at its function's `{` nesting, and `var` waits for its
            // name across a `;` nested deeper in `{` or `[`.
            ';' => {
                const base = n.baseCurly();
                const base_square: i32 = if (f) |h| h.base_square else 0;
                switch (n.decl) {
                    .var_list => if (n.curly <= base) {
                        n.decl = .none;
                    },
                    .var_next => if (n.curly <= base and n.square <= base_square) {
                        n.decl = .none;
                    },
                    .none => {},
                }
                if (f) |h| {
                    h.expect = .none;
                    h.stage = .done;
                }
            },
            else => {},
        }
    }

    fn declare(n: *Normalizer, t: []const u8) u16 {
        if (n.decl == .var_next) {
            n.decl = .var_list;
            n.var_level = n.square;
        }
        if (n.header()) |h| if (h.expect != .none) {
            h.expect = .none;
            if (h.stage == .params) h.declared_param = true;
        };
        const entry = n.entryFor(t);
        if (entry != 0) {
            n.names[entry - 1].number = n.next_number + 1;
            n.next_number += 1;
        }
        return entry;
    }

    /// The entry of `t` in the innermost scope, created (undeclared) if it has none; 0 when the
    /// tables are full.
    fn entryFor(n: *Normalizer, t: []const u8) u16 {
        const slot = n.findSlot(t);
        const current = n.slots[slot];
        if (current != 0 and n.names[current - 1].level == n.function_count) return current;
        return n.addEntry(t, slot, n.function_count);
    }

    fn addEntry(n: *Normalizer, t: []const u8, slot: usize, level: u8) u16 {
        if (n.nnames == max_names or t.len > 255) return 0;
        const previous = n.slots[slot];
        const off = if (previous != 0) n.names[previous - 1].off else blk: {
            if (n.name_used + t.len > n.name_bytes.len) return 0;
            const offset: u32 = @intCast(n.name_used);
            @memcpy(n.name_bytes[n.name_used..][0..t.len], t);
            n.name_used += t.len;
            break :blk offset;
        };
        const frame = if (level == 0) null else &n.functions[level - 1];
        n.names[n.nnames] = .{
            .off = off,
            .len = @intCast(t.len),
            .level = level,
            .slot = @intCast(slot),
            .previous_value = previous,
            .previous_binding = if (frame) |f| f.last_binding else 0,
        };
        n.nnames += 1;
        const entry: u16 = @intCast(n.nnames);
        n.slots[slot] = entry;
        if (frame) |f| f.last_binding = entry;
        return entry;
    }

    /// The end of the script ends every function still open, so their undeclared names
    /// resolve outwards.
    fn closeScopes(n: *Normalizer) void {
        while (n.function_count > 0) n.finishFunction();
    }

    fn finishFunction(n: *Normalizer) void {
        n.function_count -= 1;
        const frame = n.functions[n.function_count];
        var entry = frame.last_binding;
        // Undo insertions in reverse order to preserve each probe chain. A name the scope never
        // declared now refers to the enclosing scope's entry for it.
        while (entry != 0) {
            const name = n.names[entry - 1];
            n.slots[name.slot] = name.previous_value;
            if (name.number == 0 and name.alias == 0) {
                const outer = n.slots[name.slot];
                n.names[entry - 1].alias = if (outer != 0 and n.names[outer - 1].level == n.function_count)
                    outer
                else
                    n.addEntry(n.name_bytes[name.off..][0..name.len], name.slot, n.function_count);
            }
            entry = name.previous_binding;
        }
        n.decl = frame.saved_decl;
        n.var_level = frame.saved_var_level;
        n.square = frame.base_square;
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

    /// The text a name entry stands for once every declaration is known.
    fn nameText(n: *const Normalizer, entry: u16, buf: *[16]u8) []const u8 {
        var e = entry;
        while (n.names[e - 1].alias != 0) e = n.names[e - 1].alias;
        const name = n.names[e - 1];
        if (name.number != 0) return std.fmt.bufPrint(buf, "n{d:0>3}", .{name.number - 1}) catch unreachable;
        return n.name_bytes[name.off..][0..name.len];
    }

    // -----------------------------------------------------------------------------------------
    // Output.

    fn emit(n: *Normalizer, kind: TokKind, t: []const u8) Error!void {
        if (kind == .sep) {
            if (t.len == 0) {
                n.soft_space = true;
            } else if (t[0] == ' ') {
                try n.put(' ');
                n.last_out = .punct;
            }
            return;
        }
        try n.space(kind);
        if (kind == .string) {
            try n.put('"');
            for (t) |c| {
                // libclamav's HTML form leaves quotes and backslashes in a string as they are.
                if (!n.html_output and (c == '"' or c == '\\')) try n.put('\\');
                try n.put(c);
            }
            try n.put('"');
            n.last_out = .string;
            return;
        }
        // Keep "a - -b" and "a + +b" from becoming decrements and increments. (The HTML form
        // writes punctuation with no space at all: `a+ +b` is `a++b`.)
        if (!n.html_output and kind == .punct and (t[0] == '+' or t[0] == '-') and n.last_out == .punct and n.last_char == t[0]) try n.put(' ');
        for (t) |c| try n.put(c);
        n.last_out = kind;
    }

    fn emitName(n: *Normalizer, entry: u16) Error!void {
        try n.space(.word);
        if (n.dlen + 3 > n.dbuf.len) try n.flushDeferred();
        n.dbuf[n.dlen] = 0;
        std.mem.writeInt(u16, n.dbuf[n.dlen + 1 ..][0..2], entry, .big);
        n.dlen += 3;
        n.last_out = .word;
        n.last_char = 'n';
    }

    /// The space before a token: between two word-like tokens, or before a word-like token
    /// after a backslash.
    fn space(n: *Normalizer, kind: TokKind) Error!void {
        const soft = n.soft_space;
        n.soft_space = false;
        const wordy = kind == .word or kind == .number;
        const last_wordy = n.last_out == .word or n.last_out == .number;
        if (wordy and (last_wordy or soft)) try n.put(' ');
    }

    /// One space between two word-like tokens.
    fn sep(n: *Normalizer, kind: TokKind) Error!void {
        const wordy = kind == .word or kind == .number;
        const last_wordy = n.last_out == .word or n.last_out == .number;
        if (wordy and last_wordy) try n.put(' ');
    }

    fn put(n: *Normalizer, c: u8) Error!void {
        if (n.dlen + 3 > n.dbuf.len) try n.flushDeferred();
        if (c == 0) {
            @memcpy(n.dbuf[n.dlen..][0..3], &[3]u8{ 0, 0xff, 0xff });
            n.dlen += 3;
        } else {
            n.dbuf[n.dlen] = c;
            n.dlen += 1;
        }
        n.last_char = c;
    }

    /// Write the held output with every name resolved as it stands now.
    fn flushDeferred(n: *Normalizer) Error!void {
        var i: usize = 0;
        while (i < n.dlen) {
            const c = n.dbuf[i];
            if (c != 0) {
                try n.out1(c);
                i += 1;
                continue;
            }
            const entry = std.mem.readInt(u16, n.dbuf[i + 1 ..][0..2], .big);
            i += 3;
            if (entry == 0xffff) {
                try n.out1(0);
                continue;
            }
            var buf: [16]u8 = undefined;
            for (n.nameText(entry, &buf)) |b| try n.out1(b);
        }
        n.dlen = 0;
        try n.flushOut();
    }

    fn out1(n: *Normalizer, c: u8) Error!void {
        if (n.olen == n.obuf.len) try n.flushOut();
        n.obuf[n.olen] = c;
        n.olen += 1;
    }

    fn flushOut(n: *Normalizer) Error!void {
        if (n.olen == 0) return;
        const chunk = n.obuf[0..n.olen];
        if (n.html_output) for (chunk) |*byte_value| {
            byte_value.* = switch (byte_value.*) {
                0 => 1,
                '\t'...'\r' => ' ',
                else => std.ascii.toLower(byte_value.*),
            };
        };
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

/// Word bytes in HTML scripts: bytes from 0x80 separate tokens there.
fn isHtmlWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '$';
}

/// Reserved words, ECMAScript 3's future reserved words included, as libclamav's normaliser
/// keeps them: none is ever renamed. (`let`, `yield`, `async`, `await`, `of` and `undefined`
/// are names to it.)
const keywords = [_][]const u8{
    "abstract",  "boolean",  "break",     "byte",       "case",   "catch",   "char",         "class",
    "const",     "continue", "debugger",  "default",    "delete", "do",      "double",       "else",
    "enum",      "export",   "extends",   "false",      "final",  "finally", "float",        "for",
    "function",  "goto",     "if",        "implements", "import", "in",      "instanceof",   "int",
    "interface", "long",     "native",    "new",        "null",   "package", "private",      "protected",
    "public",    "return",   "short",     "static",     "super",  "switch",  "synchronized", "this",
    "throw",     "throws",   "transient", "true",       "try",    "typeof",  "var",          "void",
    "volatile",  "while",    "with",
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

test "the HTML form matches libclamav's javascript file" {
    // Each script is fed with the end tag that follows it in the page, as the HTML scanner
    // passes it; the expected text is the `javascript` file clamscan --leave-temps kept for
    // `<html><body><script>SCRIPT</script></body></html>` (tools/diff/js_goldens.py), whose
    // writer adds `<script>` before and `</script>` after unless the form already ends so.
    const cases = [_][2][]const u8{
        .{ "a++;b--;a+ +b;a- -b;a+++b;", "<script>a++;b--;a++b;a--b;a+++b;</script>" },
        .{ "x='say \"hi\"';y='\\x41\\xe9\\u20ac\\uD800';", "<script>x=\"say \"hi\"\";y=\"a\xe9\xe2\x82\xac\xed\xa0\x80\";</script>" },
        .{ "x='\\101\\0\\9';", "<script>x=\"101\x019\";</script>" },
        .{ "x='\\x4';y='\\u00';z='\\xzz\\uzzzz';", "<script>x=\"\\\";y=\"\\00\";z=\"\xff\xef\xbf\xbf\";</script>" },
        .{ "x='\\\\';y=1;'z';", "<script>x=\"\\';y=1;\"z\";</script>\"</script>" },
        .{ "x='unterminated", "<script>x=\"unterminated</script>\"</script>" },
        .{ "x=/a\\/b/gi;y=/A\"B/;", "<script>x=/a/b/gi;y=/a\"b/;</script>\"</script>" },
        .{ "a=1;// comment with / slashes\nb=2;//c\nd;", "<script>a=1;comment with/slashes b=2;d;</script>" },
        .{ "a\x00b;c\x01d;#e@f`g\x80h;", "<script>ab;c d;e f g h;</script>" },
        .{ "x=a\\b;y=(\\d);z=a.\\nb;w=1\\2;v=a \\);u=a\\u0041;", "<script>x=a b;y=( d);z=a.nb;w=1  2;v=a );u=a\\0041;</script>" },
        .{ "x=f((a);", "<script>x=f((a);</script>)</script>" },
        .{ "eval('a=1');b;x=eval('c')+1;eval(unescape('d=2;'));", "<script>a=b;x=1+1;cd=2;</script>" },
        .{ "x='a'+unescape('%62')+'c';var unescape('%41'),b;", "<script>x=\"a\"+\"b\"+\"c\";var\"a\",n001;</script>" },
        .{ "a=1;var a;var b;var a;", "<script>n002=1;var n002;var n001;var n002;</script>" },
        .{ "x={a:1};var a;function f(){b=1;var c}var b;", "<script>x={n000:1};var n000;function n001(){n003=1;var n002}var n003;</script>" },
        .{ "function f(a){function g(){return a}}f;g;", "<script>function n000(n001){function n002(){return n001}}f;g;</script>" },
        .{ "var a=[b,c],d;var e={f:1,g:2},h;function i(){var j,k;for(var l=0,m=0;;);}", "<script>var n000=[b,c],n001;var n002={f:1,g:2},n003;function n004(){var n005,k;for(var n006=0,m=0;;);}</script>" },
        .{ "{var a;},b;var c;\n[var d;e,f]", "<script>{var n000;},n001;var n002;[var n003;e,f]</script>" },
        .{ "function(a)b,c;function(r,{s,t;function({u;function()v,w;", "<script>function(n000)b,n001;function(n002,{n003,t;function({u;function()n004,n005;</script>))</script>" },
        .{ "function x10 unescape('a') b;function [function }c;function d;}d", "<script>function n000\"a\"n001;function[function}n002;function n003;}d</script>" },
        .{ "var byte,let,undefined,yield;", "<script>var byte,n000,n001,n002;</script>" },
    };
    for (cases) |c| {
        var cap: Capture = .{};
        const n = try std.testing.allocator.create(Normalizer);
        defer std.testing.allocator.destroy(n);
        n.* = .initHtml(.{ .ctx = &cap, .write = Capture.write });
        try n.feed(c[0]);
        try n.feed("</script>");
        try n.finish();
        const out = cap.buf[0..cap.len];
        var file: [8192]u8 = undefined;
        const tail = if (std.mem.endsWith(u8, out, "</script>")) "" else "</script>";
        const got = try std.fmt.bufPrint(&file, "<script>{s}{s}", .{ out, tail });
        std.testing.expectEqualStrings(c[1], got) catch |e| {
            std.debug.print("script: {s}\n", .{c[0]});
            return e;
        };
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
