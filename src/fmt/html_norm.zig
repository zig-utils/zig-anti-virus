//! HTML normaliser for ClamAV target type 3, reproducing the `nocomment.html` and `notags.html`
//! files `clamscan --leave-temps` keeps for an HTML file, and the scripts it hands to its
//! JavaScript normaliser. Every rule here was derived black-box from clamscan 1.5.4's output on
//! generated documents (docs/clean-room.md, "HTML normalisation"); no ClamAV source was used.
//!
//! Input is cut into chunks of at most 8191 bytes. A chunk whose next byte is not whitespace
//! ends after its last whitespace byte instead (when it has one), and whitespace at the start
//! of a chunk is dropped.
//!
//! The nocomment form keeps markup, lower-cased, with whitespace collapsed (a run becomes one
//! space, written only before the next character, and none after a tag), comments and other
//! `<!...>` declarations removed, character references decoded, attribute values requoted with
//! `"`, and script and style content with all whitespace removed. The notags form keeps text
//! only: every tag and character reference becomes a space, runs of spaces collapse, and the
//! `href` of an `a` tag and the `src` of an `img` tag are written out in their original case.
const std = @import("std");
const named_refs = @import("html_named_refs.zig").refs;

/// A byte sink. `write` returns error.Stop to end normalisation early.
pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
};

/// A sink for a sequence of delimited pieces (scripts, data URIs).
pub const Pieces = struct {
    ctx: *anyopaque,
    begin: *const fn (ctx: *anyopaque) error{Stop}!void,
    data: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
    end: *const fn (ctx: *anyopaque) error{Stop}!void,
};

pub const Outputs = struct {
    nocomment: ?Output = null,
    notags: ?Output = null,
    /// Each script's raw text followed by its end tag (`</script`, plus the `>` when it comes
    /// right after).
    scripts: ?Pieces = null,
    /// Each data URI's file (below), one piece per URI.
    data_uris: ?Pieces = null,
};

/// The file clamscan makes of a data URI (RFC 2397) found in an attribute value, observed in
/// its `rfc2397/` temporary files: a mail-like header with the media type (lower-cased) and a
/// base64 transfer encoding when the media type contains `;base64`, then the data with `%`
/// escapes decoded. Only URIs with a `,` make one.
const DataUri = struct {
    active: bool = false,
    quote: u8 = 0,
    comma: bool = false,
    mt: [256]u8 = undefined,
    mt_len: usize = 0,
    /// 0 none, 1 after `%`, 2 after a hex digit (in `hi`), 3 a decoded byte (in `hi`) waiting.
    esc: u8 = 0,
    hi: u8 = 0,
    /// Inside a reference, which is left out of the data.
    in_ref: bool = false,
    ref_len: usize = 0,
    /// The data ended (at an unterminated reference) but the URI goes on.
    done: bool = false,
    /// Whitespace in the media type of a quoted URI: the quote is forgotten, and the run is
    /// one space.
    type_ws: bool = false,
    /// A byte of data has arrived since the comma.
    data_seen: bool = false,
};

/// The longest chunk the input is cut into.
pub const chunk_max = 8191;

const out_len = 4096;

/// A buffered output.
const Buffered = struct {
    out: ?Output,
    buf: [out_len]u8 = undefined,
    len: usize = 0,

    fn put(b: *Buffered, c: u8) error{Stop}!void {
        if (b.out == null) return;
        if (b.len == out_len) try b.flush();
        b.buf[b.len] = c;
        b.len += 1;
    }

    fn putAll(b: *Buffered, s: []const u8) error{Stop}!void {
        for (s) |c| try b.put(c);
    }

    fn flush(b: *Buffered) error{Stop}!void {
        const o = b.out orelse return;
        if (b.len > 0) try o.write(o.ctx, b.buf[0..b.len]);
        b.len = 0;
    }
};

const State = enum {
    text,
    /// After `<`.
    tag_open,
    /// Inside a tag, outside quotes.
    tag,
    /// Inside a quoted attribute value.
    tag_quoted,
    /// `<!...>`: dropped up to the next `>`.
    decl,
    /// Script or style content.
    raw,
};

/// Where a tag is in its tokens.
const TagPart = enum { name, between, attr, after_eq, value };

const max_name = 32;
const max_value = 1024;

pub const Normalizer = struct {
    nc: Buffered,
    nt: Buffered,
    scripts: ?Pieces,
    data_uris: ?Pieces,
    du: DataUri = .{},
    du_buf: [256]u8 = undefined,
    du_len: usize = 0,

    chunk: [chunk_max + 1]u8 = undefined,
    chunk_len: usize = 0,
    chunk_skip: usize = 0,

    state: State = .text,
    /// Whitespace seen in text that the nocomment form writes before the next character.
    nc_space: bool = false,
    /// The nocomment form writes no space yet (start of input, or right after a tag).
    nc_suppress: bool = true,
    /// The pending whitespace run is a single space.
    nc_run_plain: bool = false,
    after_decl: bool = false,
    /// The last byte written to the notags form was a space.
    nt_space: bool = false,

    // Tags.
    part: TagPart = .name,
    end_tag: bool = false,
    quote: u8 = 0,
    /// A space is owed before the next token in the tag (collapsed whitespace).
    tag_space: bool = false,
    /// In a quoted value, the previous byte was whitespace.
    value_space: bool = false,
    value_gt: bool = false,
    value_had_ws: bool = false,
    /// Whitespace owed before the value's next byte.
    value_ws: u8 = 0,
    value_len: usize = 0,
    /// How much of `data:` the value has started with (5 once decided).
    dprefix: usize = 0,
    data_uri: bool = false,
    /// A value has started with `data:` and the next byte decides.
    dpending: bool = false,
    after_durl: bool = false,
    data_escape: u8 = 0,
    /// The data URI's `,` has been seen.
    data_comma: bool = false,
    data_tail: [64]u8 = undefined,
    data_tail_len: usize = 0,
    /// After a data URI ended at `&`, its closing quote is dropped.
    drop_quote: u8 = 0,
    vgroup: [3]u8 = undefined,
    vgroup_len: usize = 0,
    /// The last token was a closed quoted value: a `=` right after it is an ordinary byte.
    after_quote: bool = false,
    name: [max_name]u8 = undefined,
    name_len: usize = 0,
    name_long: bool = false,
    attr: [max_name]u8 = undefined,
    attr_len: usize = 0,
    /// The current attribute's value is captured for the notags form.
    capturing: bool = false,
    captured: bool = false,
    capture: [max_value]u8 = undefined,
    capture_len: usize = 0,
    capture_space: bool = false,
    capture_due: bool = false,
    /// A NUL ended the capture.
    capture_closed: bool = false,
    /// The quoted value was left without its closing quote: the capture loses its last byte.
    capture_trim: bool = false,
    /// The rest of a script's end tag goes to the notags form as text.
    nt_tag_text: bool = false,

    // Script and style content.
    raw_script: bool = false,
    /// How much of `</script` or `</style` has matched.
    raw_match: usize = 0,
    raw_held: [8]u8 = undefined,
    /// The quote of the string script or style content is in, or 0.
    raw_quote: u8 = 0,
    raw_after_lt: bool = false,
    raw_decl: bool = false,
    /// The bytes of a script piece not yet handed over.
    piece: [4096]u8 = undefined,
    piece_gt: bool = false,
    piece_len: usize = 0,
    /// A script or style end tag was just matched; a `>` right after belongs to it.
    after_raw: bool = false,
    raw_end_open: bool = false,
    raw_end_extra: bool = false,
    /// The tag being parsed is the end tag of script or style content.
    raw_end_tag: bool = false,
    /// A script piece is open.
    piece_open: bool = false,
    /// The open piece has been handed to the sink: it begins with the first byte after the
    /// open tag, so a script tag closed by the last byte of input begins none.
    piece_begun: bool = false,

    // Character references.
    in_ref: bool = false,
    /// The reference is inside an unquoted data URI.
    ref_durl: bool = false,
    ref_numeric: bool = false,
    ref_hex: bool = false,
    ref_digits: usize = 0,
    ref_value: u64 = 0,
    ref_name: [max_value]u8 = undefined,
    ref_digits_text: [32]u8 = undefined,
    ref_digits_len: usize = 0,
    ref_len: usize = 0,
    /// The reference is inside a tag (an attribute value).
    ref_in_tag: bool = false,
    ref_semi: bool = false,
    nt_ref: bool = false,
    nt_ref_first: bool = false,
    nt_ref_numeric: bool = false,
    nt_ref_hex: bool = false,
    nt_ref_digits: usize = 0,
    nt_ref_value: u64 = 0,
    nt_ref_len: usize = 0,

    // High bytes in text, for the notags form's grouping and for U+3002 / U+FF0E.
    group: [3]u8 = undefined,
    group_len: usize = 0,
    phantom: bool = false,

    pub const Error = error{Stop};

    pub fn init(outputs: Outputs) Normalizer {
        return .{ .nc = .{ .out = outputs.nocomment }, .nt = .{ .out = outputs.notags }, .scripts = outputs.scripts, .data_uris = outputs.data_uris };
    }

    pub fn feed(n: *Normalizer, in: []const u8) Error!void {
        var rest = in;
        while (rest.len > 0) {
            const take = @min(rest.len, n.chunk.len - n.chunk_len);
            @memcpy(n.chunk[n.chunk_len..][0..take], rest[0..take]);
            n.chunk_len += take;
            rest = rest[take..];
            if (n.chunk_len == n.chunk.len) {
                // A full chunk plus the byte after it: decide where the chunk ends.
                var cut: usize = chunk_max;
                if (!isSpace(n.chunk[chunk_max])) {
                    var i: usize = chunk_max;
                    while (i > 0) : (i -= 1) {
                        if (isSpace(n.chunk[i - 1])) {
                            cut = i;
                            break;
                        }
                    }
                }
                // Observed: when a chunk is cut short, the next one starts later by the number of
                // NUL bytes in the part of the 8191-byte window left over.
                const skip = std.mem.count(u8, n.chunk[cut..chunk_max], &.{0});
                try n.process(n.chunk[0..cut]);
                std.mem.copyForwards(u8, n.chunk[0 .. n.chunk_len - cut], n.chunk[cut..n.chunk_len]);
                n.chunk_len -= cut;
                n.chunk_skip = skip;
            }
        }
    }

    pub fn finish(n: *Normalizer) Error!void {
        try n.process(n.chunk[0..n.chunk_len]);
        n.chunk_len = 0;
        try n.endOfInput();
        try n.nc.flush();
        try n.nt.flush();
    }

    fn process(n: *Normalizer, chunk: []const u8) Error!void {
        var i: usize = @min(chunk.len, n.chunk_skip);
        n.chunk_skip = 0;
        while (i < chunk.len and isSpace(chunk[i])) i += 1;
        for (chunk[i..]) |c| try n.step(c);
    }

    fn isSpace(c: u8) bool {
        return switch (c) {
            ' ', '\t', '\n', 0x0b, 0x0c, '\r' => true,
            else => false,
        };
    }

    // ---------------------------------------------------------------------------------------
    // Outputs

    /// A character of text for the nocomment form.
    fn ncText(n: *Normalizer, c: u8) Error!void {
        if (n.after_decl) {
            n.after_decl = false;
            n.nc_space = false;
        }
        if (n.nc_space and !n.nc_suppress) try n.nc.put(' ');
        n.nc_space = false;
        n.nc_suppress = false;
        try n.nc.put(c);
    }

    /// Markup for the nocomment form: a pending space is written first.
    fn ncMarkup(n: *Normalizer, s: []const u8) Error!void {
        n.after_decl = false;
        if (n.nc_space and !n.nc_suppress) try n.nc.put(' ');
        n.nc_space = false;
        n.nc_suppress = false;
        try n.nc.putAll(s);
    }

    fn ntChar(n: *Normalizer, c: u8) Error!void {
        try n.nt.put(c);
        n.nt_space = c == ' ';
    }

    fn ntSpace(n: *Normalizer) Error!void {
        if (n.nt_space) return;
        try n.nt.put(' ');
        n.nt_space = true;
    }

    /// A text byte for the notags form.
    fn ntText(n: *Normalizer, c: u8) Error!void {
        switch (c) {
            ' ', '\t', '\n', 0x0b, 0x0c => try n.ntSpace(),
            '\r', 0 => {},
            0x01...0x08, 0x0e...0x1f => try n.ntSpace(),
            else => try n.ntChar(lower(c)),
        }
    }

    fn lower(c: u8) u8 {
        return std.ascii.toLower(c);
    }

    // ---------------------------------------------------------------------------------------
    // High bytes in text and in script and style content come in groups of three, each written
    // when the byte after it arrives (a last group is dropped at the end of the input). A group
    // that is U+3002 or U+FF0E in UTF-8 becomes `.`. Otherwise the nocomment form gets the
    // bytes as they are; the notags form gets the first, the second and the second again, a
    // group of two as the first twice, a group of one as a NUL, without changing its space
    // collapsing state.

    fn groupByte(n: *Normalizer, c: u8) void {
        n.group[n.group_len] = c;
        n.group_len += 1;
    }

    fn groupEmit(n: *Normalizer) Error!void {
        const g = n.group[0..n.group_len];
        n.group_len = 0;
        if (g.len == 0) return;
        if (g.len == 1 and g[0] == 0 and n.phantom) {
            // What a two-byte dot leaves behind.
            n.phantom = false;
            try n.ncText(0);
            try n.nt.put(0);
            return;
        }
        if (std.mem.eql(u8, g, "\xe3\x80\x82") or std.mem.eql(u8, g, "\xef\xbc\x8e") or std.mem.eql(u8, g, "\xef\xb9\x92")) {
            try n.ncText('.');
            try n.nt.put('.');
            return;
        }
        for (g) |x| try n.ncText(x);
        switch (g.len) {
            1 => try n.nt.put(0),
            2 => try n.nt.putAll(&.{ g[0], g[0] }),
            else => try n.nt.putAll(&.{ g[0], g[1], g[1] }),
        }
    }

    // ---------------------------------------------------------------------------------------
    // The state machine

    fn step(n: *Normalizer, c: u8) Error!void {
        // NUL bytes are ignored everywhere.
        if (c == 0) return;
        if (n.du.active) try n.duByte(c);
        if (n.state == .text or n.state == .raw) {
            if (n.phantom and c >= 0x80) {
                n.phantom = false;
                n.group_len = 0;
            } else if (n.group_len == 1 and n.group[0] == 0xa1 and !n.phantom and (c == 0x43 or c == 0x44 or c == 0x4f) and !n.in_ref and n.raw_match == 0) {
                // Big5 dots (A1 43, A1 44, A1 4F).
                if (n.state == .raw) try n.pieceByte(c);
                try n.ncText('.');
                try n.nt.put('.');
                n.group[0] = 0;
                n.phantom = true;
                return;
            }
        }
        if (n.group_len == 3 or (n.group_len > 0 and (c < 0x80 or (n.state != .text and n.state != .raw)))) try n.groupEmit();
        if (n.capture_due) {
            n.capture_due = false;
            try n.ntSpace();
            for (n.capture[0..n.capture_len]) |x| try n.ntChar(x);
            // Written even after a capture that ends in whitespace.
            try n.ntChar(' ');
        }
        if (n.piece_gt) {
            // After `</script>`, a whitespace byte still goes with the script.
            n.piece_gt = false;
            if (n.piece_open) try n.endPiece(if (isSpace(c)) c else null);
        }
        if (n.after_raw) {
            n.after_raw = false;
            // A whitespace byte right after the end tag goes with the script, and so does a
            // `>` (and a whitespace byte after that).
            if (n.piece_open) {
                if (c == '>') {
                    try n.pieceByte(c);
                    n.piece_gt = true;
                } else try n.endPiece(if (isSpace(c)) c else null);
            }
            // In the notags form the end tag is over when whitespace follows: the rest of the
            // tag is text there. Whitespace after an end tag with more in it is kept.
            switch (c) {
                ' ', '\t', '\n', 0x0b, 0x0c => {
                    n.nt_tag_text = true;
                    n.raw_end_extra = true;
                },
                else => {},
            }
        }
        if (n.state == .text) try n.ntTextStep(c);
        if (n.in_ref) {
            if (try n.refStep(c)) {
                // Script text keeps its references as written.
                if (n.state == .raw) try n.pieceByte(c);
                return;
            }
        }
        switch (n.state) {
            .text => try n.textByte(c),
            .tag_open => {
                if (n.raw_end_open and n.nt_tag_text) try n.ntText(c);
                try n.tagOpen(c);
            },
            .tag => {
                if (n.nt_tag_text) try n.ntText(c);
                try n.tagByte(c);
            },
            .tag_quoted => {
                if (n.nt_tag_text) try n.ntText(c);
                try n.quotedByte(c);
            },
            .decl => if (c == '>') {
                n.state = .text;
                n.nc_space = false;
                n.nc_suppress = true;
            },
            .raw => try n.rawByte(c),
        }
    }

    /// Text for the nocomment form.
    fn textByte(n: *Normalizer, c: u8) Error!void {
        if (c >= 0x80) return n.groupByte(c);
        switch (c) {
            '<' => n.state = .tag_open,
            '&' => n.startRef(false),
            ' ', '\t', '\n', 0x0b, 0x0c => {
                // A declaration drops a run that is one space, and keeps any other run.
                n.nc_run_plain = !n.nc_space and c == ' ';
                n.nc_space = true;
            },
            '\r' => {},
            0x01...0x08, 0x0e...0x1f => try n.ncText(c),
            else => try n.ncText(lower(c)),
        }
    }

    /// Text for the notags form. A character reference becomes a space; in this form its name
    /// runs over letters, digits, `-`, `_` and `:`, and a numeric one over its digits.
    fn ntTextStep(n: *Normalizer, c: u8) Error!void {
        if (n.nt_ref) {
            const consumed = blk: {
                if (n.nt_ref_first) {
                    n.nt_ref_first = false;
                    if (c == '#') {
                        n.nt_ref_numeric = true;
                        break :blk true;
                    }
                }
                if (n.nt_ref_numeric) {
                    if (n.nt_ref_value == 0 and (c == 'x' or c == 'X')) {
                        n.nt_ref_hex = true;
                        break :blk true;
                    }
                    const d: ?u8 = if (n.nt_ref_hex) std.fmt.charToDigit(c, 16) catch null else std.fmt.charToDigit(c, 10) catch null;
                    const v = d orelse break :blk false;
                    const mul = @mulWithOverflow(n.nt_ref_value, @as(u64, if (n.nt_ref_hex) 16 else 10));
                    const add = @addWithOverflow(mul[0], v);
                    if (mul[1] != 0 or add[1] != 0) break :blk false;
                    n.nt_ref_value = add[0];
                    n.nt_ref_digits += 1;
                    break :blk true;
                }
                if (n.nt_ref_len == 1024) break :blk false;
                const name = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == ':';
                if (name) n.nt_ref_len += 1;
                break :blk name;
            };
            if (consumed) return;
            n.nt_ref = false;
            if (c == ';') return;
        }
        if (c >= 0x80) return;
        switch (c) {
            '<' => try n.ntSpace(),
            '&' => {
                n.nt_ref = true;
                n.nt_ref_first = true;
                n.nt_ref_numeric = false;
                n.nt_ref_hex = false;
                n.nt_ref_digits = 0;
                n.nt_ref_value = 0;
                n.nt_ref_len = 0;
                try n.ntSpace();
            },
            else => try n.ntText(c),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Tags

    fn startTag(n: *Normalizer) void {
        n.raw_end_tag = false;
        n.data_uri = false;
        n.dpending = false;
        n.after_durl = false;
        n.drop_quote = 0;
        n.state = .tag;
        n.part = .name;
        n.end_tag = false;
        n.name_len = 0;
        n.name_long = false;
        n.tag_space = false;
        n.captured = false;
        n.capturing = false;
    }

    fn tagOpen(n: *Normalizer, c: u8) Error!void {
        switch (c) {
            ' ', '\t', '\n', 0x0b, 0x0c, '\r' => {},
            '!' => {
                // A whitespace run before a declaration is written at once.
                if (n.nc_space and !n.nc_suppress) try n.nc.put(' ');
                n.nc_space = false;
                n.state = .decl;
            },
            else => {
                if (n.raw_end_open) {
                    // The rest of a script or style end tag.
                    n.raw_end_open = false;
                    n.state = .tag;
                    return n.tagByte(c);
                }
                try n.ncMarkup("<");
                n.startTag();
                if (c == '/') {
                    n.end_tag = true;
                    try n.nc.put('/');
                    return;
                }
                try n.tagByte(c);
            },
        }
    }

    fn tagByte(n: *Normalizer, c: u8) Error!void {
        if (n.dpending) {
            if (!try n.dataDecide(c)) {
                if (c == '>') return n.closeTag();
            }
        }
        if (n.data_uri) {
            // An unquoted data URI ends at whitespace or `>`, which it swallows too, or at a
            // character reference, which is written. A `%` escape takes the next two bytes,
            // whatever they are.
            if (n.data_escape > 0) {
                // `%` takes the next byte, and the one after only when that is a hex digit.
                n.data_escape -= 1;
                if (n.data_escape == 1 and std.fmt.charToDigit(c, 16) == error.InvalidCharacter) n.data_escape = 0;
                return;
            }
            if (c == '%') {
                n.data_escape = 2;
                return;
            }
            if (!n.data_comma) {
                // Before the `,` (the media type) whitespace and `>` end the URI and count as
                // tag syntax.
                switch (c) {
                    ',' => n.data_comma = true,
                    ' ', '\t', '\n', 0x0b, 0x0c, '\r' => {
                        n.data_uri = false;
                        n.part = .between;
                        n.tag_space = true;
                        return;
                    },
                    '>' => {
                        n.data_uri = false;
                        return n.closeTag();
                    },
                    else => {},
                }
                return;
            }
            switch (c) {
                ' ', '\t', '\n', 0x0b, 0x0c, '\r', '>' => {
                    // What follows is attribute name again, written with no space before it
                    // (whitespace after the URI is skipped).
                    n.data_uri = false;
                    n.data_tail_len = 0;
                    n.part = .attr;
                    n.after_durl = true;
                },
                // References inside the data are written, decoded; their names may also
                // hold `-`, `_` and `:`.
                '&' => {
                    n.startRef(true);
                    n.ref_durl = true;
                },
                else => {},
            }
            return;
        }
        if (n.drop_quote != 0) {
            // The rest of a quoted data URI after its `&` reference, closing quote included.
            if (c == n.drop_quote) n.drop_quote = 0;
            return;
        }
        if (n.after_durl) {
            switch (c) {
                ' ', '\t', '\n', 0x0b, 0x0c, '\r' => return,
                else => n.after_durl = false,
            }
        }
        const after_quote = n.after_quote;
        n.after_quote = false;
        if (after_quote and c == '=') {
            if (n.tag_space) {
                try n.nc.put(' ');
                n.tag_space = false;
            }
            return n.nc.put('=');
        }
        if (n.part == .value and !(c >= 'a' and c <= 'z') and c != ':') try n.valueFlushPrefix();
        switch (c) {
            '>' => return n.closeTag(),
            '\r' => return,
            ' ', '\t', '\n', 0x0b, 0x0c => {
                if (n.part == .value or n.part == .attr or n.part == .name) {
                    if (n.part == .value) n.attr_len = 0;
                    n.endAttr();
                    n.part = .between;
                }
                // In the rest of a script or style end tag whitespace is skipped.
                if (n.part != .after_eq and !n.raw_end_tag) n.tag_space = true;
                return;
            },
            0 => return,
            // In the tag name `=` is part of the name.
            '=' => if (n.part != .name and n.part != .after_eq and !n.after_quote) {
                n.tag_space = false;
                if (n.part != .value) {
                    try n.nc.put('=');
                    n.part = .after_eq;
                    if (!n.captured and n.wantsCapture()) {
                        n.capturing = true;
                        n.capture_closed = false;
                        n.capture_trim = false;
                        n.capture_len = 0;
                        n.capture_space = false;
                    }
                } else if (n.part == .value) {
                    return n.valueByte('=', '=');
                }
                return;
            },
            '"', '\'' => if (n.part == .after_eq) {
                n.tag_space = false;
                n.quote = c;
                n.part = .value;
                n.value_space = false;
                n.value_gt = false;
                n.value_had_ws = false;
                n.value_ws = 0;
                n.value_len = 0;
                n.dprefix = 0;
                n.state = .tag_quoted;
                try n.nc.put('"');
                return;
            },
            '&' => if (n.part == .after_eq or n.part == .value) {
                n.startRef(true);
                return;
            },
            else => {},
        }
        if (n.part == .between) {
            n.part = .attr;
            n.attr_len = 0;
        }
        if (n.tag_space) {
            try n.nc.put(' ');
            n.tag_space = false;
        }
        switch (n.part) {
            .name => {
                if (n.name_len < max_name) {
                    n.name[n.name_len] = lower(c);
                    n.name_len += 1;
                } else n.name_long = true;
            },
            .attr => if (n.attr_len < max_name) {
                n.attr[n.attr_len] = lower(c);
                n.attr_len += 1;
            },
            .after_eq => {
                n.part = .value;
                n.value_len = 0;
                n.dprefix = 0;
            },
            else => {},
        }
        if (n.part == .value) return n.valueByte(c, if (c == '\'') '"' else lower(c));
        try n.nc.put(lower(c));
    }

    /// A byte of an attribute value, written as `out`: high bytes of values wait (across tags
    /// and text) for the next value byte and are written before it, and a value that starts with `data:` is a data URI (RFC 2397), written as `data`
    /// and otherwise swallowed (up to the closing quote or `&` when quoted, whitespace when
    /// not).
    /// After a value's `data:`: a data URI starts unless the tag ends right there; either way
    /// the value is written as `data`.
    fn dataDecide(n: *Normalizer, c: u8) Error!bool {
        if (!n.dpending) return false;
        n.dpending = false;
        try n.nc.putAll("data");
        if (c == '>') return false;
        try n.duEnd();
        n.du = .{ .active = true, .quote = if (n.state == .tag_quoted) n.quote else 0 };
        try n.duByte(c);
        n.data_uri = true;
        n.data_comma = false;
        n.data_escape = 0;
        n.data_tail_len = 0;
        n.capturing = false;
        n.captured = false;
        return true;
    }

    fn valueByte(n: *Normalizer, c: u8, out: u8) Error!void {
        if (c >= 0x80) {
            if (n.vgroup_len == 3) try n.vgroupEmit();
            n.vgroup[n.vgroup_len] = c;
            n.vgroup_len += 1;
            n.value_len += 1;
            return;
        }
        const pending = n.vgroup_len;
        try n.vgroupEmit();
        if (pending > 0 and n.dprefix == 0) {
            // Bytes written before the value's first byte: it no longer starts with `data:`.
            n.dprefix = 5;
        }
        if (n.value_len == n.dprefix and n.dprefix < 5 and c == "data:"[n.dprefix]) {
            n.dprefix += 1;
            n.value_len += 1;
            // Decided by the byte after the `:`.
            if (n.dprefix == 5) n.dpending = true;
            return;
        }
        if (n.dprefix > 0 and n.dprefix < 5) {
            const held = n.dprefix;
            n.dprefix = 5;
            for ("data:"[0..held]) |x| {
                try n.captureByte(x);
                try n.nc.put(x);
            }
        }
        n.dprefix = 5;
        n.value_len += 1;
        try n.captureByte(if (c == '\'' or c == '"') '"' else c);
        try n.nc.put(out);
    }

    fn vgroupEmit(n: *Normalizer) Error!void {
        const g = n.vgroup[0..n.vgroup_len];
        n.vgroup_len = 0;
        if (g.len == 0) return;
        if (std.mem.eql(u8, g, "\xe3\x80\x82") or std.mem.eql(u8, g, "\xef\xbc\x8e")) {
            try n.captureByte('.');
            return n.nc.put('.');
        }
        for (g) |x| try n.captureByte(x);
        try n.nc.putAll(g);
    }

    /// Value bytes held as a possible `data:` prefix are written after all.
    fn valueFlushPrefix(n: *Normalizer) Error!void {
        if (n.dprefix > 0 and n.dprefix < 5) {
            for ("data:"[0..n.dprefix]) |x| {
                try n.captureByte(x);
                try n.nc.put(x);
            }
        }
        n.dprefix = 5;
    }

    /// A quoted attribute value. Observed: a whitespace run keeps its first byte (a newline
    /// becomes a space), written before the next byte. A `>` counts as a run too (whitespace
    /// right after it is dropped). Once the value has held one run, a second whitespace run
    /// leaves the quoted value (the rest is tag content) and a `>` ends the tag. The closing
    /// quote is followed by a space unless the value held a run.
    fn quotedByte(n: *Normalizer, c: u8) Error!void {
        if (n.dpending) _ = try n.dataDecide(c);
        if (n.data_uri) {
            if (n.data_escape > 0) {
                // `%` takes the next byte, and the one after only when that is a hex digit.
                n.data_escape -= 1;
                if (n.data_escape == 1 and std.fmt.charToDigit(c, 16) == error.InvalidCharacter) n.data_escape = 0;
                return;
            }
            if (c == '%') {
                n.data_escape = 2;
                return;
            }
            if (c == n.quote or c == '&') {
                n.data_uri = false;
                try n.nc.put('"');
                n.state = .tag;
                n.endAttr();
                if (c == n.quote) {
                    // A `=` right after assigns the same attribute again.
                    n.part = .attr;
                    n.tag_space = false;
                    return;
                }
                n.drop_quote = n.quote;
                n.part = .value;
                n.startRef(true);
            }
            return;
        }
        if (!(c >= 'a' and c <= 'z') and c != ':') try n.valueFlushPrefix();
        switch (c) {
            ' ', '\t', '\n', 0x0b, 0x0c => {
                if (n.value_space) return;
                if (n.value_had_ws or n.value_gt) {
                    // A second whitespace run leaves the quoted value: the rest is tag content.
                    n.capture_trim = true;
                    n.state = .tag;
                    return n.tagByte(c);
                }
                const w: u8 = if (c == '\n') ' ' else c;
                if (n.value_len == 0) {
                    try n.nc.put(w);
                    try n.captureByte(' ');
                } else n.value_ws = w;
                n.value_space = true;
                n.value_had_ws = true;
                n.value_len += 1;
                return;
            },
            '\r', 0 => return,
            else => {},
        }
        if (n.value_ws != 0) {
            try n.nc.put(n.value_ws);
            try n.captureByte(' ');
            n.value_ws = 0;
        }
        n.value_len += 1;
        if (c == n.quote) {
            try n.nc.put('"');
            n.state = .tag;
            n.endAttr();
            n.part = .between;
            n.tag_space = !(n.value_had_ws or n.value_gt);
            n.after_quote = true;
            n.attr_len = 0;
            return;
        }
        switch (c) {
            '>' => {
                if (n.value_had_ws or n.value_gt) {
                    n.capture_trim = true;
                    return n.closeTag();
                }
                n.value_gt = true;
                n.value_space = true;
                try n.captureByte(c);
                try n.nc.put('>');
                return;
            },
            '&' => {
                n.value_space = false;
                n.startRef(true);
                return;
            },
            '"', '\'' => {
                n.value_space = false;
                return n.valueByte(c, '"');
            },
            else => {},
        }
        n.value_space = false;
        n.value_len -= 1;
        try n.valueByte(c, lower(c));
    }

    fn wantsCapture(n: *const Normalizer) bool {
        if (n.end_tag or n.name_long) return false;
        const tag = n.name[0..n.name_len];
        const attr = n.attr[0..n.attr_len];
        return (std.mem.eql(u8, tag, "a") and std.mem.eql(u8, attr, "href")) or
            (std.mem.eql(u8, tag, "img") and std.mem.eql(u8, attr, "src"));
    }

    fn captureByte(n: *Normalizer, c: u8) Error!void {
        if (!n.capturing or n.capture_closed) return;
        if (c == ' ' or c == '\t' or c == '\n') {
            if (n.capture_space) return;
            n.capture_space = true;
            if (n.capture_len < max_value) {
                n.capture[n.capture_len] = ' ';
                n.capture_len += 1;
            }
            return;
        }
        n.capture_space = false;
        if (n.capture_len < max_value) {
            n.capture[n.capture_len] = c;
            n.capture_len += 1;
        }
    }

    fn endAttr(n: *Normalizer) void {
        if (n.capturing) {
            n.capturing = false;
            if (n.capture_trim and n.capture_len > 0) n.capture_len -= 1;
            n.captured = n.capture_len > 0;
        }
    }

    fn closeTag(n: *Normalizer) Error!void {
        // A data URI is not ended by the tag: a quoted one runs to its quote.
        n.endAttr();
        try n.valueFlushPrefix();
        n.drop_quote = 0;
        try n.nc.put('>');
        n.state = .text;
        n.nt_tag_text = false;
        n.nc_space = false;
        // Whitespace after a tag is dropped (not after a script or style end tag with more
        // than its name).
        n.nc_suppress = !(n.raw_end_tag and n.raw_end_extra);
        n.raw_end_tag = false;
        n.raw_end_extra = false;
        if (n.captured) {
            // Written when the next byte arrives.
            n.capture_due = true;
            n.captured = false;
        }
        if (!n.end_tag and !n.name_long) {
            const tag = n.name[0..n.name_len];
            if (std.mem.eql(u8, tag, "script") or std.mem.eql(u8, tag, "style")) {
                n.state = .raw;
                n.raw_script = tag.len == 6;
                n.raw_match = 0;
                n.raw_quote = 0;
                n.raw_after_lt = false;
                n.raw_decl = false;
                n.piece_len = 0;
                if (n.raw_script and n.scripts != null) {
                    n.piece_open = true;
                    n.piece_begun = false;
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Script and style content

    /// Script content ends at `</script`; style content at `</style` or `</script`.
    fn rawEndsWith(n: *const Normalizer, held: []const u8) enum { no, prefix, full } {
        var any_prefix = false;
        const ends = [_][]const u8{ "</script", "</style" };
        for (ends, 0..) |end, i| {
            if (i == 1 and n.raw_script) continue;
            if (held.len > end.len) continue;
            var same = true;
            for (held, end[0..held.len]) |x, y| {
                if (lower(x) != y) same = false;
            }
            if (!same) continue;
            if (held.len == end.len) return .full;
            any_prefix = true;
        }
        return if (any_prefix) .prefix else .no;
    }

    fn rawByte(n: *Normalizer, c: u8) Error!void {
        // The byte after a `<` (whitespace skipped) cannot start an end tag.
        if (n.raw_after_lt or n.raw_decl) return n.rawContent(c);
        n.raw_held[n.raw_match] = c;
        switch (n.rawEndsWith(n.raw_held[0 .. n.raw_match + 1])) {
            .full => {
                n.raw_match += 1;
                return n.endRaw();
            },
            .prefix => {
                n.raw_match += 1;
                return;
            },
            .no => {},
        }
        if (n.raw_match > 0) {
            const held = n.raw_held;
            const count = n.raw_match;
            n.raw_match = 0;
            for (held[0..count]) |x| try n.rawContent(x);
            return n.rawByte(c);
        }
        try n.rawContent(c);
    }

    fn rawContent(n: *Normalizer, c: u8) Error!void {
        try n.pieceByte(c);
        if (n.raw_after_lt) {
            // The byte after a `<` (whitespace skipped) is written as it is, lower-cased.
            switch (c) {
                ' ', '\t', '\n', 0x0b, 0x0c, '\r' => return,
                else => {},
            }
            n.raw_after_lt = false;
            if (c == '!') n.raw_decl = true;
            return n.ncText(lower(c));
        }
        // Inside `<!...>` a `<` is an ordinary byte.
        if (c == '<' and !n.raw_decl) n.raw_after_lt = true;
        if (c == '>') n.raw_decl = false;
        // Inside `<!...>` high bytes are written as they are, to the nocomment form only.
        if (c >= 0x80) return if (n.raw_decl) n.ncText(c) else n.groupByte(c);
        switch (c) {
            ' ', '\t', '\n', 0x0b, 0x0c, '\r', 0 => {},
            '\'' => try n.ncText('"'),
            // No references are decoded inside `<!...>`.
            '&' => if (n.raw_decl) try n.ncText('&') else n.startRef(false),
            else => try n.ncText(lower(c)),
        }
    }

    fn endRaw(n: *Normalizer) Error!void {
        const held = n.raw_held[0..n.raw_match];
        for (held) |x| try n.pieceByte(x);
        var end: [8]u8 = undefined;
        for (held, 0..) |x, i| end[i] = lower(x);
        try n.ncMarkup(end[0..held.len]);
        n.raw_match = 0;
        n.startTag();
        n.end_tag = true;
        n.name_len = 0;
        n.after_raw = true;
        n.raw_end_tag = true;
        // Whitespace before the rest of the end tag is skipped, as after `<`.
        n.state = .tag_open;
        n.raw_end_open = true;
    }

    /// Script text, buffered up to the byte that ends a run of letters, digits, `_` and `$`.
    fn pieceByte(n: *Normalizer, c: u8) Error!void {
        if (!n.piece_open) return;
        const p = n.scripts orelse return;
        if (!n.piece_begun) {
            try p.begin(p.ctx);
            n.piece_begun = true;
        }
        if (n.piece_len == n.piece.len) {
            try p.data(p.ctx, n.piece[0..n.piece_len]);
            n.piece_len = 0;
        }
        n.piece[n.piece_len] = c;
        n.piece_len += 1;
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '$')) {
            try p.data(p.ctx, n.piece[0..n.piece_len]);
            n.piece_len = 0;
        }
    }

    fn endPiece(n: *Normalizer, next: ?u8) Error!void {
        const p = n.scripts orelse return;
        if (next) |c| try n.pieceByte(c);
        if (n.piece_len > 0) try p.data(p.ctx, n.piece[0..n.piece_len]);
        n.piece_len = 0;
        n.piece_open = false;
        if (n.piece_begun) try p.end(p.ctx);
        n.piece_begun = false;
    }

    // ---------------------------------------------------------------------------------------
    // Character references

    fn startRef(n: *Normalizer, in_tag: bool) void {
        n.in_ref = true;
        n.ref_in_tag = in_tag;
        n.ref_numeric = false;
        n.ref_hex = false;
        n.ref_digits = 0;
        n.ref_value = 0;
        n.ref_len = 0;
        n.ref_digits_len = 0;
        n.ref_durl = false;
    }

    /// Returns true when `c` was consumed by the reference.
    fn refStep(n: *Normalizer, c: u8) Error!bool {
        if (n.ref_len == 0 and !n.ref_numeric and c == '#') {
            n.ref_numeric = true;
            return true;
        }
        if (n.ref_numeric) {
            // `x` switches to hex while the value is still 0 (leading zeros allowed).
            if (n.ref_value == 0 and (c == 'x' or c == 'X')) {
                n.ref_hex = true;
                return true;
            }
            const d: ?u8 = if (n.ref_hex) std.fmt.charToDigit(c, 16) catch null else std.fmt.charToDigit(c, 10) catch null;
            if (d) |v| {
                const base: u64 = if (n.ref_hex) 16 else 10;
                const mul = @mulWithOverflow(n.ref_value, base);
                const add = @addWithOverflow(mul[0], v);
                if (mul[1] == 0 and add[1] == 0) {
                    n.ref_value = add[0];
                    n.ref_digits += 1;
                    if (n.ref_digits_len < n.ref_digits_text.len) {
                        n.ref_digits_text[n.ref_digits_len] = c;
                        n.ref_digits_len += 1;
                    }
                    return true;
                }
                // Too large: the reference ends before this digit.
                try n.endRef(false);
                return false;
            }
            try n.endRef(c == ';');
            return c == ';';
        }
        const name_byte = std.ascii.isAlphanumeric(c) or
            (n.ref_durl and (c == '-' or c == '_' or c == ':'));
        if (name_byte and n.ref_len < n.ref_name.len) {
            n.ref_name[n.ref_len] = c;
            n.ref_len += 1;
            return true;
        }
        try n.endRef(c == ';');
        return c == ';';
    }

    fn refOut(n: *Normalizer, s: []const u8) Error!void {
        return n.refOutCase(s, s);
    }

    /// `captured` is what the notags capture of an `href` or `src` gets: the decoded bytes in
    /// their own case; a NUL ends the capture, and an unterminated empty numeric reference adds
    /// nothing.
    fn refOutCase(n: *Normalizer, s: []const u8, captured: []const u8) Error!void {
        if (n.ref_in_tag) {
            if (n.state == .tag and n.part == .after_eq and s.len > 0 and s[0] != 0) n.part = .value;
            for (s) |c| try n.nc.put(c);
            for (captured) |c| {
                if (c == 0) {
                    if (n.ref_numeric and n.ref_semi) {
                        n.capture_closed = true;
                        n.capture_trim = true;
                    }
                    continue;
                }
                try n.captureByte(c);
            }
        } else for (s) |c| try n.ncText(c);
    }

    /// The reference is complete; `semi` when it ended with `;`.
    fn endRef(n: *Normalizer, semi: bool) Error!void {
        n.in_ref = false;
        n.ref_semi = semi;
        if (n.ref_numeric) {
            const v = n.ref_value;
            if (!semi) {
                try n.refOut(&.{@truncate(v)});
                return;
            }
            const big = v > 0xffff;
            const u: u16 = @truncate(v);
            if (big and u == 0) return;
            return n.codePoint(u, !big);
        }
        const name = n.ref_name[0..n.ref_len];
        if (semi) {
            if (lookup(name)) |cp| return n.codePoint(cp, true);
        }
        var buf: [max_value + 2]u8 = undefined;
        buf[0] = '&';
        for (name, 0..) |c, i| buf[1 + i] = lower(c);
        var len = 1 + name.len;
        if (semi) {
            buf[len] = ';';
            len += 1;
        }
        try n.refOut(buf[0..len]);
    }

    fn codePoint(n: *Normalizer, u: u16, fold: bool) Error!void {
        if (isDot(u)) return n.refOut(".");
        if (u < 0xff) {
            const b: u8 = @intCast(u);
            return n.refOutCase(&.{if (fold) lower(b) else b}, &.{b});
        }
        var buf: [8]u8 = undefined;
        try n.refOut(std.fmt.bufPrint(&buf, "&#x{x:0>4};", .{u}) catch unreachable);
    }

    // ---------------------------------------------------------------------------------------
    // Data URI files

    fn duByte(n: *Normalizer, c: u8) Error!void {
        const d = &n.du;
        // Carriage returns are left out of the media type and before the first byte of data;
        // after that one is data in a quoted URI and ends an unquoted one.
        if (c == '\r' and !(d.comma and d.data_seen)) return;
        if (!d.comma) {
            switch (c) {
                ' ', '\t', '\n', 0x0b, 0x0c => if (d.quote != 0 or d.type_ws) {
                    // Whitespace in the media type: from here on the URI ends as an
                    // unquoted one does, the closing quote being data.
                    if (!d.type_ws and d.mt_len < d.mt.len) {
                        d.mt[d.mt_len] = ' ';
                        d.mt_len += 1;
                    }
                    d.quote = 0;
                    d.type_ws = true;
                    return;
                },
                else => {},
            }
            d.type_ws = false;
            const end = if (d.quote != 0) c == d.quote else switch (c) {
                ' ', '\t', '\n', 0x0b, 0x0c, '\r', '>' => true,
                else => false,
            };
            if (end) {
                d.active = false;
                return;
            }
            if (c == ',') {
                d.comma = true;
                const p = n.data_uris orelse return;
                try p.begin(p.ctx);
                const mt = d.mt[0..d.mt_len];
                try p.data(p.ctx, "From html-normalise\nContent-type: ");
                try p.data(p.ctx, mt);
                try p.data(p.ctx, "\n");
                if (std.mem.indexOf(u8, mt, ";base64") != null) try p.data(p.ctx, "Content-transfer-encoding: base64\n");
                try p.data(p.ctx, "\n");
                return;
            }
            if (d.mt_len < d.mt.len) {
                d.mt[d.mt_len] = lower(c);
                d.mt_len += 1;
            }
            return;
        }
        switch (d.esc) {
            1 => {
                if (std.fmt.charToDigit(c, 16)) |v| {
                    d.hi = v;
                    d.esc = 2;
                } else |_| {
                    d.esc = 0;
                    try n.duOut("%0");
                }
                return;
            },
            2 => {
                // The decoded byte is written when the next byte arrives.
                const v = std.fmt.charToDigit(c, 16) catch 0;
                d.hi = d.hi * 16 + v;
                d.esc = 3;
                return;
            },
            3 => {
                d.esc = 0;
                try n.duOut(&.{d.hi});
            },
            else => {},
        }
        if (d.in_ref) {
            // A reference is left out, its `;` too.
            if (d.ref_len < 1024 and (std.ascii.isAlphanumeric(c) or c == '#' or c == '-' or c == '_' or c == ':')) {
                d.ref_len += 1;
                return;
            }
            d.in_ref = false;
            if (c == ';') return;
        }
        const end = if (d.quote != 0) c == d.quote else switch (c) {
            ' ', '\t', '\n', 0x0b, 0x0c, '\r', '>' => true,
            else => false,
        };
        if (end) return n.duEnd();
        // A newline as the first byte of data is written as a space.
        if (!d.data_seen and c == '\n' and !d.done) {
            d.data_seen = true;
            return n.duOut(" ");
        }
        d.data_seen = true;
        if (d.done) return;
        switch (c) {
            '%' => d.esc = 1,
            '&' => {
                d.in_ref = true;
                d.ref_len = 0;
            },
            else => try n.duOut(&.{c}),
        }
    }

    fn duOut(n: *Normalizer, bytes: []const u8) Error!void {
        if (n.du.done) return;
        const p = n.data_uris orelse return;
        for (bytes) |b| {
            if (n.du_len == n.du_buf.len) {
                try p.data(p.ctx, n.du_buf[0..n.du_len]);
                n.du_len = 0;
            }
            n.du_buf[n.du_len] = b;
            n.du_len += 1;
        }
    }

    fn duEnd(n: *Normalizer) Error!void {
        if (!n.du.active) return;
        const opened = n.du.comma;
        n.du.active = false;
        const p = n.data_uris orelse return;
        if (!opened) return;
        if (n.du_len > 0) try p.data(p.ctx, n.du_buf[0..n.du_len]);
        n.du_len = 0;
        try p.end(p.ctx);
    }

    /// Code points written as `.` (observed: U+3002, U+FE52, U+FF0E).
    fn isDot(u: u16) bool {
        return u == 0x3002 or u == 0xfe52 or u == 0xff0e;
    }

    fn lookup(name: []const u8) ?u16 {
        var lo: usize = 0;
        var hi: usize = named_refs.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            switch (std.mem.order(u8, named_refs[mid][0], name)) {
                .eq => return named_refs[mid][1],
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return null;
    }

    fn endOfInput(n: *Normalizer) Error!void {
        // A named reference with a name is written; a numeric or empty one is dropped, as is a
        // last group of high bytes.
        // A whitespace run before an unfinished declaration or reference is still written.
        if (n.nc_space and !n.nc_suppress and (n.state == .decl or (n.in_ref and !n.ref_in_tag and n.state == .text))) {
            try n.nc.put(' ');
            n.nc_space = false;
        }
        if (n.in_ref and n.state == .raw and !n.ref_numeric and n.ref_len > 0 and lookup(n.ref_name[0..n.ref_len]) != null) {
            n.in_ref = false;
            try n.codePoint(lookup(n.ref_name[0..n.ref_len]).?, true);
        } else if (n.in_ref and n.state == .raw and (n.ref_numeric or n.ref_len > 0)) {
            // In script and style content an unfinished reference is written as it came.
            try n.ncText('&');
            if (n.ref_numeric) try n.ncText('#');
            if (n.ref_hex) try n.ncText('x');
            for (n.ref_digits_text[0..n.ref_digits_len]) |x| try n.ncText(x);
            for (n.ref_name[0..n.ref_len]) |x| try n.ncText(lower(x));
        } else if (n.in_ref and !n.ref_numeric and n.ref_len > 0 and n.state != .raw) {
            // At the end of the input a known name is decoded without its `;`.
            n.in_ref = false;
            if (lookup(n.ref_name[0..n.ref_len])) |cp| try n.codePoint(cp, true) else try n.endRef(false);
        }
        n.in_ref = false;
        n.group_len = 0;
        n.du.esc = 0;
        try n.duEnd();
        if (n.state == .tag_open and !n.raw_end_open) try n.ncMarkup("<");
        if (n.state == .tag_quoted and n.data_uri) try n.nc.put('"');
        if (n.state == .tag_quoted and !n.data_uri and n.value_ws != 0) try n.nc.put(n.value_ws);
        if (n.state == .tag or n.state == .tag_quoted) {
            if (n.dpending) {
                n.dpending = false;
                try n.nc.putAll("data:");
            } else if (!n.data_uri) try n.valueFlushPrefix();
        }
        if (n.after_raw or n.piece_gt) {
            n.after_raw = false;
            n.piece_gt = false;
            if (n.piece_open) try n.endPiece(null);
        }
        if (n.state == .raw) {
            if (n.raw_match > 0) {
                const held = n.raw_held;
                const count = n.raw_match;
                n.raw_match = 0;
                for (held[0..count]) |x| try n.rawContent(x);
            }
            if (n.piece_open) try n.endPiece(null);
        }
    }
};

const testing = std.testing;

const Collect = struct {
    list: std.ArrayList(u8) = .empty,

    fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        c.list.appendSlice(testing.allocator, bytes) catch return error.Stop;
    }

    fn output(c: *Collect) Output {
        return .{ .ctx = c, .write = write };
    }
};

fn normalize(in: []const u8, step: usize) !struct { nc: []u8, nt: []u8 } {
    var nc: Collect = .{};
    var nt: Collect = .{};
    var n = Normalizer.init(.{ .nocomment = nc.output(), .notags = nt.output() });
    var i: usize = 0;
    while (i < in.len) : (i += step) try n.feed(in[i..@min(in.len, i + step)]);
    try n.finish();
    return .{ .nc = try nc.list.toOwnedSlice(testing.allocator), .nt = try nt.list.toOwnedSlice(testing.allocator) };
}

const Pieces2 = struct {
    list: std.ArrayList(u8) = .empty,

    fn begin(ctx: *anyopaque) error{Stop}!void {
        const c: *Pieces2 = @ptrCast(@alignCast(ctx));
        c.list.append(testing.allocator, '[') catch return error.Stop;
    }
    fn data(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const c: *Pieces2 = @ptrCast(@alignCast(ctx));
        c.list.appendSlice(testing.allocator, bytes) catch return error.Stop;
    }
    fn end(ctx: *anyopaque) error{Stop}!void {
        const c: *Pieces2 = @ptrCast(@alignCast(ctx));
        c.list.append(testing.allocator, ']') catch return error.Stop;
    }
    fn pieces(c: *Pieces2) Pieces {
        return .{ .ctx = c, .begin = begin, .data = data, .end = end };
    }
};

fn extract(in: []const u8, comptime field: []const u8) ![]u8 {
    var p: Pieces2 = .{};
    var outs: Outputs = .{};
    @field(outs, field) = p.pieces();
    var n = Normalizer.init(outs);
    try n.feed(in);
    try n.finish();
    return p.list.toOwnedSlice(testing.allocator);
}

test "observed data URI files and script pieces" {
    const cases = [_]struct { []const u8, []const u8, []const u8 }{
        .{ "data_uris", "<html><img src=\"data:A;base64x,Q%41\">", "[From html-normalise\nContent-type: a;base64x\nContent-transfer-encoding: base64\n\nQA]" },
        .{ "data_uris", "<html><img src=\"data:a b,c\">y", "[From html-normalise\nContent-type: a b\n\nc\"]" },
        .{ "data_uris", "<html><img src=data:a,b\rc>y", "[From html-normalise\nContent-type: a\n\nb]" },
        .{ "data_uris", "<html><img src=\"data:a,\nZ\">y", "[From html-normalise\nContent-type: a\n\n Z]" },
        .{ "scripts", "<html><script>", "" },
        .{ "scripts", "<html><script>a</script>", "[a</script>]" },
    };
    for (cases) |c| {
        const got = if (std.mem.eql(u8, c[0], "data_uris")) try extract(c[1], "data_uris") else try extract(c[1], "scripts");
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(c[2], got);
    }
}

test "observed forms of small documents" {
    const cases = [_]struct { []const u8, []const u8, []const u8 }{
        .{ "<html><body>Hello &amp; <b>World</b><!-- c --><script>var a=1;</script></body></html>", "<html><body>hello & <b>world</b><script>vara=1;</script></body></html>", " hello world " },
        .{ "<html><p class='A  B'>x</p>", "<html><p class=\"a b\">x</p>", " x " },
        .{ "<html><a href=\"X Y\">x</a>", "<html><a href=\"x y\">x</a>", " X Y x " },
        .{ "<html>&#65;&#x42;&Eacute;&bogus;", "<html>ab\xc9&bogus;", " " },
        .{ "<html>x  <p>  y  </p>  z", "<html>x <p>y </p>z", " x y z" },
        // A quoted href left without its quote loses its last byte in notags.
        .{ "<html><a href=\"a b>c\">z</a>", "<html><a href=\"a b>c\">z</a>", " a  c\">z " },
        .{ "<html><a href=\"ab \">z</a>", "<html><a href=\"ab \">z</a>", " ab  z " },
        .{ "<html><a href=\"B\t&#0;BB\" x=1>z</a>", "<html><a href=\"b\t\x00bb\" x=1>z</a>", " B z " },
    };
    for (cases) |c| for ([_]usize{ 1, 7, 4096 }) |step| {
        const got = try normalize(c[0], step);
        defer testing.allocator.free(got.nc);
        defer testing.allocator.free(got.nt);
        try testing.expectEqualStrings(c[1], got.nc);
        try testing.expectEqualStrings(c[2], got.nt);
    };
}
