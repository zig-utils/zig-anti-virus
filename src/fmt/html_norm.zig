//! The HTML normaliser for target type 3, reproducing libclamav's (htmlnorm.c) three outputs byte
//! for byte, as measured with `clamscan --leave-temps` (tools/diff/norm.py):
//!
//! - `nocomment`: the normalised document (libclamav's nocomment.html);
//! - `notags`: the text with tags removed (notags.html), plus the href of each <a> and the src of
//!   each <img>;
//! - `scripts`: the raw bytes of each script element, from after its start tag to after its end
//!   tag, for the JavaScript normaliser (libclamav's `javascript` file is their normalised form);
//! - `data_uris`: each RFC 2397 `data:` attribute value, as libclamav writes it under rfc2397/
//!   (a small header, then the data).
//!
//! The rules are libclamav's state machine, reimplemented from its behaviour, quirks included,
//! because target-3 signatures are written against its output: comments end at the first `>`;
//! whitespace inside a quoted attribute value ends the quoting, so the rest of the value is read
//! unquoted and the next space ends it; any quote inside a value is written as `"`; bytes from
//! 0x80 up inside a value are held until the next ordinary value byte, which may be in the next
//! value; a reference ending without `;` writes its value as a raw byte.
//!
//! libclamav reads its input in chunks of at most 8191 bytes with NULs dropped, cutting a full
//! chunk back to its last whitespace, and skips the whitespace that starts each chunk. That is
//! reproduced exactly (the cut is re-read from the raw input, as libclamav seeks back), so the
//! output does not depend on how the caller splits its blocks. Memory is fixed: a chunk, a
//! window of the raw input, two output buffers and the tag fields.
//!
//! Not reproduced (listed on #45): libclamav decodes Microsoft Script Encoder bodies
//! (`language="jscript.encode"`, `<%@ ... %>`). The 743 named references are covered
//! by native-binary differential fixtures, including names absent from HTML 4.01.
const std = @import("std");

pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
};

/// A stream that arrives in pieces: one piece per script element or data URI.
pub const Pieces = struct {
    ctx: *anyopaque,
    begin: *const fn (ctx: *anyopaque) error{Stop}!void,
    data: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
    end: *const fn (ctx: *anyopaque) error{Stop}!void,
};

pub const Outputs = struct {
    nocomment: ?Output = null,
    notags: ?Output = null,
    scripts: ?Pieces = null,
    data_uris: ?Pieces = null,
};

/// libclamav reads at most this many bytes per chunk (8192 with its terminator).
pub const chunk_max = 8191;
const str_max = 1024;
const out_len = 8192;

const State = enum {
    bad,
    norm,
    eight_bit,
    comment,
    char_ref,
    entity_ref_decode,
    skip_ws,
    trim_ws,
    tag,
    tag_arg,
    tag_arg_val,
    tag_arg_equal,
    process_tag,
    char_ref_decode,
    rfc2397_type,
    rfc2397_init,
    rfc2397_data,
    rfc2397_finish,
    rfc2397_esc,
    escape_char,
};

const InTag = enum { none, script, style };
const Quoted = enum { single, double, not };

/// An output file as libclamav buffers it: an 8 KiB buffer flushed when full, so the byte just
/// written can always be taken back (comment starts and data URIs do).
const OutBuf = struct {
    out: ?Output,
    buf: [out_len]u8 = undefined,
    len: usize = 0,

    fn c(o: *OutBuf, b: u8) error{Stop}!void {
        if (o.out == null) return;
        if (o.len == out_len) try o.flush();
        o.buf[o.len] = b;
        o.len += 1;
    }

    fn str(o: *OutBuf, s: []const u8) error{Stop}!void {
        const out = o.out orelse return;
        if (o.len + s.len >= out_len) try o.flush();
        if (s.len >= out_len) return out.write(out.ctx, s);
        @memcpy(o.buf[o.len..][0..s.len], s);
        o.len += s.len;
    }

    fn rewind(o: *OutBuf) void {
        if (o.out != null and o.len > 0) o.len -= 1;
    }

    fn flush(o: *OutBuf) error{Stop}!void {
        const out = o.out orelse return;
        if (o.len == 0) return;
        const n = o.len;
        o.len = 0;
        try out.write(out.ctx, o.buf[0..n]);
    }
};

/// An attribute value kept for the tag being read: only those libclamav looks up.
const Arg = struct {
    buf: [str_max]u8 = undefined,
    len: usize = 0,
    seen: bool = false,
    set: bool = false,

    fn value(a: *const Arg) ?[]const u8 {
        return if (a.set) a.buf[0..a.len] else null;
    }
};

fn isSpace(b: u8) bool {
    return switch (b) {
        ' ', '\t', '\n', 0x0b, 0x0c, '\r' => true,
        else => false,
    };
}

fn lower(b: u8) u8 {
    return std.ascii.toLower(b);
}

pub const Normalizer = struct {
    nocomment: OutBuf,
    notags: OutBuf,
    data_out: OutBuf,
    scripts: ?Pieces,
    data_uris: ?Pieces,

    /// The chunk being collected (NULs dropped) and a window of the raw input it came from.
    chunk: [chunk_max + 1]u8 = undefined,
    chunk_len: usize = 0,
    raw: [chunk_max + 1]u8 = undefined,
    raw_count: u64 = 0,
    /// A bad state stopped the normaliser, as libclamav stops: nothing more is read.
    dead: bool = false,

    state: State = .norm,
    next_state: State = .bad,
    in_tag: InTag = .none,
    binary: bool = false,
    escape: bool = false,
    hex: bool = false,
    text_space_written: bool = false,
    quoted: Quoted = .not,
    value: i64 = 0,
    esc_length: u64 = 0,
    mbchar: u32 = 0,
    mbchar2: u32 = 0,
    tag: [str_max + 1]u8 = undefined,
    tag_length: usize = 0,
    tag_arg: [str_max + 1]u8 = undefined,
    tag_arg_length: usize = 0,
    tag_val: [str_max + 1]u8 = undefined,
    tag_val_length: usize = 0,
    entity_val: [str_max + 1]u8 = undefined,
    entity_val_length: usize = 0,
    href: Arg = .{},
    src: Arg = .{},
    /// A script element is open (libclamav's js_state).
    in_script: bool = false,
    /// Where the open style element's body starts in the current chunk (libclamav's style_begin).
    style_begin: usize = 0,
    data_open: bool = false,

    pub const Error = error{Stop};

    pub fn init(outputs: Outputs) Normalizer {
        return .{
            .nocomment = .{ .out = outputs.nocomment },
            .notags = .{ .out = outputs.notags },
            .data_out = .{ .out = if (outputs.data_uris) |p| .{ .ctx = p.ctx, .write = p.data } else null },
            .scripts = outputs.scripts,
            .data_uris = outputs.data_uris,
        };
    }

    pub fn feed(n: *Normalizer, in: []const u8) Error!void {
        for (in) |b| {
            if (n.chunk_len == chunk_max) try n.cut(b);
            n.raw[@intCast(n.raw_count % n.raw.len)] = b;
            n.raw_count += 1;
            if (b != 0) {
                n.chunk[n.chunk_len] = b;
                n.chunk_len += 1;
            }
        }
    }

    /// A full chunk with more input to come (`next` is the raw byte after it): libclamav cuts it
    /// back to its last whitespace unless `next` is whitespace, and re-reads the rest from the raw
    /// input (seeking back by the number of chunk bytes it dropped).
    fn cut(n: *Normalizer, next: u8) Error!void {
        var count: usize = chunk_max;
        if (!isSpace(next)) {
            var len: usize = chunk_max;
            while (!isSpace(n.chunk[len - 1]) and len > 1) len -= 1;
            if (len != 1) count = len;
        }
        const back = chunk_max - count;
        try n.run(n.chunk[0..count]);
        if (n.next_state == n.state) n.next_state = .bad;
        n.chunk_len = 0;
        var i: u64 = n.raw_count - back;
        while (i < n.raw_count) : (i += 1) {
            const b = n.raw[@intCast(i % n.raw.len)];
            if (b == 0) continue;
            n.chunk[n.chunk_len] = b;
            n.chunk_len += 1;
        }
    }

    /// End of input: the last chunk, then what libclamav does when it stops.
    pub fn finish(n: *Normalizer) Error!void {
        if (n.chunk_len > 0) try n.run(n.chunk[0..n.chunk_len]);
        n.chunk_len = 0;
        if (!n.dead) {
            // A reference cut off by the end of the input.
            const name = n.entity_val[0..n.entity_val_length];
            if (named(name)) |cp| {
                try n.u16Normalize(cp);
            } else if (name.len > 0) {
                try n.nocomment.c('&');
                for (name) |b| try n.nocomment.c(lower(b));
            }
        }
        if (n.in_script) try n.endScript();
        try n.closeData();
        try n.nocomment.flush();
        try n.notags.flush();
    }

    fn endScript(n: *Normalizer) Error!void {
        n.in_script = false;
        if (n.scripts) |s| try s.end(s.ctx);
    }

    fn closeData(n: *Normalizer) Error!void {
        if (!n.data_open) return;
        n.data_open = false;
        try n.data_out.flush();
        if (n.data_uris) |p| try p.end(p.ctx);
    }

    fn scriptBytes(n: *Normalizer, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        if (n.scripts) |s| try s.data(s.ctx, bytes);
    }

    /// A UTF-16 code unit as libclamav writes it: nothing for 0, the byte below 0xff, `.` for
    /// the ideographic full stops, `&#xhhhh;` for the rest.
    fn u16Normalize(n: *Normalizer, u: u16) Error!void {
        if (u == 0) return;
        if (u < 0xff) return n.nocomment.c(@intCast(u));
        if (u == 0x3002 or u == 0xff0e or u == 0xfe52) return n.nocomment.c('.');
        var buf: [8]u8 = "&#x0000;".*;
        var v = u;
        var i: usize = 6;
        while (i >= 3) : (i -= 1) {
            buf[i] = "0123456789abcdef"[v & 0xf];
            v >>= 4;
        }
        try n.nocomment.str(&buf);
    }

    fn tagValPut(n: *Normalizer, b: u8) void {
        if (n.tag_val_length < str_max) {
            n.tag_val[n.tag_val_length] = b;
            n.tag_val_length += 1;
        }
    }

    /// The value of a finished attribute: kept when libclamav looks it up later (the first
    /// `href` and `src`); a quoted value loses its first and last bytes.
    fn addArg(n: *Normalizer, with_value: bool) void {
        const name = n.tag_arg[0..n.tag_arg_length];
        const arg: *Arg = if (std.mem.eql(u8, name, "href")) &n.href else if (std.mem.eql(u8, name, "src")) &n.src else return;
        // The first attribute of that name decides, with or without a value.
        if (arg.seen) return;
        arg.seen = true;
        if (!with_value) return;
        arg.set = true;
        var v = n.tag_val[0..n.tag_val_length];
        if (std.mem.indexOfScalar(u8, v, 0)) |z| v = v[0..z];
        if (v.len > 0 and v[0] == '"') {
            v = v[1..];
            if (v.len > 0) v = v[0 .. v.len - 1];
        }
        @memcpy(arg.buf[0..v.len], v);
        arg.len = v.len;
    }

    fn mbFlush(n: *Normalizer, mb: u32, text: bool) Error!void {
        const c0: u8 = @truncate(mb >> 16);
        const c1: u8 = @truncate(mb >> 8);
        const c2: u8 = @truncate(mb);
        if (c0 != 0) {
            try n.nocomment.c(c0);
            if (text) try n.notags.c(c0);
        }
        if (c0 != 0 or c1 != 0) {
            try n.nocomment.c(c1);
            if (text) try n.notags.c(c1);
        }
        try n.nocomment.c(c2);
        // libclamav writes c1 here, not c2.
        if (text) try n.notags.c(c1);
    }

    fn isFullStop(mb: u32, b: u8) bool {
        return mb == 0xE38082 or mb == 0xEFBC8E or mb == 0xEFB992 or (mb == 0xA1 and (b == 0x43 or b == 0x44 or b == 0x4F));
    }

    /// One chunk through the state machine.
    fn run(n: *Normalizer, line: []u8) Error!void {
        if (n.dead) return;
        var p: usize = 0;
        var js_begin: ?usize = null;
        if (n.in_tag == .style) n.style_begin = 0;
        while (p < line.len and isSpace(line[p])) p += 1;
        loop: while (p < line.len) {
            const ch = line[p];
            if (!n.binary and ch == '\n') {
                line[p] = ' ';
                continue;
            }
            if (!n.binary and ch == '\r') {
                p += 1;
                continue;
            }
            switch (n.state) {
                .bad => {
                    n.dead = true;
                    break :loop;
                },
                .skip_ws => if (isSpace(ch)) {
                    p += 1;
                } else {
                    n.state = n.next_state;
                    n.next_state = .bad;
                },
                .trim_ws => if (isSpace(ch)) {
                    p += 1;
                } else {
                    if (n.in_tag == .none) try n.nocomment.c(' ');
                    n.state = n.next_state;
                    n.next_state = .bad;
                },
                .eight_bit => if (ch < 0x80 or n.mbchar >= 0x10000) {
                    if (isFullStop(n.mbchar, ch)) {
                        try n.nocomment.c('.');
                        try n.notags.c('.');
                        if (n.mbchar == 0xA1) {
                            p += 1;
                            n.mbchar = 0;
                            continue;
                        }
                    } else try n.mbFlush(n.mbchar, true);
                    n.mbchar = 0;
                    n.state = n.next_state;
                    n.next_state = .norm;
                } else {
                    n.mbchar = (n.mbchar << 8) | ch;
                    p += 1;
                },
                .norm => if (ch == '<') {
                    try n.nocomment.c('<');
                    if (n.in_tag == .none and !n.text_space_written) {
                        try n.notags.c(' ');
                        n.text_space_written = true;
                    }
                    p += 1;
                    n.state = .skip_ws;
                    n.tag_length = 0;
                    n.next_state = .tag;
                } else if (isSpace(ch)) {
                    if (!n.text_space_written and n.in_tag == .none) {
                        try n.notags.c(' ');
                        n.text_space_written = true;
                    }
                    n.state = .trim_ws;
                    n.next_state = .norm;
                } else if (ch == '&') {
                    if (!n.text_space_written and n.in_tag == .none) {
                        try n.notags.c(' ');
                        n.text_space_written = true;
                    }
                    n.state = .char_ref;
                    n.next_state = .norm;
                    p += 1;
                } else if (ch >= 0x80) {
                    n.state = .eight_bit;
                    n.next_state = .norm;
                    n.mbchar = ch;
                    p += 1;
                } else {
                    var c = lower(ch);
                    if (n.in_tag != .none and c == '\'') c = '"';
                    try n.nocomment.c(c);
                    if (n.in_tag == .none) {
                        if (ch < 0x20) {
                            if (!n.text_space_written) {
                                try n.notags.c(' ');
                                n.text_space_written = true;
                            }
                        } else {
                            try n.notags.c(c);
                            n.text_space_written = false;
                        }
                    }
                    p += 1;
                },
                .tag => if (n.tag_length == 0 and ch == '!') {
                    // A comment or declaration: scripts keep it, otherwise the `<` is taken back.
                    if (n.in_tag != .none) try n.nocomment.c('!') else n.nocomment.rewind();
                    n.state = .comment;
                    n.next_state = .bad;
                    p += 1;
                } else if (ch == '>') {
                    try n.nocomment.c('>');
                    p += 1;
                    n.state = .skip_ws;
                    n.next_state = .process_tag;
                } else if (!isSpace(ch)) {
                    try n.nocomment.c(lower(ch));
                    // Inside a script or style only an end tag matters.
                    if (n.in_tag != .none and n.tag_length == 0 and ch != '/') n.state = .norm;
                    if (n.tag_length < str_max) {
                        n.tag[n.tag_length] = lower(ch);
                        n.tag_length += 1;
                    }
                    p += 1;
                } else {
                    n.state = .skip_ws;
                    n.tag_arg_length = 0;
                    n.next_state = if (n.in_tag == .none) .tag_arg else .process_tag;
                },
                .tag_arg => if (ch == '=') {
                    try n.nocomment.c('=');
                    p += 1;
                    n.state = .skip_ws;
                    n.escape = false;
                    n.quoted = .not;
                    n.tag_val_length = 0;
                    n.next_state = .tag_arg_val;
                } else if (isSpace(ch)) {
                    p += 1;
                    n.state = .skip_ws;
                    n.next_state = .tag_arg_equal;
                } else if (ch == '>') {
                    try n.nocomment.c('>');
                    if (n.tag_arg_length > 0) n.addArg(false);
                    p += 1;
                    n.state = .process_tag;
                    n.next_state = .bad;
                } else {
                    if (n.tag_arg_length == 0) try n.nocomment.c(' ');
                    try n.nocomment.c(lower(ch));
                    if (n.tag_arg_length < str_max) {
                        n.tag_arg[n.tag_arg_length] = lower(ch);
                        n.tag_arg_length += 1;
                    }
                    p += 1;
                },
                .tag_arg_equal => if (ch == '=') {
                    try n.nocomment.c('=');
                    p += 1;
                    n.state = .skip_ws;
                    n.escape = false;
                    n.quoted = .not;
                    n.tag_val_length = 0;
                    n.next_state = .tag_arg_val;
                } else {
                    if (n.tag_arg_length > 0) n.addArg(false);
                    n.tag_arg_length = 0;
                    n.state = .tag_arg;
                    n.next_state = .bad;
                },
                .tag_arg_val => {
                    const tv = n.tag_val[0..n.tag_val_length];
                    if (std.mem.eql(u8, tv, "data:") or std.mem.eql(u8, tv, "\"data:")) {
                        // An RFC 2397 data URI: its media type and data leave the document.
                        n.nocomment.rewind();
                        if (n.quoted != .not) try n.nocomment.c('"');
                        n.tag_val_length = 0;
                        n.state = .rfc2397_type;
                        n.next_state = .tag_arg;
                    } else if (ch == '&') {
                        n.state = .char_ref;
                        n.next_state = .tag_arg_val;
                        p += 1;
                    } else if (ch == '\'' or ch == '"') {
                        const mine: Quoted = if (ch == '\'') .single else .double;
                        try n.nocomment.c('"');
                        n.tagValPut('"');
                        p += 1;
                        if (n.tag_val_length == 1) {
                            n.quoted = mine;
                        } else if (!n.escape and n.quoted == mine) {
                            n.tag_val[n.tag_val_length] = 0;
                            n.addArg(true);
                            n.state = .skip_ws;
                            n.tag_arg_length = 0;
                            n.next_state = .tag_arg;
                        }
                    } else if (isSpace(ch) or ch == '>') {
                        if (n.quoted == .not) {
                            n.addArg(true);
                            n.state = .skip_ws;
                            n.tag_arg_length = 0;
                            n.next_state = .tag_arg;
                        } else {
                            try n.nocomment.c(ch);
                            n.tagValPut(if (isSpace(ch)) ' ' else '>');
                            n.state = .skip_ws;
                            n.escape = false;
                            n.quoted = .not;
                            n.next_state = .tag_arg_val;
                            p += 1;
                        }
                    } else {
                        if (n.mbchar2 != 0 and (ch < 0x80 or n.mbchar2 >= 0x10000)) {
                            if (isFullStop(n.mbchar2, ch)) {
                                try n.nocomment.c('.');
                                n.tagValPut('.');
                                if (n.mbchar2 == 0xA1) {
                                    p += 1;
                                    n.mbchar2 = 0;
                                    continue;
                                }
                            } else {
                                const c0: u8 = @truncate(n.mbchar2 >> 16);
                                const c1: u8 = @truncate(n.mbchar2 >> 8);
                                const c2: u8 = @truncate(n.mbchar2);
                                if (c0 != 0) try n.nocomment.c(c0);
                                if (c0 != 0 or c1 != 0) try n.nocomment.c(c1);
                                try n.nocomment.c(c2);
                                if (c0 != 0) n.tagValPut(c0);
                                if (c0 != 0 or c1 != 0) n.tagValPut(c1);
                                n.tagValPut(c2);
                            }
                            n.mbchar2 = 0;
                        }
                        if (ch >= 0x80) {
                            n.mbchar2 = (n.mbchar2 << 8) | ch;
                        } else {
                            try n.nocomment.c(lower(ch));
                            n.tagValPut(ch);
                        }
                        p += 1;
                    }
                    n.escape = p < line.len and line[p] == '\\';
                },
                .comment => {
                    if (n.in_tag != .none and !isSpace(ch)) {
                        var c = lower(ch);
                        if (c == '\'') c = '"';
                        try n.nocomment.c(c);
                    }
                    if (ch == '>') {
                        n.state = .skip_ws;
                        n.next_state = .norm;
                    }
                    p += 1;
                },
                .process_tag => {
                    n.state = .skip_ws;
                    n.next_state = .norm;
                    const tag = n.tag[0..n.tag_length];
                    if (tag.len > 0 and tag[0] == '/') {
                        if (std.mem.eql(u8, tag, "/script")) {
                            n.in_tag = .none;
                            if (n.in_script) {
                                try n.scriptBytes(line[js_begin orelse 0 .. p]);
                                js_begin = null;
                                try n.endScript();
                            }
                        } else if (std.mem.eql(u8, tag, "/style") and n.in_tag == .style) {
                            // libclamav measures the style body back from here, `</style>` long;
                            // when that falls before the body's start in this chunk (the end tag
                            // was finished in the next chunk) it stops normalising altogether.
                            if (p < n.style_begin + "</style>".len) {
                                n.dead = true;
                                break :loop;
                            }
                            n.in_tag = .none;
                        }
                    } else if (std.mem.eql(u8, tag, "script")) {
                        n.in_tag = .script;
                        if (!n.in_script) {
                            n.in_script = true;
                            if (n.scripts) |s| try s.begin(s.ctx);
                            js_begin = p;
                        }
                    } else if (std.mem.eql(u8, tag, "style")) {
                        n.in_tag = .style;
                        n.style_begin = p;
                    } else if (std.mem.eql(u8, tag, "a") or std.mem.eql(u8, tag, "img")) {
                        // The link of an <a> and the image of an <img> are text to libclamav.
                        const v = (if (tag.len == 1) n.href.value() else n.src.value()) orelse "";
                        if (v.len > 0) {
                            try n.notags.str(v);
                            try n.notags.c(' ');
                            n.text_space_written = true;
                        }
                    }
                    n.href = .{};
                    n.src = .{};
                },
                .char_ref => if (ch == '#') {
                    n.value = 0;
                    n.hex = false;
                    n.state = .char_ref_decode;
                    p += 1;
                } else {
                    n.state = .entity_ref_decode;
                },
                .entity_ref_decode => if (ch == ';') {
                    const name = n.entity_val[0..n.entity_val_length];
                    if (named(name)) |cp| {
                        try n.u16Normalize(cp);
                        if (n.next_state == .tag_arg_val) {
                            // The value keeps what was written (one byte, `.` or `&#x....;`).
                            var tmp: [8]u8 = undefined;
                            for (u16Bytes(cp, &tmp)) |b| n.tagValPut(b);
                        }
                    } else {
                        try n.nocomment.c('&');
                        if (n.next_state == .tag_arg_val) n.tagValPut('&');
                        for (name) |b| {
                            try n.nocomment.c(lower(b));
                            if (n.next_state == .tag_arg_val) n.tagValPut(lower(b));
                        }
                        if (n.next_state == .tag_arg_val) n.tagValPut(';');
                        try n.nocomment.c(';');
                    }
                    n.entity_val_length = 0;
                    n.state = n.next_state;
                    n.next_state = .bad;
                    p += 1;
                } else if ((std.ascii.isAlphanumeric(ch) or ch == '_' or ch == ':' or ch == '-') and n.entity_val_length < str_max) {
                    n.entity_val[n.entity_val_length] = ch;
                    n.entity_val_length += 1;
                    p += 1;
                } else {
                    // Not a reference after all: written as it was, lowercased.
                    if (n.next_state == .tag_arg_val) n.tagValPut('&');
                    try n.nocomment.c('&');
                    for (n.entity_val[0..n.entity_val_length]) |b| {
                        try n.nocomment.c(lower(b));
                        if (n.next_state == .tag_arg_val) n.tagValPut(lower(b));
                    }
                    n.state = n.next_state;
                    n.next_state = .bad;
                    n.entity_val_length = 0;
                },
                .char_ref_decode => if (n.value == 0 and (ch == 'x' or ch == 'X')) {
                    n.hex = true;
                    p += 1;
                } else if (ch == ';') {
                    if (n.next_state == .tag_arg_val) n.tagValPut(@truncate(@as(u64, @bitCast(n.value))));
                    if (n.value < 0x80) {
                        try n.nocomment.c(lower(@intCast(n.value)));
                    } else {
                        try n.u16Normalize(@truncate(@as(u64, @bitCast(n.value))));
                    }
                    n.state = n.next_state;
                    n.next_state = .bad;
                    p += 1;
                } else if (std.ascii.isDigit(ch) or (n.hex and std.ascii.isHex(ch))) {
                    const max = std.math.maxInt(i64);
                    if (n.hex and n.value < @divTrunc(max, 16)) {
                        n.value *= 16;
                    } else if (n.value < @divTrunc(max, 10)) {
                        n.value *= 10;
                    } else {
                        try n.nocomment.c(@truncate(@as(u64, @bitCast(n.value))));
                        n.state = n.next_state;
                        n.next_state = .bad;
                        p += 1;
                        continue;
                    }
                    const inc: i64 = if (std.ascii.isDigit(ch)) ch - '0' else lower(ch) - 'a' + 10;
                    if (n.value > max - inc) {
                        try n.nocomment.c(@truncate(@as(u64, @bitCast(n.value))));
                        n.state = n.next_state;
                        n.next_state = .bad;
                        p += 1;
                        continue;
                    }
                    n.value += inc;
                    p += 1;
                } else {
                    // No `;`: the value so far is written as a raw byte.
                    try n.nocomment.c(@truncate(@as(u64, @bitCast(n.value))));
                    n.state = n.next_state;
                    n.next_state = .bad;
                },
                .rfc2397_type => {
                    if (ch == '\'' or ch == '"') {
                        const mine: Quoted = if (ch == '\'') .single else .double;
                        if (!n.escape and n.quoted == mine) {
                            n.state = .skip_ws;
                            n.tag_arg_length = 0;
                            n.next_state = .tag_arg;
                        } else n.tagValPut('"');
                        p += 1;
                    } else if (isSpace(ch) or ch == '>') {
                        if (n.quoted == .not) {
                            n.state = .skip_ws;
                            n.tag_arg_length = 0;
                            n.next_state = .tag_arg;
                        } else {
                            n.tagValPut(if (isSpace(ch)) ' ' else '>');
                            n.state = .skip_ws;
                            n.escape = false;
                            n.quoted = .not;
                            n.next_state = .rfc2397_type;
                            p += 1;
                        }
                    } else if (ch == ',') {
                        n.tag_val[n.tag_val_length] = 0;
                        n.state = .rfc2397_init;
                        n.escape = false;
                        n.next_state = .bad;
                        p += 1;
                    } else {
                        n.tagValPut(lower(ch));
                        p += 1;
                    }
                    n.escape = p < line.len and line[p] == '\\';
                },
                .rfc2397_init => {
                    try n.closeData();
                    if (n.data_uris) |d| {
                        try d.begin(d.ctx);
                        n.data_open = true;
                        const media = n.tag_val[0..n.tag_val_length];
                        try n.data_out.str("From html-normalise\n");
                        try n.data_out.str("Content-type: ");
                        try n.data_out.str(media);
                        try n.data_out.c('\n');
                        if (std.mem.indexOf(u8, media, ";base64") != null) try n.data_out.str("Content-transfer-encoding: base64\n");
                        try n.data_out.c('\n');
                    }
                    n.state = .rfc2397_data;
                    n.binary = true;
                },
                .rfc2397_data => {
                    if (ch == '&') {
                        n.state = .char_ref;
                        n.next_state = .rfc2397_data;
                        p += 1;
                    } else if (ch == '%') {
                        n.esc_length = 0;
                        n.value = 0;
                        n.state = .escape_char;
                        n.next_state = .rfc2397_esc;
                        p += 1;
                    } else if ((ch == '\'' and n.quoted == .single) or (ch == '"' and n.quoted == .double) or
                        ((isSpace(ch) or ch == '>') and n.quoted == .not))
                    {
                        if (!n.escape or n.quoted == .not) {
                            n.state = .rfc2397_finish;
                        } else try n.data_out.c(ch);
                        p += 1;
                    } else {
                        try n.data_out.c(ch);
                        p += 1;
                    }
                    n.escape = p < line.len and line[p] == '\\';
                },
                .rfc2397_finish => {
                    try n.closeData();
                    n.state = .skip_ws;
                    n.escape = false;
                    n.quoted = .not;
                    n.next_state = .tag_arg;
                    n.binary = false;
                },
                .rfc2397_esc => {
                    const v: u8 = @truncate(@as(u64, @bitCast(n.value)));
                    if (n.esc_length == 2) {
                        try n.data_out.c(v);
                    } else if (n.esc_length == 1) {
                        try n.data_out.c('%');
                        try n.data_out.c(v +% '0');
                    } else try n.data_out.c('%');
                    n.state = .rfc2397_data;
                },
                .escape_char => {
                    if (n.value < @divTrunc(std.math.maxInt(i64), 16)) {
                        n.value *= 16;
                    } else {
                        n.state = n.next_state;
                        n.next_state = .bad;
                        p += 1;
                        continue;
                    }
                    n.esc_length += 1;
                    if (std.ascii.isHex(ch)) {
                        n.value += if (std.ascii.isDigit(ch)) ch - '0' else lower(ch) - 'a' + 10;
                    } else n.state = n.next_state;
                    if (n.esc_length == 2) n.state = n.next_state;
                    p += 1;
                },
            }
        }
        // A bad state stops everything; the script so far is still ended by `finish`.
        if (n.dead) return;
        // End of the chunk: an open script gets the rest of it.
        if (n.in_script) try n.scriptBytes(line[js_begin orelse 0 .. p]);
    }
};

fn u16Bytes(u: u16, out: *[8]u8) []const u8 {
    if (u == 0) return out[0..0];
    if (u < 0xff) {
        out[0] = @intCast(u);
        return out[0..1];
    }
    if (u == 0x3002 or u == 0xff0e or u == 0xfe52) {
        out[0] = '.';
        return out[0..1];
    }
    out.* = "&#x0000;".*;
    var v = u;
    var i: usize = 6;
    while (i >= 3) : (i -= 1) {
        out[i] = "0123456789abcdef"[v & 0xf];
        v >>= 4;
    }
    return out[0..8];
}

fn named(name: []const u8) ?u16 {
    var lo: usize = 0;
    var hi: usize = named_refs.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, name, named_refs[mid][0])) {
            .lt => hi = mid,
            .gt => lo = mid + 1,
            .eq => return named_refs[mid][1],
        }
    }
    return null;
}

const named_refs = @import("html_named_refs.zig").refs;

// Tests --------------------------------------------------------------------------------------------

const Collect = struct {
    nocomment: std.ArrayList(u8) = .empty,
    notags: std.ArrayList(u8) = .empty,
    scripts: std.ArrayList(u8) = .empty,

    fn deinit(c: *Collect) void {
        c.nocomment.deinit(std.testing.allocator);
        c.notags.deinit(std.testing.allocator);
        c.scripts.deinit(std.testing.allocator);
    }
    fn wNocomment(ctx: *anyopaque, b: []const u8) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        c.nocomment.appendSlice(std.testing.allocator, b) catch return error.Stop;
    }
    fn wNotags(ctx: *anyopaque, b: []const u8) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        c.notags.appendSlice(std.testing.allocator, b) catch return error.Stop;
    }
    fn sBegin(ctx: *anyopaque) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        c.scripts.append(std.testing.allocator, '[') catch return error.Stop;
    }
    fn sData(ctx: *anyopaque, b: []const u8) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        c.scripts.appendSlice(std.testing.allocator, b) catch return error.Stop;
    }
    fn sEnd(ctx: *anyopaque) error{Stop}!void {
        const c: *Collect = @ptrCast(@alignCast(ctx));
        c.scripts.append(std.testing.allocator, ']') catch return error.Stop;
    }
};

fn run(input: []const u8, split: usize) !Collect {
    var c: Collect = .{};
    errdefer c.deinit();
    const n = try std.testing.allocator.create(Normalizer);
    defer std.testing.allocator.destroy(n);
    n.* = .init(.{
        .nocomment = .{ .ctx = &c, .write = Collect.wNocomment },
        .notags = .{ .ctx = &c, .write = Collect.wNotags },
        .scripts = .{ .ctx = &c, .begin = Collect.sBegin, .data = Collect.sData, .end = Collect.sEnd },
    });
    var i: usize = 0;
    while (i < input.len) : (i += split) try n.feed(input[i..@min(input.len, i + split)]);
    try n.finish();
    return c;
}

// Expected outputs below are libclamav 1.5.4's nocomment.html and notags.html for the same input.
const page =
    "<!DOCTYPE html>\n<HTML>  <Body BGCOLOR = red   onload='Go( \"a b\" )'>\n" ++
    "  Hello <!-- hidden > shown --> &AMP;   W&#79;rld &#x41;&nbsp;&bogus; &#65 &amp\n" ++
    "<A HREF=http://Example.com/Path  target = \"_blank\">Link</A><img src='P.png'><br/>\n" ++
    "<p title=\"x\xe9\" alt=y>\xe3\x80\x82 &#x263A;</p><SCRIPT type=text/javascript>var A = '<b>';\n" ++
    "</SCRIPT ><style>P { a: 'b' }</style>\n</BODY></HTML>";

test "libclamav's nocomment and notags, quirks included" {
    var c = try run(page, page.len);
    defer c.deinit();
    try std.testing.expectEqualStrings(
        "<html><body bgcolor=red onload=\"go( \"a b\" )'>hello shown --> &amp; world a\xa0&bogus; A &amp " ++
            "<a href=http://example.com/path target=\"_blank\">link</a><img src=\"p.png\"><br/>" ++
            "<p title=\"x\" alt=\xe9y>. &#x263a;</p><script type=text/javascript>vara=\"<b>\";</script>" ++
            "<style>p{a:\"b\"}</style></body></html>",
        c.nocomment.items,
    );
    try std.testing.expectEqualStrings(" hello shown --> w rld http://Example.com/Path link P.png .> ", c.notags.items);
    // A script runs from after its start tag to where its end tag is processed.
    try std.testing.expectEqualStrings("[var A = '<b>'; </SCRIPT ]", c.scripts.items);
}

test "chunks: whitespace starting a chunk is dropped, a cut is re-read from the raw input" {
    // The 8191st byte is followed by a space, so the chunk is not cut and the next one starts
    // with the space, which libclamav skips.
    var input: [6 + 8185 + 6]u8 = undefined;
    @memcpy(input[0..6], "<html>");
    @memset(input[6..][0..8185], 'a');
    @memcpy(input[6 + 8185 ..], " b</p>");
    var c = try run(&input, 1000);
    defer c.deinit();
    try std.testing.expectEqual(@as(usize, 8196), c.nocomment.items.len);
    try std.testing.expectEqualStrings("aab</p>", c.nocomment.items[c.nocomment.items.len - 7 ..]);

    // A cut back to the space before NULs: libclamav seeks back by the bytes it dropped, which
    // lands past the cut in the raw input.
    var nul: [6 + 8000 + 3 + 600 + 4]u8 = undefined;
    @memcpy(nul[0..6], "<html>");
    @memset(nul[6..][0..8000], 'a');
    @memcpy(nul[8006..][0..3], " c ");
    for (0..300) |i| @memcpy(nul[8009 + 2 * i ..][0..2], "b\x00");
    @memcpy(nul[nul.len - 4 ..], "</p>");
    for ([_]usize{ 1, 7, 4096, nul.len }) |split| {
        var d = try run(&nul, split);
        defer d.deinit();
        try std.testing.expectEqual(@as(usize, 8222), d.nocomment.items.len);
        try std.testing.expectEqual(@as(usize, 8214), d.notags.items.len);
    }
}

test "a style end tag finished in the next chunk stops normalisation" {
    // The space after `</style>` ends the first chunk; the tag is processed in the second, where
    // libclamav's style body start is the chunk start, and it gives up.
    var input: [6 + 8170 + 16 + 3]u8 = undefined;
    @memcpy(input[0..6], "<html>");
    @memset(input[6..][0..8170], 'a');
    @memcpy(input[8176..][0..16], "<style>x</style>");
    @memcpy(input[8192..], " yz");
    var c = try run(&input, input.len);
    defer c.deinit();
    try std.testing.expect(std.mem.endsWith(u8, c.nocomment.items, "<style>x</style>"));
}

test "&apos; decodes, as libclamav decodes it" {
    var c = try run("<html><p a=\"x&apos;y\">it&apos;s</p>", 7);
    defer c.deinit();
    try std.testing.expectEqualStrings("<html><p a=\"x'y\">it's</p>", c.nocomment.items);
}

test "ISO named references in text and links retain libclamav's supported set" {
    const input = "<html><a href=\"&Agr;&Acy;&boxh;&frac13;&apos;\">" ++
        "&Agr;&Acy;&boxh;&frac13;&tdot;&DotDot;&apos; &Abreve;&AMP;&NotEqualTilde;</a>";
    for ([_]usize{ 1, 7, input.len }) |split| {
        var c = try run(input, split);
        defer c.deinit();
        try std.testing.expectEqualStrings(
            "<html><a href=\"&#x0391;&#x0410;&#x2500;&#x2153;'\">" ++
                "&#x0391;&#x0410;&#x2500;&#x2153;&#x20db;&#x20dc;' &abreve;&amp;&notequaltilde;</a>",
            c.nocomment.items,
        );
        try std.testing.expectEqualStrings(" &#x0391;&#x0410;&#x2500;&#x2153;' ", c.notags.items);
    }
}

test "every supported named reference matches the native libclamav fixture across feeds" {
    const input = @embedFile("fixtures/html_named_refs.html");
    const html_hex = comptime std.mem.trim(u8, @embedFile("fixtures/html_named_refs.html.hex"), "\n");
    const notags_hex = comptime std.mem.trim(u8, @embedFile("fixtures/html_named_refs.notags.hex"), "\n");
    var html: [html_hex.len / 2]u8 = undefined;
    var notags: [notags_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&html, html_hex);
    _ = try std.fmt.hexToBytes(&notags, notags_hex);
    for ([_]usize{ 1, 7, 4096, input.len }) |split| {
        var c = try run(input, split);
        defer c.deinit();
        try std.testing.expectEqualStrings(&html, c.nocomment.items);
        try std.testing.expectEqualStrings(&notags, c.notags.items);
    }
}
