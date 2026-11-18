//! RTF (P5.14): embedded objects. An RTF document hides payloads in `{\object ...
//! {\*\objdata <hex>}}` groups (and in `\bin` runs inside them). The document is read in one
//! forward pass, so it works over streams. Every objdata group is hex-decoded into a collector,
//! the way Word reads it: white space, line breaks, nested groups and control words inside the
//! data are skipped, `\binN` copies N raw bytes, and an odd final digit is dropped. Group depth
//! is a counter, so nesting costs no memory.
//!
//! The decoded data is an OLE1 object ([MS-OLEDS] 2.2.4 ObjectHeader + EmbeddedObject). When it
//! parses as one, its native data becomes the child `object/<n>`; a Package object's native
//! data is unwrapped once more to the packaged file, named by its label (`object/<n>/<label>`).
//! Anything else is scanned whole as `objdata/<n>`.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Collector = @import("collect.zig").Collector;
const Walker = container.Walker;
const Error = container.Error;

pub fn isRtf(head: []const u8) bool {
    return std.mem.startsWith(u8, head, "{\\rtf");
}

const State = enum { text, backslash, word, param, hex_escape, bin };

pub fn walk(w: *Walker, r: *Io.Reader) Error!void {
    var p: Parser = .{ .w = w, .collector = .init(w) };
    defer p.collector.deinit();
    while (true) {
        const chunk = r.peekGreedy(1) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return if (w.halt != null) error.Halted else {},
        };
        for (chunk) |c| try p.byte(c);
        r.toss(chunk.len);
    }
    // An objdata group the file never closed is still scanned.
    if (p.in_objdata) try p.endObject();
}

const Parser = struct {
    w: *Walker,
    collector: Collector,
    state: State = .text,
    depth: u32 = 0,
    word: [32]u8 = undefined,
    word_len: usize = 0,
    param: i64 = 0,
    param_neg: bool = false,
    param_digits: u8 = 0,
    /// "\*" was just seen: the next control word names an ignorable destination.
    star: bool = false,
    in_objdata: bool = false,
    objdata_depth: u32 = 0,
    high: ?u8 = null,
    bin_left: u64 = 0,
    objects: u32 = 0,
    name_buf: [300]u8 = undefined,

    fn byte(p: *Parser, c: u8) Error!void {
        switch (p.state) {
            .bin => {
                if (p.in_objdata and p.depth == p.objdata_depth) p.collector.append(&.{c});
                p.bin_left -= 1;
                if (p.bin_left == 0) p.state = .text;
            },
            .text => switch (c) {
                '\\' => p.state = .backslash,
                '{' => p.depth +|= 1,
                '}' => try p.close(),
                // Only the objdata group's own text is data: nested groups ({\*\junk 4142}) are
                // skipped, as Word skips them.
                else => if (p.in_objdata and p.depth == p.objdata_depth) p.hexDigit(c),
            },
            .backslash => {
                if (std.ascii.isAlphabetic(c)) {
                    p.word[0] = c;
                    p.word_len = 1;
                    p.state = .word;
                } else if (c == '\'') {
                    p.state = .hex_escape;
                    p.word_len = 0;
                } else {
                    // A control symbol: \* marks an ignorable destination; \{ \} \\ are text.
                    p.state = .text;
                    if (c == '*') p.star = true;
                }
            },
            .hex_escape => {
                // \'hh is a character of text; inside objdata it is not data.
                p.word_len += 1;
                if (p.word_len == 2) p.state = .text;
            },
            .word => {
                if (std.ascii.isAlphabetic(c)) {
                    if (p.word_len < p.word.len) {
                        p.word[p.word_len] = c;
                        p.word_len += 1;
                    }
                    return;
                }
                p.param = 0;
                p.param_neg = false;
                p.param_digits = 0;
                if (c == '-' or std.ascii.isDigit(c)) {
                    p.state = .param;
                    if (c == '-') p.param_neg = true else p.addDigit(c);
                    return;
                }
                try p.controlWord(false);
                try p.afterWord(c);
            },
            .param => {
                if (std.ascii.isDigit(c)) return p.addDigit(c);
                try p.controlWord(true);
                try p.afterWord(c);
            },
        }
    }

    fn addDigit(p: *Parser, c: u8) void {
        if (p.param_digits < 10) {
            p.param = p.param * 10 + (c - '0');
            p.param_digits += 1;
        }
    }

    /// The byte that ended a control word: a space is part of the word, anything else is
    /// processed normally.
    fn afterWord(p: *Parser, c: u8) Error!void {
        if (p.state == .bin) return;
        p.state = .text;
        if (c != ' ') try p.byte(c);
    }

    fn controlWord(p: *Parser, has_param: bool) Error!void {
        const word = p.word[0..p.word_len];
        const star = p.star;
        p.star = false;
        if (std.mem.eql(u8, word, "bin") and has_param) {
            const n: i64 = if (p.param_neg) -p.param else p.param;
            if (n > 0) {
                p.bin_left = @intCast(n);
                p.state = .bin;
            }
            return;
        }
        _ = star;
        if (std.mem.eql(u8, word, "objdata") and !p.in_objdata) {
            p.in_objdata = true;
            p.objdata_depth = p.depth;
            p.high = null;
            p.collector.reset();
        }
    }

    fn hexDigit(p: *Parser, c: u8) void {
        const v = std.fmt.charToDigit(c, 16) catch return;
        if (p.high) |h| {
            p.collector.append(&.{h << 4 | v});
            p.high = null;
        } else p.high = v;
    }

    fn close(p: *Parser) Error!void {
        if (p.in_objdata and p.depth == p.objdata_depth) try p.endObject();
        p.depth -|= 1;
    }

    fn endObject(p: *Parser) Error!void {
        p.in_objdata = false;
        const n = p.objects;
        p.objects += 1;
        defer p.collector.reset();
        const src = p.collector.source();
        if (ole1Native(p.w, src)) |native| {
            if (packaged(p.w, native.data, &p.name_buf)) |pkg| {
                var buf: [340]u8 = undefined;
                const name = std.fmt.bufPrint(&buf, "object/{d}/{s}", .{ n, pkg.label }) catch "object";
                return p.w.child(name, pkg.data, .member);
            }
            var buf: [24]u8 = undefined;
            const name = std.fmt.bufPrint(&buf, "object/{d}", .{n}) catch "object";
            return p.w.child(name, native.data, .member);
        }
        var buf: [24]u8 = undefined;
        const name = std.fmt.bufPrint(&buf, "objdata/{d}", .{n}) catch "objdata";
        try p.w.child(name, src, .member);
    }
};

const Native = struct { data: Source };

/// An OLE1 ObjectHeader for an embedded object: OLEVersion, FormatID 2, three length-prefixed
/// ANSI strings (class, topic, item), then NativeDataSize and the native data.
fn ole1Native(w: *Walker, src: Source) ?Native {
    const total = src.len() orelse return null;
    var off: u64 = 0;
    var head: [8]u8 = undefined;
    src.readAllAt(w.io, 0, &head) catch return null;
    if (std.mem.readInt(u32, head[4..8], .little) != 2) return null;
    off = 8;
    for (0..3) |_| {
        var lb: [4]u8 = undefined;
        src.readAllAt(w.io, off, &lb) catch return null;
        const len = std.mem.readInt(u32, &lb, .little);
        if (len > 4096 or off + 4 + len > total) return null;
        off += 4 + len;
    }
    var sb: [4]u8 = undefined;
    src.readAllAt(w.io, off, &sb) catch return null;
    off += 4;
    const size = std.mem.readInt(u32, &sb, .little);
    const avail = total - off;
    if (size == 0) return null;
    // A truncated object is scanned as far as it goes.
    return .{ .data = src.slice(off, @min(size, avail)) catch return null };
}

const Package = struct { label: []const u8, data: Source };

/// The OLE Packager's native data: 0x0002, label and original path (NUL-terminated), a
/// reserved word pair, the temporary path with its length, then the file's size and bytes.
fn packaged(w: *Walker, src: Source, name_buf: []u8) ?Package {
    const total = src.len() orelse return null;
    var head: [2]u8 = undefined;
    src.readAllAt(w.io, 0, &head) catch return null;
    if (std.mem.readInt(u16, &head, .little) != 2) return null;
    var off: u64 = 2;
    var label: []const u8 = "";
    for (0..2) |k| {
        var got: [260]u8 = undefined;
        const n = src.readAt(w.io, off, &got) catch return null;
        const end = std.mem.indexOfScalar(u8, got[0..n], 0) orelse return null;
        if (k == 0) {
            const l = @min(end, name_buf.len);
            @memcpy(name_buf[0..l], got[0..l]);
            label = baseName(name_buf[0..l]);
        }
        off += end + 1;
    }
    var fixed: [8]u8 = undefined;
    src.readAllAt(w.io, off, &fixed) catch return null;
    const tmp_len = std.mem.readInt(u32, fixed[4..8], .little);
    if (tmp_len > 4096) return null;
    off += 8 + tmp_len;
    var sb: [4]u8 = undefined;
    src.readAllAt(w.io, off, &sb) catch return null;
    off += 4;
    const size = std.mem.readInt(u32, &sb, .little);
    if (off > total) return null;
    return .{ .label = if (label.len > 0) label else "package", .data = src.slice(off, @min(size, total - off)) catch return null };
}

fn baseName(f: []const u8) []const u8 {
    const cut = std.mem.lastIndexOfAny(u8, f, "/\\");
    return if (cut) |i| (if (i + 1 < f.len) f[i + 1 ..] else f) else f;
}

test "RTF fixtures: objdata, Package objects, \\bin and obfuscated hex" {
    try @import("pdf.zig").checkDocs(".rtf");
}
