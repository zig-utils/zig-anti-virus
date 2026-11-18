//! PDF (P5.12): objects, streams, filters, object streams, JavaScript and embedded files.
//!
//! The parser does not trust the cross-reference table. Pass one finds every "N G obj" header in
//! the file. Pass two lexes each object's dictionary, bounded by the next header, and decodes its
//! stream through the filter chain (FlateDecode, LZWDecode with predictors, ASCIIHexDecode,
//! ASCII85Decode, RunLengthDecode). Every stream becomes a child: `obj/<n>`, `js/<n>` for
//! JavaScript, `embedded/<n>` for embedded files, `objstm/<n>` for object streams. Object streams
//! and cross-reference streams are collected and parsed as well. Classic xref tables and xref
//! streams are then read, and an entry pointing at an object pass one missed adds that object.
//!
//! JavaScript is found wherever a /JS key appears, at any depth, in objects and inside object
//! streams: a string value becomes a child (PDF escapes and UTF-16BE decoded), and an indirect
//! value is resolved after pass two to the stream or string object it names.
//!
//! Bounds: the object table is capped, dictionary nesting is capped (deeper values are skipped
//! iteratively), filter chains are capped at `max_filters`, and stream output goes through a
//! `Meter`, so the ratio guard, MaxFileSize and the scan's total output limit apply to every
//! stream. Searches for a missing "endstream" remember where none exists, so a file of
//! unterminated streams is still read in linear time.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const Collector = @import("collect.zig").Collector;
const inflate = @import("inflate.zig");
const filter = @import("pdf_filter.zig");
const crypt = @import("pdf_crypt.zig");

/// Most objects indexed per file. Past it the rest of the file is only scanned raw.
pub const max_objects = 1 << 18;
/// Most filters applied to one stream.
pub const max_filters = 8;
/// Dictionaries and arrays nested deeper than this are skipped without looking inside.
pub const max_depth = 32;
const max_js_refs = 4096;
const max_objstms = 256;
const max_extra = 4096;

/// Offset of "%PDF-" in a head, if the head is a PDF (the header may follow up to 1 KiB of junk,
/// as readers accept).
pub fn headerOffset(head: []const u8) ?usize {
    return std.mem.indexOf(u8, head[0..@min(head.len, 1024 + 5)], "%PDF-");
}

const Obj = struct {
    num: u32,
    gen: u16,
    /// Offset of the header's first digit, and of the byte after "obj".
    hdr: u64,
    off: u64,
};

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len() orelse return;
    var head: [1029]u8 = undefined;
    const hn = src.readAt(w.io, 0, &head) catch 0;
    const p = w.scratch.allocator().create(Parser) catch return w.limit(.memory);
    p.* = .{
        .w = w,
        .src = src,
        .total = total,
        .base = headerOffset(head[0..hn]) orelse 0,
        .collector = .init(w),
        .strings = .initCapacity(w, 64 * 1024),
        .lex = undefined,
        .objs = &.{},
    };
    const lex_buf = w.alloc(u8, 16 * 1024) orelse return;
    p.lex = .{ .io = w.io, .src = src, .end = total, .buf = lex_buf };
    const cap: usize = @intCast(@min(max_objects, total / 8 + 16));
    p.objs = w.alloc(Obj, cap) orelse return;
    defer p.collector.deinit();
    defer p.strings.deinit();
    try p.findObjects();
    try p.findEncryption();
    try p.objects();
    try p.xrefTables();
    try p.extraObjects();
    try p.resolveJs();
}

const Parser = struct {
    w: *Walker,
    src: Source,
    total: u64,
    /// Offset of "%PDF-": xref offsets are relative to it.
    base: u64,
    lex: Lexer,
    objs: []Obj,
    nobjs: usize = 0,
    /// Object indices sorted by number, built on first lookup.
    by_num: ?[]u32 = null,
    /// Offsets of "xref" keywords and "trailer" dictionaries found in pass one.
    xrefs: [64]u64 = undefined,
    nxrefs: usize = 0,
    trailers: [64]u64 = undefined,
    ntrailers: usize = 0,
    /// Offsets of "/XRef" names (cross-reference stream dictionaries carry the trailer keys).
    xref_names: [64]u64 = undefined,
    nxref_names: usize = 0,
    /// Objects found only through an xref entry.
    extra: [max_extra]Obj = undefined,
    nextra: usize = 0,
    /// Indirect /JS targets, and those already emitted.
    js_refs: [max_js_refs]u32 = undefined,
    njs: usize = 0,
    js_done: [max_js_refs]u32 = undefined,
    njs_done: usize = 0,
    js_strings: u32 = 0,
    objstms: [max_objstms]u32 = undefined,
    nobjstms: usize = 0,
    collector: Collector,
    /// Decoded /JS strings (separate from `collector`, which may hold an object stream).
    strings: Collector,
    /// Extract /JS strings while parsing (pass two and object streams, not re-reads).
    extract_js: bool = false,
    /// Stream data of the object being read ends here; headers before it are inside the data.
    skip_until: u64 = 0,
    /// No "endstream" exists at or after this offset.
    no_endstream_from: u64 = std.math.maxInt(u64),
    crypt: ?crypt.Decryptor = null,
    /// Encrypted with a key we do not have: streams and strings are ciphertext, so streams are
    /// scanned as they are and strings are not extracted.
    locked: bool = false,
    /// The object being read (for per-object encryption keys).
    cur_num: u32 = 0,
    cur_gen: u16 = 0,
    reported: std.EnumSet(Report) = .empty,
    name_buf: [48]u8 = undefined,

    const Report = enum { objects, depth, xref, filters, encrypted };

    fn once(p: *Parser, r: Report, what: container.Notice.What, detail: []const u8) void {
        if (p.reported.contains(r)) return;
        p.reported.insert(r);
        p.w.notice(what, detail);
    }

    // -----------------------------------------------------------------------------------------
    // Pass one: object headers, xref keywords and trailers.

    fn findObjects(p: *Parser) Error!void {
        const w = p.w;
        const buf = w.alloc(u8, container.block_len) orelse return;
        defer w.free(buf);
        const overlap = 40;
        var off: u64 = 0;
        var last: u64 = 0;
        while (off < p.total) {
            const got = p.src.readAt(w.io, off, buf) catch break;
            if (got == 0) break;
            const data = buf[0..got];
            const eof = off + got >= p.total;
            const from: usize = if (off == 0) 0 else overlap;
            var i: usize = from;
            while (std.mem.indexOfPos(u8, data, i, "obj")) |at| : (i = at + 1) {
                if (at + 3 < got and isRegular(data[at + 3])) continue;
                const hdr = headerBefore(data, at) orelse continue;
                const abs = off + hdr.start;
                if (abs < last and last != 0) continue;
                if (p.nobjs == p.objs.len) {
                    p.once(.objects, .malformed, "pdf: object table full");
                    break;
                }
                p.objs[p.nobjs] = .{ .num = hdr.num, .gen = hdr.gen, .hdr = abs, .off = off + at + 3 };
                p.nobjs += 1;
                last = abs + 1;
            }
            i = from;
            while (std.mem.indexOfPos(u8, data, i, "xref")) |at| : (i = at + 1) {
                if (at > 0 and isRegular(data[at - 1])) continue; // startxref
                if (at + 4 < got and isRegular(data[at + 4])) continue;
                if (p.nxrefs < p.xrefs.len) {
                    p.xrefs[p.nxrefs] = off + at + 4;
                    p.nxrefs += 1;
                }
            }
            i = from;
            while (std.mem.indexOfPos(u8, data, i, "trailer")) |at| : (i = at + 1) {
                if (at > 0 and isRegular(data[at - 1])) continue;
                if (p.ntrailers < p.trailers.len) {
                    p.trailers[p.ntrailers] = off + at + 7;
                    p.ntrailers += 1;
                }
            }
            i = from;
            while (std.mem.indexOfPos(u8, data, i, "/XRef")) |at| : (i = at + 1) {
                if (p.nxref_names < p.xref_names.len) {
                    p.xref_names[p.nxref_names] = off + at;
                    p.nxref_names += 1;
                }
            }
            if (eof) break;
            off += got - overlap;
        }
    }

    /// The object whose header is the last one at or before `at`.
    fn objectAt(p: *const Parser, at: u64) ?Obj {
        var lo: usize = 0;
        var hi: usize = p.nobjs;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (p.objs[mid].hdr <= at) lo = mid + 1 else hi = mid;
        }
        return if (lo > 0) p.objs[lo - 1] else null;
    }

    // -----------------------------------------------------------------------------------------
    // Encryption: the trailer (or an xref stream dictionary) names the /Encrypt dictionary.

    fn findEncryption(p: *Parser) Error!void {
        var info: crypt.Info = .{};
        var found = false;
        // Trailers, newest last.
        for (p.trailers[0..p.ntrailers]) |t| {
            p.lex.pos = t;
            p.lex.end = p.total;
            if (p.lex.next() != .dict_open) continue;
            var d: DictInfo = .{};
            try p.parseDict(&d, 1, .top);
            if (d.encrypt) |e| {
                info.encrypt = e;
                found = true;
            }
            if (d.id_len > 0) {
                info.id = d.id;
                info.id_len = d.id_len;
            }
        }
        // Xref streams carry the trailer keys in their own dictionaries.
        for (p.xref_names[0..p.nxref_names]) |at| {
            const o = p.objectAt(at) orelse continue;
            p.setObject(o);
            if (p.lex.next() != .dict_open) continue;
            var d: DictInfo = .{};
            try p.parseDict(&d, 1, .top);
            if (d.type != .xref) continue;
            if (d.encrypt) |e| {
                info.encrypt = e;
                found = true;
            }
            if (d.id_len > 0) {
                info.id = d.id;
                info.id_len = d.id_len;
            }
        }
        if (!found) return;
        const enc = info.encrypt.?;
        // The /Encrypt dictionary: direct (in place) or an indirect object.
        var ed: crypt.Dict = .{};
        switch (enc) {
            .ref => |num| {
                const o = p.findObj(num) orelse return p.encrypted("pdf: encryption dictionary missing");
                p.setObject(o);
                if (p.lex.next() != .dict_open) return p.encrypted("pdf: encryption dictionary missing");
            },
            .direct => |at| {
                p.lex.pos = at;
                p.lex.end = p.total;
            },
        }
        try p.parseEncryptDict(&ed);
        p.crypt = crypt.Decryptor.init(ed, info.id[0..info.id_len]) catch |e| switch (e) {
            error.Unsupported => return p.encrypted("pdf: unsupported security handler"),
            error.WrongPassword => return p.encrypted("pdf: user password required"),
        };
    }

    fn encrypted(p: *Parser, detail: []const u8) void {
        p.locked = true;
        p.once(.encrypted, .encrypted, detail);
    }

    /// Keys of the encryption dictionary (the lexer is just past its "<<").
    fn parseEncryptDict(p: *Parser, ed: *crypt.Dict) Error!void {
        while (true) {
            const t = p.lex.next();
            switch (t) {
                .eof => return,
                .dict_close => return,
                .name => |n| {
                    const key = Key.of(n);
                    const v = p.lex.next();
                    switch (key) {
                        .Filter => if (v == .name) {
                            ed.standard = std.mem.eql(u8, v.name, "Standard");
                        },
                        .V => if (v == .int) {
                            ed.v = v.int;
                        },
                        .R => if (v == .int) {
                            ed.r = v.int;
                        },
                        .Length => if (v == .int) {
                            ed.length = v.int;
                        },
                        .P => if (v == .int) {
                            ed.p = v.int;
                        },
                        .O, .U, .OE, .UE => if (v == .str_lit or v == .str_hex) {
                            const dest: *crypt.Dict.Bytes = switch (key) {
                                .O => &ed.o,
                                .U => &ed.u,
                                .OE => &ed.oe,
                                else => &ed.ue,
                            };
                            dest.len = p.readString(v, &dest.buf);
                        },
                        .EncryptMetadata => if (v == .keyword) {
                            ed.encrypt_metadata = !std.mem.eql(u8, v.keyword, "false");
                        },
                        .CF => if (v == .dict_open) {
                            try p.parseCryptFilters(ed);
                        },
                        .StmF => if (v == .name) {
                            ed.stmf_identity = std.mem.eql(u8, v.name, "Identity");
                        },
                        .StrF => if (v == .name) {
                            ed.strf_identity = std.mem.eql(u8, v.name, "Identity");
                        },
                        else => p.skipValue(v),
                    }
                },
                else => p.skipValue(t),
            }
        }
    }

    /// /CF << /StdCF << /CFM /AESV2 ... >> >>: the method of the standard crypt filter.
    fn parseCryptFilters(p: *Parser, ed: *crypt.Dict) Error!void {
        while (true) {
            const t = p.lex.next();
            switch (t) {
                .eof, .dict_close => return,
                .name => {
                    const v = p.lex.next();
                    if (v != .dict_open) {
                        p.skipValue(v);
                        continue;
                    }
                    while (true) {
                        const k = p.lex.next();
                        switch (k) {
                            .eof, .dict_close => break,
                            .name => |kn| {
                                const is_cfm = std.mem.eql(u8, kn, "CFM");
                                const kv = p.lex.next();
                                if (is_cfm and kv == .name) {
                                    ed.cfm = crypt.Method.of(kv.name);
                                } else p.skipValue(kv);
                            },
                            else => p.skipValue(k),
                        }
                    }
                },
                else => p.skipValue(t),
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Pass two: every object.

    fn setObject(p: *Parser, o: Obj) void {
        p.lex.pos = o.off;
        p.lex.end = p.nextHeader(o);
        p.cur_num = o.num;
        p.cur_gen = o.gen;
    }

    /// Where the next object header after `o` starts (the end of `o`'s dictionary).
    fn nextHeader(p: *Parser, o: Obj) u64 {
        // Objects are found in file order; extra objects use the end of the file.
        var lo: usize = 0;
        var hi: usize = p.nobjs;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (p.objs[mid].hdr <= o.hdr) lo = mid + 1 else hi = mid;
        }
        return if (lo < p.nobjs) p.objs[lo].hdr else p.total;
    }

    fn objects(p: *Parser) Error!void {
        var i: usize = 0;
        while (i < p.nobjs) : (i += 1) {
            const o = p.objs[i];
            if (o.hdr < p.skip_until) continue;
            try p.object(o);
        }
    }

    fn object(p: *Parser, o: Obj) Error!void {
        if (p.w.halt != null) return error.Halted;
        p.setObject(o);
        const t = p.lex.next();
        if (t != .dict_open) return;
        var d: DictInfo = .{};
        p.extract_js = true;
        try p.parseDict(&d, 1, .top);
        p.extract_js = false;
        const kw = p.lex.next();
        if (kw != .keyword or !std.mem.eql(u8, kw.keyword, "stream")) return;
        try p.stream(o, &d);
    }

    fn stream(p: *Parser, o: Obj, d: *DictInfo) Error!void {
        // The data starts after the EOL that follows "stream" (CRLF or LF; a lone CR is accepted).
        var start = p.lex.pos;
        if (p.lex.peekAt(start) == '\r') start += 1;
        if (p.lex.peekAt(start) == '\n') start += 1;
        const len = p.streamLength(start, d);
        const data = p.src.slice(start, len) catch return;
        p.skip_until = start + len;
        const js = p.isJsRef(o.num);
        var name: []const u8 = undefined;
        var kind: container.Kind = .decompressed;
        if (js) {
            name = std.fmt.bufPrint(&p.name_buf, "js/{d}", .{o.num}) catch "js";
            kind = .script;
            p.markJsDone(o.num);
        } else name = std.fmt.bufPrint(&p.name_buf, "{s}/{d}", .{ switch (d.type) {
            .embedded_file => "embedded",
            .objstm => "objstm",
            .xref => "xref",
            else => "obj",
        }, o.num }) catch "obj";
        if (d.type == .embedded_file) kind = .member;
        switch (d.type) {
            .objstm, .xref => {
                // Collected, scanned, then parsed: objects inside, or xref entries.
                try p.decode(data, d, o, .collect);
                try p.collector.emit(name, kind);
                return;
            },
            else => try p.decode(data, d, o, .{ .child = .{ .name = name, .kind = kind } }),
        }
    }

    /// The stream's length: /Length when "endstream" follows it, otherwise up to the next
    /// "endstream" (searched once, with the miss remembered), otherwise to the next object
    /// header, so one unterminated stream does not hide the objects after it.
    fn streamLength(p: *Parser, start: u64, d: *const DictInfo) u64 {
        var declared: ?u64 = null;
        if (d.length) |l| switch (l) {
            .int => |v| if (v >= 0) {
                declared = @intCast(v);
            },
            .ref => |num| if (p.resolveInt(num)) |v| if (v >= 0) {
                declared = @intCast(v);
            },
        };
        if (declared) |l| if (l <= p.total - start and p.endstreamAt(start + l)) return l;
        const next_header = @max(p.lex.end, start);
        if (p.findEndstream(start)) |e| if (e <= next_header) return e - start;
        return next_header - start;
    }

    fn endstreamAt(p: *Parser, at: u64) bool {
        var q = at;
        var k: usize = 0;
        while (k < 4) : (k += 1) {
            const c = p.lex.peekAt(q) orelse return false;
            if (!isSpace(c)) break;
            q += 1;
        }
        var word: [9]u8 = undefined;
        p.src.readAllAt(p.w.io, q, &word) catch return false;
        return std.mem.eql(u8, &word, "endstream");
    }

    /// Offset of the stream's last data byte + 1 before the next "endstream" (its preceding EOL
    /// is not data).
    fn findEndstream(p: *Parser, start: u64) ?u64 {
        if (start >= p.no_endstream_from) return null;
        const w = p.w;
        var block: [8192]u8 = undefined;
        var off = start;
        while (off < p.total) {
            const got = p.src.readAt(w.io, off, &block) catch break;
            if (got == 0) break;
            if (std.mem.indexOf(u8, block[0..got], "endstream")) |at| {
                var e = off + at;
                if (e > start and p.lex.peekAt(e - 1) == '\n') e -= 1;
                if (e > start and p.lex.peekAt(e - 1) == '\r') e -= 1;
                return e;
            }
            if (off + got >= p.total) break;
            off += got - 8;
        }
        p.no_endstream_from = start;
        return null;
    }

    const Sink = union(enum) {
        child: struct { name: []const u8, kind: container.Kind },
        collect,
    };

    /// Decode `data` through the stream's filters into a child or the collector.
    fn decode(p: *Parser, data: Source, d: *const DictInfo, o: Obj, sink: Sink) Error!void {
        const w = p.w;
        const mark = w.scratch.mark();
        defer w.scratch.release(mark);
        if (p.locked or (p.crypt == null and d.nfilters == 0)) {
            switch (sink) {
                .child => |c| return w.child(c.name, data, if (c.kind == .decompressed) .slice else c.kind),
                .collect => {},
            }
        }
        const sr_buf = w.alloc(u8, 16 * 1024) orelse return;
        const sr = w.scratch.allocator().create(container.SourceReader) catch return w.limit(.memory);
        sr.* = .init(w.io, data, sr_buf);
        var chain: Chain = .{ .p = p };
        var cur: *Io.Reader = &sr.interface;
        if (p.crypt) |*c| if (d.type != .xref and !(d.type == .metadata and !c.encrypt_metadata) and !c.stm_identity) {
            cur = chain.add(.decrypt, cur, .{}, c.objectKey(o.num, o.gen)) orelse return;
        };
        for (d.filters[0..d.nfilters], 0..) |f, k| {
            switch (f) {
                .crypt => continue,
                .image => break,
                .unknown => {
                    p.once(.filters, .unsupported, "pdf: filter");
                    break;
                },
                else => {},
            }
            cur = chain.add(f, cur, d.parms[k], .{}) orelse return;
        }
        if (d.filter_overflow) p.once(.filters, .unsupported, "pdf: filter chain too long");
        const meter_buf = w.alloc(u8, container.block_len) orelse return;
        var meter: container.Meter = .init(w, cur, &sr.pulled, meter_buf);
        switch (sink) {
            .child => |c| try w.child(c.name, .{ .stream = .{ .reader = &meter.interface } }, c.kind),
            .collect => {
                while (true) {
                    const chunk = meter.interface.peekGreedy(1) catch |e| switch (e) {
                        error.EndOfStream => break,
                        error.ReadFailed => break,
                    };
                    p.collector.append(chunk);
                    meter.interface.toss(chunk.len);
                    if (p.collector.full) break;
                }
            },
        }
        if (meter.tripped == null) if (chain.failure()) |why| w.notice(.malformed, why);
        if (sink == .collect) {
            // Parse what was collected while it is still here.
            if (d.type == .objstm) try p.objectStream(o, d) else if (d.type == .xref) p.xrefStream(d);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Object streams and cross-reference data.

    /// The collector holds a decoded object stream: look for /JS in every object inside, and
    /// remember the stream for indirect references resolved later.
    fn objectStream(p: *Parser, o: Obj, d: *const DictInfo) Error!void {
        if (p.nobjstms < max_objstms) {
            p.objstms[p.nobjstms] = o.num;
            p.nobjstms += 1;
        }
        const first = d.first orelse return;
        if (first < 0) return;
        const saved = p.lex;
        defer p.lex = saved;
        const buf = p.w.alloc(u8, 4096) orelse return;
        p.lex = .{ .io = p.w.io, .src = p.collector.source(), .end = p.collector.size(), .buf = buf, .pos = @intCast(first) };
        // Strings inside an object stream were decrypted with the stream; they are not
        // encrypted again.
        const c = p.crypt;
        p.crypt = null;
        defer p.crypt = c;
        p.extract_js = true;
        defer p.extract_js = false;
        try p.scanForJs();
    }

    /// Lex to the end, handling /JS keys at any depth (inside an object stream).
    fn scanForJs(p: *Parser) Error!void {
        var steps: usize = 0;
        while (steps < 1 << 22) : (steps += 1) {
            const t = p.lex.next();
            switch (t) {
                .eof => return,
                .dict_open => {
                    var d: DictInfo = .{};
                    try p.parseDict(&d, 1, .nested);
                },
                else => {},
            }
        }
    }

    /// The collector holds a decoded xref stream: check every type 1 entry's offset.
    fn xrefStream(p: *Parser, d: *const DictInfo) void {
        const wa: usize = @intCast(std.math.clamp(d.w[0], 0, 8));
        const wb: usize = @intCast(std.math.clamp(d.w[1], 0, 8));
        const wc: usize = @intCast(std.math.clamp(d.w[2], 0, 8));
        const entry = wa + wb + wc;
        if (entry == 0) return;
        const src = p.collector.source();
        const n = p.collector.size() / entry;
        var rec: [24]u8 = undefined;
        var i: u64 = 0;
        while (i < n and i < 1 << 22) : (i += 1) {
            src.readAllAt(p.w.io, i * entry, rec[0..entry]) catch return;
            const typ = if (wa == 0) 1 else beInt(rec[0..wa]);
            if (typ != 1) continue;
            p.checkXref(p.base +| beInt(rec[wa..][0..wb]));
        }
    }

    fn xrefTables(p: *Parser) Error!void {
        for (p.xrefs[0..p.nxrefs]) |at| {
            p.lex.pos = at;
            p.lex.end = p.total;
            var entries: usize = 0;
            // Subsections: "start count" then count entries "offset gen n|f".
            while (entries < 1 << 22) {
                const save = p.lex.pos;
                const s = p.lex.next();
                const c = p.lex.next();
                if (s != .int or c != .int) {
                    p.lex.pos = save;
                    break;
                }
                var k: i64 = 0;
                while (k < c.int and entries < 1 << 22) : (k += 1) {
                    const off = p.lex.next();
                    const gen = p.lex.next();
                    const kind = p.lex.next();
                    entries += 1;
                    if (off != .int or gen != .int or kind != .keyword) break;
                    if (std.mem.eql(u8, kind.keyword, "n") and off.int > 0) p.checkXref(p.base +| @as(u64, @intCast(off.int)));
                }
            }
        }
    }

    /// An xref entry: if no known object starts at `at`, try to read a header there and add it.
    fn checkXref(p: *Parser, at: u64) void {
        if (at >= p.total) return p.once(.xref, .mismatch, "pdf: xref entry past the end");
        var lo: usize = 0;
        var hi: usize = p.nobjs;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (p.objs[mid].hdr < at) lo = mid + 1 else hi = mid;
        }
        // Allow white space between the offset and the header.
        if (lo < p.nobjs and p.objs[lo].hdr >= at and p.objs[lo].hdr - at <= 4) return;
        for (p.extra[0..p.nextra]) |e| if (e.hdr == at) return;
        var lx = p.lex;
        lx.pos = at;
        lx.end = @min(p.total, at + 256);
        const num = lx.next();
        const gen = lx.next();
        const kw = lx.next();
        if (num != .int or gen != .int or kw != .keyword or !std.mem.eql(u8, kw.keyword, "obj") or
            num.int < 0 or num.int > std.math.maxInt(u32) or gen.int < 0 or gen.int > std.math.maxInt(u16))
        {
            return p.once(.xref, .mismatch, "pdf: xref entry points at no object");
        }
        p.once(.xref, .mismatch, "pdf: object found only through the xref");
        if (p.nextra == max_extra) return;
        p.extra[p.nextra] = .{ .num = @intCast(num.int), .gen = @intCast(gen.int), .hdr = at, .off = lx.pos };
        p.nextra += 1;
    }

    fn extraObjects(p: *Parser) Error!void {
        for (p.extra[0..p.nextra]) |o| try p.object(o);
    }

    // -----------------------------------------------------------------------------------------
    // JavaScript.

    fn isJsRef(p: *const Parser, num: u32) bool {
        return std.mem.indexOfScalar(u32, p.js_refs[0..p.njs], num) != null;
    }

    fn markJsDone(p: *Parser, num: u32) void {
        if (p.njs_done < p.js_done.len) {
            p.js_done[p.njs_done] = num;
            p.njs_done += 1;
        }
    }

    fn addJsRef(p: *Parser, num: u32) void {
        if (p.isJsRef(num) or p.njs == p.js_refs.len) return;
        p.js_refs[p.njs] = num;
        p.njs += 1;
    }

    /// A /JS string value: decode it (escapes, UTF-16BE) into a `js/s<n>` child.
    fn jsString(p: *Parser, t: Token) Error!void {
        var name_buf: [24]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "js/s{d}", .{p.js_strings}) catch "js";
        p.js_strings += 1;
        try p.stringChild(t, name);
    }

    fn stringChild(p: *Parser, t: Token, name: []const u8) Error!void {
        // The lexer's window is shared, so remember where it was.
        const saved_pos = p.lex.pos;
        defer p.lex.pos = saved_pos;
        var sink: StringSink = .{ .c = &p.strings };
        var dec: ?crypt.StringDecrypt = if (p.crypt) |*c| (if (c.str_identity) null else c.stringDecrypt(p.cur_num, p.cur_gen)) else null;
        p.decodeString(t, &sink, if (dec) |*x| x else null);
        if (dec) |*x| x.finish(&sink);
        sink.flush();
        try p.strings.emit(name, .script);
    }

    /// Resolve indirect /JS references: stream objects become `js/<n>` children, string objects
    /// too; objects inside object streams are found by decoding those streams again.
    fn resolveJs(p: *Parser) Error!void {
        var unresolved: [64]u32 = undefined;
        var nun: usize = 0;
        for (p.js_refs[0..p.njs]) |num| {
            if (std.mem.indexOfScalar(u32, p.js_done[0..p.njs_done], num) != null) continue;
            p.markJsDone(num);
            const o = p.findObj(num) orelse {
                if (nun < unresolved.len) {
                    unresolved[nun] = num;
                    nun += 1;
                }
                continue;
            };
            p.setObject(o);
            const t = p.lex.next();
            var name_buf: [24]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "js/{d}", .{num}) catch "js";
            switch (t) {
                .str_lit, .str_hex => try p.stringChild(t, name),
                .dict_open => {
                    var d: DictInfo = .{};
                    try p.parseDict(&d, 1, .top);
                    const kw = p.lex.next();
                    if (kw != .keyword or !std.mem.eql(u8, kw.keyword, "stream")) continue;
                    var start = p.lex.pos;
                    if (p.lex.peekAt(start) == '\r') start += 1;
                    if (p.lex.peekAt(start) == '\n') start += 1;
                    const len = p.streamLength(start, &d);
                    const data = p.src.slice(start, len) catch continue;
                    try p.decode(data, &d, o, .{ .child = .{ .name = name, .kind = .script } });
                },
                else => {},
            }
        }
        if (nun > 0) try p.jsInObjectStreams(unresolved[0..nun]);
    }

    /// String objects referenced by /JS that live inside object streams.
    fn jsInObjectStreams(p: *Parser, nums: []const u32) Error!void {
        for (p.objstms[0..p.nobjstms]) |sn| {
            const o = p.findObj(sn) orelse continue;
            p.setObject(o);
            if (p.lex.next() != .dict_open) continue;
            var d: DictInfo = .{};
            try p.parseDict(&d, 1, .top);
            const kw = p.lex.next();
            if (kw != .keyword or !std.mem.eql(u8, kw.keyword, "stream")) continue;
            var start = p.lex.pos;
            if (p.lex.peekAt(start) == '\r') start += 1;
            if (p.lex.peekAt(start) == '\n') start += 1;
            const len = p.streamLength(start, &d);
            const data = p.src.slice(start, len) catch continue;
            const first = d.first orelse continue;
            const count = d.n orelse continue;
            if (first < 0 or count <= 0) continue;
            const mark = p.w.scratch.mark();
            defer p.w.scratch.release(mark);
            // Collect the decoded stream without scanning it again.
            var dd = d;
            dd.type = .other;
            p.collector.reset();
            try p.decodeQuiet(data, &dd, o);
            const saved = p.lex;
            defer p.lex = saved;
            const buf = p.w.alloc(u8, 4096) orelse return;
            p.lex = .{ .io = p.w.io, .src = p.collector.source(), .end = p.collector.size(), .buf = buf };
            var k: i64 = 0;
            while (k < count and k < 1 << 16) : (k += 1) {
                const num = p.lex.next();
                const rel = p.lex.next();
                if (num != .int or rel != .int) break;
                if (num.int < 0 or rel.int < 0) continue;
                const n32 = std.math.cast(u32, num.int) orelse continue;
                if (std.mem.indexOfScalar(u32, nums, n32) == null) continue;
                const save = p.lex.pos;
                p.lex.pos = @intCast(first +| rel.int);
                const t = p.lex.next();
                if (t == .str_lit or t == .str_hex) {
                    // Copy out first: the child reuses the collector.
                    var tmp: Collector = .init(p.w);
                    defer tmp.deinit();
                    var sink: StringSink = .{ .c = &tmp };
                    p.decodeString(t, &sink, null);
                    sink.flush();
                    var name_buf: [24]u8 = undefined;
                    const name = std.fmt.bufPrint(&name_buf, "js/{d}", .{n32}) catch "js";
                    try tmp.emit(name, .script);
                }
                p.lex.pos = save;
            }
            p.collector.reset();
        }
    }

    /// Decode into the collector without scanning or parsing (used to re-read object streams).
    fn decodeQuiet(p: *Parser, data: Source, d: *const DictInfo, o: Obj) Error!void {
        var dd = d.*;
        dd.type = .other;
        const saved = p.nobjstms;
        defer p.nobjstms = saved;
        try p.decodeInto(data, &dd, o);
    }

    fn decodeInto(p: *Parser, data: Source, d: *const DictInfo, o: Obj) Error!void {
        const w = p.w;
        const sr_buf = w.alloc(u8, 16 * 1024) orelse return;
        const sr = w.scratch.allocator().create(container.SourceReader) catch return w.limit(.memory);
        sr.* = .init(w.io, data, sr_buf);
        var chain: Chain = .{ .p = p };
        var cur: *Io.Reader = &sr.interface;
        if (p.crypt) |*c| if (!c.stm_identity) {
            cur = chain.add(.decrypt, cur, .{}, c.objectKey(o.num, o.gen)) orelse return;
        };
        for (d.filters[0..d.nfilters], 0..) |f, k| {
            switch (f) {
                .crypt => continue,
                .image, .unknown => break,
                else => {},
            }
            cur = chain.add(f, cur, d.parms[k], .{}) orelse return;
        }
        const meter_buf = w.alloc(u8, container.block_len) orelse return;
        var meter: container.Meter = .init(w, cur, &sr.pulled, meter_buf);
        while (true) {
            const chunk = meter.interface.peekGreedy(1) catch break;
            p.collector.append(chunk);
            meter.interface.toss(chunk.len);
            if (p.collector.full) break;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Objects by number.

    fn findObj(p: *Parser, num: u32) ?Obj {
        if (p.by_num == null) {
            const idx = p.w.scratch.allocator().alloc(u32, p.nobjs) catch return p.findObjLinear(num);
            for (idx, 0..) |*x, i| x.* = @intCast(i);
            const Ctx = struct {
                objs: []const Obj,
                fn less(c: @This(), a: u32, b: u32) bool {
                    return c.objs[a].num < c.objs[b].num or (c.objs[a].num == c.objs[b].num and a < b);
                }
            };
            std.sort.block(u32, idx, Ctx{ .objs = p.objs[0..p.nobjs] }, Ctx.less);
            p.by_num = idx;
        }
        const idx = p.by_num.?;
        // The last definition of a number wins (incremental updates append).
        var lo: usize = 0;
        var hi: usize = idx.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (p.objs[idx[mid]].num <= num) lo = mid + 1 else hi = mid;
        }
        if (lo > 0 and p.objs[idx[lo - 1]].num == num) return p.objs[idx[lo - 1]];
        for (p.extra[0..p.nextra]) |e| if (e.num == num) return e;
        return null;
    }

    fn findObjLinear(p: *Parser, num: u32) ?Obj {
        var i = p.nobjs;
        while (i > 0) {
            i -= 1;
            if (p.objs[i].num == num) return p.objs[i];
        }
        return null;
    }

    /// The integer value of object `num` (an indirect /Length).
    fn resolveInt(p: *Parser, num: u32) ?i64 {
        const o = p.findObj(num) orelse return null;
        var lx = p.lex;
        lx.pos = o.off;
        lx.end = @min(p.total, o.off + 64);
        const t = lx.next();
        return if (t == .int) t.int else null;
    }

    // -----------------------------------------------------------------------------------------
    // Dictionaries.

    const Mode = enum { top, nested };

    /// Parse a dictionary whose "<<" was just read. At the top level of an object the keys a
    /// stream needs are recorded; at every depth /JS values are handled.
    fn parseDict(p: *Parser, d: *DictInfo, depth: usize, mode: Mode) Error!void {
        if (depth > max_depth) {
            p.once(.depth, .malformed, "pdf: nesting too deep");
            return p.skipRest(1);
        }
        while (true) {
            const t = p.lex.next();
            switch (t) {
                .eof, .dict_close => return,
                .name => |n| {
                    const key = Key.of(n);
                    const v = p.lex.next();
                    try p.value(d, depth, mode, key, v);
                },
                // Values in key position (damaged dictionaries): look inside them anyway.
                else => try p.value(d, depth, mode, .other, t),
            }
        }
    }

    fn value(p: *Parser, d: *DictInfo, depth: usize, mode: Mode, key: Key, v: Token) Error!void {
        if (key == .JS) return p.jsValue(d, v);
        const top = mode == .top;
        switch (v) {
            .dict_open => {
                if (top and key == .DecodeParms) {
                    d.parms[0] = try p.parseParms(depth + 1);
                    return;
                }
                if (top and key == .Encrypt) d.encrypt = .{ .direct = p.lex.pos };
                var inner: DictInfo = .{};
                try p.parseDict(&inner, depth + 1, .nested);
            },
            .arr_open => try p.array(d, depth + 1, if (top) key else .other),
            .int => |i| {
                const r = p.maybeRef(i);
                if (!top) return;
                switch (key) {
                    .Length => d.length = if (r) |num| .{ .ref = num } else .{ .int = i },
                    .N => d.n = i,
                    .First => d.first = i,
                    .Encrypt => if (r) |num| {
                        d.encrypt = .{ .ref = num };
                    },
                    else => {},
                }
            },
            .name => |n| if (top) switch (key) {
                .Filter => {
                    d.filters[0] = FilterId.of(n);
                    d.nfilters = 1;
                },
                .Type => d.type = TypeName.of(n),
                else => {},
            },
            else => {},
        }
    }

    fn jsValue(p: *Parser, d: *DictInfo, v: Token) Error!void {
        _ = d;
        switch (v) {
            .str_lit, .str_hex => if (p.extract_js and !p.locked) try p.jsString(v),
            .int => |i| if (p.maybeRef(i)) |num| p.addJsRef(num),
            .dict_open => {
                var inner: DictInfo = .{};
                try p.parseDict(&inner, 2, .nested);
            },
            .arr_open => try p.skipRest(1),
            else => {},
        }
    }

    fn array(p: *Parser, d: *DictInfo, depth: usize, key: Key) Error!void {
        if (depth > max_depth) {
            p.once(.depth, .malformed, "pdf: nesting too deep");
            return p.skipRest(1);
        }
        var k: usize = 0;
        while (true) : (k += 1) {
            const t = p.lex.next();
            switch (t) {
                .eof, .arr_close => return,
                .name => |n| if (key == .Filter) {
                    if (d.nfilters < max_filters) {
                        d.filters[d.nfilters] = FilterId.of(n);
                        d.nfilters += 1;
                    } else d.filter_overflow = true;
                },
                .dict_open => {
                    if (key == .DecodeParms) {
                        const parms = try p.parseParms(depth + 1);
                        if (k < max_filters) d.parms[k] = parms;
                    } else {
                        var inner: DictInfo = .{};
                        try p.parseDict(&inner, depth + 1, .nested);
                    }
                },
                .arr_open => try p.array(d, depth + 1, .other),
                .int => |i| {
                    if (key == .W and k < 3) d.w[k] = i else _ = p.maybeRef(i);
                },
                .str_lit, .str_hex => if (key == .ID and k == 0) {
                    d.id_len = p.readString(t, &d.id);
                },
                else => {},
            }
        }
    }

    /// /DecodeParms << /Predictor 12 /Columns 5 ... >>.
    fn parseParms(p: *Parser, depth: usize) Error!filter.Predictor.Params {
        var parms: filter.Predictor.Params = .{};
        while (true) {
            const t = p.lex.next();
            switch (t) {
                .eof, .dict_close => return parms,
                .name => |name| {
                    var key_buf: [16]u8 = undefined;
                    const n = key_buf[0..@min(name.len, key_buf.len)];
                    @memcpy(n, name[0..n.len]);
                    const v = p.lex.next();
                    if (v != .int) {
                        if (v == .dict_open) {
                            var inner: DictInfo = .{};
                            try p.parseDict(&inner, depth + 1, .nested);
                        } else p.skipValue(v);
                        continue;
                    }
                    if (std.mem.eql(u8, n, "Predictor")) parms.predictor = v.int;
                    if (std.mem.eql(u8, n, "Colors")) parms.colors = v.int;
                    if (std.mem.eql(u8, n, "BitsPerComponent")) parms.bpc = v.int;
                    if (std.mem.eql(u8, n, "Columns")) parms.columns = v.int;
                    if (std.mem.eql(u8, n, "EarlyChange")) parms.early_change = v.int != 0;
                },
                else => p.skipValue(t),
            }
        }
    }

    /// After an integer: "N G R" is a reference to object N.
    fn maybeRef(p: *Parser, n: i64) ?u32 {
        const save = p.lex.pos;
        const g = p.lex.next();
        if (g == .int) {
            const r = p.lex.next();
            if (r == .keyword and std.mem.eql(u8, r.keyword, "R")) return std.math.cast(u32, n);
        }
        p.lex.pos = save;
        return null;
    }

    /// Skip a value whose first token was `t` (dictionaries and arrays without recursion).
    fn skipValue(p: *Parser, t: Token) void {
        switch (t) {
            .dict_open, .arr_open => p.skipRest(1) catch {},
            .int => |i| _ = p.maybeRef(i),
            else => {},
        }
    }

    /// Skip to the close of `open` currently open dictionaries or arrays.
    fn skipRest(p: *Parser, open: usize) Error!void {
        var depth = open;
        while (depth > 0) {
            switch (p.lex.next()) {
                .eof => return,
                .dict_open, .arr_open => depth += 1,
                .dict_close, .arr_close => depth -= 1,
                else => {},
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Strings.

    /// Read a short string value (an /ID, /O or /U) into `out`; returns its length.
    fn readString(p: *Parser, t: Token, out: []u8) usize {
        const saved = p.lex.pos;
        defer p.lex.pos = saved;
        var sink: FixedSink = .{ .out = out };
        p.decodeStringRaw(t, &sink);
        return sink.len;
    }

    fn decodeString(p: *Parser, t: Token, sink: *StringSink, dec: ?*crypt.StringDecrypt) void {
        if (dec) |x| {
            var ds: DecryptSink = .{ .dec = x, .out = sink };
            p.decodeStringRaw(t, &ds);
        } else p.decodeStringRaw(t, sink);
    }

    /// Decode a literal or hex string starting at the token's offset into `sink.put(byte)`.
    fn decodeStringRaw(p: *Parser, t: Token, sink: anytype) void {
        const l = &p.lex;
        switch (t) {
            .str_hex => |at| {
                var q = at + 1;
                var high: ?u8 = null;
                while (l.peekAt(q)) |c| : (q += 1) {
                    if (c == '>') break;
                    const v = std.fmt.charToDigit(c, 16) catch continue;
                    if (high) |h| {
                        sink.put(h << 4 | v);
                        high = null;
                    } else high = v;
                }
                if (high) |h| sink.put(h << 4);
            },
            .str_lit => |at| {
                var q = at + 1;
                var depth: usize = 1;
                while (l.peekAt(q)) |c| {
                    q += 1;
                    switch (c) {
                        '(' => {
                            depth += 1;
                            sink.put(c);
                        },
                        ')' => {
                            depth -= 1;
                            if (depth == 0) return;
                            sink.put(c);
                        },
                        '\\' => {
                            const e = l.peekAt(q) orelse return;
                            q += 1;
                            switch (e) {
                                'n' => sink.put('\n'),
                                'r' => sink.put('\r'),
                                't' => sink.put('\t'),
                                'b' => sink.put(8),
                                'f' => sink.put(12),
                                '0'...'7' => {
                                    var v: u32 = e - '0';
                                    var k: usize = 1;
                                    while (k < 3) : (k += 1) {
                                        const d = l.peekAt(q) orelse break;
                                        if (d < '0' or d > '7') break;
                                        v = v * 8 + (d - '0');
                                        q += 1;
                                    }
                                    sink.put(@truncate(v));
                                },
                                '\r' => {
                                    if (l.peekAt(q) == '\n') q += 1;
                                },
                                '\n' => {},
                                else => sink.put(e),
                            }
                        },
                        else => sink.put(c),
                    }
                }
            },
            else => {},
        }
    }
};

/// Collects decoded string bytes, converting UTF-16BE (a leading FE FF) to UTF-8.
const StringSink = struct {
    c: *Collector,
    buf: [512]u8 = undefined,
    len: usize = 0,
    count: usize = 0,
    utf16: bool = false,
    bom: [2]u8 = undefined,
    hi: ?u8 = null,

    pub fn put(s: *StringSink, b: u8) void {
        defer s.count += 1;
        if (s.count < 2) {
            s.bom[s.count] = b;
            if (s.count == 1) {
                if (s.bom[0] == 0xfe and s.bom[1] == 0xff) {
                    s.utf16 = true;
                } else {
                    s.raw(s.bom[0]);
                    s.raw(s.bom[1]);
                }
            }
            return;
        }
        if (!s.utf16) return s.raw(b);
        const h = s.hi orelse {
            s.hi = b;
            return;
        };
        s.hi = null;
        const unit: u21 = @as(u21, h) << 8 | b;
        var enc: [4]u8 = undefined;
        // Surrogates are not paired here; they become '?', which a signature never needs.
        const n = std.unicode.utf8Encode(if (unit >= 0xd800 and unit <= 0xdfff) '?' else unit, &enc) catch 1;
        for (enc[0..n]) |x| s.raw(x);
    }

    fn raw(s: *StringSink, b: u8) void {
        s.buf[s.len] = b;
        s.len += 1;
        if (s.len == s.buf.len) s.flushBuf();
    }

    fn flushBuf(s: *StringSink) void {
        s.c.append(s.buf[0..s.len]);
        s.len = 0;
    }

    pub fn flush(s: *StringSink) void {
        if (s.count == 1) s.raw(s.bom[0]);
        s.flushBuf();
    }
};

const FixedSink = struct {
    out: []u8,
    len: usize = 0,
    pub fn put(s: *FixedSink, b: u8) void {
        if (s.len < s.out.len) {
            s.out[s.len] = b;
            s.len += 1;
        }
    }
};

const DecryptSink = struct {
    dec: *crypt.StringDecrypt,
    out: *StringSink,
    pub fn put(s: *DecryptSink, b: u8) void {
        s.dec.put(b, s.out);
    }
};

// ---------------------------------------------------------------------------------------------
// Dictionary contents.

const Value = union(enum) { int: i64, ref: u32 };

const TypeName = enum {
    other,
    objstm,
    xref,
    embedded_file,
    metadata,

    fn of(n: []const u8) TypeName {
        if (std.mem.eql(u8, n, "ObjStm")) return .objstm;
        if (std.mem.eql(u8, n, "XRef")) return .xref;
        if (std.mem.eql(u8, n, "EmbeddedFile")) return .embedded_file;
        if (std.mem.eql(u8, n, "Metadata")) return .metadata;
        return .other;
    }
};

pub const FilterId = enum {
    flate,
    lzw,
    ascii_hex,
    ascii85,
    run_length,
    crypt,
    /// Image codecs: the data is passed on as it is.
    image,
    unknown,
    /// Internal: decryption of the stream before its filters.
    decrypt,

    pub fn of(n: []const u8) FilterId {
        const Pair = struct { []const u8, FilterId };
        const names = [_]Pair{
            .{ "FlateDecode", .flate },          .{ "Fl", .flate },
            .{ "LZWDecode", .lzw },              .{ "LZW", .lzw },
            .{ "ASCIIHexDecode", .ascii_hex },   .{ "AHx", .ascii_hex },
            .{ "ASCII85Decode", .ascii85 },      .{ "A85", .ascii85 },
            .{ "RunLengthDecode", .run_length }, .{ "RL", .run_length },
            .{ "Crypt", .crypt },                .{ "DCTDecode", .image },
            .{ "DCT", .image },                  .{ "JPXDecode", .image },
            .{ "CCITTFaxDecode", .image },       .{ "CCF", .image },
            .{ "JBIG2Decode", .image },
        };
        for (names) |e| if (std.mem.eql(u8, n, e[0])) return e[1];
        return .unknown;
    }
};

const DictInfo = struct {
    length: ?Value = null,
    filters: [max_filters]FilterId = undefined,
    nfilters: usize = 0,
    filter_overflow: bool = false,
    parms: [max_filters]filter.Predictor.Params = @splat(.{}),
    type: TypeName = .other,
    n: ?i64 = null,
    first: ?i64 = null,
    w: [3]i64 = .{ 0, 0, 0 },
    encrypt: ?crypt.Info.Ref = null,
    id: [32]u8 = undefined,
    id_len: usize = 0,
};

const Key = enum {
    other,
    Length,
    Filter,
    DecodeParms,
    Type,
    N,
    First,
    JS,
    W,
    Encrypt,
    ID,
    V,
    R,
    O,
    U,
    OE,
    UE,
    P,
    CF,
    StmF,
    StrF,
    EncryptMetadata,

    fn of(n: []const u8) Key {
        inline for (@typeInfo(Key).@"enum".field_names, 0..) |f, i| {
            if (i > 0 and std.mem.eql(u8, n, f)) return @fromBackingInt(@intCast(i));
        }
        return .other;
    }
};

// ---------------------------------------------------------------------------------------------
// Filter chains.

const Chain = struct {
    p: *Parser,
    lzw: ?*filter.Lzw = null,
    inflate: ?*inflate.Inflate = null,
    dec: ?*crypt.StreamDecrypt = null,

    /// Add one filter (and its predictor) after `in`. Null when memory ran out (reported).
    fn add(c: *Chain, f: FilterId, in: *Io.Reader, parms: filter.Predictor.Params, key: crypt.Key) ?*Io.Reader {
        const w = c.p.w;
        const a = w.scratch.allocator();
        const buf = w.alloc(u8, 4096) orelse return null;
        var out: *Io.Reader = switch (f) {
            .flate => blk: {
                const work = w.alloc(u8, inflate.work_len) orelse return null;
                const d = a.create(inflate.Inflate) catch return oom(w);
                // Most streams are zlib; some writers emit raw deflate.
                const head = in.peek(2) catch &[_]u8{ 0, 0 };
                const zlib = head.len == 2 and head[0] & 0x0f == 8 and (@as(u16, head[0]) << 8 | head[1]) % 31 == 0;
                d.* = .init(in, if (zlib) .zlib else .raw, work);
                d.interface.buffer = buf;
                c.inflate = d;
                break :blk &d.interface;
            },
            .lzw => blk: {
                const t = a.create(filter.Lzw.Table) catch return oom(w);
                const d = a.create(filter.Lzw) catch return oom(w);
                d.* = .init(in, t, parms.early_change, buf);
                c.lzw = d;
                break :blk &d.interface;
            },
            .ascii_hex => blk: {
                const d = a.create(filter.AsciiHex) catch return oom(w);
                d.* = .init(in, buf);
                break :blk &d.interface;
            },
            .ascii85 => blk: {
                const d = a.create(filter.Ascii85) catch return oom(w);
                d.* = .init(in, buf);
                break :blk &d.interface;
            },
            .run_length => blk: {
                const d = a.create(filter.RunLength) catch return oom(w);
                d.* = .init(in, buf);
                break :blk &d.interface;
            },
            .decrypt => blk: {
                const d = a.create(crypt.StreamDecrypt) catch return oom(w);
                d.* = .init(in, key, buf);
                c.dec = d;
                break :blk &d.interface;
            },
            .crypt, .image, .unknown => unreachable,
        };
        if ((f == .flate or f == .lzw) and parms.predictor >= 2) {
            const kind: filter.Predictor.Kind = if (parms.predictor == 2) .tiff else .png;
            const row = parms.rowLen() orelse {
                c.p.once(.filters, .unsupported, "pdf: predictor parameters");
                return out;
            };
            if (parms.predictor > 2 and parms.predictor < 10) return out;
            const rows = w.alloc(u8, 2 * row) orelse return null;
            const pbuf = w.alloc(u8, 4096) orelse return null;
            const d = a.create(filter.Predictor) catch return oom(w);
            d.* = .init(out, kind, parms, rows, pbuf);
            out = &d.interface;
        }
        return out;
    }

    fn oom(w: *Walker) ?*Io.Reader {
        w.limit(.memory);
        return null;
    }

    fn failure(c: *const Chain) ?[]const u8 {
        if (c.inflate) |d| if (d.err) |e| return switch (e) {
            inline else => |x| "pdf: FlateDecode: " ++ @errorName(x),
        };
        if (c.lzw) |d| if (d.err != null) return "pdf: LZWDecode: invalid code";
        if (c.dec) |d| if (d.bad) return "pdf: decryption: bad padding";
        return null;
    }
};

// ---------------------------------------------------------------------------------------------
// Lexer.

fn isSpace(c: u8) bool {
    return switch (c) {
        0, '\t', '\n', 0x0c, '\r', ' ' => true,
        else => false,
    };
}

fn isDelim(c: u8) bool {
    return switch (c) {
        '(', ')', '<', '>', '[', ']', '{', '}', '/', '%' => true,
        else => false,
    };
}

fn isRegular(c: u8) bool {
    return !isSpace(c) and !isDelim(c);
}

/// "N G" right before an "obj" at `at`: the object number and generation, and where N starts.
fn headerBefore(data: []const u8, at: usize) ?struct { num: u32, gen: u16, start: usize } {
    var j = at;
    while (j > 0 and isSpace(data[j - 1])) j -= 1;
    const gen_end = j;
    while (j > 0 and std.ascii.isDigit(data[j - 1]) and gen_end - j < 6) j -= 1;
    if (j == gen_end) return null;
    const gen = std.fmt.parseInt(u16, data[j..gen_end], 10) catch return null;
    const sp = j;
    while (j > 0 and isSpace(data[j - 1])) j -= 1;
    if (j == sp) return null;
    const num_end = j;
    while (j > 0 and std.ascii.isDigit(data[j - 1]) and num_end - j < 11) j -= 1;
    if (j == num_end) return null;
    if (j > 0 and isRegular(data[j - 1])) return null;
    const num = std.fmt.parseInt(u32, data[j..num_end], 10) catch return null;
    return .{ .num = num, .gen = gen, .start = j };
}

fn beInt(b: []const u8) u64 {
    var v: u64 = 0;
    for (b) |c| v = v << 8 | c;
    return v;
}

pub const Token = union(enum) {
    eof,
    name: []const u8,
    int: i64,
    real,
    /// Offset of the string's opening '(' or '<'; the lexer has skipped the string.
    str_lit: u64,
    str_hex: u64,
    dict_open,
    dict_close,
    arr_open,
    arr_close,
    keyword: []const u8,
    other,
};

const Lexer = struct {
    io: Io,
    src: Source,
    /// Tokens end here (the next object header).
    end: u64,
    buf: []u8,
    base: u64 = 0,
    len: usize = 0,
    pos: u64 = 0,
    name_buf: [128]u8 = undefined,
    kw_buf: [32]u8 = undefined,

    fn peekAt(l: *Lexer, at: u64) ?u8 {
        if (at >= l.end) return null;
        if (at < l.base or at >= l.base + l.len) {
            const want: usize = @intCast(@min(l.buf.len, l.end - at));
            const n = l.src.readAt(l.io, at, l.buf[0..want]) catch return null;
            if (n == 0) return null;
            l.base = at;
            l.len = n;
        }
        return l.buf[@intCast(at - l.base)];
    }

    fn next(l: *Lexer) Token {
        // White space and comments.
        while (true) {
            const c = l.peekAt(l.pos) orelse return .eof;
            if (isSpace(c)) {
                l.pos += 1;
            } else if (c == '%') {
                while (l.peekAt(l.pos)) |x| : (l.pos += 1) if (x == '\n' or x == '\r') break;
            } else break;
        }
        const start = l.pos;
        const c = l.peekAt(l.pos).?;
        l.pos += 1;
        switch (c) {
            '/' => {
                var n: usize = 0;
                while (l.peekAt(l.pos)) |x| {
                    if (!isRegular(x)) break;
                    l.pos += 1;
                    var b = x;
                    // #xx escapes in names (/J#53 is /JS).
                    if (x == '#') {
                        const h1 = l.peekAt(l.pos);
                        const h2 = l.peekAt(l.pos + 1);
                        if (h1 != null and h2 != null) {
                            const v1 = std.fmt.charToDigit(h1.?, 16) catch null;
                            const v2 = std.fmt.charToDigit(h2.?, 16) catch null;
                            if (v1 != null and v2 != null) {
                                b = v1.? << 4 | v2.?;
                                l.pos += 2;
                            }
                        }
                    }
                    if (n < l.name_buf.len) {
                        l.name_buf[n] = b;
                        n += 1;
                    }
                }
                return .{ .name = l.name_buf[0..n] };
            },
            '(' => {
                var depth: usize = 1;
                while (l.peekAt(l.pos)) |x| {
                    l.pos += 1;
                    switch (x) {
                        '\\' => l.pos += 1,
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if (depth == 0) break;
                        },
                        else => {},
                    }
                }
                return .{ .str_lit = start };
            },
            '<' => {
                if (l.peekAt(l.pos) == '<') {
                    l.pos += 1;
                    return .dict_open;
                }
                while (l.peekAt(l.pos)) |x| {
                    l.pos += 1;
                    if (x == '>') break;
                }
                return .{ .str_hex = start };
            },
            '>' => {
                if (l.peekAt(l.pos) == '>') {
                    l.pos += 1;
                    return .dict_close;
                }
                return .other;
            },
            '[' => return .arr_open,
            ']' => return .arr_close,
            '{', '}', ')' => return .other,
            else => {
                var n: usize = 0;
                l.kw_buf[0] = c;
                n = 1;
                while (l.peekAt(l.pos)) |x| {
                    if (!isRegular(x)) break;
                    if (n < l.kw_buf.len) l.kw_buf[n] = x;
                    n += 1;
                    l.pos += 1;
                }
                const word = l.kw_buf[0..@min(n, l.kw_buf.len)];
                if (n <= l.kw_buf.len) {
                    if (std.fmt.parseInt(i64, word, 10)) |v| return .{ .int = v } else |_| {}
                }
                if (std.ascii.isDigit(c) or c == '-' or c == '+' or c == '.') return .real;
                return .{ .keyword = word };
            },
        }
    }
};

// ---------------------------------------------------------------------------------------------

const scan = @import("scan.zig");
const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

test "lexer tokens, names with escapes and nested strings" {
    const text = "<< /Type /J#53 /K [1 0 R (a (b) \\) c) <41 42>] -3 1.5 true >> % c\nstream";
    var buf: [8]u8 = undefined;
    var l: Lexer = .{ .io = std.testing.io, .src = .{ .memory = text }, .end = text.len, .buf = &buf };
    try std.testing.expect(l.next() == .dict_open);
    try std.testing.expectEqualStrings("Type", l.next().name);
    try std.testing.expectEqualStrings("JS", l.next().name);
    try std.testing.expectEqualStrings("K", l.next().name);
    try std.testing.expect(l.next() == .arr_open);
    try std.testing.expectEqual(@as(i64, 1), l.next().int);
    try std.testing.expectEqual(@as(i64, 0), l.next().int);
    try std.testing.expectEqualStrings("R", l.next().keyword);
    try std.testing.expect(l.next() == .str_lit);
    try std.testing.expect(l.next() == .str_hex);
    try std.testing.expect(l.next() == .arr_close);
    try std.testing.expectEqual(@as(i64, -3), l.next().int);
    try std.testing.expect(l.next() == .real);
    try std.testing.expectEqualStrings("true", l.next().keyword);
    try std.testing.expect(l.next() == .dict_close);
    try std.testing.expectEqualStrings("stream", l.next().keyword);
    try std.testing.expect(l.next() == .eof);
}

test "object headers are found backwards from obj" {
    const h = headerBefore("x\n12 0 obj", 7).?;
    try std.testing.expectEqual(@as(u32, 12), h.num);
    try std.testing.expectEqual(@as(usize, 2), h.start);
    try std.testing.expect(headerBefore("endobj", 3) == null);
    try std.testing.expect(headerBefore("a12 0 obj", 6) == null);
}

const docs = @import("fixtures/docs.zig");

/// Scan every document fixture of `ext` positionally and as a stream, and check its children
/// (each seen twice, with exact bytes) and notices (each expected one raised, no malformed
/// notice unless expected). Shared by the PDF, RTF and 7z tests.
pub fn checkDocs(ext: []const u8) !void {
    for (docs.docs) |d| {
        if (!std.mem.endsWith(u8, d.name, ext)) continue;
        var rig: scan.TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(d.bytes, d.name);
        for (d.members) |m| {
            var path_buf: [512]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ d.name, m.path });
            var seen: usize = 0;
            for (rig.rec.objects.items) |e| if (std.mem.eql(u8, e.path, path)) {
                seen += 1;
                if (e.bytes != m.len or e.crc != m.crc) {
                    std.debug.print("{s}: {s} is {d} bytes crc {x}, want {d} crc {x}\n", .{ d.name, path, e.bytes, e.crc, m.len, m.crc });
                    rig.rec.dump();
                    return error.TestUnexpectedResult;
                }
            };
            if (seen != 2) {
                std.debug.print("{s}: {s} seen {d} times\n", .{ d.name, path, seen });
                rig.rec.dump();
                return error.TestUnexpectedResult;
            }
        }
        var want_malformed = false;
        for (d.notices) |n| {
            const tag = std.meta.stringToEnum(std.meta.Tag(container.Notice.What), n).?;
            if (tag == .malformed) want_malformed = true;
            if (!rig.rec.has(tag)) {
                std.debug.print("{s}: expected a {s} notice\n", .{ d.name, n });
                rig.rec.dump();
                return error.TestUnexpectedResult;
            }
        }
        if (!want_malformed and rig.rec.has(.malformed)) {
            std.debug.print("{s}: unexpected malformed notice\n", .{d.name});
            rig.rec.dump();
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
    }
}

test "PDF fixtures: streams, filters, object streams, JavaScript, embedded files, encryption" {
    try checkDocs(".pdf");
}
