//! 7z archives (P5.14), from the format description in the LZMA SDK (7zFormat.txt).
//!
//! The signature header points at the archive header at the end of the file. An encoded header
//! (kEncodedHeader) is itself a folder that decodes to the real header, and may be nested. Each
//! folder of the main streams is decoded once, through a linear chain of coders, and its output
//! is split into the files it holds by the substream sizes; every file is scanned as a stream
//! child named by its path.
//!
//! Coders: Copy, LZMA and LZMA2 (our decoders in lzma.zig), Deflate (inflate.zig), BZip2
//! (bzip2.zig) and the x86 BCJ filter (bcj.zig). AES-encrypted folders and headers are reported
//! as encrypted; other coders (BCJ2, PPMd, ARM filters, Delta) as unsupported, and their packed
//! bytes are still scanned with the archive's raw bytes.
//!
//! Bounds: the header is read into scratch up to `max_header`, at most `max_folders` folders,
//! `max_coders` coders per folder and MaxFiles files are kept, dictionaries take big-window
//! tokens, and every folder's output goes through a `Meter` (ratio, MaxFileSize, total output).
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const lzma = @import("lzma.zig");
const inflate = @import("inflate.zig");
const bzip2 = @import("bzip2.zig");
const bcj = @import("bcj.zig");

pub const signature = "7z\xbc\xaf\x27\x1c";
pub const max_header = 16 * 1024 * 1024;
pub const max_folders = 1024;
pub const max_coders = 4;
const max_names = 64 * 1024;

const Id = enum(u8) {
    end = 0x00,
    header = 0x01,
    archive_properties = 0x02,
    additional_streams_info = 0x03,
    main_streams_info = 0x04,
    files_info = 0x05,
    pack_info = 0x06,
    unpack_info = 0x07,
    substreams_info = 0x08,
    size = 0x09,
    crc = 0x0a,
    folder = 0x0b,
    coders_unpack_size = 0x0c,
    num_unpack_stream = 0x0d,
    empty_stream = 0x0e,
    empty_file = 0x0f,
    name = 0x11,
    encoded_header = 0x17,
    dummy = 0x19,
    _,
};

const Method = enum { copy, lzma, lzma2, deflate, bzip2, bcj_x86, aes, unsupported };

fn methodOf(id: []const u8) Method {
    const Pair = struct { []const u8, Method };
    for ([_]Pair{
        .{ "\x00", .copy },
        .{ "\x21", .lzma2 },
        .{ "\x03\x01\x01", .lzma },
        .{ "\x03\x03\x01\x03", .bcj_x86 },
        .{ "\x04\x01\x08", .deflate },
        .{ "\x04\x02\x02", .bzip2 },
        .{ "\x06\xf1\x07\x01", .aes },
    }) |p| if (std.mem.eql(u8, id, p[0])) return p[1];
    return .unsupported;
}

const Coder = struct {
    method: Method,
    props: [8]u8 = undefined,
    props_len: u8 = 0,
    in_streams: u32 = 1,
    out_streams: u32 = 1,
};

const Folder = struct {
    coders: [max_coders]Coder = undefined,
    ncoders: u32 = 0,
    /// (in index, out index) pairs, folder-global stream numbering.
    binds: [max_coders]struct { in: u64, out: u64 } = undefined,
    nbinds: u32 = 0,
    /// Folder in-stream indices fed by packed streams, in packed order.
    packed_in: [max_coders]u64 = undefined,
    npacked: u32 = 0,
    unpack_sizes: [max_coders * 2]u64 = @splat(0),
    nunpack: u32 = 0,
    too_complex: bool = false,
    /// Files (substreams) in this folder.
    nsub: u64 = 1,
    /// First packed stream of this folder, in archive order.
    first_pack: u64 = 0,

    fn totalOut(f: *const Folder) u64 {
        var n: u64 = 0;
        for (f.coders[0..f.ncoders]) |c| n += c.out_streams;
        return n;
    }

    /// The out stream not bound to any coder's input: the folder's result.
    fn mainOut(f: *const Folder) ?u64 {
        var i: u64 = 0;
        while (i < f.totalOut()) : (i += 1) {
            var bound = false;
            for (f.binds[0..f.nbinds]) |b| if (b.out == i) {
                bound = true;
            };
            if (!bound) return i;
        }
        return null;
    }

    fn unpackSize(f: *const Folder) u64 {
        const m = f.mainOut() orelse return 0;
        return if (m < f.nunpack) f.unpack_sizes[@intCast(m)] else 0;
    }
};

pub fn isSevenZip(head: []const u8) bool {
    return std.mem.startsWith(u8, head, signature);
}

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len() orelse return;
    var sh: [32]u8 = undefined;
    src.readAllAt(w.io, 0, &sh) catch return w.notice(.malformed, "7z: truncated signature header");
    const next_off = std.mem.readInt(u64, sh[12..20], .little);
    const next_size = std.mem.readInt(u64, sh[20..28], .little);
    if (next_size == 0) return; // an empty archive
    if (next_off > total or next_size > total - 32 or 32 + next_off > total - next_size) return w.notice(.malformed, "7z: header outside the file");
    if (next_size > max_header) return w.notice(.unsupported, "7z: header too large");
    const a = w.scratch.allocator().create(Archive) catch return w.limit(.memory);
    a.* = .{ .w = w, .src = src };
    var hdr = w.alloc(u8, @intCast(next_size)) orelse return;
    src.readAllAt(w.io, 32 + next_off, hdr) catch return w.notice(.malformed, "7z: truncated header");
    // Encoded headers decode to the next header; a few levels at most.
    var levels: usize = 0;
    while (hdr.len > 0 and hdr[0] == @backingInt(Id.encoded_header)) : (levels += 1) {
        if (levels == 4) return w.notice(.malformed, "7z: header encoded too many times");
        var c: Cursor = .{ .b = hdr[1..] };
        a.reset();
        a.streamsInfo(&c) catch return a.headerError();
        if (a.nfolders == 0) return w.notice(.malformed, "7z: encoded header without a folder");
        const f = &a.folders[0];
        const size = f.unpackSize();
        if (size > max_header) return w.notice(.unsupported, "7z: header too large");
        const out = w.alloc(u8, @intCast(size)) orelse return;
        const got = try a.decodeFolder(0, .{ .buffer = out });
        if (a.encrypted) return w.notice(.encrypted, "7z: encrypted header");
        if (got != size) return w.notice(.malformed, "7z: encoded header did not decode");
        hdr = out;
    }
    if (hdr.len == 0 or hdr[0] != @backingInt(Id.header)) return w.notice(.malformed, "7z: no header");
    var c: Cursor = .{ .b = hdr[1..] };
    a.reset();
    a.parseHeader(&c) catch return a.headerError();
    try a.extract();
}

const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    const Err = error{Truncated};

    fn byte(c: *Cursor) Err!u8 {
        if (c.i >= c.b.len) return error.Truncated;
        c.i += 1;
        return c.b[c.i - 1];
    }

    fn id(c: *Cursor) Err!Id {
        return @fromBackingInt(@intCast(try c.byte()));
    }

    /// 7z's variable-length UINT64: the first byte's leading 1 bits count the extra bytes.
    fn number(c: *Cursor) Err!u64 {
        const first = try c.byte();
        var mask: u8 = 0x80;
        var v: u64 = 0;
        var k: u6 = 0;
        while (k < 8) : (k += 1) {
            if (first & mask == 0) {
                const high: u64 = first & (mask -% 1);
                return v | (high << (8 * k));
            }
            v |= @as(u64, try c.byte()) << (8 * k);
            mask >>= 1;
        }
        return v;
    }

    fn skip(c: *Cursor, n: u64) Err!void {
        if (n > c.b.len - c.i) return error.Truncated;
        c.i += @intCast(n);
    }

    fn bytes(c: *Cursor, n: u64) Err![]const u8 {
        const start = c.i;
        try c.skip(n);
        return c.b[start..c.i];
    }
};

const HeaderError = Cursor.Err || error{ Malformed, TooMany };

const Archive = struct {
    w: *Walker,
    src: Source,
    pack_pos: u64 = 0,
    pack_sizes: [max_folders * 2]u64 = undefined,
    npack: u64 = 0,
    folders: [max_folders]Folder = undefined,
    nfolders: usize = 0,
    /// Sizes of every file with data, in folder order.
    sub_sizes: []u64 = &.{},
    nsub: usize = 0,
    names: [max_names]u8 = undefined,
    names_len: usize = 0,
    /// Per file: name slice and whether it has a data stream.
    files: []File = &.{},
    nfiles: usize = 0,
    encrypted: bool = false,
    reported_unsupported: bool = false,

    const File = struct { name: []const u8 = "", has_stream: bool = true };

    fn reset(a: *Archive) void {
        a.pack_pos = 0;
        a.npack = 0;
        a.nfolders = 0;
        a.nsub = 0;
        a.nfiles = 0;
    }

    fn headerError(a: *Archive) void {
        a.w.notice(.malformed, "7z: header");
    }

    fn parseHeader(a: *Archive, c: *Cursor) HeaderError!void {
        while (true) {
            switch (try c.id()) {
                .end => return,
                .archive_properties => {
                    // Property type, size, data, until a zero type.
                    while (true) {
                        const t = try c.byte();
                        if (t == 0) break;
                        try c.skip(try c.number());
                    }
                },
                .additional_streams_info => {
                    // Not used by any current encoder; parsed and dropped.
                    try a.streamsInfo(c);
                    a.reset();
                },
                .main_streams_info => try a.streamsInfo(c),
                .files_info => try a.filesInfo(c),
                else => return error.Malformed,
            }
        }
    }

    fn streamsInfo(a: *Archive, c: *Cursor) HeaderError!void {
        while (true) {
            switch (try c.id()) {
                .end => return,
                .pack_info => try a.packInfo(c),
                .unpack_info => try a.unpackInfo(c),
                .substreams_info => try a.substreamsInfo(c),
                else => return error.Malformed,
            }
        }
    }

    fn packInfo(a: *Archive, c: *Cursor) HeaderError!void {
        a.pack_pos = try c.number();
        a.npack = try c.number();
        if (a.npack > a.pack_sizes.len) return error.TooMany;
        while (true) {
            switch (try c.id()) {
                .end => return,
                .size => for (a.pack_sizes[0..@intCast(a.npack)]) |*s| {
                    s.* = try c.number();
                },
                .crc => try skipDigests(c, a.npack),
                else => return error.Malformed,
            }
        }
    }

    fn unpackInfo(a: *Archive, c: *Cursor) HeaderError!void {
        if (try c.id() != .folder) return error.Malformed;
        const n = try c.number();
        if (n > max_folders) return error.TooMany;
        if (try c.byte() != 0) return error.Malformed; // external
        a.nfolders = @intCast(n);
        var first_pack: u64 = 0;
        for (a.folders[0..a.nfolders]) |*f| {
            f.* = .{};
            try folder(c, f);
            f.first_pack = first_pack;
            first_pack += f.npacked;
        }
        if (try c.id() != .coders_unpack_size) return error.Malformed;
        for (a.folders[0..a.nfolders]) |*f| {
            const outs = f.totalOut();
            if (outs > f.unpack_sizes.len) return error.TooMany;
            f.nunpack = @intCast(outs);
            for (f.unpack_sizes[0..f.nunpack]) |*s| s.* = try c.number();
        }
        while (true) {
            switch (try c.id()) {
                .end => return,
                .crc => try skipDigests(c, a.nfolders),
                else => return error.Malformed,
            }
        }
    }

    fn folder(c: *Cursor, f: *Folder) HeaderError!void {
        const ncoders = try c.number();
        if (ncoders == 0 or ncoders > 64) return error.Malformed;
        var total_in: u64 = 0;
        var total_out: u64 = 0;
        var k: u64 = 0;
        while (k < ncoders) : (k += 1) {
            const flags = try c.byte();
            if (flags & 0x80 != 0) return error.Malformed; // alternative methods: reserved
            const id = try c.bytes(flags & 0x0f);
            var coder: Coder = .{ .method = methodOf(id) };
            if (flags & 0x10 != 0) {
                const ins = try c.number();
                const outs = try c.number();
                if (ins > 64 or outs > 64) return error.Malformed;
                coder.in_streams = @intCast(ins);
                coder.out_streams = @intCast(outs);
            }
            if (flags & 0x20 != 0) {
                const props = try c.bytes(try c.number());
                coder.props_len = @intCast(@min(props.len, coder.props.len));
                @memcpy(coder.props[0..coder.props_len], props[0..coder.props_len]);
            }
            total_in += coder.in_streams;
            total_out += coder.out_streams;
            if (k < max_coders) f.coders[@intCast(k)] = coder else f.too_complex = true;
        }
        f.ncoders = @intCast(@min(ncoders, max_coders));
        if (total_out == 0) return error.Malformed;
        const nbinds = total_out - 1;
        if (nbinds > total_in) return error.Malformed;
        k = 0;
        while (k < nbinds) : (k += 1) {
            const in = try c.number();
            const out = try c.number();
            if (k < max_coders) f.binds[@intCast(k)] = .{ .in = in, .out = out } else f.too_complex = true;
        }
        f.nbinds = @intCast(@min(nbinds, max_coders));
        const npacked = total_in - nbinds;
        if (npacked == 1) {
            // The one in stream no bind pair feeds.
            var i: u64 = 0;
            while (i < total_in) : (i += 1) {
                var bound = false;
                for (f.binds[0..f.nbinds]) |b| if (b.in == i) {
                    bound = true;
                };
                if (!bound) break;
            }
            f.packed_in[0] = i;
        } else {
            k = 0;
            while (k < npacked) : (k += 1) {
                const idx = try c.number();
                if (k < max_coders) f.packed_in[@intCast(k)] = idx else f.too_complex = true;
            }
        }
        f.npacked = @intCast(@min(npacked, max_coders));
        if (ncoders > max_coders or npacked > max_coders) f.too_complex = true;
    }

    fn substreamsInfo(a: *Archive, c: *Cursor) HeaderError!void {
        var t = try c.id();
        if (t == .num_unpack_stream) {
            for (a.folders[0..a.nfolders]) |*f| f.nsub = try c.number();
            t = try c.id();
        }
        var total: u64 = 0;
        for (a.folders[0..a.nfolders]) |f| total += f.nsub;
        // MaxFiles is enforced as the files are scanned; this only bounds the size table.
        if (total > 1 << 20) return error.TooMany;
        a.sub_sizes = a.w.scratch.allocator().alloc(u64, @intCast(total)) catch return error.TooMany;
        a.nsub = @intCast(total);
        // Sizes: all but the last of each folder are listed; the last is the remainder.
        var i: usize = 0;
        for (a.folders[0..a.nfolders]) |f| {
            if (f.nsub == 0) continue;
            var used: u64 = 0;
            var k: u64 = 0;
            while (k + 1 < f.nsub) : (k += 1) {
                const s = if (t == .size) try c.number() else 0;
                a.sub_sizes[i] = s;
                used +|= s;
                i += 1;
            }
            a.sub_sizes[i] = f.unpackSize() -| used;
            i += 1;
        }
        if (t == .size) t = try c.id();
        while (t != .end) {
            switch (t) {
                .crc => {
                    // Digests for the streams without a known CRC; count them generously.
                    try skipDigests(c, a.nsub);
                },
                else => return error.Malformed,
            }
            t = try c.id();
        }
    }

    fn filesInfo(a: *Archive, c: *Cursor) HeaderError!void {
        const n = try c.number();
        if (n > 1 << 20) return error.TooMany;
        a.files = a.w.scratch.allocator().alloc(File, @intCast(n)) catch return error.TooMany;
        a.nfiles = @intCast(n);
        for (a.files) |*f| f.* = .{};
        while (true) {
            const t = try c.id();
            if (t == .end) return;
            const size = try c.number();
            const body = try c.bytes(size);
            var bc: Cursor = .{ .b = body };
            switch (t) {
                .empty_stream => {
                    for (a.files, 0..) |*f, i| f.has_stream = !bit(body, i);
                },
                .name => {
                    if (try bc.byte() != 0) continue; // external
                    a.names_len = 0;
                    for (a.files) |*f| f.name = a.utf16Name(&bc);
                },
                else => {},
            }
        }
    }

    /// One NUL-terminated UTF-16LE name, converted into `names`.
    fn utf16Name(a: *Archive, c: *Cursor) []const u8 {
        const start = a.names_len;
        while (c.i + 1 < c.b.len) {
            const unit = std.mem.readInt(u16, c.b[c.i..][0..2], .little);
            c.i += 2;
            if (unit == 0) break;
            var e: [4]u8 = undefined;
            const cp: u21 = if (unit >= 0xd800 and unit <= 0xdfff) '?' else unit;
            const len = std.unicode.utf8Encode(cp, &e) catch 1;
            if (a.names_len + len > a.names.len or a.names_len - start + len > 1000) continue;
            @memcpy(a.names[a.names_len..][0..len], e[0..len]);
            a.names_len += len;
        }
        for (a.names[start..a.names_len]) |*ch| if (ch.* == '\\') {
            ch.* = '/';
        };
        return a.names[start..a.names_len];
    }

    fn skipDigests(c: *Cursor, n: u64) HeaderError!void {
        const all = try c.byte();
        var defined: u64 = n;
        if (all == 0) {
            const bits = try c.bytes((n + 7) / 8);
            defined = 0;
            var i: u64 = 0;
            while (i < n) : (i += 1) {
                if (bit(bits, @intCast(i))) defined += 1;
            }
        }
        try c.skip(defined * 4);
    }

    fn bit(bits: []const u8, i: usize) bool {
        if (i / 8 >= bits.len) return false;
        return bits[i / 8] & (@as(u8, 0x80) >> @intCast(i % 8)) != 0;
    }

    // -----------------------------------------------------------------------------------------
    // Extraction.

    fn extract(a: *Archive) Error!void {
        const w = a.w;
        // With no substreams info, each folder holds one file.
        if (a.nsub == 0 and a.nfolders > 0) {
            a.sub_sizes = w.scratch.allocator().alloc(u64, a.nfolders) catch return w.limit(.memory);
            for (a.folders[0..a.nfolders], 0..) |f, i| a.sub_sizes[i] = f.unpackSize();
            a.nsub = a.nfolders;
            for (a.folders[0..a.nfolders]) |*f| f.nsub = 1;
        }
        var sub: usize = 0;
        var file: usize = 0;
        for (0..a.nfolders) |fi| {
            const f = &a.folders[fi];
            const nsub: usize = @intCast(@min(f.nsub, a.nsub - sub));
            var names: Names = .{ .a = a, .file = file, .first_sub = sub };
            _ = try a.decodeFolder(fi, .{ .split = .{ .sizes = a.sub_sizes[sub..][0..nsub], .names = &names } });
            file = names.file;
            sub += nsub;
            if (w.halt != null) return error.Halted;
        }
    }

    /// Names files in order, skipping those without a data stream.
    const Names = struct {
        a: *Archive,
        file: usize,
        first_sub: usize,
        buf: [32]u8 = undefined,

        fn next(n: *Names, sub: usize) []const u8 {
            const a = n.a;
            while (n.file < a.nfiles and !a.files[n.file].has_stream) n.file += 1;
            if (n.file < a.nfiles) {
                defer n.file += 1;
                if (a.files[n.file].name.len > 0) return a.files[n.file].name;
            }
            return std.fmt.bufPrint(&n.buf, "stream/{d}", .{sub}) catch "stream";
        }
    };

    const Sink = union(enum) {
        /// Decode into a buffer (encoded headers); returns the bytes produced.
        buffer: []u8,
        /// Split into files and scan each.
        split: struct { sizes: []const u64, names: *Names },
    };

    /// Decode folder `fi` through its coder chain.
    fn decodeFolder(a: *Archive, fi: usize, sink: Sink) Error!usize {
        const w = a.w;
        const f = &a.folders[fi];
        const mark = w.scratch.mark();
        defer w.scratch.release(mark);
        if (f.too_complex or f.npacked != 1) return a.unsupported("7z: coder graph");
        // The packed stream's place in the file.
        var off: u64 = 32 + a.pack_pos;
        var p: u64 = 0;
        while (p < f.first_pack and p < a.npack) : (p += 1) off +|= a.pack_sizes[@intCast(p)];
        if (f.first_pack >= a.npack) return a.malformed("7z: packed stream missing");
        const packed_size = a.pack_sizes[@intCast(f.first_pack)];
        const total = a.src.len().?;
        if (off > total) return a.malformed("7z: packed stream outside the file");
        const data = a.src.slice(off, @min(packed_size, total - off)) catch return a.malformed("7z: packed stream outside the file");
        // Order the coders from the packed stream to the main output.
        var chain: [max_coders]u32 = undefined;
        var nchain: usize = 0;
        var in_idx = f.packed_in[0];
        while (nchain < f.ncoders) {
            const ci = coderOfIn(f, in_idx) orelse return a.malformed("7z: coder graph");
            const coder = f.coders[ci];
            if (coder.in_streams != 1 or coder.out_streams != 1) return a.unsupported("7z: coder graph");
            chain[nchain] = ci;
            nchain += 1;
            const out_idx = outIndex(f, ci);
            // The next coder is the one whose input is bound to this output.
            var next: ?u64 = null;
            for (f.binds[0..f.nbinds]) |b| if (b.out == out_idx) {
                next = b.in;
            };
            in_idx = next orelse break;
        }
        const sr_buf = w.alloc(u8, 16 * 1024) orelse return 0;
        const sr = w.scratch.allocator().create(container.SourceReader) catch return oom(w);
        sr.* = .init(w.io, data, sr_buf);
        var cur: *Io.Reader = &sr.interface;
        var dec: Decoders = .{};
        var tokens: [max_coders]?@import("../engine/budget.zig").Budget.Token = @splat(null);
        defer for (tokens) |t| if (t) |tok| tok.release();
        for (chain[0..nchain], 0..) |ci, k| {
            const coder = f.coders[ci];
            const out_size = f.unpack_sizes[@intCast(@min(outIndex(f, ci), f.nunpack -| 1))];
            cur = (try a.coderReader(&dec, coder, cur, out_size, &tokens[k])) orelse return 0;
        }
        const meter_buf = w.alloc(u8, container.block_len) orelse return 0;
        var meter: container.Meter = .init(w, cur, &sr.pulled, meter_buf);
        switch (sink) {
            .buffer => |out| {
                var n: usize = 0;
                while (n < out.len) {
                    const k = container.readSome(&meter.interface, out[n..]) catch break;
                    n += k;
                }
                if (dec.failed()) |why| w.notice(.malformed, why);
                return n;
            },
            .split => |s| {
                const head = w.alloc(u8, @import("detect.zig").head_len) orelse return 0;
                for (s.sizes, 0..) |size, k| {
                    var lim: Limited = .init(&meter.interface, size, head);
                    try w.child(s.names.next(s.names.first_sub + k), .{ .stream = .{ .reader = &lim.interface, .len_hint = size } }, .member);
                    try w.drain(&lim.interface);
                    if (meter.tripped != null) break;
                }
                if (meter.tripped == null) if (dec.failed()) |why| w.notice(.malformed, why);
                return 0;
            },
        }
    }

    fn coderReader(a: *Archive, dec: *Decoders, coder: Coder, in: *Io.Reader, out_size: u64, token: *?@import("../engine/budget.zig").Budget.Token) Error!?*Io.Reader {
        const w = a.w;
        const alloc = w.scratch.allocator();
        const buf = w.alloc(u8, 4096) orelse return null;
        switch (coder.method) {
            .copy => return in,
            .aes => {
                a.encrypted = true;
                w.notice(.encrypted, "7z: AES-256");
                return null;
            },
            .unsupported => {
                _ = try a.unsupported("7z: coder");
                return null;
            },
            .lzma => {
                if (coder.props_len < 5) return a.malformedNull("7z: LZMA properties");
                const header = lzma.Alone.parseHeader(coder.props[0..5]) catch return a.malformedNull("7z: LZMA properties");
                if (@as(u5, header.props.lc) + header.props.lp > 8) {
                    _ = try a.unsupported("7z: LZMA lc + lp over 8");
                    return null;
                }
                const dict_len: u64 = @max(@min(header.dict_size, out_size), 4096);
                const probs_len = header.props.probCount();
                token.* = w.window(dict_len, probs_len * 2) orelse return null;
                const dict_buf = w.alloc(u8, @intCast(dict_len)) orelse return null;
                const probs = w.alloc(u16, probs_len) orelse return null;
                const dict = alloc.create(lzma.Dict) catch return oomNull(w);
                dict.* = .{ .buf = dict_buf };
                const d = alloc.create(lzma.Alone) catch return oomNull(w);
                d.* = lzma.Alone.init(in, header, out_size, probs, dict, buf) catch return a.malformedNull("7z: LZMA stream");
                dec.lzma = d;
                return &d.interface;
            },
            .lzma2 => {
                if (coder.props_len < 1) return a.malformedNull("7z: LZMA2 properties");
                const declared = lzma.Lzma2.dictSize(coder.props[0]) catch return a.malformedNull("7z: LZMA2 properties");
                const dict_len: u64 = @max(@min(declared, out_size), 4096);
                token.* = w.window(dict_len, lzma.Lzma2.probs_len * 2) orelse return null;
                const dict_buf = w.alloc(u8, @intCast(dict_len)) orelse return null;
                const probs = w.alloc(u16, lzma.Lzma2.probs_len) orelse return null;
                const dict = alloc.create(lzma.Dict) catch return oomNull(w);
                dict.* = .{ .buf = dict_buf };
                const d = alloc.create(lzma.Lzma2) catch return oomNull(w);
                d.* = .init(in, probs, dict, buf);
                dec.lzma2 = d;
                return &d.interface;
            },
            .deflate => {
                const work = w.alloc(u8, inflate.work_len) orelse return null;
                const d = alloc.create(inflate.Inflate) catch return oomNull(w);
                d.* = .init(in, .raw, work);
                d.interface.buffer = buf;
                dec.inflate = d;
                return &d.interface;
            },
            .bzip2 => {
                const head = in.peek(4) catch return a.malformedNull("7z: BZip2 stream");
                const level = bzip2.Decoder.peekLevel(head) orelse return a.malformedNull("7z: BZip2 stream");
                token.* = w.window(bzip2.workingSet(level), 0) orelse return null;
                const tt = w.alloc(u32, @as(usize, level) * 100_000) orelse return null;
                const tables = alloc.create(bzip2.Decoder.TablesType) catch return oomNull(w);
                const d = alloc.create(bzip2.Decoder) catch return oomNull(w);
                d.* = bzip2.Decoder.init(in, tt, tables, buf) catch return a.malformedNull("7z: BZip2 stream");
                dec.bzip2 = d;
                return &d.interface;
            },
            .bcj_x86 => {
                const work = w.alloc(u8, 64 * 1024) orelse return null;
                const d = alloc.create(bcj.X86Reader) catch return oomNull(w);
                d.* = .init(in, work, buf);
                return &d.interface;
            },
        }
    }

    fn coderOfIn(f: *const Folder, in_idx: u64) ?u32 {
        var base: u64 = 0;
        for (f.coders[0..f.ncoders], 0..) |c, i| {
            if (in_idx >= base and in_idx < base + c.in_streams) return @intCast(i);
            base += c.in_streams;
        }
        return null;
    }

    fn outIndex(f: *const Folder, ci: u32) u64 {
        var base: u64 = 0;
        for (f.coders[0..ci]) |c| base += c.out_streams;
        return base;
    }

    fn unsupported(a: *Archive, detail: []const u8) Error!usize {
        if (!a.reported_unsupported) a.w.notice(.unsupported, detail);
        a.reported_unsupported = true;
        return 0;
    }

    fn malformed(a: *Archive, detail: []const u8) Error!usize {
        a.w.notice(.malformed, detail);
        return 0;
    }

    fn malformedNull(a: *Archive, detail: []const u8) ?*Io.Reader {
        a.w.notice(.malformed, detail);
        return null;
    }

    fn oom(w: *Walker) usize {
        w.limit(.memory);
        return 0;
    }

    fn oomNull(w: *Walker) ?*Io.Reader {
        w.limit(.memory);
        return null;
    }
};

const Decoders = struct {
    lzma: ?*lzma.Alone = null,
    lzma2: ?*lzma.Lzma2 = null,
    inflate: ?*inflate.Inflate = null,
    bzip2: ?*bzip2.Decoder = null,

    fn failed(d: *const Decoders) ?[]const u8 {
        if (d.lzma) |x| if (x.err != null) return "7z: LZMA stream";
        if (d.lzma2) |x| if (x.err != null) return "7z: LZMA2 stream";
        if (d.inflate) |x| if (x.err != null) return "7z: Deflate stream";
        if (d.bzip2) |x| if (x.err) |e| if (e != error.EndOfStream) return "7z: BZip2 stream";
        return null;
    }
};

/// At most `left` bytes of `in`.
const Limited = struct {
    in: *Io.Reader,
    left: u64,
    interface: Io.Reader,

    /// `buffer` lets the child peek its head for detection; it never holds bytes past `left`.
    fn init(in: *Io.Reader, left: u64, buffer: []u8) Limited {
        return .{ .in = in, .left = left, .interface = .{ .vtable = container.fillVTable(Limited), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(l: *Limited, dest: []u8) Io.Reader.Error!usize {
        if (l.left == 0) return 0;
        const want: usize = @intCast(@min(dest.len, l.left));
        const n = container.readSome(l.in, dest[0..want]) catch |e| switch (e) {
            error.EndOfStream => return 0,
            error.ReadFailed => return error.ReadFailed,
        };
        l.left -= n;
        return n;
    }
};

test "7z fixtures: LZMA, LZMA2, BCJ, Deflate, BZip2, Copy, encoded headers, solid folders" {
    try @import("pdf.zig").checkDocs(".7z");
}

test "7z numbers" {
    var c: Cursor = .{ .b = &.{ 0x7f, 0x80, 0x80, 0xc0, 0x01, 0x02, 0xff, 1, 2, 3, 4, 5, 6, 7, 8 } };
    try std.testing.expectEqual(@as(u64, 0x7f), try c.number());
    try std.testing.expectEqual(@as(u64, 0x80), try c.number());
    try std.testing.expectEqual(@as(u64, 0x0201), try c.number());
    try std.testing.expectEqual(@as(u64, 0x0807060504030201), try c.number());
}
