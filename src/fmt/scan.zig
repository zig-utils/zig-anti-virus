//! The format dispatcher: the `ParseFn` a `Walker` calls for every object. It detects the format
//! from the first bytes, hands the raw bytes to the visitor, and recurses into children.
//!
//! Positional sources are fed raw with positional reads, then parsed positionally (members of a
//! stored archive become slices, never copies). Streams are fed through a `Tee` while they are
//! parsed, so one pass both scans and parses them; a stream whose format needs random access is
//! materialised first (scratch up to 8 MiB, spill file beyond).
const std = @import("std");
const Io = std.Io;
const engine = struct {
    const container = @import("../engine/container.zig");
    const source = @import("../engine/source.zig");
};
const container = engine.container;
const Walker = container.Walker;
const Object = container.Object;
const Source = engine.source.Source;
const Error = container.Error;
const detect = @import("detect.zig");
const Format = detect.Format;
const decode = @import("decode.zig");
const archive = @import("archive.zig");
const tar = @import("tar.zig");
const cpio = @import("cpio.zig");
const zip = @import("zip.zig");
const pe = @import("pe.zig");
const elf = @import("elf.zig");
const macho = @import("macho.zig");
const html_norm = @import("html_norm.zig");
const text_norm = @import("text_norm.zig");

pub fn parse(w: *Walker, obj: *Object, src: Source) Error!void {
    switch (src) {
        .stream => |st| return parseStream(w, obj, st),
        else => return parsePositional(w, obj, src),
    }
}

fn parsePositional(w: *Walker, obj: *Object, src: Source) Error!void {
    var head: [detect.head_len]u8 = undefined;
    const n = src.readAt(w.io, 0, &head) catch 0;
    obj.format = detect.detect(head[0..n]);
    try w.begin(obj);
    try w.feedSource(obj, src);
    switch (obj.format) {
        .gzip, .bzip2, .xz, .zstd => {
            const buf = w.alloc(u8, container.block_len) orelse return;
            var sr: container.SourceReader = .init(w.io, src, buf);
            try decompress(w, obj, &sr.interface, &sr.pulled);
        },
        .tar => {
            var cursor: archive.Cursor = .{ .w = w, .positional = src };
            try tar.walk(w, &cursor);
        },
        .cpio => {
            var cursor: archive.Cursor = .{ .w = w, .positional = src };
            try cpio.walk(w, &cursor);
        },
        .zip => try zip.walk(w, src),
        .pe => try pe.walk(w, src),
        .elf => try elf.walk(w, src),
        .macho => try macho.walk(w, src),
        .macho_fat => try macho.walkFat(w, src),
        .html => try normalizeHtml(w, src),
        .binary, .text => {
            if (obj.format == .text) {
                const buf = w.alloc(u8, container.block_len) orelse return;
                var sr: container.SourceReader = .init(w.io, src, buf);
                try normalizeText(w, &sr.interface);
            }
            if (zip.hasTrailer(w, src)) {
                // Data with a zip appended (a self-extractor stub, a polyglot): walk the zip too.
                w.notice(.mismatch, "zip: archive appended to other data");
                try zip.walk(w, src);
            }
        },
    }
}

fn parseStream(w: *Walker, obj: *Object, st: Source.Stream) Error!void {
    const r = st.reader;
    r.fill(@min(detect.head_len, r.buffer.len)) catch |e| switch (e) {
        error.EndOfStream => {},
        error.ReadFailed => return if (w.halt != null) error.Halted else {},
    };
    obj.format = detect.detect(r.buffered());
    try w.begin(obj);
    const tee_buf = w.alloc(u8, container.block_len) orelse return w.drain(r);
    var tee: container.Tee = .init(w, obj, r, tee_buf);
    defer tee.interface = undefined;
    switch (obj.format) {
        .gzip, .bzip2, .xz, .zstd => try decompress(w, obj, &tee.interface, &tee.pulled),
        .tar => {
            var cursor: archive.Cursor = .{ .w = w, .reader = &tee.interface };
            try tar.walk(w, &cursor);
        },
        .cpio => {
            var cursor: archive.Cursor = .{ .w = w, .reader = &tee.interface };
            try cpio.walk(w, &cursor);
        },
        // Normalised text is produced in the same pass that feeds the raw bytes.
        .text => try normalizeText(w, &tee.interface),
        .zip, .pe, .elf, .macho, .macho_fat, .html => {
            var mat = try w.materialize(&tee.interface, st.len_hint) orelse return w.drain(&tee.interface);
            defer mat.deinit(w.io);
            try randomAccess(w, obj.format, mat.source);
        },
        else => {},
    }
    try w.drain(&tee.interface);
}

/// Formats parsed positionally, after a stream was materialised.
fn randomAccess(w: *Walker, format: Format, src: Source) Error!void {
    switch (format) {
        .zip => try zip.walk(w, src),
        .pe => try pe.walk(w, src),
        .elf => try elf.walk(w, src),
        .macho => try macho.walk(w, src),
        .macho_fat => try macho.walkFat(w, src),
        .html => try normalizeHtml(w, src),
        else => unreachable,
    }
}

/// The target type 7 stream of a text object, as a derived child named "text". Input past
/// MaxScriptNormalize is reported and left unnormalised (its raw bytes are still scanned).
fn normalizeText(w: *Walker, r: *Io.Reader) Error!void {
    var d: Object = undefined;
    try w.beginDerived(&d, "text", .normalized_text);
    defer w.endDerived(&d);
    const out = w.alloc(u8, container.block_len) orelse return;
    var n: text_norm.Normalizer = .{};
    var done: u64 = 0;
    const max = w.tracker.limits.max_script_normalize;
    while (true) {
        const chunk = r.peekGreedy(1) catch |e| switch (e) {
            error.EndOfStream => return,
            error.ReadFailed => return if (w.halt != null) error.Halted else {},
        };
        const take = @min(chunk.len, out.len, max -| done);
        if (take == 0) return w.limit(.script_normalize);
        try w.feed(&d, out[0..n.feed(chunk[0..take], out)]);
        r.toss(take);
        done += take;
    }
}

/// The target type 3 stream of an HTML object (derived child "html"), then each script body as
/// a derived child "script/<n>". Two passes over a positional source, bounded state, no
/// whole-document buffer; input past MaxHTMLNormalize is reported and left unnormalised.
fn normalizeHtml(w: *Walker, src: Source) Error!void {
    const buf = w.alloc(u8, container.block_len) orelse return;
    inline for (.{ html_norm.Mode.normalized, html_norm.Mode.scripts }) |mode| {
        var sink: HtmlSink = .{ .w = w, .mode = mode };
        defer sink.close();
        if (mode == .normalized) try w.beginDerived(&sink.obj, "html", .normalized_html);
        sink.open = mode == .normalized;
        var n = html_norm.Normalizer.init(mode, .{ .ctx = &sink, .write = HtmlSink.write, .boundary = HtmlSink.boundary });
        var off: u64 = 0;
        const total = src.len().?;
        const max = w.tracker.limits.max_html_normalize;
        var limited = false;
        while (off < total) {
            if (off >= max) {
                limited = true;
                break;
            }
            const want: usize = @intCast(@min(buf.len, max - off));
            const got = src.readAt(w.io, off, buf[0..want]) catch break;
            if (got == 0) break;
            n.feed(buf[0..got]) catch return sink.failure();
            off += got;
        }
        n.finish() catch return sink.failure();
        if (limited and mode == .normalized) w.limit(.html_normalize);
    }
}

const HtmlSink = struct {
    w: *Walker,
    mode: html_norm.Mode,
    obj: Object = undefined,
    open: bool = false,
    scripts: u32 = 0,
    name_buf: [24]u8 = undefined,

    fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const s: *HtmlSink = @ptrCast(@alignCast(ctx));
        if (!s.open) return;
        s.w.feed(&s.obj, bytes) catch return error.Stop;
    }

    fn boundary(ctx: *anyopaque, begin: bool) error{Stop}!void {
        const s: *HtmlSink = @ptrCast(@alignCast(ctx));
        if (begin) {
            const name = std.fmt.bufPrint(&s.name_buf, "script/{d}", .{s.scripts}) catch "script";
            s.scripts += 1;
            s.w.beginDerived(&s.obj, name, .script) catch return error.Stop;
            s.open = true;
        } else s.close();
    }

    fn close(s: *HtmlSink) void {
        if (!s.open) return;
        s.w.endDerived(&s.obj);
        s.open = false;
    }

    fn failure(s: *HtmlSink) Error {
        _ = s;
        return error.Halted;
    }
};

/// Name for a compression wrapper's output: the parent's name without its extension.
fn innerName(name: []const u8, format: Format) []const u8 {
    const exts: []const []const u8 = switch (format) {
        .gzip => &.{ ".gz", ".tgz", ".z" },
        .bzip2 => &.{ ".bz2", ".tbz2", ".tbz" },
        .xz => &.{ ".xz", ".txz" },
        .zstd => &.{ ".zst", ".zstd", ".tzst" },
        else => &.{},
    };
    const base = if (std.mem.lastIndexOfScalar(u8, name, '/')) |i| name[i + 1 ..] else name;
    for (exts) |e| {
        if (base.len > e.len and std.ascii.endsWithIgnoreCase(base, e)) {
            return base[0 .. base.len - e.len];
        }
    }
    return @tagName(format);
}

/// Decode a compression wrapper read from `in` and scan its output as one stream child.
fn decompress(w: *Walker, obj: *const Object, in: *Io.Reader, pulled: *const u64) Error!void {
    const codec: decode.Codec = switch (obj.format) {
        .gzip => .gzip,
        .bzip2 => .bzip2,
        .xz => .xz,
        .zstd => .zstd,
        else => unreachable,
    };
    try decode.childFrom(w, codec, in, pulled, innerName(obj.name, obj.format), null, .decompressed);
}

// ---------------------------------------------------------------------------------------------
// Test support: a walker over the real dispatcher with a recording visitor.

pub const TestRig = struct {
    scratch: @import("../engine/scratch.zig").Scratch,
    tracker: @import("../engine/limits.zig").Tracker,
    budget: @import("../engine/budget.zig").Budget,
    rec: container.Recorder,
    tmp: std.testing.TmpDir,
    walker: Walker,

    pub fn init(rig: *TestRig, lim: @import("../engine/limits.zig").Limits) !void {
        rig.scratch = try .init(64 * 1024 * 1024);
        rig.tracker = .init(lim);
        rig.budget = .init(64 * 1024 * 1024);
        rig.rec = .{ .gpa = std.testing.allocator };
        rig.tmp = std.testing.tmpDir(.{});
        rig.walker = .{
            .io = std.testing.io,
            .scratch = &rig.scratch,
            .tracker = &rig.tracker,
            .budget = &rig.budget,
            .spill_dir = rig.tmp.dir,
            .visitor = rig.rec.visitor(),
            .parse = parse,
            .options = .{ .budget_wait_ms = 1 },
        };
    }

    pub fn deinit(rig: *TestRig) void {
        rig.rec.deinit();
        rig.tmp.cleanup();
        rig.scratch.deinit();
    }

    /// Scan `bytes` as a memory source, and again as a forward-only stream.
    pub fn scanBoth(rig: *TestRig, bytes: []const u8, name: []const u8) !void {
        rig.walker.scan(.{ .memory = bytes }, name) catch |e| if (rig.walker.halt == null) return e;
        rig.tracker.reset();
        var r: Io.Reader = .fixed(bytes);
        rig.walker.scan(.{ .stream = .{ .reader = &r } }, name) catch |e| if (rig.walker.halt == null) return e;
    }
};

const fixtures = @import("fixtures/fixtures.zig");

test "every compression vector scans end to end, positional and streamed" {
    inline for (.{ "gzip", "bzip2", "xz", "zstd" }) |group| {
        for (@field(fixtures, group ++ "_vectors")) |v| {
            var rig: TestRig = undefined;
            try rig.init(.{});
            defer rig.deinit();
            const name = group ++ ".bin";
            try rig.scanBoth(v.compressed, name);
            const limited = std.mem.eql(u8, v.name, "dict-64m") or std.mem.eql(u8, v.name, "window-128m");
            const unsupported = std.mem.eql(u8, v.name, "bcj-x86");
            var children: usize = 0;
            for (rig.rec.objects.items) |e| {
                if (e.kind != .decompressed) continue;
                children += 1;
                try std.testing.expectEqualStrings(name ++ "/" ++ group, e.path);
                try std.testing.expectEqual(@as(u64, v.plain_len), e.bytes);
                try std.testing.expectEqual(v.plain_crc, e.crc);
            }
            if (limited) {
                try std.testing.expect(rig.rec.hasLimit(.window_size));
                try std.testing.expectEqual(@as(usize, 0), children);
            } else if (unsupported) {
                try std.testing.expect(rig.rec.has(.unsupported));
            } else {
                if (rig.rec.notices.items.len != 0) {
                    std.debug.print("{s} {s}:\n", .{ group, v.name });
                    rig.rec.dump();
                }
                try std.testing.expectEqual(@as(usize, 0), rig.rec.notices.items.len);
                try std.testing.expectEqual(@as(usize, 2), children);
            }
            try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
        }
    }
}

test "nested wrappers: a gzip stream inside a zstd frame" {
    // The zstd frame stores the gzip vector in one raw block, so the gzip decoder reads from
    // the zstd decoder's output stream.
    const gz = fixtures.gzip_vectors[0];
    var rig: TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    // A raw zstd frame of the gzip bytes, stored as one raw block (frame header with
    // single-segment content size, then a raw last block).
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;
    try frame.appendSlice(gpa, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x60 }); // FHD: single segment, 2-byte FCS
    var fcs: [2]u8 = undefined;
    std.mem.writeInt(u16, &fcs, @intCast(gz.compressed.len - 256), .little);
    try frame.appendSlice(gpa, &fcs);
    const bh: u24 = @intCast((gz.compressed.len << 3) | 1); // raw block, last
    var bhb: [3]u8 = undefined;
    std.mem.writeInt(u24, &bhb, bh, .little);
    try frame.appendSlice(gpa, &bhb);
    try frame.appendSlice(gpa, gz.compressed);
    try rig.scanBoth(frame.items, "x.tar.gz.zst");
    const inner = rig.rec.find("x.tar.gz.zst/x.tar.gz/x.tar") orelse {
        rig.rec.dump();
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u64, gz.plain_len), inner.bytes);
    try std.testing.expectEqual(@as(u8, 2), inner.depth);
}

test "a decompression bomb of each format stops at the ratio limit with an event" {
    for (fixtures.bomb_vectors) |v| {
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        rig.scanBoth(v.compressed, "bomb.bin") catch |e| {
            std.debug.print("bomb {s}: {t}\n", .{ v.name, e });
            return e;
        };
        try std.testing.expect(rig.rec.hasLimit(.ratio));
        // Stopped once output passed 100x the compressed bytes read (the whole small file is read
        // in the first block), not at 64 MiB.
        const bound = 100 * @max(v.compressed.len, 1024 * 1024 / 100) + 2 * container.block_len;
        for (rig.rec.objects.items) |e| if (e.kind == .decompressed) try std.testing.expect(e.bytes <= bound);
    }
}

test "archives: every tar, cpio and zip variant, positional and streamed" {
    for (fixtures.archives) |a| {
        if (std.mem.indexOf(u8, a.name, "bomb") != null) continue;
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(a.bytes, a.name);
        for (a.members) |m| {
            var path_buf: [2048]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ a.name, m.path });
            var seen: usize = 0;
            for (rig.rec.objects.items) |e| if (std.mem.eql(u8, e.path, path)) {
                seen += 1;
                std.testing.expectEqual(@as(u64, m.len), e.bytes) catch |err| {
                    std.debug.print("{s}: {s}\n", .{ a.name, path });
                    return err;
                };
                try std.testing.expectEqual(m.crc, e.crc);
            };
            // Appended zips are found by their trailer, which only positional sources can reach.
            const want: usize = if (std.mem.eql(u8, a.name, "sfx.zip")) 1 else 2;
            if (seen != want) {
                std.debug.print("{s}: member {s} seen {d} times\n", .{ a.name, path, seen });
                rig.rec.dump();
                return error.TestUnexpectedResult;
            }
        }
        if (a.malformed != rig.rec.has(.malformed)) {
            std.debug.print("{s}: malformed expected {}\n", .{ a.name, a.malformed });
            rig.rec.dump();
            return error.TestUnexpectedResult;
        }
        const Expect = struct { name: []const u8, what: std.meta.Tag(container.Notice.What) };
        for ([_]Expect{
            .{ .name = "hidden-entry.zip", .what = .mismatch },
            .{ .name = "method-mismatch.zip", .what = .mismatch },
            .{ .name = "encrypted.zip", .what = .encrypted },
            .{ .name = "deflate64.zip", .what = .unsupported },
        }) |x| if (std.mem.eql(u8, a.name, x.name) and !rig.rec.has(x.what)) {
            std.debug.print("{s}: expected a {t} notice\n", .{ a.name, x.what });
            rig.rec.dump();
            return error.TestUnexpectedResult;
        };
        if (std.mem.eql(u8, a.name, "encrypted.zip")) try std.testing.expect(rig.rec.find("encrypted.zip/secret.bin") == null);
        try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
    }
}

test "overlapping-entry zip bombs are reported and bounded" {
    for (fixtures.archives) |a| {
        if (std.mem.indexOf(u8, a.name, "bomb.zip") == null) continue;
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(a.bytes, a.name);
        try std.testing.expect(rig.rec.has(.overlap));
        var members: usize = 0;
        var bytes: u64 = 0;
        for (rig.rec.objects.items) |e| if (e.depth == 1) {
            members += 1;
            bytes += e.bytes;
        };
        // One entry per scan decoded (the rest share its bytes), and that one stopped by the
        // ratio guard: nowhere near the 2 GB and 8 GB the entries claim.
        try std.testing.expectEqual(@as(usize, 2), members);
        try std.testing.expect(bytes < 16 * 1024 * 1024);
    }
}

test "executables: children from overlays and resources, positional and streamed" {
    for (fixtures.exes) |e| {
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        try rig.scanBoth(e.bytes, e.name);
        for (e.members) |m| {
            var path_buf: [2048]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ e.name, m.path });
            var seen: usize = 0;
            for (rig.rec.objects.items) |o| if (std.mem.eql(u8, o.path, path)) {
                seen += 1;
                try std.testing.expectEqual(@as(u64, m.len), o.bytes);
                try std.testing.expectEqual(m.crc, o.crc);
            };
            if (seen != 2) {
                std.debug.print("{s}: {s} seen {d} times\n", .{ e.name, path, seen });
                rig.rec.dump();
                return error.TestUnexpectedResult;
            }
        }
        if (e.malformed != rig.rec.has(.malformed)) {
            std.debug.print("{s}: malformed expected {}\n", .{ e.name, e.malformed });
            rig.rec.dump();
            return error.TestUnexpectedResult;
        }
    }
}

test "HTML yields its normalised stream and scripts; text yields its normalised stream" {
    const page = "<HTML><Body>Hello   <B>World</B><!-- x --><script>Alert(1)</script></body></HTML>\n";
    var rig: TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(page, "p.html");
    const norm = "<html><body>hello <b>world</b><script>alert(1)</script></body></html> ";
    var hasher = std.hash.Crc32.init();
    hasher.update(norm);
    var seen: usize = 0;
    for (rig.rec.objects.items) |e| {
        if (std.mem.eql(u8, e.path, "p.html/html")) {
            seen += 1;
            try std.testing.expectEqual(container.Kind.normalized_html, e.kind);
            try std.testing.expectEqual(@as(u64, norm.len), e.bytes);
            try std.testing.expectEqual(hasher.final(), e.crc);
        }
        if (std.mem.eql(u8, e.path, "p.html/script/0")) {
            seen += 1;
            try std.testing.expectEqual(@as(u64, "Alert(1)".len), e.bytes);
        }
    }
    try std.testing.expectEqual(@as(usize, 4), seen);

    var rig2: TestRig = undefined;
    try rig2.init(.{});
    defer rig2.deinit();
    try rig2.scanBoth("Plain  TEXT\twith\r\nLines\n", "t.txt");
    var texts: usize = 0;
    for (rig2.rec.objects.items) |e| if (std.mem.eql(u8, e.path, "t.txt/text")) {
        texts += 1;
        try std.testing.expectEqual(@as(u64, "plain text with lines ".len), e.bytes);
    };
    try std.testing.expectEqual(@as(usize, 2), texts);
}

test "normaliser limits are reported" {
    var rig: TestRig = undefined;
    try rig.init(.{ .max_html_normalize = 10, .max_script_normalize = 5 });
    defer rig.deinit();
    try rig.walker.scan(.{ .memory = "<html><body>a long enough page</body></html>" }, "p.html");
    try std.testing.expect(rig.rec.hasLimit(.html_normalize));
    try rig.walker.scan(.{ .memory = "some longer text" }, "t.txt");
    try std.testing.expect(rig.rec.hasLimit(.script_normalize));
}
