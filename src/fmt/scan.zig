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
const ole2 = @import("ole2.zig");
const iso9660 = @import("iso9660.zig");
const cab = @import("cab.zig");
const dmg = @import("dmg.zig");
const nsis = @import("nsis.zig");
const chm = @import("chm.zig");
const mime = @import("mime.zig");
const pdf = @import("pdf.zig");
const rtf = @import("rtf.zig");
const sevenzip = @import("sevenzip.zig");
const upx = @import("unpack/upx.zig");
const html_norm = @import("html_norm.zig");
const js_norm = @import("js_norm.zig");
const text_norm = @import("text_norm.zig");
const js_file = @import("js_file.zig");
const heuristics = @import("../engine/heuristics.zig");
const ftm = @import("ftm.zig");
const types = @import("types.zig");
const vm = @import("../match/verify_vm.zig");

pub fn parse(w: *Walker, obj: *Object, src: Source) Error!void {
    switch (src) {
        .stream => |st| return parseStream(w, obj, st),
        else => return parsePositional(w, obj, src),
    }
}

fn parsePositional(w: *Walker, obj: *Object, src: Source) Error!void {
    var head: [detect.head_len]u8 = undefined;
    const n = src.readAt(w.io, 0, &head) catch 0;
    obj.format = retype(w, obj, head[0..n], deepPositional(w, src, detect.detect(head[0..n])));
    try w.begin(obj);
    try w.feedSource(obj, src);
    checkName(w, obj);
    checkEntropy(w, obj.format, src);
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
        .pe => {
            try pe.walk(w, src);
            try upx.walk(w, src, .pe);
        },
        .elf => {
            try elf.walk(w, src);
            try upx.walk(w, src, .elf);
        },
        .macho => {
            try macho.walk(w, src);
            try upx.walk(w, src, .macho);
        },
        .macho_fat => try macho.walkFat(w, src),
        .ole2 => try ole2.walk(w, src),
        .iso9660 => try iso9660.walk(w, src),
        .cab => try cab.walk(w, src),
        .dmg => try dmg.walk(w, src),
        .nsis => try nsis.walk(w, src),
        .chm => try chm.walk(w, src),
        .mail => try mime.walk(w, src),
        .pdf => try pdf.walk(w, src),
        .sevenzip => try sevenzip.walk(w, src),
        .rtf => {
            const buf = w.alloc(u8, container.block_len) orelse return;
            var sr: container.SourceReader = .init(w.io, src, buf);
            try rtf.walk(w, &sr.interface);
        },
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
    if (obj.kind == .script and (obj.format == .text or obj.format == .binary or obj.format == .html)) try normalizeJs(w, src);
}

/// The normalised JavaScript of an extracted script (a PDF /JS value), as a derived child "js".
/// Input past MaxScriptNormalize is reported and left unnormalised.
fn normalizeJs(w: *Walker, src: Source) Error!void {
    const total = src.len() orelse return;
    const j = w.scratch.allocator().create(js_norm.Normalizer) catch return w.limit(.memory);
    const buf = w.alloc(u8, container.block_len) orelse return;
    var sink: JsSink = .{ .w = w };
    try w.beginDerived(&sink.obj, "js", .normalized_js);
    defer w.endDerived(&sink.obj);
    j.* = .init(.{ .ctx = &sink, .write = JsSink.write });
    const max = w.tracker.limits.max_script_normalize;
    var off: u64 = 0;
    while (off < total) {
        if (off >= max) {
            w.limit(.script_normalize);
            break;
        }
        const want: usize = @intCast(@min(buf.len, max - off));
        const got = src.readAt(w.io, off, buf[0..want]) catch break;
        if (got == 0) break;
        j.feed(buf[0..got]) catch return error.Halted;
        off += got;
    }
    j.finish() catch return error.Halted;
}

const JsSink = struct {
    w: *Walker,
    obj: Object = undefined,

    fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const s: *JsSink = @ptrCast(@alignCast(ctx));
        s.w.feed(&s.obj, bytes) catch return error.Stop;
    }
};

fn parseStream(w: *Walker, obj: *Object, st: Source.Stream) Error!void {
    const r = st.reader;
    r.fill(@min(detect.head_len, r.buffer.len)) catch |e| switch (e) {
        error.EndOfStream => {},
        error.ReadFailed => return if (w.halt != null) error.Halted else {},
    };
    obj.format = detect.detect(r.buffered());
    if (obj.format == .binary) obj.format = deepStream(r);
    obj.format = retype(w, obj, r.buffered(), obj.format);
    try w.begin(obj);
    checkName(w, obj);
    const tee_buf = w.alloc(u8, container.block_len) orelse return w.drain(r);
    var tee: container.Tee = .init(w, obj, r, tee_buf);
    defer tee.interface = undefined;
    if (obj.kind == .script and (obj.format == .text or obj.format == .binary or obj.format == .html)) {
        // An extracted script gets its text or HTML stream and its normalised JavaScript: two
        // passes, so it is materialised first (scripts are bounded by MaxScriptNormalize).
        var mat = try w.materialize(&tee.interface, st.len_hint) orelse return w.drain(&tee.interface);
        defer mat.deinit(w.io);
        try w.drain(&tee.interface);
        switch (obj.format) {
            .text => {
                const buf = w.alloc(u8, container.block_len) orelse return;
                var sr: container.SourceReader = .init(w.io, mat.source, buf);
                try normalizeText(w, &sr.interface);
            },
            .html => try normalizeHtml(w, mat.source),
            else => {},
        }
        return normalizeJs(w, mat.source);
    }
    switch (obj.format) {
        .gzip, .bzip2, .xz, .zstd => try decompress(w, obj, &tee.interface, &tee.pulled),
        .tar => {
            var cursor: archive.Cursor = .{ .w = w, .reader = &tee.interface, .container_size = st.len_hint };
            try tar.walk(w, &cursor);
        },
        .cpio => {
            var cursor: archive.Cursor = .{ .w = w, .reader = &tee.interface, .container_size = st.len_hint };
            try cpio.walk(w, &cursor);
        },
        // Normalised text is produced in the same pass that feeds the raw bytes.
        .text => try normalizeText(w, &tee.interface),
        .rtf => try rtf.walk(w, &tee.interface),
        .zip, .pe, .elf, .macho, .macho_fat, .ole2, .iso9660, .cab, .dmg, .nsis, .chm, .mail, .pdf, .sevenzip, .html => {
            var mat = try w.materialize(&tee.interface, st.len_hint) orelse return w.drain(&tee.interface);
            defer mat.deinit(w.io);
            checkEntropy(w, obj.format, mat.source);
            try randomAccess(w, obj.format, mat.source);
        },
        else => {},
    }
    try w.drain(&tee.interface);
}

/// Re-typing by the database's type magics (fmt/ftm.zig): text and binary data that clamscan
/// types as HTML, mail or PDF from the magics in their head are parsed as such.
fn retype(w: *Walker, obj: *Object, head: []const u8, f: Format) Format {
    _ = obj;
    if (f != .binary and f != .text) return f;
    const magics = w.options.types orelse return f;
    var budget: vm.Budget = .{};
    const c = ftm.classify(magics.*, head, .{ .file_size = std.math.maxInt(u64) }, &budget);
    return switch (c.type) {
        .html => .html,
        .mail => .mail,
        .pdf => .pdf,
        else => f,
    };
}

/// Formats recognised past the detection head, for positional sources: ISO 9660 by its volume
/// descriptor (`detect.detectDeep`), and disk images by their trailer. A disk image's data fork
/// starts with its first chunk, so its head can look like raw data or a compression wrapper.
fn deepPositional(w: *Walker, src: Source, head_format: Format) Format {
    switch (head_format) {
        .binary, .gzip, .bzip2, .xz, .zstd => {},
        else => return head_format,
    }
    if (dmg.hasTrailer(w, src)) return .dmg;
    if (head_format != .binary) return head_format;
    var probe: [detect.deep_probe_end - detect.deep_probe_off]u8 = undefined;
    src.readAllAt(w.io, detect.deep_probe_off, &probe) catch return .binary;
    return detect.detectDeep(&probe) orelse .binary;
}

/// The same for a stream, when its buffer can hold the probe without consuming anything.
fn deepStream(r: *Io.Reader) Format {
    if (r.buffer.len < detect.deep_probe_end) return .binary;
    r.fill(detect.deep_probe_end) catch return .binary;
    return detect.detectDeep(r.buffered()[detect.deep_probe_off..detect.deep_probe_end]) orelse .binary;
}

/// Heuristics.Guardian.ExtensionMismatch: a document, image or text name on an executable.
fn checkName(w: *Walker, obj: *const Object) void {
    if (heuristics.extensionMismatch(obj.name, obj.format) != null) heuristics.report(w, .extension_mismatch);
}

/// Heuristics.Guardian.HighEntropy: both ends of an executable (or of anything, in a risky
/// context) look random.
fn checkEntropy(w: *Walker, format: Format, src: Source) void {
    const cfg = w.options.heuristics orelse return;
    if (!cfg.wants(.high_entropy) or !(cfg.risky or heuristics.isExecutable(format))) return;
    const total = src.len() orelse return;
    const block = cfg.entropy_block;
    if (total < 2 * block) return;
    const buf = w.alloc(u8, 2 * block) orelse return;
    defer w.free(buf);
    src.readAllAt(w.io, 0, buf[0..block]) catch return;
    src.readAllAt(w.io, total - block, buf[block..]) catch return;
    if (heuristics.highEntropy(buf[0..block], buf[block..], cfg)) heuristics.report(w, .high_entropy);
}

fn reportScript(w: *Walker, s: *const heuristics.ScriptScanner) void {
    const found = s.finish();
    var it = found.iterator();
    while (it.next()) |id| heuristics.report(w, id);
}

/// Formats parsed positionally, after a stream was materialised.
fn randomAccess(w: *Walker, format: Format, src: Source) Error!void {
    switch (format) {
        .zip => try zip.walk(w, src),
        .pe => {
            try pe.walk(w, src);
            try upx.walk(w, src, .pe);
        },
        .elf => {
            try elf.walk(w, src);
            try upx.walk(w, src, .elf);
        },
        .macho => {
            try macho.walk(w, src);
            try upx.walk(w, src, .macho);
        },
        .macho_fat => try macho.walkFat(w, src),
        .ole2 => try ole2.walk(w, src),
        .iso9660 => try iso9660.walk(w, src),
        .cab => try cab.walk(w, src),
        .dmg => try dmg.walk(w, src),
        .nsis => try nsis.walk(w, src),
        .chm => try chm.walk(w, src),
        .mail => try mime.walk(w, src),
        .pdf => try pdf.walk(w, src),
        .sevenzip => try sevenzip.walk(w, src),
        .html => try normalizeHtml(w, src),
        else => unreachable,
    }
}

/// The target type 7 stream of a text object, as a derived child named "text". Input past
/// MaxScriptNormalize is reported and left unnormalised (its raw bytes are still scanned).
fn normalizeText(w: *Walker, r: *Io.Reader) Error!void {
    const buf = w.alloc(u8, container.block_len) orelse return w.drain(r);
    defer w.free(buf);
    var d: Object = undefined;
    try w.beginDerived(&d, "text", .normalized_text);
    defer w.endDerived(&d);
    var n: text_norm.Normalizer = .{ .seams = .{ .pages = .{ .page = @intCast(std.heap.pageSize()) } } };
    var markers: heuristics.ScriptScanner = .{};
    const max = w.tracker.limits.max_script_normalize;
    var total: u64 = 0;
    while (true) {
        const want = @min(buf.len / 2, max - @min(max, total));
        if (want == 0) {
            w.limit(.script_normalize);
            return w.drain(r);
        }
        const got = r.readSliceShort(buf[0..want]) catch |e| switch (e) {
            error.ReadFailed => return if (w.halt != null) error.Halted else {},
        };
        if (got == 0) return reportScript(w, &markers);
        total += got;
        if (w.options.heuristics != null) markers.update(buf[0..got]);
        const out = buf[want..][0..got];
        const len = n.feed(buf[0..got], out);
        try w.feed(&d, out[0..len]);
    }
}

/// The target type 3 streams of an HTML object, as derived children: "nocomment" and "notags"
/// (normalized_html) and "js", the JavaScript file of its scripts (normalized_js). Input past
/// MaxHTMLNormalize is reported and left out; a notags form over MaxHTMLNoTags too.
fn normalizeHtml(w: *Walker, src: Source) Error!void {
    const total = src.len() orelse return;
    const Pass = enum { nocomment, notags, js };
    const norm = w.scratch.allocator().create(html_norm.Normalizer) catch return w.limit(.memory);
    const buf = w.alloc(u8, container.block_len) orelse return;
    defer w.free(buf);
    const max = w.tracker.limits.max_html_normalize;
    for ([_]Pass{ .nocomment, .notags, .js }) |pass| {
        var sink: HtmlSink = .{ .w = w };
        const kind: container.Kind = if (pass == .js) .normalized_js else .normalized_html;
        try w.beginDerived(&sink.obj, @tagName(pass), kind);
        defer w.endDerived(&sink.obj);
        const out: html_norm.Output = .{ .ctx = &sink, .write = HtmlSink.write };
        var js: js_file.JavascriptFile = .{ .out = out };
        norm.* = .init(switch (pass) {
            .nocomment => .{ .nocomment = out },
            .notags => .{ .notags = out },
            .js => .{ .scripts = js.pieces() },
        });
        var markers: heuristics.ScriptScanner = .{};
        var off: u64 = 0;
        while (off < total and off < max) {
            const want: usize = @intCast(@min(buf.len, max - off, total - off));
            const got = src.readAt(w.io, off, buf[0..want]) catch break;
            if (got == 0) break;
            if (pass == .nocomment and w.options.heuristics != null) markers.update(buf[0..got]);
            norm.feed(buf[0..got]) catch break;
            off += got;
        }
        norm.finish() catch {};
        if (pass == .nocomment and w.options.heuristics != null) reportScript(w, &markers);
        if (sink.halted) return error.Halted;
        if (pass == .nocomment and total > max) w.limit(.html_normalize);
        if (pass == .notags and sink.bytes > w.tracker.limits.max_html_notags) w.limit(.html_notags);
    }
}

const HtmlSink = struct {
    w: *Walker,
    obj: Object = undefined,
    bytes: u64 = 0,
    halted: bool = false,

    fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const s: *HtmlSink = @ptrCast(@alignCast(ctx));
        s.bytes += bytes.len;
        if (s.bytes > s.w.tracker.limits.max_html_notags and s.obj.kind == .normalized_html and std.mem.eql(u8, s.obj.name, "notags")) return error.Stop;
        s.w.feed(&s.obj, bytes) catch {
            s.halted = true;
            return error.Stop;
        };
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
            // Appended zips and disk images are found by their trailers, which only positional
            // sources can reach.
            const want: usize = if (std.mem.eql(u8, a.name, "sfx.zip") or std.mem.endsWith(u8, a.name, ".dmg")) 1 else 2;
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
            .{ .name = "macro.docm", .what = .macros },
            .{ .name = "macro.docm", .what = .external },
            .{ .name = "macro.docm", .what = .embedded },
            .{ .name = "quantum.cab", .what = .unsupported },
            .{ .name = "overlap.cab", .what = .overlap },
            .{ .name = "dupes.chm", .what = .overlap },
        }) |x| if (std.mem.eql(u8, a.name, x.name) and !rig.rec.has(x.what)) {
            std.debug.print("{s}: expected a {t} notice\n", .{ a.name, x.what });
            rig.rec.dump();
            return error.TestUnexpectedResult;
        };
        if (std.mem.eql(u8, a.name, "encrypted.zip")) try std.testing.expect(rig.rec.find("encrypted.zip/secret.bin") == null);
        if (std.mem.eql(u8, a.name, "plain.docx")) try std.testing.expect(!rig.rec.has(.macros) and !rig.rec.has(.external));
        try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
    }
}

test "overlapping-entry zip bombs are reported and bounded" {
    for (fixtures.archives) |a| {
        if (std.mem.indexOf(u8, a.name, "overlap-bomb") == null and std.mem.indexOf(u8, a.name, "entry-bomb") == null) continue;
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

test "heuristics: each one fires on its positive fixture, and only when enabled" {
    const H = heuristics.Id;
    const Case = struct { name: []const u8, bytes: []const u8, id: H };
    var rnd: [16384]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(5);
    prng.random().bytes(&rnd);
    // A PE header in front of random data: packed-looking at both ends.
    var packed_pe: [16384]u8 = rnd;
    @memcpy(packed_pe[0..2], "MZ");
    const evil_js = "var p = 'x'; eval(atob('YWxlcnQoMSk=')); eval(unescape('%61%6c%65%72%74'));";
    const page = "<html><script>" ++ evil_js ++ "</script></html>";
    const exe = struct {
        fn find(name: []const u8) []const u8 {
            for (fixtures.exes) |e| if (std.mem.eql(u8, e.name, name)) return e.bytes;
            unreachable;
        }
    }.find;
    const cases = [_]Case{
        .{ .name = "pe-ep-outside.exe", .bytes = exe("pe-ep-outside.exe"), .id = .pe_entry_outside_sections },
        .{ .name = "pe-wx.exe", .bytes = exe("pe-wx.exe"), .id = .pe_write_exec_section },
        .{ .name = "pe-overlap.exe", .bytes = exe("pe-overlap.exe"), .id = .pe_overlapping_sections },
        .{ .name = "ep-outside.elf", .bytes = exe("ep-outside.elf"), .id = .elf_entry_outside_segments },
        .{ .name = "wx.elf", .bytes = exe("wx.elf"), .id = .elf_write_exec_segment },
        .{ .name = "ep-outside.macho", .bytes = exe("ep-outside.macho"), .id = .macho_entry_outside_segments },
        .{ .name = "wx.macho", .bytes = exe("wx.macho"), .id = .macho_write_exec_segment },
        .{ .name = "invoice.pdf", .bytes = exe("pe32.exe"), .id = .extension_mismatch },
        .{ .name = "packed.bin", .bytes = &packed_pe, .id = .high_entropy },
        .{ .name = "page.html", .bytes = page, .id = .script_eval_chain },
    };
    for (cases) |case| {
        for ([_]bool{ true, false }) |enabled| {
            var cfg: heuristics.Config = .{ .min_severity = .low };
            if (!enabled) cfg.disabled.insert(case.id);
            var rig: TestRig = undefined;
            try rig.init(.{});
            defer rig.deinit();
            rig.walker.options.heuristics = &cfg;
            try rig.scanBoth(case.bytes, case.name);
            var fired = false;
            for (rig.rec.notices.items) |nt| {
                if (nt.what == .heuristic and std.mem.eql(u8, nt.detail, case.id.name())) fired = true;
            }
            if (fired != enabled) {
                std.debug.print("{s}: {s} fired={} enabled={}\n", .{ case.name, case.id.name(), fired, enabled });
                rig.rec.dump();
                return error.TestUnexpectedResult;
            }
        }
    }
    // Clean fixtures raise nothing at the default (medium) severity.
    for ([_][]const u8{ "pe32.exe", "pe64.exe", "x86_64.elf", "x86_64-main.macho", "universal.fat" }) |name| {
        var cfg: heuristics.Config = .{};
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        rig.walker.options.heuristics = &cfg;
        try rig.scanBoth(exe(name), name);
        try std.testing.expect(!rig.rec.has(.heuristic));
    }
}

test "container metadata (.cdb) signatures fire on zip members, filename regex included" {
    const gpa = std.testing.allocator;
    const ir = @import("../compile/ir.zig");
    const cdb = @import("../compile/cdb.zig");
    const cdb_match = @import("../match/container.zig");
    const regex_pool = @import("../match/regex_pool.zig");
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var column: u32 = 0;
    const rules = [_]ir.CdbRule{
        // The third member, stored: 68 bytes in and out, its CRC, not encrypted.
        try cdb.parseLine(arena, "Zip.Eicar.Meta-1-0:CL_TYPE_ZIP:*:eicar\\.com$:68:68:0:3:6851cf3c:*", &column),
        try cdb.parseLine(arena, "Zip.Encrypted-2-0:CL_TYPE_ZIP:*:^secret:*:*:1:*:*:*", &column),
        // tar and cpio: the third file, by type and position; the cpio CRC variant is its own type.
        try cdb.parseLine(arena, "Tar.Eicar-3-0:CL_TYPE_POSIX_TAR:*:eicar\\.com$:68:68:0:3:*:*", &column),
        try cdb.parseLine(arena, "Cpio.Bin-4-0:CL_TYPE_CPIO_NEWC:*:^b\\.bin$:3000:*:*:2:*:*", &column),
        // Needs the container's size, which a stream does not carry: decided on positional scans.
        try cdb.parseLine(arena, "Cpio.Sized-5-0:CL_TYPE_CPIO_CRC:1-100000:*:68:*:*:*:*:*", &column),
    };
    const pool_bytes = try regex_pool.build(arena, &.{ rules[0].filename_program.?, rules[1].filename_program.?, rules[2].filename_program.?, rules[3].filename_program.? });
    const pool_image = try arena.alignedAlloc(u8, .@"8", pool_bytes.len);
    @memcpy(pool_image, pool_bytes);
    const pool = try regex_pool.RegexPool.init(pool_image);
    const table_bytes = try cdb_match.build(arena, &rules, &.{ 1, 2, 3, 4, 5 }, &.{ 0, 1, 2, 3, null });
    const table_image = try arena.alignedAlloc(u8, .@"8", table_bytes.len);
    @memcpy(table_image, table_bytes);
    const mem = try arena.alignedAlloc(u8, .@"8", pool.scratchBytes(64));
    var scratch = try regex_pool.Scratch.initBuffer(mem, pool, 64);
    const hook: container.CdbHook = .{ .table = try cdb_match.CdbTable.init(table_image, pool), .scratch = &scratch };

    const Case = struct { []const u8, ?u32, []const u8 };
    for ([_]Case{
        .{ "stored.zip", 1, "stored.zip/eicar.com" },
        .{ "deflate.zip", null, "" }, // compressed: the stored size differs
        .{ "encrypted.zip", 2, "encrypted.zip/secret.bin" },
        .{ "ustar.tar", 3, "ustar.tar/eicar.com" },
        .{ "newc.cpio", 4, "newc.cpio/b.bin" },
        .{ "crc.cpio", 5, "crc.cpio/eicar.com" },
    }) |c| {
        const a = for (fixtures.archives) |x| {
            if (std.mem.eql(u8, x.name, c[0])) break x;
        } else unreachable;
        var rig: TestRig = undefined;
        try rig.init(.{});
        defer rig.deinit();
        rig.walker.options.cdb = &hook;
        try rig.scanBoth(a.bytes, a.name);
        var hit: ?u32 = null;
        for (rig.rec.notices.items) |n| if (n.what == .container_signature) {
            hit = n.what.container_signature;
            try std.testing.expectEqualStrings(c[2], n.path);
        };
        try std.testing.expectEqual(c[1], hit);
        // The streamed pass cannot tell the cpio's size: that record is reported undecided.
        if (std.mem.eql(u8, c[0], "crc.cpio")) try std.testing.expect(rig.rec.hasLimit(.container_size_unknown));
    }
}
