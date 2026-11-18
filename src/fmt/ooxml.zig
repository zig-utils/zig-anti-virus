//! Office Open XML (ECMA-376 part 2, Open Packaging Conventions) on top of the zip parser. Every
//! part is scanned as an ordinary zip member, so vbaProject.bin reaches the OLE2 parser by its
//! magic like any other member. This layer reads the package's small XML parts with zig-xml's
//! incremental tokenizer and reports what they declare:
//!
//! - `[Content_Types].xml` with a macro-enabled main part or a vbaProject content type: the
//!   `macros` notice (docm, xlsm, pptm and friends);
//! - relationships (`*.rels`) whose TargetMode is External, other than plain hyperlinks: the
//!   `external` notice with the target (remote templates, OLE links, frames, remote images);
//!   relationships to embedded objects, packages or a VBA project: the `embedded` notice.
//!
//! Parts are read with a bounded window (16 KiB) and at most `max_part` decompressed bytes.
const std = @import("std");
const Io = std.Io;
const xml = @import("xml");
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;

pub const max_part: u64 = 4 * 1024 * 1024;
const window: usize = 16 * 1024;

pub const Part = enum { content_types, relationships, other };

pub fn classify(name: []const u8) Part {
    if (std.ascii.eqlIgnoreCase(name, "[Content_Types].xml")) return .content_types;
    if (std.ascii.endsWithIgnoreCase(name, ".rels")) return .relationships;
    return .other;
}

/// Inspect one package part. `data` is the member's stored bytes, `method` its zip method
/// (store and deflate are the only ones OPC allows). Findings are notices at the part's path.
pub fn inspect(w: *Walker, name: []const u8, data: Source, method: u16, size: u64) void {
    const kind = classify(name);
    if (kind == .other or size > max_part) return;
    if (method != 0 and method != 8) return;
    const mark = w.scratch.mark();
    defer w.scratch.release(mark);
    const in_buf = w.alloc(u8, container.block_len) orelse return;
    var sr: container.SourceReader = .init(w.io, data, in_buf);
    var reader: *Io.Reader = &sr.interface;
    var inflate: std.compress.flate.Decompress = undefined;
    var limited_buf: [4096]u8 = undefined;
    var limited: Io.Reader.Limited = undefined;
    if (method == 8) {
        const win = w.alloc(u8, std.compress.flate.max_window_len) orelse return;
        inflate = .init(reader, .raw, win);
        reader = &inflate.reader;
    }
    limited = reader.limited(.limited64(max_part), &limited_buf);
    var tok = xml.Reader.initStream(w.scratch.allocator(), &limited.interface, .{ .buffer_size = window }) catch return;
    w.path.push(name);
    defer w.path.pop();
    var flagged_macros = false;
    while (true) {
        const ev = tok.next() catch |e| {
            if (e != error.ReadFailed) w.notice(.malformed, "ooxml: xml part");
            return;
        } orelse return;
        const el = switch (ev) {
            .open, .self_closing => |el| el,
            else => continue,
        };
        switch (kind) {
            .content_types => {
                const ct = el.attribute("ContentType") orelse continue;
                if (!flagged_macros and isMacroContentType(ct)) {
                    w.notice(.macros, ct);
                    flagged_macros = true;
                }
            },
            .relationships => {
                if (!std.mem.eql(u8, localName(el.name), "Relationship")) continue;
                const target = el.attribute("Target") orelse "";
                const rtype = el.attribute("Type") orelse "";
                // External targets the application loads (templates, OLE links, frames,
                // remote images); plain hyperlinks only open when clicked and are common.
                if (el.attribute("TargetMode")) |mode| {
                    if (std.ascii.eqlIgnoreCase(mode, "External") and !std.mem.endsWith(u8, rtype, "/hyperlink"))
                        w.notice(.external, target[0..@min(target.len, 512)]);
                }
                if (std.mem.endsWith(u8, rtype, "/oleObject") or std.mem.endsWith(u8, rtype, "/package") or
                    std.mem.endsWith(u8, rtype, "/attachedTemplate") or std.mem.endsWith(u8, rtype, "/vbaProject"))
                {
                    w.notice(.embedded, target[0..@min(target.len, 512)]);
                }
            },
            .other => unreachable,
        }
    }
}

fn localName(name: []const u8) []const u8 {
    return if (std.mem.lastIndexOfScalar(u8, name, ':')) |i| name[i + 1 ..] else name;
}

pub fn isMacroContentType(ct: []const u8) bool {
    return std.ascii.findIgnoreCase(ct, "macroEnabled") != null or
        std.ascii.eqlIgnoreCase(ct, "application/vnd.ms-office.vbaProject") or
        std.ascii.eqlIgnoreCase(ct, "application/vnd.ms-excel.sheet.binary.macroEnabled.main");
}

test "macro content types" {
    try std.testing.expect(isMacroContentType("application/vnd.ms-word.document.macroEnabled.main+xml"));
    try std.testing.expect(isMacroContentType("application/vnd.ms-office.vbaProject"));
    try std.testing.expect(!isMacroContentType("application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"));
    try std.testing.expectEqual(Part.relationships, classify("word/_rels/document.xml.rels"));
    try std.testing.expectEqual(Part.content_types, classify("[Content_Types].xml"));
}
