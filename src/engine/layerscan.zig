//! The per-layer scan model the differential tools compare with clamscan: which bytes of an
//! object are matched with which target types, derived black-box from clamscan 1.5.4's
//! verdicts on generated files and signatures (docs/clean-room.md, "Scan model").
//!
//! - Files of five bytes or fewer are not scanned. Whole-file hashes come first.
//! - An object is typed with the database's type magics (fmt/ftm.zig), or zav's own format
//!   detection when the database has none.
//! - Text (ASCII, UTF-16) is matched raw with target 0 and normalised (fmt/text_norm.zig) with
//!   target 7. HTML is never matched raw: its nocomment and notags forms and its JavaScript
//!   file are matched with target 3, and the JavaScript file, as a text child, also raw and
//!   normalised. PE, ELF and Mach-O files are matched raw with targets 1, 6 and 9 and their
//!   entry point and sections; mail with 4, OLE2 with 2, graphics with 5, PDF with 10, Flash
//!   with 11, Java with 12; anything else with target 0. Target-specific signatures and target 0
//!   apply together.
//! - A logical signature with HandlerType does not alert unless the object is being scanned as
//!   that type; otherwise the object is scanned again as that type.
//! - Container members (the format dispatcher's children) are scanned the same way, one level
//!   at a time, with their container's type.
const std = @import("std");
const Io = std.Io;
const db = @import("../db/root.zig");
const bodyscan = @import("bodyscan.zig");
const hashscan = @import("hashscan.zig");
const limits = @import("limits.zig");
const scratch_mod = @import("scratch.zig");
const container = @import("container.zig");
const budget_mod = @import("budget.zig");
const ftm = @import("../fmt/ftm.zig");
const types = @import("../fmt/types.zig");
const detect = @import("../fmt/detect.zig");
const scan_fmt = @import("../fmt/scan.zig");
const pe = @import("../fmt/pe.zig");
const elf = @import("../fmt/elf.zig");
const macho = @import("../fmt/macho.zig");
const html_norm = @import("../fmt/html_norm.zig");
const text_norm = @import("../fmt/text_norm.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");
const logical = @import("../match/logical.zig");
const regex_pool = @import("../match/regex_pool.zig");

pub const Engine = struct {
    database: db.reader.Database,
    body: bodyscan.BodyIndex,
    hashes: hashscan.HashIndex,
    types: ?ftm.Ftm = null,
    regex_mem: []align(8) u8 = &.{},
    regex_scratch: ?regex_pool.Scratch = null,
    /// Signature id to HandlerType, for the logical signatures that have one.
    handlers: std.AutoHashMapUnmanaged(u32, types.ClType) = .empty,

    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, options: db.reader.OpenOptions) !Engine {
        const database = try db.reader.open(io, dir, path, options);
        errdefer database.close();
        var e: Engine = .{ .database = database, .body = try .load(database), .hashes = try .load(database) };
        errdefer e.handlers.deinit(gpa);
        if (database.section(.ftm_trie, 0)) |section| {
            const progs: ?prog.Programs = if (database.section(.subsig_prog, 1)) |p| try .init(p) else null;
            e.types = try .init(section, progs);
        }
        if (e.body.regexes) |pool| {
            e.regex_mem = try gpa.alignedAlloc(u8, .@"8", pool.scratchBytes(256));
            e.regex_scratch = try regex_pool.Scratch.initBuffer(e.regex_mem, pool, 256);
        }
        if (e.body.ldb) |table| {
            for (table.records, 0..) |r, i| {
                const h = table.tdb(i).handler;
                if (h != 0) try e.handlers.put(gpa, r.sig, @fromBackingInt(h));
            }
        }
        return e;
    }

    pub fn close(e: *Engine, gpa: std.mem.Allocator) void {
        e.handlers.deinit(gpa);
        if (e.regex_mem.len > 0) gpa.free(e.regex_mem);
        e.database.close();
    }

    /// The type clamscan gives `data`, with this database's type magics.
    pub fn fileType(e: *const Engine, data: []const u8) ?types.ClType {
        const f = e.types orelse return null;
        var budget: vm.Budget = .{};
        return ftm.classify(f, data, .{}, &budget).type;
    }

    pub fn handlerOf(e: *const Engine, sig: u32) ?types.ClType {
        return e.handlers.get(sig);
    }
};

pub const Result = union(enum) {
    clean,
    found: u32,
    limited: limits.Event,
};

pub const Kind = enum { binary, text, html, other };

pub const Classified = struct {
    format: detect.Format,
    kind: Kind,
    file: bodyscan.File,
    type: types.ClType = .binary_data,
};

/// Why an object is being scanned: the type of its container (0 at the root) and its depth.
const Layer = struct {
    container: u16 = 0,
    depth: u8 = 0,
};

/// Children are scanned to this depth.
const max_depth = 8;

pub const Scanner = struct {
    gpa: std.mem.Allocator,
    io: Io,
    scratch: scratch_mod.Scratch,
    state: logical.State,
    limits: limits.Limits = .{},
    tracker: limits.Tracker,
    pe_sections: []pe.Section,
    elf_segments: []elf.Segment,
    elf_sections: []elf.Section,
    macho_segments: []macho.Segment,
    macho_sections: []macho.Section,
    vm_sections: []vm.Section,
    html: *html_norm.Normalizer,
    walk_scratch: scratch_mod.Scratch,
    forms: [3]std.ArrayList(u8) = @splat(.empty),

    pub fn init(gpa: std.mem.Allocator, io: Io) !*Scanner {
        const s = try gpa.create(Scanner);
        errdefer gpa.destroy(s);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .scratch = try .init(scratch_mod.default_reservation),
            .state = undefined,
            .tracker = .init(.{}),
            .pe_sections = try gpa.alloc(pe.Section, pe.max_sections),
            .elf_segments = try gpa.alloc(elf.Segment, elf.max_headers),
            .elf_sections = try gpa.alloc(elf.Section, elf.max_headers),
            .macho_segments = try gpa.alloc(macho.Segment, macho.max_segments),
            .macho_sections = try gpa.alloc(macho.Section, macho.max_sections),
            .vm_sections = try gpa.alloc(vm.Section, @max(pe.max_sections, elf.max_headers, macho.max_sections)),
            .html = try gpa.create(html_norm.Normalizer),
            .walk_scratch = try .init(scratch_mod.default_reservation),
        };
        s.state = try .init(s.scratch.allocator());
        return s;
    }

    pub fn deinit(s: *Scanner) void {
        s.gpa.free(s.pe_sections);
        s.gpa.free(s.elf_segments);
        s.gpa.free(s.elf_sections);
        s.gpa.free(s.macho_segments);
        s.gpa.free(s.macho_sections);
        s.gpa.free(s.vm_sections);
        s.gpa.destroy(s.html);
        for (&s.forms) |*f| f.deinit(s.gpa);
        s.walk_scratch.deinit();
        s.scratch.deinit();
        s.gpa.destroy(s);
    }

    /// The target type and offsets `data` is matched with at the root, without a database
    /// (zav's own format detection).
    pub fn classify(s: *Scanner, data: []const u8) Classified {
        const t = fallbackType(data);
        var c: Classified = .{ .format = detect.detect(data[0..@min(data.len, detect.head_len)]), .kind = .binary, .type = t, .file = .{ .info = .{ .size = data.len } } };
        c.kind = if (t == .html) .html else if (ftm.isText(t)) .text else if (t == .binary_data) .binary else .other;
        c.file.target = targetOf(t);
        c.file.info = s.fileInfo(t, data);
        return c;
    }

    pub fn scan(s: *Scanner, e: *Engine, data: []const u8) !Result {
        s.tracker = .init(s.limits);
        return s.scanObject(e, data, .{});
    }

    fn scanObject(s: *Scanner, e: *Engine, data: []const u8, layer: Layer) anyerror!Result {
        if (data.len < limits.min_scan_size) return .clean;
        if (hashscan.FileHashes.init(&e.hashes, data.len)) |fh_init| {
            var fh = fh_init;
            fh.update(data);
            switch (fh.finish(&e.hashes)) {
                .infected => |sig| return .{ .found = sig },
                .allowed => return .clean,
                else => {},
            }
        }
        const t = e.fileType(data) orelse fallbackType(data);
        return s.scanAs(e, data, t, layer, true);
    }

    /// Match `data` as an object of type `t`. `rescan` allows one HandlerType re-scan.
    fn scanAs(s: *Scanner, e: *Engine, data: []const u8, t: types.ClType, layer: Layer, rescan: bool) anyerror!Result {
        var handler: ?types.ClType = null;
        const r = try s.matchAs(e, data, t, layer, &handler);
        if (r != .clean) return r;
        if (handler) |h| if (rescan) return s.scanAs(e, data, h, layer, false);
        return try s.children(e, data, t, layer);
    }

    fn matchAs(s: *Scanner, e: *Engine, data: []const u8, t: types.ClType, layer: Layer, handler: *?types.ClType) anyerror!Result {
        if (t == .html) {
            try s.normalizeHtml(data);
            const forms = [_][]const u8{ s.forms[0].items, s.forms[1].items };
            for (forms) |form| {
                const r = try s.body(e, form, 3, .{ .size = form.len }, t, layer, handler);
                if (r != .clean) return r;
            }
            const js = s.forms[2].items;
            if (js.len > 0) {
                const r = try s.body(e, js, 3, .{ .size = js.len }, t, layer, handler);
                if (r != .clean) return r;
                // The JavaScript file is also a text child of the page (matched raw and
                // normalised, not re-typed).
                if (layer.depth < max_depth) {
                    const owned = try s.gpa.dupe(u8, js);
                    defer s.gpa.free(owned);
                    const child = try s.scanAs(e, owned, .text_ascii, .{ .container = @backingInt(types.ClType.html), .depth = layer.depth +| 1 }, false);
                    if (child != .clean) return child;
                }
            }
            return .clean;
        }
        if (ftm.isText(t)) {
            const raw = try s.body(e, data, 0, .{ .size = data.len }, t, layer, handler);
            if (raw != .clean) return raw;
            const norm = try s.normalizeText(data);
            defer s.gpa.free(norm);
            return s.body(e, norm, 7, .{ .size = norm.len }, t, layer, handler);
        }
        const target = targetOf(t);
        const info = s.fileInfo(t, data);
        if (t == .msexe) {
            if (pe.parse(s.io, .{ .memory = data }, s.pe_sections)) |pi| {
                var block: [64 * 1024]u8 = undefined;
                switch (hashscan.scanPe(s.io, &e.hashes, .{ .memory = data }, &pi, &block)) {
                    .infected => |sig| return .{ .found = sig },
                    else => {},
                }
            } else |_| {}
        }
        return s.body(e, data, target, info, t, layer, handler);
    }

    fn fileInfo(s: *Scanner, t: types.ClType, data: []const u8) vm.FileInfo {
        var info: vm.FileInfo = .{ .size = data.len };
        const src: @import("source.zig").Source = .{ .memory = data };
        switch (t) {
            .msexe => if (pe.parse(s.io, src, s.pe_sections)) |pi| {
                info.entry_point = pi.ep_offset;
                for (pi.sections, 0..) |sec, i| s.vm_sections[i] = .{ .offset = sec.raw_off, .size = sec.raw_size };
                info.sections = s.vm_sections[0..pi.sections.len];
            } else |_| {},
            .elf => if (elf.parse(s.io, src, s.elf_segments, s.elf_sections)) |ei| {
                info.entry_point = ei.ep_offset;
                for (ei.sections, 0..) |sec, i| s.vm_sections[i] = .{ .offset = sec.offset, .size = sec.size };
                info.sections = s.vm_sections[0..ei.sections.len];
            } else |_| {},
            .macho => if (macho.parse(s.io, src, s.macho_segments, s.macho_sections)) |mi| {
                info.entry_point = mi.matchEntryPoint();
                for (mi.sections, 0..) |sec, i| s.vm_sections[i] = .{ .offset = sec.offset, .size = sec.size };
                info.sections = s.vm_sections[0..mi.sections.len];
            } else |_| {},
            else => {},
        }
        return info;
    }

    /// The body stage over one buffer. A HandlerType signature for another type is recorded in
    /// `handler` instead of alerting.
    fn body(s: *Scanner, e: *Engine, data: []const u8, target: u8, info: vm.FileInfo, t: types.ClType, layer: Layer, handler: *?types.ClType) !Result {
        if (data.len < limits.min_scan_size) return .clean;
        s.state.reset();
        s.state.regex_scratch = if (e.regex_scratch) |*rs| rs else null;
        var budget: vm.Budget = .{};
        const file: bodyscan.File = .{ .info = info, .target = target, .container = layer.container };
        const v = try bodyscan.scanBuffer(&e.body, data, file, &budget, &s.tracker, &s.state);
        switch (v) {
            .clean => return .clean,
            .limited => |ev| return .{ .limited = ev },
            .infected => |d| {
                if (e.handlerOf(d.sig)) |h| {
                    if (h != t) {
                        if (handler.* == null) handler.* = h;
                        return .clean;
                    }
                }
                return .{ .found = d.sig };
            },
        }
    }

    // -------------------------------------------------------------------------------------------
    // Normalised forms

    fn normalizeText(s: *Scanner, data: []const u8) ![]u8 {
        const out = try s.gpa.alloc(u8, data.len);
        errdefer s.gpa.free(out);
        var n: text_norm.Normalizer = .{ .seams = .{ .pages = .{ .page = @intCast(std.heap.pageSize()) } } };
        const len = n.feed(data, out);
        return s.gpa.realloc(out, len);
    }

    const FormSink = struct {
        s: *Scanner,
        i: usize,
        fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
            const f: *FormSink = @ptrCast(@alignCast(ctx));
            f.s.forms[f.i].appendSlice(f.s.gpa, bytes) catch return error.Stop;
        }
    };

    /// The nocomment and notags forms of an HTML object and its JavaScript file, in `forms`.
    pub fn normalizeHtml(s: *Scanner, data: []const u8) !void {
        for (&s.forms) |*f| f.clearRetainingCapacity();
        var sinks: [3]FormSink = .{ .{ .s = s, .i = 0 }, .{ .s = s, .i = 1 }, .{ .s = s, .i = 2 } };
        var js: JavascriptFile = .{ .out = .{ .ctx = &sinks[2], .write = FormSink.write } };
        s.html.* = .init(.{
            .nocomment = .{ .ctx = &sinks[0], .write = FormSink.write },
            .notags = .{ .ctx = &sinks[1], .write = FormSink.write },
            .scripts = js.pieces(),
        });
        const max = s.limits.max_html_normalize;
        s.html.feed(data[0..@min(data.len, max)]) catch {};
        s.html.finish() catch {};
        // MaxHTMLNoTags: a notags form over the limit is not matched.
        if (s.forms[1].items.len > s.limits.max_html_notags) s.forms[1].clearRetainingCapacity();
    }

    // -------------------------------------------------------------------------------------------
    // Containers

    const Child = struct { data: []u8 };

    const Collect = struct {
        s: *Scanner,
        list: std.ArrayList(Child) = .empty,
        current: ?std.ArrayList(u8) = null,
        total: u64 = 0,

        fn enter(ptr: *anyopaque, obj: *const container.Object) error{Stop}!void {
            const c: *Collect = @ptrCast(@alignCast(ptr));
            if (obj.depth != 1) return;
            switch (obj.kind) {
                .member, .decompressed, .slice, .unpacked, .script => c.current = .empty,
                else => {},
            }
        }

        fn data(ptr: *anyopaque, obj: *const container.Object, bytes: []const u8) error{Stop}!void {
            const c: *Collect = @ptrCast(@alignCast(ptr));
            if (obj.depth != 1) return;
            if (c.current) |*cur| {
                c.total += bytes.len;
                if (c.total > c.s.limits.max_scan_size) return error.Stop;
                cur.appendSlice(c.s.gpa, bytes) catch return error.Stop;
            }
        }

        fn leave(ptr: *anyopaque, obj: *const container.Object) void {
            const c: *Collect = @ptrCast(@alignCast(ptr));
            if (obj.depth != 1) return;
            if (c.current) |*cur| {
                const owned = cur.toOwnedSlice(c.s.gpa) catch {
                    cur.deinit(c.s.gpa);
                    c.current = null;
                    return;
                };
                c.list.append(c.s.gpa, .{ .data = owned }) catch c.s.gpa.free(owned);
                c.current = null;
            }
        }

        fn notice(_: *anyopaque, _: container.Notice) void {}

        const vtable: container.Visitor.VTable = .{ .enter = enter, .data = data, .leave = leave, .notice = notice };
    };

    fn isContainer(t: types.ClType) bool {
        return switch (t) {
            .mail, .zip, .gz, .bz, .xz, .posix_tar, .old_tar, .cpio_newc, .cpio_crc, .cpio_odc, .cpio_old, .msole2, .msword, .msxl, .msppt, .pdf, .@"7z", .mscab, .iso9660, .dmg, .mschm, .nulsft, .rtf, .ooxml_word, .ooxml_xl, .ooxml_ppt => true,
            else => false,
        };
    }

    fn children(s: *Scanner, e: *Engine, data: []const u8, t: types.ClType, layer: Layer) anyerror!Result {
        if (!isContainer(t) or layer.depth >= max_depth) return .clean;
        var collect: Collect = .{ .s = s };
        defer {
            for (collect.list.items) |ch| s.gpa.free(ch.data);
            collect.list.deinit(s.gpa);
            if (collect.current) |*cur| cur.deinit(s.gpa);
        }
        var tracker: limits.Tracker = .init(s.limits);
        var budget: budget_mod.Budget = .init(budget_mod.default_capacity);
        s.walk_scratch.reset();
        var w: container.Walker = .{
            .io = s.io,
            .scratch = &s.walk_scratch,
            .tracker = &tracker,
            .budget = &budget,
            .spill_dir = Io.Dir.cwd(),
            .visitor = .{ .ptr = &collect, .vtable = &Collect.vtable },
            .parse = scan_fmt.parse,
            .options = .{ .budget_wait_ms = 1, .memory_child_max = 256 * 1024 * 1024 },
        };
        w.scan(.{ .memory = data }, "object") catch {};
        for (collect.list.items) |ch| {
            const r = try s.scanObject(e, ch.data, .{ .container = @backingInt(t), .depth = layer.depth +| 1 });
            if (r != .clean) return r;
        }
        return .clean;
    }
};

/// The target type an object of type `t` is matched with (raw bytes).
pub fn targetOf(t: types.ClType) u8 {
    return switch (t) {
        .msexe => 1,
        .msole2, .msword, .msxl, .msppt => 2,
        .html => 3,
        .mail => 4,
        .graphics, .gif, .png, .jpeg, .tiff => 5,
        .elf => 6,
        .text_ascii, .text_utf8, .text_utf16le, .text_utf16be => 7,
        .macho, .macho_unibin => 9,
        .pdf => 10,
        .swf => 11,
        .java => 12,
        else => 0,
    };
}

/// Typing without a database's type magics: zav's own format detection, then the text test.
pub fn fallbackType(data: []const u8) types.ClType {
    const head = data[0..@min(data.len, detect.head_len)];
    return switch (detect.detect(head)) {
        .pe => .msexe,
        .elf => .elf,
        .macho => .macho,
        .macho_fat => .macho_unibin,
        .mail => .mail,
        .zip => .zip,
        .gzip => .gz,
        .bzip2 => .bz,
        .xz => .xz,
        .tar => .posix_tar,
        .ole2 => .msole2,
        .pdf => .pdf,
        .rtf => .rtf,
        .sevenzip => .@"7z",
        .cab => .mscab,
        .html => .html,
        else => ftm.textType(data),
    };
}

/// The JavaScript file clamscan writes for an HTML object (fmt/js_file.zig).
pub const JavascriptFile = @import("../fmt/js_file.zig").JavascriptFile;

test "target types follow the file type" {
    try std.testing.expectEqual(@as(u8, 1), targetOf(.msexe));
    try std.testing.expectEqual(@as(u8, 3), targetOf(.html));
    try std.testing.expectEqual(@as(u8, 0), targetOf(.binary_data));
}
