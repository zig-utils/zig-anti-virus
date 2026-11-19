//! One object scanned the way libclamav scans one layer (cli_magic_scan) with a whole database:
//! hashes, file typing, then the body signatures over each form of the object libclamav
//! matches, each with its target type. Containers are the walker's (container.zig); this is the
//! per-object part, over an in-memory view.
//!
//! File typing follows libclamav:
//! - zav's format detection gives executables (with their entry point and sections), PDF, mail;
//! - text and binary data are re-typed from the database's embedded type magics (.ftm body
//!   magics) found in the first 1024 bytes (cli_determine_fmap_type, `ftm.retype`): binary data
//!   with an HTML tag near its start is HTML, mail headers make mail, and so on. A database
//!   without type magics gets no re-typing (libclamav then falls back to a built-in list);
//! - HTML is never matched raw (DOCUMENT HTMLSKIPRAW). Its normalised forms are, with target
//!   type 3: nocomment.html, notags.html (up to MaxHTMLNoTags) and the scripts' normalised
//!   JavaScript, which is also matched with target type 7 (cli_scanhtml);
//! - ASCII text is matched raw with target type 0. When its embedded type magics over the whole
//!   file settle on HTML (scanraw), it is also scanned as HTML and not normalised as text;
//!   otherwise its normalised text is matched with target type 7 (cli_scanscript);
//! - a logical signature with `HandlerType` that matches makes libclamav scan the object again as
//!   that type, once (LAYER_ATTRIBUTES_RETYPED); the signature reports from that scan.
const std = @import("std");
const Io = std.Io;
const db = @import("../db/root.zig");
const regex_pool = @import("../match/regex_pool.zig");
const bodyscan = @import("bodyscan.zig");
const hashscan = @import("hashscan.zig");
const limits = @import("limits.zig");
const scratch_mod = @import("scratch.zig");
const source = @import("source.zig");
const vm = @import("../match/verify_vm.zig");
const logical = @import("../match/logical.zig");
const prog = @import("../match/prog.zig");
const detect = @import("../fmt/detect.zig");
const ftm = @import("../fmt/ftm.zig");
const types = @import("../fmt/types.zig");
const pe = @import("../fmt/pe.zig");
const elf = @import("../fmt/elf.zig");
const macho = @import("../fmt/macho.zig");
const html_norm = @import("../fmt/html_norm.zig");
const js_norm = @import("../fmt/js_norm.zig");
const text_norm = @import("../fmt/text_norm.zig");
const fmt_scan = @import("../fmt/scan.zig");
const container = @import("container.zig");
const budget_mod = @import("budget.zig");

/// One compiled database, ready to scan with.
pub const Engine = struct {
    database: db.reader.Database,
    body: bodyscan.BodyIndex,
    hashes: hashscan.HashIndex,
    /// The type magics, when the database has any.
    types: ?ftm.Ftm = null,
    regex_mem: []align(8) u8 = &.{},
    regex_scratch: ?regex_pool.Scratch = null,

    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, options: db.reader.OpenOptions) !Engine {
        const database = try db.reader.open(io, dir, path, options);
        errdefer database.close();
        var e: Engine = .{ .database = database, .body = try .load(database), .hashes = try .load(database) };
        if (database.section(.ftm_trie, 0)) |section| {
            const magic_progs: ?prog.Programs = if (database.section(.subsig_prog, 1)) |p| try .init(p) else null;
            e.types = try .init(section, magic_progs);
        }
        if (e.body.regexes) |pool| {
            // Sized for the database's largest linear and backtracking programs.
            e.regex_mem = try gpa.alignedAlloc(u8, .@"8", pool.scratchBytes(256));
            e.regex_scratch = try regex_pool.Scratch.initBuffer(e.regex_mem, pool, 256);
            e.regex_scratch.?.setStepBudget(1 << 22);
        }
        return e;
    }

    pub fn close(e: *Engine, gpa: std.mem.Allocator) void {
        if (e.regex_mem.len > 0) gpa.free(e.regex_mem);
        e.database.close();
    }

    /// The file type libclamav gives a whole file (cli_determine_fmap_type), from the type
    /// magics: the first 1024 bytes classified by the magic trie (or as text or binary data),
    /// a tar header in binary data, then text and binary data re-typed by embedded type magics,
    /// and ASCII text by the magics over the whole file (scanraw).
    /// Null without type magics in the database.
    pub fn fileType(e: *const Engine, data: []const u8) ?types.ClType {
        const magics = e.types orelse return null;
        var budget: vm.Budget = .{};
        const head = data[0..@min(data.len, ftm.retype_window)];
        var t = ftm.classify(magics, head, .{ .file_size = data.len }, &budget).type;
        if (t == .binary_data and data.len >= 512 and detect.isTar(data[0..512])) {
            t = if (std.mem.eql(u8, data[257..262], "ustar")) .posix_tar else .old_tar;
        }
        switch (t) {
            .text_ascii, .text_utf8, .text_utf16le, .text_utf16be, .binary_data => if (ftm.retype(magics, data, t, &budget)) |r| {
                t = r;
            },
            else => {},
        }
        // scanraw: ASCII text whose type magics over the whole file settle on HTML or mail
        // becomes that type.
        if (t == .text_ascii) switch (ftm.embeddedType(magics, data, .any, true, &budget)) {
            .html => t = .html,
            .mail => t = .mail,
            else => {},
        };
        return t;
    }

    /// The HandlerType of the logical signature `sig`, if it has one.
    pub fn handlerOf(e: *const Engine, sig: u32) ?types.ClType {
        const table = e.body.ldb orelse return null;
        for (table.records, 0..) |r, i| if (r.sig == sig) {
            const h = table.tdb(i).handler;
            return if (h == 0) null else @fromBackingInt(h);
        };
        return null;
    }
};

pub const Result = union(enum) {
    clean,
    found: u32,
    limited: limits.Event,
};

/// How libclamav handles an object once it is typed.
pub const Kind = enum { binary, text, html, other };

/// What is known about an object before matching.
pub const Classified = struct {
    format: detect.Format,
    kind: Kind,
    file: bodyscan.File,
    pe: ?pe.Info = null,
    /// The type libclamav's re-typing gave it, when it did.
    retyped: ?types.ClType = null,
};

/// Per-worker scan state: logical state in scratch, executable tables, normaliser buffers.
pub const Scanner = struct {
    gpa: std.mem.Allocator,
    io: Io,
    scratch: scratch_mod.Scratch,
    state: logical.State,
    limits: limits.Limits = .{},
    block: []u8,
    pe_sections: []pe.Section,
    elf_segments: []elf.Segment,
    elf_sections: []elf.Section,
    macho_segments: []macho.Segment,
    macho_sections: []macho.Section,
    vm_sections: []vm.Section,
    norm: std.ArrayList(u8) = .empty,
    html: *html_norm.Normalizer,
    forms: [3]std.ArrayList(u8) = @splat(.empty),
    /// Scratch for walking mail attachments and OLE2 macro streams, made on first use.
    walk_scratch: ?scratch_mod.Scratch = null,

    pub fn init(gpa: std.mem.Allocator, io: Io) !*Scanner {
        const s = try gpa.create(Scanner);
        errdefer gpa.destroy(s);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .scratch = try .init(scratch_mod.default_reservation),
            .state = undefined,
            .block = try gpa.alloc(u8, 64 * 1024),
            .pe_sections = try gpa.alloc(pe.Section, 96),
            .elf_segments = try gpa.alloc(elf.Segment, 256),
            .elf_sections = try gpa.alloc(elf.Section, 1024),
            .macho_segments = try gpa.alloc(macho.Segment, 256),
            .macho_sections = try gpa.alloc(macho.Section, 1024),
            .vm_sections = try gpa.alloc(vm.Section, 1024),
            .html = try gpa.create(html_norm.Normalizer),
        };
        s.state = try logical.State.init(s.scratch.allocator());
        return s;
    }

    pub fn deinit(s: *Scanner) void {
        for (&s.forms) |*f| f.deinit(s.gpa);
        if (s.walk_scratch) |*w| w.deinit();
        s.gpa.destroy(s.html);
        s.norm.deinit(s.gpa);
        s.gpa.free(s.vm_sections);
        s.gpa.free(s.macho_sections);
        s.gpa.free(s.macho_segments);
        s.gpa.free(s.elf_sections);
        s.gpa.free(s.elf_segments);
        s.gpa.free(s.pe_sections);
        s.gpa.free(s.block);
        s.scratch.deinit();
        s.gpa.destroy(s);
    }

    /// The object's format, target type and executable layout from zav's own detection.
    pub fn classify(s: *Scanner, data: []const u8) Classified {
        const format = detect.detect(data[0..@min(data.len, detect.head_len)]);
        var out: Classified = .{ .format = format, .kind = switch (format) {
            .binary => .binary,
            .text => .text,
            .html => .html,
            else => .other,
        }, .file = .{ .info = .{ .size = data.len } } };
        const src: source.Source = .{ .memory = data };
        switch (format) {
            .pe => if (pe.parse(s.io, src, s.pe_sections)) |info| {
                out.pe = info;
                out.file.target = 1;
                out.file.info.entry_point = info.ep_offset;
                const n = @min(info.sections.len, s.vm_sections.len);
                for (info.sections[0..n], s.vm_sections[0..n]) |sec, *v| v.* = .{ .offset = sec.raw_off, .size = sec.raw_size };
                out.file.info.sections = s.vm_sections[0..n];
            } else |_| {},
            .elf => if (elf.parse(s.io, src, s.elf_segments, s.elf_sections)) |info| {
                out.file.target = 6;
                out.file.info.entry_point = info.ep_offset;
                const n = @min(info.sections.len, s.vm_sections.len);
                for (info.sections[0..n], s.vm_sections[0..n]) |sec, *v| v.* = .{ .offset = sec.offset, .size = sec.size };
                out.file.info.sections = s.vm_sections[0..n];
            } else |_| {},
            .macho => if (macho.parse(s.io, src, s.macho_segments, s.macho_sections)) |info| {
                out.file.target = 9;
                out.file.info.entry_point = info.matchEntryPoint();
                const n = @min(info.sections.len, s.vm_sections.len);
                for (info.sections[0..n], s.vm_sections[0..n]) |sec, *v| v.* = .{ .offset = sec.offset, .size = sec.size };
                out.file.info.sections = s.vm_sections[0..n];
            } else |_| {},
            .mail => out.file.target = 4,
            else => {},
        }
        return out;
    }

    /// `classify`, then libclamav's re-typing of text and binary data with the database's type
    /// magics. A file typed CL_TYPE_IGNORED is not scanned at all (returns null).
    pub fn typed(s: *Scanner, e: *const Engine, data: []const u8) ?Classified {
        var c = s.classify(data);
        const magics = e.types orelse return c;
        if (c.kind == .other) return c;
        var budget: vm.Budget = .{};
        const base: types.ClType = if (c.kind == .binary) .binary_data else textType(data);
        if (ftm.retype(magics, data, base, &budget)) |t| {
            if (t == .ignored) return null;
            c.retyped = t;
            setType(&c, t);
        } else if (c.kind == .html) {
            // zav's detection calls more files HTML than libclamav's magics do.
            c.kind = .text;
        }
        return c;
    }

    /// Scan one object with one database: the first detection, like clamscan without
    /// --allmatch.
    pub fn scan(s: *Scanner, e: *Engine, data: []const u8) !Result {
        if (data.len < limits.min_scan_size) return .clean;
        var tracker = limits.Tracker.init(s.limits);
        const src: source.Source = .{ .memory = data };
        switch (try hashscan.scanSource(s.io, &e.hashes, src, &tracker, s.block)) {
            .infected => |sig| return .{ .found = sig },
            .limited => |ev| return .{ .limited = ev },
            .clean, .allowed => {},
        }
        const c = s.typed(e, data) orelse return .clean;
        if (c.pe) |*info| switch (hashscan.scanPe(s.io, &e.hashes, src, info, s.block)) {
            .infected => |sig| return .{ .found = sig },
            else => {},
        };
        return s.layer(e, data, c, false, &tracker);
    }

    fn layer(s: *Scanner, e: *Engine, data: []const u8, c: Classified, retyped: bool, tracker: *limits.Tracker) !Result {
        const r = try s.scanForms(e, data, c, tracker);
        if (r == .found and !retyped) if (e.handlerOf(r.found)) |h| {
            // HandlerType: scan the object again as that type, once; the signature (or one the
            // new type brings in) reports from there.
            var again = s.classify(data);
            again.retyped = h;
            setType(&again, h);
            return s.layer(e, data, again, true, tracker);
        };
        return r;
    }

    fn scanForms(s: *Scanner, e: *Engine, data: []const u8, c: Classified, tracker: *limits.Tracker) !Result {
        if (c.kind == .html) return s.scanHtml(e, data, tracker);
        var limited: ?limits.Event = null;
        switch (try s.body(e, data, c.file, tracker)) {
            .infected => |d| return .{ .found = d.sig },
            .limited => |ev| limited = ev,
            .clean => {},
        }
        if (c.format == .ole2) switch (try s.scanMacros(e, data, tracker)) {
            .found => |sig| return .{ .found = sig },
            .limited => |ev| limited = limited orelse ev,
            .clean => {},
        };
        if (c.format == .mail or c.retyped == .mail) switch (try s.scanMailAttachments(e, data)) {
            .found => |sig| return .{ .found = sig },
            .limited => |ev| limited = limited orelse ev,
            .clean => {},
        };
        if (c.kind == .text) {
            // scanraw: ASCII text whose type magics settle on HTML is scanned as HTML too (and
            // not as text); on mail, its raw bytes are matched with the mail target as well.
            var mail = false;
            if (e.types) |magics| if (c.retyped == null and textType(data) == .text_ascii) {
                var budget: vm.Budget = .{};
                switch (ftm.embeddedType(magics, data, .any, true, &budget)) {
                    .html => {
                        const r = try s.scanHtml(e, data, tracker);
                        return if (r == .clean and limited != null) .{ .limited = limited.? } else r;
                    },
                    .mail => mail = true,
                    else => {},
                }
            };
            if (mail) switch (try s.body(e, data, .{ .info = .{ .size = data.len }, .target = 4 }, tracker)) {
                .infected => |d| return .{ .found = d.sig },
                .limited => |ev| limited = limited orelse ev,
                .clean => {},
            };
            // Target 7 (and type-0) signatures also run over the normalised text.
            s.norm.clearRetainingCapacity();
            try s.norm.resize(s.gpa, data.len);
            var n: text_norm.Normalizer = .{};
            const text = s.norm.items[0..n.feed(data, s.norm.items)];
            switch (try s.body(e, text, .{ .info = .{ .size = text.len }, .target = 7 }, tracker)) {
                .infected => |d| return .{ .found = d.sig },
                .limited => |ev| limited = limited orelse ev,
                .clean => {},
            }
        }
        if (limited) |ev| return .{ .limited = ev };
        return .clean;
    }

    /// cli_vba_scandir: each VBA module's decompressed source in an OLE2 compound file, matched
    /// with target type 2. The walker's OLE2 parser finds them (its `macro/<module>` children).
    fn scanMacros(s: *Scanner, e: *Engine, data: []const u8, tracker: *limits.Tracker) !Result {
        const ws = try s.prepareWalk();
        var mc: MacroCollect = .{ .s = s, .e = e, .tracker = tracker };
        defer mc.source.deinit(s.gpa);
        _ = s.walkObject(ws, data, mc.visitor(), null);
        if (mc.err) |err| return err;
        if (mc.found) |sig| return .{ .found = sig };
        if (mc.limited) |ev| return .{ .limited = ev };
        return .clean;
    }

    fn prepareWalk(s: *Scanner) !*scratch_mod.Scratch {
        if (s.walk_scratch == null) s.walk_scratch = try .init(scratch_mod.default_reservation);
        const ws = &s.walk_scratch.?;
        ws.reset();
        return ws;
    }

    fn walkObject(s: *Scanner, ws: *scratch_mod.Scratch, data: []const u8, visitor: container.Visitor, magics: ?*const ftm.Ftm) ?limits.Event {
        var budget = budget_mod.Budget.init(64 * 1024 * 1024);
        var walk_tracker = limits.Tracker.init(s.limits);
        var w: container.Walker = .{
            .io = s.io,
            .scratch = ws,
            .tracker = &walk_tracker,
            .budget = &budget,
            .spill_dir = Io.Dir.cwd(),
            .visitor = visitor,
            .parse = fmt_scan.parse,
            .options = .{ .types = magics },
        };
        w.scan(.{ .memory = data }, "object") catch {};
        return walk_tracker.last;
    }

    fn scanMailAttachments(s: *Scanner, e: *const Engine, data: []const u8) !Result {
        const ws = try s.prepareWalk();
        const files = try ws.allocator().alloc(?hashscan.FileHashes, @as(usize, s.limits.max_recursion) + 1);
        @memset(files, null);
        var hashes: MailAttachmentHashes = .{ .files = files, .index = &e.hashes };
        const event = s.walkObject(ws, data, .{ .ptr = &hashes, .vtable = &MailAttachmentHashes.vtable }, if (e.types) |*magics| magics else null);
        if (hashes.found) |sig| return .{ .found = sig };
        if (event) |ev| return .{ .limited = ev };
        return .clean;
    }

    const MailAttachmentHashes = struct {
        index: *const hashscan.HashIndex,
        files: []?hashscan.FileHashes,
        found: ?u32 = null,

        const vtable: container.Visitor.VTable = .{ .enter = enter, .data = feed, .leave = leave, .notice = notice };

        fn enter(ptr: *anyopaque, obj: *const container.Object) error{Stop}!void {
            const hashes: *MailAttachmentHashes = @ptrCast(@alignCast(ptr));
            if (hashes.found != null) return error.Stop;
            if (obj.kind != .member) return;
            hashes.files[obj.depth] = if (obj.size) |size| .init(hashes.index, size) else null;
        }

        fn feed(ptr: *anyopaque, obj: *const container.Object, bytes: []const u8) error{Stop}!void {
            const hashes: *MailAttachmentHashes = @ptrCast(@alignCast(ptr));
            if (hashes.found != null) return error.Stop;
            if (obj.kind != .member) return;
            if (hashes.files[obj.depth]) |*file| file.update(bytes);
        }

        fn leave(ptr: *anyopaque, obj: *const container.Object) void {
            const hashes: *MailAttachmentHashes = @ptrCast(@alignCast(ptr));
            if (obj.kind != .member or hashes.found != null) return;
            if (hashes.files[obj.depth]) |*file| {
                const result = file.finish(hashes.index);
                if (result == .infected) hashes.found = result.infected;
                hashes.files[obj.depth] = null;
            }
        }

        fn notice(_: *anyopaque, _: container.Notice) void {}
    };

    const MacroCollect = struct {
        s: *Scanner,
        e: *Engine,
        tracker: *limits.Tracker,
        source: std.ArrayList(u8) = .empty,
        in_macro: bool = false,
        found: ?u32 = null,
        limited: ?limits.Event = null,
        err: ?anyerror = null,

        fn visitor(m: *MacroCollect) container.Visitor {
            return .{ .ptr = m, .vtable = &.{ .enter = enter, .data = dataFn, .leave = leave, .notice = notice } };
        }
        fn isMacro(obj: *const container.Object) bool {
            return obj.kind == .script and std.mem.startsWith(u8, obj.name, "macro/");
        }
        fn enter(ptr: *anyopaque, obj: *const container.Object) error{Stop}!void {
            const m: *MacroCollect = @ptrCast(@alignCast(ptr));
            if (!isMacro(obj)) return;
            m.in_macro = true;
            m.source.clearRetainingCapacity();
        }
        fn dataFn(ptr: *anyopaque, obj: *const container.Object, bytes: []const u8) error{Stop}!void {
            const m: *MacroCollect = @ptrCast(@alignCast(ptr));
            if (!isMacro(obj) or !m.in_macro) return;
            m.source.appendSlice(m.s.gpa, bytes) catch |err| {
                m.err = err;
                return error.Stop;
            };
        }
        fn leave(ptr: *anyopaque, obj: *const container.Object) void {
            const m: *MacroCollect = @ptrCast(@alignCast(ptr));
            if (!isMacro(obj) or !m.in_macro or m.found != null) return;
            m.in_macro = false;
            const src = m.source.items;
            const v = m.s.body(m.e, src, .{ .info = .{ .size = src.len }, .target = 2 }, m.tracker) catch |err| {
                m.err = err;
                return;
            };
            switch (v) {
                .infected => |d| m.found = d.sig,
                .limited => |ev| m.limited = m.limited orelse ev,
                .clean => {},
            }
        }
        fn notice(_: *anyopaque, _: container.Notice) void {}
    };

    /// cli_scanhtml: nocomment.html and notags.html with target type 3, then the normalised
    /// JavaScript with target types 3 and 7. No raw scan.
    fn scanHtml(s: *Scanner, e: *Engine, data: []const u8, tracker: *limits.Tracker) !Result {
        if (data.len > s.limits.max_html_normalize) return .{ .limited = .html_normalize };
        try s.normalizeHtml(data);
        var limited: ?limits.Event = null;
        const Pass = struct { form: usize, target: u8 };
        for ([_]Pass{ .{ .form = 0, .target = 3 }, .{ .form = 1, .target = 3 }, .{ .form = 2, .target = 3 }, .{ .form = 2, .target = 7 } }) |pass| {
            const bytes = s.forms[pass.form].items;
            if (pass.form == 1 and data.len > s.limits.max_html_notags) {
                limited = limited orelse .html_notags;
                continue;
            }
            // libclamav writes the JavaScript file only when there was a script.
            if (pass.form == 2 and bytes.len == 0) continue;
            switch (try s.body(e, bytes, .{ .info = .{ .size = bytes.len }, .target = pass.target }, tracker)) {
                .infected => |d| return .{ .found = d.sig },
                .limited => |ev| limited = limited orelse ev,
                .clean => {},
            }
        }
        if (limited) |ev| return .{ .limited = ev };
        return .clean;
    }

    /// libclamav's three HTML forms into `forms`: nocomment.html, notags.html, javascript.
    pub fn normalizeHtml(s: *Scanner, data: []const u8) !void {
        for (&s.forms) |*f| f.clearRetainingCapacity();
        var sink: FormSink = .{ .s = s };
        s.html.* = .init(.{
            .nocomment = .{ .ctx = &sink, .write = FormSink.nocomment },
            .notags = .{ .ctx = &sink, .write = FormSink.notags },
            .scripts = JavascriptFile.pieces(&sink.js),
        });
        sink.js = .{ .out = .{ .ctx = &sink, .write = FormSink.javascript } };
        s.html.feed(data) catch return sink.err orelse error.OutOfMemory;
        s.html.finish() catch return sink.err orelse error.OutOfMemory;
    }

    const FormSink = struct {
        s: *Scanner,
        js: JavascriptFile = undefined,
        err: ?anyerror = null,

        fn add(f: *FormSink, i: usize, bytes: []const u8) error{Stop}!void {
            f.s.forms[i].appendSlice(f.s.gpa, bytes) catch |err| {
                f.err = err;
                return error.Stop;
            };
        }
        fn nocomment(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
            return add(@ptrCast(@alignCast(ctx)), 0, bytes);
        }
        fn notags(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
            return add(@ptrCast(@alignCast(ctx)), 1, bytes);
        }
        fn javascript(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
            return add(@ptrCast(@alignCast(ctx)), 2, bytes);
        }
    };

    fn body(s: *Scanner, e: *Engine, data: []const u8, file: bodyscan.File, tracker: *limits.Tracker) !bodyscan.Verdict {
        s.state.reset();
        s.state.regex_scratch = if (e.regex_scratch) |*r| r else null;
        var budget: vm.Budget = .{};
        return bodyscan.scanBuffer(&e.body, data, file, &budget, tracker, &s.state);
    }
};

/// libclamav's `javascript` file from the script elements of an HTML object: each script's
/// normalised JavaScript between `<script>` and `</script>` (added unless the script already
/// ends with it), newline separated.
pub const JavascriptFile = struct {
    out: html_norm.Output,
    js: js_norm.Normalizer = undefined,
    scripts: usize = 0,
    tail: [9]u8 = @splat(0),
    tail_len: usize = 0,

    pub fn pieces(j: *JavascriptFile) html_norm.Pieces {
        return .{ .ctx = j, .begin = begin, .data = data, .end = end };
    }

    fn write(j: *JavascriptFile, bytes: []const u8) error{Stop}!void {
        try j.out.write(j.out.ctx, bytes);
        for (bytes) |b| {
            std.mem.copyForwards(u8, j.tail[0..8], j.tail[1..9]);
            j.tail[8] = b;
        }
        j.tail_len +|= bytes.len;
    }

    fn jsOut(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        return j.write(bytes);
    }

    fn begin(ctx: *anyopaque) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        if (j.scripts > 0) try j.write("\n");
        j.scripts += 1;
        j.tail_len = 0;
        try j.write("<script>");
        j.js = .initHtml(.{ .ctx = j, .write = jsOut });
    }

    fn data(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        try j.js.feed(bytes);
    }

    fn end(ctx: *anyopaque) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        try j.js.finish();
        if (j.tail_len < 9 or !std.mem.eql(u8, &j.tail, "</script>")) try j.write("</script>");
    }
};

/// libclamav's target type for a file type (cli_mtargets), and how the object is handled.
fn setType(c: *Classified, t: types.ClType) void {
    c.kind = switch (t) {
        .html, .html_utf16 => .html,
        .text_ascii, .text_utf8, .text_utf16le, .text_utf16be, .script => .text,
        .binary_data => .binary,
        else => .other,
    };
    // A re-typed executable keeps whatever layout zav parsed; the target follows the type.
    c.file.target = switch (t) {
        .msexe => 1,
        .msole2 => 2,
        .html => 3,
        .mail => 4,
        .graphics, .gif, .png, .jpeg, .tiff => 5,
        .elf => 6,
        .macho, .macho_unibin => 9,
        .pdf => 10,
        .swf => 11,
        .java => 12,
        else => 0,
    };
}

/// libclamav's text type of a file from its first 1024 bytes (textdet.c).
fn textType(data: []const u8) types.ClType {
    return ftm.textType(data[0..@min(data.len, ftm.retype_window)]);
}

// Tests --------------------------------------------------------------------------------------------

test "HTML JavaScript lowercases output and keeps const and let names" {
    const s = try Scanner.init(std.testing.allocator, std.testing.io);
    defer s.deinit();
    try s.normalizeHtml(
        "<html><script>Object.defineProperty(window, \"Caps\", {value: \"ABC\"});console.Log(/AB+/g);</script>" ++
            "<script>const LOWER = \"TEST\"; let UPPER = LOWER; var Mixed = UPPER; Use(Mixed);</script></html>",
    );
    // Observed with the official ClamAV 1.5.4 binary on the two scripts.
    try std.testing.expectEqualStrings(
        "<script>object.defineproperty(window,\"caps\",{value:\"abc\"});console.log(/ab+/g);</script>\n" ++
            "<script>const lower=\"test\";let upper=lower;var n000=upper;use(n000);</script>",
        s.forms[2].items,
    );
}

fn testEngine(tmp: *std.testing.TmpDir, files: []const [2][]const u8) !Engine {
    const Compiler = @import("../compile/compiler.zig").Compiler;
    var c = Compiler.init(std.testing.allocator);
    defer c.deinit();
    for (files) |f| try c.addFile(f[0], f[1]);
    _ = try c.write(std.testing.io, tmp.dir, "l.zavdb", .{ .db_version = 1 });
    return Engine.open(std.testing.allocator, std.testing.io, tmp.dir, "l.zavdb", .{ .allow_unsigned = true });
}

fn expectFound(s: *Scanner, e: *Engine, data: []const u8, want: ?[]const u8) !void {
    var buf: [256]u8 = undefined;
    switch (try s.scan(e, data)) {
        .found => |sig| try std.testing.expectEqualStrings(want orelse "(clean)", try e.hashes.meta.?.name(sig, &buf)),
        .clean => try std.testing.expect(want == null),
        .limited => |ev| {
            std.debug.print("limited {t}\n", .{ev});
            return error.TestUnexpectedResult;
        },
    }
}

// Type magics in the official daily.ftm's form (written here, not copied from a database).
const test_magics =
    \\1:*:3c736372697074(3e|20):HTML data:CL_TYPE_ANY:CL_TYPE_HTML
    \\1:*:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML
    \\1:0:4d5a:DOS/W32 executable:CL_TYPE_ANY:CL_TYPE_MSEXE
    \\
;

test "binary data with an HTML tag near its start is HTML: no raw scan, normalised forms" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var e = try testEngine(&tmp, &.{
        .{ "t.ftm", test_magics },
        .{ "t.ndb", "Test.Raw:0:*:3c7363726970743e416c657274\nTest.Norm:3:*:3c7363726970743e616c657274\nTest.NoTags:3:*:68696464656e2074657874\n" },
    });
    defer e.close(std.testing.allocator);
    const s = try Scanner.init(std.testing.allocator, std.testing.io);
    defer s.deinit();
    // NULs make it binary data; `<script>` in the first 1024 bytes makes it HTML. The raw bytes
    // (`<script>Alert`) are not matched; nocomment.html (`<script>alert`) is.
    try expectFound(s, &e, "\x00\x01\x02<script>Alert(1)</script>", "Test.Norm");
    // Text only reaches notags.html.
    try expectFound(s, &e, "\x00\x00<html><b>Hidden</b> <i>TEXT</i>", "Test.NoTags");
    // Past the first 1024 bytes the tag re-types nothing: binary data is matched raw.
    var far: [1100 + 22]u8 = undefined;
    @memset(far[0..1100], 0);
    @memcpy(far[1100..], "<script>Alert(1);</a>z");
    try expectFound(s, &e, &far, "Test.Raw");
    // Without type magics in the database nothing is re-typed either.
    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    var plain = try testEngine(&tmp2, &.{.{ "t.ndb", "Test.Raw:0:*:3c7363726970743e416c657274\n" }});
    defer plain.close(std.testing.allocator);
    try expectFound(s, &plain, "\x00\x01\x02<script>Alert(1)</script>", "Test.Raw");
}

test "ASCII text with an HTML tag anywhere is also scanned as HTML, and not as text" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var e = try testEngine(&tmp, &.{
        .{ "t.ftm", test_magics },
        .{ "t.ndb", "Test.Norm:3:*:3c7363726970743e78\nTest.Text:7:*:6869207468657265\n" },
    });
    defer e.close(std.testing.allocator);
    const s = try Scanner.init(std.testing.allocator, std.testing.io);
    defer s.deinit();
    var page: [1500]u8 = undefined;
    @memset(&page, 'a');
    @memcpy(page[0..9], "hi  there");
    @memcpy(page[1400..1418], "<script>x</script>");
    try expectFound(s, &e, &page, "Test.Norm");
    // Without the tag it is text, normalised for target 7.
    @memcpy(page[1400..1418], "..................");
    try expectFound(s, &e, &page, "Test.Text");
}

test "HandlerType: the object is scanned again as the handler's type" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var e = try testEngine(&tmp, &.{
        .{ "t.ldb", "Test.Handler;Engine:51-255,HandlerType:CL_TYPE_PDF,Target:0;0;48414e444c45\n" },
        .{ "t.ndb", "Test.PdfOnly:10:*:48414e444c45\n" },
    });
    defer e.close(std.testing.allocator);
    const s = try Scanner.init(std.testing.allocator, std.testing.io);
    defer s.deinit();
    try std.testing.expectEqual(types.ClType.pdf, e.handlerOf(e.body.ldb.?.records[0].sig).?);
    // The re-scan as CL_TYPE_PDF matches target-10 signatures; one of the two reports.
    var buf: [64]u8 = undefined;
    const r = try s.scan(&e, "\x00\x00HANDLE\x00\x00");
    const name = try e.hashes.meta.?.name(r.found, &buf);
    try std.testing.expect(std.mem.eql(u8, name, "Test.Handler") or std.mem.eql(u8, name, "Test.PdfOnly"));
}
