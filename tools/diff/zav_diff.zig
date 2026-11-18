//! zav-diff: the zav side of the differential suite against libclamav (and yara).
//!
//!   zav-diff check [--tmp DIR] [--known FILE] CASES...
//!       Compile every signature of every case, scan every sample, and compare the verdicts with
//!       the expectations recorded from clamscan (`=>` in the case files). Differences listed in
//!       the known file are reported but do not fail; a listed difference that no longer occurs
//!       does fail, so the list stays exact. Exit 0 when everything agrees, 1 otherwise.
//!   zav-diff materialize --out DIR CASES...
//!       Write each case's databases and samples for clamscan: DIR/<case>/all.<ext> (every
//!       signature the case expects ClamAV to load), DIR/<case>/sig<N>.<ext> (one per signature)
//!       and DIR/<case>/s<N> (samples), plus DIR/<case>/manifest.
//!   zav-diff scan [--tmp DIR] [--per-sig] --sigs FILE... -- PATH...
//!       Scan files with a database compiled from signature files and print clamscan's line
//!       format. --per-sig compiles every signature line on its own and reports all that match
//!       (clamscan --allmatch); the default reports the first detection.
//!
//! Case files hold the grammar (see tools/diff/README.md):
//!
//!   case NAME
//!   ndb Diff.Name:0:*:41?243        a signature (ndb ldb hdb hsb mdb msb imp ftm cdb fp sfp ign2 yara)
//!   ndb! Diff.Bad:0:*:4             a signature ClamAV refuses to load
//!   sample bin "A\x12C" => Diff.Name
//!   sample 40*"A" x"00 ff" => OK
//!
//! Scanning follows clamscan: the hash stage, then the body stage over the raw bytes with the
//! file's target type, then (for text) the normalised bytes with target type 7. Executables get
//! their entry point and sections from zav's PE, ELF and Mach-O parsers.
const std = @import("std");
const Io = std.Io;
const zav = @import("zav");

const bodyscan = zav.engine.bodyscan;
const hashscan = zav.engine.hashscan;
const vm = zav.match.verify_vm;
const logical = zav.match.logical;
const regex = zav.regex;

/// The 8 bytes `bin` stands for in a sample: enough NULs that libclamav calls the file binary
/// data (and not text, whose normalised form is scanned too).
pub const bin_marker = "\xde\xad\xbe\xef\x00\x00\x00\x00";

pub const Sig = struct {
    /// Database extension: ndb, ldb, yar, hdb, ...
    ext: []const u8,
    text: []const u8,
    /// ClamAV refuses to load it (written `ndb!`).
    rejected: bool,
    line: usize,

    /// The name clamscan prints for this signature (without `.UNOFFICIAL`).
    pub fn name(s: Sig, buf: []u8) []const u8 {
        if (std.mem.eql(u8, s.ext, "yar")) {
            // YARA rules print as YARA.<rule>.
            var it = std.mem.tokenizeAny(u8, s.text, " \t{");
            while (it.next()) |tok| {
                if (std.mem.eql(u8, tok, "rule")) {
                    const rule = it.next() orelse return "";
                    return std.fmt.bufPrint(buf, "YARA.{s}", .{std.mem.trimEnd(u8, rule, ":")}) catch "";
                }
            }
            return "";
        }
        const sep: []const u8 = if (std.mem.eql(u8, s.ext, "ldb") or std.mem.eql(u8, s.ext, "ldu")) ";" else ":";
        if (isHashExt(s.ext)) {
            // hash:size:name[:flevel]
            var it = std.mem.splitScalar(u8, s.text, ':');
            _ = it.next();
            _ = it.next();
            return it.next() orelse "";
        }
        return s.text[0 .. std.mem.indexOf(u8, s.text, sep) orelse s.text.len];
    }

    /// Signatures that shape the scan rather than detect (allowlists, type magic, ignore lists)
    /// go into every database of their case.
    pub fn isContext(s: Sig) bool {
        for ([_][]const u8{ "ftm", "fp", "sfp", "ign2" }) |e| if (std.mem.eql(u8, s.ext, e)) return true;
        return false;
    }
};

fn isHashExt(ext: []const u8) bool {
    for ([_][]const u8{ "hdb", "hsb", "mdb", "msb", "imp", "fp", "sfp" }) |e| if (std.mem.eql(u8, ext, e)) return true;
    return false;
}

pub const Sample = struct {
    bytes: []const u8,
    /// Expected names, sorted, or empty for OK.
    expect: []const []const u8,
    line: usize,
};

pub const Case = struct {
    name: []const u8,
    file: []const u8,
    sigs: std.ArrayList(Sig) = .empty,
    samples: std.ArrayList(Sample) = .empty,
};

pub const ParseError = error{ BadCase, OutOfMemory };

/// Parse case files. Everything is allocated in `arena`.
pub fn parseCases(arena: std.mem.Allocator, file: []const u8, text: []const u8, out: *std.ArrayList(Case), diag: *Diag) ParseError!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_no: usize = 0;
    var current: ?*Case = null;
    var yara_buf: std.ArrayList(u8) = .empty;
    var yara_start: usize = 0;
    var in_yara = false;
    while (lines.next()) |raw| {
        line_no += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (in_yara) {
            if (std.mem.eql(u8, line, ">>")) {
                in_yara = false;
                try current.?.sigs.append(arena, .{ .ext = "yar", .text = try yara_buf.toOwnedSlice(arena), .rejected = false, .line = yara_start });
            } else {
                try yara_buf.appendSlice(arena, raw);
                try yara_buf.append(arena, '\n');
            }
            continue;
        }
        if (line.len == 0 or line[0] == '#') continue;
        const sp = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
        const word = line[0..sp];
        const rest = std.mem.trim(u8, line[sp..], " \t");
        if (std.mem.eql(u8, word, "case")) {
            const c = try out.addOne(arena);
            c.* = .{ .name = rest, .file = file };
            current = c;
            continue;
        }
        const c = current orelse return diag.fail(file, line_no, "a signature or sample before the first case");
        if (std.mem.eql(u8, word, "sample")) {
            try c.samples.append(arena, try parseSample(arena, rest, file, line_no, diag));
            continue;
        }
        if (std.mem.eql(u8, word, "yara") and std.mem.eql(u8, rest, "<<")) {
            in_yara = true;
            yara_buf = .empty;
            yara_start = line_no;
            continue;
        }
        const rejected = word.len > 0 and word[word.len - 1] == '!';
        const kw = if (rejected) word[0 .. word.len - 1] else word;
        const ext: []const u8 = if (std.mem.eql(u8, kw, "yara")) "yar" else for ([_][]const u8{ "ndb", "ndu", "ldb", "ldu", "hdb", "hsb", "mdb", "msb", "imp", "ftm", "cdb", "fp", "sfp", "ign2" }) |e| {
            if (std.mem.eql(u8, kw, e)) break e;
        } else return diag.fail(file, line_no, "unknown directive");
        if (rest.len == 0) return diag.fail(file, line_no, "empty signature");
        try c.sigs.append(arena, .{ .ext = ext, .text = rest, .rejected = rejected, .line = line_no });
    }
    if (in_yara) return diag.fail(file, yara_start, "unterminated yara <<");
}

pub const Diag = struct {
    buf: [512]u8 = undefined,
    msg: []const u8 = "",

    fn fail(d: *Diag, file: []const u8, line: usize, what: []const u8) ParseError {
        d.msg = std.fmt.bufPrint(&d.buf, "{s}:{d}: {s}", .{ file, line, what }) catch what;
        return error.BadCase;
    }
};

fn parseSample(arena: std.mem.Allocator, text: []const u8, file: []const u8, line: usize, diag: *Diag) ParseError!Sample {
    const arrow = std.mem.lastIndexOf(u8, text, "=>") orelse return diag.fail(file, line, "sample without => expectation");
    var bytes: std.ArrayList(u8) = .empty;
    var p = std.mem.trim(u8, text[0..arrow], " \t");
    while (p.len > 0) {
        var count: usize = 1;
        // N*TERM
        var digits: usize = 0;
        while (digits < p.len and std.ascii.isDigit(p[digits])) digits += 1;
        if (digits > 0 and digits < p.len and p[digits] == '*') {
            count = std.fmt.parseInt(usize, p[0..digits], 10) catch return diag.fail(file, line, "bad repeat count");
            if (count > 64 * 1024 * 1024) return diag.fail(file, line, "repeat count too large");
            p = p[digits + 1 ..];
        }
        var term: std.ArrayList(u8) = .empty;
        if (std.mem.startsWith(u8, p, "bin")) {
            try term.appendSlice(arena, bin_marker);
            p = p[3..];
        } else if (std.mem.startsWith(u8, p, "pad(")) {
            // Zero bytes up to an absolute offset.
            const close = std.mem.indexOfScalar(u8, p, ')') orelse return diag.fail(file, line, "unterminated pad(");
            const to = std.fmt.parseInt(usize, p[4..close], 0) catch return diag.fail(file, line, "bad pad offset");
            if (to < bytes.items.len or to > 64 * 1024 * 1024) return diag.fail(file, line, "pad offset behind the sample or too large");
            try term.appendNTimes(arena, 0, to - bytes.items.len);
            p = p[close + 1 ..];
        } else if (std.mem.startsWith(u8, p, "pe")) {
            // A PE32 header block (0x200 bytes), optionally with the entry point RVA: pe(0x1010).
            var ep: u32 = 0x1000;
            p = p[2..];
            if (p.len > 0 and p[0] == '(') {
                const close = std.mem.indexOfScalar(u8, p, ')') orelse return diag.fail(file, line, "unterminated pe(");
                ep = std.fmt.parseInt(u32, p[1..close], 0) catch return diag.fail(file, line, "bad pe entry point");
                p = p[close + 1 ..];
            }
            try term.appendSlice(arena, &peHeader(ep));
        } else if (p.len > 0 and (p[0] == '"' or (p[0] == 'x' and p.len > 1 and p[1] == '"'))) {
            const hex = p[0] == 'x';
            if (hex) p = p[1..];
            var i: usize = 1;
            while (i < p.len and p[i] != '"') : (i += 1) {
                if (p[i] == '\\') i += 1;
            }
            if (i >= p.len) return diag.fail(file, line, "unterminated string");
            const body = p[1..i];
            p = p[i + 1 ..];
            if (hex) {
                var nib: ?u8 = null;
                for (body) |ch| {
                    if (ch == ' ') continue;
                    const v = std.fmt.charToDigit(ch, 16) catch return diag.fail(file, line, "bad hex string");
                    if (nib) |hi| {
                        try term.append(arena, hi << 4 | v);
                        nib = null;
                    } else nib = v;
                }
                if (nib != null) return diag.fail(file, line, "odd hex string");
            } else {
                var j: usize = 0;
                while (j < body.len) : (j += 1) {
                    if (body[j] != '\\') {
                        try term.append(arena, body[j]);
                        continue;
                    }
                    j += 1;
                    if (j >= body.len) return diag.fail(file, line, "trailing backslash");
                    switch (body[j]) {
                        'x' => {
                            if (j + 2 >= body.len) return diag.fail(file, line, "short \\x escape");
                            const v = std.fmt.parseInt(u8, body[j + 1 .. j + 3], 16) catch return diag.fail(file, line, "bad \\x escape");
                            try term.append(arena, v);
                            j += 2;
                        },
                        '0' => try term.append(arena, 0),
                        'n' => try term.append(arena, '\n'),
                        'r' => try term.append(arena, '\r'),
                        't' => try term.append(arena, '\t'),
                        '\\', '"' => try term.append(arena, body[j]),
                        else => return diag.fail(file, line, "unknown escape"),
                    }
                }
            }
        } else return diag.fail(file, line, "bad sample term");
        for (0..count) |_| try bytes.appendSlice(arena, term.items);
        p = std.mem.trimStart(u8, p, " \t");
    }

    var names: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeAny(u8, text[arrow + 2 ..], " \t");
    while (it.next()) |tok| {
        if (std.mem.eql(u8, tok, "OK")) continue;
        try names.append(arena, tok);
    }
    std.mem.sort([]const u8, names.items, {}, lessString);
    return .{ .bytes = bytes.items, .expect = names.items, .line = line };
}

/// A minimal, valid PE32 header: two sections, .text at file 0x200 (RVA 0x1000) and .data at
/// file 0x400 (RVA 0x2000), each 0x200 bytes, file alignment 0x200. The caller supplies the
/// section bytes, so a complete file is 0x600 bytes.
pub fn peHeader(ep: u32) [0x200]u8 {
    var h: [0x200]u8 = @splat(0);
    h[0] = 'M';
    h[1] = 'Z';
    std.mem.writeInt(u32, h[0x3c..][0..4], 0x40, .little);
    @memcpy(h[0x40..0x44], "PE\x00\x00");
    const coff = h[0x44..];
    std.mem.writeInt(u16, coff[0..2], 0x14c, .little); // i386
    std.mem.writeInt(u16, coff[2..4], 2, .little); // sections
    std.mem.writeInt(u16, coff[16..18], 0xe0, .little); // optional header size
    std.mem.writeInt(u16, coff[18..20], 0x0102, .little); // executable, 32-bit
    const opt = h[0x58..];
    std.mem.writeInt(u16, opt[0..2], 0x10b, .little);
    std.mem.writeInt(u32, opt[4..8], 0x200, .little); // SizeOfCode
    std.mem.writeInt(u32, opt[8..12], 0x200, .little); // SizeOfInitializedData
    std.mem.writeInt(u32, opt[16..20], ep, .little);
    std.mem.writeInt(u32, opt[20..24], 0x1000, .little); // BaseOfCode
    std.mem.writeInt(u32, opt[24..28], 0x2000, .little); // BaseOfData
    std.mem.writeInt(u32, opt[28..32], 0x400000, .little); // ImageBase
    std.mem.writeInt(u32, opt[32..36], 0x1000, .little); // SectionAlignment
    std.mem.writeInt(u32, opt[36..40], 0x200, .little); // FileAlignment
    std.mem.writeInt(u16, opt[40..42], 4, .little); // OS version
    std.mem.writeInt(u16, opt[48..50], 4, .little); // subsystem version
    std.mem.writeInt(u32, opt[56..60], 0x3000, .little); // SizeOfImage
    std.mem.writeInt(u32, opt[60..64], 0x200, .little); // SizeOfHeaders
    std.mem.writeInt(u16, opt[68..70], 2, .little); // GUI
    std.mem.writeInt(u32, opt[72..76], 0x100000, .little);
    std.mem.writeInt(u32, opt[76..80], 0x1000, .little);
    std.mem.writeInt(u32, opt[80..84], 0x100000, .little);
    std.mem.writeInt(u32, opt[84..88], 0x1000, .little);
    std.mem.writeInt(u32, opt[92..96], 16, .little); // NumberOfRvaAndSizes
    const Sec = struct { name: []const u8, va: u32, raw: u32, flags: u32 };
    for ([_]Sec{
        .{ .name = ".text", .va = 0x1000, .raw = 0x200, .flags = 0x60000020 },
        .{ .name = ".data", .va = 0x2000, .raw = 0x400, .flags = 0xc0000040 },
    }, 0..) |sec, i| {
        const t = h[0x138 + 40 * i ..][0..40];
        @memcpy(t[0..sec.name.len], sec.name);
        std.mem.writeInt(u32, t[8..12], 0x200, .little); // VirtualSize
        std.mem.writeInt(u32, t[12..16], sec.va, .little);
        std.mem.writeInt(u32, t[16..20], 0x200, .little); // SizeOfRawData
        std.mem.writeInt(u32, t[20..24], sec.raw, .little);
        std.mem.writeInt(u32, t[36..40], sec.flags, .little);
    }
    return h;
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

// Scanning ---------------------------------------------------------------------------------------

/// One compiled database, ready to scan with.
pub const Engine = struct {
    database: zav.db.reader.Database,
    body: bodyscan.BodyIndex,
    hashes: hashscan.HashIndex,
    regex_mem: []align(8) u8 = &.{},
    regex_scratch: ?regex.Scratch = null,

    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8) !Engine {
        const database = try zav.db.reader.open(io, dir, path, .{ .allow_unsigned = true });
        errdefer database.close();
        var e: Engine = .{ .database = database, .body = try .load(database), .hashes = try .load(database) };
        if (e.body.regexes) |pool| {
            const capacity = pool.capacity(256);
            e.regex_mem = try gpa.alignedAlloc(u8, .@"8", regex.Scratch.bytesNeeded(capacity));
            e.regex_scratch = try regex.Scratch.initBuffer(e.regex_mem, capacity);
            e.regex_scratch.?.step_budget = 1 << 22;
        }
        return e;
    }

    pub fn close(e: *Engine, gpa: std.mem.Allocator) void {
        if (e.regex_mem.len > 0) gpa.free(e.regex_mem);
        e.database.close();
    }
};

pub const Result = union(enum) {
    clean,
    found: u32,
    limited: zav.engine.limits.Event,
};

/// Per-worker scan state: logical state in scratch, PE/ELF/Mach-O tables, a text buffer.
pub const Scanner = struct {
    gpa: std.mem.Allocator,
    io: Io,
    scratch: zav.engine.scratch.Scratch,
    state: logical.State,
    block: []u8,
    pe_sections: []zav.fmt.pe.Section,
    elf_segments: []zav.fmt.elf.Segment,
    elf_sections: []zav.fmt.elf.Section,
    macho_segments: []zav.fmt.macho.Segment,
    macho_sections: []zav.fmt.macho.Section,
    vm_sections: []vm.Section,
    norm: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator, io: Io) !*Scanner {
        const s = try gpa.create(Scanner);
        errdefer gpa.destroy(s);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .scratch = try .init(zav.engine.scratch.default_reservation),
            .state = undefined,
            .block = try gpa.alloc(u8, 64 * 1024),
            .pe_sections = try gpa.alloc(zav.fmt.pe.Section, 96),
            .elf_segments = try gpa.alloc(zav.fmt.elf.Segment, 256),
            .elf_sections = try gpa.alloc(zav.fmt.elf.Section, 1024),
            .macho_segments = try gpa.alloc(zav.fmt.macho.Segment, 256),
            .macho_sections = try gpa.alloc(zav.fmt.macho.Section, 1024),
            .vm_sections = try gpa.alloc(vm.Section, 1024),
        };
        s.state = try logical.State.init(s.scratch.allocator());
        return s;
    }

    pub fn deinit(s: *Scanner) void {
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

    /// What zav knows about a file before matching: its target type and executable layout.
    pub const Classified = struct {
        format: zav.fmt.detect.Format,
        file: bodyscan.File,
        pe: ?zav.fmt.pe.Info = null,
    };

    pub fn classify(s: *Scanner, data: []const u8) Classified {
        const format = zav.fmt.detect.detect(data[0..@min(data.len, zav.fmt.detect.head_len)]);
        var out: Classified = .{ .format = format, .file = .{ .info = .{ .size = data.len } } };
        const src: zav.engine.source.Source = .{ .memory = data };
        switch (format) {
            .pe => if (zav.fmt.pe.parse(s.io, src, s.pe_sections)) |info| {
                out.pe = info;
                out.file.target = 1;
                out.file.info.entry_point = info.ep_offset;
                const n = @min(info.sections.len, s.vm_sections.len);
                for (info.sections[0..n], s.vm_sections[0..n]) |sec, *v| v.* = .{ .offset = sec.raw_off, .size = sec.raw_size };
                out.file.info.sections = s.vm_sections[0..n];
            } else |_| {},
            .elf => if (zav.fmt.elf.parse(s.io, src, s.elf_segments, s.elf_sections)) |info| {
                out.file.target = 6;
                out.file.info.entry_point = info.ep_offset;
                const n = @min(info.sections.len, s.vm_sections.len);
                for (info.sections[0..n], s.vm_sections[0..n]) |sec, *v| v.* = .{ .offset = sec.offset, .size = sec.size };
                out.file.info.sections = s.vm_sections[0..n];
            } else |_| {},
            .macho => if (zav.fmt.macho.parse(s.io, src, s.macho_segments, s.macho_sections)) |info| {
                out.file.target = 9;
                out.file.info.entry_point = info.ep_offset;
                const n = @min(info.sections.len, s.vm_sections.len);
                for (info.sections[0..n], s.vm_sections[0..n]) |sec, *v| v.* = .{ .offset = sec.offset, .size = sec.size };
                out.file.info.sections = s.vm_sections[0..n];
            } else |_| {},
            else => {},
        }
        return out;
    }

    /// Scan one file's bytes with one database: the first detection, like clamscan without
    /// --allmatch.
    pub fn scan(s: *Scanner, e: *Engine, data: []const u8) !Result {
        if (data.len < zav.engine.limits.min_scan_size) return .clean;
        var tracker = zav.engine.limits.Tracker.init(.{});
        const src: zav.engine.source.Source = .{ .memory = data };
        switch (try hashscan.scanSource(s.io, &e.hashes, src, &tracker, s.block)) {
            .infected => |sig| return .{ .found = sig },
            .limited => |ev| return .{ .limited = ev },
            .clean, .allowed => {},
        }
        const c = s.classify(data);
        if (c.pe) |*info| switch (hashscan.scanPe(s.io, &e.hashes, src, info, s.block)) {
            .infected => |sig| return .{ .found = sig },
            else => {},
        };

        var limited: ?zav.engine.limits.Event = null;
        switch (try s.body(e, data, c.file, &tracker)) {
            .infected => |d| return .{ .found = d.sig },
            .limited => |ev| limited = ev,
            .clean => {},
        }
        if (c.format == .text) {
            // Target 7 (and type-0) signatures also run over the normalised text.
            s.norm.clearRetainingCapacity();
            try s.norm.resize(s.gpa, data.len);
            var n: zav.fmt.text_norm.Normalizer = .{};
            const len = n.feed(data, s.norm.items);
            const text = s.norm.items[0..len];
            switch (try s.body(e, text, .{ .info = .{ .size = text.len }, .target = 7 }, &tracker)) {
                .infected => |d| return .{ .found = d.sig },
                .limited => |ev| limited = limited orelse ev,
                .clean => {},
            }
        }
        if (limited) |ev| return .{ .limited = ev };
        return .clean;
    }

    fn body(s: *Scanner, e: *Engine, data: []const u8, file: bodyscan.File, tracker: *zav.engine.limits.Tracker) !bodyscan.Verdict {
        s.state.reset();
        s.state.regex_scratch = if (e.regex_scratch) |*r| r else null;
        var budget: vm.Budget = .{};
        return bodyscan.scanBuffer(&e.body, data, file, &budget, tracker, &s.state);
    }
};

// Commands ---------------------------------------------------------------------------------------

const App = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    err: *Io.Writer,
};

pub fn main(init: std.process.Init) !u8 {
    var out_buf: [16 * 1024]u8 = undefined;
    var out = Io.File.stdout().writerStreaming(init.io, &out_buf);
    var err_buf: [4096]u8 = undefined;
    var err = Io.File.stderr().writerStreaming(init.io, &err_buf);
    defer out.interface.flush() catch {};
    defer err.interface.flush() catch {};
    const app: App = .{ .gpa = init.gpa, .arena = init.arena.allocator(), .io = init.io, .out = &out.interface, .err = &err.interface };

    const args = try init.minimal.args.toSlice(app.arena);
    if (args.len < 2) return usage(app);
    const cmd = args[1];
    const rest = args[2..];
    if (std.mem.eql(u8, cmd, "check")) return check(app, rest);
    if (std.mem.eql(u8, cmd, "materialize")) return materialize(app, rest);
    if (std.mem.eql(u8, cmd, "scan")) return scanCmd(app, rest);
    return usage(app);
}

fn usage(app: App) !u8 {
    try app.err.writeAll(
        \\usage: zav-diff check [--tmp DIR] [--known FILE] CASES...
        \\       zav-diff materialize --out DIR CASES...
        \\       zav-diff scan [--tmp DIR] [--per-sig] --sigs FILE... -- PATH...
        \\
    );
    return 2;
}

fn loadCases(app: App, paths: []const []const u8) !std.ArrayList(Case) {
    var cases: std.ArrayList(Case) = .empty;
    // A directory stands for the .case files in it, in name order.
    var files: std.ArrayList([]const u8) = .empty;
    for (paths) |path| {
        var dir = Io.Dir.cwd().openDir(app.io, path, .{ .iterate = true }) catch {
            try files.append(app.arena, path);
            continue;
        };
        defer dir.close(app.io);
        const first = files.items.len;
        var it = dir.iterate();
        while (try it.next(app.io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".case")) continue;
            try files.append(app.arena, try std.fs.path.join(app.arena, &.{ path, entry.name }));
        }
        std.mem.sort([]const u8, files.items[first..], {}, lessString);
    }
    for (files.items) |path| {
        const text = try Io.Dir.cwd().readFileAlloc(app.io, path, app.arena, .limited(64 * 1024 * 1024));
        var diag: Diag = .{};
        parseCases(app.arena, path, text, &cases, &diag) catch |e| {
            try app.err.print("zav-diff: {s}\n", .{diag.msg});
            return e;
        };
    }
    // Case names must be unique: they key the known-differences list and the output directories.
    for (cases.items, 0..) |a, i| for (cases.items[i + 1 ..]) |b| {
        if (std.mem.eql(u8, a.name, b.name)) {
            try app.err.print("zav-diff: duplicate case {s} ({s}, {s})\n", .{ a.name, a.file, b.file });
            return error.BadCase;
        }
    };
    return cases;
}

fn dbFileName(buf: []u8, base: []const u8, ext: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}.{s}", .{ base, ext }) catch unreachable;
}

const Compiled = struct {
    /// The compiler refused the signature (or skipped it: flevel, ignored).
    rejected: bool,
    path: []const u8,
};

/// Compile `sig` (plus the case's context signatures) into DIR/PATH.
fn compileSig(app: App, dir: Io.Dir, path: []const u8, case: Case, sig: ?Sig) !Compiled {
    var c = zav.compile.compiler.Compiler.init(app.gpa);
    defer c.deinit();
    var name_buf: [64]u8 = undefined;
    for (case.sigs.items) |ctx| {
        if (!ctx.isContext() or ctx.rejected) continue;
        if (sig) |s| if (s.line == ctx.line) continue;
        try addSigText(&c, &name_buf, ctx);
    }
    var rejected = false;
    if (sig) |s| {
        const before = c.rejected.items.len;
        try addSigText(&c, &name_buf, s);
        rejected = c.rejected.items.len != before;
    }
    // A signature skipped for its functionality level counts as loaded, as clamscan loads it
    // without an error and without the signature.
    _ = try c.write(app.io, dir, path, .{ .db_version = 1 });
    return .{ .rejected = rejected, .path = path };
}

fn addSigText(c: *zav.compile.compiler.Compiler, name_buf: []u8, s: Sig) !void {
    const text = if (std.mem.eql(u8, s.ext, "yar")) s.text else blk: {
        // One line, newline-terminated.
        break :blk s.text;
    };
    try c.addFile(dbFileName(name_buf, "case", s.ext), text);
}

const Known = struct {
    case: []const u8,
    sample: usize,
    /// zav's result as printed in reports: OK, names, LIMITED(event), REJECTS, LOADS.
    zav: []const u8,
    used: bool = false,
};

fn loadKnown(app: App, path: ?[]const u8) !std.ArrayList(Known) {
    var list: std.ArrayList(Known) = .empty;
    const p = path orelse return list;
    const text = try Io.Dir.cwd().readFileAlloc(app.io, p, app.arena, .limited(16 * 1024 * 1024));
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |raw| {
        n += 1;
        const line = std.mem.trim(u8, raw[0 .. std.mem.indexOfScalar(u8, raw, '#') orelse raw.len], " \t\r");
        if (line.len == 0) continue;
        // CASE sN|sigN zav=RESULT
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const case = it.next() orelse continue;
        const which = it.next() orelse {
            try app.err.print("zav-diff: {s}:{d}: missing sample\n", .{ p, n });
            return error.BadKnown;
        };
        const result = std.mem.trim(u8, it.rest(), " \t");
        if (!std.mem.startsWith(u8, result, "zav=")) {
            try app.err.print("zav-diff: {s}:{d}: expected zav=RESULT\n", .{ p, n });
            return error.BadKnown;
        }
        const idx = if (std.mem.startsWith(u8, which, "sig"))
            1_000_000 + (std.fmt.parseInt(usize, which[3..], 10) catch return error.BadKnown)
        else if (std.mem.startsWith(u8, which, "s"))
            std.fmt.parseInt(usize, which[1..], 10) catch return error.BadKnown
        else
            return error.BadKnown;
        try list.append(app.arena, .{ .case = case, .sample = idx, .zav = result[4..] });
    }
    return list;
}

fn findKnown(known: []Known, case: []const u8, idx: usize) ?*Known {
    for (known) |*k| if (k.sample == idx and std.mem.eql(u8, k.case, case)) return k;
    return null;
}

fn check(app: App, args: []const []const u8) !u8 {
    var tmp_path: []const u8 = ".zav-diff-tmp";
    var known_path: ?[]const u8 = null;
    var paths: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--tmp") and i + 1 < args.len) {
            i += 1;
            tmp_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--known") and i + 1 < args.len) {
            i += 1;
            known_path = args[i];
        } else try paths.append(app.arena, args[i]);
    }
    const cases = try loadCases(app, paths.items);
    const known = try loadKnown(app, known_path);
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(app.io, tmp_path);
    var tmp = try cwd.openDir(app.io, tmp_path, .{});
    defer tmp.close(app.io);

    const scanner = try Scanner.init(app.gpa, app.io);
    defer scanner.deinit();

    var agree: usize = 0;
    var known_hits: usize = 0;
    var failures: usize = 0;
    var total: usize = 0;
    for (cases.items) |case| {
        // results[sample] = names zav found.
        const results = try app.arena.alloc(std.ArrayList([]const u8), case.samples.items.len);
        for (results) |*r| r.* = .empty;
        for (case.sigs.items, 0..) |sig, si| {
            if (sig.isContext() and !sig.rejected) continue;
            const compiled = try compileSig(app, tmp, "sig.zavdb", case, sig);
            var name_buf: [256]u8 = undefined;
            const sig_name = sig.name(&name_buf);
            // Load parity: ClamAV loads it exactly when zav compiles it.
            if (compiled.rejected != sig.rejected) {
                total += 1;
                const got: []const u8 = if (compiled.rejected) "REJECTS" else "LOADS";
                if (findKnown(known.items, case.name, 1_000_000 + si + 1)) |k| {
                    k.used = true;
                    if (std.mem.eql(u8, k.zav, got)) {
                        known_hits += 1;
                    } else {
                        failures += 1;
                        try app.out.print("FAIL {s} sig{d} ({s}:{d}): known says zav={s}, zav {s}\n", .{ case.name, si + 1, case.file, sig.line, k.zav, got });
                    }
                } else {
                    failures += 1;
                    try app.out.print("FAIL {s} sig{d} ({s}:{d}): libclamav {s}, zav {s}: {s}\n", .{ case.name, si + 1, case.file, sig.line, if (sig.rejected) "rejects" else "loads", got, sig.text });
                }
            } else {
                total += 1;
                agree += 1;
                if (findKnown(known.items, case.name, 1_000_000 + si + 1)) |k| {
                    k.used = true;
                    failures += 1;
                    try app.out.print("FAIL {s} sig{d}: listed as a known difference, but zav now agrees\n", .{ case.name, si + 1 });
                }
            }
            if (compiled.rejected or sig.rejected) continue;
            var engine = try Engine.open(app.gpa, app.io, tmp, compiled.path);
            defer engine.close(app.gpa);
            for (case.samples.items, results) |sample, *r| {
                switch (try scanner.scan(&engine, sample.bytes)) {
                    .clean => {},
                    .found => try r.append(app.arena, try app.arena.dupe(u8, sig_name)),
                    .limited => |ev| try r.append(app.arena, try std.fmt.allocPrint(app.arena, "LIMITED({t})", .{ev})),
                }
            }
        }
        for (case.samples.items, results, 0..) |sample, *r, n| {
            total += 1;
            std.mem.sort([]const u8, r.items, {}, lessString);
            const got = try joinResult(app.arena, r.items);
            const want = try joinResult(app.arena, sample.expect);
            const same = std.mem.eql(u8, got, want);
            const k = findKnown(known.items, case.name, n + 1);
            if (k) |kk| kk.used = true;
            if (same) {
                agree += 1;
                if (k != null) {
                    failures += 1;
                    try app.out.print("FAIL {s} s{d}: listed as a known difference, but zav now agrees ({s})\n", .{ case.name, n + 1, got });
                }
            } else if (k != null and std.mem.eql(u8, k.?.zav, got)) {
                known_hits += 1;
            } else {
                failures += 1;
                try app.out.print("FAIL {s} s{d} ({s}:{d}): libclamav {s}, zav {s}\n", .{ case.name, n + 1, case.file, sample.line, want, got });
            }
        }
    }
    for (known.items) |k| if (!k.used) {
        failures += 1;
        try app.out.print("FAIL known difference {s} {d} matches no case or sample\n", .{ k.case, k.sample });
    };
    try app.out.print("zav-diff: {d} cases, {d} checks: {d} agree, {d} known differences, {d} failures\n", .{ cases.items.len, total, agree, known_hits, failures });
    return if (failures == 0) 0 else 1;
}

fn joinResult(arena: std.mem.Allocator, names: []const []const u8) ![]const u8 {
    if (names.len == 0) return "OK";
    // Dedupe (clamscan --allmatch can print a name twice).
    var out: std.ArrayList(u8) = .empty;
    var last: []const u8 = "";
    for (names) |n| {
        if (std.mem.eql(u8, n, last)) continue;
        if (out.items.len > 0) try out.append(arena, ' ');
        try out.appendSlice(arena, n);
        last = n;
    }
    return out.items;
}

fn materialize(app: App, args: []const []const u8) !u8 {
    var out_path: ?[]const u8 = null;
    var paths: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else try paths.append(app.arena, args[i]);
    }
    const root_path = out_path orelse return usage(app);
    const cases = try loadCases(app, paths.items);
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(app.io, root_path);
    var root = try cwd.openDir(app.io, root_path, .{});
    defer root.close(app.io);
    var index: std.ArrayList(u8) = .empty;
    for (cases.items) |case| {
        try root.createDirPath(app.io, case.name);
        var dir = try root.openDir(app.io, case.name, .{});
        defer dir.close(app.io);
        // all.<ext>: every signature ClamAV should load, grouped by extension.
        var exts: std.ArrayList([]const u8) = .empty;
        for (case.sigs.items) |s| {
            for (exts.items) |e| {
                if (std.mem.eql(u8, e, s.ext)) break;
            } else try exts.append(app.arena, s.ext);
        }
        var manifest: std.ArrayList(u8) = .empty;
        var name_buf: [64]u8 = undefined;
        for (exts.items) |ext| {
            var text: std.ArrayList(u8) = .empty;
            for (case.sigs.items) |s| {
                if (s.rejected or !std.mem.eql(u8, s.ext, ext)) continue;
                try text.appendSlice(app.arena, s.text);
                if (text.items.len > 0 and text.items[text.items.len - 1] != '\n') try text.append(app.arena, '\n');
            }
            if (text.items.len == 0) continue;
            const fname = dbFileName(&name_buf, "all", ext);
            try dir.writeFile(app.io, .{ .sub_path = fname, .data = text.items });
            try manifest.print(app.arena, "db {s}\n", .{fname});
        }
        for (case.sigs.items, 0..) |s, n| {
            var base_buf: [32]u8 = undefined;
            const base = try std.fmt.bufPrint(&base_buf, "sig{d}", .{n + 1});
            const fname = dbFileName(&name_buf, base, s.ext);
            const data = if (s.text.len > 0 and s.text[s.text.len - 1] == '\n') s.text else try std.fmt.allocPrint(app.arena, "{s}\n", .{s.text});
            try dir.writeFile(app.io, .{ .sub_path = fname, .data = data });
            var sig_name_buf: [256]u8 = undefined;
            try manifest.print(app.arena, "sig {d} {s} {d} {s} {s}\n", .{ n + 1, fname, s.line, if (s.rejected) "rejects" else "loads", s.name(&sig_name_buf) });
        }
        for (case.samples.items, 0..) |sample, n| {
            var sname_buf: [32]u8 = undefined;
            const sname = try std.fmt.bufPrint(&sname_buf, "s{d}", .{n + 1});
            try dir.writeFile(app.io, .{ .sub_path = sname, .data = sample.bytes });
            try manifest.print(app.arena, "sample {d} {s} {d} {s}\n", .{ n + 1, sname, sample.line, try joinResult(app.arena, sample.expect) });
        }
        try dir.writeFile(app.io, .{ .sub_path = "manifest", .data = manifest.items });
        try index.print(app.arena, "{s}\t{s}\n", .{ case.name, case.file });
    }
    try root.writeFile(app.io, .{ .sub_path = "cases", .data = index.items });
    try app.out.print("zav-diff: wrote {d} cases to {s}\n", .{ cases.items.len, root_path });
    return 0;
}

fn scanCmd(app: App, args: []const []const u8) !u8 {
    var tmp_path: []const u8 = ".zav-diff-tmp";
    var per_sig = false;
    var sig_files: std.ArrayList([]const u8) = .empty;
    var targets: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    var in_sigs = false;
    var in_targets = false;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (in_targets) {
            try targets.append(app.arena, a);
        } else if (std.mem.eql(u8, a, "--")) {
            in_targets = true;
        } else if (std.mem.eql(u8, a, "--tmp") and i + 1 < args.len) {
            i += 1;
            tmp_path = args[i];
        } else if (std.mem.eql(u8, a, "--per-sig")) {
            per_sig = true;
        } else if (std.mem.eql(u8, a, "--sigs")) {
            in_sigs = true;
        } else if (in_sigs) {
            try sig_files.append(app.arena, a);
        } else return usage(app);
    }
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(app.io, tmp_path);
    var tmp = try cwd.openDir(app.io, tmp_path, .{});
    defer tmp.close(app.io);
    const scanner = try Scanner.init(app.gpa, app.io);
    defer scanner.deinit();

    // Every signature as a (file name, line) pair; whole files when not per-sig.
    const Unit = struct { name: []const u8, text: []const u8 };
    var units: std.ArrayList(Unit) = .empty;
    for (sig_files.items) |path| {
        const text = try cwd.readFileAlloc(app.io, path, app.arena, .limited(1 << 30));
        const base = std.fs.path.basename(path);
        if (!per_sig or std.mem.endsWith(u8, base, ".yar") or std.mem.endsWith(u8, base, ".yara")) {
            try units.append(app.arena, .{ .name = base, .text = text });
            continue;
        }
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (std.mem.trim(u8, line, " \r\t").len == 0) continue;
            try units.append(app.arena, .{ .name = base, .text = line });
        }
    }
    const datas = try app.arena.alloc([]const u8, targets.items.len);
    for (targets.items, datas) |path, *d| d.* = cwd.readFileAlloc(app.io, path, app.arena, .limited(1 << 30)) catch |e| blk: {
        try app.out.print("{s}: {t} ERROR\n", .{ path, e });
        break :blk &.{};
    };
    const results = try app.arena.alloc(std.ArrayList([]const u8), targets.items.len);
    for (results) |*r| r.* = .empty;

    var group_start: usize = 0;
    while (group_start < units.items.len) {
        var c = zav.compile.compiler.Compiler.init(app.gpa);
        defer c.deinit();
        var group_end = group_start + 1;
        try c.addFile(units.items[group_start].name, units.items[group_start].text);
        if (!per_sig) {
            while (group_end < units.items.len) : (group_end += 1) try c.addFile(units.items[group_end].name, units.items[group_end].text);
        }
        group_start = group_end;
        const summary = try c.write(app.io, tmp, "scan.zavdb", .{ .db_version = 1 });
        if (summary.signatures == 0) continue;
        var engine = try Engine.open(app.gpa, app.io, tmp, "scan.zavdb");
        defer engine.close(app.gpa);
        var name_buf: [512]u8 = undefined;
        for (datas, results) |data, *r| {
            switch (try scanner.scan(&engine, data)) {
                .clean => {},
                .found => |sig| {
                    const name = if (engine.hashes.meta) |m| try m.name(sig, &name_buf) else "unknown";
                    try r.append(app.arena, try app.arena.dupe(u8, name));
                },
                .limited => |ev| try r.append(app.arena, try std.fmt.allocPrint(app.arena, "LIMITED({t})", .{ev})),
            }
        }
    }
    var found = false;
    for (targets.items, results) |path, r| {
        if (r.items.len == 0) {
            try app.out.print("{s}: OK\n", .{path});
            continue;
        }
        for (r.items) |name| {
            if (std.mem.startsWith(u8, name, "LIMITED(")) {
                try app.out.print("{s}: {s}\n", .{ path, name });
            } else {
                found = true;
                try app.out.print("{s}: {s} FOUND\n", .{ path, name });
            }
        }
    }
    return if (found) 1 else 0;
}

test "sample terms" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var diag: Diag = .{};
    const s = try parseSample(arena_state.allocator(), "bin \"A\\x12C\" 3*\"z\" x\"00 ff\" => B A", "t", 1, &diag);
    try std.testing.expectEqualSlices(u8, bin_marker ++ "A\x12Czzz\x00\xff", s.bytes);
    try std.testing.expectEqual(@as(usize, 2), s.expect.len);
    try std.testing.expectEqualStrings("A", s.expect[0]);
}
