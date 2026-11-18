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
        } else if (std.mem.startsWith(u8, p, "elf")) {
            // An ELF64 x86_64 executable header block (0x140 bytes): .text at file 0x140 and
            // .data at 0x240, 0x100 bytes each, one PT_LOAD over the file, entry at 0x140.
            try term.appendSlice(arena, &elfHeader());
            p = p[3..];
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

pub fn elfHeader() [0x140]u8 {
    var h: [0x140]u8 = @splat(0);
    @memcpy(h[0..4], "\x7fELF");
    h[4] = 2; // 64-bit
    h[5] = 1; // little-endian
    h[6] = 1;
    std.mem.writeInt(u16, h[16..18], 2, .little); // ET_EXEC
    std.mem.writeInt(u16, h[18..20], 62, .little); // x86_64
    std.mem.writeInt(u32, h[20..24], 1, .little);
    std.mem.writeInt(u64, h[24..32], 0x400140, .little); // entry
    std.mem.writeInt(u64, h[32..40], 0x40, .little); // phoff
    std.mem.writeInt(u64, h[40..48], 0x78, .little); // shoff
    std.mem.writeInt(u16, h[52..54], 64, .little);
    std.mem.writeInt(u16, h[54..56], 56, .little);
    std.mem.writeInt(u16, h[56..58], 1, .little);
    std.mem.writeInt(u16, h[58..60], 64, .little);
    std.mem.writeInt(u16, h[60..62], 3, .little);
    const ph = h[0x40..0x78];
    std.mem.writeInt(u32, ph[0..4], 1, .little); // PT_LOAD
    std.mem.writeInt(u32, ph[4..8], 5, .little); // R+X
    std.mem.writeInt(u64, ph[16..24], 0x400000, .little);
    std.mem.writeInt(u64, ph[24..32], 0x400000, .little);
    std.mem.writeInt(u64, ph[32..40], 0x340, .little);
    std.mem.writeInt(u64, ph[40..48], 0x340, .little);
    std.mem.writeInt(u64, ph[48..56], 0x1000, .little);
    for ([_][2]u64{ .{ 0x140, 6 }, .{ 0x240, 3 } }, 1..) |sec, i| {
        const sh = h[0x78 + 64 * i ..][0..64];
        std.mem.writeInt(u32, sh[4..8], 1, .little); // PROGBITS
        std.mem.writeInt(u64, sh[8..16], sec[1], .little); // flags
        std.mem.writeInt(u64, sh[16..24], 0x400000 + sec[0], .little);
        std.mem.writeInt(u64, sh[24..32], sec[0], .little);
        std.mem.writeInt(u64, sh[32..40], 0x100, .little);
        std.mem.writeInt(u64, sh[48..56], 16, .little);
    }
    return h;
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
                out.file.info.entry_point = info.matchEntryPoint();
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
    if (std.mem.eql(u8, cmd, "rejects")) return rejects(app, rest);
    if (std.mem.eql(u8, cmd, "info")) return infoCmd(app, rest);
    if (std.mem.eql(u8, cmd, "normalize")) return normalizeCmd(app, rest);
    if (std.mem.eql(u8, cmd, "roundtrip")) return roundtripCmd(app, rest);
    return usage(app);
}

fn usage(app: App) !u8 {
    try app.err.writeAll(
        \\usage: zav-diff check [--tmp DIR] [--known FILE] CASES...
        \\       zav-diff materialize --out DIR CASES...
        \\       zav-diff scan [--tmp DIR] [--per-sig] --sigs FILE... -- PATH...
        \\       zav-diff rejects FILE...
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
    // --print: also write zav's own verdicts (`LOAD case sigN LOADS|REJECTS`, `RESULT case sN
    // names`) for every signature zav loads, for comparisons with other engines (yara).
    var print = false;
    // --refusals-known: a signature zav refuses with a reason counts as a known difference (for
    // cases generated from the databases, where the refusals are tallied by reason elsewhere).
    var refusals_known = false;
    var refused: usize = 0;
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
        } else if (std.mem.eql(u8, args[i], "--print")) {
            print = true;
        } else if (std.mem.eql(u8, args[i], "--refusals-known")) {
            refusals_known = true;
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
        const own = try app.arena.alloc(std.ArrayList([]const u8), case.samples.items.len);
        for (own) |*r| r.* = .empty;
        // Signatures zav refuses as a listed known difference: their matches are left out of
        // the expectations, since the refusal is the difference.
        var excused: std.ArrayList([]const u8) = .empty;
        for (case.sigs.items, 0..) |sig, si| {
            if (sig.isContext() and !sig.rejected) continue;
            const compiled = try compileSig(app, tmp, "sig.zavdb", case, sig);
            var name_buf: [256]u8 = undefined;
            const sig_name = sig.name(&name_buf);
            // Load parity: ClamAV loads it exactly when zav compiles it.
            if (compiled.rejected != sig.rejected) {
                total += 1;
                const got: []const u8 = if (compiled.rejected) "REJECTS" else "LOADS";
                if (refusals_known and compiled.rejected) {
                    refused += 1;
                    known_hits += 1;
                    try excused.append(app.arena, try app.arena.dupe(u8, sig_name));
                } else if (findKnown(known.items, case.name, 1_000_000 + si + 1)) |k| {
                    k.used = true;
                    if (std.mem.eql(u8, k.zav, got)) {
                        known_hits += 1;
                        if (compiled.rejected) try excused.append(app.arena, try app.arena.dupe(u8, sig_name));
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
            if (print) try app.out.print("LOAD {s} sig{d} {s}\n", .{ case.name, si + 1, if (compiled.rejected) "REJECTS" else "LOADS" });
            if (compiled.rejected or (sig.rejected and !print)) continue;
            var engine = try Engine.open(app.gpa, app.io, tmp, compiled.path);
            defer engine.close(app.gpa);
            for (case.samples.items, results, own) |sample, *r, *o| {
                const name: ?[]const u8 = switch (try scanner.scan(&engine, sample.bytes)) {
                    .clean => null,
                    .found => try app.arena.dupe(u8, sig_name),
                    .limited => |ev| try std.fmt.allocPrint(app.arena, "LIMITED({t})", .{ev}),
                };
                const n = name orelse continue;
                try o.append(app.arena, n);
                if (!sig.rejected) try r.append(app.arena, n);
            }
        }
        if (print) for (own, 0..) |*o, n| {
            std.mem.sort([]const u8, o.items, {}, lessString);
            try app.out.print("RESULT {s} s{d} {s}\n", .{ case.name, n + 1, try joinResult(app.arena, o.items) });
        };
        for (case.samples.items, results, 0..) |sample, *r, n| {
            total += 1;
            std.mem.sort([]const u8, r.items, {}, lessString);
            const got = try joinResult(app.arena, r.items);
            var expect: std.ArrayList([]const u8) = .empty;
            for (sample.expect) |name| {
                for (excused.items) |e| {
                    if (std.mem.eql(u8, e, name)) break;
                } else try expect.append(app.arena, name);
            }
            const want = try joinResult(app.arena, expect.items);
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
    try app.out.print("zav-diff: {d} cases, {d} checks: {d} agree, {d} known differences ({d} signatures zav refuses), {d} failures\n", .{ cases.items.len, total, agree, known_hits, refused, failures });
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

/// `roundtrip FILE...`: parse every hex body of the .ndb/.ndu and .ldb/.ldu files (logical
/// subsigs without their offset and modifiers) and print it back; the text must come back as
/// written, modulo letter case and whitespace (P4.01). Prints each difference, then the counts.
fn roundtripCmd(app: App, args: []const []const u8) !u8 {
    var bodies: usize = 0;
    var same: usize = 0;
    var refused: usize = 0;
    var differ: usize = 0;
    for (args) |path| {
        const text = try Io.Dir.cwd().readFileAlloc(app.io, path, app.arena, .limited(1 << 30));
        const ext = std.fs.path.extension(path);
        const is_ldb = std.mem.eql(u8, ext, ".ldb") or std.mem.eql(u8, ext, ".ldu");
        var lines = std.mem.splitScalar(u8, text, '\n');
        var line_no: usize = 0;
        while (lines.next()) |raw| {
            line_no += 1;
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (line.len == 0 or line[0] == '#') continue;
            var arena_state = std.heap.ArenaAllocator.init(app.gpa);
            defer arena_state.deinit();
            const a = arena_state.allocator();
            var fields = std.mem.splitScalar(u8, line, if (is_ldb) ';' else ':');
            var i: usize = 0;
            while (fields.next()) |f| : (i += 1) {
                var body = f;
                var options: zav.compile.hexsig.Options = .{ .literal_pairs = true };
                if (is_ldb) {
                    // (A ';' inside a PCRE subsig splits it here; its pieces are skipped.)
                    if (i < 3 or f.len == 0 or std.mem.indexOfScalar(u8, f, '/') != null or std.mem.indexOfScalar(u8, f, '#') != null or std.mem.startsWith(u8, f, "${")) continue;
                    if (std.mem.lastIndexOf(u8, body, "::")) |m| {
                        const mods = zav.compile.hexsig.parseModifiers(body[m + 2 ..]) catch zav.compile.ir.Modifiers{};
                        options = zav.compile.hexsig.clamavOptions(mods);
                        body = body[0..m];
                    }
                    if (std.mem.lastIndexOfScalar(u8, body, ':')) |c| body = body[c + 1 ..];
                } else if (i != 3) continue;
                bodies += 1;
                var diag: zav.compile.hexsig.Diag = .{};
                const pattern = zav.compile.hexsig.parseWith(a, body, &diag, options) catch |e| {
                    refused += 1;
                    try app.out.print("{s}:{d}: refused ({t} at {d}): {s}\n", .{ path, line_no, e, diag.pos, body[0..@min(body.len, 200)] });
                    continue;
                };
                var buf: std.Io.Writer.Allocating = .init(a);
                try zav.compile.hexsig.format(pattern, &buf.writer);
                const printed = buf.written();
                if (equalLoose(printed, body)) {
                    same += 1;
                } else {
                    differ += 1;
                    try app.out.print("{s}:{d}: {s}\n    printed {s}\n", .{ path, line_no, body, printed });
                }
            }
        }
    }
    try app.out.print("zav-diff roundtrip: {d} bodies, {d} print back as written, {d} differ, {d} refused\n", .{ bodies, same, differ, refused });
    return if (differ == 0) 0 else 1;
}

fn equalLoose(a: []const u8, b: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (true) {
        while (i < a.len and (a[i] == ' ' or a[i] == '\t')) i += 1;
        while (j < b.len and (b[j] == ' ' or b[j] == '\t')) j += 1;
        if (i == a.len or j == b.len) return i == a.len and j == b.len;
        if (std.ascii.toLower(a[i]) != std.ascii.toLower(b[j])) return false;
        i += 1;
        j += 1;
    }
}

/// `normalize text|html|notags|js FILE`: zav's target-7 normalised text, or the target-3 forms
/// of an HTML file (libclamav's nocomment.html, notags.html and `javascript`), on stdout, for
/// comparison with libclamav's (tools/diff/norm.py).
fn normalizeCmd(app: App, args: []const []const u8) !u8 {
    if (args.len != 2) return usage(app);
    const data = try Io.Dir.cwd().readFileAlloc(app.io, args[1], app.arena, .limited(1 << 30));
    if (std.mem.eql(u8, args[0], "text")) {
        const out = try app.arena.alloc(u8, data.len);
        var n: zav.fmt.text_norm.Normalizer = .{};
        try app.out.writeAll(out[0..n.feed(data, out)]);
        return 0;
    }
    const Sink = struct {
        list: std.ArrayList(u8) = .empty,
        arena: std.mem.Allocator,
        js: zav.fmt.js_norm.Normalizer = undefined,
        start: usize = 0,
        fn write(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.list.appendSlice(self.arena, bytes) catch return error.Stop;
        }
        // libclamav's `javascript` file: each script as <script>...</script>, newline separated.
        fn begin(ctx: *anyopaque) error{Stop}!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.list.items.len > 0) try write(ctx, "\n");
            self.start = self.list.items.len;
            try write(ctx, "<script>");
            self.js = .init(.{ .ctx = ctx, .write = write });
        }
        fn piece(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            try self.js.feed(bytes);
        }
        fn end(ctx: *anyopaque) error{Stop}!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            try self.js.finish();
            const out = self.list.items[self.start..];
            if (out.len < 9 or !std.mem.endsWith(u8, out, "</script>")) try write(ctx, "</script>");
        }
    };
    var sink: Sink = .{ .arena = app.arena };
    const writer: zav.fmt.html_norm.Output = .{ .ctx = &sink, .write = Sink.write };
    var outputs: zav.fmt.html_norm.Outputs = .{};
    if (std.mem.eql(u8, args[0], "html")) {
        outputs.nocomment = writer;
    } else if (std.mem.eql(u8, args[0], "notags")) {
        outputs.notags = writer;
    } else if (std.mem.eql(u8, args[0], "js")) {
        outputs.scripts = .{ .ctx = &sink, .begin = Sink.begin, .data = Sink.piece, .end = Sink.end };
    } else return usage(app);
    const norm = try app.arena.create(zav.fmt.html_norm.Normalizer);
    norm.* = .init(outputs);
    norm.feed(data) catch {};
    norm.finish() catch {};
    try app.out.writeAll(sink.list.items);
    return 0;
}

/// What zav's format parsers say about executables, one line per file, tab-separated:
/// `PATH FORMAT EP SECTIONS` where EP is the entry point file offset (`-` for none) and
/// SECTIONS is `offset+size,...` (PE: the loader-aligned raw ranges). For tools/diff/formats.py.
fn infoCmd(app: App, args: []const []const u8) !u8 {
    const scanner = try Scanner.init(app.gpa, app.io);
    defer scanner.deinit();
    for (args) |path| {
        const data = Io.Dir.cwd().readFileAlloc(app.io, path, app.arena, .limited(1 << 30)) catch |e| {
            try app.out.print("{s}\terror\t{t}\t\n", .{ path, e });
            continue;
        };
        const src: zav.engine.source.Source = .{ .memory = data };
        const format = zav.fmt.detect.detect(data[0..@min(data.len, zav.fmt.detect.head_len)]);
        var ep: ?u64 = null;
        var secs: std.ArrayList(u8) = .empty;
        var ok = true;
        switch (format) {
            .pe => if (zav.fmt.pe.parse(app.io, src, scanner.pe_sections)) |info| {
                ep = info.ep_offset;
                for (info.sections) |sec| try secs.print(app.arena, "{d}+{d},", .{ sec.raw_off, sec.raw_size });
            } else |_| {
                ok = false;
            },
            .elf => if (zav.fmt.elf.parse(app.io, src, scanner.elf_segments, scanner.elf_sections)) |info| {
                ep = info.ep_offset;
                for (info.sections) |sec| try secs.print(app.arena, "{d}+{d},", .{ sec.offset, sec.size });
            } else |_| {
                ok = false;
            },
            .macho => if (zav.fmt.macho.parse(app.io, src, scanner.macho_segments, scanner.macho_sections)) |info| {
                ep = info.matchEntryPoint();
                for (info.sections) |sec| try secs.print(app.arena, "{d}+{d},", .{ sec.offset, sec.size });
            } else |_| {
                ok = false;
            },
            else => {},
        }
        if (!ok) {
            try app.out.print("{s}\t{t}\tbroken\t\n", .{ path, format });
            continue;
        }
        if (ep) |e| {
            try app.out.print("{s}\t{t}\t{d}\t{s}\n", .{ path, format, e, secs.items });
        } else try app.out.print("{s}\t{t}\t-\t{s}\n", .{ path, format, secs.items });
    }
    return 0;
}

/// Every line of the given signature files the compiler refuses, with its reason and column:
/// `FILE:LINE:COLUMN: REASON: TEXT`. Exit 0 when nothing was refused.
fn rejects(app: App, args: []const []const u8) !u8 {
    var total: usize = 0;
    for (args) |path| {
        const text = try Io.Dir.cwd().readFileAlloc(app.io, path, app.arena, .limited(1 << 30));
        var c = zav.compile.compiler.Compiler.init(app.gpa);
        defer c.deinit();
        try c.addFile(std.fs.path.basename(path), text);
        if (c.rejected.items.len == 0) continue;
        var lines: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| try lines.append(app.arena, line);
        for (c.rejected.items) |r| {
            const line = if (r.line_number >= 1 and r.line_number <= lines.items.len) lines.items[r.line_number - 1] else "";
            try app.out.print("{s}:{d}:{d}: {t}: {s}\n", .{ path, r.line_number, r.column, r.reason, line });
        }
        total += c.rejected.items.len;
    }
    try app.err.print("zav-diff: {d} rejected\n", .{total});
    return if (total == 0) 0 else 1;
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
            // A directory stands for the files in it, in name order.
            var dir = Io.Dir.cwd().openDir(app.io, a, .{ .iterate = true }) catch {
                try targets.append(app.arena, a);
                continue;
            };
            defer dir.close(app.io);
            const first = targets.items.len;
            var it = dir.iterate();
            while (try it.next(app.io)) |entry| {
                if (entry.kind == .file) try targets.append(app.arena, try std.fs.path.join(app.arena, &.{ a, entry.name }));
            }
            std.mem.sort([]const u8, targets.items[first..], {}, lessString);
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
    // Ignore lists first: the compiler takes them before the signatures they name.
    std.mem.sort([]const u8, sig_files.items, {}, struct {
        fn ign(p: []const u8) bool {
            return std.mem.endsWith(u8, p, ".ign2") or std.mem.endsWith(u8, p, ".ign");
        }
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return ign(a) and !ign(b);
        }
    }.less);
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
