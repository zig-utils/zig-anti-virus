//! Heuristics: detections that need no signature. Each has a name under Heuristics.Guardian.*,
//! a default severity, and can be disabled; findings at or above `Config.min_severity` are
//! reported as `heuristic` notices carrying the name, which configuration turns into a
//! "suspicious" verdict (never "infected" by default).
//!
//! - Entropy: the first and last 4 KiB of an object both look random. Only in high-risk
//!   contexts: executables, or objects the caller marks risky (temp directories, uploads).
//! - Executable header anomalies: entry point outside every section or segment, writable and
//!   executable sections or segments, overlapping section data.
//! - Extension mismatch: a name that promises a document, image or text holding an executable
//!   or archive.
//! - Script obfuscation: long encoded blobs, eval chains, dense escape sequences.
//!
//! Thresholds are conservative defaults chosen against benign system files; the benign corpus
//! (B1) is what tunes them.
const std = @import("std");
const container = @import("container.zig");
const Format = container.Format;

pub const Severity = enum(u2) { low, medium, high };

pub const Id = enum(u8) {
    high_entropy,
    pe_entry_outside_sections,
    pe_write_exec_section,
    pe_overlapping_sections,
    elf_entry_outside_segments,
    elf_write_exec_segment,
    macho_entry_outside_segments,
    macho_write_exec_segment,
    extension_mismatch,
    script_encoded_blob,
    script_eval_chain,
    script_dense_escapes,

    pub fn name(id: Id) []const u8 {
        return switch (id) {
            .high_entropy => "Heuristics.Guardian.HighEntropy",
            .pe_entry_outside_sections => "Heuristics.Guardian.PE.EntryOutsideSections",
            .pe_write_exec_section => "Heuristics.Guardian.PE.WritableExecutableSection",
            .pe_overlapping_sections => "Heuristics.Guardian.PE.OverlappingSections",
            .elf_entry_outside_segments => "Heuristics.Guardian.ELF.EntryOutsideSegments",
            .elf_write_exec_segment => "Heuristics.Guardian.ELF.WritableExecutableSegment",
            .macho_entry_outside_segments => "Heuristics.Guardian.MachO.EntryOutsideSegments",
            .macho_write_exec_segment => "Heuristics.Guardian.MachO.WritableExecutableSegment",
            .extension_mismatch => "Heuristics.Guardian.ExtensionMismatch",
            .script_encoded_blob => "Heuristics.Guardian.Script.EncodedBlob",
            .script_eval_chain => "Heuristics.Guardian.Script.EvalChain",
            .script_dense_escapes => "Heuristics.Guardian.Script.DenseEscapes",
        };
    }

    pub fn severity(id: Id) Severity {
        return switch (id) {
            .high_entropy, .pe_write_exec_section, .elf_write_exec_segment, .macho_write_exec_segment => .low,
            // Unicode tables and bundled assets in benign JavaScript trip these: informational.
            .script_encoded_blob, .script_dense_escapes => .low,
            .pe_overlapping_sections => .medium,
            .pe_entry_outside_sections, .elf_entry_outside_segments, .macho_entry_outside_segments, .extension_mismatch, .script_eval_chain => .high,
        };
    }
};

pub const Config = struct {
    disabled: std.EnumSet(Id) = .empty,
    /// Findings below this severity are not reported.
    min_severity: Severity = .medium,
    /// The caller marks the scan high-risk (temp directory, upload): entropy applies to every
    /// object, not only executables.
    risky: bool = false,
    /// Entropy in bits per byte that both blocks must reach.
    entropy_threshold: f64 = 7.95,
    entropy_block: usize = 4096,

    pub fn wants(c: *const Config, id: Id) bool {
        return !c.disabled.contains(id) and @backingInt(id.severity()) >= @backingInt(c.min_severity);
    }
};

/// Report a finding through the walker if heuristics are on and the configuration wants it.
pub fn report(w: *container.Walker, id: Id) void {
    const cfg = w.options.heuristics orelse return;
    if (cfg.wants(id)) w.notice(.heuristic, id.name());
}

/// Report each (condition, heuristic) pair whose condition holds.
pub fn reportAll(w: *container.Walker, checks: []const struct { bool, Id }) void {
    for (checks) |c| if (c[0]) report(w, c[1]);
}

/// Shannon entropy of `bytes` in bits per byte (0 to 8).
pub fn entropy(bytes: []const u8) f64 {
    if (bytes.len == 0) return 0;
    var counts: [256]u32 = @splat(0);
    for (bytes) |b| counts[b] += 1;
    const n: f64 = @floatFromInt(bytes.len);
    var h: f64 = 0;
    for (counts) |c| {
        if (c == 0) continue;
        const p = @as(f64, @floatFromInt(c)) / n;
        h -= p * @log2(p);
    }
    return h;
}

/// Both the first and the last block are near-random (packed, encrypted or compressed content
/// where none is expected). Needs a full block at each end.
pub fn highEntropy(first: []const u8, last: []const u8, cfg: *const Config) bool {
    if (first.len < cfg.entropy_block or last.len < cfg.entropy_block) return false;
    return entropy(first) >= cfg.entropy_threshold and entropy(last) >= cfg.entropy_threshold;
}

pub fn isExecutable(f: Format) bool {
    return switch (f) {
        .pe, .elf, .macho, .macho_fat => true,
        else => false,
    };
}

/// A name whose extension promises something an executable or archive is not. Returns the
/// extension when it mismatches `detected`.
pub fn extensionMismatch(name: []const u8, detected: Format) ?[]const u8 {
    const base = if (std.mem.lastIndexOfScalar(u8, name, '/')) |i| name[i + 1 ..] else name;
    const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse return null;
    const ext = base[dot..];
    const benign_kind = for (benign_extensions) |e| {
        if (std.ascii.eqlIgnoreCase(e, ext)) break true;
    } else false;
    if (!benign_kind) return null;
    return switch (detected) {
        .pe, .elf, .macho, .macho_fat => ext,
        else => null,
    };
}

/// Extensions of documents, images, media and plain text: never executable content.
const benign_extensions = [_][]const u8{
    ".txt", ".pdf",  ".doc", ".docx", ".xls", ".xlsx", ".ppt",  ".pptx", ".rtf", ".odt",  ".csv",
    ".jpg", ".jpeg", ".png", ".gif",  ".bmp", ".svg",  ".webp", ".ico",  ".tif", ".tiff", ".heic",
    ".mp3", ".mp4",  ".wav", ".avi",  ".mov", ".mkv",  ".html", ".htm",  ".md",  ".json", ".xml",
};

/// Streaming script-obfuscation markers over raw script or text bytes. State is a handful of
/// counters, so it runs inside the pass that already reads the object.
pub const ScriptScanner = struct {
    /// Current run of base64-alphabet characters, and the longest seen.
    run: u64 = 0,
    longest_run: u64 = 0,
    /// Standalone "eval(" calls, and those that decode their argument first: "eval(atob(",
    /// "eval(unescape(", "eval(function(p,a,c,k,e" (the packer), "eval(String.fromCharCode(".
    evals: u32 = 0,
    decoding_evals: u32 = 0,
    /// Escape sequences (\xHH, \uHHHH, %uHHHH, %HH) and total bytes.
    escapes: u64 = 0,
    bytes: u64 = 0,
    /// Tail of the previous block, so markers split across blocks are seen.
    tail: [24]u8 = undefined,
    tail_len: u8 = 0,

    pub const blob_min: u64 = 4096;
    pub const decoding_evals_min: u32 = 2;
    pub const escape_density_min: f64 = 0.2;
    pub const escape_bytes_min: u64 = 1024;

    pub fn update(s: *ScriptScanner, data: []const u8) void {
        s.bytes += data.len;
        for (data) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=') {
                s.run += 1;
            } else {
                s.longest_run = @max(s.longest_run, s.run);
                s.run = 0;
            }
        }
        s.longest_run = @max(s.longest_run, s.run);
        // Marker search over tail + data, in bounded windows.
        var window: [24 + 4096]u8 = undefined;
        var off: usize = 0;
        while (off < data.len) {
            const take = @min(4096, data.len - off);
            @memcpy(window[0..s.tail_len], s.tail[0..s.tail_len]);
            @memcpy(window[s.tail_len..][0..take], data[off..][0..take]);
            const w = window[0 .. s.tail_len + take];
            s.scanMarkers(w, s.tail_len);
            const keep = @min(w.len, s.tail.len);
            @memcpy(s.tail[0..keep], w[w.len - keep ..]);
            s.tail_len = @intCast(keep);
            off += take;
        }
    }

    /// Count markers that end at or after `fresh` (so tail bytes are not counted twice).
    fn scanMarkers(s: *ScriptScanner, w: []const u8, fresh: usize) void {
        var i: usize = 0;
        while (i < w.len) : (i += 1) {
            const c = w[i];
            if (c == 'e' or c == 'E') {
                // A call of the global eval, not a method (".eval(") or a longer name.
                const standalone = i == 0 or !(std.ascii.isAlphanumeric(w[i - 1]) or w[i - 1] == '.' or w[i - 1] == '_' or w[i - 1] == '$');
                if (standalone and i + 5 <= w.len and std.mem.eql(u8, w[i..][0..5], "eval(") and i + 5 > fresh) {
                    s.evals += 1;
                    var after = w[i + 5 ..];
                    while (after.len > 0 and (after[0] == ' ' or after[0] == '\t')) after = after[1..];
                    for ([_][]const u8{ "atob(", "unescape(", "function(p,a,c,k,e", "String.fromCharCode(", "decodeURIComponent(" }) |m| {
                        if (after.len >= m.len and std.mem.eql(u8, after[0..m.len], m)) {
                            s.decoding_evals += 1;
                            break;
                        }
                    }
                }
            } else if (c == '\\' and i + 1 < w.len and (w[i + 1] == 'x' or w[i + 1] == 'u') and i + 2 > fresh) {
                s.escapes += 1;
            } else if (c == '%' and i + 2 < w.len and std.ascii.isHex(w[i + 1]) and std.ascii.isHex(w[i + 2]) and i + 3 > fresh) {
                s.escapes += 1;
            } else if (c == '%' and i + 1 < w.len and (w[i + 1] == 'u' or w[i + 1] == 'U') and i + 2 > fresh) {
                s.escapes += 1;
            }
        }
    }

    pub const Findings = std.EnumSet(Id);

    pub fn finish(s: *const ScriptScanner) Findings {
        var f: Findings = .empty;
        if (s.longest_run >= blob_min) f.insert(.script_encoded_blob);
        if (s.decoding_evals >= decoding_evals_min) f.insert(.script_eval_chain);
        if (s.bytes >= escape_bytes_min) {
            // Each escape is 3 to 6 bytes; density is escape bytes over all bytes, roughly.
            const density = @as(f64, @floatFromInt(s.escapes * 4)) / @as(f64, @floatFromInt(s.bytes));
            if (density >= escape_density_min) f.insert(.script_dense_escapes);
        }
        return f;
    }
};

test "entropy" {
    try std.testing.expectEqual(@as(f64, 0), entropy("aaaa"));
    try std.testing.expectApproxEqAbs(@as(f64, 1), entropy("abab"), 1e-9);
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    try std.testing.expectApproxEqAbs(@as(f64, 8), entropy(&all), 1e-9);
}

test "high entropy needs both ends random" {
    var rnd: [8192]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1);
    prng.random().bytes(&rnd);
    const cfg: Config = .{};
    try std.testing.expect(highEntropy(rnd[0..4096], rnd[4096..], &cfg));
    var text: [4096]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = "the quick brown fox "[i % 20];
    try std.testing.expect(!highEntropy(rnd[0..4096], &text, &cfg));
    try std.testing.expect(!highEntropy(rnd[0..100], rnd[100..200], &cfg));
}

test "extension mismatch" {
    try std.testing.expectEqualStrings(".pdf", extensionMismatch("invoice.pdf", .pe).?);
    try std.testing.expectEqualStrings(".JPG", extensionMismatch("dir/photo.JPG", .elf).?);
    try std.testing.expect(extensionMismatch("setup.exe", .pe) == null);
    try std.testing.expect(extensionMismatch("notes.txt", .text) == null);
    try std.testing.expect(extensionMismatch("noext", .pe) == null);
}

test "script markers" {
    var s: ScriptScanner = .{};
    s.update("var x = 1; eval(atob('ZXZpbA==')); ev");
    s.update("al(unescape('%u4141')); ");
    try std.testing.expect(s.finish().contains(.script_eval_chain));

    var b: ScriptScanner = .{};
    var blob: [6000]u8 = undefined;
    for (&blob, 0..) |*c, i| c.* = "QUJDREVGR0hJSktM"[i % 16];
    b.update("var payload = '");
    b.update(blob[0..3000]);
    b.update(blob[3000..]);
    try std.testing.expect(b.finish().contains(.script_encoded_blob));

    var e: ScriptScanner = .{};
    var esc: [2000]u8 = undefined;
    for (&esc, 0..) |*c, i| c.* = "\\x41"[i % 4];
    e.update(&esc);
    try std.testing.expect(e.finish().contains(.script_dense_escapes));

    var benign: ScriptScanner = .{};
    benign.update("function add(a, b) { return a + b; }\nconsole.log(add(1, 2)); // 100% fine\n");
    try std.testing.expectEqual(@as(usize, 0), benign.finish().count());
}

test "config filters by severity and disabled set" {
    var cfg: Config = .{};
    try std.testing.expect(cfg.wants(.pe_entry_outside_sections));
    try std.testing.expect(!cfg.wants(.high_entropy)); // low, under the default medium
    cfg.min_severity = .low;
    try std.testing.expect(cfg.wants(.high_entropy));
    cfg.disabled.insert(.high_entropy);
    try std.testing.expect(!cfg.wants(.high_entropy));
}
