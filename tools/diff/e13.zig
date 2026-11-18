//! E13: zig-regex byte mode against PCRE2 on the regexes zav compiles (ClamAV PCRE subsigs and
//! YARA regex strings).
//!
//!   e13 CORPUS [--show N]
//!
//! CORPUS (written by tools/diff/realdb.py corpus) is lines of
//!
//!   P <flags> <pattern hex> <source>     a pattern; flags are PCRE letters (i s m x E U), - for none
//!   S <subject hex>                      a subject for the pattern above
//!
//! Every pattern is compiled as zav compiles it (zav.compile.cdb.compileRegex) and with PCRE2
//! (no UTF, the same options); every subject is searched from offset 0 with both. Results are
//! counted by category: both compile, only one compiles, and per subject whether the match, its
//! start and its end agree. Exit 0 always; the report is the result.
const std = @import("std");
const Io = std.Io;
const zav = @import("zav");
const regex = zav.regex;

const pcre2 = struct {
    const Code = opaque {};
    const MatchData = opaque {};
    const MatchContext = opaque {};
    extern fn pcre2_compile_8(pattern: [*]const u8, length: usize, options: u32, errorcode: *c_int, erroroffset: *usize, ccontext: ?*anyopaque) ?*Code;
    extern fn pcre2_code_free_8(code: *Code) void;
    extern fn pcre2_match_data_create_from_pattern_8(code: *const Code, gcontext: ?*anyopaque) ?*MatchData;
    extern fn pcre2_match_data_free_8(md: *MatchData) void;
    extern fn pcre2_match_8(code: *const Code, subject: [*]const u8, length: usize, start: usize, options: u32, md: *MatchData, mcontext: ?*MatchContext) c_int;
    extern fn pcre2_get_ovector_pointer_8(md: *MatchData) [*]usize;
    extern fn pcre2_match_context_create_8(gcontext: ?*anyopaque) ?*MatchContext;
    extern fn pcre2_set_match_limit_8(mcontext: *MatchContext, limit: u32) c_int;

    const caseless: u32 = 0x00000008;
    const dollar_endonly: u32 = 0x00000010;
    const dotall: u32 = 0x00000020;
    const extended: u32 = 0x00000080;
    const multiline: u32 = 0x00000400;
    const ungreedy: u32 = 0x00040000;
    const error_nomatch: c_int = -1;
};

const Counts = struct {
    patterns: usize = 0,
    both_compile: usize = 0,
    zav_only: usize = 0,
    pcre_only: usize = 0,
    neither: usize = 0,
    subjects: usize = 0,
    agree_nomatch: usize = 0,
    agree_span: usize = 0,
    /// Same start, different end: zig-regex reports leftmost-longest ends.
    end_only: usize = 0,
    /// One engine matches and the other does not, or the starts differ.
    disagree: usize = 0,
    /// A search hit a step or match limit in either engine.
    limited: usize = 0,
};

fn hexDecode(arena: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.BadHex;
    const out = try arena.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    var out_buf: [16 * 1024]u8 = undefined;
    var out_w = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        try out.writeAll("usage: e13 CORPUS [--show N]\n");
        return 2;
    }
    var show: usize = 40;
    if (args.len >= 4 and std.mem.eql(u8, args[2], "--show")) show = try std.fmt.parseInt(usize, args[3], 10);
    const text = try Io.Dir.cwd().readFileAlloc(io, args[1], arena, .limited(1 << 31));

    const mctx = pcre2.pcre2_match_context_create_8(null) orelse return error.OutOfMemory;
    _ = pcre2.pcre2_set_match_limit_8(mctx, 1_000_000);

    var counts: Counts = .{};
    var shown: usize = 0;
    var by_source: std.StringArrayHashMapUnmanaged(Counts) = .empty;

    var program: ?regex.Program = null;
    var scratch_mem: []align(8) u8 = &.{};
    var scratch: ?regex.Scratch = null;
    var code: ?*pcre2.Code = null;
    var md: ?*pcre2.MatchData = null;
    var pattern_text: []const u8 = "";
    var flags_text: []const u8 = "";
    var source: []const u8 = "";
    var dollar_eol = false;
    var pat_arena: std.heap.ArenaAllocator = .init(gpa);
    defer pat_arena.deinit();

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len < 2) continue;
        var it = std.mem.splitScalar(u8, line, ' ');
        const kind = it.next().?;
        if (std.mem.eql(u8, kind, "P")) {
            if (code) |c| pcre2.pcre2_code_free_8(c);
            if (md) |m| pcre2.pcre2_match_data_free_8(m);
            code = null;
            md = null;
            program = null;
            scratch = null;
            if (scratch_mem.len > 0) gpa.free(scratch_mem);
            scratch_mem = &.{};
            _ = pat_arena.reset(.retain_capacity);

            flags_text = it.next() orelse continue;
            pattern_text = try hexDecode(arena, it.next() orelse continue);
            source = it.next() orelse "?";
            dollar_eol = std.mem.eql(u8, source, "clamav") and std.mem.indexOfAny(u8, flags_text, "Em") == null and std.mem.indexOfScalar(u8, pattern_text, '$') != null;
            counts.patterns += 1;
            const src = try by_source.getOrPut(arena, source);
            if (!src.found_existing) src.value_ptr.* = .{};
            src.value_ptr.patterns += 1;

            var zf: regex.common.CompileFlags = .{};
            var pf: u32 = 0;
            for (flags_text) |f| switch (f) {
                'i' => {
                    zf.case_insensitive = true;
                    pf |= pcre2.caseless;
                },
                's' => {
                    zf.dot_all = true;
                    pf |= pcre2.dotall;
                },
                'm' => {
                    zf.multiline = true;
                    pf |= pcre2.multiline;
                },
                'x' => {
                    zf.extended = true;
                    pf |= pcre2.extended;
                },
                'E' => pf |= pcre2.dollar_endonly,
                'U' => pf |= pcre2.ungreedy,
                else => {},
            };
            const zpattern = if (std.mem.indexOfScalar(u8, flags_text, 'U') != null) try std.mem.concat(pat_arena.allocator(), u8, &.{ "(?U)", pattern_text }) else pattern_text;
            const zav_ok = if (zav.compile.cdb.compileRegexKind(pat_arena.allocator(), zpattern, zf, .leftmost_first)) |blob| blk: {
                program = regex.Program.load(blob) catch null;
                break :blk program != null;
            } else |_| false;
            if (program) |*p| {
                const cap = p.capacity();
                var c2 = cap;
                c2.dfa_states = 256;
                scratch_mem = try gpa.alignedAlloc(u8, .@"8", regex.Scratch.bytesNeeded(c2));
                scratch = try regex.Scratch.initBuffer(scratch_mem, c2);
                scratch.?.step_budget = 1 << 24;
            }
            var err: c_int = 0;
            var erroff: usize = 0;
            code = pcre2.pcre2_compile_8(pattern_text.ptr, pattern_text.len, pf, &err, &erroff, null);
            if (code) |c| md = pcre2.pcre2_match_data_create_from_pattern_8(c, null);
            const pcre_ok = code != null;
            if (zav_ok and pcre_ok) {
                counts.both_compile += 1;
                src.value_ptr.both_compile += 1;
            } else if (zav_ok) {
                counts.zav_only += 1;
                src.value_ptr.zav_only += 1;
                if (shown < show) {
                    shown += 1;
                    try out.print("ZAV-ONLY /{s}/{s} ({s})\n", .{ pattern_text, flags_text, source });
                }
            } else if (pcre_ok) {
                counts.pcre_only += 1;
                src.value_ptr.pcre_only += 1;
            } else {
                counts.neither += 1;
                src.value_ptr.neither += 1;
            }
            continue;
        }
        if (!std.mem.eql(u8, kind, "S")) continue;
        const p = &(program orelse continue);
        const c = code orelse continue;
        const subject = try hexDecode(arena, it.next() orelse continue);
        counts.subjects += 1;
        const src = by_source.getPtr(source).?;
        src.subjects += 1;

        var zres = p.findFrom(&scratch.?, subject, 0) catch {
            counts.limited += 1;
            src.limited += 1;
            continue;
        };
        // As zav runs PCRE subsigs (match/logical.zig): without E or m, a `$` may also match
        // before a final newline, by searching the subject without it.
        if (zres == null and dollar_eol and subject.len > 0 and subject[subject.len - 1] == '\n') {
            zres = p.findFrom(&scratch.?, subject[0 .. subject.len - 1], 0) catch null;
        }
        const rc = pcre2.pcre2_match_8(c, subject.ptr, subject.len, 0, 0, md.?, mctx);
        if (rc < 0 and rc != pcre2.error_nomatch) {
            counts.limited += 1;
            src.limited += 1;
            continue;
        }
        const ov = pcre2.pcre2_get_ovector_pointer_8(md.?);
        const pmatch: ?[2]usize = if (rc >= 0) .{ ov[0], ov[1] } else null;
        if (zres == null and pmatch == null) {
            counts.agree_nomatch += 1;
            src.agree_nomatch += 1;
        } else if (zres != null and pmatch != null and zres.?.start == pmatch.?[0]) {
            if (zres.?.end == pmatch.?[1]) {
                counts.agree_span += 1;
                src.agree_span += 1;
            } else {
                counts.end_only += 1;
                src.end_only += 1;
                if (shown < show) {
                    shown += 1;
                    try out.print("END /{s}/{s} ({s}) on {x}: zig-regex {any}, pcre2 {any}\n", .{ pattern_text, flags_text, source, subject[0..@min(subject.len, 120)], zres, pmatch });
                }
            }
        } else {
            counts.disagree += 1;
            src.disagree += 1;
            if (shown < show) {
                shown += 1;
                try out.print("DISAGREE /{s}/{s} ({s}) on {x}: zig-regex {any}, pcre2 {any}\n", .{ pattern_text, flags_text, source, subject[0..@min(subject.len, 120)], zres, pmatch });
            }
        }
    }

    if (code) |c| pcre2.pcre2_code_free_8(c);
    if (md) |m| pcre2.pcre2_match_data_free_8(m);
    if (scratch_mem.len > 0) gpa.free(scratch_mem);
    try out.print(
        \\E13: {d} patterns: {d} compile in both, {d} only in zig-regex, {d} only in PCRE2, {d} in neither
        \\     {d} subjects: {d} agree (no match), {d} agree (same span), {d} same start but a different end,
        \\     {d} disagree (match or start), {d} limited
        \\
    , .{ counts.patterns, counts.both_compile, counts.zav_only, counts.pcre_only, counts.neither, counts.subjects, counts.agree_nomatch, counts.agree_span, counts.end_only, counts.disagree, counts.limited });
    for (by_source.keys(), by_source.values()) |k, v| {
        try out.print("  {s}: {d} patterns ({d} both, {d} PCRE2 only), {d} subjects: {d}+{d} agree, {d} end only, {d} disagree, {d} limited\n", .{ k, v.patterns, v.both_compile, v.pcre_only, v.subjects, v.agree_nomatch, v.agree_span, v.end_only, v.disagree, v.limited });
    }
    return 0;
}
