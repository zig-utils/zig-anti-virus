//! File typing with a database's type magics (`.ftm`), reproducing the types `clamscan 1.5.4`
//! reports in its `--gen-json` metadata. The rules were derived black-box from clamscan's output
//! on generated inputs (docs/clean-room.md, "File typing"); no ClamAV source was used.
//!
//! Typing runs in stages:
//!
//! 1. Fixed magics (`.ftm` type 0, byte comparisons at an offset). When several match, the one
//!    that comes last in the database wins.
//! 2. Without one, the first 1024 bytes decide between text and binary data (`textType`).
//! 3. Text and binary data (and GIF, for HTML only) are re-typed by the body magics (`.ftm`
//!    type 1) found in the first 1024 bytes, or at their own offsets for anchored ones, combined
//!    in file order by `Combiner`.
//! 4. Over the whole file, a disk image magic (ISO 9660 anywhere, UDF and DMG at their offsets)
//!    re-types almost anything; XDP and MHTML anywhere re-type text and binary data; HTML
//!    anywhere re-types ASCII text.
//!
//! FTM_TRIE layout (written by compile/ftm_build.zig): an `FtmHeader`, then `group_count`
//! `FtmGroup`s (one trie root per fixed offset), `node_count` `FtmNode`s, `edge_count`
//! `FtmEdge`s and `entry_count` `FtmEntry`s, all little-endian and 4-byte aligned.
const std = @import("std");
const ir = @import("../compile/ir.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");
const types = @import("types.zig");
const subtype = @import("subtype.zig");

pub const FtmHeader = extern struct {
    magic: [4]u8 = "FTMT".*,
    version: u32 = 1,
    group_count: u32,
    node_count: u32,
    edge_count: u32,
    entry_count: u32,
    _reserved: [8]u8 = @splat(0),
};

pub const FtmGroup = extern struct { offset: u32, root: u32 };

pub const FtmNode = extern struct {
    first_edge: u32,
    edge_count: u16,
    /// 1 + the index of the first entry ending at this node, 0 for none.
    entry: u16,
};

pub const FtmEdge = extern struct {
    byte: u8,
    _pad: [3]u8 = @splat(0),
    child: u32,
};

pub const any_offset: u32 = 0xffff_ffff;
pub const no_prog: u32 = 0xffff_ffff;

pub const FtmEntry = extern struct {
    kind: ir.MagicKind,
    _pad: u8 = 0,
    rtype: u16,
    type: u16,
    magic_len: u16,
    /// 1 + the index of the next entry ending at the same node, 0 for none.
    next: u32 = 0,
    /// Index of the body program in SUBSIG_PROG variant 1 (body kind), else `no_prog`.
    prog: u32 = no_prog,
    offset: u32,
    _reserved: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(FtmHeader) == 32);
    std.debug.assert(@sizeOf(FtmGroup) == 8);
    std.debug.assert(@sizeOf(FtmNode) == 8);
    std.debug.assert(@sizeOf(FtmEdge) == 8);
    std.debug.assert(@sizeOf(FtmEntry) == 24);
}

pub const Ftm = struct {
    groups: []const FtmGroup,
    nodes: []const FtmNode,
    edges: []const FtmEdge,
    entries: []const FtmEntry,
    programs: ?prog.Programs,

    pub const Error = error{BadFtm};

    pub fn init(section: []const u8, programs: ?prog.Programs) Error!Ftm {
        if (section.len < @sizeOf(FtmHeader) or @intFromPtr(section.ptr) % 4 != 0) return error.BadFtm;
        const h: *align(1) const FtmHeader = @ptrCast(section.ptr);
        if (!std.mem.eql(u8, &h.magic, "FTMT") or h.version != 1) return error.BadFtm;
        var off: usize = @sizeOf(FtmHeader);
        const groups = try take(FtmGroup, section, &off, h.group_count);
        const nodes = try take(FtmNode, section, &off, h.node_count);
        const edges = try take(FtmEdge, section, &off, h.edge_count);
        const entries = try take(FtmEntry, section, &off, h.entry_count);
        for (groups) |g| if (g.root >= nodes.len) return error.BadFtm;
        for (nodes) |n| {
            if (@as(u64, n.first_edge) + n.edge_count > edges.len) return error.BadFtm;
            if (n.entry > entries.len) return error.BadFtm;
        }
        for (edges) |e| if (e.child >= nodes.len) return error.BadFtm;
        for (entries) |e| {
            if (e.next > entries.len) return error.BadFtm;
            if (e.prog != no_prog) {
                const p = programs orelse return error.BadFtm;
                if (e.prog >= p.count()) return error.BadFtm;
            }
        }
        return .{ .groups = groups, .nodes = nodes, .edges = edges, .entries = entries, .programs = programs };
    }

    fn take(comptime T: type, section: []const u8, off: *usize, count: u32) Error![]const T {
        const bytes = std.math.mul(usize, count, @sizeOf(T)) catch return error.BadFtm;
        if (bytes > section.len - off.*) return error.BadFtm;
        const ptr: [*]const T = @ptrCast(@alignCast(section.ptr + off.*));
        off.* += bytes;
        return ptr[0..count];
    }
};

pub const Trigger = struct { type: types.ClType, offset: usize };
pub const max_triggers = 16;

pub const Classification = struct {
    type: types.ClType,
    /// A fixed magic decided the base type (stage 1).
    by_magic: bool,
    /// Body magics found in the first 1024 bytes, in file order (at most `max_triggers`).
    triggers: [max_triggers]Trigger = undefined,
    trigger_count: u8 = 0,

    pub fn embedded(c: *const Classification) []const Trigger {
        return c.triggers[0..c.trigger_count];
    }

    fn addTrigger(c: *Classification, t: Trigger) void {
        if (c.trigger_count == max_triggers) return;
        c.triggers[c.trigger_count] = t;
        c.trigger_count += 1;
    }
};

pub const Options = struct {
    /// Type partitions (`.ftm` type 4) instead of files.
    partitions: bool = false,
    /// Size of the whole object when `data` is only its head. The whole-file stage (4) and
    /// EOF-anchored magics run only when `data` is the whole object.
    file_size: ?u64 = null,
};

/// The bytes the text test and unanchored body magics look at.
pub const head_window = 1024;

fn isTextByte(b: u8) bool {
    return switch (b) {
        0x07, 0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x1b => true,
        0x20...0x7e => true,
        0x80...0xff => true,
        else => false,
    };
}

/// Text or binary data, from the first 1024 bytes. Observed rules: every byte printable ASCII,
/// one of BEL BS TAB LF FF CR ESC, or 0x80 and up makes ASCII text; otherwise a byte order mark
/// FF FE makes UTF-16LE and FE FF UTF-16BE; otherwise the data is UTF-16BE unless a 16-bit
/// big-endian unit after the first is FFFE or a control code below 0x80 that ASCII text may
/// not contain, which makes binary data. A trailing odd byte is not looked at.
pub fn textType(head: []const u8) types.ClType {
    const h = head[0..@min(head.len, head_window)];
    for (h) |b| {
        if (!isTextByte(b)) break;
    } else return .text_ascii;
    if (h.len >= 2) {
        if (h[0] == 0xff and h[1] == 0xfe) return .text_utf16le;
        if (h[0] == 0xfe and h[1] == 0xff) return .text_utf16be;
    }
    var i: usize = 2;
    while (i + 1 < h.len) : (i += 2) {
        const u = @as(u16, h[i]) << 8 | h[i + 1];
        if (u == 0xfffe) return .binary_data;
        if (u < 0x80 and !isTextByte(@intCast(u))) return .binary_data;
    }
    return .text_utf16be;
}

pub fn isText(t: types.ClType) bool {
    return switch (t) {
        .text_ascii, .text_utf8, .text_utf16le, .text_utf16be => true,
        else => false,
    };
}

/// Types stage 3 re-types.
fn retypable(t: types.ClType) bool {
    return isText(t) or t == .binary_data;
}

/// How a body magic found in the head combines with what was found before it (stage 3). The
/// classes and the order of the low ones were measured pairwise: every pair of embedded types,
/// in both orders, in text and in binary data.
const Class = enum {
    /// Not part of stage 3 (whole-file types, or types stage 3 never yields).
    none,
    /// Ranked: a later one replaces an earlier one only when it ranks higher.
    low,
    /// Self-extractor markers: they leave the base type, and cancel low types and executables.
    sfx,
    /// MSEXE: replaced by anything found after it.
    exe,
    /// AUTOIT, NULSFT, ISHIELD_MSI: replaced by anything but low types.
    installer,
    /// XDP, MHTML: replaced by executables, installers and each other.
    document,
    /// IGNORED: never replaced.
    top,
    /// A UDF magic inside the head, not at its start: replaces anything but IGNORED.
    disk,
};

fn classOf(m: Match) Class {
    if (m.type == .udf) return if (m.start == 0) .low else .disk;
    // Measured: an XDP or MHTML magic at the very start combines like an installer.
    if (m.start == 0 and (m.type == .xdp or m.type == .mhtml)) return .installer;
    return switch (m.type) {
        .zipsfx, .rarsfx, .arjsfx, .cabsfx, .@"7zsfx" => .sfx,
        .msexe => .exe,
        .autoit, .nulsft, .ishield_msi => .installer,
        .xdp, .mhtml => .document,
        .ignored => .top,
        .iso9660, .udf, .dmg => .none,
        else => .low,
    };
}

fn lowRank(t: types.ClType) u8 {
    return switch (t) {
        .udf => 8,
        .sis, .macho_unibin => 1,
        .pdf => 2,
        .java, .python_compiled, .lha_lzh => 3,
        .mbr => 4,
        .html => 5,
        .mail => 6,
        .xml_xl, .xml_word, .xml_hwp, .apm => 7,
        else => 3,
    };
}

/// Stage 3: feed the head's body-magic matches in file order.
const Combiner = struct {
    cur: ?Match = null,
    /// The first of a run of XDP/MHTML matches that replaced each other: a self-extractor
    /// marker after the run brings it back (observed with two and three document magics
    /// and a marker).
    first_doc: ?Match = null,

    fn add(c: *Combiner, m: Match) void {
        const new = classOf(m);
        if (new == .none) return;
        if (c.cur) |cur| {
            if (classOf(cur) == .document) {
                if (new == .sfx) {
                    if (c.first_doc) |f| c.cur = f;
                    return;
                }
                if (new == .document) {
                    if (c.first_doc == null) c.first_doc = cur;
                } else if (new == .exe or new == .installer or new == .top or new == .disk) {
                    // Only a match that replaces the document ends the run (a MAIL match
                    // between two document magics does not).
                    c.first_doc = null;
                }
            }
        }
        const cur = c.cur orelse {
            c.cur = m;
            return;
        };
        const replace = switch (classOf(cur)) {
            .none => true,
            .low => new != .low or lowRank(m.type) > lowRank(cur.type),
            .sfx, .installer => new != .low,
            .exe => true,
            .document => new == .exe or new == .installer or new == .document or new == .top or new == .disk,
            .top => false,
            .disk => new == .top,
        };
        if (replace) c.cur = m;
    }

    /// The re-typed type, or null to keep the base type.
    fn result(c: Combiner) ?types.ClType {
        const m = c.cur orelse return null;
        return if (classOf(m) == .sfx) null else m.type;
    }
};

/// Stage 4 disk images: which types they do not replace.
fn diskReplaces(disk: types.ClType, cur: types.ClType) bool {
    switch (cur) {
        .html, .gz, .ignored, .zip, .tnef, .posix_tar, .cpio_old, .xz => return false,
        .msexe, .elf, .macho => return disk != .dmg,
        else => return true,
    }
}

const max_matches = 256;
/// Matches one body magic contributes to the whole-file stage, and all of them together.
const max_entry_matches = 64;
const max_file_matches = 2048;

const Match = struct { start: usize, end: usize, type: types.ClType, entry: u32 };

/// File order is the order in which matches end.
fn lessMatch(_: void, a: Match, b: Match) bool {
    if (a.end != b.end) return a.end < b.end;
    if (a.start != b.start) return a.start < b.start;
    return a.entry < b.entry;
}

fn entryType(e: FtmEntry) types.ClType {
    return @fromBackingInt(e.type);
}

/// Stage 1: the last fixed magic in database order that matches, if any.
fn fixedType(f: Ftm, data: []const u8, kind: ir.MagicKind) ?types.ClType {
    var best: ?u32 = null;
    for (f.groups) |g| {
        if (g.offset >= data.len) continue;
        var node = f.nodes[g.root];
        var pos: usize = g.offset;
        while (true) {
            var e: u32 = node.entry;
            while (e != 0) {
                const entry = f.entries[e - 1];
                if (entry.kind == kind and (best == null or e - 1 > best.?)) best = e - 1;
                e = entry.next;
            }
            if (pos >= data.len or node.edge_count == 0) break;
            const edges = f.edges[node.first_edge..][0..node.edge_count];
            const b = data[pos];
            const next = for (edges) |edge| {
                if (edge.byte == b) break edge.child;
            } else break;
            node = f.nodes[next];
            pos += 1;
        }
    }
    const i = best orelse return null;
    return entryType(f.entries[i]);
}

/// Every match of body magic `entry` in `data` (bounded), appended to `out`.
fn bodyMatches(f: Ftm, entry_index: u32, data: []const u8, size: u64, budget: *vm.Budget, out: []Match, n: *usize) void {
    const e = f.entries[entry_index];
    const progs = f.programs orelse return;
    const p = progs.get(e.prog);
    var scanner = vm.Scanner.init(p, data, .{ .size = size }, budget);
    while (n.* < out.len) {
        const m = (scanner.next() catch return) orelse return;
        out[n.*] = .{ .start = m.start, .end = m.end, .type = entryType(e), .entry = entry_index };
        n.* += 1;
    }
}

fn isWholeFileType(t: types.ClType) bool {
    return switch (t) {
        .iso9660, .udf, .dmg => true,
        else => false,
    };
}

/// Type `data` (the whole object, or its head with `options.file_size` set).
pub fn classify(f: Ftm, data: []const u8, options: Options, budget: *vm.Budget) Classification {
    if (options.partitions) {
        if (fixedType(f, data, .partition)) |t| return .{ .type = t, .by_magic = true };
    }
    var c: Classification = .{ .type = undefined, .by_magic = false };
    if (fixedType(f, data, .bytes)) |t| {
        c.type = t;
        c.by_magic = true;
    } else c.type = textType(data);
    switch (c.type) {
        .msole2 => if (subtype.ole2Type(data)) |t| {
            c.type = t;
        },
        .zip => if (subtype.zipType(data)) |t| {
            c.type = t;
        },
        .binary_data => if (subtype.isOldTar(data)) {
            c.type = .old_tar;
        },
        else => {},
    }
    const whole = options.file_size == null or options.file_size.? == data.len;
    const size: u64 = options.file_size orelse data.len;
    const head = data[0..@min(data.len, head_window)];

    // Stage 3: body magics that lie wholly in the head. An IGNORED one there also stops the
    // whole-file stage, whatever the base type.
    var ignored = false;
    var stage3_all = false;
    {
        var buf: [max_matches]Match = undefined;
        var n: usize = 0;
        const all = retypable(c.type);
        const gif = c.type == .gif;
        stage3_all = all or gif;
        for (f.entries, 0..) |e, i| {
            if (e.kind != .body or e.prog == no_prog) continue;
            const t = entryType(e);
            if (t == .iso9660 or t == .dmg) continue;
            if (!all and t != .ignored and !(gif and (t == .html or t == .udf))) continue;
            bodyMatches(f, @intCast(i), head, head.len, budget, &buf, &n);
        }
        const matches = buf[0..n];
        std.mem.sort(Match, matches, {}, lessMatch);
        var comb: Combiner = .{};
        for (matches) |m| {
            if (m.type == .ignored) ignored = true;
            if (!all and m.type == .ignored) continue;
            c.addTrigger(.{ .type = m.type, .offset = m.start });
            comb.add(m);
        }
        if (comb.result()) |t| c.type = t;
    }
    if (!whole or ignored) return c;
    const head_udf_done = stage3_all;

    // Stage 4, whole file: disk images (the last one in the file), then XDP or MHTML (the first
    // one) for text and binary data, then for ASCII text the stage 3 combination over every
    // body magic in the file, when it yields HTML or MAIL.
    var disk: ?Match = null;
    var document: ?Match = null;
    const ascii = c.type == .text_ascii;
    var many: [max_file_matches]Match = undefined;
    var many_n: usize = 0;
    var buf: [max_entry_matches]Match = undefined;
    for (f.entries, 0..) |e, i| {
        if (e.kind != .body or e.prog == no_prog) continue;
        const t = entryType(e);
        const doc = (t == .xdp or t == .mhtml) and e.offset == any_offset;
        if (!(isWholeFileType(t) or (doc and retypable(c.type)) or (ascii and !doc and t != .xdp and t != .mhtml))) continue;
        var n: usize = 0;
        bodyMatches(f, @intCast(i), data, size, budget, &buf, &n);
        for (buf[0..n]) |m| {
            if (isWholeFileType(t) or doc) {
                // A magic at the very start, or one stage 3 already combined, is not seen again.
                if (m.start == 0 and t != .iso9660 and t != .dmg) continue;
                if (m.end <= head_window and head_udf_done and t != .iso9660 and t != .dmg) continue;
            }
            if (isWholeFileType(t)) {
                if (disk == null or m.start >= disk.?.start) disk = m;
            } else if (doc) {
                if (document == null or m.start < document.?.start) document = m;
            } else if (many_n < many.len) {
                many[many_n] = m;
                many_n += 1;
            }
        }
    }
    if (disk) |d| {
        if (diskReplaces(d.type, c.type)) {
            c.type = d.type;
            return c;
        }
    }
    if (document) |d| {
        c.type = d.type;
        return c;
    }
    if (ascii) {
        const matches = many[0..many_n];
        std.mem.sort(Match, matches, {}, lessMatch);
        var comb: Combiner = .{};
        for (matches) |m| comb.add(m);
        if (comb.result()) |t| {
            if (t == .html or t == .mail) c.type = t;
        }
    }
    return c;
}
