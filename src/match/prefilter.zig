//! Stage one and two of the byte-pattern scan (docs/DESIGN.md 3.4 and 5): the PREFILTER and
//! ATOM_TABLE of each partition, and the scan that turns a buffer into candidate (program,
//! anchor start) pairs for the verify VM.
//!
//! All partitions share one PREFILTER section, so a database with every target type stays
//! well inside the section table:
//!
//!     Directory (64 bytes)    magic "PFDR", version, partition count
//!     refs: [partition count]PartitionRef (16 bytes)   {filters offset, length, table offset, length}
//!     regions, each 64-byte aligned: a partition's PREFILTER, then its ATOM_TABLE
//!
//! A partition with no reference (zero lengths) has no searched program of its own target and
//! is scanned with partition 0. Every partition refers to the same ATOM_TABLE region: its
//! entries carry their program's target, and stage two keeps a partition's own and type 0's.
//!
//! PREFILTER[p], little-endian, offsets from the region start:
//!
//!     Header (64 bytes)     magic "PFLT", version, partition, filter count, seed, short list
//!     filters: [count]FilterRef (16 bytes)   {stride, q, blob offset, blob length}
//!     short:   [short_count]u32   programs with no atom, found by the reference scanner
//!     gate:    [65536]u8          which stride-one filters hold grams starting with two bytes
//!     blobs:   zig-regex `literals.Sbbf` blobs, each 64-byte aligned
//!
//! Each filter is a split-block Bloom filter over the `q`-byte grams (4, or 3 or 2 for tier D) at
//! offsets `0 .. stride - 1` of every atom of its tier, so sampling every `stride`-th position
//! cannot miss an atom (zig-regex `literals.sbbf`). Every filter of a partition shares one hash
//! seed: one hash per position serves all of them. Partition k >= 1 holds the atoms of its own
//! programs and of type 0, so a file is scanned once.
//!
//! ATOM_TABLE[p]:
//!
//!     Header (32 bytes)     magic "ATOM", version, slot count (a power of two), entry count
//!     slots:   [slot_count]Slot (8 bytes)    {key, first entry}, linear probing, at most half full
//!     entries: [entry_count]Entry (16 bytes) {program, extension, back, ext_len, stride, q, flags}
//!     checks:  [check_count]Check (24 bytes)  {offset in the anchor part, value, mask}
//!
//! A slot's key is an atom's first gram (shorter grams zero-extended); its entries follow one
//! another up to the one flagged `last`. A filter hit at position `pos` of a filter with stride
//! s means an atom may start at `pos - k` for some k below s: stage two reads the gram there,
//! probes the table, and for each entry of the same stride and gram length compares up to four
//! more bytes (`ext`), or a masked 8-byte window of the anchor part (a check), before handing
//! `pos - k - back` (the anchor part's start) to the verifier.
//! An atom occurrence is reported by exactly one sampled position of its own filter, so no
//! candidate is produced twice.
const std = @import("std");
const regex = @import("regex");
const sbbf = regex.literals.sbbf;
const prog = @import("prog.zig");

pub const Header = extern struct {
    magic: [4]u8 = "PFLT".*,
    version: u32 = 1,
    partition: u8,
    filter_count: u8,
    _pad: u16 = 0,
    seed: u32,
    short_off: u32,
    short_count: u32,
    /// Offset of the stride-one gate, 0 for none: one byte per possible first two bytes of a
    /// gram, saying which stride-one filters hold a gram starting with them (`gate_s1`,
    /// `gate_q3`, `gate_q2`), so the many positions whose two bytes start no such gram skip
    /// those filters' block tests and the rest test only the filters that can hold them.
    gate_off: u32 = 0,
    _reserved: [36]u8 = @splat(0),
};

pub const FilterRef = extern struct {
    stride: u8,
    q: u8,
    _pad: u16 = 0,
    off: u32,
    len: u32,
    /// Atoms (programs, counting case variants once) in the filter.
    atoms: u32,
};

pub const TableHeader = extern struct {
    magic: [4]u8 = "ATOM".*,
    version: u32 = 1,
    slot_count: u32,
    entry_count: u32,
    check_count: u32 = 0,
    _reserved: [12]u8 = @splat(0),
};

/// A masked compare of the 8 bytes at `rel` from the anchor part's start, for atoms whose own
/// bytes and extension say little (a run of zeros next to a short opcode): the entry's `ext`
/// holds the check's index instead of extension bytes.
pub const Check = extern struct {
    rel: u32,
    _pad: u32 = 0,
    value: u64,
    mask: u64,
};

pub const empty_slot: u32 = 0xffff_ffff;
pub const gate_len = 65536;
pub const gate_s1: u8 = 1 << 0;
pub const gate_q3: u8 = 1 << 1;
pub const gate_q2: u8 = 1 << 2;

pub const Slot = extern struct {
    key: u32,
    first: u32,
};

pub const entry_last: u8 = 1 << 0;
pub const entry_nocase: u8 = 1 << 1;
/// `ext` is an index into the checks, not extension bytes.
pub const entry_check: u8 = 1 << 2;
/// The program's target type sits in the top four bits: the table is shared by every
/// partition, and a partition keeps entries of its own target and of type 0.
pub const entry_target_shift = 4;

pub const Entry = extern struct {
    prog: u32,
    /// Up to four bytes that follow the key gram in the atom, little-endian.
    ext: u32,
    /// Distance from the atom's first byte back to the anchor part's start.
    back: u32,
    ext_len: u8,
    stride: u8,
    q: u8,
    flags: u8,
};

comptime {
    std.debug.assert(@sizeOf(Header) == 64);
    std.debug.assert(@sizeOf(FilterRef) == 16);
    std.debug.assert(@sizeOf(TableHeader) == 32);
    std.debug.assert(@sizeOf(Slot) == 8);
    std.debug.assert(@sizeOf(Entry) == 16);
}

pub const Directory = extern struct {
    magic: [4]u8 = "PFDR".*,
    version: u32 = 1,
    partition_count: u32,
    _reserved: [52]u8 = @splat(0),
};

pub const PartitionRef = extern struct {
    filters_off: u32 = 0,
    filters_len: u32 = 0,
    table_off: u32 = 0,
    table_len: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Directory) == 64);
    std.debug.assert(@sizeOf(PartitionRef) == 16);
}

pub const partitions = 15;

/// Every partition of a PREFILTER section, validated.
pub fn loadAll(section: []const u8, programs: prog.Programs) Error![partitions]?Partition {
    var out: [partitions]?Partition = @splat(null);
    if (section.len < @sizeOf(Directory) or @intFromPtr(section.ptr) % 64 != 0) return error.BadPrefilter;
    const d: *const Directory = @ptrCast(@alignCast(section.ptr));
    if (!std.mem.eql(u8, &d.magic, "PFDR") or d.version != 1 or d.partition_count > partitions) return error.BadPrefilter;
    const refs_end = @sizeOf(Directory) + @as(usize, d.partition_count) * @sizeOf(PartitionRef);
    if (refs_end > section.len) return error.BadPrefilter;
    const refs = std.mem.bytesAsSlice(PartitionRef, section[@sizeOf(Directory)..refs_end]);
    for (refs, 0..) |r, p| {
        if (r.filters_len == 0) continue;
        if (@as(u64, r.filters_off) + r.filters_len > section.len or @as(u64, r.table_off) + r.table_len > section.len) return error.BadPrefilter;
        if (r.filters_off % 64 != 0 or r.table_off % 64 != 0) return error.BadPrefilter;
        // Every partition refers to one table: it is validated once.
        var shared: ?*const Partition = null;
        for (out[0..p], refs[0..p]) |*prev, pr| {
            if (prev.* != null and pr.table_off == r.table_off and pr.table_len == r.table_len) shared = &prev.*.?;
        }
        out[p] = try Partition.init(section[r.filters_off..][0..r.filters_len], section[r.table_off..][0..r.table_len], programs, shared);
        if (out[p].?.partition != p) return error.BadPrefilter;
    }
    return out;
}

pub const max_filters = 5;

pub const Filter = struct {
    stride: u8,
    q: u8,
    atoms: u32,
    sbbf: sbbf.Sbbf,
};

pub const Error = error{BadPrefilter};

/// One partition's filters and atom table, viewed in place.
pub const Partition = struct {
    partition: u8,
    seed: u32,
    filters: [max_filters]Filter,
    filter_count: usize,
    short: []align(1) const u32,
    /// The stride-one gate (see `Header.gate_off`), empty when no stride-one filter exists.
    gate: []const u8,
    slots: []const Slot,
    entries: []const Entry,
    checks: []const Check,

    /// View a partition's PREFILTER region and the ATOM_TABLE region, or reuse the table an
    /// earlier partition already validated (`shared`).
    pub fn init(pf_bytes: []const u8, table_bytes: []const u8, programs: prog.Programs, shared: ?*const Partition) Error!Partition {
        if (pf_bytes.len < @sizeOf(Header) or @intFromPtr(pf_bytes.ptr) % 64 != 0) return error.BadPrefilter;
        const h: *const Header = @ptrCast(@alignCast(pf_bytes.ptr));
        if (!std.mem.eql(u8, &h.magic, "PFLT") or h.version != 1 or h.filter_count > max_filters) return error.BadPrefilter;
        var part: Partition = .{
            .partition = h.partition,
            .seed = h.seed,
            .filters = undefined,
            .filter_count = h.filter_count,
            .short = &.{},
            .gate = &.{},
            .slots = &.{},
            .entries = &.{},
            .checks = &.{},
        };
        const refs_end = @sizeOf(Header) + @as(usize, h.filter_count) * @sizeOf(FilterRef);
        if (refs_end > pf_bytes.len) return error.BadPrefilter;
        const refs = std.mem.bytesAsSlice(FilterRef, pf_bytes[@sizeOf(Header)..refs_end]);
        for (refs, 0..) |r, i| {
            const ok_stride = (r.q == 4 and (r.stride == 1 or r.stride == 4 or r.stride == 8)) or ((r.q == 3 or r.q == 2) and r.stride == 1);
            if (!ok_stride or r.off % 64 != 0 or @as(u64, r.off) + r.len > pf_bytes.len) return error.BadPrefilter;
            const f = sbbf.Sbbf.load(pf_bytes[r.off..][0..r.len]) catch return error.BadPrefilter;
            if (f.seed != h.seed or f.stride != r.stride) return error.BadPrefilter;
            for (refs[0..i]) |prev| if (prev.stride == r.stride and prev.q == r.q) return error.BadPrefilter;
            part.filters[i] = .{ .stride = r.stride, .q = r.q, .atoms = r.atoms, .sbbf = f };
        }
        if (@as(u64, h.short_off) + @as(u64, h.short_count) * 4 > pf_bytes.len) return error.BadPrefilter;
        part.short = std.mem.bytesAsSlice(u32, pf_bytes[h.short_off..][0 .. @as(usize, h.short_count) * 4]);
        for (part.short) |i| if (i >= programs.count()) return error.BadPrefilter;
        var stride_one = false;
        for (part.filters[0..part.filter_count]) |f| stride_one = stride_one or f.stride == 1;
        if (stride_one) {
            if (h.gate_off == 0 or h.gate_off % 64 != 0 or @as(u64, h.gate_off) + gate_len > pf_bytes.len) return error.BadPrefilter;
            part.gate = pf_bytes[h.gate_off..][0..gate_len];
        } else if (h.gate_off != 0) return error.BadPrefilter;

        if (shared) |t| {
            part.slots = t.slots;
            part.entries = t.entries;
            part.checks = t.checks;
            return part;
        }
        try part.initTable(table_bytes, programs);
        return part;
    }

    /// Validate and view the ATOM_TABLE region.
    fn initTable(part: *Partition, table_bytes: []const u8, programs: prog.Programs) Error!void {
        if (table_bytes.len < @sizeOf(TableHeader) or @intFromPtr(table_bytes.ptr) % 8 != 0) return error.BadPrefilter;
        const th: *const TableHeader = @ptrCast(@alignCast(table_bytes.ptr));
        if (!std.mem.eql(u8, &th.magic, "ATOM") or th.version != 1) return error.BadPrefilter;
        if (th.slot_count == 0 or !std.math.isPowerOfTwo(th.slot_count)) return error.BadPrefilter;
        const slots_end = @sizeOf(TableHeader) + @as(u64, th.slot_count) * @sizeOf(Slot);
        const entries_end = slots_end + @as(u64, th.entry_count) * @sizeOf(Entry);
        const checks_end = entries_end + @as(u64, th.check_count) * @sizeOf(Check);
        if (checks_end > table_bytes.len) return error.BadPrefilter;
        const slot_ptr: [*]const Slot = @ptrCast(@alignCast(table_bytes.ptr + @sizeOf(TableHeader)));
        const entry_ptr: [*]const Entry = @ptrCast(@alignCast(table_bytes.ptr + slots_end));
        part.slots = slot_ptr[0..th.slot_count];
        part.entries = entry_ptr[0..th.entry_count];
        const check_ptr: [*]const Check = @ptrCast(@alignCast(table_bytes.ptr + entries_end));
        part.checks = check_ptr[0..th.check_count];
        // Every chain stays inside the entries and ends; every program exists and carries the
        // atom the entry claims. A corrupt table is refused rather than half used.
        var free: usize = 0;
        for (part.slots) |s| {
            if (s.first == empty_slot) {
                free += 1;
                continue;
            }
            var e = s.first;
            while (true) : (e += 1) {
                if (e >= part.entries.len) return error.BadPrefilter;
                const entry = part.entries[e];
                if (entry.prog >= programs.count() or entry.ext_len > 4) return error.BadPrefilter;
                if (entry.flags & entry_check != 0 and (entry.ext >= part.checks.len or entry.ext_len != 0)) return error.BadPrefilter;
                // Entries of filters this partition lacks belong to other partitions.
                const ok = (entry.q == 4 and (entry.stride == 1 or entry.stride == 4 or entry.stride == 8)) or ((entry.q == 3 or entry.q == 2) and entry.stride == 1);
                if (!ok or entry.flags >> entry_target_shift > 14) return error.BadPrefilter;
                if (entry.flags & entry_last != 0) break;
            }
        }
        if (free == 0) return error.BadPrefilter;
    }

    /// The first entry for `key`, or null.
    pub inline fn lookup(part: *const Partition, key: u32) ?u32 {
        const mask = part.slots.len - 1;
        var i = slotOf(key, part.slots.len);
        while (true) : (i = (i + 1) & mask) {
            const s = part.slots[i];
            if (s.first == empty_slot) return null;
            if (s.key == key) return s.first;
        }
    }
};

/// Print each partition's filters (size, grams, bits per gram, share of bits set, expected
/// false-positive rate) and the shared atom table's load, for `zav info` and E2.
pub fn describe(parts: *const [partitions]?Partition, w: *std.Io.Writer) !void {
    var table_done = false;
    for (parts, 0..) |slot, p| {
        const part = slot orelse continue;
        if (!table_done) {
            table_done = true;
            var used: usize = 0;
            for (part.slots) |sl| used += @intFromBool(sl.first != empty_slot);
            try w.print("  atom table   {d} slots ({d:.1}% used), {d} entries, {d} checks, {d} bytes\n", .{
                part.slots.len,
                100 * @as(f64, @floatFromInt(used)) / @as(f64, @floatFromInt(part.slots.len)),
                part.entries.len,
                part.checks.len,
                part.slots.len * @sizeOf(Slot) + part.entries.len * @sizeOf(Entry) + part.checks.len * @sizeOf(Check),
            });
        }
        try w.print("  partition {d:<2} {d} programs without an atom{s}\n", .{ p, part.short.len, if (part.gate.len > 0) ", stride-one gate" else "" });
        for (part.filters[0..part.filter_count]) |f| {
            var set: u64 = 0;
            for (f.sbbf.blocks) |b| for (b) |word| {
                set += @popCount(word);
            };
            const bits = f.sbbf.blocks.len * 256;
            try w.print("    stride {d} q {d}: {d} atoms, {d} grams, {d} bytes, {d:.1} bits/gram, {d:.1}% bits set, expected FPR {d:.3}%\n", .{
                f.stride,                                                                         f.q,
                f.atoms,                                                                          f.sbbf.num_keys,
                f.sbbf.blocks.len * 32,                                                           @as(f64, @floatFromInt(bits)) / @as(f64, @floatFromInt(@max(f.sbbf.num_keys, 1))),
                100 * @as(f64, @floatFromInt(set)) / @as(f64, @floatFromInt(bits)), f.sbbf.expectedFalsePositiveRate() * 100,
            });
        }
    }
}

/// The home slot of `key` in a table of `n` slots (a power of two).
pub inline fn slotOf(key: u32, n: usize) usize {
    const h = (@as(u64, key) *% 0x9E37_79B9_7F4A_7C15) >> 32;
    return @intCast(h & (n - 1));
}

pub inline fn load4(data: []const u8, pos: usize) u32 {
    return std.mem.readInt(u32, data[pos..][0..4], .little);
}

inline fn foldGram(x: u32) u32 {
    // ASCII lowercase on all four bytes at once: bytes in 'A'..'Z' get 0x20 added.
    const v: @Vector(4, u8) = @bitCast(x);
    const upper = (v >= @as(@Vector(4, u8), @splat('A'))) & (v <= @as(@Vector(4, u8), @splat('Z')));
    return @bitCast(v | @select(u8, upper, @as(@Vector(4, u8), @splat(0x20)), @as(@Vector(4, u8), @splat(0))));
}

/// Whether the `len` bytes at `data[pos..]` equal the low `len` bytes of `ext`.
inline fn extMatches(data: []const u8, pos: usize, ext: u32, len: u8, nocase: bool) bool {
    if (len == 0) return true;
    if (pos + len > data.len) return false;
    var got: u32 = 0;
    for (0..len) |i| got |= @as(u32, data[pos + i]) << @intCast(8 * i);
    const mask: u32 = if (len == 4) 0xffff_ffff else (@as(u32, 1) << @intCast(8 * len)) - 1;
    if (nocase) return foldGram(got) & mask == foldGram(ext) & mask;
    return got & mask == ext & mask;
}

/// Whether the check's window, read from the anchor part starting at `part_start`, matches.
/// A window running past the data cannot be decided here: the verifier decides.
inline fn checkMatches(c: Check, data: []const u8, part_start: usize) bool {
    const at = part_start + c.rel;
    if (at + 8 > data.len) return true;
    return std.mem.readInt(u64, data[at..][0..8], .little) & c.mask == c.value;
}

/// A candidate from stage one: a sampled position and the filter that fired.
pub const Candidate = packed struct(u64) {
    pos: u56,
    filter: u8,
};

/// Candidates per stage-two batch (8 KiB on the scanning thread's stack).
pub const ring_len = 1024;

/// Counters for E2 and E3.
pub const Stats = struct {
    /// Positions where some filter fired.
    candidates: u64 = 0,
    /// Atom table probes in stage two.
    probes: u64 = 0,
    /// Entries whose extension bytes matched (handed to the verifier).
    verifies: u64 = 0,
    /// Deferred programs searched in the second pass.
    deferred: u64 = 0,
    /// Verifies per program, when a benchmark wants to see which atoms fire.
    per_prog: ?[]u32 = null,
    /// Whole-buffer scanner runs per program (no atom, or deferred and not batched).
    per_prog_scans: ?[]u32 = null,
    /// Whole-buffer scanner runs.
    scans: u64 = 0,
    /// Verify calls that ran out of their own step budget, per program.
    per_prog_exhausted: ?[]u32 = null,
    /// Candidates and probes by filter kind: stride 8, 4, 1 (4-byte grams), 3-gram, 2-gram.
    by_kind: [5]struct { candidates: u64 = 0, probes: u64 = 0, verifies: u64 = 0 } = @splat(.{}),
};

/// Run stages one and two over `data`, calling `sink.candidate(prog_index, anchor_start)` for
/// every surviving candidate; it returns false to stop the scan. `ring` is caller scratch.
pub fn scan(part: *const Partition, data: []const u8, ring: *[ring_len]Candidate, sink: anytype, stats: ?*Stats) bool {
    var pos: usize = 0;
    while (pos < data.len) {
        const n, const next = stage1(part, data, pos, ring);
        pos = next;
        if (stats) |s| s.candidates += n;
        if (!stage2(part, data, ring[0..n], sink, stats)) return false;
    }
    return true;
}

/// Stage one from `start` until the ring is nearly full or the data ends: the candidates
/// written and where to resume.
pub fn stage1(part: *const Partition, data: []const u8, start: usize, ring: *[ring_len]Candidate) struct { usize, usize } {
    return kernel.run(part, data, start, ring);
}

const kernel = @import("stage1.zig");

/// Stage two over a batch of candidates.
pub fn stage2(part: *const Partition, data: []const u8, cands: []const Candidate, sink: anytype, stats: ?*Stats) bool {
    for (cands) |c| {
        const f = part.filters[c.filter];
        const pos: usize = c.pos;
        const kind: usize = switch (f.q) {
            4 => switch (f.stride) {
                8 => 0,
                4 => 1,
                else => 2,
            },
            3 => 3,
            else => 4,
        };
        if (stats) |s| s.by_kind[kind].candidates += 1;
        var k: usize = 0;
        while (k < f.stride and k <= pos) : (k += 1) {
            const start = pos - k;
            if (start + f.q > data.len) continue;
            const key = switch (f.q) {
                4 => load4(data, start),
                3 => @as(u32, data[start]) | @as(u32, data[start + 1]) << 8 | @as(u32, data[start + 2]) << 16,
                else => @as(u32, data[start]) | @as(u32, data[start + 1]) << 8,
            };
            if (stats) |s| {
                s.probes += 1;
                s.by_kind[kind].probes += 1;
            }
            var e = part.lookup(key) orelse continue;
            while (true) : (e += 1) {
                const entry = part.entries[e];
                const target = entry.flags >> entry_target_shift;
                if (entry.stride == f.stride and entry.q == f.q and entry.back <= start and
                    (target == 0 or target == part.partition) and
                    (if (entry.flags & entry_check != 0) checkMatches(part.checks[entry.ext], data, start - entry.back) else extMatches(data, start + f.q, entry.ext, entry.ext_len, entry.flags & entry_nocase != 0)))
                {
                    if (stats) |s| {
                        s.verifies += 1;
                        s.by_kind[kind].verifies += 1;
                        if (s.per_prog) |pp| pp[entry.prog] +|= 1;
                    }
                    if (!sink.candidate(entry.prog, start - entry.back)) return false;
                }
                if (entry.flags & entry_last != 0) break;
            }
        }
    }
    return true;
}

/// The stage-one reference: every position, every filter its stride samples, the filter's own
/// membership test behind the gate the kernel uses. The kernel must return exactly these.
pub fn stage1Reference(part: *const Partition, data: []const u8, out: *std.ArrayList(Candidate), gpa: std.mem.Allocator) !void {
    for (0..data.len) |pos| {
        for (part.filters[0..part.filter_count], 0..) |f, fi| {
            if (pos % f.stride != 0 or pos + f.q > data.len) continue;
            if (f.q == 4 and pos + 4 > data.len) continue;
            var g: u32 = 0;
            for (0..f.q) |k| g |= @as(u32, data[pos + k]) << @intCast(8 * k);
            if (f.stride == 1) {
                if (pos + 2 > data.len) continue;
                const two = std.mem.readInt(u16, data[pos..][0..2], .little);
                const bit: u8 = switch (f.q) {
                    4 => gate_s1,
                    3 => gate_q3,
                    else => gate_q2,
                };
                if (part.gate[two] & bit == 0) continue;
            }
            if (f.sbbf.contains(g)) try out.append(gpa, .{ .pos = @intCast(pos), .filter = @intCast(fi) });
        }
    }
}

const testing = std.testing;

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    programs: prog.Programs,
    part: Partition,

    fn deinit(f: *Fixture) void {
        f.arena.deinit();
    }
};

/// Programs for `hexes` (all type 0, searched, atoms chosen by the default model), and
/// partition 0 built over them.
fn fixture(hexes: []const []const u8) !Fixture {
    const zc = struct {
        const hexsig = @import("../compile/hexsig.zig");
        const prog_build = @import("../compile/prog_build.zig");
        const atoms = @import("../compile/atoms.zig");
        const gm = @import("../compile/gram_model.zig");
        const prefilter_build = @import("../compile/prefilter_build.zig");
    };
    var f: Fixture = .{ .arena = .init(testing.allocator), .programs = undefined, .part = undefined };
    errdefer f.arena.deinit();
    const a = f.arena.allocator();
    var inputs: std.ArrayList(zc.prog_build.Input) = .empty;
    for (hexes, 0..) |hex, i| {
        var diag: zc.hexsig.Diag = .{};
        try inputs.append(a, .{ .pattern = try zc.hexsig.parse(a, hex, &diag), .sig = @intCast(i) });
    }
    const planned = try zc.atoms.plan(a, zc.gm.Model.default(), .{}, inputs.items, &.{});
    var w = zc.prog_build.Writer.init(a, null);
    for (inputs.items, planned) |*in, p| {
        in.atom = p.atom(in.offset.kind);
        _ = try w.add(in.*);
    }
    const bytes = try w.finish();
    const image = try a.alignedAlloc(u8, .@"64", bytes.len);
    @memcpy(image, bytes);
    f.programs = try .init(image);
    const section = (try zc.prefilter_build.buildAll(a, f.programs, w.atoms.items, .{})).?;
    const all = try loadAll(section, f.programs);
    f.part = all[0].?;
    return f;
}

/// Bytes the program matches (shortest gaps, first alternatives, random filler) and where its
/// anchor part starts in them.
fn sampleOf(a: std.mem.Allocator, p: prog.Program, r: std.Random) !struct { []const u8, usize } {
    var out: std.ArrayList(u8) = .empty;
    var part: usize = 0;
    var anchor_start: usize = 0;
    for (p.pattern.ops) |o| {
        switch (o.code) {
            .lit => try out.appendSlice(a, p.pattern.bytes(o)),
            .masked => for (p.pattern.bytes(o), p.pattern.masks(o)) |v, m| {
                try out.append(a, (r.int(u8) & ~m) | (v & m));
            },
            .gapf => for (0..o.a) |_| try out.append(a, r.int(u8)),
            .alt => for (p.pattern.altOps(p.pattern.alternatives(o)[0])) |x| switch (x.code) {
                .lit => try out.appendSlice(a, p.pattern.bytes(x)),
                .masked => try out.appendSlice(a, p.pattern.bytes(x)),
                else => for (0..x.a) |_| try out.append(a, r.int(u8)),
            },
            .bound => try out.append(a, ' '),
            .part_end => {
                for (0..o.a) |_| try out.append(a, r.int(u8));
                part += 1;
                if (part == p.header.anchor_part) anchor_start = out.items.len;
            },
            else => return error.Unsupported,
        }
    }
    return .{ out.items, anchor_start };
}

const Collect = struct {
    gpa: std.mem.Allocator,
    got: std.ArrayList([2]usize) = .empty,

    pub fn candidate(c: *Collect, prog_index: u32, anchor_start: usize) bool {
        c.got.append(c.gpa, .{ prog_index, anchor_start }) catch return false;
        return true;
    }
};

test "every planted atom is found: tiers A to D, nocase, wide, the end of the data" {
    const hexes = [_][]const u8{
        "13a7c95be2f1408d77e3b1aa", // tier A
        "5be2f1408d77e3", // tier B
        "c95be2f1", // tier C
        "ff25a4{3}0000000000000000", // a 3-byte atom beats zeros
        "8185??f?ffff{4}81ad", // only 2-byte literals
        "6576616c28756e65736361706528", // text, stride 8
    };
    var f = try fixture(&hexes);
    defer f.deinit();
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    var data: [1 << 16]u8 = undefined;
    r.bytes(&data);
    // Plant a match of each program at many offsets, including the very end, and remember
    // where its anchor part starts.
    var planted: std.ArrayList(struct { prog: usize, at: usize, sample: []const u8, anchor_start: usize }) = .empty;
    defer planted.deinit(testing.allocator);
    var sample_arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer sample_arena.deinit();
    for (0..f.programs.count()) |pi| {
        const p = f.programs.get(pi);
        const sample, const part_start = try sampleOf(sample_arena.allocator(), p, r);
        for (0..40) |n| {
            const at = if (n == 0) data.len - sample.len else r.uintLessThan(usize, data.len - sample.len - 64) + 32;
            @memcpy(data[at..][0..sample.len], sample);
            try planted.append(testing.allocator, .{ .prog = pi, .at = at, .sample = sample, .anchor_start = at + part_start });
        }
    }
    var c: Collect = .{ .gpa = testing.allocator };
    defer c.got.deinit(testing.allocator);
    var ring: [ring_len]Candidate = undefined;
    _ = scan(&f.part, &data, &ring, &c, null);
    for (planted.items) |want| {
        // Overwritten by a later plant: no longer there.
        if (!std.mem.eql(u8, data[want.at..][0..want.sample.len], want.sample)) continue;
        var found = false;
        for (c.got.items) |g| found = found or (g[0] == want.prog and g[1] == want.anchor_start);
        if (!found) {
            std.debug.print("missed program {d} at {d}\n", .{ want.prog, want.at });
            return error.TestUnexpectedResult;
        }
    }
}

test "the kernel and the scalar reference return the same candidates" {
    const hexes = [_][]const u8{ "13a7c95be2f1408d77e3b1aa", "5be2f1408d77e3", "c95be2f1", "ff25a4{3}0000000000000000", "8185??f?ffff{4}81ad", "4142434445464748494a4b", "000000ff" };
    var f = try fixture(&hexes);
    defer f.deinit();
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    const data = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(data);
    // Random bytes, runs of zeros, and text-like stretches, so every filter fires.
    r.bytes(data);
    for (0..200) |_| {
        const at = r.uintLessThan(usize, data.len - 300);
        switch (r.uintLessThan(u8, 3)) {
            0 => @memset(data[at..][0..256], 0),
            1 => for (data[at..][0..256]) |*b| {
                b.* = 'a' + r.uintLessThan(u8, 26);
            },
            else => @memcpy(data[at..][0..4], "\xc9\x5b\xe2\xf1"),
        }
    }
    var want: std.ArrayList(Candidate) = .empty;
    defer want.deinit(testing.allocator);
    try stage1Reference(&f.part, data, &want, testing.allocator);
    var got: std.ArrayList(Candidate) = .empty;
    defer got.deinit(testing.allocator);
    var ring: [ring_len]Candidate = undefined;
    // Odd slices too, so unaligned starts and the scalar tail are covered.
    for ([_]usize{ 0, 1, 7, 16, 31 }) |skip| {
        got.clearRetainingCapacity();
        want.clearRetainingCapacity();
        try stage1Reference(&f.part, data[skip..], &want, testing.allocator);
        var pos: usize = 0;
        while (pos < data.len - skip) {
            const n, const next = stage1(&f.part, data[skip..], pos, &ring);
            try got.appendSlice(testing.allocator, ring[0..n]);
            pos = next;
        }
        const lt = struct {
            fn less(_: void, a: Candidate, b: Candidate) bool {
                return @as(u64, @bitCast(a)) < @as(u64, @bitCast(b));
            }
        }.less;
        std.mem.sort(Candidate, want.items, {}, lt);
        std.mem.sort(Candidate, got.items, {}, lt);
        try testing.expectEqualSlices(u64, @ptrCast(want.items), @ptrCast(got.items));
    }
}

test "false-positive rate on random data is within twice the theoretical rate" {
    // Many random tier-A atoms make a filter of realistic size.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    const hexes = try a.alloc([]const u8, 20000);
    for (hexes) |*h| {
        var raw: [12]u8 = undefined;
        r.bytes(&raw);
        h.* = try std.fmt.allocPrint(a, "{x}", .{raw});
    }
    var f = try fixture(hexes);
    defer f.deinit();
    const data = try a.alloc(u8, 1 << 22);
    r.bytes(data);
    var ring: [ring_len]Candidate = undefined;
    for (f.part.filters[0..f.part.filter_count], 0..) |filt, fi| {
        if (filt.stride != 8) continue;
        var hits: u64 = 0;
        var tested: u64 = 0;
        var pos: usize = 0;
        while (pos < data.len) {
            const n, const next = stage1(&f.part, data, pos, &ring);
            for (ring[0..n]) |c| hits += @intFromBool(c.filter == fi);
            pos = next;
        }
        tested = data.len / 8;
        const rate = @as(f64, @floatFromInt(hits)) / @as(f64, @floatFromInt(tested));
        const theory = filt.sbbf.expectedFalsePositiveRate();
        try testing.expect(rate <= 2 * theory);
        try testing.expect(rate >= theory / 2);
    }
}
