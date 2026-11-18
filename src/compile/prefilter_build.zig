//! Builds the PREFILTER[p] and ATOM_TABLE[p] regions of one partition (layouts in
//! match/prefilter.zig) from the finished SUBSIG_PROG programs and the atoms atoms.zig chose for
//! them (prog_build.Writer.atoms). The filters are zig-regex `literals.Sbbf` blobs, built by its
//! builder.
const std = @import("std");
const regex = @import("regex");
const sbbf = regex.literals.sbbf;
const prog = @import("../match/prog.zig");
const pf = @import("../match/prefilter.zig");
const atoms = @import("atoms.zig");
const prog_build = @import("prog_build.zig");

pub const Options = struct {
    /// Filter size per distinct gram; about 16 gives 0.1 to 0.3 percent false positives.
    bits_per_key: u32 = 16,
    seed: u32 = 0x7a61_7631,
};

const filter_specs = [_]struct { stride: u8, q: u8 }{ .{ .stride = 8, .q = 4 }, .{ .stride = 4, .q = 4 }, .{ .stride = 1, .q = 4 }, .{ .stride = 1, .q = 3 }, .{ .stride = 1, .q = 2 } };
/// Filters with only a few grams still get this many bits (2 KiB), so their false-positive
/// rate stays near zero instead of a block holding every key.
const min_filter_bits = 16384;

fn specIndex(stride: u8, q: u8) usize {
    for (filter_specs, 0..) |s, i| if (s.stride == stride and s.q == q) return i;
    unreachable;
}

const Keyed = struct {
    key: u32,
    entry: pf.Entry,

    fn less(_: void, a: Keyed, b: Keyed) bool {
        if (a.key != b.key) return a.key < b.key;
        if (a.entry.prog != b.entry.prog) return a.entry.prog < b.entry.prog;
        return a.entry.stride < b.entry.stride;
    }
};

fn gramOf(bytes: []const u8, q: u8) u32 {
    var g: u32 = 0;
    for (bytes[0..q], 0..) |b, i| g |= @as(u32, b) << @intCast(8 * i);
    return g;
}

/// Whether program `p` is searched in `partition`: its own target, or type 0 everywhere.
fn inPartition(p: prog.Program, partition: u8) bool {
    return p.header.target == partition or p.header.target == 0;
}

/// The atom of a searched program: its window in the anchor literal, or null.
const Window = struct { lit: []const u8, window: []const u8, nocase: bool };

fn windowOf(p: prog.Program, spec: prog_build.AtomSpec) Window {
    const op = p.pattern.ops[p.header.anchor_op];
    const lit = p.pattern.bytes(op);
    return .{ .lit = lit, .window = lit[spec.off..][0 .. spec.stride + spec.q - 1], .nocase = op.flags & @import("ir.zig").op_nocase != 0 };
}

fn searched(p: prog.Program) bool {
    return p.header.off_kind == .any and p.header.flags & prog.flag_deferred == 0;
}

/// The ATOM_TABLE region every partition shares: the atoms of every searched program, each
/// entry tagged with its program's target, so a partition's stage two keeps only its own and
/// type 0's (one table instead of type 0's atoms copied into each partition).
pub fn buildTable(gpa: std.mem.Allocator, programs: prog.Programs, specs: []const prog_build.AtomSpec) ![]align(64) u8 {
    var keyed: std.ArrayList(Keyed) = .empty;
    defer keyed.deinit(gpa);
    var checks: std.ArrayList(pf.Check) = .empty;
    defer checks.deinit(gpa);
    for (0..programs.count()) |i| {
        const p = programs.get(i);
        const h = p.header;
        const spec = specs[i];
        if (!searched(p) or spec.q == 0) continue;
        const w = windowOf(p, spec);
        const lit = w.lit;
        const after = lit.len - spec.off - spec.q;
        const ext_len: u8 = @intCast(@min(after, 4));
        const check = bestCheck(p, @as(u32, spec.off) + h.anchor_delta, spec.q, lit[spec.off + spec.q ..][0..ext_len], w.nocase);
        var entry: pf.Entry = .{
            .prog = @intCast(i),
            .ext = gramOf(lit[spec.off + spec.q ..], ext_len),
            .back = @as(u32, spec.off) + h.anchor_delta,
            .ext_len = ext_len,
            .stride = spec.stride,
            .q = spec.q,
            .flags = (if (w.nocase) pf.entry_nocase else 0) | h.target << pf.entry_target_shift,
        };
        if (check) |ck| {
            entry.flags |= pf.entry_check;
            entry.ext = @intCast(checks.items.len);
            entry.ext_len = 0;
            try checks.append(gpa, ck);
        }
        if (!w.nocase) {
            try keyed.append(gpa, .{ .key = gramOf(w.window, spec.q), .entry = entry });
            continue;
        }
        if (check == null) entry.ext = gramOf(&lowerAll(lit[spec.off + spec.q ..][0..ext_len]), ext_len);
        var it = variants(w.window[0..spec.q]);
        while (it.next()) |v| try keyed.append(gpa, .{ .key = v, .entry = entry });
    }

    // Entries grouped by key in key order, slots at most half full.
    std.mem.sort(Keyed, keyed.items, {}, Keyed.less);
    var distinct: usize = 0;
    for (keyed.items, 0..) |k, i| {
        if (i == 0 or k.key != keyed.items[i - 1].key) distinct += 1;
    }
    const slot_count = try std.math.ceilPowerOfTwo(usize, @max(16, distinct * 2));
    const slots_at = @sizeOf(pf.TableHeader);
    const entries_at = slots_at + slot_count * @sizeOf(pf.Slot);
    const checks_at = entries_at + keyed.items.len * @sizeOf(pf.Entry);
    const table = try gpa.alignedAlloc(u8, .@"64", checks_at + checks.items.len * @sizeOf(pf.Check));
    errdefer gpa.free(table);
    const th: pf.TableHeader = .{ .slot_count = @intCast(slot_count), .entry_count = @intCast(keyed.items.len), .check_count = @intCast(checks.items.len) };
    @memcpy(table[checks_at..], std.mem.sliceAsBytes(checks.items));
    @memcpy(table[0..@sizeOf(pf.TableHeader)], std.mem.asBytes(&th));
    const slots: []pf.Slot = @ptrCast(@alignCast(table[slots_at..entries_at]));
    @memset(slots, .{ .key = 0, .first = pf.empty_slot });
    const entries: []pf.Entry = @ptrCast(@alignCast(table[entries_at..checks_at]));
    for (keyed.items, 0..) |k, i| {
        var e = k.entry;
        const last = i + 1 == keyed.items.len or keyed.items[i + 1].key != k.key;
        if (last) e.flags |= pf.entry_last;
        entries[i] = e;
        if (i == 0 or keyed.items[i - 1].key != k.key) {
            var s = pf.slotOf(k.key, slot_count);
            while (slots[s].first != pf.empty_slot) s = (s + 1) & (slot_count - 1);
            slots[s] = .{ .key = k.key, .first = @intCast(i) };
        }
    }
    return table;
}

/// The PREFILTER region of `partition` (its filters, gate and short list), or null when no
/// searched program of its own target exists (the scan then uses partition 0, which holds
/// every type-0 program).
pub fn build(gpa: std.mem.Allocator, programs: prog.Programs, specs: []const prog_build.AtomSpec, partition: u8, options: Options) !?[]align(64) u8 {
    var own = false;
    var builders: [filter_specs.len]?sbbf.Builder = @splat(null);
    defer for (&builders) |*b| if (b.*) |*x| x.deinit();
    var atom_counts: [filter_specs.len]u32 = @splat(0);
    var short: std.ArrayList(u32) = .empty;
    defer short.deinit(gpa);
    const gate = try gpa.alloc(u8, pf.gate_len);
    defer gpa.free(gate);
    @memset(gate, 0);

    for (0..programs.count()) |i| {
        const p = programs.get(i);
        if (!searched(p) or !inPartition(p, partition)) continue;
        if (p.header.target == partition) own = true;
        const spec = specs[i];
        if (spec.q == 0) {
            try short.append(gpa, @intCast(i));
            continue;
        }
        const w = windowOf(p, spec);
        const si = specIndex(spec.stride, spec.q);
        if (builders[si] == null) builders[si] = try sbbf.Builder.init(gpa, .{ .stride = spec.stride, .bits_per_key = 1, .seed = options.seed });
        const b = &builders[si].?;
        atom_counts[si] += 1;
        const gate_bit: u8 = switch (spec.q) {
            4 => pf.gate_s1,
            3 => pf.gate_q3,
            else => pf.gate_q2,
        };
        for (0..spec.stride) |k| {
            const g = w.window[k..][0..spec.q];
            if (!w.nocase) {
                const x = gramOf(g, spec.q);
                try b.addGram(x);
                if (spec.stride == 1) gate[x & 0xffff] |= gate_bit;
                continue;
            }
            var it = variants(g);
            while (it.next()) |v| {
                try b.addGram(v);
                if (spec.stride == 1) gate[v & 0xffff] |= gate_bit;
            }
        }
    }
    if (!own) return null;

    // PREFILTER: header, filter refs, short list, then the filter blobs.
    var owned: [filter_specs.len]?sbbf.Sbbf.Owned = @splat(null);
    defer for (&owned) |*o| if (o.*) |*x| x.deinit(gpa);
    var count: usize = 0;
    for (&builders, &owned) |*b, *o| if (b.*) |*x| {
        // Bits per distinct gram: the configured density, raised for small filters.
        const grams = distinctCount(x.grams.items);
        x.options.bits_per_key = @intCast(@max(options.bits_per_key, std.math.divCeil(usize, min_filter_bits, @max(grams, 1)) catch unreachable));
        o.* = try x.finish();
        count += 1;
    };
    const refs_at = @sizeOf(pf.Header);
    const short_at = refs_at + count * @sizeOf(pf.FilterRef);
    const stride_one = builders[2] != null or builders[3] != null or builders[4] != null;
    const gate_at = std.mem.alignForward(usize, short_at + short.items.len * 4, 64);
    var len = if (stride_one) gate_at + pf.gate_len else gate_at;
    len = std.mem.alignForward(usize, len, 64);
    const len_before_blobs = len;
    for (owned) |o| if (o) |x| {
        len = std.mem.alignForward(usize, len + x.bytes.len, 64);
    };
    const out = try gpa.alignedAlloc(u8, .@"64", len);
    errdefer gpa.free(out);
    @memset(out, 0);
    const header: pf.Header = .{
        .partition = partition,
        .filter_count = @intCast(count),
        .seed = options.seed,
        .short_off = @intCast(short_at),
        .short_count = @intCast(short.items.len),
        .gate_off = if (stride_one) @intCast(gate_at) else 0,
    };
    @memcpy(out[0..@sizeOf(pf.Header)], std.mem.asBytes(&header));
    @memcpy(out[short_at..][0 .. short.items.len * 4], std.mem.sliceAsBytes(short.items));
    if (stride_one) @memcpy(out[gate_at..][0..pf.gate_len], gate);
    var at = len_before_blobs;
    var r: usize = 0;
    for (owned, filter_specs, atom_counts) |o, spec, n| if (o) |x| {
        const ref: pf.FilterRef = .{ .stride = spec.stride, .q = spec.q, .off = @intCast(at), .len = @intCast(x.bytes.len), .atoms = n };
        @memcpy(out[refs_at + r * @sizeOf(pf.FilterRef) ..][0..@sizeOf(pf.FilterRef)], std.mem.asBytes(&ref));
        @memcpy(out[at..][0..x.bytes.len], x.bytes);
        at = std.mem.alignForward(usize, at + x.bytes.len, 64);
        r += 1;
    };
    return out;
}

/// The PREFILTER section for every partition (layout in match/prefilter.zig), or null when no
/// program is searched.
pub fn buildAll(gpa: std.mem.Allocator, programs: prog.Programs, specs: []const prog_build.AtomSpec, options: Options) !?[]align(64) u8 {
    std.debug.assert(specs.len == programs.count());
    var built: [pf.partitions]?[]align(64) u8 = @splat(null);
    defer for (built) |b| if (b) |x| gpa.free(x);
    var any = false;
    for (&built, 0..) |*slot, p| {
        slot.* = try build(gpa, programs, specs, @intCast(p), options);
        if (slot.* != null) any = true;
    }
    if (!any) return null;
    const table = try buildTable(gpa, programs, specs);
    defer gpa.free(table);
    var refs: [pf.partitions]pf.PartitionRef = @splat(.{});
    var len: usize = std.mem.alignForward(usize, @sizeOf(pf.Directory) + pf.partitions * @sizeOf(pf.PartitionRef), 64);
    const table_off = len;
    len = std.mem.alignForward(usize, len + table.len, 64);
    for (built, &refs) |b, *r| if (b) |x| {
        r.filters_off = @intCast(len);
        r.filters_len = @intCast(x.len);
        r.table_off = @intCast(table_off);
        r.table_len = @intCast(table.len);
        len = std.mem.alignForward(usize, len + x.len, 64);
    };
    const out = try gpa.alignedAlloc(u8, .@"64", len);
    @memset(out, 0);
    const dir: pf.Directory = .{ .partition_count = pf.partitions };
    @memcpy(out[0..@sizeOf(pf.Directory)], std.mem.asBytes(&dir));
    @memcpy(out[@sizeOf(pf.Directory)..][0 .. pf.partitions * @sizeOf(pf.PartitionRef)], std.mem.sliceAsBytes(&refs));
    @memcpy(out[table_off..][0..table.len], table);
    for (built, refs) |b, r| if (b) |x| @memcpy(out[r.filters_off..][0..x.len], x);
    return out;
}

/// Bits a byte constrains, weighted down for 00 and ff (the bytes padding is made of).
fn byteScore(value: u8, mask: u8) f32 {
    const bits: f32 = @floatFromInt(@popCount(mask));
    const v = value & mask;
    return if (v == 0 or v == mask) bits / 4 else bits;
}

/// A masked 8-byte window of the anchor part that says more than the extension bytes after
/// the atom, or null. `atom_at` is the atom's distance from the part's start; bytes inside the
/// atom's key gram are already matched and count for nothing.
fn bestCheck(p: prog.Program, atom_at: u32, q: u8, ext: []const u8, nocase: bool) ?pf.Check {
    if (nocase or p.header.flags & prog.flag_folded != 0) return null;
    // The anchor part's bytes at fixed distances from its start, up to 64.
    var value: [64]u8 = @splat(0);
    var mask: [64]u8 = @splat(0);
    var len: usize = 0;
    const ops = p.pattern.ops;
    var i: usize = 0;
    var part: usize = 0;
    while (i < ops.len and part < p.header.anchor_part) : (i += 1) {
        if (ops[i].code == .part_end) part += 1;
    }
    var delta: usize = 0;
    scan: while (i < ops.len and delta < value.len) : (i += 1) {
        const o = ops[i];
        switch (o.code) {
            .lit, .masked => {
                const bytes = p.pattern.bytes(o);
                for (0..o.len) |k| {
                    if (delta + k >= value.len) break :scan;
                    if (o.code == .masked and o.flags & @import("ir.zig").op_negate != 0) continue;
                    value[delta + k] = bytes[k];
                    mask[delta + k] = if (o.code == .lit) 0xff else p.pattern.masks(o)[k];
                    if (o.code == .lit and o.flags & @import("ir.zig").op_nocase != 0) return null;
                }
                delta += o.len;
            },
            .gapf => delta += o.a,
            else => break,
        }
        len = @min(delta, value.len);
    }
    if (atom_at < len) for (atom_at..@min(atom_at + q, len)) |k| {
        mask[k] = 0;
    };
    var ext_score: f32 = 0;
    for (ext) |b| ext_score += byteScore(b, 0xff);
    var best: f32 = 0;
    var best_at: usize = 0;
    var w: usize = 0;
    while (w + 8 <= @max(len, 8)) : (w += 1) {
        var score: f32 = 0;
        for (w..w + 8) |k| score += byteScore(value[k], mask[k]);
        if (score > best) {
            best = score;
            best_at = w;
        }
    }
    if (best < 12 or best <= ext_score + 4) return null;
    var c: pf.Check = .{ .rel = @intCast(best_at), .value = 0, .mask = 0 };
    for (0..8) |k| {
        c.value |= @as(u64, value[best_at + k] & mask[best_at + k]) << @intCast(8 * k);
        c.mask |= @as(u64, mask[best_at + k]) << @intCast(8 * k);
    }
    return c;
}

fn distinctCount(grams: []u32) usize {
    std.mem.sort(u32, grams, {}, std.sort.asc(u32));
    var n: usize = 0;
    for (grams, 0..) |g, i| {
        if (i == 0 or g != grams[i - 1]) n += 1;
    }
    return n;
}

fn lowerAll(bytes: []const u8) [4]u8 {
    var out: [4]u8 = @splat(0);
    for (bytes, 0..) |b, i| out[i] = std.ascii.toLower(b);
    return out;
}

fn variants(g: []const u8) atoms.Variants {
    var b: [4]u8 = @splat(0);
    @memcpy(b[0..g.len], g);
    return atoms.Variants.init(&b);
}
