//! Atom selection, tiers and tier-D deferral (docs/DESIGN.md 4.2, P4.03 and P4.10).
//!
//! Candidate rate, not signature count, decides scan speed, so each searched program gets the
//! rarest window the benign 4-gram model (gram_model.zig) knows of. A window is a run of
//! `stride + 3` bytes inside one literal op whose distance from its part's start is fixed (the
//! verify VM starts a candidate from there). Every 4-gram of it at offsets `0 .. stride - 1`
//! goes into the filter of its stride, so sampling every `stride`-th position finds it:
//!
//!     sampled   run of 6 or more bytes   stride 3   the window's 3 grams in the sampled filter
//!     C         run of 4 or 5            stride 1, behind the gate
//!     D         run of 3 or fewer        a 3- or 2-byte gram, behind the gate
//!
//! A sampled filter's stage-one cost is one block test per `stride` bytes whatever it holds,
//! and filters of different strides add up: strides 8 and 4 together cost 6 tests per 16
//! bytes, stride 2 alone 8, stride 3 alone 5.3. So each partition has one sampled stride
//! (`Costs.sampled`, 3 by default): every window long enough for it shares its filter, which
//! also keeps the filter small (3 grams per atom instead of 8). E2 records the measurements.
//! A window costs its grams' summed benign probability (stage-two probes per byte) plus a
//! penalty for the filter its stride needs, and the cheapest window wins. Stride-one windows
//! (4-byte and tier D) also pay for the positions their first two bytes open in the gate in
//! front of the stride-one filters: on PE files a gate holding text grams passed 30% of
//! positions.
//!
//! Logical signatures need far fewer atoms than they have subsigs. A *cover* of an expression
//! is a set of subsigs one of which must match whenever the expression is true: `0&1` is
//! covered by either subsig alone, `0|1` only by both, `(0|1)>2` by both, `0=0` by none.
//! Byte compares are covered by their trigger, PCRE subsigs by their trigger expression, and a
//! subsig pinned to an offset costs nothing (the anchored index checks it for every file). The
//! cheapest cover's subsigs are searched; every other subsig is *deferred*: it is searched only
//! in a second pass over a file in which its signature was touched, which can only happen when
//! a cover subsig matched. An expression with no cover keeps every subsig searched, so the
//! detections are the same as searching everything (Hyperscan's Rose decomposition, applied to
//! ClamAV's logical expressions).
const std = @import("std");
const ir = @import("ir.zig");
const prog = @import("../match/prog.zig");
const prog_build = @import("prog_build.zig");
const gm = @import("gram_model.zig");

pub const q = 4;

/// What atom selection weighs, in nanoseconds per scanned byte.
pub const Costs = struct {
    /// An atom table probe (the table is larger than the caches).
    probe_ns: f64 = 20,
    /// A verify call (its program is in the warm region).
    verify_ns: f64 = 200,
    /// The sampled strides windows may use (each of 2, 3, 4, 8 at most once); windows too
    /// short for every one of them go behind the gate at stride 1.
    sampled: []const u8 = &.{3},
    /// What a window pays for using the filter of its stride (`strides`): a bias towards
    /// sampled filters between windows of similar candidate cost. Whether a stride-1 filter
    /// exists at all is decided by the programs that cannot avoid one, and once it does an
    /// atom in it costs a probe only where its gram occurs, so the bias stays small.
    stride_penalty: [strides.len]f64 = .{ 0.0005, 0.0003, 0.0002, 0.0001, 0 },
    q3_penalty: f64 = 0.002,
    q2_penalty: f64 = 0.005,
    /// A position the stride-one gate passes, paid at the benign rate of a stride-one window's
    /// first two bytes. A pass costs about 9 ns in the batched kernel (a hash and up to three
    /// block tests); the bigram model, built mostly from non-PE files, rates the byte pairs of
    /// PE code rarer than PE files show, and 30 is the value of 4, 10 and 30 that gave the
    /// fastest stage one on B2, which the model never saw (E2).
    gate_ns: f64 = 30,
    /// Prefix selection (E3): the first 4-byte window of the first literal, stride 1, and no
    /// deferral.
    prefix: bool = false,
    /// Search every subsig (the non-deferred path the deferred one is checked against).
    no_defer: bool = false,
    /// Programs one atom table key (or deferred-pass key) may hold while another window is
    /// available (`Crowd`) that costs at most `crowd_slack` more.
    max_chain: u32 = 32,
    crowd_slack: f64 = 0.002,

    fn allows(c: Costs, s: u8) bool {
        return s == 1 or std.mem.indexOfScalar(u8, c.sampled, s) != null;
    }
};

/// Cost of a program with no atom at all (the reference scanner finds it): avoided whenever a
/// cover allows.
pub const no_atom_cost: f64 = 1000;
pub const tier_d_cost = no_atom_cost;

/// The strides of 4-byte windows, as `Costs.stride_penalty` orders them.
pub const strides = [_]u8{ 1, 2, 3, 4, 8 };

pub const Choice = struct {
    /// Sampling stride of the atom's filter: 8, 4, 3, 2 or 1 (always 1 for 3- and 2-byte atoms).
    stride: u8 = 0,
    anchor: prog_build.Anchor = .{},
    /// Offset of the atom's first byte inside the anchor literal.
    atom_off: u16 = 0,
    /// Gram length: 4, or 3 or 2 for a tier-D atom, 0 for none.
    q: u8 = 0,
    /// Estimated stage-two and verify nanoseconds per byte, plus the filter penalty (or
    /// `no_atom_cost`).
    cost: f64 = tier_d_cost,
    /// Longest fixed literal run seen, for the tier histogram.
    longest: u16 = 0,
};

/// Every literal op whose distance from its part's start is fixed, in op order.
pub const Literals = struct {
    pattern: ir.Pattern,
    part0_only: bool,
    i: usize = 0,
    part: usize = 0,
    delta: ?u32 = 0,

    pub const Item = struct { op: u16, part: u8, delta: u16 };

    pub fn next(it: *Literals) ?Item {
        const ops = it.pattern.ops;
        while (it.i < ops.len) {
            const i = it.i;
            const o = ops[i];
            it.i += 1;
            var out: ?Item = null;
            switch (o.code) {
                .part_end => {
                    if (it.part0_only) {
                        it.i = ops.len;
                        return null;
                    }
                    it.part += 1;
                    it.delta = 0;
                    continue;
                },
                .lit => if (it.delta) |d| if (d < prog.no_anchor) {
                    out = .{ .op = @intCast(i), .part = @intCast(it.part), .delta = @intCast(d) };
                },
                else => {},
            }
            if (it.delta) |d| it.delta = switch (o.code) {
                .lit, .masked => d + o.len,
                .gapf => d + o.a,
                .nalt => d + (o.b & 0xffff),
                .alt => if (o.b & 0xffff == o.b >> 16) d + (o.b & 0xffff) else null,
                .bound => d + ir.boundWidth(ops, i),
                else => null,
            };
            if (out) |x| return x;
        }
        return null;
    }
};

/// Benign probability of a 4-byte window, summed over its case variants when it is matched
/// case-insensitively.
pub fn gramProb(model: gm.Model, bytes: *const [4]u8, nocase: bool) f64 {
    if (!nocase) return model.prob(std.mem.readInt(u32, bytes, .little));
    var total: f64 = 0;
    var it = Variants.init(bytes);
    while (it.next()) |g| total += model.prob(g);
    return total;
}

/// The same for a 3-byte window.
pub fn gram3Prob(model: gm.Model, bytes: *const [3]u8, nocase: bool) f64 {
    if (!nocase) return model.prob3(bytes);
    var total: f64 = 0;
    var it = Variants.init3(bytes);
    while (it.next()) |g| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, g, .little);
        total += model.prob3(b[0..3]);
    }
    return total;
}

/// Benign probability of a window's first two bytes: how often the stride-one gate opens
/// for it.
pub fn gram2Prob(model: gm.Model, bytes: *const [2]u8, nocase: bool) f64 {
    if (!nocase) return model.prob2(bytes);
    var total: f64 = 0;
    var it = Variants.init(&(bytes.* ++ [2]u8{ 0, 0 }));
    while (it.next()) |g| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, g, .little);
        total += model.prob2(b[0..2]);
    }
    return total;
}

/// The case variants of a 4-byte (or 3-byte) window, ASCII letters only, as little-endian
/// grams (a 3-byte window's fourth byte is 0).
pub const Variants = struct {
    base: [4]u8,
    letters: u4,
    n: u5 = 0,

    pub fn init(bytes: *const [4]u8) Variants {
        var v: Variants = .{ .base = undefined, .letters = 0 };
        for (bytes, 0..) |b, i| {
            v.base[i] = std.ascii.toLower(b);
            if (std.ascii.isAlphabetic(b)) v.letters |= @as(u4, 1) << @intCast(i);
        }
        return v;
    }

    pub fn init3(bytes: *const [3]u8) Variants {
        return init(&(bytes.* ++ [1]u8{0}));
    }

    pub fn count(v: Variants) usize {
        return @as(usize, 1) << @intCast(@popCount(v.letters));
    }

    pub fn next(v: *Variants) ?u32 {
        // Walk the subsets of `letters`: variant k upper-cases the letters in subset k.
        while (v.n < 16) {
            const k: u4 = @intCast(v.n);
            v.n += 1;
            if (k & ~v.letters != 0) continue;
            var out = v.base;
            for (0..4) |i| {
                if (k & (@as(u4, 1) << @intCast(i)) != 0) out[i] = std.ascii.toUpper(out[i]);
            }
            return std.mem.readInt(u32, &out, .little);
        }
        return null;
    }
};

/// The cheapest atom window of a program. Programs pinned to an offset are verified from where
/// the match starts, so `part0_only` keeps their anchor in the first part (as prog_build does).
pub fn choose(model: gm.Model, costs: Costs, p: ir.Pattern, part0_only: bool) Choice {
    return chooseAvoiding(model, costs, p, part0_only, null);
}

/// Atom table keys too many programs share (`Costs.max_chain`): a candidate walks its key's
/// whole chain, so a key shared by a hundred thousand programs (`VB5!`, the start of every
/// Visual Basic 5 header, held 108,490) costs a hundred thousand compares wherever it occurs.
/// A key is its gram length and its gram, lower-cased for a folded literal.
pub const Banned = std.AutoHashMapUnmanaged(u64, void);

pub fn keyId(bytes: []const u8, nocase: bool) u64 {
    var g: u32 = 0;
    for (bytes, 0..) |b, i| g |= @as(u32, if (nocase) std.ascii.toLower(b) else b) << @intCast(8 * i);
    return @as(u64, bytes.len) << 32 | g;
}

fn isBanned(banned: ?*const Banned, bytes: []const u8, nocase: bool) bool {
    const b = banned orelse return false;
    return b.contains(keyId(bytes, nocase));
}

/// The table key of a choice (null without an atom).
pub fn choiceKey(c: Choice, p: ir.Pattern) ?u64 {
    if (c.q == 0 or c.anchor.op == prog.no_anchor) return null;
    const o = p.ops[c.anchor.op];
    return keyId(p.bytes(o)[c.atom_off..][0..c.q], o.flags & ir.op_nocase != 0);
}

/// The key a deferred program is searched by (engine/bodyscan.zig `Pending`): its anchor
/// literal's first four bytes, or fewer.
pub fn deferredKey(a: prog_build.Anchor, p: ir.Pattern) ?u64 {
    if (a.op == prog.no_anchor) return null;
    const o = p.ops[a.op];
    const bytes = p.bytes(o);
    if (bytes.len < 2) return null;
    return keyId(bytes[0..@min(bytes.len, 4)], o.flags & ir.op_nocase != 0);
}

/// `choose`, skipping windows whose key is in `banned`.
pub fn chooseAvoiding(model: gm.Model, costs: Costs, p: ir.Pattern, part0_only: bool, banned: ?*const Banned) Choice {
    if (costs.prefix) return choosePrefix(p, part0_only);
    var best: Choice = .{ .anchor = prog_build.chooseAnchor(p, part0_only) };
    var it: Literals = .{ .pattern = p, .part0_only = part0_only };
    while (it.next()) |lit| {
        const o = p.ops[lit.op];
        const bytes = p.bytes(o);
        const nocase = o.flags & ir.op_nocase != 0;
        best.longest = @max(best.longest, o.len);
        if (bytes.len < q) continue;
        // Per-offset gram probabilities; a window of stride s sums s of them.
        var probs: [512]f64 = undefined;
        const grams = @min(bytes.len - q + 1, probs.len);
        for (0..grams) |k| probs[k] = gramProb(model, bytes[k..][0..4], nocase);
        for (strides, 0..) |s, si| {
            if (grams < s or !costs.allows(s)) continue;
            var sum: f64 = 0;
            for (probs[0..s]) |x| sum += x;
            var off: usize = 0;
            while (true) : (off += 1) {
                // Every sampled gram of the window costs a probe when it occurs; the atom's
                // first gram (its table key) costs a verify.
                var cost = costs.probe_ns * sum + costs.verify_ns * probs[off] + costs.stride_penalty[si];
                if (s == 1) cost += costs.gate_ns * gram2Prob(model, bytes[off..][0..2], nocase);
                if (cost < best.cost and !isBanned(banned, bytes[off..][0..4], nocase)) best = .{
                    .stride = s,
                    .anchor = .{ .part = lit.part, .op = lit.op, .delta = lit.delta },
                    .atom_off = @intCast(off),
                    .q = 4,
                    .cost = cost,
                    .longest = best.longest,
                };
                if (off + s >= grams) break;
                sum += probs[off + s] - probs[off];
            }
        }
    }
    // Tier D: the rarest 3-byte window, for the 3-gram filter. It also replaces a 4-byte window
    // that is far more common (a run of zeros next to a rare 3-byte opcode).
    it = .{ .pattern = p, .part0_only = part0_only };
    while (it.next()) |lit| {
        const o = p.ops[lit.op];
        const bytes = p.bytes(o);
        if (bytes.len < 3) continue;
        const nocase = o.flags & ir.op_nocase != 0;
        for (0..bytes.len - 2) |off| {
            const cost = costs.q3_penalty + (costs.probe_ns + costs.verify_ns) * gram3Prob(model, bytes[off..][0..3], nocase) +
                costs.gate_ns * gram2Prob(model, bytes[off..][0..2], nocase);
            if (cost < best.cost and !isBanned(banned, bytes[off..][0..3], nocase)) best = .{
                .stride = 1,
                .anchor = .{ .part = lit.part, .op = lit.op, .delta = lit.delta },
                .atom_off = @intCast(off),
                .q = 3,
                .cost = cost,
                .longest = best.longest,
            };
        }
    }
    // The rarest 2-byte window, for the 2-gram filter: the last resort when only literals of
    // two bytes remain (`8185??f?ffff`), and better than a 4-byte window of zeros beside one.
    it = .{ .pattern = p, .part0_only = part0_only };
    while (it.next()) |lit| {
        const o = p.ops[lit.op];
        const bytes = p.bytes(o);
        if (bytes.len < 2) continue;
        const nocase = o.flags & ir.op_nocase != 0;
        for (0..bytes.len - 1) |off| {
            var prob: f64 = 0;
            if (nocase) {
                var vit = Variants.init(&(bytes[off..][0..2].* ++ [2]u8{ 0, 0 }));
                while (vit.next()) |g| {
                    var b: [4]u8 = undefined;
                    std.mem.writeInt(u32, &b, g, .little);
                    prob += model.prob2(b[0..2]);
                }
            } else prob = model.prob2(bytes[off..][0..2]);
            const cost = costs.q2_penalty + (costs.probe_ns + costs.verify_ns + costs.gate_ns) * prob;
            if (cost < best.cost and !isBanned(banned, bytes[off..][0..2], nocase)) best = .{
                .stride = 1,
                .anchor = .{ .part = lit.part, .op = lit.op, .delta = lit.delta },
                .atom_off = @intCast(off),
                .q = 2,
                .cost = cost,
                .longest = best.longest,
            };
        }
    }
    return best;
}

/// Prefix selection, as an Aho-Corasick of a fixed depth would take it: the first literal of
/// four bytes or more, from its start, stride 1 (shorter literals: their first 3 or 2 bytes).
fn choosePrefix(p: ir.Pattern, part0_only: bool) Choice {
    var c: Choice = .{ .anchor = prog_build.chooseAnchor(p, part0_only) };
    for ([_]u8{ 4, 3, 2 }) |q_len| {
        var it: Literals = .{ .pattern = p, .part0_only = part0_only };
        while (it.next()) |lit| {
            const o = p.ops[lit.op];
            c.longest = @max(c.longest, o.len);
            if (o.len < q_len) continue;
            return .{ .stride = 1, .anchor = .{ .part = lit.part, .op = lit.op, .delta = lit.delta }, .atom_off = 0, .q = q_len, .cost = 0, .longest = c.longest };
        }
    }
    return c;
}

/// What the planner decided for one program.
pub const Planned = struct {
    choice: Choice,
    /// Searched only after its logical signature was touched.
    deferred: bool = false,

    /// The anchor the program is verified from and the atom the prefilter holds for it: none
    /// for a program pinned to an offset (the anchored index finds it), a deferred one (the
    /// second pass finds it by its anchor literal) or one without a literal of two bytes.
    pub fn atom(p: Planned, kind: ir.OffsetKind) prog_build.Atom {
        const c = p.choice;
        if (kind != .any or p.deferred or c.q == 0) return .{ .anchor = c.anchor };
        return .{ .anchor = c.anchor, .spec = .{ .off = c.atom_off, .q = c.q, .stride = c.stride } };
    }
};

/// The atom of a program that nothing can defer (a body signature, a YARA string).
pub fn chooseFor(model: gm.Model, costs: Costs, in: prog_build.Input, crowd: ?*const Crowd) Choice {
    if (in.offset.kind != .any) return pinned(in.pattern);
    const best = choose(model, costs, in.pattern, false);
    const cr = crowd orelse return best;
    const key = choiceKey(best, in.pattern) orelse return best;
    if (!cr.banned.contains(key)) return best;
    // The cheapest window's key is crowded: the next cheapest whose key is not, unless it costs
    // more than `crowd_slack` beyond it (moving a family onto a common gram would cost every
    // benign file far more than the crowded key costs crafted ones).
    const free = chooseAvoiding(model, costs, in.pattern, false, &cr.banned);
    return if (free.q != 0 and free.cost <= best.cost + costs.crowd_slack) free else best;
}

/// Cover of an expression: a subsig mask and its cost, or none.
const Cover = struct {
    mask: u64,
    cost: f64,

    fn join(a: ?Cover, b: ?Cover) ?Cover {
        const x = a orelse return null;
        const y = b orelse return null;
        // Costs of shared subsigs are counted once.
        return .{ .mask = x.mask | y.mask, .cost = x.cost + y.cost };
    }

    fn cheaper(a: ?Cover, b: ?Cover) ?Cover {
        const x = a orelse return b;
        const y = b orelse return a;
        return if (y.cost < x.cost) y else x;
    }
};

/// Subsig costs and the expression evaluator for one logical rule.
const CoverCtx = struct {
    rule: *const ir.LogicalRule,
    /// Cost of searching each subsig's programs (0 for pinned ones), or null when the subsig
    /// has no programs of its own (byte compare, PCRE).
    costs: []const ?f64,
    depth: u8 = 0,

    fn leaf(c: *CoverCtx, i: usize) ?Cover {
        if (i >= c.rule.subsigs.len) return null;
        if (c.costs[i]) |cost| return .{ .mask = @as(u64, 1) << @intCast(i), .cost = cost };
        if (c.depth > 8) return null;
        c.depth += 1;
        defer c.depth -= 1;
        return switch (c.rule.subsigs[i]) {
            .byte_compare => |bc| c.leaf(bc.trigger),
            .pcre => |pc| c.expr(pc.trigger),
            .hex => null,
        };
    }

    /// The cheapest cover of an RPN expression, with costs of a mask recomputed so shared
    /// subsigs count once.
    fn expr(c: *CoverCtx, ops: []const ir.RpnOp) ?Cover {
        var stack: [ir.max_rpn_depth]struct { cover: ?Cover, leaves: ?Cover } = undefined;
        var sp: usize = 0;
        for (ops) |op| switch (op.code) {
            .sub => {
                if (sp == stack.len) return null;
                const l = c.leaf(op.index);
                stack[sp] = .{ .cover = l, .leaves = l };
                sp += 1;
            },
            .@"and", .@"or" => {
                if (sp < 2) return null;
                const b = stack[sp - 1];
                const a = stack[sp - 2];
                sp -= 1;
                const leaves = Cover.join(a.leaves, b.leaves);
                stack[sp - 1] = .{
                    .cover = if (op.code == .@"and") Cover.cheaper(a.cover, b.cover) else Cover.join(a.cover, b.cover),
                    .leaves = leaves,
                };
            },
            .eq, .gt, .lt => {
                if (sp < 1) return null;
                const x = &stack[sp - 1];
                // The comparison reads the summed count of every leaf below: it needs a match
                // of one of them unless it holds with a count of zero.
                const needs_hit = switch (op.code) {
                    .gt => true,
                    .eq => op.k > 0 or op.distinct > 0,
                    else => op.distinct > 0,
                };
                x.cover = if (needs_hit) x.leaves else null;
            },
            _ => return null,
        };
        if (sp != 1) return null;
        const cov = stack[0].cover orelse return null;
        var cost: f64 = 0;
        var m = cov.mask;
        while (m != 0) : (m &= m - 1) cost += c.costs[@ctz(m)] orelse 0;
        return .{ .mask = cov.mask, .cost = cost };
    }
};

/// Decide atoms for `inputs` (the order prog_build will serialise them in) and defer the
/// subsigs of each logical rule outside its cheapest cover. `rules[i]` covers the programs
/// `first[i] .. first[i] + count[i]`; YARA rules are passed as null (their conditions are not
/// RPN, so nothing of theirs is deferred).
pub fn plan(gpa: std.mem.Allocator, model: gm.Model, costs: Costs, inputs: []const prog_build.Input, logicals: []const Logical, crowd: ?*Crowd) ![]Planned {
    const out = try gpa.alloc(Planned, inputs.len);
    errdefer gpa.free(out);
    for (inputs, out) |in, *o| {
        o.* = .{ .choice = chooseFor(model, costs, in, crowd) };
    }
    if (costs.prefix or costs.no_defer) {
        try noteAll(crowd, inputs, out);
        return out;
    }
    var sub_costs: [ir.max_subsigs]?f64 = undefined;
    for (logicals) |l| {
        const rule = l.rule orelse continue;
        const n = @min(rule.subsigs.len, ir.max_subsigs);
        @memset(sub_costs[0..n], null);
        for (rule.subsigs[0..n], 0..) |sub, i| if (sub == .hex) {
            sub_costs[i] = 0;
        };
        const programs = inputs[l.first..][0..l.count];
        for (programs, out[l.first..][0..l.count]) |in, o| {
            if (in.subsig >= n) continue;
            if (in.offset.kind != .any) continue;
            sub_costs[in.subsig] = (sub_costs[in.subsig] orelse 0) + o.choice.cost;
        }
        var ctx: CoverCtx = .{ .rule = rule, .costs = sub_costs[0..n] };
        const cover = ctx.expr(rule.expr) orelse continue;
        for (programs, out[l.first..][0..l.count]) |in, *o| {
            if (in.offset.kind != .any) continue;
            if (in.subsig < 64 and cover.mask & (@as(u64, 1) << @intCast(in.subsig)) == 0) {
                o.deferred = true;
                if (deferredAnchorCrowd(model, costs, in.pattern, crowd)) |a| o.choice.anchor = a;
            }
        }
    }
    try noteAll(crowd, inputs, out);
    return out;
}

/// The keys programs have taken so far, for `Costs.max_chain`: a candidate walks its key's
/// whole chain, so a key many programs share is a worst case wherever it occurs, and crafted
/// input can repeat it (E4). The compiler adds programs in database order; once a key holds
/// `max_chain` of them, later programs take their next cheapest window (or, deferred, anchor
/// literal) whose key is not crowded, and a program with no other keeps the crowded key.
/// Expected cost is what atom selection weighs; this bounds the worst case.
pub const Crowd = struct {
    gpa: std.mem.Allocator,
    max_chain: u32,
    counts: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    banned: Banned = .empty,

    pub fn init(gpa: std.mem.Allocator, max_chain: u32) Crowd {
        return .{ .gpa = gpa, .max_chain = max_chain };
    }

    pub fn deinit(cr: *Crowd) void {
        cr.counts.deinit(cr.gpa);
        cr.banned.deinit(cr.gpa);
    }

    pub fn note(cr: *Crowd, key: u64) !void {
        const gop = try cr.counts.getOrPut(cr.gpa, key);
        gop.value_ptr.* = if (gop.found_existing) gop.value_ptr.* + 1 else 1;
        if (gop.value_ptr.* == cr.max_chain) try cr.banned.put(cr.gpa, key, {});
    }

    /// Record the key of one planned program.
    pub fn notePlanned(cr: *Crowd, in: prog_build.Input, o: Planned) !void {
        if (in.offset.kind != .any) return;
        const key = (if (o.deferred) deferredKey(o.choice.anchor, in.pattern) else choiceKey(o.choice, in.pattern)) orelse return;
        try cr.note(key);
    }
};

fn noteAll(crowd: ?*Crowd, inputs: []const prog_build.Input, out: []const Planned) !void {
    const cr = crowd orelse return;
    for (inputs, out) |in, o| try cr.notePlanned(in, o);
}

/// The anchor of a deferred program. The second pass keys a deferred program on the first
/// (up to) four bytes of its anchor literal behind a bitmap of their first two
/// (engine/bodyscan.zig `Pending`), so the literal whose prefix is rarest is the cheapest
/// anchor, not the one holding the rarest window: a prefix of `00 00` passes the bitmap at
/// most positions of a PE file. Null keeps the anchor (no literal of two bytes).
pub fn deferredAnchor(model: gm.Model, costs: Costs, p: ir.Pattern, banned: ?*const Banned) ?prog_build.Anchor {
    const a = deferredAnchorCost(model, costs, p, banned) orelse return null;
    return a.anchor;
}

const CostedAnchor = struct { anchor: prog_build.Anchor, cost: f64 };

/// A deferred program's anchor under a crowd: the cheapest literal, or the cheapest whose key
/// is not crowded when it costs at most `crowd_slack` more.
fn deferredAnchorCrowd(model: gm.Model, costs: Costs, p: ir.Pattern, crowd: ?*const Crowd) ?prog_build.Anchor {
    const best = deferredAnchorCost(model, costs, p, null) orelse return null;
    const cr = crowd orelse return best.anchor;
    const key = deferredKey(best.anchor, p) orelse return best.anchor;
    if (!cr.banned.contains(key)) return best.anchor;
    const free = deferredAnchorCost(model, costs, p, &cr.banned) orelse return best.anchor;
    return if (free.cost <= best.cost + costs.crowd_slack) free.anchor else best.anchor;
}

fn deferredAnchorCost(model: gm.Model, costs: Costs, p: ir.Pattern, banned: ?*const Banned) ?CostedAnchor {
    var best: ?prog_build.Anchor = null;
    var best_cost: f64 = std.math.inf(f64);
    var it: Literals = .{ .pattern = p, .part0_only = false };
    while (it.next()) |lit| {
        const o = p.ops[lit.op];
        const bytes = p.bytes(o);
        if (bytes.len < 2) continue;
        const nocase = o.flags & ir.op_nocase != 0;
        if (isBanned(banned, bytes[0..@min(bytes.len, 4)], nocase)) continue;
        const key_prob = switch (@min(bytes.len, 4)) {
            4 => gramProb(model, bytes[0..4], nocase),
            3 => gram3Prob(model, bytes[0..3], nocase),
            else => gram2Prob(model, bytes[0..2], nocase),
        };
        const cost = costs.gate_ns * gram2Prob(model, bytes[0..2], nocase) + (costs.probe_ns + costs.verify_ns) * key_prob;
        // The longer literal on ties: it fails sooner in the verifier.
        if (cost < best_cost or (cost == best_cost and best != null and o.len > p.ops[best.?.op].len)) {
            best_cost = cost;
            best = .{ .part = lit.part, .op = lit.op, .delta = lit.delta };
        }
    }
    return .{ .anchor = best orelse return null, .cost = best_cost };
}

/// A program pinned to an offset: the anchored index finds it, so it needs no atom.
fn pinned(p: ir.Pattern) Choice {
    var c: Choice = .{ .anchor = prog_build.chooseAnchor(p, true), .cost = 0 };
    var it: Literals = .{ .pattern = p, .part0_only = false };
    while (it.next()) |lit| c.longest = @max(c.longest, p.ops[lit.op].len);
    return c;
}

pub const Logical = struct {
    /// Null for a YARA rule.
    rule: ?*const ir.LogicalRule,
    first: u32,
    count: u32,
};

/// Tier counts for the coverage report and E3.
pub const Histogram = struct {
    /// Searched programs by class: 4-byte atoms at stride 8, 4, 3, 2 and 1, D with a 3-byte
    /// atom, D with a 2-byte one, D with none.
    searched: [classes]u64 = @splat(0),
    /// Deferred programs by the class they would have had.
    deferred: [classes]u64 = @splat(0),
    /// Programs pinned to an offset (the anchored index), by the longest stride their longest
    /// run allows.
    anchored: [classes]u64 = @splat(0),
    /// Tier D proper, the programs whose longest fixed literal is under 4 bytes (E3's
    /// definition), by what became of them: searched through a 3- or 2-byte atom, searched
    /// through a 4-byte one (a window across masks, alternations or wildcards), deferred,
    /// anchored, or searched with no atom.
    tier_d: [5]u64 = @splat(0),

    const classes = 8;

    fn class(c: Choice) usize {
        if (c.q == 4) return switch (c.stride) {
            8 => 0,
            4 => 1,
            3 => 2,
            2 => 3,
            else => 4,
        };
        return switch (c.q) {
            3 => 5,
            2 => 6,
            else => 7,
        };
    }

    pub fn add(h: *Histogram, in: prog_build.Input, p: Planned) void {
        if (p.choice.longest < 4) h.tier_d[
            if (in.offset.kind != .any) 3 else if (p.deferred) 2 else switch (p.choice.q) {
                4 => 1,
                3, 2 => 0,
                else => 4,
            }
        ] += 1;
        if (in.offset.kind != .any) {
            const n = p.choice.longest;
            h.anchored[if (n >= 11) 0 else if (n >= 7) 1 else if (n >= 6) 2 else if (n == 5) 3 else if (n == 4) 4 else if (n == 3) 5 else if (n == 2) 6 else 7] += 1;
        } else if (p.deferred) {
            h.deferred[class(p.choice)] += 1;
        } else h.searched[class(p.choice)] += 1;
    }

    pub fn render(h: Histogram, w: *std.Io.Writer) !void {
        try w.writeAll("atom tiers (programs)\n  tier          searched  deferred  anchored\n");
        for ([_][]const u8{ "s=8", "s=4", "s=3", "s=2", "C  s=1", "D  3-gram", "D  2-gram", "D  none" }, 0..) |name, i| {
            try w.print("  {s:<12} {d:>9} {d:>9} {d:>9}\n", .{ name, h.searched[i], h.deferred[i], h.anchored[i] });
        }
        const d = h.tier_d;
        var total: u64 = 0;
        for (d) |x| total += x;
        const pct = struct {
            fn f(x: u64, t: u64) f64 {
                return 100 * @as(f64, @floatFromInt(x)) / @as(f64, @floatFromInt(@max(t, 1)));
            }
        }.f;
        try w.print("tier D (longest fixed literal under 4 bytes): {d} programs; searched through 3- or 2-byte atoms {d} ({d:.1}%), through 4-byte atoms {d}, deferred {d}, anchored {d} (deferred or anchored {d:.1}%), no atom {d}\n", .{ total, d[0], pct(d[0], total), d[1], d[2], d[3], pct(d[2] + d[3], total), d[4] });
    }
};

const testing = std.testing;
const hexsig = @import("hexsig.zig");

fn parse(a: std.mem.Allocator, hex: []const u8) !ir.Pattern {
    var diag: hexsig.Diag = .{};
    return hexsig.parse(a, hex, &diag);
}

test "strides follow the run length and windows avoid common grams" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m = gm.Model.default();
    // Zero padding then a rare tail: the sampled stride, with the window on the tail.
    const long = choose(m, .{}, try parse(a, "000000000000000013a7c95be2f1408d77e3b1"), false);
    try testing.expectEqual(@as(u8, 3), long.stride);
    try testing.expect(long.atom_off >= 8);
    // The previous design's strides, when asked for: stride 8 on the 11-byte tail, and with
    // only 8 rare bytes a stride-4 window on them beats a stride-8 one over zeros.
    const tiers: Costs = .{ .sampled = &.{ 8, 4 } };
    const long8 = choose(m, tiers, try parse(a, "000000000000000013a7c95be2f1408d77e3b1"), false);
    try testing.expectEqual(@as(u8, 8), long8.stride);
    try testing.expectEqual(@as(u16, 8), long8.atom_off);
    try testing.expectEqual(@as(u8, 4), choose(m, tiers, try parse(a, "000000000000000013a7c95be2f1408d"), false).stride);
    // A rare 3-byte opcode beats a 4-byte window of zeros.
    const opcode = choose(m, .{}, try parse(a, "ff25a4{3}0000000000000000"), false);
    try testing.expectEqual(@as(u8, 3), opcode.q);
    try testing.expectEqual(@as(u16, 0), opcode.anchor.op);
    try testing.expectEqual(@as(u8, 3), choose(m, .{}, try parse(a, "13a7c95be2f140"), false).stride);
    // Runs of 4 and 5 bytes: stride 1, behind the gate.
    const c4 = choose(m, .{}, try parse(a, "13a7c95b"), false);
    try testing.expectEqual(@as(u8, 1), c4.stride);
    try testing.expectEqual(@as(u8, 4), c4.q);
    try testing.expectEqual(@as(u8, 1), choose(m, .{}, try parse(a, "13a7c95be2"), false).stride);
    try testing.expect(choose(m, .{}, try parse(a, "13a7??c9"), false).q < 4);
    const d3 = choose(m, .{}, try parse(a, "13a7??c95be2"), false);
    try testing.expectEqual(@as(u8, 3), d3.q);
    try testing.expectEqual(@as(u16, 2), d3.anchor.op);
    try testing.expectEqual(@as(u8, 2), choose(m, .{}, try parse(a, "13a7??c9"), false).q);
    try testing.expectEqual(@as(u8, 0), choose(m, .{}, try parse(a, "13??c9??2a"), false).q);
    // A short rare literal can beat a long common one.
    const mixed = choose(m, .{}, try parse(a, "0000000000000000000000*8d3e1fa7"), false);
    try testing.expectEqual(@as(u8, 4), mixed.q);
    try testing.expectEqual(@as(u8, 1), mixed.stride);
    try testing.expectEqual(@as(u8, 1), mixed.anchor.part);
    // After a variable alternation the distance is unknown: no window there.
    const alt = choose(m, .{}, try parse(a, "4d5a(aa|bbbb)13a7c95be2f1408d77"), false);
    try testing.expect(alt.q < 4);
}

test "case variants" {
    var it = Variants.init("aB1c");
    try testing.expectEqual(@as(usize, 8), it.count());
    var n: usize = 0;
    var seen_upper = false;
    while (it.next()) |g| {
        n += 1;
        if (g == std.mem.readInt(u32, "AB1C", .little)) seen_upper = true;
    }
    try testing.expectEqual(@as(usize, 8), n);
    try testing.expect(seen_upper);
}

test "covers defer subsigs a cheaper partner implies" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m = gm.Model.default();
    const ldb = @import("ldb.zig");
    const Case = struct { line: []const u8, deferred: []const bool };
    for ([_]Case{
        // 0&1: only the long subsig is searched.
        .{ .line = "T-1;Target:0;0&1;13a7c95be2f1408d77;4142", .deferred = &.{ false, true } },
        // 0|1: both must be searched.
        .{ .line = "T-2;Target:0;0|1;13a7c95be2f1408d77;4142", .deferred = &.{ false, false } },
        // 0&(1=0): the count of 1 is only read once 0 matched, so 1 is deferred.
        .{ .line = "T-3;Target:0;0&1=0;13a7c95be2f1408d77;4142", .deferred = &.{ false, true } },
        // A byte compare is covered by its trigger, so 1 alone covers 1&2 (and 0, named
        // nowhere, is deferred).
        .{ .line = "T-6;Target:0;1&2;4142;13a7c95be2f1408d77;1(>>4#de3#>100)", .deferred = &.{ true, false } },
        // (0|1)>2 is covered by both; 2 is ANDed in and cheaper still.
        .{ .line = "T-4;Target:0;(0|1)>2&2;4142;4344;13a7c95be2f1408d77", .deferred = &.{ true, true, false } },
        // A pinned subsig costs nothing: it covers, and the searched one is deferred.
        .{ .line = "T-5;Target:1;0&1;EP+0:e8c95be2;13a7c95be2f1408d77", .deferred = &.{ false, true } },
    }) |case| {
        var column: u32 = 0;
        const rule = try ldb.parseLine(a, case.line, &column);
        var inputs: std.ArrayList(prog_build.Input) = .empty;
        for (rule.subsigs, 0..) |sub, i| if (sub == .hex) try inputs.append(a, .{ .pattern = sub.hex.pattern, .offset = sub.hex.offset, .sig = 0, .subsig = @intCast(i) });
        const planned = try plan(a, m, .{}, inputs.items, &.{.{ .rule = &rule, .first = 0, .count = @intCast(inputs.items.len) }}, null);
        for (planned, case.deferred) |p, want| testing.expectEqual(want, p.deferred) catch |err| {
            std.debug.print("{s}: costs {any}\n", .{ case.line, planned });
            return err;
        };
    }
}
