//! The benign-corpus 4-gram frequency model atom selection scores windows with (docs/DESIGN.md
//! 4.2). A 4-gram's benign frequency decides how often its atom would fire on clean files, so
//! the compiler picks, for every subsignature, the window whose grams are rarest.
//!
//! Storing all 2^32 counts is out of the question, so the model keeps three things, each as a
//! cost: minus log2 of the probability, in eighths of a bit, saturating at 255 (about 2^-32).
//!
//!     unigram costs   [256]u8
//!     bigram costs    [65536]u8, indexed by `a | b << 8`
//!     top grams       [top_count]u32 sorted ascending, then [top_count]u8 costs
//!
//! The top grams are the most frequent 4-grams of the corpus with exact counts. Any other gram
//! is estimated with an order-1 Markov chain over bigrams, P(abcd) = P(ab) P(c|b) P(d|c), and
//! never scored as more frequent than the rarest top gram (it would have been a top gram).
//!
//! `tools/gram_model.zig` builds the file from the B1 corpus (bench/corpus/B1.json); the
//! compiler embeds it. The same corpus always gives the same bytes.
const std = @import("std");

pub const magic = "ZGM1".*;
pub const max_cost: u8 = 255;
/// Cost units per bit.
pub const scale: f64 = 8;

pub const Header = extern struct {
    magic: [4]u8 = magic,
    version: u32 = 1,
    /// 4-grams counted.
    total: u64,
    top_count: u32,
    _reserved: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Header) == 24);
}

/// The model compiled into the compiler.
pub const embedded: []const u8 = @embedFile("gram_model.bin");

pub const Model = struct {
    total: u64,
    uni: *const [256]u8,
    bi: *const [65536]u8,
    top: []align(1) const u32,
    top_cost: []const u8,
    /// Cost of the rarest top gram: the floor for every estimated gram.
    floor: u8,

    pub const Error = error{BadModel};

    pub fn init(bytes: []const u8) Error!Model {
        if (bytes.len < @sizeOf(Header)) return error.BadModel;
        const h = std.mem.bytesToValue(Header, bytes[0..@sizeOf(Header)]);
        if (!std.mem.eql(u8, &h.magic, &magic) or h.version != 1) return error.BadModel;
        const need = @sizeOf(Header) + 256 + 65536 + @as(usize, h.top_count) * 5;
        if (bytes.len != need or h.top_count == 0) return error.BadModel;
        const uni_at = @sizeOf(Header);
        const bi_at = uni_at + 256;
        const top_at = bi_at + 65536;
        const cost_at = top_at + @as(usize, h.top_count) * 4;
        const top = std.mem.bytesAsSlice(u32, bytes[top_at..cost_at]);
        for (1..top.len) |i| if (top[i - 1] >= top[i]) return error.BadModel;
        const costs = bytes[cost_at..][0..h.top_count];
        var floor: u8 = 0;
        for (costs) |c| floor = @max(floor, c);
        return .{
            .total = h.total,
            .uni = bytes[uni_at..][0..256],
            .bi = bytes[bi_at..][0..65536],
            .top = top,
            .top_cost = costs,
            .floor = floor,
        };
    }

    pub fn default() Model {
        return init(embedded) catch unreachable;
    }

    /// Estimated cost of the gram whose bytes are `g` read little-endian (byte 0 first).
    pub fn cost(m: Model, g: u32) u8 {
        if (m.findTop(g)) |i| return m.top_cost[i];
        const a: u8 = @truncate(g);
        const b: u8 = @truncate(g >> 8);
        const c: u8 = @truncate(g >> 16);
        const d: u8 = @truncate(g >> 24);
        var x: i32 = m.bi[@as(u16, a) | @as(u16, b) << 8];
        x += @as(i32, m.bi[@as(u16, b) | @as(u16, c) << 8]) - m.uni[b];
        x += @as(i32, m.bi[@as(u16, c) | @as(u16, d) << 8]) - m.uni[c];
        return @intCast(std.math.clamp(x, m.floor, max_cost));
    }

    /// Estimated probability that a 4-byte window of a benign file is `g`.
    pub fn prob(m: Model, g: u32) f64 {
        return std.math.exp2(-@as(f64, @floatFromInt(m.cost(g))) / scale);
    }

    /// Estimated cost of a 3-byte window `abc` (byte 0 first), from the bigrams.
    pub fn cost3(m: Model, bytes: *const [3]u8) u8 {
        const ab = @as(u16, bytes[0]) | @as(u16, bytes[1]) << 8;
        const bc = @as(u16, bytes[1]) | @as(u16, bytes[2]) << 8;
        const x: i32 = @as(i32, m.bi[ab]) + m.bi[bc] - m.uni[bytes[1]];
        return @intCast(std.math.clamp(x, 0, max_cost));
    }

    pub fn prob3(m: Model, bytes: *const [3]u8) f64 {
        return std.math.exp2(-@as(f64, @floatFromInt(m.cost3(bytes))) / scale);
    }

    pub fn prob2(m: Model, bytes: *const [2]u8) f64 {
        const c = m.bi[@as(u16, bytes[0]) | @as(u16, bytes[1]) << 8];
        return std.math.exp2(-@as(f64, @floatFromInt(c)) / scale);
    }

    fn findTop(m: Model, g: u32) ?usize {
        var lo: usize = 0;
        var hi: usize = m.top.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (m.top[mid] < g) lo = mid + 1 else hi = mid;
        }
        return if (lo < m.top.len and m.top[lo] == g) lo else null;
    }
};

/// Cost of `count` out of `total`, in eighths of a bit, saturating.
pub fn costOf(count: u64, total: u64) u8 {
    if (count == 0 or total == 0) return max_cost;
    const bits = std.math.log2(@as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(count)));
    return @intFromFloat(@min(@as(f64, max_cost), @round(bits * scale)));
}

/// Counts for building a model. The 4-gram heavy hitters are found in two passes over the
/// corpus: `sketch` counts every gram into hashed buckets, then `exact` counts only grams
/// whose bucket reached the threshold `finishSketch` picks.
pub const Builder = struct {
    gpa: std.mem.Allocator,
    uni: [256]u64 = @splat(0),
    bi: [65536]u64 = @splat(0),
    total: u64 = 0,
    sketch: []u16,
    threshold: u16 = 0,
    exact: std.AutoHashMapUnmanaged(u32, u64) = .empty,

    pub const sketch_bits = 26;

    pub fn init(gpa: std.mem.Allocator) !Builder {
        const sketch = try gpa.alloc(u16, 1 << sketch_bits);
        @memset(sketch, 0);
        return .{ .gpa = gpa, .sketch = sketch };
    }

    pub fn deinit(b: *Builder) void {
        b.gpa.free(b.sketch);
        b.exact.deinit(b.gpa);
    }

    fn bucket(g: u32) usize {
        return @intCast((@as(u64, g) *% 0x9E37_79B9_7F4A_7C15) >> (64 - sketch_bits));
    }

    /// Pass one over a file.
    pub fn addSketch(b: *Builder, data: []const u8) void {
        for (data, 0..) |x, i| {
            b.uni[x] += 1;
            if (i + 1 < data.len) b.bi[@as(u16, x) | @as(u16, data[i + 1]) << 8] += 1;
            if (i + 4 <= data.len) {
                const s = &b.sketch[bucket(std.mem.readInt(u32, data[i..][0..4], .little))];
                s.* +|= 1;
                b.total += 1;
            }
        }
    }

    /// Pick the threshold so about `candidates` buckets qualify for exact counting.
    pub fn finishSketch(b: *Builder, candidates: usize) void {
        var hist: [65536]u64 = @splat(0);
        for (b.sketch) |s| hist[s] += 1;
        var above: u64 = 0;
        var t: usize = 65535;
        while (t > 1) : (t -= 1) {
            above += hist[t];
            if (above >= candidates) break;
        }
        b.threshold = @intCast(t);
    }

    /// Pass two over the same file.
    pub fn addExact(b: *Builder, data: []const u8) !void {
        if (data.len < 4) return;
        for (0..data.len - 3) |i| {
            const g = std.mem.readInt(u32, data[i..][0..4], .little);
            if (b.sketch[bucket(g)] < b.threshold) continue;
            const e = try b.exact.getOrPut(b.gpa, g);
            if (!e.found_existing) e.value_ptr.* = 0;
            e.value_ptr.* += 1;
        }
    }

    /// The model bytes, keeping the `top_count` most frequent grams (ties by gram value).
    pub fn finish(b: *Builder, gpa: std.mem.Allocator, top_count: usize) ![]u8 {
        const Pair = struct { g: u32, n: u64 };
        var pairs: std.ArrayList(Pair) = .empty;
        defer pairs.deinit(gpa);
        var it = b.exact.iterator();
        while (it.next()) |e| try pairs.append(gpa, .{ .g = e.key_ptr.*, .n = e.value_ptr.* });
        std.mem.sort(Pair, pairs.items, {}, struct {
            fn lt(_: void, x: Pair, y: Pair) bool {
                return if (x.n != y.n) x.n > y.n else x.g < y.g;
            }
        }.lt);
        const k = @min(top_count, pairs.items.len);
        const top = pairs.items[0..k];
        std.mem.sort(Pair, top, {}, struct {
            fn lt(_: void, x: Pair, y: Pair) bool {
                return x.g < y.g;
            }
        }.lt);
        const out = try gpa.alloc(u8, @sizeOf(Header) + 256 + 65536 + k * 5);
        const h: Header = .{ .total = b.total, .top_count = @intCast(k) };
        @memcpy(out[0..@sizeOf(Header)], std.mem.asBytes(&h));
        var at: usize = @sizeOf(Header);
        var uni_total: u64 = 0;
        for (b.uni) |n| uni_total += n;
        var bi_total: u64 = 0;
        for (b.bi) |n| bi_total += n;
        for (b.uni) |n| {
            out[at] = costOf(n, uni_total);
            at += 1;
        }
        for (b.bi) |n| {
            out[at] = costOf(n, bi_total);
            at += 1;
        }
        for (top) |p| {
            std.mem.writeInt(u32, out[at..][0..4], p.g, .little);
            at += 4;
        }
        for (top) |p| {
            out[at] = costOf(p.n, b.total);
            at += 1;
        }
        return out;
    }
};

const testing = std.testing;

test "a built model reads back and ranks grams by frequency" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    var data: [1 << 16]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1);
    prng.random().bytes(&data);
    // Zero runs and a repeated phrase are common; random bytes are not.
    @memset(data[0..8192], 0);
    for (0..512) |i| @memcpy(data[8192 + i * 16 ..][0..8], "PADDING!");
    b.addSketch(&data);
    b.finishSketch(1024);
    try b.addExact(&data);
    const bytes = try b.finish(testing.allocator, 64);
    defer testing.allocator.free(bytes);
    const m = try Model.init(bytes);
    const zeros = m.cost(0);
    const pad = m.cost(std.mem.readInt(u32, "PADD", .little));
    const rare = m.cost(std.mem.readInt(u32, "\x13\x37\xc0\xde", .little));
    try testing.expect(zeros < pad);
    try testing.expect(pad < rare);
    try testing.expect(rare >= m.floor);
    // Same input, same bytes.
    var b2 = try Builder.init(testing.allocator);
    defer b2.deinit();
    b2.addSketch(&data);
    b2.finishSketch(1024);
    try b2.addExact(&data);
    const again = try b2.finish(testing.allocator, 64);
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
    try testing.expectError(error.BadModel, Model.init(bytes[0 .. bytes.len - 1]));
}

test "the embedded model loads and scores padding as common" {
    const m = Model.default();
    try testing.expect(m.top.len > 1000);
    try testing.expect(m.cost(0) < 40);
    try testing.expect(m.cost(0xffff_ffff) < m.cost(std.mem.readInt(u32, "\x9a\x3f\xe1\x07", .little)));
}
