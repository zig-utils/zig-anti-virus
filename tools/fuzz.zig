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

    var cases: usize = 0;
    for (0..iterations) |i| {
        if (selected(only, "cvdContainer")) {
            try cvdContainer(gpa.allocator(), random, if (i % 2 == 0) zav.compile.cvd.fixture_cvd else zav.compile.cvd.fixture_cld);
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
        // Host and CVE parsers live in fuzz_host.zig; each name selects one target.
        cases += try host_fuzz.run(gpa.allocator(), random, only);
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
        "61~62??63[1-3]6465",
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
            .part_end => at += o.a + random.uintAtMost(usize, @min(3, o.b - o.a)),
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
            const edge = pos == 0 or pos == data.len;
            const class: ir.Bound = @fromBackingInt(o.flags);
            var lens: [3]usize = undefined;
            var n: usize = 0;
            switch (class) {
                .nonalnum, .word => {
                    if (pos < data.len and !naiveAlnum(data[pos])) {
                        lens[n] = 1;
                        n += 1;
                    }
                    if (class == .word and edge) {
                        lens[n] = 0;
                        n += 1;
                    }
                },
                .line => {
                    if (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n') {
                        lens[n] = 2;
                        n += 1;
                    }
                    if (pos < data.len and (data[pos] == '\r' or data[pos] == '\n')) {
                        lens[n] = 1;
                        n += 1;
                    }
                    if (edge) {
                        lens[n] = 0;
                        n += 1;
                    }
                },
            }
            for (lens[0..n]) |l| if (naiveOps(p, rest, data, w, pos + l, flags)) return true;
            return false;
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
    const bodies = [_][]const u8{ "aa(bb|cc??|{3}dd)ee*ff{-3}11(B)", "!(aabb|ccdd)eeff[1-4]00~11", "deadbeef" };
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
fn hashSections(random: std.Random) void {
    const hashidx = zav.match.hashidx;
    var buf: [hashidx.top_entries * 4 + 64 + 4096 + 64]u8 align(8) = @splat(0);
    random.bytes(buf[0..random.uintLessThan(usize, 256)]);
    @memcpy(buf[0..4], "NEED");
    buf[4] = 1;
    for (0..random.uintLessThan(usize, 16)) |_| buf[random.uintLessThan(usize, buf.len)] = random.int(u8);
    if (hashidx.NeedMap.init(buf[0..random.uintLessThan(usize, buf.len + 1)])) |map| {
        _ = map.mask(random.int(u64) % (hashidx.dense_limit * 2));
    } else |_| {}
    var hot: [512]u8 align(8) = @splat(0);
    var cold: [512]u8 = @splat(0);
    random.bytes(&hot);
    random.bytes(&cold);
    @memcpy(hot[0..4], "HASH");
    hot[4] = 1;
    hot[8] = random.uintLessThan(u8, 3);
    hot[9] = random.uintLessThan(u8, 3);
    if (hashidx.Table.init(&hot, &cold)) |t| {
        var d: [32]u8 = undefined;
        random.bytes(&d);
        _ = t.lookup(random.int(u16), d[0..t.algo.digestLen()]);
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
