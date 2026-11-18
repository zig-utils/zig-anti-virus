//! Deterministic fuzzing: `zig build fuzz -Dfuzz-iterations=N -Dfuzz-seed=S`. Same seed, same
//! cases. Each target mutates valid inputs and must never crash, hang or leak; errors are fine.
//! `-Dfuzz-target=name` runs only the targets whose function name contains `name`.
const std = @import("std");
const zav = @import("zav");

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
