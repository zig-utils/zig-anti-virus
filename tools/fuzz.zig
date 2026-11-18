//! Deterministic fuzzing: `zig build fuzz -Dfuzz-iterations=N -Dfuzz-seed=S`. Same seed, same
//! cases. Each target mutates valid inputs and must never crash, hang or leak; errors are fine.
const std = @import("std");
const zav = @import("zav");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const iterations = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 10_000;
    const seed = if (args.len > 2) try std.fmt.parseInt(u64, args[2], 10) else 0x5eed_5eed;

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa.deinit() == .leak) @panic("fuzz: leak");

    var cases: usize = 0;
    for (0..iterations) |i| {
        try cvdContainer(gpa.allocator(), random, if (i % 2 == 0) zav.compile.cvd.fixture_cvd else zav.compile.cvd.fixture_cld);
        cases += 1;
    }
    std.debug.print("fuzz: {d} cases, seed {d}, ok\n", .{ cases, seed });
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
