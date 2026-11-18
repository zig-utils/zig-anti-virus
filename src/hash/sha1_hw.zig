//! Hardware SHA-1 block compression, which std.crypto lacks: x86 SHA-NI and the ARMv8 SHA-1
//! instructions. Written from the instruction definitions (Intel SDM, Arm ARM). `available` is
//! comptime: these kernels exist only in code compiled for a CPU that has the extension, which is
//! why the engine builds one object per CPU variant and picks one at runtime.
const std = @import("std");
const builtin = @import("builtin");

const V4 = @Vector(4, u32);

/// Whether the compile-time target has hardware SHA-1.
pub const available = builtin.zig_backend != .stage2_c and switch (builtin.cpu.arch) {
    // The kernel also uses SSSE3 byte shuffles and SSE4.1 lane inserts, which every SHA-NI CPU has.
    .x86_64 => builtin.cpu.hasAll(.x86, &.{ .sha, .sse4_1 }),
    // LLVM's sha2 feature covers both the SHA-1 and SHA-256 instructions.
    .aarch64 => builtin.cpu.has(.aarch64, .sha2),
    else => false,
};

/// Compress `n` 64-byte blocks into `state`. Only callable when `available`.
pub fn blocks(state: *[5]u32, data: [*]const u8, n: usize) void {
    if (comptime !available) @compileError("hardware SHA-1 is not enabled for this target");
    switch (builtin.cpu.arch) {
        .x86_64 => x86.blocks(state, data, n),
        .aarch64 => arm.blocks(state, data, n),
        else => unreachable,
    }
}

const x86 = X86(x86_asm);

/// The SHA-NI instructions, one inline asm statement each so LLVM allocates the registers.
const x86_asm = struct {
    /// Four rounds with round function and constant `f` (0 to 3, one per 20 rounds).
    inline fn rnds4(abcd: V4, ew: V4, comptime f: u2) V4 {
        return asm ("sha1rnds4 $" ++ .{'0' + @as(u8, f)} ++ ", %[ew], %[abcd]"
            : [abcd] "=x" (-> V4),
            : [_] "0" (abcd),
              [ew] "x" (ew),
        );
    }

    /// rol(A of `prev`, 30) added to the top lane of `w`: E for the next four rounds plus W.
    inline fn nexte(prev: V4, w: V4) V4 {
        return asm ("sha1nexte %[w], %[e]"
            : [e] "=x" (-> V4),
            : [_] "0" (prev),
              [w] "x" (w),
        );
    }

    inline fn msg1(a: V4, b: V4) V4 {
        return asm ("sha1msg1 %[b], %[a]"
            : [a] "=x" (-> V4),
            : [_] "0" (a),
              [b] "x" (b),
        );
    }

    inline fn msg2(a: V4, b: V4) V4 {
        return asm ("sha1msg2 %[b], %[a]"
            : [a] "=x" (-> V4),
            : [_] "0" (a),
              [b] "x" (b),
        );
    }
};

/// The SHA-NI block loop over an instruction set `ops`: the real instructions, or the software
/// model in the tests below, which checks the lane order and schedule on any machine.
fn X86(comptime ops: type) type {
    return struct {
        /// Big-endian words of a 16-byte group with the first word in the top lane, the order the
        /// SHA-NI instructions expect (A and W0 live in bits 127:96).
        inline fn load(b: *const [16]u8) V4 {
            const v: @Vector(16, u8) = b.*;
            return @bitCast(@shuffle(u8, v, undefined, [16]i32{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }));
        }

        fn blocks(state: *[5]u32, data: [*]const u8, n: usize) void {
            var abcd: V4 = .{ state[3], state[2], state[1], state[0] };
            // E sits in the top lane; the lower lanes must stay zero because sha1rnds4 reads them
            // as the next three message words after the first add.
            var e0: V4 = .{ 0, 0, 0, state[4] };
            for (0..n) |i| {
                const b = data[i * 64 ..][0..64];
                const abcd_save = abcd;
                const e_save = e0;
                var w: [20]V4 = undefined;
                inline for (0..4) |j| w[j] = load(b[j * 16 ..][0..16]);
                var prev: V4 = undefined;
                inline for (0..20) |r| {
                    const ew = if (r == 0) e0 +% w[0] else ops.nexte(prev, w[r]);
                    prev = abcd;
                    abcd = ops.rnds4(abcd, ew, r / 5);
                    if (r + 4 < 20) w[r + 4] = ops.msg2(ops.msg1(w[r], w[r + 1]) ^ w[r + 2], w[r + 3]);
                }
                e0 = ops.nexte(prev, e_save);
                abcd +%= abcd_save;
            }
            state.* = .{ abcd[3], abcd[2], abcd[1], abcd[0], e0[3] };
        }
    };
}

const arm = struct {
    const k = [4]u32{ 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

    inline fn load(b: *const [16]u8) V4 {
        const v: V4 = @bitCast(b.*);
        return if (builtin.cpu.arch.endian() == .little) @byteSwap(v) else v;
    }

    /// Four rounds: choose (0), parity (1 and 3) or majority (2).
    inline fn rounds(abcd: V4, e: u32, wk: V4, comptime f: u2) V4 {
        const op = switch (f) {
            0 => "sha1c",
            1, 3 => "sha1p",
            2 => "sha1m",
        };
        return asm (op ++ " %[abcd:q], %[e:s], %[wk].4s"
            : [abcd] "=w" (-> V4),
            : [_] "0" (abcd),
              [e] "w" (e),
              [wk] "w" (wk),
        );
    }

    /// rol(a, 30).
    inline fn h(a: u32) u32 {
        return asm ("sha1h %[out:s], %[a:s]"
            : [out] "=w" (-> u32),
            : [a] "w" (a),
        );
    }

    inline fn su0(a: V4, b: V4, c: V4) V4 {
        return asm ("sha1su0 %[a].4s, %[b].4s, %[c].4s"
            : [a] "=w" (-> V4),
            : [_] "0" (a),
              [b] "w" (b),
              [c] "w" (c),
        );
    }

    inline fn su1(a: V4, b: V4) V4 {
        return asm ("sha1su1 %[a].4s, %[b].4s"
            : [a] "=w" (-> V4),
            : [_] "0" (a),
              [b] "w" (b),
        );
    }

    fn blocks(state: *[5]u32, data: [*]const u8, n: usize) void {
        var abcd: V4 = state[0..4].*;
        var e: u32 = state[4];
        for (0..n) |i| {
            const b = data[i * 64 ..][0..64];
            const abcd_save = abcd;
            const e_save = e;
            var w: [20]V4 = undefined;
            inline for (0..4) |j| w[j] = load(b[j * 16 ..][0..16]);
            inline for (0..20) |r| {
                // E for the next four rounds is rol(A, 30) of this group's input.
                const e_next = h(abcd[0]);
                const wk = w[r] +% @as(V4, @splat(k[r / 5]));
                abcd = rounds(abcd, e, wk, r / 5);
                e = e_next;
                if (r + 4 < 20) w[r + 4] = su1(su0(w[r], w[r + 1], w[r + 2]), w[r + 3]);
            }
            abcd +%= abcd_save;
            e +%= e_save;
        }
        state[0..4].* = abcd;
        state[4] = e;
    }
};

/// Software model of the SHA-NI instructions from the Intel SDM pseudocode. Lane 3 is bits 127:96.
const x86_model = struct {
    const rotl = std.math.rotl;

    fn rnds4(abcd: V4, ew: V4, comptime f: u2) V4 {
        const k = arm.k[f];
        var a = abcd[3];
        var b = abcd[2];
        var c = abcd[1];
        var d = abcd[0];
        var e: u32 = 0;
        const w = [4]u32{ ew[3], ew[2], ew[1], ew[0] };
        for (0..4) |i| {
            const fv = switch (f) {
                0 => (b & c) ^ (~b & d),
                1, 3 => b ^ c ^ d,
                2 => (b & c) ^ (b & d) ^ (c & d),
            };
            const t = fv +% rotl(u32, a, 5) +% w[i] +% e +% k;
            e = d;
            d = c;
            c = rotl(u32, b, 30);
            b = a;
            a = t;
        }
        return .{ d, c, b, a };
    }

    fn nexte(prev: V4, w: V4) V4 {
        return .{ w[0], w[1], w[2], w[3] +% rotl(u32, prev[3], 30) };
    }

    fn msg1(a: V4, b: V4) V4 {
        return .{ b[2] ^ a[0], b[3] ^ a[1], a[0] ^ a[2], a[1] ^ a[3] };
    }

    fn msg2(a: V4, b: V4) V4 {
        const w16 = rotl(u32, a[3] ^ b[2], 1);
        const w17 = rotl(u32, a[2] ^ b[1], 1);
        const w18 = rotl(u32, a[1] ^ b[0], 1);
        const w19 = rotl(u32, a[0] ^ w16, 1);
        return .{ w19, w18, w17, w16 };
    }
};

test "the SHA-NI block loop is SHA-1 under a software model of the instructions" {
    var prng = std.Random.DefaultPrng.init(0x5a1);
    var data: [64 * 9]u8 = undefined;
    prng.random().bytes(&data);
    for (0..10) |n| {
        // Chaining states after n blocks from the IV.
        var want = std.crypto.hash.Sha1.init(.{});
        want.update(data[0 .. n * 64]);
        var got: [5]u32 = std.crypto.hash.Sha1.init(.{}).s;
        X86(x86_model).blocks(&got, &data, n);
        try std.testing.expectEqualSlices(u32, &want.s, &got);
    }
}
