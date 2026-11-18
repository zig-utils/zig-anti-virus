//! The ASCII text normaliser for target type 7: uppercase letters become lowercase, every run of
//! whitespace (space, tab, CR, LF, VT, FF) becomes one space, the other control bytes below 0x20
//! and every byte from 0x80 up are dropped, and everything else (printable ASCII and 0x7f) is
//! copied. This is byte-for-byte libclamav's output over all 256 byte values
//! (tools/diff/norm.py). Streaming: the only state is whether the last byte written was a space,
//! so blocks can be fed in any split.
const std = @import("std");

pub const Normalizer = struct {
    last_space: bool = false,

    const Action = enum(u2) { copy, lower, space, skip };
    const table: [256]Action = blk: {
        var t: [256]Action = @splat(.copy);
        for (0..0x20) |c| t[c] = .skip;
        for (0x80..0x100) |c| t[c] = .skip;
        for ("\t\n\x0b\x0c\r ") |c| t[c] = .space;
        for ('A'..'Z' + 1) |c| t[c] = .lower;
        break :blk t;
    };

    /// Normalise `in` into `out` (which must be at least `in.len` long); returns the bytes
    /// written. Output never exceeds input.
    pub fn feed(n: *Normalizer, in: []const u8, out: []u8) usize {
        std.debug.assert(out.len >= in.len);
        var o: usize = 0;
        for (in) |c| {
            switch (table[c]) {
                .copy => {
                    out[o] = c;
                    o += 1;
                    n.last_space = false;
                },
                .lower => {
                    out[o] = c + 32;
                    o += 1;
                    n.last_space = false;
                },
                .space => if (!n.last_space) {
                    out[o] = ' ';
                    o += 1;
                    n.last_space = true;
                },
                .skip => {},
            }
        }
        return o;
    }
};

fn normalize(in: []const u8, out: []u8) []const u8 {
    var n: Normalizer = .{};
    return out[0..n.feed(in, out)];
}

test "lowercase, collapse whitespace, drop control bytes" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("hello world, this is text! ", normalize("Hello \t\r\n  WORLD,\x00 This IS\x01 text!\n\n", &buf));
    try std.testing.expectEqualStrings("caf \x7f", normalize("CAF\xc3\xa9\x0b\xff\x7f", &buf));
}

test "streaming in any split gives the same output" {
    const input = "  Mixed\tCASE  \n\n text   with  RUNS of   whitespace\r\n";
    var whole: [128]u8 = undefined;
    const want = normalize(input, &whole);
    for (1..input.len) |cut| {
        var n: Normalizer = .{};
        var out: [128]u8 = undefined;
        var o = n.feed(input[0..cut], &out);
        o += n.feed(input[cut..], out[o..]);
        try std.testing.expectEqualStrings(want, out[0..o]);
    }
}
