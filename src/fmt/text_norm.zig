//! The ASCII text normaliser for target type 7: uppercase letters become lowercase, every run of
//! whitespace (space, tab, CR, LF, VT, FF) becomes one space, the other control bytes below 0x20
//! and every byte from 0x80 up are dropped, and everything else (printable ASCII and 0x7f) is
//! copied. This is byte-for-byte libclamav's output over all 256 byte values
//! (tools/diff/norm.py). Streaming: the state is whether the last byte written was a space (and,
//! with seams, where the input stands), so blocks can be fed in any split.
//!
//! libclamav normalises into a fixed buffer (SCANBUFF, 128 KiB, plus the longest target-7
//! pattern) and forgets the last-byte-was-a-space state whenever it starts the buffer again, so
//! a whitespace run cut there leaves two spaces. Where that happens is deterministic (`Seams`):
//! - without relative-offset target-7 signatures (cli_scanscript's in-memory loop) the input is
//!   read one page at a time and the buffer restarts before a page that might not fit, so the
//!   seams depend on the host's page size (4 KiB on x86-64 Linux, 16 KiB on arm64 macOS);
//! - with them (text_normalize_map) the buffer restarts every SCANBUFF + maxpatlen input bytes.
//! The default is no seams; `zav-diff normalize` reproduces the first case byte for byte.
const std = @import("std");

/// Where libclamav restarts its whitespace collapsing.
pub const Seams = union(enum) {
    none,
    /// Input read `page` bytes at a time into a `buffer`-byte output buffer; before a page that
    /// might overflow it, the buffer restarts (keeping `carry` bytes, the target-7 maxpatlen).
    pages: struct { page: u32, buffer: u32 = scanbuff, carry: u32 = 0 },
    /// The buffer restarts every this many input bytes.
    input: u64,
};

/// libclamav's SCANBUFF (CMake default).
pub const scanbuff = 128 * 1024;

pub const Normalizer = struct {
    last_space: bool = false,
    seams: Seams = .none,
    /// The whole input's length, when known: libclamav's last page is shorter.
    total: ?u64 = null,
    /// Input bytes seen, and bytes in libclamav's buffer (`pages` seams).
    in_pos: u64 = 0,
    buf_pos: u64 = 0,

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
            switch (n.seams) {
                .none => {},
                .pages => |p| if (n.in_pos % p.page == 0) {
                    const left = if (n.total) |t| t -| n.in_pos else p.page;
                    if (n.buf_pos + @min(p.page, left) > p.buffer) {
                        n.last_space = false;
                        n.buf_pos = p.carry;
                    }
                },
                .input => |every| if (n.in_pos != 0 and n.in_pos % every == 0) {
                    n.last_space = false;
                },
            }
            n.in_pos += 1;
            const before = o;
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
            n.buf_pos += o - before;
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

test "seams: libclamav restarts whitespace collapsing where its buffer restarts" {
    // 1.2 MB of "abc   " with 16 KiB pages: the buffer restarts about every 120,150 output bytes;
    // only the restarts that cut a whitespace run show. Byte-identical with libclamav 1.5.4 on
    // arm64 macOS (tools/diff/norm.py).
    const gpa = std.testing.allocator;
    const n_units = 200_000;
    const in = try gpa.alloc(u8, 6 * n_units);
    defer gpa.free(in);
    for (0..n_units) |i| @memcpy(in[6 * i ..][0..6], "abc   ");
    const out = try gpa.alloc(u8, in.len);
    defer gpa.free(out);
    var n: Normalizer = .{ .seams = .{ .pages = .{ .page = 16384 } }, .total = in.len };
    var o: usize = 0;
    var at: usize = 0;
    while (at < in.len) : (at += 1000) o += n.feed(in[at..@min(in.len, at + 1000)], out[o..]);
    var doubles: [4]usize = undefined;
    var count: usize = 0;
    for (1..o) |i| if (out[i] == ' ' and out[i - 1] == ' ') {
        if (count < doubles.len) doubles[count] = i;
        count += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(usize, 240_300), doubles[0]);
    try std.testing.expectEqual(@as(usize, 600_749), doubles[1]);
}
