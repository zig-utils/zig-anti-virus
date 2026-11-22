//! Text normaliser for ClamAV target type 7, reproducing the `clamav-*.tmp` file
//! `clamscan --leave-temps` keeps for a text file. Derived black-box (docs/clean-room.md, "Text
//! normalisation"); no ClamAV source was used.
//!
//! - TAB, LF, VT, FF, CR and space become one space; a run of them (bytes dropped below do not
//!   end a run) becomes a single space.
//! - `A`-`Z` become lower case; every other byte from `!` to DEL is kept.
//! - Other control bytes and bytes from 0x80 up are dropped.
//!
//! clamscan normalises a file in rounds: each round reads whole memory pages while its output
//! plus another page still fits in 128 KiB, and a round starts with a fresh whitespace state, so
//! a whitespace run that spans a round boundary yields two spaces. Rounds depend on the host
//! page size (4 KiB on x86-64 Linux, 16 KiB on Apple silicon); `Seams.pages` reproduces them.
const std = @import("std");

/// Output a round may hold.
pub const round_output = 128 * 1024;

pub const Seams = union(enum) {
    /// One whitespace state over the whole input.
    none,
    /// clamscan's rounds for a host with this page size.
    pages: struct { page: u32 },
};

pub const Normalizer = struct {
    seams: Seams = .none,
    last_space: bool = false,
    /// Input consumed in the current page, and output produced in the current round.
    page_used: u64 = 0,
    round_out: u64 = 0,

    /// Normalise `in` into `out` (at least `in.len` bytes; output never grows) and return the
    /// bytes written. Input may arrive in any pieces.
    pub fn feed(n: *Normalizer, in: []const u8, out: []u8) usize {
        std.debug.assert(out.len >= in.len);
        var o: usize = 0;
        switch (n.seams) {
            .none => for (in) |b| {
                o += n.byte(b, out[o..]);
            },
            .pages => |p| {
                const page: u64 = @max(p.page, 1);
                for (in) |b| {
                    if (n.page_used == page) {
                        n.page_used = 0;
                        if (n.round_out + page > round_output) {
                            n.round_out = 0;
                            n.last_space = false;
                        }
                    }
                    n.page_used += 1;
                    const w = n.byte(b, out[o..]);
                    o += w;
                    n.round_out += w;
                }
            },
        }
        return o;
    }

    inline fn byte(n: *Normalizer, b: u8, out: []u8) usize {
        switch (b) {
            '\t', '\n', 0x0b, 0x0c, '\r', ' ' => {
                if (n.last_space) return 0;
                n.last_space = true;
                out[0] = ' ';
                return 1;
            },
            '!'...0x7f => {
                n.last_space = false;
                out[0] = std.ascii.toLower(b);
                return 1;
            },
            else => return 0,
        }
    }
};

const testing = std.testing;

fn normalize(comptime seams: Seams, in: []const u8, buf: []u8) []const u8 {
    var n: Normalizer = .{ .seams = seams };
    return buf[0..n.feed(in, buf)];
}

test "case, whitespace runs and dropped bytes" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings(" hello world tabs \x7f ", normalize(.none, "  Hello \x01 World\r\n\tTABS \x7f\x80\x00 ", &buf));
}

test "rounds restart the whitespace state at page boundaries" {
    // Pages of 16 bytes, each all spaces: every round holds as many pages as leave room for
    // one more within 128 KiB, so with 1-byte output per page a seam never comes; with a page
    // size of 64 KiB the second page starts a new round.
    var in: [3 * 65536]u8 = @splat(' ');
    var out: [3 * 65536]u8 = undefined;
    try testing.expectEqualStrings(" ", normalize(.{ .pages = .{ .page = 16 } }, &in, &out));
    @memset(in[0..65535], 'a');
    @memset(in[65536 .. 2 * 65536 - 1], 'b');
    // Page 0: 65535 'a' and a space (65536 out). Page 1 fits (65536 + 65536 = 128 KiB). Page 2
    // would not: a new round, whose leading space is kept.
    const got = normalize(.{ .pages = .{ .page = 65536 } }, &in, &out);
    try testing.expectEqual(@as(usize, 2 * 65536 + 1), got.len);
}

test "pieces give the same output as one feed" {
    const unit = "A  b\t\tC ";
    var in: [unit.len * 300]u8 = undefined;
    for (0..300) |k| @memcpy(in[k * unit.len ..][0..unit.len], unit);
    var one: [in.len]u8 = undefined;
    var two: [in.len]u8 = undefined;
    var n1: Normalizer = .{ .seams = .{ .pages = .{ .page = 64 } } };
    const a = n1.feed(&in, &one);
    var n2: Normalizer = .{ .seams = .{ .pages = .{ .page = 64 } } };
    var b: usize = 0;
    var i: usize = 0;
    while (i < in.len) : (i += 7) b += n2.feed(in[i..@min(in.len, i + 7)], two[b..]);
    try testing.expectEqualSlices(u8, one[0..a], two[0..b]);
}
