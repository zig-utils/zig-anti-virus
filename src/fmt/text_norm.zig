//! Text normaliser for ClamAV target type 7. Removed pending a clean-room rewrite
//! (docs/clean-room.md); this stub keeps the public interface compiling and copies its input.
const std = @import("std");

pub const Seams = union(enum) {
    none,
    pages: struct { page: u32 },
};

pub const Normalizer = struct {
    seams: Seams = .none,
    total: ?u64 = null,

    pub fn feed(n: *Normalizer, in: []const u8, out: []u8) usize {
        _ = n;
        const k = @min(in.len, out.len);
        @memcpy(out[0..k], in[0..k]);
        return k;
    }
};
