//! File formats, containers and normalisers, streamed with bounded memory.
//! See docs/DESIGN.md for the design this module implements.

pub const types = @import("types.zig");
pub const detect = @import("detect.zig");
pub const scan = @import("scan.zig");
pub const decode = @import("decode.zig");
pub const gzip = @import("gzip.zig");
pub const bzip2 = @import("bzip2.zig");
pub const lzma = @import("lzma.zig");
pub const xz = @import("xz.zig");
pub const zstd = @import("zstd.zig");
pub const archive = @import("archive.zig");
pub const tar = @import("tar.zig");
pub const cpio = @import("cpio.zig");
/// Reference vectors (tests, fuzzing, benchmarks).
pub const fixtures = @import("fixtures/fixtures.zig");

test {
    _ = types;
    _ = detect;
    _ = scan;
    _ = decode;
    _ = gzip;
    _ = bzip2;
    _ = lzma;
    _ = xz;
    _ = zstd;
    _ = archive;
    _ = tar;
    _ = cpio;
}
