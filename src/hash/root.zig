//! Fused multi-algorithm hashing with CPU-variant (hardware SHA) dispatch.
//! See docs/DESIGN.md sections 1 and 5 for the design this module implements.
//!
//! The block kernels (kernel.zig, sha1_hw.zig) are compiled once per CPU variant listed in
//! variants.zig and linked into the same binary; dispatch.zig picks one at runtime. Streaming,
//! padding and the fused pass (hasher.zig, multihash.zig) are compiled once.

pub const variants = @import("variants.zig");
pub const dispatch = @import("dispatch.zig");
pub const kernel = @import("kernel.zig");
pub const sha1_hw = @import("sha1_hw.zig");
pub const hasher = @import("hasher.zig");
pub const multihash = @import("multihash.zig");

pub const Algo = hasher.Algo;
pub const Md5 = hasher.Md5;
pub const Sha1 = hasher.Sha1;
pub const Sha256 = hasher.Sha256;
pub const Multihash = multihash.Multihash;
pub const Set = multihash.Set;
pub const Limits = multihash.Limits;
pub const Digests = multihash.Digests;
pub const Kernels = dispatch.Kernels;

test {
    _ = variants;
    _ = dispatch;
    _ = kernel;
    _ = sha1_hw;
    _ = hasher;
    _ = multihash;
    _ = @import("tests.zig");
}
