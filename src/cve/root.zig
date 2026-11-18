//! CVE automation: KEV, NVD and OSV feeds compiled into a .zavcve index, inventory collectors.
//! See docs/DESIGN.md section 4.4.

pub const version = @import("version.zig");
pub const feeds = @import("feeds.zig");

test {
    _ = version;
    _ = feeds;
}
