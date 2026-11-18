//! CVE automation: KEV, NVD and OSV feeds compiled into a .zavcve index, inventory collectors.
//! See docs/DESIGN.md section 4.4.

pub const version = @import("version.zig");
pub const feeds = @import("feeds.zig");
pub const index = @import("index.zig");
pub const inventory = @import("inventory/root.zig");

/// Vulnerability checks, run by `zav host` (installed software) and `zav audit` (paths).
pub const registry = inventory.checks;

test {
    _ = version;
    _ = feeds;
    _ = index;
    _ = inventory;
    _ = inventory.lockfiles;
    _ = inventory.gobuild;
    _ = inventory.item;
}
