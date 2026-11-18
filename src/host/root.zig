//! Host checks: processes, network, kernel, persistence, privileges, hardening, integrity.
//!
//! The linux-guardian check catalogue, done without its flaws: checks read /proc, /sys and
//! netlink directly and never shell out (ps, ss, find, lsmod and modinfo are all replaced),
//! names match as tokens rather than substrings, package-manager ownership replaces hard-coded
//! allowlists, and unchanged files are not hashed twice. Every check reads through a `Host`, so it
//! runs against the real machine or a fixture tree.
const std = @import("std");

pub const finding = @import("finding.zig");
pub const sys = @import("sys.zig");
pub const host = @import("host.zig");
pub const context = @import("context.zig");
pub const suppress = @import("suppress.zig");
pub const scan = @import("scan.zig");
pub const schema = @import("schema.zig");
pub const tokens = @import("tokens.zig");

pub const Host = host.Host;
pub const Scan = scan.Scan;
pub const Check = scan.Check;
pub const Finding = finding.Finding;
pub const Severity = finding.Severity;
pub const Category = finding.Category;

/// Every check this build knows, in run order.
pub const registry = [_]Check{};

test {
    _ = finding;
    _ = sys;
    _ = host;
    _ = context;
    _ = suppress;
    _ = scan;
    _ = schema;
    _ = tokens;
}
