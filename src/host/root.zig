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
pub const cache = @import("cache.zig");
pub const baseline = @import("baseline.zig");
pub const linux = struct {
    pub const packages = @import("linux/packages.zig");
    pub const sqlite = @import("linux/sqlite.zig");
    pub const rpm = @import("linux/rpm.zig");
    pub const integrity = @import("linux/integrity.zig");
    pub const procfs = @import("linux/procfs.zig");
    pub const process = @import("linux/process.zig");
    pub const network = @import("linux/network.zig");
    pub const kernel = @import("linux/kernel.zig");
    pub const persistence = @import("linux/persistence.zig");
    pub const privilege = @import("linux/privilege.zig");
    pub const hardening = @import("linux/hardening.zig");
};

pub const Host = host.Host;
pub const Scan = scan.Scan;
pub const Check = scan.Check;
pub const Finding = finding.Finding;
pub const Severity = finding.Severity;
pub const Category = finding.Category;

/// Every check this build knows, in run order.
pub const registry = linux.process.checks ++ linux.network.checks ++ linux.kernel.checks ++ linux.persistence.checks ++ linux.privilege.checks ++ linux.hardening.checks ++ linux.integrity.checks;

test {
    _ = finding;
    _ = sys;
    _ = host;
    _ = context;
    _ = suppress;
    _ = scan;
    _ = schema;
    _ = tokens;
    _ = cache;
    _ = linux.packages;
    _ = linux.sqlite;
    _ = linux.rpm;
    _ = linux.integrity;
    _ = linux.procfs;
    _ = linux.process;
    _ = linux.network;
    _ = linux.kernel;
    _ = linux.persistence;
    _ = linux.privilege;
    _ = linux.hardening;
    _ = baseline;
}
