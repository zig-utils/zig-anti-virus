//! Matching kernels: hash index, need map, split-block Bloom prefilters, atom tables, verify VM, logical signatures.
//! See docs/DESIGN.md for the design this module implements.

pub const hashidx = @import("hashidx.zig");
pub const prog = @import("prog.zig");
pub const verify_vm = @import("verify_vm.zig");
pub const prefilter = @import("prefilter.zig");
pub const stage1 = @import("stage1.zig");
pub const anchored = @import("anchored.zig");
pub const ldb_table = @import("ldb_table.zig");
pub const logical = @import("logical.zig");
pub const container = @import("container.zig");
pub const regex_pool = @import("regex_pool.zig");
pub const yara_cond = @import("yara_cond.zig");

test {
    _ = hashidx;
    _ = prog;
    _ = verify_vm;
    _ = prefilter;
    _ = stage1;
    _ = anchored;
    _ = ldb_table;
    _ = logical;
    _ = container;
    _ = regex_pool;
    _ = yara_cond;
}
