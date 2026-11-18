//! Offline signature compiler: ClamAV CVD/CLD, rule IR, YARA subset, Guardian rules, atom selection, layout.
//! See docs/DESIGN.md for the design this module implements.

pub const cvd = @import("cvd.zig");
pub const cvd_sign = @import("cvd_sign.zig");
pub const ir = @import("ir.zig");
pub const hashsig = @import("hashsig.zig");
pub const hexsig = @import("hexsig.zig");
pub const ndb = @import("ndb.zig");
pub const prog_build = @import("prog_build.zig");
pub const gram_model = @import("gram_model.zig");
pub const atoms = @import("atoms.zig");
pub const prefilter_build = @import("prefilter_build.zig");
pub const anchored_build = @import("anchored_build.zig");
pub const ldb = @import("ldb.zig");
pub const ldb_build = @import("ldb_build.zig");
pub const ftm = @import("ftm.zig");
pub const ftm_build = @import("ftm_build.zig");
pub const cdb = @import("cdb.zig");
pub const yara = @import("yara.zig");
pub const hash_build = @import("hash_build.zig");
pub const filters = @import("filters.zig");
pub const coverage = @import("coverage.zig");
pub const compiler = @import("compiler.zig");
pub const mbazaar = @import("mbazaar.zig");
pub const builtin = @import("builtin.zig");
pub const lines = @import("lines.zig");
pub const census = @import("census.zig");
pub const spill = @import("spill.zig");
pub const names = @import("names.zig");

test {
    _ = cvd;
    _ = cvd_sign;
    _ = ir;
    _ = hashsig;
    _ = hexsig;
    _ = ndb;
    _ = prog_build;
    _ = gram_model;
    _ = atoms;
    _ = prefilter_build;
    _ = anchored_build;
    _ = ldb;
    _ = ldb_build;
    _ = ftm;
    _ = ftm_build;
    _ = cdb;
    _ = yara;
    _ = hash_build;
    _ = filters;
    _ = coverage;
    _ = compiler;
    _ = mbazaar;
    _ = builtin;
    _ = lines;
    _ = census;
    _ = spill;
    _ = names;
    _ = @This();
}
