//! HTML normaliser for ClamAV target type 3. Removed pending a clean-room rewrite
//! (docs/clean-room.md); this stub keeps the public interface compiling and produces no output.
const std = @import("std");

/// A byte sink. `write` returns error.Stop to end normalisation early.
pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
};

/// A sink for a sequence of delimited pieces (scripts, data URIs).
pub const Pieces = struct {
    ctx: *anyopaque,
    begin: *const fn (ctx: *anyopaque) error{Stop}!void,
    data: *const fn (ctx: *anyopaque, bytes: []const u8) error{Stop}!void,
    end: *const fn (ctx: *anyopaque) error{Stop}!void,
};

pub const Outputs = struct {
    nocomment: ?Output = null,
    notags: ?Output = null,
    scripts: ?Pieces = null,
    data_uris: ?Pieces = null,
};

pub const Normalizer = struct {
    outputs: Outputs,

    pub const Error = error{Stop};

    pub fn init(outputs: Outputs) Normalizer {
        return .{ .outputs = outputs };
    }

    pub fn feed(n: *Normalizer, in: []const u8) Error!void {
        _ = n;
        _ = in;
    }

    pub fn finish(n: *Normalizer) Error!void {
        _ = n;
    }
};
