//! Fused multi-algorithm hashing: any subset of MD5, SHA-1 and SHA-256 over the same bytes in one
//! pass. Input is walked in cache-resident sub-blocks and every running hasher consumes a sub-block
//! before the next is touched, so each byte is pulled from memory once (docs/DESIGN.md section 5).
//!
//! Speculative mode is for streams of unknown size: give each algorithm a limit (the largest file
//! size any signature of that table names) and the hasher stops, reported as dropped, as soon as
//! the stream is known to exceed it. No signature of that algorithm can match a longer file.
const std = @import("std");
const dispatch = @import("dispatch.zig");
const hasher = @import("hasher.zig");

pub const Algo = hasher.Algo;
pub const Set = std.EnumSet(Algo);

/// Per-algorithm byte limits for speculative hashing. Null hashes without limit.
pub const Limits = struct {
    md5: ?u64 = null,
    sha1: ?u64 = null,
    sha256: ?u64 = null,

    fn get(limits: Limits, algo: Algo) ?u64 {
        return switch (algo) {
            inline else => |a| @field(limits, @tagName(a)),
        };
    }
};

pub const Digests = struct {
    md5: [16]u8 = @splat(0),
    sha1: [20]u8 = @splat(0),
    sha256: [32]u8 = @splat(0),
    /// Algorithms whose digest field is valid.
    computed: Set = .empty,
    /// Requested algorithms stopped because the stream outgrew their limit.
    dropped: Set = .empty,
    /// Bytes seen.
    len: u64 = 0,
};

pub const Options = struct {
    limits: Limits = .{},
    /// Kernel variant to run; null picks the best for this CPU.
    kernels: ?*const dispatch.Kernels = null,
};

pub const Multihash = struct {
    /// Bytes each hasher consumes before the next one runs: well inside L1 on every target
    /// (32 KiB and up), so the second and third pass over a sub-block hit cache.
    pub const sub_block_len = 16 * 1024;

    running: Set,
    dropped: Set = .empty,
    limits: Limits,
    len: u64 = 0,
    md5: hasher.Md5,
    sha1: hasher.Sha1,
    sha256: hasher.Sha256,

    pub fn init(algos: Set, options: Options) Multihash {
        const k = options.kernels orelse dispatch.active();
        return .{
            .running = algos,
            .limits = options.limits,
            .md5 = .initWith(k),
            .sha1 = .initWith(k),
            .sha256 = .initWith(k),
        };
    }

    /// Hash the next bytes of the stream with every algorithm still running.
    pub fn update(m: *Multihash, bytes: []const u8) void {
        m.len +|= bytes.len;
        inline for (comptime std.enums.values(Algo)) |algo| {
            if (m.running.contains(algo)) if (m.limits.get(algo)) |limit| if (m.len > limit) {
                m.running.remove(algo);
                m.dropped.insert(algo);
            };
        }
        if (m.running.count() <= 1) return m.updateAll(bytes);
        var off: usize = 0;
        while (off < bytes.len) : (off += sub_block_len) m.updateAll(bytes[off..@min(off + sub_block_len, bytes.len)]);
    }

    fn updateAll(m: *Multihash, bytes: []const u8) void {
        inline for (comptime std.enums.values(Algo)) |algo| {
            if (m.running.contains(algo)) @field(m, @tagName(algo)).update(bytes);
        }
    }

    /// Whether any algorithm is still running. When none is, the caller can stop feeding bytes.
    pub fn active(m: *const Multihash) bool {
        return m.running.count() != 0;
    }

    pub fn final(m: *Multihash) Digests {
        var out: Digests = .{ .computed = m.running, .dropped = m.dropped, .len = m.len };
        inline for (comptime std.enums.values(Algo)) |algo| {
            if (m.running.contains(algo)) @field(m, @tagName(algo)).final(&@field(out, @tagName(algo)));
        }
        return out;
    }
};
