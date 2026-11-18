//! Scan limits and the events they raise. Defaults match clamd's, so verdicts are comparable.
//! Running into a limit is a reported result, never a silent pass: the caller decides (from
//! configuration) whether a limited scan counts as clean, suspicious or an error.
const std = @import("std");

pub const Limits = struct {
    /// Total bytes scanned across a file and everything inside it (clamd MaxScanSize).
    max_scan_size: u64 = 400 * 1024 * 1024,
    /// Largest single file or member scanned (MaxFileSize).
    max_file_size: u64 = 100 * 1024 * 1024,
    /// Container nesting depth (MaxRecursion).
    max_recursion: u8 = 17,
    /// Files inside one top-level file (MaxFiles).
    max_files: u32 = 10_000,
    /// Largest embedded executable extracted (MaxEmbeddedPE).
    max_embedded_pe: u64 = 40 * 1024 * 1024,
    /// HTML bytes normalised (MaxHTMLNormalize).
    max_html_normalize: u64 = 40 * 1024 * 1024,
    /// Script bytes normalised (MaxScriptNormalize).
    max_script_normalize: u64 = 20 * 1024 * 1024,
    /// A member may expand to this many times its compressed size once past `ratio_floor`.
    max_ratio: u32 = 100,
    ratio_floor: u64 = 1024 * 1024,
    /// Decompressed output across one top-level file.
    max_total_output: u64 = 1024 * 1024 * 1024,
    /// Wall time for one top-level scan (MaxScanTime), in milliseconds.
    max_scan_time_ms: u64 = 120_000,
    /// Largest decoder window or dictionary accepted (zstd, xz, LZMA). Windows over 1 MiB also
    /// need a big-window budget token.
    max_window: u64 = 8 * 1024 * 1024,
};

pub const Event = enum(u8) {
    scan_size,
    file_size,
    recursion,
    files,
    embedded_pe,
    html_normalize,
    script_normalize,
    ratio,
    total_output,
    scan_time,
    big_window_budget,
    verify_steps,
    /// A byte-compare subsig pointed outside the data.
    byte_compare_bounds,
    /// Logical-signature state filled its spill arena.
    logical_state,
    /// A decoder window (zstd frame window, LZMA dictionary) larger than `max_window`.
    window_size,
    /// The worker's scratch arena could not hold a child's working set.
    memory,
};

/// Per-scan accounting. Lives in scratch; resetting it is O(1).
pub const Tracker = struct {
    limits: Limits,
    scanned: u64 = 0,
    output: u64 = 0,
    files: u32 = 0,
    depth: u8 = 0,
    /// Set bit per event raised during this scan.
    raised: std.EnumSet(Event) = .empty,
    /// The most recent event, so a caller that got error.LimitReached can name it.
    last: ?Event = null,

    pub fn init(limits: Limits) Tracker {
        return .{ .limits = limits };
    }

    pub fn reset(t: *Tracker) void {
        t.* = .init(t.limits);
    }

    /// Record an event and report whether scanning should stop.
    fn raise(t: *Tracker, event: Event) error{LimitReached} {
        t.raised.insert(event);
        t.last = event;
        return error.LimitReached;
    }

    pub fn note(t: *Tracker, event: Event) void {
        t.raised.insert(event);
        t.last = event;
    }

    /// Account for `n` more scanned bytes.
    pub fn addScanned(t: *Tracker, n: u64) error{LimitReached}!void {
        t.scanned +|= n;
        if (t.scanned > t.limits.max_scan_size) return t.raise(.scan_size);
    }

    /// Check a file or member's size before scanning it.
    pub fn checkFileSize(t: *Tracker, size: u64) error{LimitReached}!void {
        if (size > t.limits.max_file_size) return t.raise(.file_size);
    }

    pub fn enterContainer(t: *Tracker) error{LimitReached}!void {
        if (t.depth >= t.limits.max_recursion) return t.raise(.recursion);
        t.depth += 1;
    }

    pub fn leaveContainer(t: *Tracker) void {
        t.depth -= 1;
    }

    pub fn addFile(t: *Tracker) error{LimitReached}!void {
        t.files += 1;
        if (t.files > t.limits.max_files) return t.raise(.files);
    }

    /// Account for decompressed output of a member: total budget and the expansion ratio guard.
    pub fn addOutput(t: *Tracker, compressed_so_far: u64, output_so_far: u64, n: u64) error{LimitReached}!void {
        t.output +|= n;
        if (t.output > t.limits.max_total_output) return t.raise(.total_output);
        const out = output_so_far + n;
        if (out > t.limits.ratio_floor and out / @max(compressed_so_far, 1) > t.limits.max_ratio) return t.raise(.ratio);
    }

    pub fn limited(t: *const Tracker) bool {
        return t.raised.count() != 0;
    }
};

test "each limit raises its own event" {
    var t = Tracker.init(.{ .max_scan_size = 10, .max_file_size = 5, .max_recursion = 2, .max_files = 1, .max_total_output = 50, .ratio_floor = 10, .max_ratio = 2 });
    try t.addScanned(10);
    try std.testing.expectError(error.LimitReached, t.addScanned(1));
    try std.testing.expect(t.raised.contains(.scan_size));
    try std.testing.expectError(error.LimitReached, t.checkFileSize(6));
    try t.enterContainer();
    try t.enterContainer();
    try std.testing.expectError(error.LimitReached, t.enterContainer());
    try t.addFile();
    try std.testing.expectError(error.LimitReached, t.addFile());
    // 30 bytes out of 5 compressed: past the floor and over 2:1.
    try std.testing.expectError(error.LimitReached, t.addOutput(5, 0, 30));
    try std.testing.expect(t.raised.contains(.ratio));
    try std.testing.expectError(error.LimitReached, t.addOutput(1000, 30, 30));
    try std.testing.expect(t.raised.contains(.total_output));
    for ([_]Event{ .scan_size, .file_size, .recursion, .files, .ratio, .total_output }) |e| try std.testing.expect(t.raised.contains(e));
    t.reset();
    try std.testing.expect(!t.limited());
}
