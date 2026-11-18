//! Decoder set-up shared by compression wrappers (gzip, bzip2, xz, zstd files) and archive
//! members (zip methods): take the window from the big-window budget, allocate it from scratch,
//! put a `Meter` on the output and scan the output as one stream child. Decoder failures become
//! notices: malformed, unsupported, or the window_size limit.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Walker = container.Walker;
const Error = container.Error;
const gzip = @import("gzip.zig");
const bzip2 = @import("bzip2.zig");
const xz = @import("xz.zig");
const lzma = @import("lzma.zig");
const zstd = @import("zstd.zig");
const inflate = @import("inflate.zig");

pub const Codec = enum {
    gzip,
    bzip2,
    xz,
    zstd,
    /// Raw deflate (zip method 8).
    deflate_raw,
    /// zip method 14: a 4-byte zip LZMA header, the 5-byte properties, then LZMA data.
    lzma_zip,
};

/// Decode an archive member's compressed bytes (a positional source).
pub fn child(w: *Walker, codec: Codec, data: Source, name: []const u8, size_hint: ?u64) Error!void {
    const buf = w.alloc(u8, container.block_len) orelse return;
    var sr: container.SourceReader = .init(w.io, data, buf);
    try childFrom(w, codec, &sr.interface, &sr.pulled, name, size_hint, .member);
}

/// Decode from `in`; `pulled` counts compressed bytes read (for the ratio guard).
pub fn childFrom(
    w: *Walker,
    codec: Codec,
    in: *Io.Reader,
    pulled: *const u64,
    name: []const u8,
    size_hint: ?u64,
    kind: container.Kind,
) Error!void {
    const meter_buf = w.alloc(u8, container.block_len) orelse return;
    switch (codec) {
        .gzip => {
            const window = w.alloc(u8, gzip.window_len) orelse return;
            var dec = gzip.Decoder.init(in, window);
            var meter: container.Meter = .init(w, &dec.interface, pulled, meter_buf);
            try emit(w, name, &meter, size_hint, kind);
            if (dec.err) |e| if (meter.tripped == null) w.notice(.malformed, @errorName(e));
        },
        .deflate_raw => {
            const window = w.alloc(u8, gzip.window_len) orelse return;
            var dec = inflate.Inflate.init(in, .raw, window);
            var meter: container.Meter = .init(w, &dec.interface, pulled, meter_buf);
            try emit(w, name, &meter, size_hint, kind);
            if (dec.err) |e| if (meter.tripped == null) w.notice(.malformed, @errorName(e));
        },
        .bzip2 => {
            const head = in.peek(4) catch return w.notice(.malformed, "bzip2: truncated");
            const level = bzip2.Decoder.peekLevel(head) orelse return w.notice(.malformed, "bzip2: header");
            const token = w.window(bzip2.workingSet(level), 0) orelse return;
            defer token.release();
            const tt = w.alloc(u32, @as(usize, level) * 100_000) orelse return;
            const tables = w.scratch.allocator().create(bzip2.Decoder.TablesType) catch return w.limit(.memory);
            var dec = bzip2.Decoder.init(in, tt, tables, &.{}) catch |e| return w.notice(.malformed, @errorName(e));
            var meter: container.Meter = .init(w, &dec.interface, pulled, meter_buf);
            try emit(w, name, &meter, size_hint, kind);
            if (dec.err) |e| if (meter.tripped == null) switch (e) {
                error.Randomised => w.notice(.unsupported, "bzip2: randomised block"),
                else => w.notice(.malformed, @errorName(e)),
            };
        },
        .xz => {
            const plan = xz.plan(in) catch |e| switch (e) {
                error.Unsupported => return w.notice(.unsupported, "xz: filter chain"),
                else => return w.notice(.malformed, @errorName(e)),
            };
            const dict_len = @max(plan.dict_size, 4096);
            const token = w.window(dict_len, lzma.Lzma2.probs_len * 2) orelse return;
            defer token.release();
            const dict = w.alloc(u8, @intCast(dict_len)) orelse return;
            const probs = w.alloc(u16, lzma.Lzma2.probs_len) orelse return;
            var dec = xz.Decoder.init(in, dict, probs, &.{}, &.{});
            var meter: container.Meter = .init(w, &dec.interface, pulled, meter_buf);
            try emit(w, name, &meter, size_hint, kind);
            if (dec.err) |e| if (meter.tripped == null) switch (e) {
                error.Unsupported => w.notice(.unsupported, "xz: filter chain"),
                error.DictTooLarge => w.limit(.window_size),
                else => w.notice(.malformed, @errorName(e)),
            };
        },
        .zstd => {
            const head = in.peek(@min(18, in.buffer.len)) catch in.buffered();
            const window = zstd.frameWindow(head, w.tracker.limits.max_window) catch |e| return w.notice(.malformed, @errorName(e));
            if (window > w.tracker.limits.max_window) return w.limit(.window_size);
            const s = zstd.sizing(window);
            const token = w.window(s.window_len, s.buffer_len - s.window_len) orelse return;
            defer token.release();
            const buffer = w.alloc(u8, s.buffer_len) orelse return;
            var dec = zstd.decode.Decoder.init(in, buffer, s.window_len);
            var meter: container.Meter = .init(w, &dec.interface, pulled, meter_buf);
            try emit(w, name, &meter, size_hint, kind);
            if (dec.err) |e| if (meter.tripped == null) switch (e) {
                error.WindowOversize => w.limit(.window_size),
                error.DictionaryIdFlagUnsupported => w.notice(.unsupported, "zstd: dictionary"),
                else => w.notice(.malformed, @errorName(e)),
            };
        },
        .lzma_zip => {
            const head = in.takeArray(9) catch return w.notice(.malformed, "lzma: truncated header");
            if (std.mem.readInt(u16, head[2..4], .little) != 5) return w.notice(.malformed, "lzma: properties size");
            const header = lzma.Alone.parseHeader(head[4..9]) catch return w.notice(.malformed, "lzma: properties");
            if (@as(u5, header.props.lc) + header.props.lp > 8) return w.notice(.unsupported, "lzma: lc + lp over 8");
            // The dictionary never needs to exceed the member's declared size.
            const dict_len: u64 = @max(@min(header.dict_size, size_hint orelse header.dict_size), 4096);
            const probs_len = header.props.probCount();
            const token = w.window(dict_len, probs_len * 2) orelse return;
            defer token.release();
            const dict_buf = w.alloc(u8, @intCast(dict_len)) orelse return;
            const probs = w.alloc(u16, probs_len) orelse return;
            var dict: lzma.Dict = .{ .buf = dict_buf };
            var dec = lzma.Alone.init(in, header, size_hint, probs, &dict, &.{}) catch |e| return w.notice(.malformed, @errorName(e));
            var meter: container.Meter = .init(w, &dec.interface, pulled, meter_buf);
            try emit(w, name, &meter, size_hint, kind);
            if (dec.err) |e| if (meter.tripped == null) w.notice(.malformed, @errorName(e));
        },
    }
}

fn emit(w: *Walker, name: []const u8, meter: *container.Meter, size_hint: ?u64, kind: container.Kind) Error!void {
    try w.child(name, .{ .stream = .{ .reader = &meter.interface, .len_hint = size_hint } }, kind);
}
