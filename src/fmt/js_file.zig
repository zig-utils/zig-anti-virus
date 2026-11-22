//! The `javascript` file clamscan --leave-temps keeps for an HTML object, observed black-box
//! (docs/clean-room.md, "Scan model"): each script's normalised JavaScript behind `<script>`,
//! followed by `</script>` unless the normalised text already ends with it, one script per
//! line. The scripts come from fmt/html_norm.zig's `Outputs.scripts`.
const std = @import("std");
const html_norm = @import("html_norm.zig");
const js_norm = @import("js_norm.zig");

/// The JavaScript file clamscan writes for an HTML object: each script's normalised text
/// behind `<script>`, followed by `</script>` unless it already ends with it, scripts one per
/// line.
pub const JavascriptFile = struct {
    out: html_norm.Output,
    js: js_norm.Normalizer = undefined,
    scripts: usize = 0,
    /// The last bytes written for the current script, to see whether it ends with `</script>`.
    tail: [9]u8 = @splat(0),
    tail_len: usize = 0,

    pub fn pieces(j: *JavascriptFile) html_norm.Pieces {
        return .{ .ctx = j, .begin = begin, .data = data, .end = end };
    }

    fn put(j: *JavascriptFile, bytes: []const u8) error{Stop}!void {
        try j.out.write(j.out.ctx, bytes);
        for (bytes) |b| {
            if (j.tail_len == j.tail.len) {
                std.mem.copyForwards(u8, j.tail[0 .. j.tail.len - 1], j.tail[1..]);
                j.tail_len -= 1;
            }
            j.tail[j.tail_len] = b;
            j.tail_len += 1;
        }
    }

    fn sink(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        try j.put(bytes);
    }

    fn begin(ctx: *anyopaque) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        if (j.scripts > 0) try j.out.write(j.out.ctx, "\n");
        j.scripts += 1;
        j.tail_len = 0;
        try j.put("<script>");
        j.js = .initHtml(.{ .ctx = j, .write = sink });
    }

    fn data(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        j.js.feed(bytes) catch return error.Stop;
    }

    fn end(ctx: *anyopaque) error{Stop}!void {
        const j: *JavascriptFile = @ptrCast(@alignCast(ctx));
        j.js.finish() catch return error.Stop;
        if (!(j.tail_len == j.tail.len and std.mem.eql(u8, &j.tail, "</script>"))) try j.put("</script>");
    }
};
