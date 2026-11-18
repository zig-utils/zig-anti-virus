//! Email (RFC 822 / MIME messages and mbox files) through zig-mime (P5.09).
//!
//! The raw message is scanned as the object itself (target type 4 applies to it, `Format.mail`).
//! zig-mime's push walker then splits it: every leaf part arrives transfer-decoded (base64,
//! quoted-printable) and is collected and scanned as a child named by its filename, or by its
//! section path when it has none (`part-1.2`). Nested messages (message/rfc822) are walked by the
//! same zig-mime walker, so their leaves keep their own section paths.
//!
//! A multipart or message part that declares base64 or quoted-printable (RFC 2045 forbids it, so
//! attackers use it) arrives from zig-mime as one decoded leaf. That child is given its
//! Content-Type line back in front of the decoded bytes, so the dispatcher recognises it as a
//! message and walks it again: its parts come out one level deeper.
//!
//! An mbox file is split at "From " lines that start a message (the first line, or a line after a
//! blank line); with more than one message each becomes a child `message/<n>`.
const std = @import("std");
const mime = @import("mime");
const container = @import("../engine/container.zig");
const Source = @import("../engine/source.zig").Source;
const Collector = @import("collect.zig").Collector;
const Walker = container.Walker;
const Error = container.Error;

/// Header field names that mark the start of a message. Any field name is accepted in a header
/// block, but at least one of these has to appear before the blank line.
const mail_fields = [_][]const u8{
    "from",       "to",          "cc",           "subject",                   "date",         "received", "return-path",      "message-id",
    "reply-to",   "sender",      "mime-version", "content-type",              "delivered-to", "x-mailer", "x-originating-ip", "in-reply-to",
    "references", "envelope-to", "x-sender",     "content-transfer-encoding", "bcc",
};

/// A head that is a header block: every line up to the first blank line (or the end of the
/// head) is a header field or a folded continuation, the first possibly an mbox "From " line,
/// and at least one field is a mail field.
pub fn isMail(head: []const u8) bool {
    if (head.len < 8) return false;
    var lines = std.mem.splitScalar(u8, head, '\n');
    var first = true;
    var known = false;
    var fields: usize = 0;
    while (lines.next()) |raw| {
        // The last piece may be cut by the end of the head; only judge complete lines.
        if (lines.index == null and head[head.len - 1] != '\n') break;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) break;
        defer first = false;
        if (first and std.mem.startsWith(u8, line, "From ")) continue;
        if (line[0] == ' ' or line[0] == '\t') {
            if (fields == 0) return false;
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
        // RFC 822's obsolete syntax allows white space before the colon.
        const field = std.mem.trimEnd(u8, line[0..colon], " \t");
        if (field.len == 0 or colon > 76) return false;
        for (field) |c| if (c <= ' ' or c >= 127) return false;
        fields += 1;
        if (!known) for (mail_fields) |f| {
            if (std.ascii.eqlIgnoreCase(field, f)) known = true;
        };
    }
    return known and fields >= 1;
}

pub fn walk(w: *Walker, src: Source) Error!void {
    const total = src.len() orelse return;
    var starts: [max_messages]u64 = undefined;
    const n = try mboxStarts(w, src, &starts);
    if (n <= 1) return walkMessage(w, src);
    if (n == max_messages) w.limit(.files);
    for (0..n) |i| {
        const end = if (i + 1 < n) starts[i + 1] else total;
        const msg = src.slice(starts[i], end - starts[i]) catch continue;
        var name_buf: [24]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "message/{d}", .{i}) catch "message";
        try w.child(name, msg, .member);
    }
}

/// Most messages split out of one mbox file. MaxFiles is normally lower; the rest stays in the
/// last message, whose raw bytes are still scanned.
const max_messages = 4096;

/// Offsets of the messages in an mbox file: 0, and every "From " line that follows a blank line.
fn mboxStarts(w: *Walker, src: Source, out: []u64) Error!usize {
    const total = src.len().?;
    var head: [5]u8 = undefined;
    src.readAllAt(w.io, 0, &head) catch return 0;
    if (!std.mem.eql(u8, &head, "From ")) return 0;
    out[0] = 0;
    var n: usize = 1;
    const buf = w.alloc(u8, container.block_len) orelse return n;
    defer w.free(buf);
    // `prev` holds the last bytes of the previous block so a "\n\nFrom " split across blocks is
    // still seen.
    const keep = 8;
    var off: u64 = 0;
    while (off < total and n < out.len) {
        const got = src.readAt(w.io, off, buf) catch break;
        if (got == 0) break;
        const data = buf[0..got];
        var i: usize = 0;
        while (std.mem.indexOfPos(u8, data, i, "\nFrom ")) |at| : (i = at + 1) {
            // A blank line before: "\n\nFrom " or "\n\r\nFrom ".
            const blank = (at >= 1 and data[at - 1] == '\n') or (at >= 2 and data[at - 1] == '\r' and data[at - 2] == '\n');
            if (!blank) continue;
            out[n] = off + at + 1;
            n += 1;
            if (n == out.len) break;
        }
        if (off + got >= total) break;
        // Step back so a pattern straddling the block edge is found in the next read.
        off += if (got > keep) got - keep else got;
    }
    return n;
}

fn walkMessage(w: *Walker, src: Source) Error!void {
    const total = src.len() orelse return;
    const state = w.scratch.allocator().create(State) catch return w.limit(.memory);
    const hdr = w.alloc(u8, 64 * 1024) orelse return;
    const block = w.alloc(u8, container.block_len) orelse return;
    state.* = .{ .w = w, .collector = .init(w), .walker = undefined };
    defer state.collector.deinit();
    // The walker's nesting counts against the recursion limit like any other container level.
    const room = w.tracker.limits.max_recursion -| w.tracker.depth;
    state.walker = .init(hdr, mime.Sink.init(state), .{
        .max_depth = @intCast(@min(room, mime.walker.max_depth_cap)),
        .max_parts = @intCast(@min(w.tracker.limits.max_files, 10_000)),
    });
    var off: u64 = 0;
    while (off < total) {
        const got = src.readAt(w.io, off, block) catch break;
        if (got == 0) break;
        state.walker.feed(block[0..got]) catch return state.stopped();
        off += got;
    }
    state.walker.finish() catch return state.stopped();
}

const State = struct {
    w: *Walker,
    walker: mime.Walker,
    collector: Collector,
    /// The leaf being collected.
    leaf: ?*const mime.Part = null,
    halted: bool = false,
    name_buf: [256]u8 = undefined,

    pub fn onEvent(s: *State, event: mime.Event) mime.Sink.Error!void {
        switch (event) {
            .part_begin => |p| {
                if (p.kind != .leaf) return;
                s.leaf = p;
                // An encoded multipart comes back decoded but without its header block; put the
                // Content-Type line back so the child is recognised and split.
                if (std.ascii.eqlIgnoreCase(p.content_type.media_type, "multipart") and
                    (p.encoding == .base64 or p.encoding == .quoted_printable))
                {
                    if (p.headers.get("content-type")) |ct| {
                        s.collector.append("Content-Type: ");
                        s.collector.append(ct);
                        s.collector.append("\r\n\r\n");
                    }
                }
            },
            .body => |b| {
                if (b.region != .content or b.raw or s.leaf != b.part) return;
                s.collector.append(b.bytes);
            },
            .part_end => |e| {
                if (s.leaf != e.part) return;
                s.leaf = null;
                const name = s.leafName(e.part);
                s.collector.emit(name, .member) catch {
                    s.halted = true;
                    return error.Aborted;
                };
            },
            .diagnostic => |d| switch (d.kind) {
                .depth_exceeded => s.w.limit(.recursion),
                .part_limit => s.w.limit(.files),
                inline else => |k| s.w.notice(.malformed, "mime: " ++ @tagName(k)),
            },
        }
    }

    /// The part's filename, its name parameter, or its section path.
    fn leafName(s: *State, p: *const mime.Part) []const u8 {
        if (p.filename orelse p.name) |f| {
            if (f.len > 0) return baseName(f);
        }
        if (p.path.len == 0) return "body";
        var out: std.Io.Writer = .fixed(&s.name_buf);
        out.writeAll("part-") catch {};
        for (p.path, 0..) |idx, i| {
            if (i > 0) out.writeByte('.') catch break;
            out.print("{d}", .{idx}) catch break;
        }
        return out.buffered();
    }

    fn stopped(s: *State) Error {
        _ = s;
        return error.Halted;
    }
};

/// The last component of an attachment's filename (clients strip directories too).
fn baseName(f: []const u8) []const u8 {
    const cut = std.mem.lastIndexOfAny(u8, f, "/\\");
    return if (cut) |i| (if (i + 1 < f.len) f[i + 1 ..] else f) else f;
}

// ---------------------------------------------------------------------------------------------

const scan = @import("scan.zig");
const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

test "detection: header blocks, mbox, and things that are not mail" {
    try std.testing.expect(isMail("From: a@example.com\r\nSubject: hi\r\n\r\nbody"));
    try std.testing.expect(isMail("X-Evasion: yes\nFrom: a@example.com\n\nbody"));
    try std.testing.expect(isMail("From a@b Mon Jan  1 00:00:00 2024\nFrom: a@b\n\n"));
    try std.testing.expect(isMail("Received: from x\n\tby y\nTo: z\n"));
    try std.testing.expect(isMail("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"));
    try std.testing.expect(!isMail("Hello world, this is text\n"));
    try std.testing.expect(!isMail("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"));
    try std.testing.expect(!isMail("Note: this is a note\nand another line\n\n"));
    try std.testing.expect(!isMail("X-Only: custom\nX-Other: field\n\n"));
}

test "EICAR attached to an email is found at its container path, base64 and quoted-printable" {
    const msg =
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: invoice\r\nMIME-Version: 1.0\r\n" ++
        "Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n" ++
        "--XX\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nSee=20attached\r\n" ++
        "--XX\r\nContent-Type: application/octet-stream; name=\"eicar.com\"\r\nContent-Transfer-Encoding: base64\r\n" ++
        "Content-Disposition: attachment; filename=\"eicar.com\"\r\n\r\n" ++
        "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNU\r\nLUZJTEUhJEgrSCo=\r\n" ++
        "--XX--\r\n";
    var rig: scan.TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(msg, "invoice.eml");
    var seen: usize = 0;
    var crc = std.hash.Crc32.init();
    crc.update(eicar);
    for (rig.rec.objects.items) |e| if (std.mem.eql(u8, e.path, "invoice.eml/eicar.com")) {
        seen += 1;
        try std.testing.expectEqual(@as(u64, eicar.len), e.bytes);
        try std.testing.expectEqual(crc.final(), e.crc);
    };
    try std.testing.expectEqual(@as(usize, 2), seen);
    try std.testing.expect(rig.rec.find("invoice.eml/part-1") != null);
    const root = rig.rec.find("invoice.eml").?;
    try std.testing.expectEqual(container.Format.mail, root.format);
    try std.testing.expectEqual(@as(usize, 0), rig.rec.notices.items.len);
    try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
}

test "a base64-encoded multipart is walked again one level down" {
    const inner = "--inner\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"payload.com\"\r\n\r\n" ++
        eicar ++ "\r\n--inner--\r\n";
    var enc_buf: [1024]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&enc_buf, inner);
    var msg_buf: [2048]u8 = undefined;
    const msg = try std.fmt.bufPrint(&msg_buf, "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=real\n\n" ++
        "--real\nContent-Type: multipart/mixed; boundary=inner\nContent-Transfer-Encoding: base64\n\n{s}\n--real--\n", .{enc});
    var rig: scan.TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.scanBoth(msg, "m.eml");
    const hit = rig.rec.find("m.eml/part-1/payload.com") orelse {
        rig.rec.dump();
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u64, eicar.len), hit.bytes);
    try std.testing.expect(rig.rec.has(.malformed)); // encoded_container is reported
}

test "an mbox file splits into messages" {
    const box = "From a@x Mon Jan  1 00:00:00 2024\nFrom: a@x\nSubject: one\n\nfirst\n\n" ++
        "From b@x Mon Jan  1 00:00:01 2024\nFrom: b@x\nSubject: two\nContent-Type: application/octet-stream; name=e.com\n\n" ++ eicar ++ "\n";
    var rig: scan.TestRig = undefined;
    try rig.init(.{});
    defer rig.deinit();
    try rig.walker.scan(.{ .memory = box }, "inbox.mbox");
    try std.testing.expect(rig.rec.find("inbox.mbox/message/0/body") != null);
    const e = rig.rec.find("inbox.mbox/message/1/e.com") orelse {
        rig.rec.dump();
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u64, eicar.len + 1), e.bytes);
}

/// The evasion corpus from zig-mime's repository (tests/evasion), copied with its marker. Each
/// sample hides an attachment the way attackers do; the marker has to reach a child object.
pub const evasion_samples = [_][]const u8{
    "bare_lf",                        "base64_after_padding",          "base64_junk",            "boundary_in_quoted_param",
    "boundary_rfc2231",               "boundary_suffix",               "case_and_spacing",       "deep_nesting",
    "duplicate_boundary_first_decoy", "duplicate_boundary_last_decoy", "duplicate_content_type", "duplicate_cte",
    "encoded_container",              "filename_conflict",             "folded_boundary_param",  "header_padding",
    "long_boundary",                  "mbox_from_line",                "missing_final_boundary", "missing_header_separator",
    "mixed_line_endings",             "multipart_without_blank_line",  "nested_same_boundary",   "part_after_close",
    "part_limit",                     "qp_obfuscated",                 "rfc822_base64",
};

/// The evasion samples' bytes (tests and the `fmt.mime` fuzz target).
pub const evasion_bytes = blk: {
    var out: [evasion_samples.len][]const u8 = undefined;
    for (evasion_samples, 0..) |name, i| out[i] = @embedFile("fixtures/mail/" ++ name ++ ".eml");
    break :blk out;
};

/// Remembers whether the marker reached any object below the message.
const MarkerSink = struct {
    found: bool = false,
    root_format: container.Format = .binary,

    const marker = "ZIG-MIME-EVASION-MARKER";

    fn visitor(s: *MarkerSink) container.Visitor {
        return .{ .ptr = s, .vtable = &.{ .enter = enter, .data = data, .leave = leave, .notice = notice } };
    }
    fn enter(ptr: *anyopaque, obj: *const container.Object) error{Stop}!void {
        const s: *MarkerSink = @ptrCast(@alignCast(ptr));
        if (obj.depth == 0) s.root_format = obj.format;
    }
    fn data(ptr: *anyopaque, obj: *const container.Object, bytes: []const u8) error{Stop}!void {
        const s: *MarkerSink = @ptrCast(@alignCast(ptr));
        if (obj.depth > 0 and std.mem.indexOf(u8, bytes, marker) != null) s.found = true;
    }
    fn leave(_: *anyopaque, _: *const container.Object) void {}
    fn notice(_: *anyopaque, _: container.Notice) void {}
};

test "every zig-mime evasion sample yields its attachment" {
    inline for (evasion_samples) |name| {
        const bytes = @embedFile("fixtures/mail/" ++ name ++ ".eml");
        for ([_]bool{ true, false }) |positional| {
            var rig: scan.TestRig = undefined;
            try rig.init(.{});
            defer rig.deinit();
            var sink: MarkerSink = .{};
            rig.walker.visitor = sink.visitor();
            if (positional) {
                try rig.walker.scan(.{ .memory = bytes }, name ++ ".eml");
            } else {
                var r: std.Io.Reader = .fixed(bytes);
                try rig.walker.scan(.{ .stream = .{ .reader = &r } }, name ++ ".eml");
            }
            if (!sink.found or sink.root_format != .mail) {
                std.debug.print("evasion sample {s}: marker found {}, format {t}\n", .{ name, sink.found, sink.root_format });
                return error.TestUnexpectedResult;
            }
            try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
        }
    }
}
