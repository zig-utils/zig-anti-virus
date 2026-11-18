//! cpio: the SVR4 "newc" (070701) and CRC (070702) ASCII-hex formats, the POSIX "odc" (070707)
//! octal format, and the old binary format (0x71c7, either byte order). Written from the cpio(5)
//! format description. Regular files are scanned; the archive ends at "TRAILER!!!".
const std = @import("std");
const container = @import("../engine/container.zig");
const archive = @import("archive.zig");
const Walker = container.Walker;

pub const max_name = 4096;

const Variant = enum { newc, odc, bin_le, bin_be };

pub fn walk(w: *Walker, cursor: *archive.Cursor) container.Error!void {
    var name_buf: [max_name]u8 = undefined;
    var first = true;
    while (true) {
        var magic: [6]u8 = undefined;
        cursor.read(magic[0..2]) catch |e| return end(w, e, first);
        const variant: Variant = if (magic[0] == 0xc7 and magic[1] == 0x71)
            .bin_le
        else if (magic[0] == 0x71 and magic[1] == 0xc7)
            .bin_be
        else blk: {
            cursor.read(magic[2..6]) catch |e| return end(w, e, first);
            if (std.mem.eql(u8, &magic, "070701") or std.mem.eql(u8, &magic, "070702")) break :blk .newc;
            if (std.mem.eql(u8, &magic, "070707")) break :blk .odc;
            w.notice(.malformed, "cpio: bad magic");
            return;
        };
        first = false;
        var mode: u64 = undefined;
        var name_size: u64 = undefined;
        var file_size: u64 = undefined;
        switch (variant) {
            .newc => {
                var h: [104]u8 = undefined;
                cursor.read(&h) catch |e| return end(w, e, false);
                mode = hex(h[8..16]) orelse return bad(w);
                file_size = hex(h[48..56]) orelse return bad(w);
                name_size = hex(h[88..96]) orelse return bad(w);
            },
            .odc => {
                var h: [70]u8 = undefined;
                cursor.read(&h) catch |e| return end(w, e, false);
                mode = octal(h[12..18]) orelse return bad(w);
                name_size = octal(h[53..59]) orelse return bad(w);
                file_size = octal(h[59..70]) orelse return bad(w);
            },
            .bin_le, .bin_be => {
                var h: [24]u8 = undefined;
                cursor.read(&h) catch |e| return end(w, e, false);
                const endian: std.builtin.Endian = if (variant == .bin_le) .little else .big;
                const word = struct {
                    fn at(b: []const u8, i: usize, e: std.builtin.Endian) u64 {
                        return std.mem.readInt(u16, b[i..][0..2], e);
                    }
                }.at;
                mode = word(&h, 4, endian);
                name_size = word(&h, 18, endian);
                // The 32-bit size is stored as two 16-bit words, most significant first.
                file_size = (word(&h, 20, endian) << 16) | word(&h, 22, endian);
            },
        }
        if (name_size == 0 or name_size > max_name) return bad(w);
        const name_raw = name_buf[0..@intCast(name_size)];
        cursor.read(name_raw) catch |e| return end(w, e, false);
        const name = archive.cstr(name_raw);
        // Padding: newc aligns header+name and data to 4 bytes, binary to 2, odc not at all.
        const header_len: u64 = switch (variant) {
            .newc => 110,
            .odc => 76,
            .bin_le, .bin_be => 26,
        };
        cursor.skip(pad(variant, header_len + name_size)) catch |e| return end(w, e, false);
        if (std.mem.eql(u8, name, "TRAILER!!!")) return;
        const is_regular = (mode & 0o170000) == 0o100000;
        if (is_regular and file_size > 0) {
            if (!try cursor.member(name, file_size, .member)) return;
        } else {
            cursor.skip(file_size) catch |e| return end(w, e, false);
        }
        cursor.skip(pad(variant, file_size)) catch |e| return end(w, e, false);
    }
}

fn pad(v: Variant, n: u64) u64 {
    return switch (v) {
        .newc => (4 - n % 4) % 4,
        .bin_le, .bin_be => n % 2,
        .odc => 0,
    };
}

fn end(w: *Walker, e: archive.Cursor.ReadError, first: bool) container.Error!void {
    switch (e) {
        // No trailer: report it unless the archive was empty.
        error.EndOfStream => if (!first) w.notice(.malformed, "cpio: truncated, no trailer"),
        error.ReadFailed => if (w.halt != null) return error.Halted,
    }
}

fn bad(w: *Walker) void {
    w.notice(.malformed, "cpio: bad header field");
}

fn hex(f: []const u8) ?u64 {
    return std.fmt.parseInt(u64, f, 16) catch null;
}

fn octal(f: []const u8) ?u64 {
    return std.fmt.parseInt(u64, f, 8) catch null;
}
