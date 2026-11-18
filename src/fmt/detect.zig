//! File-type detection from the first bytes of an object. Only magic numbers and cheap structural
//! checks: the decision has to be made from a short head (`head_len` bytes) so streams can be
//! classified with a peek, before anything is consumed.
const std = @import("std");

/// Bytes a detector looks at. tar needs 512 (the header block), HTML sniffing likes more.
pub const head_len = 4096;

pub const Format = enum(u8) {
    /// Nothing recognised; scanned as raw bytes only.
    binary,
    text,
    html,
    gzip,
    bzip2,
    xz,
    zstd,
    zip,
    tar,
    cpio,
    pe,
    elf,
    macho,
    macho_fat,
    ole2,

    /// Containers whose members are read in order, so they work over a forward-only stream.
    pub fn streamable(f: Format) bool {
        return switch (f) {
            .gzip, .bzip2, .xz, .zstd, .tar, .cpio => true,
            else => false,
        };
    }

    /// Formats parsed with positional reads (central directories, section tables).
    pub fn needsRandomAccess(f: Format) bool {
        return switch (f) {
            .zip, .pe, .elf, .macho, .macho_fat, .ole2 => true,
            else => false,
        };
    }
};

pub fn detect(head: []const u8) Format {
    if (head.len >= 3 and head[0] == 0x1f and head[1] == 0x8b and head[2] == 8) return .gzip;
    if (head.len >= 10 and std.mem.eql(u8, head[0..3], "BZh") and head[3] >= '1' and head[3] <= '9' and
        (std.mem.eql(u8, head[4..10], "\x31\x41\x59\x26\x53\x59") or std.mem.eql(u8, head[4..10], "\x17\x72\x45\x38\x50\x90")))
        return .bzip2;
    if (std.mem.startsWith(u8, head, "\xfd7zXZ\x00")) return .xz;
    if (head.len >= 4) {
        const le = std.mem.readInt(u32, head[0..4], .little);
        if (le == 0xFD2FB528) return .zstd;
        if (le & 0xFFFFFFF0 == 0x184D2A50) return .zstd; // skippable frame
    }
    if (std.mem.startsWith(u8, head, "PK\x03\x04") or std.mem.startsWith(u8, head, "PK\x05\x06") or
        std.mem.startsWith(u8, head, "PK\x07\x08")) return .zip;
    if (std.mem.startsWith(u8, head, "\x7fELF")) return .elf;
    if (std.mem.startsWith(u8, head, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")) return .ole2;
    if (head.len >= 4) {
        const be = std.mem.readInt(u32, head[0..4], .big);
        switch (be) {
            0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE => return .macho,
            // Java class files share CAFEBABE; their next word is a version >= 45, a fat header's
            // is a small architecture count.
            0xCAFEBABE, 0xCAFEBABF => if (head.len >= 8 and std.mem.readInt(u32, head[4..8], .big) -% 1 < 30) return .macho_fat,
            else => {},
        }
    }
    if (std.mem.startsWith(u8, head, "MZ")) return .pe;
    if (isCpio(head)) return .cpio;
    if (isTar(head)) return .tar;
    if (isHtml(head)) return .html;
    if (isText(head)) return .text;
    return .binary;
}

fn isCpio(head: []const u8) bool {
    if (std.mem.startsWith(u8, head, "070701") or std.mem.startsWith(u8, head, "070702") or
        std.mem.startsWith(u8, head, "070707")) return true;
    return head.len >= 26 and ((head[0] == 0xc7 and head[1] == 0x71) or (head[0] == 0x71 and head[1] == 0xc7));
}

/// ustar and GNU magic, or a v7 header whose checksum adds up.
pub fn isTar(head: []const u8) bool {
    if (head.len < 512) return false;
    if (std.mem.eql(u8, head[257..262], "ustar")) return true;
    // v7: the checksum field is octal over the header with the field itself as spaces.
    const field = head[148..156];
    var stored: u32 = 0;
    var digits: usize = 0;
    for (field) |c| switch (c) {
        '0'...'7' => {
            stored = stored * 8 + (c - '0');
            digits += 1;
        },
        ' ', 0 => if (digits > 0) break,
        else => return false,
    };
    if (digits == 0) return false;
    var sum: u32 = 0;
    for (head[0..512], 0..) |c, i| sum += if (i >= 148 and i < 156) ' ' else c;
    return sum == stored and head[0] != 0;
}

fn isText(head: []const u8) bool {
    if (head.len == 0) return false;
    var bad: usize = 0;
    for (head) |c| switch (c) {
        0 => return false,
        '\t', '\n', '\r', 0x0c => {},
        1...8, 11, 14...31, 127 => bad += 1,
        else => {},
    };
    return bad * 100 <= head.len;
}

const html_markers = [_][]const u8{
    "<html", "<!doctype html", "<head", "<body", "<script", "<iframe", "<meta ", "<title", "<form", "<object", "<embed", "<svg",
};

fn isHtml(head: []const u8) bool {
    if (!isText(head)) return false;
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, head, i, '<')) |lt| : (i = lt + 1) {
        for (html_markers) |m| {
            if (lt + m.len <= head.len and std.ascii.eqlIgnoreCase(head[lt..][0..m.len], m)) return true;
        }
    }
    return false;
}

test "magic numbers" {
    try std.testing.expectEqual(Format.gzip, detect("\x1f\x8b\x08\x00"));
    try std.testing.expectEqual(Format.bzip2, detect("BZh91AY&SY...."));
    try std.testing.expectEqual(Format.xz, detect("\xfd7zXZ\x00\x00"));
    try std.testing.expectEqual(Format.zstd, detect("\x28\xb5\x2f\xfd"));
    try std.testing.expectEqual(Format.zip, detect("PK\x03\x04"));
    try std.testing.expectEqual(Format.elf, detect("\x7fELF\x02"));
    try std.testing.expectEqual(Format.ole2, detect("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"));
    try std.testing.expectEqual(Format.macho, detect("\xcf\xfa\xed\xfe"));
    try std.testing.expectEqual(Format.macho_fat, detect("\xca\xfe\xba\xbe\x00\x00\x00\x02"));
    try std.testing.expectEqual(Format.binary, detect("\xca\xfe\xba\xbe\x00\x00\x00\x34")); // Java class
    try std.testing.expectEqual(Format.pe, detect("MZ\x90\x00"));
    try std.testing.expectEqual(Format.cpio, detect("070701000000"));
    try std.testing.expectEqual(Format.html, detect("<!-- x -->\n<HTML><body>hi</body></HTML>"));
    try std.testing.expectEqual(Format.text, detect("just some words\n"));
    try std.testing.expectEqual(Format.binary, detect("\x00\x01\x02"));
    var tar: [512]u8 = @splat(0);
    @memcpy(tar[0..4], "file");
    @memcpy(tar[257..263], "ustar\x00");
    try std.testing.expectEqual(Format.tar, detect(&tar));
}
