//! Mach-O code signature classification from the file itself: LC_CODE_SIGNATURE, the embedded
//! signature SuperBlob, CodeDirectory flags and the CMS blob. It tells unsigned, ad-hoc
//! (including linker-signed) and certificate-signed code apart, for every slice of a universal
//! binary. It does not validate the certificate chain or page hashes; a binary with a forged
//! certificate blob classifies as signed, so this is a triage signal, not a trust decision.
const std = @import("std");
const Host = @import("../host.zig").Host;

pub const Signing = enum {
    not_macho,
    unsigned,
    adhoc,
    signed,

    fn weaker(a: Signing, b: Signing) Signing {
        return if (@backingInt(a) <= @backingInt(b)) a else b;
    }
};

const mh_magic_64 = 0xfeedfacf;
const mh_magic = 0xfeedface;
const fat_magic = 0xcafebabe;
const fat_magic_64 = 0xcafebabf;
const lc_code_signature = 0x1d;
const cs_adhoc = 0x2;

pub const max_slices = 16;

/// Reads at an offset, so large binaries are not loaded whole.
pub const Source = struct {
    ctx: *const anyopaque,
    readFn: *const fn (ctx: *const anyopaque, offset: u64, buf: []u8) usize,

    fn read(s: Source, offset: u64, buf: []u8) []u8 {
        return buf[0..s.readFn(s.ctx, offset, buf)];
    }

    pub fn fromSlice(bytes: *const []const u8) Source {
        return .{ .ctx = @ptrCast(bytes), .readFn = struct {
            fn f(ctx: *const anyopaque, offset: u64, buf: []u8) usize {
                const b: *const []const u8 = @ptrCast(@alignCast(ctx));
                if (offset >= b.len) return 0;
                const n = @min(buf.len, b.len - @as(usize, @intCast(offset)));
                @memcpy(buf[0..n], b.*[@intCast(offset)..][0..n]);
                return n;
            }
        }.f };
    }
};

pub fn classify(src: Source) Signing {
    var head: [8]u8 = undefined;
    const h = src.read(0, &head);
    if (h.len < 8) return .not_macho;
    const be = std.mem.readInt(u32, h[0..4], .big);
    if (be == fat_magic or be == fat_magic_64) {
        const n = std.mem.readInt(u32, h[4..8], .big);
        if (n == 0 or n > max_slices) return .not_macho; // also rejects Java class files (0xcafebabe)
        const entry: usize = if (be == fat_magic) 20 else 32;
        var result: Signing = .signed;
        var arch: [32]u8 = undefined;
        for (0..n) |i| {
            const a = src.read(8 + i * entry, arch[0..entry]);
            if (a.len < entry) return .not_macho;
            const offset: u64 = if (be == fat_magic) std.mem.readInt(u32, a[8..12], .big) else std.mem.readInt(u64, a[8..16], .big);
            result = result.weaker(classifySlice(src, offset));
        }
        return result;
    }
    return classifySlice(src, 0);
}

fn classifySlice(src: Source, base: u64) Signing {
    var hdr: [32]u8 = undefined;
    const h = src.read(base, &hdr);
    if (h.len < 28) return .not_macho;
    const magic = std.mem.readInt(u32, h[0..4], .little);
    const header_len: u64 = switch (magic) {
        mh_magic_64 => 32,
        mh_magic => 28,
        else => return .not_macho,
    };
    const ncmds = std.mem.readInt(u32, h[16..20], .little);
    const sizeofcmds = std.mem.readInt(u32, h[20..24], .little);
    if (ncmds > 4096 or sizeofcmds > 16 * 1024 * 1024) return .not_macho;
    var off = base + header_len;
    const end = off + sizeofcmds;
    var lc: [16]u8 = undefined;
    var i: u32 = 0;
    while (i < ncmds and off + 8 <= end) : (i += 1) {
        const c = src.read(off, &lc);
        if (c.len < 8) return .unsigned;
        const cmd = std.mem.readInt(u32, c[0..4], .little);
        const size = std.mem.readInt(u32, c[4..8], .little);
        if (size < 8) return .unsigned;
        if (cmd == lc_code_signature and c.len >= 16) {
            const dataoff = std.mem.readInt(u32, c[8..12], .little);
            const datasize = std.mem.readInt(u32, c[12..16], .little);
            return superBlob(src, base + dataoff, datasize);
        }
        off += size;
    }
    return .unsigned;
}

fn superBlob(src: Source, at: u64, size: u32) Signing {
    var hdr: [12]u8 = undefined;
    const h = src.read(at, &hdr);
    if (h.len < 12 or std.mem.readInt(u32, h[0..4], .big) != 0xfade0cc0) return .unsigned;
    const count = std.mem.readInt(u32, h[8..12], .big);
    if (count > 64) return .unsigned;
    var adhoc = false;
    var have_cd = false;
    var cms = false;
    var idx: [8]u8 = undefined;
    for (0..count) |i| {
        const e = src.read(at + 12 + i * 8, &idx);
        if (e.len < 8) break;
        const typ = std.mem.readInt(u32, e[0..4], .big);
        const boff = std.mem.readInt(u32, e[4..8], .big);
        if (boff >= size) continue;
        var blob: [16]u8 = undefined;
        const b = src.read(at + boff, &blob);
        if (b.len < 16) continue;
        const bmagic = std.mem.readInt(u32, b[0..4], .big);
        const blen = std.mem.readInt(u32, b[4..8], .big);
        if (typ == 0 and bmagic == 0xfade0c02) {
            have_cd = true;
            if (std.mem.readInt(u32, b[12..16], .big) & cs_adhoc != 0) adhoc = true;
        } else if (typ == 0x10000 and bmagic == 0xfade0b01 and blen > 8) {
            cms = true;
        }
    }
    if (!have_cd) return .unsigned;
    return if (cms and !adhoc) .signed else .adhoc;
}

/// Classify a file under the host root.
pub fn classifyPath(h: Host, path: []const u8) !Signing {
    var file = try h.root.openFile(h.io, Host.rel(path), .{});
    defer file.close(h.io);
    const Ctx = struct { file: std.Io.File, io: std.Io };
    const ctx: Ctx = .{ .file = file, .io = h.io };
    return classify(.{ .ctx = &ctx, .readFn = struct {
        fn f(c: *const anyopaque, offset: u64, buf: []u8) usize {
            const x: *const Ctx = @ptrCast(@alignCast(c));
            return x.file.readPositionalAll(x.io, buf, offset) catch 0;
        }
    }.f });
}

// Tests -----------------------------------------------------------------------------------------

/// A minimal 64-bit Mach-O with an optional signature: `cms` adds a non-empty CMS blob, `adhoc`
/// sets CS_ADHOC in the CodeDirectory.
pub fn buildFixture(buf: []u8, sign: enum { none, adhoc, signed }) []u8 {
    @memset(buf, 0);
    std.mem.writeInt(u32, buf[0..4], mh_magic_64, .little);
    std.mem.writeInt(u32, buf[4..8], 0x0100000c, .little); // arm64
    std.mem.writeInt(u32, buf[12..16], 2, .little); // MH_EXECUTE
    if (sign == .none) {
        std.mem.writeInt(u32, buf[16..20], 0, .little);
        return buf[0..64];
    }
    std.mem.writeInt(u32, buf[16..20], 1, .little);
    std.mem.writeInt(u32, buf[20..24], 16, .little);
    std.mem.writeInt(u32, buf[32..36], lc_code_signature, .little);
    std.mem.writeInt(u32, buf[36..40], 16, .little);
    const sig: u32 = 128;
    std.mem.writeInt(u32, buf[40..44], sig, .little);
    std.mem.writeInt(u32, buf[44..48], 128, .little);
    const s = buf[sig..];
    std.mem.writeInt(u32, s[0..4], 0xfade0cc0, .big);
    std.mem.writeInt(u32, s[4..8], 128, .big);
    std.mem.writeInt(u32, s[8..12], 2, .big);
    std.mem.writeInt(u32, s[12..16], 0, .big); // CodeDirectory slot
    std.mem.writeInt(u32, s[16..20], 32, .big);
    std.mem.writeInt(u32, s[20..24], 0x10000, .big); // CMS slot
    std.mem.writeInt(u32, s[24..28], 64, .big);
    std.mem.writeInt(u32, s[32..36], 0xfade0c02, .big);
    std.mem.writeInt(u32, s[36..40], 32, .big);
    std.mem.writeInt(u32, s[44..48], if (sign == .adhoc) cs_adhoc else 0, .big);
    std.mem.writeInt(u32, s[64..68], 0xfade0b01, .big);
    std.mem.writeInt(u32, s[68..72], if (sign == .signed) 40 else 8, .big);
    return buf[0..256];
}

test "signature classification of synthetic Mach-O files" {
    var buf: [256]u8 = undefined;
    var bytes: []const u8 = buildFixture(&buf, .none);
    try std.testing.expectEqual(Signing.unsigned, classify(.fromSlice(&bytes)));
    bytes = buildFixture(&buf, .adhoc);
    try std.testing.expectEqual(Signing.adhoc, classify(.fromSlice(&bytes)));
    bytes = buildFixture(&buf, .signed);
    try std.testing.expectEqual(Signing.signed, classify(.fromSlice(&bytes)));
    bytes = "#!/bin/sh\necho hi\n";
    try std.testing.expectEqual(Signing.not_macho, classify(.fromSlice(&bytes)));
    const java = [_]u8{ 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41 };
    bytes = &java;
    try std.testing.expectEqual(Signing.not_macho, classify(.fromSlice(&bytes)));
}

test "live: Apple binaries are signed" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const h = try Host.openLive(std.testing.io);
    defer h.close();
    try std.testing.expectEqual(Signing.signed, try classifyPath(h, "/bin/ls"));
}
