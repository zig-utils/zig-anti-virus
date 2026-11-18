//! PDF standard security handler with the empty user password (ISO 32000-2 section 7.6): most
//! encrypted malicious PDFs only set an owner password, so readers open them without asking, and
//! a scanner has to decrypt them the same way. Revisions 2 to 4 (RC4 and AES-128, keys from MD5)
//! and 5 and 6 (AES-256, keys from SHA-2) are supported. A file that needs a real user password
//! is reported as encrypted and scanned undecrypted.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

/// Where the trailer says the encryption dictionary is, and the first /ID string.
pub const Info = struct {
    encrypt: ?Ref = null,
    id: [32]u8 = undefined,
    id_len: usize = 0,

    pub const Ref = union(enum) {
        ref: u32,
        /// A direct dictionary: the offset just past its "<<".
        direct: u64,
    };
};

pub const Method = enum {
    none,
    rc4,
    aes128,
    aes256,

    pub fn of(n: []const u8) Method {
        if (std.mem.eql(u8, n, "V2")) return .rc4;
        if (std.mem.eql(u8, n, "AESV2")) return .aes128;
        if (std.mem.eql(u8, n, "AESV3")) return .aes256;
        return .none;
    }
};

/// The encryption dictionary's keys.
pub const Dict = struct {
    standard: bool = false,
    v: i64 = 0,
    r: i64 = 0,
    length: i64 = 40,
    p: i64 = 0,
    o: Bytes = .{},
    u: Bytes = .{},
    oe: Bytes = .{},
    ue: Bytes = .{},
    encrypt_metadata: bool = true,
    cfm: Method = .none,
    stmf_identity: bool = false,
    strf_identity: bool = false,

    pub const Bytes = struct {
        buf: [48]u8 = @splat(0),
        len: usize = 0,
    };
};

pub const Key = struct {
    method: Method = .none,
    bytes: [32]u8 = undefined,
    len: usize = 0,
};

const padding = [32]u8{
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
};

pub const Decryptor = struct {
    file_key: [32]u8 = undefined,
    key_len: usize = 0,
    method: Method,
    encrypt_metadata: bool,
    stm_identity: bool,
    str_identity: bool,

    pub fn init(d: Dict, id: []const u8) error{ Unsupported, WrongPassword }!Decryptor {
        if (!d.standard) return error.Unsupported;
        var dec: Decryptor = .{
            .method = switch (d.v) {
                1, 2 => .rc4,
                4 => if (d.cfm == .none) .rc4 else d.cfm,
                5 => .aes256,
                else => return error.Unsupported,
            },
            .encrypt_metadata = d.encrypt_metadata,
            .stm_identity = d.v >= 4 and d.stmf_identity,
            .str_identity = d.v >= 4 and d.strf_identity,
        };
        switch (d.r) {
            2, 3, 4 => {
                if (d.o.len < 32 or d.u.len < 16) return error.Unsupported;
                const n: usize = if (d.r == 2) 5 else @intCast(std.math.clamp(@divTrunc(d.length, 8), 5, 16));
                var h = Md5.init(.{});
                h.update(&padding);
                h.update(d.o.buf[0..32]);
                var p: [4]u8 = undefined;
                std.mem.writeInt(u32, &p, @truncate(@as(u64, @bitCast(d.p))), .little);
                h.update(&p);
                h.update(id);
                if (d.r >= 4 and !d.encrypt_metadata) h.update(&.{ 0xff, 0xff, 0xff, 0xff });
                var digest: [16]u8 = undefined;
                h.final(&digest);
                if (d.r >= 3) for (0..50) |_| Md5.hash(digest[0..n], &digest, .{});
                @memcpy(dec.file_key[0..n], digest[0..n]);
                dec.key_len = n;
                if (!dec.checkUser(d, id)) return error.WrongPassword;
            },
            5, 6 => {
                if (d.u.len < 48 or d.ue.len < 32) return error.Unsupported;
                var hash: [32]u8 = undefined;
                hash2B(d.r, "", d.u.buf[32..40], "", &hash);
                if (!std.mem.eql(u8, &hash, d.u.buf[0..32])) return error.WrongPassword;
                var kek: [32]u8 = undefined;
                hash2B(d.r, "", d.u.buf[40..48], "", &kek);
                // UE is the file key encrypted with AES-256 in CBC mode and a zero IV.
                const ctx = Aes256.initDec(kek);
                var iv: [16]u8 = @splat(0);
                for (0..2) |b| {
                    const blk = d.ue.buf[b * 16 ..][0..16];
                    var out: [16]u8 = undefined;
                    ctx.decrypt(&out, blk);
                    for (&out, iv) |*o, v| o.* ^= v;
                    @memcpy(dec.file_key[b * 16 ..][0..16], &out);
                    iv = blk.*;
                }
                dec.key_len = 32;
            },
            else => return error.Unsupported,
        }
        return dec;
    }

    /// Algorithms 4 and 5: does the empty password open the file?
    fn checkUser(dec: *const Decryptor, d: Dict, id: []const u8) bool {
        const key = dec.file_key[0..dec.key_len];
        if (d.r == 2) {
            var out = padding;
            var rc4 = Rc4.init(key);
            rc4.apply(&out);
            return std.mem.eql(u8, &out, d.u.buf[0..32]);
        }
        var h = Md5.init(.{});
        h.update(&padding);
        h.update(id);
        var digest: [16]u8 = undefined;
        h.final(&digest);
        for (0..20) |i| {
            var k: [16]u8 = undefined;
            for (k[0..key.len], key) |*x, y| x.* = y ^ @as(u8, @intCast(i));
            var rc4 = Rc4.init(k[0..key.len]);
            rc4.apply(&digest);
        }
        return std.mem.eql(u8, &digest, d.u.buf[0..16]);
    }

    /// Algorithm 1: the key for one object's strings and streams.
    pub fn objectKey(dec: *const Decryptor, num: u32, gen: u16) Key {
        var k: Key = .{ .method = dec.method };
        if (dec.method == .aes256) {
            @memcpy(k.bytes[0..32], dec.file_key[0..32]);
            k.len = 32;
            return k;
        }
        var h = Md5.init(.{});
        h.update(dec.file_key[0..dec.key_len]);
        var ng: [5]u8 = undefined;
        std.mem.writeInt(u24, ng[0..3], @truncate(num), .little);
        std.mem.writeInt(u16, ng[3..5], gen, .little);
        h.update(&ng);
        if (dec.method == .aes128) h.update("sAlT");
        var digest: [16]u8 = undefined;
        h.final(&digest);
        k.len = @min(dec.key_len + 5, 16);
        @memcpy(k.bytes[0..k.len], digest[0..k.len]);
        return k;
    }

    pub fn stringDecrypt(dec: *const Decryptor, num: u32, gen: u16) StringDecrypt {
        return .init(dec.objectKey(num, gen));
    }
};

/// Algorithm 2.B (revision 6), or plain SHA-256 for revision 5.
fn hash2B(r: i64, password: []const u8, salt: []const u8, udata: []const u8, out: *[32]u8) void {
    var k: [64]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(password);
    h.update(salt);
    h.update(udata);
    h.final(k[0..32]);
    if (r == 5) {
        out.* = k[0..32].*;
        return;
    }
    var klen: usize = 32;
    var k1: [64 * (127 + 64 + 48)]u8 = undefined;
    var e: [k1.len]u8 = undefined;
    var round: usize = 0;
    while (true) : (round += 1) {
        const piece_len = password.len + klen + udata.len;
        var n: usize = 0;
        for (0..64) |_| {
            @memcpy(k1[n..][0..password.len], password);
            @memcpy(k1[n + password.len ..][0..klen], k[0..klen]);
            @memcpy(k1[n + password.len + klen ..][0..udata.len], udata);
            n += piece_len;
        }
        // AES-128-CBC with key k[0..16] and IV k[16..32], no padding (n is a multiple of 16).
        const ctx = Aes128.initEnc(k[0..16].*);
        var iv: [16]u8 = k[16..32].*;
        var b: usize = 0;
        while (b < n) : (b += 16) {
            var blk: [16]u8 = k1[b..][0..16].*;
            for (&blk, iv) |*x, v| x.* ^= v;
            ctx.encrypt(e[b..][0..16], &blk);
            iv = e[b..][0..16].*;
        }
        var sum: u32 = 0;
        for (e[0..16]) |x| sum += x;
        switch (sum % 3) {
            0 => {
                Sha256.hash(e[0..n], k[0..32], .{});
                klen = 32;
            },
            1 => {
                Sha384.hash(e[0..n], k[0..48], .{});
                klen = 48;
            },
            else => {
                Sha512.hash(e[0..n], k[0..64], .{});
                klen = 64;
            },
        }
        // Spec rounds count from 1: stop after round 64 or later once the last byte of E is at
        // most that round number minus 32.
        if (round >= 63 and e[n - 1] <= round - 31) break;
    }
    out.* = k[0..32].*;
}

pub const Rc4 = struct {
    s: [256]u8,
    i: u8 = 0,
    j: u8 = 0,

    pub fn init(key: []const u8) Rc4 {
        var r: Rc4 = .{ .s = undefined };
        for (&r.s, 0..) |*x, i| x.* = @intCast(i);
        var j: u8 = 0;
        for (0..256) |i| {
            j +%= r.s[i] +% key[i % key.len];
            std.mem.swap(u8, &r.s[i], &r.s[j]);
        }
        return r;
    }

    pub fn apply(r: *Rc4, data: []u8) void {
        for (data) |*b| {
            r.i +%= 1;
            r.j +%= r.s[r.i];
            std.mem.swap(u8, &r.s[r.i], &r.s[r.j]);
            b.* ^= r.s[r.s[r.i] +% r.s[r.j]];
        }
    }
};

/// AES-CBC decryption as data arrives: the first block is the IV, and the last block's PKCS#5
/// padding is removed, so one decrypted block is held back until more input proves it is not
/// the last.
const Cbc = struct {
    dec128: ?std.crypto.core.aes.AesDecryptCtx(Aes128) = null,
    dec256: ?std.crypto.core.aes.AesDecryptCtx(Aes256) = null,
    iv: [16]u8 = undefined,
    have_iv: bool = false,
    in: [16]u8 = undefined,
    in_len: usize = 0,
    held: [16]u8 = undefined,
    have_held: bool = false,
    bad: bool = false,

    fn init(k: Key) Cbc {
        var c: Cbc = .{};
        if (k.method == .aes256) c.dec256 = Aes256.initDec(k.bytes[0..32].*) else c.dec128 = Aes128.initDec(k.bytes[0..16].*);
        return c;
    }

    /// Add one byte; returns a block of plaintext when one is released.
    fn put(c: *Cbc, b: u8) ?[16]u8 {
        c.in[c.in_len] = b;
        c.in_len += 1;
        if (c.in_len < 16) return null;
        c.in_len = 0;
        if (!c.have_iv) {
            c.iv = c.in;
            c.have_iv = true;
            return null;
        }
        var out: [16]u8 = undefined;
        if (c.dec256) |*d| d.decrypt(&out, &c.in) else c.dec128.?.decrypt(&out, &c.in);
        for (&out, c.iv) |*o, v| o.* ^= v;
        c.iv = c.in;
        const released = if (c.have_held) c.held else null;
        c.held = out;
        c.have_held = true;
        return released;
    }

    /// The held last block without its padding.
    fn finish(c: *Cbc) []const u8 {
        if (!c.have_held) return &.{};
        const pad = c.held[15];
        if (pad == 0 or pad > 16) {
            c.bad = true;
            return c.held[0..];
        }
        return c.held[0 .. 16 - pad];
    }
};

pub const StringDecrypt = struct {
    key: Key,
    rc4: Rc4 = undefined,
    cbc: Cbc = .{},

    pub fn init(k: Key) StringDecrypt {
        var s: StringDecrypt = .{ .key = k };
        if (k.method == .rc4) s.rc4 = .init(k.bytes[0..k.len]) else s.cbc = .init(k);
        return s;
    }

    pub fn put(s: *StringDecrypt, b: u8, sink: anytype) void {
        switch (s.key.method) {
            .none => sink.put(b),
            .rc4 => {
                var x = [1]u8{b};
                s.rc4.apply(&x);
                sink.put(x[0]);
            },
            .aes128, .aes256 => if (s.cbc.put(b)) |blk| for (blk) |x| sink.put(x),
        }
    }

    pub fn finish(s: *StringDecrypt, sink: anytype) void {
        if (s.key.method == .aes128 or s.key.method == .aes256) for (s.cbc.finish()) |x| sink.put(x);
    }
};

pub const StreamDecrypt = struct {
    in: *Io.Reader,
    key: Key,
    rc4: Rc4 = undefined,
    cbc: Cbc = .{},
    done: bool = false,
    bad: bool = false,
    pending: [16]u8 = undefined,
    pending_len: usize = 0,
    pending_pos: usize = 0,
    interface: Io.Reader,

    pub fn init(in: *Io.Reader, k: Key, buffer: []u8) StreamDecrypt {
        var s: StreamDecrypt = .{ .in = in, .key = k, .interface = .{ .vtable = container.fillVTable(StreamDecrypt), .buffer = buffer, .seek = 0, .end = 0 } };
        if (k.method == .rc4) s.rc4 = .init(k.bytes[0..k.len]) else if (k.method != .none) s.cbc = .init(k);
        return s;
    }

    pub fn fill(s: *StreamDecrypt, dest: []u8) Io.Reader.Error!usize {
        switch (s.key.method) {
            .none => return container.readSome(s.in, dest) catch |e| switch (e) {
                error.EndOfStream => 0,
                error.ReadFailed => error.ReadFailed,
            },
            .rc4 => {
                const n = container.readSome(s.in, dest) catch |e| switch (e) {
                    error.EndOfStream => return 0,
                    error.ReadFailed => return error.ReadFailed,
                };
                s.rc4.apply(dest[0..n]);
                return n;
            },
            .aes128, .aes256 => {
                var n: usize = 0;
                while (n < dest.len) {
                    if (s.pending_pos < s.pending_len) {
                        const k = @min(s.pending_len - s.pending_pos, dest.len - n);
                        @memcpy(dest[n..][0..k], s.pending[s.pending_pos..][0..k]);
                        s.pending_pos += k;
                        n += k;
                        continue;
                    }
                    if (s.done) break;
                    const b = s.in.takeByte() catch |e| switch (e) {
                        error.EndOfStream => {
                            s.done = true;
                            const last = s.cbc.finish();
                            s.bad = s.cbc.bad;
                            @memcpy(s.pending[0..last.len], last);
                            s.pending_len = last.len;
                            s.pending_pos = 0;
                            continue;
                        },
                        error.ReadFailed => return error.ReadFailed,
                    };
                    if (s.cbc.put(b)) |blk| {
                        s.pending = blk;
                        s.pending_len = 16;
                        s.pending_pos = 0;
                    }
                }
                return n;
            },
        }
    }
};

test "RC4 matches the classic test vector" {
    var data = "Plaintext".*;
    var r = Rc4.init("Key");
    r.apply(&data);
    try std.testing.expectEqualSlices(u8, &.{ 0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3 }, &data);
}

test "AES-CBC stream and string decryption remove the padding" {
    const key: Key = .{ .method = .aes128, .bytes = @splat(7), .len = 16 };
    const plain = "javascript payload: app.alert(1);";
    // Encrypt with a fixed IV and PKCS#5 padding.
    var ct: [16 + 48]u8 = undefined;
    const iv: [16]u8 = @splat(9);
    ct[0..16].* = iv;
    var padded: [48]u8 = undefined;
    @memcpy(padded[0..plain.len], plain);
    @memset(padded[plain.len..], 48 - plain.len);
    const enc = Aes128.initEnc(key.bytes[0..16].*);
    var prev = iv;
    var b: usize = 0;
    while (b < 48) : (b += 16) {
        var blk: [16]u8 = padded[b..][0..16].*;
        for (&blk, prev) |*x, v| x.* ^= v;
        enc.encrypt(ct[16 + b ..][0..16], &blk);
        prev = ct[16 + b ..][0..16].*;
    }
    var in: Io.Reader = .fixed(&ct);
    var buf: [5]u8 = undefined;
    var s = StreamDecrypt.init(&in, key, &buf);
    var out: [64]u8 = undefined;
    var n: usize = 0;
    while (true) {
        const k = container.readSome(&s.interface, out[n..]) catch break;
        n += k;
    }
    try std.testing.expectEqualStrings(plain, out[0..n]);
    try std.testing.expect(!s.bad);

    const Sink = struct {
        out: [64]u8 = undefined,
        len: usize = 0,
        pub fn put(x: *@This(), c: u8) void {
            x.out[x.len] = c;
            x.len += 1;
        }
    };
    var sd = StringDecrypt.init(key);
    var sink: Sink = .{};
    for (ct) |c| sd.put(c, &sink);
    sd.finish(&sink);
    try std.testing.expectEqualStrings(plain, sink.out[0..sink.len]);
}
