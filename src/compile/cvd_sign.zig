//! Detached CVD signatures (`<name>-<version>.cvd.sign`), which newer ClamAV releases publish
//! next to every database alongside the legacy signature in the CVD header.
//!
//! The file is text: a `#clamsign-1.0` line, then one line per signature,
//! `min_flevel:max_flevel:type:data`. The only type in use is `pkcs7-pem`, whose data is a base-64
//! DER PKCS#7 (RFC 2315 / RFC 5652) SignedData over the whole CVD file, detached:
//! - signed attributes carry the content type (data) and the SHA-2 digest of the CVD;
//! - the signer's RSA key signs the DER of those attributes (PKCS#1 v1.5);
//! - the certificates in the envelope chain the signer to a root whose SubjectPublicKeyInfo
//!   SHA-256 is pinned here. Every link is checked: issuer and subject names match, the issuer is
//!   a CA, the signature verifies, and the signing time falls inside every certificate's
//!   validity.
//!
//! Everything in the file is hostile input: every DER length is checked against its parent, no
//! pointer leaves the decoded buffer, and only big-integer arithmetic is delegated to std
//! (`std.crypto.ff`; Cisco's release key is 8192-bit, beyond std's X.509 RSA limit of 4096).
//!
//! The format follows the observed files and the public standards above; no ClamAV code is used.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const Pin = [32]u8;

/// SHA-256 of the SubjectPublicKeyInfo of "Cisco Software Identity Root CA RSA 4096 SHA512
/// 2099", the root ClamAV ships as certs/clamav.crt (checked against that file and the chain in
/// main-63.cvd.sign).
pub const cisco_root_pin: Pin = hexPin("551bd3758a4ba400b02f5a5f94c213fef490488f2f66fc1b2c9aee9447a41107");

pub const max_sign_file = 256 * 1024;
const max_certs = 8;
const max_chain = 5;

pub const Error = error{
    BadSignFile,
    UnsupportedSignature,
    NoSignature,
    BadDer,
    BadPkcs7,
    BadCertificate,
    DigestMismatch,
    SignatureInvalid,
    UntrustedChain,
    CertificateNotValid,
} || std.mem.Allocator.Error;

fn hexPin(comptime hex: []const u8) Pin {
    var out: Pin = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Verify a `.sign` file against the SHA-256 of the whole CVD it accompanies. Every `pkcs7-pem`
/// line must verify and at least one must be present; lines of other types are ignored.
pub fn verify(gpa: std.mem.Allocator, text: []const u8, file_digest: *const [32]u8, pin: *const Pin) Error!void {
    if (text.len > max_sign_file) return error.BadSignFile;
    var lines = std.mem.splitScalar(u8, text, '\n');
    const first = std.mem.trimEnd(u8, lines.next() orelse return error.BadSignFile, "\r ");
    if (!std.mem.eql(u8, first, "#clamsign-1.0")) return error.BadSignFile;
    var verified: usize = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r ");
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        _ = fields.next() orelse return error.BadSignFile; // min flevel
        _ = fields.next() orelse return error.BadSignFile; // max flevel
        const kind = fields.next() orelse return error.BadSignFile;
        const data = fields.rest();
        if (!std.mem.eql(u8, kind, "pkcs7-pem")) continue;
        const decoder = std.base64.standard.Decoder;
        const len = decoder.calcSizeForSlice(data) catch return error.BadSignFile;
        const der = try gpa.alloc(u8, len);
        defer gpa.free(der);
        decoder.decode(der, data) catch return error.BadSignFile;
        try verifyPkcs7(der, file_digest, pin);
        verified += 1;
    }
    if (verified == 0) return error.NoSignature;
}

// ---------------------------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------------------------

const Tlv = struct {
    tag: u8,
    /// First byte of the identifier.
    head: usize,
    /// Content range.
    start: usize,
    end: usize,

    fn content(t: Tlv, b: []const u8) []const u8 {
        return b[t.start..t.end];
    }

    fn whole(t: Tlv, b: []const u8) []const u8 {
        return b[t.head..t.end];
    }
};

/// Parse one TLV at `pos` that must end by `limit`. Definite lengths only, low tag numbers only.
fn tlv(b: []const u8, pos: usize, limit: usize) Error!Tlv {
    if (limit > b.len or pos >= limit or limit - pos < 2) return error.BadDer;
    const tag = b[pos];
    if (tag & 0x1f == 0x1f) return error.BadDer;
    var i = pos + 1;
    const first = b[i];
    i += 1;
    var len: usize = 0;
    if (first < 0x80) {
        len = first;
    } else {
        const n = first & 0x7f;
        if (n == 0 or n > 4 or limit - i < n) return error.BadDer;
        for (b[i..][0..n]) |byte| len = (len << 8) | byte;
        i += n;
    }
    if (limit - i < len) return error.BadDer;
    return .{ .tag = tag, .head = pos, .start = i, .end = i + len };
}

/// Children of a constructed TLV, in order.
const Children = struct {
    b: []const u8,
    pos: usize,
    end: usize,

    fn of(b: []const u8, parent: Tlv) Children {
        return .{ .b = b, .pos = parent.start, .end = parent.end };
    }

    fn next(c: *Children) Error!?Tlv {
        if (c.pos == c.end) return null;
        const t = try tlv(c.b, c.pos, c.end);
        c.pos = t.end;
        return t;
    }

    fn expect(c: *Children, tag: u8) Error!Tlv {
        const t = (try c.next()) orelse return error.BadDer;
        if (t.tag != tag) return error.BadDer;
        return t;
    }

    /// The next child if it has `tag`, otherwise nothing is consumed.
    fn optional(c: *Children, tag: u8) Error!?Tlv {
        if (c.pos == c.end) return null;
        const t = try tlv(c.b, c.pos, c.end);
        if (t.tag != tag) return null;
        c.pos = t.end;
        return t;
    }
};

const tag_int = 0x02;
const tag_bitstring = 0x03;
const tag_octets = 0x04;
const tag_oid = 0x06;
const tag_utc = 0x17;
const tag_generalized = 0x18;
const tag_seq = 0x30;
const tag_set = 0x31;
const tag_ctx0 = 0xa0;
const tag_ctx1 = 0xa1;
const tag_ctx3 = 0xa3;

const oid_signed_data = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 };
const oid_data = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01 };
const oid_content_type = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03 };
const oid_message_digest = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04 };
const oid_signing_time = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05 };
const oid_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_sha256_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const oid_sha384_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
const oid_sha512_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d };
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
const oid_sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
const oid_sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };

const HashAlg = enum { sha256, sha384, sha512 };

fn digestOid(oid: []const u8) ?HashAlg {
    if (std.mem.eql(u8, oid, &oid_sha256)) return .sha256;
    if (std.mem.eql(u8, oid, &oid_sha384)) return .sha384;
    if (std.mem.eql(u8, oid, &oid_sha512)) return .sha512;
    return null;
}

fn signatureOid(oid: []const u8) ?HashAlg {
    if (std.mem.eql(u8, oid, &oid_sha256_rsa)) return .sha256;
    if (std.mem.eql(u8, oid, &oid_sha384_rsa)) return .sha384;
    if (std.mem.eql(u8, oid, &oid_sha512_rsa)) return .sha512;
    return null;
}

/// The OID inside an AlgorithmIdentifier.
fn algorithm(b: []const u8, alg: Tlv) Error![]const u8 {
    if (alg.tag != tag_seq) return error.BadDer;
    var c = Children.of(b, alg);
    return (try c.expect(tag_oid)).content(b);
}

// ---------------------------------------------------------------------------------------------
// X.509, only what chain verification needs
// ---------------------------------------------------------------------------------------------

const Cert = struct {
    tbs: []const u8,
    serial: []const u8,
    issuer: []const u8,
    subject: []const u8,
    not_before: i64,
    not_after: i64,
    spki: []const u8,
    modulus: []const u8,
    exponent: []const u8,
    sig_hash: HashAlg,
    signature: []const u8,
    is_ca: bool,
};

fn parseCert(b: []const u8, cert: Tlv) Error!Cert {
    if (cert.tag != tag_seq) return error.BadCertificate;
    var top = Children.of(b, cert);
    const tbs = try top.expect(tag_seq);
    const sig_alg = (try top.next()) orelse return error.BadCertificate;
    const sig_bits = try top.expect(tag_bitstring);
    if (try top.next() != null) return error.BadCertificate;

    var c = Children.of(b, tbs);
    _ = try c.optional(tag_ctx0); // version
    const serial = try c.expect(tag_int);
    _ = try c.expect(tag_seq); // signature algorithm, repeated
    const issuer = try c.expect(tag_seq);
    const validity = try c.expect(tag_seq);
    const subject = try c.expect(tag_seq);
    const spki = try c.expect(tag_seq);
    var is_ca = false;
    while (try c.next()) |field| {
        if (field.tag == tag_ctx3) is_ca = try basicConstraintsCa(b, field);
    }

    var v = Children.of(b, validity);
    const not_before = try parseTime(b, (try v.next()) orelse return error.BadCertificate);
    const not_after = try parseTime(b, (try v.next()) orelse return error.BadCertificate);

    var k = Children.of(b, spki);
    const key_alg = (try k.next()) orelse return error.BadCertificate;
    if (!std.mem.eql(u8, try algorithm(b, key_alg), &oid_rsa)) return error.BadCertificate;
    const key_bits = try k.expect(tag_bitstring);
    if (key_bits.end == key_bits.start or b[key_bits.start] != 0) return error.BadCertificate;
    const key = try tlv(b, key_bits.start + 1, key_bits.end);
    if (key.tag != tag_seq) return error.BadCertificate;
    var kc = Children.of(b, key);
    const modulus = try kc.expect(tag_int);
    const exponent = try kc.expect(tag_int);

    if (sig_bits.end == sig_bits.start or b[sig_bits.start] != 0) return error.BadCertificate;
    return .{
        .tbs = tbs.whole(b),
        .serial = serial.content(b),
        .issuer = issuer.whole(b),
        .subject = subject.whole(b),
        .not_before = not_before,
        .not_after = not_after,
        .spki = spki.whole(b),
        .modulus = std.mem.trimStart(u8, modulus.content(b), &.{0}),
        .exponent = exponent.content(b),
        .sig_hash = signatureOid(try algorithm(b, sig_alg)) orelse return error.UnsupportedSignature,
        .signature = b[sig_bits.start + 1 .. sig_bits.end],
        .is_ca = is_ca,
    };
}

/// `[3] { SEQUENCE OF Extension { OID, [BOOLEAN critical], OCTET STRING } }`: the cA flag of
/// basicConstraints, false when absent.
fn basicConstraintsCa(b: []const u8, wrapper: Tlv) Error!bool {
    var w = Children.of(b, wrapper);
    const list = try w.expect(tag_seq);
    var exts = Children.of(b, list);
    while (try exts.next()) |ext| {
        if (ext.tag != tag_seq) return error.BadCertificate;
        var e = Children.of(b, ext);
        const oid = try e.expect(tag_oid);
        if (!std.mem.eql(u8, oid.content(b), &oid_basic_constraints)) continue;
        _ = try e.optional(0x01); // critical
        const value = try e.expect(tag_octets);
        const seq = try tlv(b, value.start, value.end);
        if (seq.tag != tag_seq) return error.BadCertificate;
        var s = Children.of(b, seq);
        const ca = (try s.optional(0x01)) orelse return false;
        return ca.end - ca.start == 1 and b[ca.start] != 0;
    }
    return false;
}

/// UTCTime `YYMMDDHHMMSSZ` or GeneralizedTime `YYYYMMDDHHMMSSZ` as Unix seconds.
fn parseTime(b: []const u8, t: Tlv) Error!i64 {
    const s = t.content(b);
    const year: i64, const rest = switch (t.tag) {
        tag_utc => blk: {
            if (s.len != 13) return error.BadCertificate;
            const yy = try digits(s[0..2]);
            break :blk .{ if (yy >= 50) 1900 + yy else 2000 + yy, s[2..] };
        },
        tag_generalized => blk: {
            if (s.len != 15) return error.BadCertificate;
            break :blk .{ try digits(s[0..4]), s[4..] };
        },
        else => return error.BadCertificate,
    };
    if (rest[10] != 'Z') return error.BadCertificate;
    const month = try digits(rest[0..2]);
    const day = try digits(rest[2..4]);
    const hour = try digits(rest[4..6]);
    const minute = try digits(rest[6..8]);
    const second = try digits(rest[8..10]);
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 60) return error.BadCertificate;
    return daysFromCivil(year, @intCast(month), @intCast(day)) * 86400 + hour * 3600 + minute * 60 + second;
}

fn digits(s: []const u8) Error!i64 {
    var v: i64 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return error.BadCertificate;
        v = v * 10 + (ch - '0');
    }
    return v;
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn daysFromCivil(year: i64, month: u8, day: u8) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m: i64 = month;
    const doy = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// Largest RSA key accepted. Cisco's release certificate has an 8192-bit key, beyond std's
/// 4096-bit `Certificate.rsa`, so the public operation is done here with `std.crypto.ff`.
const max_rsa_bits = 8192;
const RsaModulus = std.crypto.ff.Modulus(max_rsa_bits);

/// RSASSA-PKCS1-v1_5 (RFC 8017 8.2.2) over the concatenation of `parts`.
fn rsaVerify(modulus: []const u8, exponent: []const u8, hash: HashAlg, signature: []const u8, parts: []const []const u8) Error!void {
    if (modulus.len < 256 or modulus.len > max_rsa_bits / 8) return error.UnsupportedSignature;
    if (signature.len != modulus.len or exponent.len == 0 or exponent.len > 4) return error.SignatureInvalid;
    const n = RsaModulus.fromBytes(modulus, .big) catch return error.BadCertificate;
    const s = RsaModulus.Fe.fromBytes(n, signature, .big) catch return error.SignatureInvalid;
    const m = n.powWithEncodedPublicExponent(s, exponent, .big) catch return error.SignatureInvalid;
    var em_buf: [max_rsa_bits / 8]u8 = undefined;
    const em = em_buf[0..modulus.len];
    m.toBytes(em, .big) catch return error.SignatureInvalid;

    // EM = 00 01 FF..FF 00 DigestInfo(hash) with at least eight FF bytes.
    var digest_buf: [64]u8 = undefined;
    const prefix: []const u8, const digest: []const u8 = switch (hash) {
        .sha256 => .{ &.{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 }, hashParts(Sha256, parts, &digest_buf) },
        .sha384 => .{ &.{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 }, hashParts(Sha384, parts, &digest_buf) },
        .sha512 => .{ &.{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 }, hashParts(Sha512, parts, &digest_buf) },
    };
    const t_len = prefix.len + digest.len;
    if (em.len < t_len + 11) return error.SignatureInvalid;
    const ps_end = em.len - t_len - 1;
    var bad: u8 = em[0] | (em[1] ^ 0x01) | em[ps_end];
    for (em[2..ps_end]) |byte| bad |= byte ^ 0xff;
    for (em[ps_end + 1 ..][0..prefix.len], prefix) |a, b| bad |= a ^ b;
    for (em[em.len - digest.len ..], digest) |a, b| bad |= a ^ b;
    if (bad != 0) return error.SignatureInvalid;
}

fn hashParts(comptime H: type, parts: []const []const u8, out: *[64]u8) []const u8 {
    var h = H.init(.{});
    for (parts) |part| h.update(part);
    h.final(out[0..H.digest_length]);
    return out[0..H.digest_length];
}

// ---------------------------------------------------------------------------------------------
// PKCS#7 SignedData
// ---------------------------------------------------------------------------------------------

/// Verify one decoded DER PKCS#7 envelope (the data of a `pkcs7-pem` line).
pub fn verifyPkcs7(b: []const u8, file_digest: *const [32]u8, pin: *const Pin) Error!void {
    const content_info = try tlv(b, 0, b.len);
    if (content_info.tag != tag_seq or content_info.end != b.len) return error.BadPkcs7;
    var ci = Children.of(b, content_info);
    if (!std.mem.eql(u8, (try ci.expect(tag_oid)).content(b), &oid_signed_data)) return error.BadPkcs7;
    var explicit = Children.of(b, try ci.expect(tag_ctx0));
    var sd = Children.of(b, try explicit.expect(tag_seq));
    _ = try sd.expect(tag_int); // version
    _ = try sd.expect(tag_set); // digest algorithms
    var encap = Children.of(b, try sd.expect(tag_seq));
    if (!std.mem.eql(u8, (try encap.expect(tag_oid)).content(b), &oid_data)) return error.BadPkcs7;
    // Detached: the signed content is the CVD file, not inside the envelope.
    if (try encap.next() != null) return error.BadPkcs7;

    var certs: [max_certs]Cert = undefined;
    var cert_count: usize = 0;
    if (try sd.optional(tag_ctx0)) |set| {
        var cs = Children.of(b, set);
        while (try cs.next()) |cert| {
            if (cert_count == max_certs) return error.BadPkcs7;
            certs[cert_count] = try parseCert(b, cert);
            cert_count += 1;
        }
    }
    _ = try sd.optional(tag_ctx1); // CRLs
    const signer_infos = try sd.expect(tag_set);
    var signers = Children.of(b, signer_infos);
    const signer = try signers.expect(tag_seq);
    if (try signers.next() != null) return error.BadPkcs7;

    var si = Children.of(b, signer);
    _ = try si.expect(tag_int);
    var sid = Children.of(b, try si.expect(tag_seq));
    const sid_issuer = (try sid.expect(tag_seq)).whole(b);
    const sid_serial = (try sid.expect(tag_int)).content(b);
    const digest_alg = digestOid(try algorithm(b, (try si.next()) orelse return error.BadPkcs7)) orelse return error.UnsupportedSignature;
    const attrs = (try si.optional(tag_ctx0)) orelse return error.BadPkcs7;
    const sig_alg_oid = try algorithm(b, (try si.next()) orelse return error.BadPkcs7);
    const signature = (try si.expect(tag_octets)).content(b);
    const sig_hash: HashAlg = if (std.mem.eql(u8, sig_alg_oid, &oid_rsa)) digest_alg else signatureOid(sig_alg_oid) orelse return error.UnsupportedSignature;

    // Signed attributes: content type data, the file's digest, and a signing time.
    var content_type_ok = false;
    var digest: ?[]const u8 = null;
    var signing_time: ?i64 = null;
    var as = Children.of(b, attrs);
    while (try as.next()) |attr| {
        if (attr.tag != tag_seq) return error.BadPkcs7;
        var a = Children.of(b, attr);
        const oid = (try a.expect(tag_oid)).content(b);
        var values = Children.of(b, try a.expect(tag_set));
        const value = (try values.next()) orelse return error.BadPkcs7;
        if (std.mem.eql(u8, oid, &oid_content_type)) {
            content_type_ok = value.tag == tag_oid and std.mem.eql(u8, value.content(b), &oid_data);
        } else if (std.mem.eql(u8, oid, &oid_message_digest)) {
            if (value.tag != tag_octets) return error.BadPkcs7;
            digest = value.content(b);
        } else if (std.mem.eql(u8, oid, &oid_signing_time)) {
            signing_time = parseTime(b, value) catch return error.BadPkcs7;
        }
    }
    if (!content_type_ok) return error.BadPkcs7;
    const claimed = digest orelse return error.BadPkcs7;
    if (digest_alg != .sha256) return error.UnsupportedSignature;
    if (!std.mem.eql(u8, claimed, file_digest)) return error.DigestMismatch;
    const when = signing_time orelse return error.BadPkcs7;

    // The signer's certificate, then its signature over the DER SET OF the attributes (the
    // implicit [0] tag replaced by SET).
    const leaf = for (certs[0..cert_count]) |*c| {
        if (std.mem.eql(u8, c.issuer, sid_issuer) and std.mem.eql(u8, c.serial, sid_serial)) break c;
    } else return error.UntrustedChain;
    try rsaVerify(leaf.modulus, leaf.exponent, sig_hash, signature, &.{ &.{tag_set}, b[attrs.head + 1 .. attrs.end] });

    // The chain up to the pinned root.
    var current = leaf;
    for (0..max_chain) |_| {
        if (when < current.not_before or when > current.not_after) return error.CertificateNotValid;
        if (pinned(current, pin)) return;
        const issuer = for (certs[0..cert_count]) |*c| {
            if (c != current and std.mem.eql(u8, c.subject, current.issuer)) break c;
        } else return error.UntrustedChain;
        // The pinned root is trusted as it is; any other issuer must say it is a CA.
        if (!issuer.is_ca and !pinned(issuer, pin)) return error.UntrustedChain;
        try rsaVerify(issuer.modulus, issuer.exponent, current.sig_hash, current.signature, &.{current.tbs});
        current = issuer;
    }
    return error.UntrustedChain;
}

fn pinned(cert: *const Cert, pin: *const Pin) bool {
    var spki_hash: [32]u8 = undefined;
    Sha256.hash(cert.spki, &spki_hash, .{});
    return std.mem.eql(u8, &spki_hash, pin);
}

// ---------------------------------------------------------------------------------------------
// Tests: a TEST-ONLY chain made by fixtures/make-sign.sh signs fixtures/test.cvd.
// ---------------------------------------------------------------------------------------------

pub const fixture_sign = @embedFile("fixtures/test.cvd.sign");
pub const fixture_pin: Pin = hexPin(std.mem.trim(u8, @embedFile("fixtures/test-root.pin"), " \r\n"));

fn fixtureDigest() [32]u8 {
    var d: [32]u8 = undefined;
    Sha256.hash(@import("cvd.zig").fixture_cvd, &d, .{});
    return d;
}

test "the fixture signature verifies against its pinned root" {
    const digest = fixtureDigest();
    try verify(std.testing.allocator, fixture_sign, &digest, &fixture_pin);
}

test "a different file, root or a flipped byte is refused" {
    const gpa = std.testing.allocator;
    var digest = fixtureDigest();
    try std.testing.expectError(error.UntrustedChain, verify(gpa, fixture_sign, &digest, &cisco_root_pin));
    digest[0] ^= 1;
    try std.testing.expectError(error.DigestMismatch, verify(gpa, fixture_sign, &digest, &fixture_pin));
    digest[0] ^= 1;

    // Flip bits in the DER: whatever it hits, the result is an error, never a pass or a crash.
    const line_start = std.mem.indexOf(u8, fixture_sign, "pkcs7-pem:").? + "pkcs7-pem:".len;
    const line_end = std.mem.indexOfAnyPos(u8, fixture_sign, line_start, "\r\n").?;
    const decoder = std.base64.standard.Decoder;
    const der = try gpa.alloc(u8, try decoder.calcSizeForSlice(fixture_sign[line_start..line_end]));
    defer gpa.free(der);
    try decoder.decode(der, fixture_sign[line_start..line_end]);
    var passes: usize = 0;
    var i: usize = 0;
    while (i < der.len) : (i += 7) {
        der[i] ^= 0x01;
        if (verifyPkcs7(der, &digest, &fixture_pin)) |_| passes += 1 else |_| {}
        der[i] ^= 0x01;
    }
    // Flips inside unsigned, unchecked fields (S/MIME capabilities, certificate extensions the
    // chain check does not read, serial padding) may still verify; signed bytes never do.
    try std.testing.expect(passes < der.len / 7 / 4);
    try verifyPkcs7(der, &digest, &fixture_pin);

    try std.testing.expectError(error.BadSignFile, verify(gpa, "not a sign file\n", &digest, &fixture_pin));
    try std.testing.expectError(error.NoSignature, verify(gpa, "#clamsign-1.0\n230::other:abc\n", &digest, &fixture_pin));
    try std.testing.expectError(error.BadSignFile, verify(gpa, "#clamsign-1.0\n230::pkcs7-pem:!!!\n", &digest, &fixture_pin));
}

test "truncated DER never reads past the buffer" {
    const gpa = std.testing.allocator;
    const digest = fixtureDigest();
    const line_start = std.mem.indexOf(u8, fixture_sign, "pkcs7-pem:").? + "pkcs7-pem:".len;
    const line_end = std.mem.indexOfAnyPos(u8, fixture_sign, line_start, "\r\n").?;
    const decoder = std.base64.standard.Decoder;
    const der = try gpa.alloc(u8, try decoder.calcSizeForSlice(fixture_sign[line_start..line_end]));
    defer gpa.free(der);
    try decoder.decode(der, fixture_sign[line_start..line_end]);
    var n: usize = 0;
    while (n < der.len) : (n += 13) try std.testing.expect(std.meta.isError(verifyPkcs7(der[0..n], &digest, &fixture_pin)));
}

test "times" {
    try std.testing.expectEqual(@as(i64, 0), daysFromCivil(1970, 1, 1));
    try std.testing.expectEqual(@as(i64, 19723), daysFromCivil(2024, 1, 1));
    const b = "\x17\x0d251216231901Z";
    try std.testing.expectEqual(@as(i64, 1765927141), try parseTime(b, try tlv(b, 0, b.len)));
}
