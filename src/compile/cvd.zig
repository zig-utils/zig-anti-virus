//! ClamAV CVD and CLD containers: header parsing, verification and member iteration.
//!
//! A container is a 512-byte ASCII header of colon-separated fields followed by a tar archive,
//! gzip-compressed unless its first member is the uncompressed `COPYING` file. Inside are a
//! `.info` file listing `name:size:sha256` for every database member, and the members.
//!
//! Verification, in the order it happens (nothing is parsed before the container is trusted):
//! 1. The header's MD5 field must equal the MD5 of every byte after the header.
//! 2. For a CVD, the digital signature field must verify against Talos's public key: the field is
//!    a base-64 number (alphabet a-z, A-Z, 0-9, `+`, `/`, least significant digit first) whose RSA
//!    public operation yields the 16 MD5 bytes. A CLD (a CVD patched locally) carries no usable
//!    signature and is refused unless the caller explicitly allows unverified input.
//! 3. While walking, the `.info` header must agree with the container header, and every member
//!    must be listed in `.info` with matching size and SHA-256. Members that appear before the
//!    `.info`, names with a path separator, and non-regular entries are refused.
//!
//! The format is implemented from ClamAV's documentation and observed behaviour, not from its code.
const std = @import("std");
const Io = std.Io;
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;
const cvd_sign = @import("cvd_sign.zig");

pub const header_len = 512;
pub const max_info_len = 1024 * 1024;
const magic = "ClamAV-VDB";

pub const Error = error{
    Truncated,
    BadMagic,
    MissingField,
    BadNumber,
    Md5Mismatch,
    MissingSignature,
    BadSignature,
    Unverified,
    InfoMismatch,
    InfoTooLarge,
    BadInfoLine,
    MemberBeforeInfo,
    UnlistedMember,
    MemberSizeMismatch,
    MemberHashMismatch,
    MissingMember,
    BadMemberName,
    UnsupportedEntry,
    DuplicateInfo,
};

/// Parsed header fields. Slices borrow the 512 bytes the header was parsed from.
pub const Header = struct {
    build_time: []const u8,
    version: u32,
    signatures: u32,
    functionality_level: u32,
    /// Lowercase hex MD5 of the body, when the field is a 32-character value.
    md5: ?*const [32]u8,
    /// Encoded digital signature, when the field is longer than one character.
    dsig: ?[]const u8,
    builder: []const u8,
    /// Build time in seconds; 0 for old containers that omit it.
    build_seconds: u64,
};

/// Parse a container header (the first 512 bytes, or a `.info` first line).
pub fn parseHeader(raw: []const u8) Error!Header {
    var text = raw;
    if (std.mem.indexOfAny(u8, text, "\r\n")) |end| text = text[0..end];
    text = std.mem.trimEnd(u8, text, " \x00\t");

    var fields = std.mem.splitScalar(u8, text, ':');
    if (!std.mem.eql(u8, fields.next() orelse return error.MissingField, magic)) return error.BadMagic;
    const build_time = fields.next() orelse return error.MissingField;
    const version = try number(u32, fields.next());
    const signatures = try number(u32, fields.next());
    const flevel = try number(u32, fields.next());
    const md5_field = fields.next() orelse return error.MissingField;
    const dsig_field = fields.next() orelse return error.MissingField;
    const builder = fields.next() orelse return error.MissingField;
    const seconds_field = fields.next();

    return .{
        .build_time = build_time,
        .version = version,
        .signatures = signatures,
        .functionality_level = flevel,
        .md5 = if (md5_field.len == 32) md5_field[0..32] else null,
        .dsig = if (dsig_field.len > 1) dsig_field else null,
        .builder = builder,
        .build_seconds = if (seconds_field) |s| try number(u64, s) else 0,
    };
}

fn number(comptime T: type, field: ?[]const u8) Error!T {
    const text = std.mem.trim(u8, field orelse return error.MissingField, " ");
    return std.fmt.parseInt(T, text, 10) catch error.BadNumber;
}

/// An RSA public key, big-endian magnitudes.
pub const PublicKey = struct {
    modulus: []const u8,
    exponent: []const u8,
};

/// Talos's legacy database signing key (1024-bit modulus, decimal exponent 100001027).
pub const talos_key: PublicKey = .{
    .modulus = &hexBytes(
        "a8f34c7b2bae902e1e608cfcec44c024375370c09cd460e1917a98546ddfc53a" ++
            "90c608bb48ba8cb7eed1ff342085ecdd1491428ca8a895972403a3db2a452dd8" ++
            "0173bb07e1e23acbc84fab2e2586930f62909d56d2e25256c989d399fa722ab2" ++
            "5ab628df79bcfce43b86a0e049263171352b75048f2d4778b69a5e574a6130ad",
    ),
    .exponent = &hexBytes("05f5e503"),
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const max_key_bits = 4096;
const Modulus = std.crypto.ff.Modulus(max_key_bits);

/// Decode ClamAV's signature encoding into a big-endian magnitude of `out.len` bytes.
pub fn decodeSignature(encoded: []const u8, out: []u8) Error!void {
    @memset(out, 0);
    var i = encoded.len;
    while (i > 0) {
        i -= 1;
        const digit: u32 = switch (encoded[i]) {
            'a'...'z' => |c| c - 'a',
            'A'...'Z' => |c| c - 'A' + 26,
            '0'...'9' => |c| c - '0' + 52,
            '+' => 62,
            '/' => 63,
            else => return error.BadSignature,
        };
        // out = out * 64 + digit, most significant byte first.
        var carry: u32 = digit;
        var j = out.len;
        while (j > 0) {
            j -= 1;
            const v = @as(u32, out[j]) * 64 + carry;
            out[j] = @truncate(v);
            carry = v >> 8;
        }
        if (carry != 0) return error.BadSignature;
    }
}

/// Verify a legacy signature: the RSA public operation on the decoded value must yield the MD5.
pub fn verifySignature(key: PublicKey, md5_hex: *const [32]u8, encoded: []const u8) Error!void {
    var expected: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, md5_hex) catch return error.BadSignature;

    const m = Modulus.fromBytes(key.modulus, .big) catch return error.BadSignature;
    var sig_buf: [max_key_bits / 8]u8 = undefined;
    const sig = sig_buf[0..key.modulus.len];
    try decodeSignature(encoded, sig);
    const s = Modulus.Fe.fromBytes(m, sig, .big) catch return error.BadSignature;
    const r = m.powWithEncodedPublicExponent(s, key.exponent, .big) catch return error.BadSignature;
    var out_buf: [max_key_bits / 8]u8 = undefined;
    const out = out_buf[0..key.modulus.len];
    r.toBytes(out, .big) catch return error.BadSignature;
    for (out[0 .. out.len - 16]) |b| if (b != 0) return error.BadSignature;
    if (!std.mem.eql(u8, out[out.len - 16 ..], &expected)) return error.BadSignature;
}

pub const Kind = enum { cvd, cld };

pub const VerifyOptions = struct {
    kind: Kind = .cvd,
    key: PublicKey = talos_key,
    /// Accept a container whose signature cannot be checked (CLD, or a local test build).
    allow_unverified: bool = false,
    /// The detached `.sign` file published next to the CVD, when there is one (`verifyFile`
    /// only). It must verify; a CVD without a legacy header signature needs it.
    sign: ?[]const u8 = null,
    sign_pin: cvd_sign.Pin = cvd_sign.cisco_root_pin,
};

/// `verify` for a container on disk, plus the detached signature: reads the header into
/// `header_buf`, then MD5 over the body and SHA-256 over the whole file in one pass.
pub fn verifyFile(gpa: std.mem.Allocator, io: Io, file: Io.File, header_buf: *[header_len]u8, options: VerifyOptions) !Header {
    if (try file.readPositionalAll(io, header_buf, 0) != header_len) return error.Truncated;
    const header = try parseHeader(header_buf);
    var buf: [64 * 1024]u8 = undefined;
    var r = file.reader(io, &buf);
    try r.seekTo(header_len);
    var md5 = Md5.init(.{});
    var sha = Sha256.init(.{});
    sha.update(header_buf);
    while (true) {
        const chunk = r.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        md5.update(chunk);
        sha.update(chunk);
        r.interface.toss(chunk.len);
    }
    var digest: [16]u8 = undefined;
    md5.final(&digest);
    var file_digest: [32]u8 = undefined;
    sha.final(&file_digest);

    var opts = options;
    if (options.sign) |text| {
        cvd_sign.verify(gpa, text, &file_digest, &options.sign_pin) catch |err| {
            if (!options.allow_unverified) return err;
        };
        // A verified detached signature stands in for a missing legacy one.
        if (header.dsig == null) opts.allow_unverified = true;
    }
    try checkMd5(header, &std.fmt.bytesToHex(digest, .lower), opts);
    return header;
}

/// The detached signature for the container at `sub_path`: `<stem>-<version>.cvd.sign` (the
/// name ClamAV's mirrors and cvdupdate use) or `<sub_path>.sign`, or null when neither exists.
pub fn readSignFile(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, sub_path: []const u8, version: u32) !?[]u8 {
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    const stem = std.fs.path.stem(sub_path);
    const parent = std.fs.path.dirname(sub_path);
    const versioned = if (parent) |p|
        try std.fmt.bufPrint(&name_buf, "{s}/{s}-{d}.cvd.sign", .{ p, stem, version })
    else
        try std.fmt.bufPrint(&name_buf, "{s}-{d}.cvd.sign", .{ stem, version });
    var plain_buf: [std.fs.max_path_bytes]u8 = undefined;
    const plain = try std.fmt.bufPrint(&plain_buf, "{s}.sign", .{sub_path});
    for ([_][]const u8{ versioned, plain }) |candidate| {
        return dir.readFileAlloc(io, candidate, gpa, .limited(cvd_sign.max_sign_file)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
    }
    return null;
}

/// Check the header against the body: MD5 always, the digital signature for a CVD.
/// `body` is consumed to its end.
pub fn verify(header: Header, body: *Io.Reader, options: VerifyOptions) (Error || Io.Reader.Error)!void {
    var md5 = Md5.init(.{});
    while (true) {
        const chunk = body.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        md5.update(chunk);
        body.toss(chunk.len);
    }
    var digest: [16]u8 = undefined;
    md5.final(&digest);
    return checkMd5(header, &std.fmt.bytesToHex(digest, .lower), options);
}

/// The checks after the body's MD5 is known: the header's MD5 field, then the legacy signature.
fn checkMd5(header: Header, hex: *const [32]u8, options: VerifyOptions) Error!void {
    if (header.md5) |declared| {
        if (!std.mem.eql(u8, declared, hex)) return error.Md5Mismatch;
    } else if (!options.allow_unverified) return error.Unverified;

    if (options.kind == .cld or header.dsig == null) {
        if (!options.allow_unverified) return if (header.dsig == null) error.MissingSignature else error.Unverified;
        return;
    }
    verifySignature(options.key, hex, header.dsig.?) catch |err| {
        if (options.allow_unverified) return;
        return err;
    };
}

/// One `.info` line.
pub const InfoEntry = struct {
    name: []const u8,
    size: u64,
    sha256: [32]u8,
    seen: bool = false,
};

pub const Info = struct {
    header: Header,
    entries: []InfoEntry,
    /// Whether the file carried a `DSIG:` line (checked by a later issue for CLD support).
    signed: bool,

    pub fn find(info: *Info, name: []const u8) ?*InfoEntry {
        for (info.entries) |*entry| if (std.mem.eql(u8, entry.name, name)) return entry;
        return null;
    }
};

/// Parse a `.info` file. Slices borrow `text`; `entries` is allocated with `gpa`.
pub fn parseInfo(gpa: std.mem.Allocator, text: []const u8) (Error || std.mem.Allocator.Error)!Info {
    var lines = std.mem.splitScalar(u8, text, '\n');
    const first = lines.next() orelse return error.BadInfoLine;
    const header = try parseHeader(first);
    var entries: std.ArrayList(InfoEntry) = .empty;
    errdefer entries.deinit(gpa);
    var signed = false;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r ");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "DSIG:")) {
            signed = true;
            continue;
        }
        var parts = std.mem.splitScalar(u8, line, ':');
        const name = parts.next() orelse return error.BadInfoLine;
        const size = std.fmt.parseInt(u64, parts.next() orelse return error.BadInfoLine, 10) catch return error.BadInfoLine;
        const hash_hex = parts.next() orelse return error.BadInfoLine;
        if (hash_hex.len != 64 or parts.next() != null) return error.BadInfoLine;
        var sha: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&sha, hash_hex) catch return error.BadInfoLine;
        try entries.append(gpa, .{ .name = name, .size = size, .sha256 = sha });
    }
    return .{ .header = header, .entries = try entries.toOwnedSlice(gpa), .signed = signed };
}

pub fn deinitInfo(gpa: std.mem.Allocator, info: *Info) void {
    gpa.free(info.entries);
}

/// Whether the body is an uncompressed tar (first member `COPYING`) or gzip.
pub fn isPlainTar(body_start: []const u8) bool {
    return std.mem.startsWith(u8, body_start, "COPYING");
}

pub const WalkOptions = struct {
    /// Require every member to be listed in a preceding `.info` with matching size and SHA-256.
    require_info: bool = true,
};

/// Walk the members of a verified container body, calling `visitor.member(name, size, reader)`
/// for each database file. `name` is only valid during the call. The reader is limited to the
/// member; whatever the visitor does not read is drained so its hash can be checked. `header`
/// must be the container's header.
pub fn walk(
    gpa: std.mem.Allocator,
    header: Header,
    body: *Io.Reader,
    options: WalkOptions,
    visitor: anytype,
) !void {
    const plain = isPlainTar(body.peek(7) catch |err| switch (err) {
        error.EndOfStream => return error.Truncated,
        else => |e| return e,
    });
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var inflate: std.compress.flate.Decompress = undefined;
    const tar_reader: *Io.Reader = if (plain) body else blk: {
        inflate = .init(body, .gzip, &window);
        break :blk &inflate.reader;
    };

    var name_buf: [256]u8 = undefined;
    var link_buf: [256]u8 = undefined;
    var it: std.tar.Iterator = .init(tar_reader, .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf });

    var info_text: ?[]u8 = null;
    defer if (info_text) |t| gpa.free(t);
    var info: ?Info = null;
    defer if (info) |*i| deinitInfo(gpa, i);

    while (try it.next()) |file| {
        if (file.kind != .file) return error.UnsupportedEntry;
        if (file.name.len == 0 or std.mem.indexOfAny(u8, file.name, "/\\") != null) return error.BadMemberName;
        if (std.mem.eql(u8, file.name, "COPYING")) continue;

        if (std.mem.endsWith(u8, file.name, ".info")) {
            if (info != null) return error.DuplicateInfo;
            if (file.size > max_info_len) return error.InfoTooLarge;
            const text = try gpa.alloc(u8, @intCast(file.size));
            info_text = text;
            try it.reader.readSliceAll(text);
            it.unread_file_bytes = 0;
            info = try parseInfo(gpa, text);
            const ih = info.?.header;
            if (ih.version != header.version or ih.signatures != header.signatures or
                ih.functionality_level != header.functionality_level or ih.build_seconds != header.build_seconds)
                return error.InfoMismatch;
            continue;
        }

        const entry: ?*InfoEntry = if (info) |*i| i.find(file.name) else null;
        if (options.require_info) {
            if (info == null) return error.MemberBeforeInfo;
            if (entry == null) return error.UnlistedMember;
            if (entry.?.size != file.size) return error.MemberSizeMismatch;
        }

        var limit_buf: [4096]u8 = undefined;
        var limited = it.reader.limited(.limited64(file.size), &limit_buf);
        var hash_buf: [4096]u8 = undefined;
        var hashed = limited.interface.hashed(Sha256.init(.{}), &hash_buf);
        try visitor.member(file.name, file.size, &hashed.reader);
        // Drain whatever the visitor left so the hash covers the whole member.
        _ = try hashed.reader.discardRemaining();
        it.unread_file_bytes = 0;
        if (limited.remaining != .nothing) return error.Truncated;
        if (entry) |e| {
            var digest: [32]u8 = undefined;
            hashed.hasher.final(&digest);
            if (!std.mem.eql(u8, &digest, &e.sha256)) return error.MemberHashMismatch;
            e.seen = true;
        }
    }

    if (options.require_info) {
        const i = info orelse return error.MemberBeforeInfo;
        for (i.entries) |e| if (!e.seen) return error.MissingMember;
    }
}

// Tests use synthetic containers made by src/compile/fixtures/make-cvd.ts and signed with a test-only key.
/// Small synthetic containers, public so fuzz targets can mutate them.
pub const fixture_cvd = @embedFile("fixtures/test.cvd");
pub const fixture_cld = @embedFile("fixtures/test.cld");
const test_key: PublicKey = .{
    .modulus = &hexBytes(
        "be9eec3a991d480553eb9c3c5c75a30a6a5125f236318b485863b9f16eb7a0c5" ++
            "1badc45a3832c2214c0a966bba91475586b652a445f9d38a286d9bdb231ad4d9" ++
            "0f4ef4d85be820182d2161789771cf5bf5fe851f461958d50c1665ada1938831" ++
            "bd2acd46713dd6c41d4f8eacd0cc9f15eae9d04c6d81a713e1893499812685a3",
    ),
    .exponent = &hexBytes("010001"),
};

/// A visitor that reads each member to its end, for fuzzing.
pub const Drain = struct {
    pub fn member(_: *Drain, _: []const u8, _: u64, reader: *Io.Reader) !void {
        _ = try reader.discardRemaining();
    }
};

const Collector = struct {
    name_store: [8][32]u8 = undefined,
    names: [8][]const u8 = undefined,
    sizes: [8]u64 = undefined,
    first_bytes: [8]u8 = undefined,
    count: usize = 0,

    fn member(self: *Collector, name: []const u8, size: u64, reader: *Io.Reader) !void {
        @memcpy(self.name_store[self.count][0..name.len], name);
        self.names[self.count] = self.name_store[self.count][0..name.len];
        self.sizes[self.count] = size;
        // Read only one byte; walk must drain the rest before checking the hash.
        self.first_bytes[self.count] = try reader.takeByte();
        self.count += 1;
    }
};

fn verifyBytes(bytes: []const u8, options: VerifyOptions) !Header {
    const header = try parseHeader(bytes[0..header_len]);
    var body: Io.Reader = .fixed(bytes[header_len..]);
    try verify(header, &body, options);
    return header;
}

test "parses the header fields" {
    const h = try parseHeader(fixture_cvd[0..header_len]);
    try std.testing.expectEqual(@as(u32, 7), h.version);
    try std.testing.expectEqual(@as(u32, 2), h.signatures);
    try std.testing.expectEqual(@as(u32, 90), h.functionality_level);
    try std.testing.expectEqual(@as(u64, 1700000000), h.build_seconds);
    try std.testing.expectEqualStrings("fixture", h.builder);
    try std.testing.expect(h.md5 != null and h.dsig != null);
}

test "a signed CVD verifies and walks every listed member" {
    const header = try verifyBytes(fixture_cvd, .{ .key = test_key });
    var body: Io.Reader = .fixed(fixture_cvd[header_len..]);
    var c: Collector = .{};
    try walk(std.testing.allocator, header, &body, .{}, &c);
    try std.testing.expectEqual(@as(usize, 2), c.count);
    try std.testing.expectEqualStrings("test.hdb", c.names[0]);
    try std.testing.expectEqualStrings("test2.hdb", c.names[1]);
    try std.testing.expectEqual(@as(u8, '4'), c.first_bytes[0]);
}

test "Talos's key does not accept a signature made with another key" {
    try std.testing.expectError(error.BadSignature, verifyBytes(fixture_cvd, .{}));
}

test "one flipped byte anywhere fails verification" {
    var copy: [fixture_cvd.len]u8 = fixture_cvd.*;
    var i: usize = header_len;
    while (i < copy.len) : (i += 97) {
        copy[i] ^= 0x01;
        try std.testing.expectError(error.Md5Mismatch, verifyBytes(&copy, .{ .key = test_key }));
        copy[i] ^= 0x01;
    }
    // A flipped signature digit fails the RSA check.
    const h = try parseHeader(copy[0..header_len]);
    const at = @intFromPtr(h.dsig.?.ptr) - @intFromPtr(&copy);
    copy[at] = if (copy[at] == 'a') 'b' else 'a';
    try std.testing.expectError(error.BadSignature, verifyBytes(&copy, .{ .key = test_key }));
}

test "a CLD is refused unless unverified input is allowed, then walks the plain tar" {
    try std.testing.expectError(error.MissingSignature, verifyBytes(fixture_cld, .{ .kind = .cld }));
    const header = try verifyBytes(fixture_cld, .{ .kind = .cld, .allow_unverified = true });
    var body: Io.Reader = .fixed(fixture_cld[header_len..]);
    try std.testing.expect(isPlainTar(fixture_cld[header_len..]));
    var c: Collector = .{};
    try walk(std.testing.allocator, header, &body, .{}, &c);
    try std.testing.expectEqual(@as(usize, 2), c.count);
}

test "a member whose content does not match .info is refused" {
    var copy: [fixture_cld.len]u8 = fixture_cld.*;
    const at = std.mem.indexOf(u8, &copy, "Eicar-Test-Signature").?;
    copy[at] = 'X';
    const header = try parseHeader(copy[0..header_len]);
    var body: Io.Reader = .fixed(copy[header_len..]);
    var c: Collector = .{};
    try std.testing.expectError(error.MemberHashMismatch, walk(std.testing.allocator, header, &body, .{}, &c));
}

test "rejects malformed headers" {
    try std.testing.expectError(error.BadMagic, parseHeader("ClamAV-XXX:a:1:2:3:x:y:z:4"));
    try std.testing.expectError(error.MissingField, parseHeader("ClamAV-VDB:a:1:2"));
    try std.testing.expectError(error.BadNumber, parseHeader("ClamAV-VDB:a:one:2:3:x:y:z:4"));
}

test "signature decoding is least-significant digit first" {
    var out: [2]u8 = undefined;
    try decodeSignature("b", &out); // 1
    try std.testing.expectEqualSlices(u8, &.{ 0, 1 }, &out);
    try decodeSignature("ab", &out); // 0 + 1*64
    try std.testing.expectEqualSlices(u8, &.{ 0, 64 }, &out);
    try std.testing.expectError(error.BadSignature, decodeSignature("!", &out));
    try std.testing.expectError(error.BadSignature, decodeSignature("////", &out)); // overflows 2 bytes
}

test "verifyFile checks the detached signature next to the container" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const compiler = @import("compiler.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "test.cvd", .data = fixture_cvd });
    const options: VerifyOptions = .{ .key = test_key, .sign_pin = cvd_sign.fixture_pin };
    var header_buf: [header_len]u8 = undefined;

    // No .sign file: the legacy signature is enough.
    {
        const file = try tmp.dir.openFile(io, "test.cvd", .{});
        defer file.close(io);
        _ = try compiler.verifyContainer(gpa, io, tmp.dir, "test.cvd", file, &header_buf, options);
    }
    // A valid one, found by the mirror's versioned name.
    const version = (try parseHeader(fixture_cvd[0..header_len])).version;
    var name_buf: [64]u8 = undefined;
    const sign_name = try std.fmt.bufPrint(&name_buf, "test-{d}.cvd.sign", .{version});
    try tmp.dir.writeFile(io, .{ .sub_path = sign_name, .data = cvd_sign.fixture_sign });
    {
        const file = try tmp.dir.openFile(io, "test.cvd", .{});
        defer file.close(io);
        _ = try compiler.verifyContainer(gpa, io, tmp.dir, "test.cvd", file, &header_buf, options);
        // The same file against Cisco's root: the chain is not trusted.
        try std.testing.expectError(error.UntrustedChain, compiler.verifyContainer(gpa, io, tmp.dir, "test.cvd", file, &header_buf, .{ .key = test_key }));
    }
    // The container changed after signing: the detached signature no longer matches.
    var changed: [fixture_cvd.len]u8 = fixture_cvd.*;
    changed[changed.len - 1] ^= 1;
    try tmp.dir.writeFile(io, .{ .sub_path = "test.cvd", .data = &changed });
    {
        const file = try tmp.dir.openFile(io, "test.cvd", .{});
        defer file.close(io);
        try std.testing.expectError(error.DigestMismatch, compiler.verifyContainer(gpa, io, tmp.dir, "test.cvd", file, &header_buf, options));
    }
}
