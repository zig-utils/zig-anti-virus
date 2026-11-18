//! Opens a `.zavdb` with a raw read-only mapping and validates it.
//!
//! Opening never reads the body: it checks the header, the section table and the signature, so
//! startup costs microseconds and the signatures stay clean, file-backed pages (no private memory).
//! The full BLAKE3 check over the body runs once at install time (`verifyFull`), and its result is
//! recorded in a sidecar so later opens of the same file skip it.
//!
//! `std.Io.File.MemoryMap` is deliberately not used: when mmap fails it falls back to allocating
//! and reading the whole file, which would turn the database into private memory. A failed mmap
//! is an error here.
const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const format = @import("format.zig");
const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{
    TooSmall,
    BadMagic,
    UnsupportedVersion,
    BadHeader,
    SizeMismatch,
    BadSectionTable,
    SectionOutOfBounds,
    SectionsOverlap,
    UnknownKey,
    BadSignature,
    Unsigned,
    RootMismatch,
    SectionHashMismatch,
};

pub const TrustedKey = struct { public_key: [32]u8 };

pub const OpenOptions = struct {
    /// Keys whose signatures are accepted.
    trusted_keys: []const TrustedKey = &.{},
    /// Accept a database with no signature (local development only).
    allow_unsigned: bool = false,
};

pub const Database = struct {
    mapping: []align(std.heap.page_size_min) const u8,

    pub fn header(db: Database) *const format.Header {
        return @ptrCast(db.mapping.ptr);
    }

    pub fn sections(db: Database) []const format.SectionEntry {
        const table: [*]const format.SectionEntry = @ptrCast(@alignCast(db.mapping.ptr + format.section_table_offset));
        return table[0..db.header().section_count];
    }

    /// The bytes of the first section of `kind` and `variant`, if present.
    pub fn section(db: Database, kind: format.SectionKind, variant: u16) ?[]const u8 {
        for (db.sections()) |s| {
            if (s.kind == kind and s.variant == variant) return db.mapping[s.offset..][0..s.size];
        }
        return null;
    }

    pub fn close(db: Database) void {
        posix.munmap(db.mapping);
    }
};

/// Check a header block and section table that `bytes` (the whole file) starts with.
pub fn validate(bytes: []const u8, options: OpenOptions) Error!void {
    if (bytes.len < format.header_size) return error.TooSmall;
    const h: *const format.Header = @ptrCast(@alignCast(bytes.ptr));
    if (!std.mem.eql(u8, &h.magic, &format.magic)) return error.BadMagic;
    if (h.format_major != format.format_major) return error.UnsupportedVersion;
    if (h.header_size != format.header_size or h.section_table_offset != format.section_table_offset) return error.BadHeader;
    if (h.total_size != bytes.len) return error.SizeMismatch;
    if (h.section_count > format.max_sections) return error.BadSectionTable;

    // The signature covers the header including the section table's hash, so check it first.
    const zero_id: [8]u8 = @splat(0);
    if (std.mem.eql(u8, &h.key_id, &zero_id)) {
        if (!options.allow_unsigned) return error.Unsigned;
    } else {
        const key = for (options.trusted_keys) |k| {
            if (std.mem.eql(u8, &format.keyId(k.public_key), &h.key_id)) break k;
        } else return error.UnknownKey;
        const pk = Ed25519.PublicKey.fromBytes(key.public_key) catch return error.UnknownKey;
        const sig = Ed25519.Signature.fromBytes(h.signature);
        sig.verify(bytes[0..format.signed_len], pk) catch return error.BadSignature;
    }

    const table_bytes = bytes[format.section_table_offset..][0 .. h.section_count * @sizeOf(format.SectionEntry)];
    if (format.xxh3(table_bytes) != h.section_table_xxh3) return error.BadSectionTable;

    const table: [*]const format.SectionEntry = @ptrCast(@alignCast(bytes.ptr + format.section_table_offset));
    const entries = table[0..h.section_count];
    for (entries, 0..) |s, i| {
        if (s.offset < format.header_size or s.offset > bytes.len or s.size > bytes.len - s.offset) return error.SectionOutOfBounds;
        if (s.align_log2 < format.min_section_alignment_log2 or s.align_log2 > 30) return error.BadSectionTable;
        if (s.offset & ((@as(u64, 1) << @intCast(s.align_log2)) - 1) != 0) return error.BadSectionTable;
        for (entries[i + 1 ..]) |other| {
            if (s.offset < other.offset + other.size and other.offset < s.offset + s.size) return error.SectionsOverlap;
        }
    }
}

/// The checks `validate` leaves for install time: BLAKE3 over the body and every section's xxh3.
pub fn verifyBody(bytes: []const u8) Error!void {
    const h: *const format.Header = @ptrCast(@alignCast(bytes.ptr));
    var root: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes[format.header_size..], &root, .{});
    if (!std.mem.eql(u8, &root, &h.blake3_root)) return error.RootMismatch;
    const table: [*]const format.SectionEntry = @ptrCast(@alignCast(bytes.ptr + format.section_table_offset));
    for (table[0..h.section_count]) |s| {
        if (format.xxh3(bytes[s.offset..][0..s.size]) != s.xxh3) return error.SectionHashMismatch;
    }
}

/// Map and validate a database. The mapping is read-only and private; nothing in it is written.
pub fn open(io: Io, dir: Io.Dir, sub_path: []const u8, options: OpenOptions) !Database {
    const file = try dir.openFile(io, sub_path, .{});
    defer file.close(io);
    const st = try file.stat(io);
    if (st.size < format.header_size) return error.TooSmall;
    const mapping = try posix.mmap(null, @intCast(st.size), .{ .READ = true }, .{ .TYPE = .PRIVATE }, file.handle, 0);
    errdefer posix.munmap(mapping);
    try validate(mapping, options);
    return .{ .mapping = mapping };
}

/// Identity of a file version for the sidecar: a changed file never matches an old record.
pub const FileStamp = extern struct {
    inode: u64,
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
    blake3_root: [32]u8,

    fn of(st: Io.File.Stat, root: [32]u8) FileStamp {
        return .{
            .inode = @intCast(st.inode),
            .size = st.size,
            .mtime_ns = @intCast(st.mtime.nanoseconds),
            .ctime_ns = @intCast(st.ctime.nanoseconds),
            .blake3_root = root,
        };
    }
};

/// Run the install-time body check once per file version, remembering success in
/// `<sub_path>.verified`. Returns whether the full check ran (false: the sidecar vouched for it).
pub fn verifyOnce(io: Io, dir: Io.Dir, sub_path: []const u8, db: Database) !bool {
    const file = try dir.openFile(io, sub_path, .{});
    const st = blk: {
        defer file.close(io);
        break :blk try file.stat(io);
    };
    const stamp = FileStamp.of(st, db.header().blake3_root);

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sidecar = try std.fmt.bufPrint(&path_buf, "{s}.verified", .{sub_path});
    var recorded: FileStamp = undefined;
    if (dir.readFile(io, sidecar, std.mem.asBytes(&recorded))) |got| {
        if (got.len == @sizeOf(FileStamp) and std.meta.eql(recorded, stamp)) return false;
    } else |_| {}

    try verifyBody(db.mapping);
    try dir.writeFile(io, .{ .sub_path = sidecar, .data = std.mem.asBytes(&stamp) });
    return true;
}
