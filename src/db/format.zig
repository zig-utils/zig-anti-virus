//! The `.zavdb` on-disk layout (docs/DESIGN.md section 3).
//!
//! Every record is an `extern struct` with comptime size and offset asserts. All integers are
//! little-endian (big-endian hosts are refused at compile time), and every reference is an offset,
//! never a pointer, so a mapping is used in place without relocation and is never written.
const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.cpu.arch.endian() != .little) @compileError("zav databases are little-endian; big-endian hosts are not supported");
}

pub const magic = "ZAVDB\x00\r\n".*;
pub const format_major: u16 = 1;
pub const format_minor: u16 = 0;
pub const header_size: u32 = 4096;
pub const section_table_offset: u32 = 512;
pub const max_sections: u32 = (header_size - section_table_offset) / @sizeOf(SectionEntry);
/// The hot region starts on a 2 MiB boundary so large-page mappings are possible.
pub const hot_alignment: u64 = 2 * 1024 * 1024;
/// Every other section is at least page aligned.
pub const min_section_alignment_log2: u8 = 12;
/// Bytes of the header covered by the signature: everything before the signature itself.
pub const signed_len = @offsetOf(Header, "signature");

/// Versions of the inputs a database was compiled from, for `zav info` and update decisions.
pub const Sources = extern struct {
    clamav_main: u32 = 0,
    clamav_daily: u32 = 0,
    clamav_bytecode: u32 = 0,
    yara_set: u32 = 0,
    malwarebazaar: u64 = 0,
    guardian_rules: u32 = 0,
    engine_flevel: u16 = 0,
    _pad: [34]u8 = @splat(0),
};

/// The first 512 bytes of a database. The section table follows at `section_table_offset`.
pub const Header = extern struct {
    magic: [8]u8 = magic,
    format_major: u16 = format_major,
    format_minor: u16 = format_minor,
    header_size: u32 = header_size,
    /// Engine features a reader must support to use this database.
    feature_flags: u64 = 0,
    /// Monotonic, assigned by the compiler.
    db_version: u64 = 0,
    build_unix_time: u64 = 0,
    total_size: u64 = 0,
    section_count: u32 = 0,
    section_table_offset: u32 = section_table_offset,
    sources: Sources = .{},
    /// xxh3-64 of the section table, so the signature covers every section's hash and bounds.
    section_table_xxh3: u64 = 0,
    _reserved: [128]u8 = @splat(0),
    /// BLAKE3 over every byte from `header_size` to `total_size`, checked once at install.
    blake3_root: [32]u8 = @splat(0),
    /// First 8 bytes of BLAKE3(public key); all zero for an unsigned database.
    key_id: [8]u8 = @splat(0),
    /// Ed25519 over the first `signed_len` bytes.
    signature: [64]u8 = @splat(0),
    _tail: [152]u8 = @splat(0),
};

pub const SectionKind = enum(u32) {
    hash_need_map = 1,
    prefilter = 2,
    atom_table = 3,
    anchored_index = 4,
    ftm_trie = 5,
    hash_hot = 6,
    subsig_prog = 7,
    literal_pool = 8,
    ldb_table = 9,
    cdb_table = 10,
    sigmeta = 11,
    hash_cold = 12,
    fp_tables = 13,
    name_pool = 14,
    regex_pool = 15,
    yara_cond = 16,
    delta_index = 17,
    coverage_report = 18,
    _,
};

pub const SectionFlags = packed struct(u16) {
    hot: bool = false,
    _: u15 = 0,
};

pub const SectionEntry = extern struct {
    kind: SectionKind,
    variant: u16 = 0,
    flags: SectionFlags = .{},
    offset: u64,
    size: u64,
    xxh3: u64,
    align_log2: u8 = min_section_alignment_log2,
    partition: u8 = 0,
    _pad: [30]u8 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(Sources) == 64);
    std.debug.assert(@sizeOf(Header) == 512);
    std.debug.assert(@offsetOf(Header, "format_major") == 8);
    std.debug.assert(@offsetOf(Header, "feature_flags") == 16);
    std.debug.assert(@offsetOf(Header, "total_size") == 40);
    std.debug.assert(@offsetOf(Header, "section_count") == 48);
    std.debug.assert(@offsetOf(Header, "sources") == 56);
    std.debug.assert(@offsetOf(Header, "section_table_xxh3") == 120);
    std.debug.assert(@offsetOf(Header, "blake3_root") == 256);
    std.debug.assert(@offsetOf(Header, "key_id") == 288);
    std.debug.assert(@offsetOf(Header, "signature") == 296);
    std.debug.assert(@sizeOf(SectionEntry) == 64);
    std.debug.assert(@alignOf(SectionEntry) == 8);
}

/// Identifier for a signing key: the first 8 bytes of its BLAKE3 hash.
pub fn keyId(public_key: [32]u8) [8]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&public_key, &out, .{});
    return out[0..8].*;
}

pub fn xxh3(bytes: []const u8) u64 {
    return std.hash.XxHash3.hash(0, bytes);
}
