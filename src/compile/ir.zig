//! The compiler's rule representation. Parsers turn signature files into these; the layout pass
//! turns them into `.zavdb` sections. Names and digests borrow the source text, which the compiler
//! keeps alive for the whole compile.
const std = @import("std");

/// Where a rule came from, for the coverage report and `zav info`.
pub const Source = enum(u8) {
    hdb,
    hsb,
    mdb,
    msb,
    imp,
    malwarebazaar,
    guardian,
    ndb,
    ldb,
    cdb,
};

pub const HashAlgo = enum(u8) {
    md5,
    sha1,
    sha256,

    pub fn digestLen(algo: HashAlgo) usize {
        return switch (algo) {
            .md5 => 16,
            .sha1 => 20,
            .sha256 => 32,
        };
    }

    /// Hash type from the length of its hex string, as .hsb and .msb do.
    pub fn fromHexLen(len: usize) ?HashAlgo {
        return switch (len) {
            32 => .md5,
            40 => .sha1,
            64 => .sha256,
            else => null,
        };
    }
};

/// What a hash covers.
pub const HashScope = enum(u8) {
    /// The whole file.
    file,
    /// One PE section's raw data.
    pe_section,
    /// The PE import table.
    pe_import,
};

pub const Flags = packed struct(u8) {
    /// Potentially unwanted application (from a `u` database such as .hdu).
    pua: bool = false,
    _: u7 = 0,
};

pub const HashRule = struct {
    algo: HashAlgo,
    scope: HashScope,
    /// First `algo.digestLen()` bytes are meaningful.
    digest: [32]u8,
    /// Exact size of the hashed data, or null for any size (functionality level 73 and above).
    size: ?u64,
    name: []const u8,
    /// Functionality level range the rule needs; 0 means unbounded on that side.
    flevel_min: u16 = 0,
    flevel_max: u16 = 0,
    source: Source,
    flags: Flags = .{},
    /// The database line the rule came from, for `.ign2` entries that pin a line's MD5.
    line: []const u8 = "",

    pub fn digestBytes(rule: *const HashRule) []const u8 {
        return rule.digest[0..rule.algo.digestLen()];
    }
};

/// Why a line did not become a rule. Every rejection is counted in the coverage report.
pub const Reason = enum(u8) {
    field_count,
    bad_hash,
    bad_size,
    wildcard_needs_flevel_73,
    bad_flevel,
    empty_name,
    unsupported_database,
    ignored,
    flevel_out_of_range,
    bytecode,
    // Hex bodies (docs/DESIGN.md section 4.1).
    hex_empty,
    hex_odd_nibble,
    hex_bad_char,
    hex_bad_range,
    hex_bad_alternation,
    hex_bad_negation,
    hex_empty_part,
    hex_no_static_byte,
    hex_too_complex,
    bad_modifier,
    // Extended (.ndb) signatures.
    bad_target,
    bad_offset,
    offset_needs_executable,
    version_info_unsupported,
    // Logical (.ldb) signatures.
    bad_tdb,
    bad_expression,
    expr_true_without_hits,
    too_many_subsigs,
    unknown_file_type,
    pcre_needs_byte_mode,
    macro_unsupported,
    fuzzy_image_unsupported,
    icon_unsupported,
    handler_type_unsupported,
    byte_compare_unsupported,
};

pub const Rejection = struct {
    source_name: []const u8,
    line_number: u32,
    reason: Reason,
    /// Byte position inside the line where the rejected construct starts, when known.
    column: u32 = 0,
};

// ---------------------------------------------------------------------------------------------
// Hex-signature IR (docs/DESIGN.md sections 3.4 and 4.1).
//
// A body is a pattern: a flat list of fixed-size ops plus a data area the ops point into with
// u32 offsets. The same bytes are the compiler's model and the serialised SUBSIG_PROG program,
// so the verify VM runs exactly what the compiler built. Parts are separated by `part_end` ops
// that carry the gap window to the next part; everything inside a part has a bounded length.
// ---------------------------------------------------------------------------------------------

pub const OpCode = enum(u8) {
    /// `len` literal bytes at `data[a..]`.
    lit = 1,
    /// `len` bytes; values at `data[a..]`, masks at `data[a + len ..]`. A byte matches when
    /// `(byte & mask) == value`. With `op_negate` (only for `len == 1`) the byte must not match.
    masked = 2,
    /// One of `len` alternatives; table of `AltEntry` at `data[a..]`. `b` is
    /// `min_len | max_len << 16`. Alternatives hold only lit, masked and gapf ops.
    alt = 3,
    /// Any window of `b & 0xffff` bytes equal to none of the `len` literal alternatives.
    nalt = 4,
    /// Skip exactly `a` bytes (`{n}` with n below 128).
    gapf = 5,
    /// A character class (`Bound` in `flags`).
    bound = 6,
    /// End of a part: the next part starts `a` to `b` bytes later (`b == unbounded` for none).
    /// `flags` holds the `GapSyntax` it was written with, so printing round-trips.
    part_end = 7,
    _,
};

pub const Op = extern struct {
    code: OpCode,
    flags: u8 = 0,
    len: u16 = 0,
    a: u32 = 0,
    b: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Op) == 12);
    std.debug.assert(@alignOf(Op) == 4);
}

/// Op flag bit for lit and alt: compare ASCII letters case-insensitively.
pub const op_nocase: u8 = 1 << 0;
/// Op flag bit for a one-byte masked op written `~..`: the byte must not match.
pub const op_negate: u8 = 1 << 1;

/// One alternative of an alt or nalt op, in the data area.
pub const AltEntry = extern struct {
    /// Data offset of the alternative's ops (4-byte aligned).
    ops_off: u32,
    op_count: u16,
    /// Bytes the alternative consumes.
    byte_len: u16,
};

comptime {
    std.debug.assert(@sizeOf(AltEntry) == 8);
}

pub const Bound = enum(u8) {
    /// `(B)`: one non-alphanumeric byte, or nothing at the start or end of the data.
    word = 0,
    /// `(L)`: CR, LF or CRLF, or nothing at the start or end of the data.
    line = 1,
    /// `(W)`: one non-alphanumeric byte.
    nonalnum = 2,
};

/// How a part break was written.
pub const GapSyntax = enum(u8) {
    /// `*`
    star = 0,
    /// `{n-m}`
    range = 1,
    /// `{-n}`
    upto = 2,
    /// `{n-}`
    from = 3,
    /// `{n}` with n of 128 or more
    exact = 4,
    /// `[n-m]`
    bracket = 5,
};

pub const unbounded: u32 = std.math.maxInt(u32);
/// `{n}` below this stays inside its part as a fixed skip; from here on it splits the body.
pub const inline_gap_limit: u32 = 128;
/// Largest `y` in `[x-y]`.
pub const bracket_limit: u32 = 32;

pub const Pattern = struct {
    ops: []const Op,
    data: []align(4) const u8,

    pub fn alternatives(p: Pattern, op: Op) []const AltEntry {
        const table: [*]const AltEntry = @ptrCast(@alignCast(p.data.ptr + op.a));
        return table[0..op.len];
    }

    pub fn altOps(p: Pattern, entry: AltEntry) []const Op {
        const ops: [*]const Op = @ptrCast(@alignCast(p.data.ptr + entry.ops_off));
        return ops[0..entry.op_count];
    }

    pub fn bytes(p: Pattern, op: Op) []const u8 {
        return p.data[op.a..][0..op.len];
    }

    pub fn masks(p: Pattern, op: Op) []const u8 {
        return p.data[op.a + op.len ..][0..op.len];
    }

    pub fn partCount(p: Pattern) usize {
        var n: usize = 1;
        for (p.ops) |op| n += @intFromBool(op.code == .part_end);
        return n;
    }
};

/// Subsignature modifiers `::i ::w ::a ::f`.
pub const Modifiers = packed struct(u8) {
    nocase: bool = false,
    wide: bool = false,
    ascii: bool = false,
    fullword: bool = false,
    _: u4 = 0,
};

/// Where a match has to start, relative to the file (docs: ExtendedSignatures, Offset).
pub const OffsetKind = enum(u8) {
    /// `*`
    any = 0,
    /// `n`
    absolute = 1,
    /// `EOF-n` (`a` holds n)
    eof_minus = 2,
    /// `EP+n` / `EP-n`
    entry_point = 3,
    /// `Sx+n`
    section_start = 4,
    /// `SEx`: anywhere inside section x
    section_entire = 5,
    /// `SL+n`
    last_section = 6,
    _,
};

pub const Offset = struct {
    kind: OffsetKind = .any,
    a: i32 = 0,
    section: u16 = 0,
    /// The `,maxshift` window: the match may start anywhere in `[offset, offset + shift]`.
    shift: u32 = 0,
};

pub const Subsig = struct {
    pattern: Pattern,
    mods: Modifiers = .{},
    offset: Offset = .{},
};

/// An `.ndb` extended signature: one subsignature, a target type and a name.
pub const BodyRule = struct {
    name: []const u8,
    /// ClamAV target type, 0 to 14; also the partition.
    target: u8,
    subsig: Subsig,
    flevel_min: u16 = 0,
    flevel_max: u16 = 0,
    source: Source,
    flags: Flags = .{},
    line: []const u8 = "",
};

// ---------------------------------------------------------------------------------------------
// Logical signatures (docs/DESIGN.md section 3.4, LDB_TABLE).
// ---------------------------------------------------------------------------------------------

/// An inclusive range from a target description block (`FileSize:100-200`).
pub const Range = struct { lo: u64, hi: u64 };

pub const max_intermediates = 16;

/// The target description block: predicates checked once per file before any subsig counts.
pub const Tdb = struct {
    target: u8 = 0,
    file_size: ?Range = null,
    entry_point: ?Range = null,
    sections: ?Range = null,
    /// `Container:CL_TYPE_*` as a `fmt.types.ClType` value.
    container: ?u16 = null,
    /// `Intermediates:A>B>C`, outermost first.
    intermediates: [max_intermediates]u16 = @splat(0),
    intermediate_count: u8 = 0,
};

pub const RpnCode = enum(u8) {
    /// Push subsig `index`: its match count, its bit in the distinct mask, count > 0.
    sub = 1,
    /// Pop two, push the conjunction; counts add, masks join.
    @"and" = 2,
    /// Pop two, push the disjunction; counts add, masks join.
    @"or" = 3,
    /// Pop one; true when count == k (and, with `distinct`, at least that many subsigs matched).
    eq = 4,
    /// count > k
    gt = 5,
    /// count < k
    lt = 6,
    _,
};

pub const RpnOp = extern struct {
    code: RpnCode,
    /// For eq, gt and lt: required distinct matched subsigs (`A=X,Y`), 0 for none.
    distinct: u8 = 0,
    index: u16 = 0,
    k: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(RpnOp) == 8);
}

/// ClamAV allows at most 64 subsignatures per logical signature.
pub const max_subsigs = 64;
/// Deepest evaluation stack an expression may need.
pub const max_rpn_depth = 64;

pub const LogicalSubsig = union(enum) {
    hex: Subsig,
};

/// An `.ldb` logical signature.
pub const LogicalRule = struct {
    name: []const u8,
    tdb: Tdb,
    expr: []const RpnOp,
    subsigs: []const LogicalSubsig,
    flevel_min: u16 = 0,
    flevel_max: u16 = 0,
    source: Source = .ldb,
    flags: Flags = .{},
    line: []const u8 = "",
};

/// A ClamAV signature name split for compact storage: `Win.Trojan.Agent-1234567-0` becomes the
/// family `Win.Trojan.Agent`, number 1234567 and revision 0. Names without that shape keep the
/// whole name as the family.
pub const NameTokens = struct {
    family: []const u8,
    number: ?u32 = null,
    revision: ?u8 = null,

    pub fn parse(name: []const u8) NameTokens {
        const last = std.mem.lastIndexOfScalar(u8, name, '-') orelse return .{ .family = name };
        const revision = std.fmt.parseInt(u8, name[last + 1 ..], 10) catch return .{ .family = name };
        const head = name[0..last];
        const second = std.mem.lastIndexOfScalar(u8, head, '-') orelse return .{ .family = name };
        const number = std.fmt.parseInt(u32, head[second + 1 ..], 10) catch return .{ .family = name };
        if (second == 0) return .{ .family = name };
        return .{ .family = head[0..second], .number = number, .revision = revision };
    }

    /// Writes the original name back into `out`.
    pub fn format(tokens: NameTokens, out: []u8) ![]const u8 {
        if (tokens.number) |n| return std.fmt.bufPrint(out, "{s}-{d}-{d}", .{ tokens.family, n, tokens.revision.? });
        if (tokens.family.len > out.len) return error.NoSpaceLeft;
        @memcpy(out[0..tokens.family.len], tokens.family);
        return out[0..tokens.family.len];
    }
};

test "name tokens round-trip" {
    var buf: [128]u8 = undefined;
    for ([_][]const u8{ "Win.Trojan.Agent-1234567-0", "Eicar-Test-Signature", "Doc.Malware.X-1-12", "-1-2", "Plain" }) |name| {
        const t = NameTokens.parse(name);
        try std.testing.expectEqualStrings(name, try t.format(&buf));
    }
    const t = NameTokens.parse("Win.Trojan.Agent-1234567-0");
    try std.testing.expectEqualStrings("Win.Trojan.Agent", t.family);
    try std.testing.expectEqual(@as(?u32, 1234567), t.number);
    try std.testing.expectEqual(@as(?u8, 0), t.revision);
    try std.testing.expectEqual(@as(?u32, null), NameTokens.parse("Eicar-Test-Signature").number);
}
