//! Writes a `.zavdb`: lays sections out (hot region first, 2 MiB aligned), hashes them, signs the
//! header, and replaces the target atomically (temp file, fsync, rename). Runs in the compiler
//! process, never in the daemon.
const std = @import("std");
const Io = std.Io;
const format = @import("format.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;

pub const Section = struct {
    kind: format.SectionKind,
    variant: u16 = 0,
    partition: u8 = 0,
    /// Hot sections are placed first, inside the 2 MiB aligned hot region.
    hot: bool = false,
    align_log2: u8 = format.min_section_alignment_log2,
    bytes: []const u8,
};

pub const Options = struct {
    db_version: u64,
    build_unix_time: u64 = 0,
    feature_flags: u64 = 0,
    sources: format.Sources = .{},
    /// Signing key. Unsigned databases are only accepted by readers that explicitly allow them.
    key_pair: ?Ed25519.KeyPair = null,
};

pub const Error = error{ TooManySections, BadAlignment, SigningFailed };

/// A planned layout: the header block (header plus section table) and where each section goes.
pub const Layout = struct {
    block: [format.header_size]u8 align(8),
    offsets: [format.max_sections]u64,
    total_size: u64,

    pub fn header(layout: *Layout) *format.Header {
        return @ptrCast(&layout.block);
    }
};

/// Lay out, hash and sign. Pure: produces the header block and offsets without touching disk.
pub fn plan(sections: []const Section, options: Options) Error!Layout {
    if (sections.len > format.max_sections) return error.TooManySections;
    var layout: Layout = .{ .block = @splat(0), .offsets = undefined, .total_size = 0 };
    const table: [*]format.SectionEntry = @ptrCast(@alignCast(&layout.block[format.section_table_offset]));

    var cursor: u64 = format.header_size;
    var placed: usize = 0;
    // Hot sections first, starting at the 2 MiB boundary, then everything else.
    for ([_]bool{ true, false }, 0..) |want_hot, pass| {
        var first_in_pass = true;
        for (sections, 0..) |s, i| {
            if (s.hot != want_hot) continue;
            if (s.align_log2 < format.min_section_alignment_log2 or s.align_log2 > 30) return error.BadAlignment;
            var alignment = @as(u64, 1) << @intCast(s.align_log2);
            if (pass == 0 and first_in_pass) alignment = @max(alignment, format.hot_alignment);
            first_in_pass = false;
            cursor = std.mem.alignForward(u64, cursor, alignment);
            layout.offsets[i] = cursor;
            table[placed] = .{
                .kind = s.kind,
                .variant = s.variant,
                .flags = .{ .hot = s.hot },
                .offset = cursor,
                .size = s.bytes.len,
                .xxh3 = format.xxh3(s.bytes),
                .align_log2 = s.align_log2,
                .partition = s.partition,
            };
            placed += 1;
            cursor += s.bytes.len;
        }
    }
    layout.total_size = std.mem.alignForward(u64, cursor, 1 << format.min_section_alignment_log2);

    const h = layout.header();
    h.* = .{
        .feature_flags = options.feature_flags,
        .db_version = options.db_version,
        .build_unix_time = options.build_unix_time,
        .total_size = layout.total_size,
        .section_count = @intCast(sections.len),
        .sources = options.sources,
    };
    h.section_table_xxh3 = format.xxh3(layout.block[format.section_table_offset..][0 .. sections.len * @sizeOf(format.SectionEntry)]);
    h.blake3_root = bodyRoot(sections, &layout);
    if (options.key_pair) |kp| {
        h.key_id = format.keyId(kp.public_key.toBytes());
        const sig = kp.sign(layout.block[0..format.signed_len], null) catch return error.SigningFailed;
        h.signature = sig.toBytes();
    }
    return layout;
}

/// BLAKE3 over the body exactly as it will be on disk, zero padding included.
fn bodyRoot(sections: []const Section, layout: *const Layout) [32]u8 {
    var hasher = Blake3.init(.{});
    const zeros: [4096]u8 = @splat(0);
    var cursor: u64 = format.header_size;
    // Visit sections in file order.
    var order: [format.max_sections]usize = undefined;
    for (sections, 0..) |_, i| order[i] = i;
    std.mem.sortUnstable(usize, order[0..sections.len], layout, struct {
        fn less(l: *const Layout, a: usize, b: usize) bool {
            return l.offsets[a] < l.offsets[b];
        }
    }.less);
    for (order[0..sections.len]) |i| {
        var gap = layout.offsets[i] - cursor;
        while (gap > 0) {
            const n = @min(gap, zeros.len);
            hasher.update(zeros[0..n]);
            gap -= n;
        }
        hasher.update(sections[i].bytes);
        cursor = layout.offsets[i] + sections[i].bytes.len;
    }
    var gap = layout.total_size - cursor;
    while (gap > 0) {
        const n = @min(gap, zeros.len);
        hasher.update(zeros[0..n]);
        gap -= n;
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Write the database to `sub_path` in `dir`, replacing any existing file atomically.
pub fn write(io: Io, dir: Io.Dir, sub_path: []const u8, sections: []const Section, options: Options) !void {
    var layout = try plan(sections, options);

    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const tmp_path = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp-{x}", .{ sub_path, std.mem.readInt(u64, &nonce, .little) });

    const file = try dir.createFile(io, tmp_path, .{ .truncate = true });
    var committed = false;
    defer if (!committed) dir.deleteFile(io, tmp_path) catch {};
    {
        defer file.close(io);
        try file.writePositionalAll(io, &layout.block, 0);
        for (sections, 0..) |s, i| try file.writePositionalAll(io, s.bytes, layout.offsets[i]);
        // Padding between sections stays a hole on filesystems that support sparse files.
        try file.setLength(io, layout.total_size);
        try file.sync(io);
    }
    try dir.rename(tmp_path, dir, sub_path, io);
    committed = true;
}
