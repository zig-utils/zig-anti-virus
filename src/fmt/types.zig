//! ClamAV file type names (`CL_TYPE_*`), from the ClamAV file types reference, as small
//! integers for on-disk records. `any` is 0. The numbering is zav's own and only ever compared
//! within one database, so adding a name at the end is compatible.
const std = @import("std");

pub const ClType = enum(u16) {
    any = 0,
    @"7z",
    @"7zsfx",
    apm,
    arj,
    arjsfx,
    autoit,
    binary_data,
    binhex,
    bz,
    cabsfx,
    cpio_crc,
    cpio_newc,
    cpio_odc,
    cpio_old,
    cryptff,
    dmg,
    egg,
    elf,
    gif,
    gpt,
    graphics,
    gz,
    html_utf16,
    html,
    hwp3,
    hwpole2,
    internal,
    ishield_msi,
    iso9660,
    java,
    jpeg,
    lnk,
    macho_unibin,
    macho,
    mail,
    mbr,
    mhtml,
    mscab,
    mschm,
    msexe,
    msole2,
    msszdd,
    nulsft,
    old_tar,
    onenote,
    ooxml_hwp,
    ooxml_ppt,
    ooxml_word,
    ooxml_xl,
    part_hfsplus,
    pdf,
    png,
    posix_tar,
    ps,
    python_compiled,
    rar,
    rarsfx,
    riff,
    rtf,
    screnc,
    script,
    sis,
    swf,
    text_ascii,
    text_utf16be,
    text_utf16le,
    text_utf8,
    tiff,
    tnef,
    udf,
    uuencoded,
    xar,
    xdp,
    xml_hwp,
    xml_word,
    xml_xl,
    xz,
    zip,
    zipsfx,
    // Used by ClamAV's own type magic though not in the file types reference.
    part_any,
    ignored,
    // In the official daily.ftm (functionality level 210).
    alz,
    lha_lzh,
    _,

    /// `CL_TYPE_ZIP` and friends, case-sensitive as ClamAV writes them.
    pub fn parse(text: []const u8) ?ClType {
        const prefix = "CL_TYPE_";
        if (!std.mem.startsWith(u8, text, prefix)) return null;
        const rest = text[prefix.len..];
        if (rest.len == 0 or rest.len > 32) return null;
        var lower: [32]u8 = undefined;
        for (rest, 0..) |c, i| {
            if (std.ascii.isLower(c)) return null;
            lower[i] = std.ascii.toLower(c);
        }
        inline for (@typeInfo(ClType).@"enum".field_names, 0..) |field, i| {
            if (std.mem.eql(u8, field, lower[0..rest.len])) return @fromBackingInt(@intCast(i));
        }
        return null;
    }

    /// The `CL_TYPE_*` name, written into `out`.
    pub fn name(t: ClType, out: []u8) error{ UnknownType, NoSpaceLeft }![]const u8 {
        const names = comptime @typeInfo(ClType).@"enum".field_names;
        const v = @backingInt(t);
        if (v >= names.len) return error.UnknownType;
        const written = try std.fmt.bufPrint(out, "CL_TYPE_{s}", .{names[v]});
        for (written[8..]) |*c| c.* = std.ascii.toUpper(c.*);
        return written;
    }
};

test "names round-trip and unknown names are refused" {
    var buf: [48]u8 = undefined;
    try std.testing.expectEqual(ClType.zip, ClType.parse("CL_TYPE_ZIP").?);
    try std.testing.expectEqual(ClType.@"7zsfx", ClType.parse("CL_TYPE_7ZSFX").?);
    try std.testing.expectEqual(ClType.any, ClType.parse("CL_TYPE_ANY").?);
    try std.testing.expectEqualStrings("CL_TYPE_MSEXE", try ClType.msexe.name(&buf));
    for ([_][]const u8{ "CL_TYPE_", "CL_TYPE_zip", "ZIP", "CL_TYPE_NOPE", "CL_TYPE_ZIP " }) |bad| {
        try std.testing.expect(ClType.parse(bad) == null);
    }
}
