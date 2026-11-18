//! rpm header blobs as stored in the rpm database: a big-endian index of (tag, type, offset,
//! count) entries followed by a data store. Only the tags ownership and verification need are
//! decoded: name, version, release, epoch, arch, and the file list with digests, modes and flags.
const std = @import("std");

pub const Error = error{ Corrupt, OutOfMemory };

pub const Tag = enum(u32) {
    name = 1000,
    version = 1001,
    release = 1002,
    epoch = 1003,
    filesizes = 1028,
    filemodes = 1030,
    filedigests = 1035,
    fileflags = 1037,
    arch = 1022,
    dirindexes = 1116,
    basenames = 1117,
    dirnames = 1118,
    filedigestalgo = 5011,
    _,
};

const Type = enum(u32) { null = 0, char = 1, int8 = 2, int16 = 3, int32 = 4, int64 = 5, string = 6, bin = 7, string_array = 8, i18nstring = 9, _ };

pub const file_config: u32 = 1 << 0;
pub const file_ghost: u32 = 1 << 6;

pub const DigestAlgo = enum(u32) { md5 = 1, sha1 = 2, sha256 = 8, sha384 = 9, sha512 = 10, _ };

/// Limits for hostile headers.
pub const max_entries = 1 << 16;
pub const max_files = 1 << 20;

pub const Header = struct {
    index: []const u8,
    store: []const u8,
    count: u32,

    pub fn parse(blob: []const u8) Error!Header {
        if (blob.len < 8) return error.Corrupt;
        const il = std.mem.readInt(u32, blob[0..4], .big);
        const dl = std.mem.readInt(u32, blob[4..8], .big);
        if (il > max_entries) return error.Corrupt;
        const index_len = @as(usize, il) * 16;
        if (8 + index_len + dl > blob.len) return error.Corrupt;
        return .{ .index = blob[8..][0..index_len], .store = blob[8 + index_len ..][0..dl], .count = il };
    }

    const Entry = struct { typ: Type, offset: u32, count: u32 };

    fn find(h: Header, tag: Tag) ?Entry {
        var i: usize = 0;
        while (i < h.count) : (i += 1) {
            const e = h.index[i * 16 ..][0..16];
            if (std.mem.readInt(u32, e[0..4], .big) != @backingInt(tag)) continue;
            return .{
                .typ = @fromBackingInt(@intCast(std.mem.readInt(u32, e[4..8], .big))),
                .offset = std.mem.readInt(u32, e[8..12], .big),
                .count = std.mem.readInt(u32, e[12..16], .big),
            };
        }
        return null;
    }

    pub fn string(h: Header, tag: Tag) ?[]const u8 {
        const e = h.find(tag) orelse return null;
        if (e.typ != .string and e.typ != .i18nstring) return null;
        if (e.offset >= h.store.len) return null;
        const rest = h.store[e.offset..];
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse return null;
        return rest[0..end];
    }

    /// The `n` strings of a string array, iterated.
    pub fn strings(h: Header, tag: Tag) Error!StringIterator {
        const e = h.find(tag) orelse return .{ .rest = "", .left = 0 };
        if (e.typ != .string_array or e.offset > h.store.len or e.count > max_files) return error.Corrupt;
        return .{ .rest = h.store[e.offset..], .left = e.count };
    }

    pub fn int32s(h: Header, tag: Tag) Error![]const u8 {
        const e = h.find(tag) orelse return "";
        if (e.typ != .int32 or e.count > max_files) return error.Corrupt;
        const len = @as(usize, e.count) * 4;
        if (e.offset + len > h.store.len) return error.Corrupt;
        return h.store[e.offset..][0..len];
    }

    pub fn int16s(h: Header, tag: Tag) Error![]const u8 {
        const e = h.find(tag) orelse return "";
        if (e.typ != .int16 or e.count > max_files) return error.Corrupt;
        const len = @as(usize, e.count) * 2;
        if (e.offset + len > h.store.len) return error.Corrupt;
        return h.store[e.offset..][0..len];
    }

    pub fn int32(h: Header, tag: Tag) ?u32 {
        const raw = h.int32s(tag) catch return null;
        if (raw.len < 4) return null;
        return std.mem.readInt(u32, raw[0..4], .big);
    }
};

pub const StringIterator = struct {
    rest: []const u8,
    left: u32,

    pub fn next(it: *StringIterator) Error!?[]const u8 {
        if (it.left == 0) return null;
        const end = std.mem.indexOfScalar(u8, it.rest, 0) orelse return error.Corrupt;
        const s = it.rest[0..end];
        it.rest = it.rest[end + 1 ..];
        it.left -= 1;
        return s;
    }
};

pub fn get32(raw: []const u8, i: usize) u32 {
    return std.mem.readInt(u32, raw[i * 4 ..][0..4], .big);
}

pub fn get16(raw: []const u8, i: usize) u16 {
    return std.mem.readInt(u16, raw[i * 2 ..][0..2], .big);
}

/// One file of a package.
pub const File = struct {
    path: []const u8,
    mode: u16,
    flags: u32,
    digest: []const u8,
};

/// Decode the file list into `out`, with paths allocated from `arena`.
pub fn files(arena: std.mem.Allocator, h: Header, out: *std.ArrayList(File), gpa: std.mem.Allocator) Error!void {
    var dirs: std.ArrayList([]const u8) = .empty;
    defer dirs.deinit(gpa);
    var dit = try h.strings(.dirnames);
    while (try dit.next()) |d| try dirs.append(gpa, d);
    const indexes = try h.int32s(.dirindexes);
    const modes = try h.int16s(.filemodes);
    const flags = try h.int32s(.fileflags);
    var digests = try h.strings(.filedigests);
    var names = try h.strings(.basenames);
    var i: usize = 0;
    while (try names.next()) |base| : (i += 1) {
        if ((i + 1) * 4 > indexes.len) return error.Corrupt;
        const di = get32(indexes, i);
        if (di >= dirs.items.len) return error.Corrupt;
        const path = try std.mem.concat(arena, u8, &.{ dirs.items[di], base });
        try out.append(gpa, .{
            .path = path,
            .mode = if ((i + 1) * 2 <= modes.len) get16(modes, i) else 0,
            .flags = if ((i + 1) * 4 <= flags.len) get32(flags, i) else 0,
            .digest = (try digests.next()) orelse "",
        });
    }
}
