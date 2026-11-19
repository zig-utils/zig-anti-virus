//! The packed getattrlistbulk ABI from sys/attr.h. Unlike readdir followed by
//! stat, this returns the file type, inode and length with each name.
const std = @import("std");

const attr_name = 0x00000001;
const attr_type = 0x00000008;
const attr_inode = 0x02000000;
const attr_error = 0x20000000;
const attr_returned = 0x80000000;
const attr_file_length = 0x00000200;
const pack_invalid = 0x00000008;

const Attributes = extern struct {
    count: u16 = 5,
    reserved: u16 = 0,
    common: u32 = attr_returned | attr_error | attr_name | attr_type | attr_inode,
    volume: u32 = 0,
    directory: u32 = 0,
    file: u32 = attr_file_length,
    fork: u32 = 0,
};

extern "c" fn getattrlistbulk(fd: std.c.fd_t, attrs: *Attributes, buffer: [*]u8, size: usize, options: u64) c_int;

const Entry = struct {
    name: []const u8,
    inode: ?u64,
    size: ?u64,
    kind: std.Io.File.Kind,
};

pub const Reader = struct {
    fd: std.c.fd_t,
    buffer: [32 * 1024]u8 align(8) = undefined,
    pending: usize = 0,
    offset: usize = 0,

    /// Entry names are valid until the next batch overwrites the buffer.
    pub fn next(reader: *Reader) !?Entry {
        if (reader.pending == 0) {
            var attrs: Attributes = .{};
            while (true) {
                const count = getattrlistbulk(reader.fd, &attrs, &reader.buffer, reader.buffer.len, pack_invalid);
                switch (std.posix.errno(count)) {
                    .SUCCESS => {
                        if (count == 0) return null;
                        reader.pending = @intCast(count);
                        reader.offset = 0;
                        break;
                    },
                    .INTR => continue,
                    .ACCES, .PERM => return error.AccessDenied,
                    .OPNOTSUPP, .NOSYS => return error.BulkAttributesUnavailable,
                    else => |err| return std.posix.unexpectedErrno(err),
                }
            }
        }
        const bytes = reader.buffer[reader.offset..];
        if (bytes.len < 4) return error.InvalidBulkEntry;
        const length = read(u32, bytes, 0);
        if (length < 48 or length > bytes.len or length % 8 != 0) return error.InvalidBulkEntry;
        reader.pending -= 1;
        reader.offset += length;
        return try decode(bytes[0..length]);
    }
};

fn decode(record: []const u8) !Entry {
    // Length, attribute_set_t, entry errno, name reference, object type,
    // 64-bit file ID, then file data length when present.
    const common = read(u32, record, 4);
    const file = read(u32, record, 16);
    if (common & attr_error != 0 and read(u32, record, 24) != 0) return error.BulkEntryUnreadable;
    if (common & attr_name == 0) return error.InvalidBulkEntry;
    const relative = read(i32, record, 28);
    const count = read(u32, record, 32);
    if (relative < 20) return error.InvalidBulkEntry;
    const offset = @as(usize, @intCast(relative)) + 28;
    if (offset > record.len or count < 2 or count > record.len - offset) return error.InvalidBulkEntry;
    const name_with_nul = record[offset..][0..count];
    const name = name_with_nul[0 .. count - 1];
    if (name_with_nul[count - 1] != 0 or std.mem.indexOfAny(u8, name, "/\x00") != null)
        return error.InvalidBulkEntry;

    const kind: std.Io.File.Kind = if (common & attr_type == 0) .unknown else switch (read(u32, record, 36)) {
        1 => .file,
        2 => .directory,
        3 => .block_device,
        4 => .character_device,
        5 => .sym_link,
        6 => .unix_domain_socket,
        7 => .named_pipe,
        else => .unknown,
    };
    return .{
        .name = name,
        .kind = kind,
        .inode = if (common & attr_inode != 0) read(u64, record, 40) else null,
        .size = if (kind == .file and file & attr_file_length != 0 and offset >= 56)
            read(u64, record, 48)
        else
            null,
    };
}

fn read(comptime T: type, bytes: []const u8, offset: usize) T {
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}
