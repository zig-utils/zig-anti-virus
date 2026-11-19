//! Directory enumeration for the scan I/O layer. Names are sorted by inode
//! before opening them. The caller owns the directory and its entry arena.
const std = @import("std");
const builtin = @import("builtin");
const mac = @import("directory_macos.zig");

pub const Mode = enum { portable, native };

pub const Entry = struct {
    name: [:0]const u8,
    inode: u64,
    kind: std.Io.File.Kind,
    size: ?u64 = null,
};

pub const Volume = struct {
    device: u64,
    mount: ?u64 = null,
    subvolume: ?u64 = null,
};

/// The allocator owns the entries and names until the caller releases its
/// arena. The directory must be opened for iteration and freshly positioned.
pub fn list(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, mode: Mode) ![]Entry {
    var entries: std.ArrayList(Entry) = .empty;
    if (builtin.os.tag == .macos and mode == .native) {
        var reader: mac.Reader = .{ .fd = dir.handle };
        while (try reader.next()) |entry| {
            const name = try a.dupeSentinel(u8, entry.name, 0);
            if (entry.inode != null and entry.kind != .unknown) {
                try entries.append(a, .{
                    .name = name,
                    .inode = entry.inode.?,
                    .kind = entry.kind,
                    .size = entry.size,
                });
            } else {
                const stat = try dir.statFile(io, name, .{ .follow_symlinks = false });
                try entries.append(a, .{ .name = name, .inode = inodeBits(stat.inode), .kind = stat.kind, .size = stat.size });
            }
        }
    } else {
        // The native threaded Zig backend uses getdents64 on Linux. It
        // already validates record boundaries and supplies inode and d_type.
        var iterator = dir.iterate();
        while (try iterator.next(io)) |entry| {
            const name = try a.dupeSentinel(u8, entry.name, 0);
            if (entry.kind == .unknown) {
                const stat = try dir.statFile(io, name, .{ .follow_symlinks = false });
                try entries.append(a, .{ .name = name, .inode = inodeBits(stat.inode), .kind = stat.kind, .size = stat.size });
            } else {
                try entries.append(a, .{ .name = name, .inode = inodeBits(entry.inode), .kind = entry.kind });
            }
        }
    }
    std.mem.sort(Entry, entries.items, {}, less);
    return entries.items;
}

fn inodeBits(inode: std.Io.File.INode) u64 {
    // Windows exposes the file ID through a signed platform integer.
    return @as(@Int(.unsigned, @bitSizeOf(std.Io.File.INode)), @bitCast(inode));
}

fn less(_: void, left: Entry, right: Entry) bool {
    return if (left.inode == right.inode)
        std.mem.lessThan(u8, left.name, right.name)
    else
        left.inode < right.inode;
}

pub const linux_mask: std.os.linux.STATX = .{
    .TYPE = true,
    .INO = true,
    .SIZE = true,
    .MNT_ID = true,
    .SUBVOL = true,
};

pub fn linuxVolume(stat: std.os.linux.Statx) Volume {
    return .{
        .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor,
        .mount = if (stat.mask.MNT_ID) stat.mnt_id else null,
        .subvolume = if (stat.mask.SUBVOL) stat.subvol else null,
    };
}

/// Identify the opened directory itself, including bind mounts that share
/// device numbers and (on newer Linux) subvolumes in the same mount.
pub fn volume(dir: std.Io.Dir) !?Volume {
    if (builtin.os.tag != .linux) return null;
    const stat = try linuxFdStat(dir.handle) orelse return null;
    return linuxVolume(stat);
}

pub fn linuxFdStat(fd: std.os.linux.fd_t) !?std.os.linux.Statx {
    const linux = std.os.linux;
    var result: linux.Statx = undefined;
    while (true) switch (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, linux_mask, &result))) {
        .SUCCESS => return result,
        .INTR => continue,
        .NOSYS => return null,
        else => |err| return std.posix.unexpectedErrno(err),
    };
}

test "native directory enumeration agrees with portable names, types and inodes" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "dir", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sample", .data = "abcdef" });
    const portable = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer portable.close(io);
    const native = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer native.close(io);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const plain = try list(arena.allocator(), io, portable, .portable);
    const optimized = try list(arena.allocator(), io, native, .native);
    try std.testing.expectEqual(@as(usize, 2), optimized.len);
    try std.testing.expectEqual(plain.len, optimized.len);
    for (plain, optimized) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqual(expected.kind, actual.kind);
        try std.testing.expectEqual(expected.inode, actual.inode);
        if (builtin.os.tag == .macos and actual.kind == .file)
            try std.testing.expectEqual(@as(?u64, 6), actual.size);
    }
    if (builtin.os.tag == .linux)
        try std.testing.expect((try volume(native)).?.mount != null);
}
