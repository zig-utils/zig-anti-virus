//! Virtual memory the engine manages itself: read-only file mappings for databases, and reserved
//! anonymous regions for scratch. One implementation per OS family, so the callers stay free of
//! `posix.mmap`, which does not exist on Windows.
//!
//! `std.Io.File.MemoryMap` is not used for databases: when mapping fails it falls back to reading
//! the file into the heap, which would turn a 200 MB database into private memory without saying
//! so. A failed mapping here is an error.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;

const is_windows = builtin.os.tag == .windows;

pub const Mapping = []align(std.heap.page_size_min) const u8;
pub const Region = []align(std.heap.page_size_min) u8;

pub const MapError = error{ AccessDenied, MapFailed, OutOfMemory };

/// Map `len` bytes of an open file, read-only. Pages are shared with the page cache and never
/// copied: the mapping costs no private memory however large the file is.
pub fn mapFile(handle: std.Io.File.Handle, len: usize) MapError!Mapping {
    if (len == 0) return error.MapFailed;
    if (is_windows) {
        var section: windows.HANDLE = windows.INVALID_HANDLE_VALUE;
        switch (windows.ntdll.NtCreateSection(
            &section,
            .{ .SPECIFIC = .{ .SECTION = .{ .QUERY = true, .MAP_READ = true } }, .STANDARD = .{ .RIGHTS = .REQUIRED } },
            null,
            null, // the whole file
            .{ .READONLY = true },
            .{ .COMMIT = true },
            handle,
        )) {
            .SUCCESS => {},
            .ACCESS_DENIED => return error.AccessDenied,
            else => return error.MapFailed,
        }
        // The view keeps the section alive; the handle is not needed past mapping.
        defer _ = windows.ntdll.NtClose(section);
        var base: ?*anyopaque = null;
        var view_len: windows.SIZE_T = len;
        switch (windows.ntdll.NtMapViewOfSection(section, windows.current_process, @ptrCast(&base), null, 0, null, &view_len, .Unmap, .{}, .{ .READONLY = true })) {
            .SUCCESS => {},
            .ACCESS_DENIED, .SECTION_PROTECTION => return error.AccessDenied,
            else => return error.MapFailed,
        }
        const ptr: [*]align(std.heap.page_size_min) const u8 = @ptrCast(@alignCast(base.?));
        return ptr[0..len];
    }
    return posix.mmap(null, len, .{ .READ = true }, .{ .TYPE = .PRIVATE }, handle, 0) catch |e| switch (e) {
        error.AccessDenied, error.PermissionDenied => error.AccessDenied,
        error.OutOfMemory => error.OutOfMemory,
        else => error.MapFailed,
    };
}

pub fn unmapFile(mapping: Mapping) void {
    if (is_windows) {
        _ = windows.ntdll.NtUnmapViewOfSection(windows.current_process, @ptrCast(@constCast(mapping.ptr)));
        return;
    }
    posix.munmap(mapping);
}

/// Reserve `len` bytes of zeroed, writable memory. Nothing is resident, or counted as private
/// memory, until a page is first touched.
pub fn reserve(len: usize) error{OutOfMemory}!Region {
    if (is_windows) {
        // Committed up front so touching a page needs no further call, which Windows charges
        // against the commit limit but not the working set: pages still arrive zeroed on demand.
        var base: ?*anyopaque = null;
        var size: windows.SIZE_T = len;
        if (windows.ntdll.NtAllocateVirtualMemory(windows.current_process, @ptrCast(&base), 0, &size, .{ .COMMIT = true, .RESERVE = true }, .{ .READWRITE = true }) != .SUCCESS)
            return error.OutOfMemory;
        const ptr: [*]align(std.heap.page_size_min) u8 = @ptrCast(@alignCast(base.?));
        return ptr[0..len];
    }
    var flags: posix.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    if (@hasField(posix.MAP, "NORESERVE")) flags.NORESERVE = true;
    return posix.mmap(null, len, .{ .READ = true, .WRITE = true }, flags, -1, 0) catch error.OutOfMemory;
}

pub fn release(region: Region) void {
    if (is_windows) {
        var base: ?*anyopaque = region.ptr;
        var size: windows.SIZE_T = 0;
        _ = windows.ntdll.NtFreeVirtualMemory(windows.current_process, @ptrCast(&base), &size, .{ .RELEASE = true });
        return;
    }
    posix.munmap(region);
}

/// Return the pages of `range` (page-aligned, inside a reserved region) to the system. The range
/// stays usable; its contents afterwards are unspecified (zero on Linux and Windows, possibly the
/// old bytes on Darwin), so callers must not read it before writing.
pub fn discard(range: Region) void {
    if (range.len == 0) return;
    if (is_windows) {
        // Decommit frees the pages; committing again hands back zeroed ones on first touch.
        var base: ?*anyopaque = range.ptr;
        var size: windows.SIZE_T = range.len;
        if (windows.ntdll.NtFreeVirtualMemory(windows.current_process, @ptrCast(&base), &size, .{ .DECOMMIT = true }) != .SUCCESS) return;
        base = range.ptr;
        size = range.len;
        _ = windows.ntdll.NtAllocateVirtualMemory(windows.current_process, @ptrCast(&base), 0, &size, .{ .COMMIT = true }, .{ .READWRITE = true });
        return;
    }
    const advice = if (builtin.os.tag.isDarwin()) std.c.MADV.FREE_REUSABLE else posix.MADV.DONTNEED;
    posix.madvise(range.ptr, range.len, advice) catch {};
}

test "a file mapping sees the file's bytes" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var data: [9000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 31);
    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = &data });
    const file = try tmp.dir.openFile(io, "f", .{});
    defer file.close(io);
    const mapping = try mapFile(file.handle, data.len);
    defer unmapFile(mapping);
    try std.testing.expectEqualSlices(u8, &data, mapping);
}

test "a reserved region is zeroed, writable, and usable after a discard" {
    const page = std.heap.pageSize();
    const region = try reserve(16 * page);
    defer release(region);
    try std.testing.expect(std.mem.allEqual(u8, region[0 .. 4 * page], 0));
    @memset(region, 0x5a);
    const tail: Region = @alignCast(region[4 * page ..]);
    discard(tail);
    @memset(tail, 7);
    try std.testing.expectEqual(@as(u8, 7), region[region.len - 1]);
    try std.testing.expectEqual(@as(u8, 0x5a), region[0]);
}
