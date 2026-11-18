//! REGEX_POOL: serialised zig-regex byte-mode programs (docs/DESIGN.md sections 1 and 3.2), for
//! `.cdb` filename regexes and PCRE subsignatures.
//!
//! Layout: a 16-byte header `{"RGXP", version, count}`, then `[count]{offset u32, len u32}`
//! (from the section start), then the program blobs. A blob is zig-regex's own serialised form
//! (position independent, versioned, CRC-32 protected), so nothing is relocated. `RegexPool.init`
//! loads, and so fully validates, every program once; matching reloads a program from its bytes
//! (a header read and a checksum), which allocates nothing. Matching state is a zig-regex
//! `Scratch` per worker, sized by `capacity` for the largest program here.
const std = @import("std");
const regex = @import("regex");

pub const PoolHeader = extern struct {
    magic: [4]u8 = "RGXP".*,
    version: u32 = 1,
    count: u32,
    _reserved: u32 = 0,
};

pub const PoolEntry = extern struct { offset: u32, len: u32 };

comptime {
    std.debug.assert(@sizeOf(PoolHeader) == 16);
    std.debug.assert(@sizeOf(PoolEntry) == 8);
}

pub const RegexPool = struct {
    bytes: []const u8,
    entries: []const PoolEntry,
    /// The largest state and class counts of any program in the pool.
    max_capacity: regex.program.Capacity,

    pub const Error = error{BadRegexPool};

    pub fn init(section: []const u8) Error!RegexPool {
        if (section.len < @sizeOf(PoolHeader) or @intFromPtr(section.ptr) % 4 != 0) return error.BadRegexPool;
        const h: *const PoolHeader = @ptrCast(@alignCast(section.ptr));
        if (!std.mem.eql(u8, &h.magic, "RGXP") or h.version != 1) return error.BadRegexPool;
        if (@as(usize, h.count) > (section.len - @sizeOf(PoolHeader)) / @sizeOf(PoolEntry)) return error.BadRegexPool;
        const e: [*]const PoolEntry = @ptrCast(@alignCast(section.ptr + @sizeOf(PoolHeader)));
        var pool: RegexPool = .{ .bytes = section, .entries = e[0..h.count], .max_capacity = .{ .states = 0, .classes = 0 } };
        for (pool.entries) |entry| {
            if (@as(u64, entry.offset) + entry.len > section.len) return error.BadRegexPool;
            const p = regex.Program.load(section[entry.offset..][0..entry.len]) catch return error.BadRegexPool;
            if (p.bytes().len != entry.len) return error.BadRegexPool;
            pool.max_capacity = pool.max_capacity.max(p.capacity());
        }
        return pool;
    }

    pub fn count(pool: RegexPool) usize {
        return pool.entries.len;
    }

    /// Program `i`, validated by `init`.
    pub fn get(pool: RegexPool, i: usize) regex.Program {
        const entry = pool.entries[i];
        // The section is read-only and was validated by init: loading cannot fail.
        return regex.Program.load(pool.bytes[entry.offset..][0..entry.len]) catch unreachable;
    }

    /// A capacity that fits every program here, with `dfa_states` cached DFA states.
    pub fn capacity(pool: RegexPool, dfa_states: u32) regex.program.Capacity {
        var c = pool.max_capacity;
        c.states = @max(c.states, 1);
        c.classes = @max(c.classes, 1);
        c.dfa_states = dfa_states;
        return c;
    }
};

/// Build a pool from serialised program blobs; program i is `blobs[i]`.
pub fn build(gpa: std.mem.Allocator, blobs: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const h: PoolHeader = .{ .count = @intCast(blobs.len) };
    try out.appendSlice(gpa, std.mem.asBytes(&h));
    const index_at = out.items.len;
    try out.appendNTimes(gpa, 0, blobs.len * @sizeOf(PoolEntry));
    for (blobs, 0..) |blob, i| {
        while (out.items.len % 8 != 0) try out.append(gpa, 0);
        const entry: PoolEntry = .{ .offset = @intCast(out.items.len), .len = @intCast(blob.len) };
        @memcpy(out.items[index_at + i * @sizeOf(PoolEntry) ..][0..@sizeOf(PoolEntry)], std.mem.asBytes(&entry));
        try out.appendSlice(gpa, blob);
    }
    return out.toOwnedSlice(gpa);
}

test "pool round-trip, matching from scratch memory, and corruption refused" {
    const gpa = std.testing.allocator;
    var a = try regex.Program.compile(gpa, "\\.(exe|scr)$", .{ .bytes = true, .case_insensitive = true });
    defer a.deinit(gpa);
    var b = try regex.Program.compile(gpa, "MZ.{2}\\x50\\x45", .{ .bytes = true });
    defer b.deinit(gpa);
    const bytes = try build(gpa, &.{ a.bytes(), b.bytes() });
    defer gpa.free(bytes);
    const image = try gpa.alignedAlloc(u8, .@"8", bytes.len);
    defer gpa.free(image);
    @memcpy(image, bytes);
    const pool = try RegexPool.init(image);
    try std.testing.expectEqual(@as(usize, 2), pool.count());

    const capacity = pool.capacity(256);
    const mem = try gpa.alignedAlloc(u8, .@"8", regex.Scratch.bytesNeeded(capacity));
    defer gpa.free(mem);
    var scratch = try regex.Scratch.initBuffer(mem, capacity);
    const p0 = pool.get(0);
    try std.testing.expect(try p0.isMatch(&scratch, "INVOICE.SCR"));
    try std.testing.expect(!try p0.isMatch(&scratch, "invoice.pdf"));
    const p1 = pool.get(1);
    try std.testing.expect(try p1.isMatch(&scratch, "xxMZ\x90\x00PE"));

    for (0..image.len) |i| {
        @memcpy(image, bytes);
        image[i] ^= 0x21;
        if (RegexPool.init(image)) |ok| {
            for (0..ok.count()) |j| _ = ok.get(j).isMatch(&scratch, "x.exe") catch {};
        } else |_| {}
    }
}
