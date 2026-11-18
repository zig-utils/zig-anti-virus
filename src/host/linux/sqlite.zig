//! A read-only SQLite table reader: enough of the file format to walk a table b-tree and decode
//! its records, plus the write-ahead log overlay so committed but uncheckpointed pages are seen.
//! rpm 4.16 and newer keep the package database in SQLite (`/var/lib/rpm/rpmdb.sqlite`), and
//! reading it directly means no rpm binary or libsqlite is needed.
//!
//! The input is hostile: page numbers, cell offsets, varints, overflow chains and tree depth are
//! all bounded, and every slice is checked against the page it claims to live in.
const std = @import("std");

pub const Error = error{ NotSqlite, Corrupt, Unsupported, TableNotFound, OutOfMemory };

pub const max_depth = 32;

pub const Db = struct {
    bytes: []const u8,
    page_size: u32,
    usable: u32,
    page_count: u32,
    /// Page number to WAL frame data, for committed frames newer than the database file.
    wal: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn open(gpa: std.mem.Allocator, bytes: []const u8, wal_bytes: ?[]const u8) Error!Db {
        if (bytes.len < 100 or !std.mem.eql(u8, bytes[0..16], "SQLite format 3\x00")) return error.NotSqlite;
        const raw_size = std.mem.readInt(u16, bytes[16..18], .big);
        const page_size: u32 = if (raw_size == 1) 65536 else raw_size;
        if (page_size < 512 or !std.math.isPowerOfTwo(page_size)) return error.Corrupt;
        const reserved = bytes[20];
        if (reserved >= page_size - 480) return error.Corrupt;
        if (std.mem.readInt(u32, bytes[56..60], .big) > 1) return error.Unsupported; // UTF-16 text
        var db: Db = .{
            .bytes = bytes,
            .page_size = page_size,
            .usable = page_size - reserved,
            .page_count = @intCast(bytes.len / page_size),
            .gpa = gpa,
        };
        if (wal_bytes) |w| try db.loadWal(w);
        return db;
    }

    pub fn deinit(db: *Db) void {
        db.wal.deinit(db.gpa);
    }

    /// Apply WAL frames up to the last valid commit. Frames are valid while their salts match the
    /// WAL header and the running checksum holds.
    fn loadWal(db: *Db, w: []const u8) Error!void {
        if (w.len < 32) return;
        const magic = std.mem.readInt(u32, w[0..4], .big);
        if (magic != 0x377f0682 and magic != 0x377f0683) return;
        const big = magic & 1 == 1;
        const page_size = std.mem.readInt(u32, w[8..12], .big);
        if (page_size != db.page_size) return;
        const salt1 = std.mem.readInt(u32, w[16..20], .big);
        const salt2 = std.mem.readInt(u32, w[20..24], .big);
        var s = walChecksum(big, w[0..24], .{ 0, 0 });
        if (s[0] != std.mem.readInt(u32, w[24..28], .big) or s[1] != std.mem.readInt(u32, w[28..32], .big)) return;

        var pending: std.ArrayList(struct { page: u32, data: []const u8 }) = .empty;
        defer pending.deinit(db.gpa);
        var off: usize = 32;
        const frame_len = 24 + @as(usize, page_size);
        while (off + frame_len <= w.len) : (off += frame_len) {
            const h = w[off..][0..24];
            if (std.mem.readInt(u32, h[8..12], .big) != salt1 or std.mem.readInt(u32, h[12..16], .big) != salt2) break;
            s = walChecksum(big, h[0..8], s);
            s = walChecksum(big, w[off + 24 ..][0..page_size], s);
            if (s[0] != std.mem.readInt(u32, h[16..20], .big) or s[1] != std.mem.readInt(u32, h[20..24], .big)) break;
            const page_no = std.mem.readInt(u32, h[0..4], .big);
            if (page_no == 0) break;
            try pending.append(db.gpa, .{ .page = page_no, .data = w[off + 24 ..][0..page_size] });
            const commit_size = std.mem.readInt(u32, h[4..8], .big);
            if (commit_size != 0) {
                for (pending.items) |p| try db.wal.put(db.gpa, p.page, p.data);
                pending.clearRetainingCapacity();
                db.page_count = @max(db.page_count, commit_size);
            }
        }
    }

    pub fn page(db: *const Db, n: u32) Error![]const u8 {
        if (n == 0 or n > db.page_count) return error.Corrupt;
        if (db.wal.get(n)) |p| return p;
        const start = @as(usize, n - 1) * db.page_size;
        if (start + db.page_size > db.bytes.len) return error.Corrupt;
        return db.bytes[start..][0..db.page_size];
    }

    /// Root page of a table, from sqlite_master.
    pub fn tableRoot(db: *const Db, name: []const u8) Error!u32 {
        var it = try db.rows(1);
        defer it.deinit();
        while (try it.next()) |row| {
            var rec = Record.init(row.payload) catch continue;
            const kind = (rec.next() catch continue) orelse continue;
            const tname = (rec.next() catch continue) orelse continue;
            _ = (rec.next() catch continue) orelse continue;
            const root = (rec.next() catch continue) orelse continue;
            if (kind != .text or !std.mem.eql(u8, kind.text, "table")) continue;
            if (tname != .text or !std.mem.eql(u8, tname.text, name)) continue;
            if (root != .int or root.int <= 0 or root.int > std.math.maxInt(u32)) return error.Corrupt;
            return @intCast(root.int);
        }
        return error.TableNotFound;
    }

    /// Iterate a table's rows in rowid order. Payloads that spill into overflow pages are
    /// assembled into a buffer owned by the iterator and valid until the next call.
    pub fn rows(db: *const Db, root: u32) Error!RowIterator {
        var it: RowIterator = .{ .db = db };
        it.stack[0] = .{ .page = root, .index = 0 };
        it.depth = 1;
        return it;
    }
};

fn walChecksum(big: bool, data: []const u8, init: [2]u32) [2]u32 {
    var s0 = init[0];
    var s1 = init[1];
    var i: usize = 0;
    while (i + 8 <= data.len) : (i += 8) {
        const x0 = std.mem.readInt(u32, data[i..][0..4], if (big) .big else .little);
        const x1 = std.mem.readInt(u32, data[i + 4 ..][0..4], if (big) .big else .little);
        s0 +%= x0 +% s1;
        s1 +%= x1 +% s0;
    }
    return .{ s0, s1 };
}

pub const Row = struct {
    rowid: i64,
    payload: []const u8,
};

pub const RowIterator = struct {
    db: *const Db,
    stack: [max_depth]struct { page: u32, index: u32 } = undefined,
    depth: usize = 0,
    buf: std.ArrayList(u8) = .empty,
    visited: u32 = 0,

    pub fn deinit(it: *RowIterator) void {
        it.buf.deinit(it.db.gpa);
    }

    pub fn next(it: *RowIterator) Error!?Row {
        const db = it.db;
        while (it.depth > 0) {
            const top = &it.stack[it.depth - 1];
            const p = try db.page(top.page);
            const hdr_off: usize = if (top.page == 1) 100 else 0;
            if (hdr_off + 8 > p.len) return error.Corrupt;
            const kind = p[hdr_off];
            const cells = std.mem.readInt(u16, p[hdr_off + 3 ..][0..2], .big);
            const interior = kind == 5;
            if (kind != 5 and kind != 13) return error.Corrupt;
            const ptrs = hdr_off + @as(usize, if (interior) 12 else 8);
            if (ptrs + @as(usize, cells) * 2 > db.usable) return error.Corrupt;

            if (interior) {
                if (top.index > cells) {
                    it.depth -= 1;
                    continue;
                }
                const child = if (top.index == cells)
                    std.mem.readInt(u32, p[hdr_off + 8 ..][0..4], .big)
                else blk: {
                    const cell = std.mem.readInt(u16, p[ptrs + top.index * 2 ..][0..2], .big);
                    if (@as(usize, cell) + 4 > db.usable) return error.Corrupt;
                    break :blk std.mem.readInt(u32, p[cell..][0..4], .big);
                };
                top.index += 1;
                it.visited += 1;
                if (it.visited > db.page_count or it.depth == max_depth) return error.Corrupt;
                it.stack[it.depth] = .{ .page = child, .index = 0 };
                it.depth += 1;
                continue;
            }

            if (top.index >= cells) {
                it.depth -= 1;
                continue;
            }
            const cell: usize = std.mem.readInt(u16, p[ptrs + top.index * 2 ..][0..2], .big);
            top.index += 1;
            if (cell >= db.usable) return error.Corrupt;
            var pos = cell;
            const len = try varint(p[0..db.usable], &pos);
            const rowid = try varint(p[0..db.usable], &pos);
            if (len > 1 << 30) return error.Corrupt;
            const payload_len: usize = @intCast(len);
            return .{ .rowid = @bitCast(rowid), .payload = try it.payload(p, pos, payload_len) };
        }
        return null;
    }

    fn payload(it: *RowIterator, p: []const u8, pos: usize, len: usize) Error![]const u8 {
        const db = it.db;
        const u: usize = db.usable;
        const x = u - 35;
        if (len <= x) {
            if (pos + len > u) return error.Corrupt;
            return p[pos..][0..len];
        }
        const m = ((u - 12) * 32 / 255) - 23;
        const k = m + ((len - m) % (u - 4));
        const local = if (k <= x) k else m;
        if (pos + local + 4 > u) return error.Corrupt;
        it.buf.clearRetainingCapacity();
        try it.buf.appendSlice(db.gpa, p[pos..][0..local]);
        var next_page = std.mem.readInt(u32, p[pos + local ..][0..4], .big);
        var guard: u32 = 0;
        while (it.buf.items.len < len) {
            if (next_page == 0) return error.Corrupt;
            guard += 1;
            if (guard > db.page_count) return error.Corrupt;
            const op = try db.page(next_page);
            next_page = std.mem.readInt(u32, op[0..4], .big);
            const take = @min(len - it.buf.items.len, u - 4);
            try it.buf.appendSlice(db.gpa, op[4..][0..take]);
        }
        return it.buf.items;
    }
};

pub fn varint(bytes: []const u8, pos: *usize) Error!u64 {
    var v: u64 = 0;
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        if (pos.* >= bytes.len) return error.Corrupt;
        const b = bytes[pos.*];
        pos.* += 1;
        if (i == 8) return (v << 8) | b;
        v = (v << 7) | (b & 0x7f);
        if (b & 0x80 == 0) return v;
    }
    unreachable;
}

pub const Value = union(enum) {
    null,
    int: i64,
    float: f64,
    text: []const u8,
    blob: []const u8,
};

/// Walks one record's columns in order.
pub const Record = struct {
    bytes: []const u8,
    header_pos: usize,
    header_end: usize,
    body_pos: usize,

    pub fn init(bytes: []const u8) Error!Record {
        var pos: usize = 0;
        const hlen = try varint(bytes, &pos);
        if (hlen > bytes.len or hlen < pos) return error.Corrupt;
        return .{ .bytes = bytes, .header_pos = pos, .header_end = @intCast(hlen), .body_pos = @intCast(hlen) };
    }

    pub fn next(r: *Record) Error!?Value {
        if (r.header_pos >= r.header_end) return null;
        const t = try varint(r.bytes[0..r.header_end], &r.header_pos);
        const size: usize = switch (t) {
            0, 8, 9 => 0,
            1 => 1,
            2 => 2,
            3 => 3,
            4 => 4,
            5 => 6,
            6, 7 => 8,
            10, 11 => return error.Corrupt,
            else => if (t > 1 << 31) return error.Corrupt else @intCast((t - 12) / 2),
        };
        if (r.body_pos + size > r.bytes.len) return error.Corrupt;
        const data = r.bytes[r.body_pos..][0..size];
        r.body_pos += size;
        return switch (t) {
            0 => .null,
            8 => .{ .int = 0 },
            9 => .{ .int = 1 },
            1...6 => blk: {
                var v: i64 = if (data[0] & 0x80 != 0) -1 else 0;
                for (data) |b| v = (v << 8) | b;
                break :blk .{ .int = v };
            },
            7 => .{ .float = @bitCast(std.mem.readInt(u64, data[0..8], .big)) },
            else => if (t % 2 == 0) .{ .blob = data } else .{ .text = data },
        };
    }
};

test "varints" {
    var pos: usize = 0;
    try std.testing.expectEqual(@as(u64, 0x7f), try varint(&.{0x7f}, &pos));
    pos = 0;
    try std.testing.expectEqual(@as(u64, 0x80), try varint(&.{ 0x81, 0x00 }, &pos));
    pos = 0;
    try std.testing.expectError(error.Corrupt, varint(&.{0x81}, &pos));
    pos = 0;
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), try varint(&@as([9]u8, @splat(0xff)), &pos));
}

test "reads a table spilling into overflow pages, with and without the WAL" {
    const gpa = std.testing.allocator;
    const fixture = @embedFile("fixtures/test.sqlite");
    var db = try Db.open(gpa, fixture, null);
    defer db.deinit();
    const root = try db.tableRoot("Packages");
    var it = try db.rows(root);
    defer it.deinit();
    var n: usize = 0;
    var big: usize = 0;
    while (try it.next()) |row| {
        n += 1;
        var rec = try Record.init(row.payload);
        _ = try rec.next(); // hnum is the rowid alias: NULL in the record
        const blob = (try rec.next()).?;
        if (blob.blob.len > 3000) {
            big += 1;
            for (blob.blob, 0..) |b, i| try std.testing.expectEqual(@as(u8, @truncate(i *% 7)), b);
        }
    }
    try std.testing.expectEqual(@as(usize, 40), n);
    try std.testing.expectEqual(@as(usize, 1), big);

    var with_wal = try Db.open(gpa, @embedFile("fixtures/wal.sqlite"), @embedFile("fixtures/wal.sqlite-wal"));
    defer with_wal.deinit();
    var wit = try with_wal.rows(try with_wal.tableRoot("t"));
    defer wit.deinit();
    var rows_seen: usize = 0;
    while (try wit.next()) |_| rows_seen += 1;
    try std.testing.expectEqual(@as(usize, 3), rows_seen); // two in the file, one only in the WAL

    var without = try Db.open(gpa, @embedFile("fixtures/wal.sqlite"), null);
    defer without.deinit();
    var oit = try without.rows(try without.tableRoot("t"));
    defer oit.deinit();
    rows_seen = 0;
    while (try oit.next()) |_| rows_seen += 1;
    try std.testing.expectEqual(@as(usize, 2), rows_seen);
}
