//! REGEX_POOL: serialised zig-regex byte-mode programs (docs/DESIGN.md sections 1 and 3.2), for
//! `.cdb` filename regexes, PCRE subsignatures and YARA regex strings.
//!
//! Layout: a 16-byte header `{"RGXP", version, count}`, then `[count]{offset u32, len u32}`
//! (from the section start), then the program blobs. A blob is zig-regex's own serialised form
//! (position independent, versioned, CRC-32 protected), so nothing is relocated. `RegexPool.init`
//! loads, and so fully validates, every program once; matching reloads a program from its bytes
//! (a header read and a checksum), which allocates nothing.
//!
//! A blob is one of two kinds, told apart by its magic: a linear-time `regex.Program` ("ZRXP")
//! or, for what that form refuses (backreferences, lookaround, atomic groups, huge counted
//! repeats), a bounded-backtracking `regex.bt.Program` ("ZRXB"). A backtracking search has a
//! step budget and a fixed stack; running out of either is an error the caller reports as a
//! limit, never a miss. Matching state is a `Scratch` per worker (both kinds' scratch), sized
//! by `scratchBytes` for the largest programs here.
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
    /// The largest state and class counts of any linear program in the pool.
    max_capacity: regex.program.Capacity,
    /// The largest slot and counter counts of any backtracking program, if there is one.
    max_bt: ?regex.bt.Capacity = null,

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
            const blob = section[entry.offset..][0..entry.len];
            if (isBacktracking(blob)) {
                const p = regex.bt.Program.load(blob) catch return error.BadRegexPool;
                if (p.bytes().len != entry.len) return error.BadRegexPool;
                pool.max_bt = if (pool.max_bt) |m| m.max(p.capacity()) else p.capacity();
            } else {
                const p = regex.Program.load(blob) catch return error.BadRegexPool;
                if (p.bytes().len != entry.len) return error.BadRegexPool;
                pool.max_capacity = pool.max_capacity.max(p.capacity());
            }
        }
        return pool;
    }

    /// The bytes `Scratch.initBuffer` needs for every program here, with `dfa_states` cached
    /// DFA states for the linear ones.
    pub fn scratchBytes(pool: RegexPool, dfa_states: u32) usize {
        const linear = std.mem.alignForward(usize, regex.Scratch.bytesNeeded(pool.capacity(dfa_states)), 8);
        return linear + if (pool.max_bt) |c| regex.bt.Scratch.bytesNeeded(c) else 0;
    }

    pub fn count(pool: RegexPool) usize {
        return pool.entries.len;
    }

    /// Program `i`, validated by `init`.
    pub fn get(pool: RegexPool, i: usize) Prog {
        const entry = pool.entries[i];
        const blob = pool.bytes[entry.offset..][0..entry.len];
        // The section is read-only and was validated by init: loading cannot fail.
        if (isBacktracking(blob)) return .{ .bt = regex.bt.Program.load(blob) catch unreachable };
        return .{ .linear = regex.Program.load(blob) catch unreachable };
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

fn isBacktracking(blob: []const u8) bool {
    return std.mem.startsWith(u8, blob, regex.bt.magic);
}

pub const Span = regex.program.Span;

/// Why a search could not decide: its step budget or (backtracking) its stack ran out, or the
/// scratch was sized for smaller programs. Never a "no match".
pub const MatchError = error{ BudgetExceeded, StackExhausted, ScratchTooSmall };

/// A program of either kind.
pub const Prog = union(enum) {
    linear: regex.Program,
    bt: regex.bt.Program,

    pub fn findFrom(p: *const Prog, s: *Scratch, input: []const u8, start: usize) MatchError!?Span {
        return switch (p.*) {
            .linear => |*l| l.findFrom(&s.linear, input, start) catch |e| mapErr(e),
            .bt => |*b| b.findFrom(try s.backtracking(), input, start) catch |e| mapErr(e),
        };
    }

    pub fn isMatch(p: *const Prog, s: *Scratch, input: []const u8) MatchError!bool {
        return switch (p.*) {
            .linear => |*l| l.isMatch(&s.linear, input) catch |e| mapErr(e),
            .bt => |*b| b.isMatch(try s.backtracking(), input) catch |e| mapErr(e),
        };
    }

    fn mapErr(e: anyerror) MatchError {
        return switch (e) {
            error.StackExhausted => error.StackExhausted,
            error.ScratchTooSmall => error.ScratchTooSmall,
            else => error.BudgetExceeded,
        };
    }
};

/// One worker's matching state for a pool: the linear programs' scratch and, when the pool has
/// backtracking programs, theirs.
pub const Scratch = struct {
    linear: regex.Scratch,
    bt: ?regex.bt.Scratch = null,

    /// In caller memory of `pool.scratchBytes(dfa_states)` bytes.
    pub fn initBuffer(buffer: []align(8) u8, pool: RegexPool, dfa_states: u32) error{BufferTooSmall}!Scratch {
        if (buffer.len < pool.scratchBytes(dfa_states)) return error.BufferTooSmall;
        const linear_len = std.mem.alignForward(usize, regex.Scratch.bytesNeeded(pool.capacity(dfa_states)), 8);
        var s: Scratch = .{ .linear = try regex.Scratch.initBuffer(buffer[0..linear_len], pool.capacity(dfa_states)) };
        if (pool.max_bt) |c| s.bt = try regex.bt.Scratch.initBuffer(@alignCast(buffer[linear_len..]), c);
        return s;
    }

    /// The same step budget for both kinds of search.
    pub fn setStepBudget(s: *Scratch, steps: u64) void {
        s.linear.step_budget = steps;
        if (s.bt) |*b| b.step_budget = steps;
    }

    fn backtracking(s: *Scratch) MatchError!*regex.bt.Scratch {
        if (s.bt) |*b| return b;
        return error.ScratchTooSmall;
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

    const mem = try gpa.alignedAlloc(u8, .@"8", pool.scratchBytes(256));
    defer gpa.free(mem);
    var scratch = try Scratch.initBuffer(mem, pool, 256);
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

test "backtracking programs share the pool; running out is an error, never a miss" {
    const gpa = std.testing.allocator;
    var a = try regex.Program.compile(gpa, "ab+c", .{ .bytes = true });
    defer a.deinit(gpa);
    var b = try regex.bt.Program.compile(gpa, "(?P<w>[a-z]+)-(?P=w)", .{ .bytes = true });
    defer b.deinit(gpa);
    var c = try regex.bt.Program.compile(gpa, "(a+)+$", .{ .bytes = true });
    defer c.deinit(gpa);
    const bytes = try build(gpa, &.{ a.bytes(), b.bytes(), c.bytes() });
    defer gpa.free(bytes);
    const image = try gpa.alignedAlloc(u8, .@"8", bytes.len);
    defer gpa.free(image);
    @memcpy(image, bytes);
    const pool = try RegexPool.init(image);
    try std.testing.expect(pool.max_bt != null);
    const mem = try gpa.alignedAlloc(u8, .@"8", pool.scratchBytes(64));
    defer gpa.free(mem);
    var scratch = try Scratch.initBuffer(mem, pool, 64);
    const p1 = pool.get(1);
    try std.testing.expect(try p1.isMatch(&scratch, "say abc-abc now"));
    try std.testing.expect(!try p1.isMatch(&scratch, "say abc-abd now"));
    try std.testing.expectEqual(@as(?Span, .{ .start = 4, .end = 11 }), try p1.findFrom(&scratch, "say abc-abc now", 0));
    scratch.setStepBudget(10_000);
    const p2 = pool.get(2);
    try std.testing.expectError(error.BudgetExceeded, p2.isMatch(&scratch, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"));
}
