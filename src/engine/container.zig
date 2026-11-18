//! The container framework. A `Walker` takes one top-level object and streams it, and every child
//! a format parser finds inside it, through the same pipeline: raw bytes go to the `Visitor` (the
//! matcher), and the format dispatcher looks for children to recurse into.
//!
//! Children arrive as a `Source`: a positional range of the parent for stored members, or a
//! forward-only stream for decompressed ones. A stream child streams in blocks unless its format
//! needs random access; then it is materialised into the worker's scratch arena (8 MiB or less)
//! or an unlinked spill file (larger), which lives in the page cache, not anonymous memory.
//!
//! Every limit is enforced here and every limit hit is reported to the visitor as a `Notice`
//! carrying the container path ("a.zip/inner.docx/word/vbaProject.bin"); configuration decides
//! whether it is a verdict. Nothing is skipped silently.
const std = @import("std");
const Io = std.Io;
const source_mod = @import("source.zig");
const Source = source_mod.Source;
const Spill = source_mod.Spill;
const Scratch = @import("scratch.zig").Scratch;
const limits = @import("limits.zig");
const Budget = @import("budget.zig").Budget;
const detect = @import("../fmt/detect.zig");
pub const Format = detect.Format;
const cdb_match = @import("../match/container.zig");
const regex = @import("regex");

/// What the archive parsers need to check `.cdb` signatures: the table and a zig-regex scratch
/// sized for its filename regexes (`RegexPool.capacity`), owned by the worker.
pub const CdbHook = struct {
    table: cdb_match.CdbTable,
    scratch: ?*regex.Scratch = null,

    /// Check one member and report a match (or an undecidable regex) as a notice at the
    /// member's path. Callers push the member name first.
    pub fn check(hook: *const CdbHook, w: *Walker, member: cdb_match.Member) void {
        const sig = hook.table.check(member, hook.scratch) catch {
            w.limit(.regex_steps);
            return;
        } orelse return;
        w.notice(.{ .container_signature = sig }, "cdb");
    }
};

/// Block size for raw-byte feeding and stream buffers.
pub const block_len: usize = 64 * 1024;
/// Random-access children up to this size are held in scratch; larger ones spill.
pub const memory_child_max: u64 = 8 * 1024 * 1024;
pub const max_path_len = 1024;

pub const Kind = enum(u8) {
    root,
    /// An archive member (zip, tar, cpio).
    member,
    /// The output of a compression wrapper (gzip, bzip2, xz, zstd).
    decompressed,
    /// A region of an executable: a fat Mach-O slice, a PE overlay or resource.
    slice,
    /// Normaliser output: the streams target types 3 and 7 match against.
    normalized_html,
    normalized_text,
    /// A script extracted from HTML.
    script,
};

/// What a visitor is told about one object. `path` stays valid until the object's `leave`.
pub const Object = struct {
    path: []const u8,
    name: []const u8,
    depth: u8,
    kind: Kind,
    format: Format = .binary,
    /// Exact size for positional sources; a hint (untrusted header value) or null for streams.
    size: ?u64,
    entered: bool = false,
};

/// A reportable condition found while walking. Limits are the clamd-equivalent events; the other
/// kinds are format findings a heuristic or config may turn into a verdict.
pub const Notice = struct {
    what: What,
    path: []const u8,
    /// Format-specific detail (the reason, the method number, the heuristic name).
    detail: []const u8 = "",

    pub const What = union(enum) {
        limit: limits.Event,
        /// The object is damaged; whatever could be read was still scanned.
        malformed,
        /// An encrypted member: reported, not decrypted.
        encrypted,
        /// Archive members that share bytes (Heuristics.Zip.OverlappingFiles).
        overlap,
        /// Two views of an archive disagree (central directory and local headers).
        mismatch,
        /// A compression method or filter this engine does not decode.
        unsupported,
        /// A heuristic fired; `detail` holds its Heuristics.Guardian.* name.
        heuristic,
        /// A document that carries macros (an OOXML macro-enabled content type).
        macros,
        /// A reference to something outside the file (an OOXML external relationship target).
        external,
        /// An embedded object or package declared by the document.
        embedded,
        /// A container metadata (.cdb) signature matched this member: its signature id.
        container_signature: u32,
    };
};

pub const Visitor = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// Calls nest: a child's enter/data/leave arrive between its parent's enter and leave, and a
    /// parent's data may continue after a child is done.
    pub const VTable = struct {
        enter: *const fn (ptr: *anyopaque, obj: *const Object) error{Stop}!void,
        data: *const fn (ptr: *anyopaque, obj: *const Object, bytes: []const u8) error{Stop}!void,
        leave: *const fn (ptr: *anyopaque, obj: *const Object) void,
        notice: *const fn (ptr: *anyopaque, notice: Notice) void,
    };
};

/// Why a walk stopped early. `stop` is the visitor's choice (a detection with early exit); the
/// others are scan-wide limits, already reported as notices.
pub const Halt = enum { stop, scan_size, scan_time };

pub const Error = error{Halted};

/// Format dispatcher. Detects `obj`'s format, calls `Walker.begin`, feeds the raw bytes and
/// recurses into children. src/fmt/scan.zig is the real one.
pub const ParseFn = *const fn (w: *Walker, obj: *Object, src: Source) Error!void;

pub const Walker = struct {
    io: Io,
    scratch: *Scratch,
    tracker: *limits.Tracker,
    budget: *Budget,
    /// Where large random-access children spill.
    spill_dir: Io.Dir,
    visitor: Visitor,
    parse: ParseFn,
    options: Options = .{},
    path: PathStack = .{},
    halt: ?Halt = null,
    deadline: ?Io.Timestamp = null,

    pub const Options = struct {
        /// How long a decoder waits for a big-window token before reporting the limit.
        budget_wait_ms: u32 = 50,
        memory_child_max: u64 = memory_child_max,
        /// Heuristic detections (engine/heuristics.zig); null turns them off.
        heuristics: ?*const @import("heuristics.zig").Config = null,
        /// Container metadata signatures, checked once per member by the archive parsers.
        cdb: ?*const CdbHook = null,
    };

    /// Scan a top-level object. Limit events are reported as notices; error.Halted means the walk
    /// stopped early (see `halt`).
    pub fn scan(w: *Walker, src: Source, name: []const u8) Error!void {
        w.halt = null;
        w.path = .{};
        if (w.tracker.limits.max_scan_time_ms != 0) {
            const now = Io.Clock.awake.now(w.io);
            w.deadline = now.addDuration(.fromMilliseconds(@intCast(@min(w.tracker.limits.max_scan_time_ms, std.math.maxInt(i64)))));
        }
        w.path.push(name);
        defer w.path.pop();
        if (src.len()) |n| w.tracker.checkFileSize(n) catch return w.limit(.file_size);
        const mark = w.scratch.mark();
        defer w.scratch.release(mark);
        var obj: Object = .{ .path = w.path.get(), .name = name, .depth = 0, .kind = .root, .size = src.len() };
        defer w.end(&obj);
        try w.parse(w, &obj, src);
    }

    /// Scan a child of the object being parsed. Recursion, file count and size limits are checked
    /// here; the child's scratch allocations are released when it returns.
    pub fn child(w: *Walker, name: []const u8, src: Source, kind: Kind) Error!void {
        if (w.halt != null) return error.Halted;
        w.path.push(name);
        defer w.path.pop();
        w.tracker.enterContainer() catch return w.limit(.recursion);
        defer w.tracker.leaveContainer();
        w.tracker.addFile() catch {
            // Once per scan: every later sibling would raise it again.
            if (w.tracker.files == w.tracker.limits.max_files + 1) w.limit(.files) else w.tracker.note(.files);
            return;
        };
        if (src.len()) |n| w.tracker.checkFileSize(n) catch return w.limit(.file_size);
        const mark = w.scratch.mark();
        defer w.scratch.release(mark);
        var obj: Object = .{ .path = w.path.get(), .name = name, .depth = w.tracker.depth, .kind = kind, .size = src.len() };
        defer w.end(&obj);
        try w.parse(w, &obj, src);
    }

    /// Tell the visitor about `obj` once its format is known.
    pub fn begin(w: *Walker, obj: *Object) Error!void {
        if (obj.entered) return;
        w.visitor.vtable.enter(w.visitor.ptr, obj) catch return w.stop(.stop);
        obj.entered = true;
    }

    /// Open a derived stream of the object being parsed (normaliser output, an extracted
    /// script): a child that is fed directly with `feed` instead of being parsed. Close it with
    /// `endDerived`.
    pub fn beginDerived(w: *Walker, d: *Object, name: []const u8, kind: Kind) Error!void {
        w.path.push(name);
        d.* = .{ .path = w.path.get(), .name = name, .depth = w.tracker.depth +| 1, .kind = kind, .format = .text, .size = null };
        w.begin(d) catch |e| {
            w.path.pop();
            return e;
        };
    }

    pub fn endDerived(w: *Walker, d: *Object) void {
        w.end(d);
        w.path.pop();
    }

    fn end(w: *Walker, obj: *Object) void {
        if (obj.entered) w.visitor.vtable.leave(w.visitor.ptr, obj);
    }

    fn stop(w: *Walker, h: Halt) Error {
        if (w.halt == null) w.halt = h;
        return error.Halted;
    }

    /// Report a limit event at the current path.
    pub fn limit(w: *Walker, event: limits.Event) void {
        w.tracker.note(event);
        w.visitor.vtable.notice(w.visitor.ptr, .{ .what = .{ .limit = event }, .path = w.path.get() });
    }

    /// Report a format finding at the current path.
    pub fn notice(w: *Walker, what: Notice.What, detail: []const u8) void {
        if (what == .limit) w.tracker.note(what.limit);
        w.visitor.vtable.notice(w.visitor.ptr, .{ .what = what, .path = w.path.get(), .detail = detail });
    }

    /// Hand raw bytes of `obj` to the visitor, counting them against MaxScanSize and checking the
    /// scan deadline.
    pub fn feed(w: *Walker, obj: *const Object, bytes: []const u8) Error!void {
        if (w.halt != null) return error.Halted;
        if (bytes.len == 0) return;
        w.tracker.addScanned(bytes.len) catch {
            w.limit(.scan_size);
            return w.stop(.scan_size);
        };
        if (w.deadline) |d| if (Io.Clock.awake.now(w.io).nanoseconds > d.nanoseconds) {
            w.limit(.scan_time);
            return w.stop(.scan_time);
        };
        w.visitor.vtable.data(w.visitor.ptr, obj, bytes) catch return w.stop(.stop);
    }

    /// Feed every byte of a positional source.
    pub fn feedSource(w: *Walker, obj: *const Object, src: Source) Error!void {
        const total = src.len() orelse return;
        const block = w.alloc(u8, @intCast(@min(block_len, @max(total, 1)))) orelse return;
        defer w.free(block);
        var off: u64 = 0;
        while (off < total) {
            const n = src.readAt(w.io, off, block) catch {
                w.notice(.malformed, "read error");
                return;
            };
            if (n == 0) break;
            try w.feed(obj, block[0..n]);
            off += n;
        }
    }

    /// Feed whatever is left of a stream.
    pub fn drain(w: *Walker, r: *Io.Reader) Error!void {
        while (true) {
            _ = r.discard(.unlimited) catch |e| switch (e) {
                error.EndOfStream => return,
                error.ReadFailed => return if (w.halt != null) error.Halted else {},
            };
            if (w.halt != null) return error.Halted;
        }
    }

    /// Allocate from scratch; on exhaustion report the memory limit and return null.
    pub fn alloc(w: *Walker, comptime T: type, n: usize) ?[]T {
        return w.scratch.allocator().alloc(T, n) catch {
            w.limit(.memory);
            return null;
        };
    }

    /// Free the most recent allocation early (scratch is a bump allocator: only the last one is
    /// actually returned; everything else goes when the child finishes).
    pub fn free(w: *Walker, mem: anytype) void {
        w.scratch.allocator().free(mem);
    }

    /// A big-window token for a decoder window of `size` bytes plus `extra` bytes of tables.
    /// Windows over `max_window` raise window_size, an exhausted pool raises big_window_budget.
    /// Null means do not decode.
    pub fn window(w: *Walker, size: u64, extra: u64) ?Budget.Token {
        if (size > w.tracker.limits.max_window) {
            w.limit(.window_size);
            return null;
        }
        return w.budget.acquire(w.io, size + extra, w.options.budget_wait_ms) orelse {
            w.limit(.big_window_budget);
            return null;
        };
    }

    /// Copy a stream child into memory or a spill file so its format can be parsed positionally.
    /// Null means it exceeded MaxFileSize (reported) or could not be stored; the stream is then
    /// left partly consumed and the caller drains it.
    pub fn materialize(w: *Walker, r: *Io.Reader, size_hint: ?u64) Error!?Materialized {
        const max = w.tracker.limits.max_file_size;
        const mem_max = @min(w.options.memory_child_max, max);
        const first = @min(mem_max, size_hint orelse mem_max);
        var buf: []u8 = w.scratch.allocator().alloc(u8, @intCast(@max(first, 1))) catch &.{};
        var len: usize = 0;
        while (true) {
            if (len == buf.len) {
                if (buf.len >= mem_max) break;
                // Grow in place when the buffer is the last allocation, else switch to a spill.
                const want: usize = @intCast(@min(mem_max, @max(buf.len * 2, block_len)));
                if (buf.len != 0 and w.scratch.allocator().resize(buf, want)) {
                    buf = buf.ptr[0..want];
                } else break;
            }
            const n = readSome(r, buf[len..]) catch |e| switch (e) {
                error.EndOfStream => return .{ .source = .{ .memory = buf[0..len] } },
                error.ReadFailed => return if (w.halt != null) error.Halted else .{ .source = .{ .memory = buf[0..len] } },
            };
            len += n;
        }
        // Too big for scratch: spill.
        var spill = Spill.create(w.io, w.spill_dir) catch {
            w.limit(.memory);
            return null;
        };
        errdefer spill.close(w.io);
        spill.append(w.io, buf[0..len]) catch {
            w.limit(.memory);
            spill.close(w.io);
            return null;
        };
        if (buf.len != 0) w.free(buf);
        var block: [block_len]u8 = undefined;
        while (true) {
            const n = readSome(r, &block) catch |e| switch (e) {
                error.EndOfStream => break,
                error.ReadFailed => {
                    if (w.halt != null) return error.Halted;
                    break;
                },
            };
            if (spill.len + n > max) {
                w.limit(.file_size);
                spill.close(w.io);
                return null;
            }
            spill.append(w.io, block[0..n]) catch {
                w.limit(.memory);
                spill.close(w.io);
                return null;
            };
        }
        return .{ .source = spill.source(), .spill = spill };
    }

    pub const Materialized = struct {
        source: Source,
        spill: ?Spill = null,

        pub fn deinit(m: *Materialized, io: Io) void {
            if (m.spill) |*s| s.close(io);
        }
    };
};

/// Read at least one byte into `dest` (EndOfStream at the end).
pub fn readSome(r: *Io.Reader, dest: []u8) Io.Reader.Error!usize {
    while (true) {
        var vec: [1][]u8 = .{dest};
        const n = try r.readVec(&vec);
        if (n != 0) return n;
    }
}

/// The container path: names joined by '/', one segment per depth. Over-long paths are cut and
/// marked with "..." rather than failing; control bytes in names print as '?'.
pub const PathStack = struct {
    buf: [max_path_len]u8 = undefined,
    len: usize = 0,
    marks: [256]u16 = undefined,
    depth: usize = 0,

    pub fn push(p: *PathStack, name: []const u8) void {
        p.marks[p.depth] = @intCast(p.len);
        p.depth += 1;
        if (p.len != 0) p.append("/");
        if (name.len == 0) return p.append("?");
        const room = max_path_len - p.len;
        if (name.len > room) {
            if (room > 3) {
                p.append(name[0 .. room - 3]);
                p.append("...");
            }
            return;
        }
        p.append(name);
    }

    fn append(p: *PathStack, bytes: []const u8) void {
        const n = @min(bytes.len, max_path_len - p.len);
        for (bytes[0..n], p.buf[p.len..][0..n]) |c, *d| d.* = if (c < 0x20 or c == 0x7f) '?' else c;
        p.len += n;
    }

    pub fn pop(p: *PathStack) void {
        p.depth -= 1;
        p.len = p.marks[p.depth];
    }

    pub fn get(p: *const PathStack) []const u8 {
        return p.buf[0..p.len];
    }
};

/// Build the vtable for an `Io.Reader` whose implementation only appends bytes to its own buffer:
/// `Impl.fill(self, dest) Io.Reader.Error!usize`, 0 meaning end of stream. `Impl` keeps the
/// reader in a field named `interface`.
pub fn fillVTable(comptime Impl: type) *const Io.Reader.VTable {
    return &struct {
        const vt: Io.Reader.VTable = .{ .stream = stream, .readVec = readVec, .discard = discard };

        fn refill(r: *Io.Reader) Io.Reader.Error!void {
            if (r.seek != 0) {
                const live = r.end - r.seek;
                std.mem.copyForwards(u8, r.buffer[0..live], r.buffer[r.seek..r.end]);
                r.seek = 0;
                r.end = live;
            }
            if (r.end == r.buffer.len) return;
            const self: *Impl = @alignCast(@fieldParentPtr("interface", r));
            const n = try self.fill(r.buffer[r.end..]);
            if (n == 0) return error.EndOfStream;
            r.end += n;
        }

        fn stream(r: *Io.Reader, w: *Io.Writer, lim: Io.Limit) Io.Reader.StreamError!usize {
            if (r.buffer.len == 0) {
                // Unbuffered: decode straight into the writer.
                const dest = lim.slice(try w.writableSliceGreedy(1));
                const self: *Impl = @alignCast(@fieldParentPtr("interface", r));
                const n = try self.fill(dest);
                if (n == 0) return error.EndOfStream;
                w.advance(n);
                return n;
            }
            try refill(r);
            return 0;
        }

        fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
            if (data[0].len != 0 and r.seek == r.end) {
                // The buffer is drained: fill the caller's slice directly, saving a copy.
                r.seek = 0;
                r.end = 0;
                const self: *Impl = @alignCast(@fieldParentPtr("interface", r));
                const n = try self.fill(data[0]);
                if (n == 0) return error.EndOfStream;
                return n;
            }
            try refill(r);
            return 0;
        }

        fn discard(r: *Io.Reader, lim: Io.Limit) Io.Reader.Error!usize {
            r.seek = 0;
            r.end = 0;
            try refill(r);
            const n = lim.minInt(r.end);
            r.seek = n;
            return n;
        }
    }.vt;
}

/// A buffered forward reader over a positional source. `pulled` counts bytes read from the
/// source (the compressed-side count a `Meter` uses). Discards skip without reading.
pub const SourceReader = struct {
    io: Io,
    src: Source,
    pulled: u64 = 0,
    err: ?Source.ReadError = null,
    interface: Io.Reader,

    pub fn init(io: Io, src: Source, buffer: []u8) SourceReader {
        return .{ .io = io, .src = src, .interface = .{ .vtable = &vtable, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    const vtable: Io.Reader.VTable = .{
        .stream = fillVTable(SourceReader).stream,
        .readVec = fillVTable(SourceReader).readVec,
        .discard = skip,
    };

    pub fn fill(sr: *SourceReader, dest: []u8) Io.Reader.Error!usize {
        const n = sr.src.readAt(sr.io, sr.pulled, dest) catch |e| {
            sr.err = e;
            return error.ReadFailed;
        };
        sr.pulled += n;
        return n;
    }

    fn skip(r: *Io.Reader, lim: Io.Limit) Io.Reader.Error!usize {
        const sr: *SourceReader = @alignCast(@fieldParentPtr("interface", r));
        const total = sr.src.len() orelse 0;
        const n: u64 = @min(total -| sr.pulled, lim.toInt() orelse std.math.maxInt(u64));
        if (n == 0) return error.EndOfStream;
        sr.pulled += n;
        return @intCast(n);
    }
};

/// Passes a stream through to its consumer while feeding every byte to the visitor as raw data
/// of `obj`. This is how one pass over a decompressed stream both scans it and parses it.
pub const Tee = struct {
    walker: *Walker,
    obj: *const Object,
    inner: *Io.Reader,
    pulled: u64 = 0,
    interface: Io.Reader,

    pub fn init(walker: *Walker, obj: *const Object, inner: *Io.Reader, buffer: []u8) Tee {
        return .{ .walker = walker, .obj = obj, .inner = inner, .interface = .{ .vtable = fillVTable(Tee), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(t: *Tee, dest: []u8) Io.Reader.Error!usize {
        const n = readSome(t.inner, dest) catch |e| switch (e) {
            error.EndOfStream => return 0,
            error.ReadFailed => return error.ReadFailed,
        };
        t.walker.feed(t.obj, dest[0..n]) catch return error.ReadFailed;
        t.pulled += n;
        return n;
    }
};

/// Guards a decoder's output: the member's expansion ratio (100:1 once past 1 MiB by default),
/// MaxFileSize for the member, and the scan's total decompressed output. When a limit trips the
/// stream fails with ReadFailed and `tripped` names the event (already reported).
pub const Meter = struct {
    walker: *Walker,
    inner: *Io.Reader,
    /// Compressed bytes read so far by the decoder's input, and the value when this member began.
    compressed: *const u64,
    compressed_base: u64,
    out: u64 = 0,
    tripped: ?limits.Event = null,
    interface: Io.Reader,

    pub fn init(walker: *Walker, inner: *Io.Reader, compressed: *const u64, buffer: []u8) Meter {
        return .{
            .walker = walker,
            .inner = inner,
            .compressed = compressed,
            .compressed_base = compressed.*,
            .interface = .{ .vtable = fillVTable(Meter), .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    pub fn fill(m: *Meter, dest: []u8) Io.Reader.Error!usize {
        if (m.tripped != null) return error.ReadFailed;
        const n = readSome(m.inner, dest) catch |e| switch (e) {
            error.EndOfStream => return 0,
            error.ReadFailed => return error.ReadFailed,
        };
        const t = m.walker.tracker;
        if (m.out + n > t.limits.max_file_size) return m.trip(.file_size);
        t.addOutput(m.compressed.* - m.compressed_base, m.out, n) catch return m.trip(t.last.?);
        m.out += n;
        return n;
    }

    fn trip(m: *Meter, event: limits.Event) error{ReadFailed} {
        m.tripped = event;
        m.walker.limit(event);
        return error.ReadFailed;
    }
};

/// A visitor that records what it sees: paths, formats, byte counts and notices. For tests,
/// tools and diagnostics; it allocates.
pub const Recorder = struct {
    gpa: std.mem.Allocator,
    objects: std.ArrayList(Entry) = .empty,
    notices: std.ArrayList(NoticeEntry) = .empty,
    /// Bytes of the current open objects, by depth.
    open: [256]u64 = @splat(0),
    open_hash: [256]std.hash.Crc32 = undefined,
    stop_at: ?[]const u8 = null,

    pub const Entry = struct {
        path: []u8,
        format: Format,
        kind: Kind,
        depth: u8,
        bytes: u64 = 0,
        crc: u32 = 0,
    };
    pub const NoticeEntry = struct { what: Notice.What, path: []u8, detail: []u8 };

    pub fn deinit(r: *Recorder) void {
        for (r.objects.items) |e| r.gpa.free(e.path);
        for (r.notices.items) |n| {
            r.gpa.free(n.path);
            r.gpa.free(n.detail);
        }
        r.objects.deinit(r.gpa);
        r.notices.deinit(r.gpa);
    }

    pub fn visitor(r: *Recorder) Visitor {
        return .{ .ptr = r, .vtable = &.{ .enter = enter, .data = data, .leave = leave, .notice = onNotice } };
    }

    fn enter(ptr: *anyopaque, obj: *const Object) error{Stop}!void {
        const r: *Recorder = @ptrCast(@alignCast(ptr));
        r.open[obj.depth] = 0;
        r.open_hash[obj.depth] = .init();
        const path = r.gpa.dupe(u8, obj.path) catch return error.Stop;
        r.objects.append(r.gpa, .{ .path = path, .format = obj.format, .kind = obj.kind, .depth = obj.depth }) catch return error.Stop;
    }

    fn data(ptr: *anyopaque, obj: *const Object, bytes: []const u8) error{Stop}!void {
        const r: *Recorder = @ptrCast(@alignCast(ptr));
        r.open[obj.depth] += bytes.len;
        r.open_hash[obj.depth].update(bytes);
        if (r.stop_at) |needle| if (std.mem.indexOf(u8, bytes, needle) != null) return error.Stop;
    }

    fn leave(ptr: *anyopaque, obj: *const Object) void {
        const r: *Recorder = @ptrCast(@alignCast(ptr));
        var i = r.objects.items.len;
        while (i > 0) {
            i -= 1;
            const e = &r.objects.items[i];
            if (e.depth == obj.depth and std.mem.eql(u8, e.path, obj.path)) {
                e.bytes = r.open[obj.depth];
                e.crc = r.open_hash[obj.depth].final();
                e.format = obj.format;
                return;
            }
        }
    }

    fn onNotice(ptr: *anyopaque, n: Notice) void {
        const r: *Recorder = @ptrCast(@alignCast(ptr));
        const path = r.gpa.dupe(u8, n.path) catch return;
        const detail = r.gpa.dupe(u8, n.detail) catch {
            r.gpa.free(path);
            return;
        };
        r.notices.append(r.gpa, .{ .what = n.what, .path = path, .detail = detail }) catch {
            r.gpa.free(path);
            r.gpa.free(detail);
        };
    }

    pub fn find(r: *const Recorder, path: []const u8) ?Entry {
        for (r.objects.items) |e| if (std.mem.eql(u8, e.path, path)) return e;
        return null;
    }

    pub fn hasLimit(r: *const Recorder, event: limits.Event) bool {
        for (r.notices.items) |n| if (n.what == .limit and n.what.limit == event) return true;
        return false;
    }

    pub fn has(r: *const Recorder, what: std.meta.Tag(Notice.What)) bool {
        for (r.notices.items) |n| if (n.what == what) return true;
        return false;
    }

    /// Print everything recorded (debugging a test).
    pub fn dump(r: *const Recorder) void {
        for (r.objects.items) |e| std.debug.print("obj {s} {t} {t} d{d} {d}B\n", .{ e.path, e.format, e.kind, e.depth, e.bytes });
        for (r.notices.items) |n| std.debug.print("notice {any} {s} {s}\n", .{ n.what, n.path, n.detail });
    }
};

// Tests use a toy container format so the framework is exercised without any real parser:
//   "NEST" count:u8 { name_len:u8 name len:u32le bytes }*   members stored, read positionally
//   "RLE1" { run:u16le byte }*                              a decompressor: child is a stream
//   "WIN!" bytes:u32le                                      needs a decoder window of `bytes`
// RLE output that needs random access (a NEST) is materialised, which is the spill path.
const toy = struct {
    fn parse(w: *Walker, obj: *Object, src: Source) Error!void {
        var head: [8]u8 = @splat(0);
        var seek_reader: SourceReader = undefined;
        var tee: Tee = undefined;
        var mat: ?Walker.Materialized = null;
        defer if (mat) |*m| m.deinit(w.io);
        var positional = src;
        switch (src) {
            .stream => |st| {
                const peeked = st.reader.peekGreedy(4) catch st.reader.buffered();
                @memcpy(head[0..@min(4, peeked.len)], peeked[0..@min(4, peeked.len)]);
                obj.format = if (std.mem.eql(u8, head[0..4], "NEST")) .zip else .binary;
                try w.begin(obj);
                const tee_buf = w.alloc(u8, block_len) orelse return;
                tee = .init(w, obj, st.reader, tee_buf);
                if (obj.format != .zip) {
                    if (std.mem.eql(u8, head[0..4], "RLE1")) return rle(w, &tee.interface, &tee.pulled);
                    return w.drain(&tee.interface);
                }
                mat = try w.materialize(&tee.interface, st.len_hint) orelse return w.drain(&tee.interface);
                positional = mat.?.source;
            },
            else => {
                _ = src.readAt(w.io, 0, &head) catch 0;
                obj.format = if (std.mem.eql(u8, head[0..4], "NEST")) .zip else .binary;
                try w.begin(obj);
                try w.feedSource(obj, src);
            },
        }
        if (std.mem.eql(u8, head[0..4], "NEST")) return nest(w, positional);
        if (std.mem.eql(u8, head[0..4], "WIN!")) {
            const bytes = std.mem.readInt(u32, head[4..8], .little);
            const token = w.window(bytes, 0) orelse return;
            defer token.release();
            const win = w.alloc(u8, bytes) orelse return;
            @memset(win, 0);
            return;
        }
        if (std.mem.eql(u8, head[0..4], "RLE1")) {
            const buf = w.alloc(u8, block_len) orelse return;
            seek_reader = .init(w.io, src, buf);
            return rle(w, &seek_reader.interface, &seek_reader.pulled);
        }
    }

    fn nest(w: *Walker, src: Source) Error!void {
        var hdr: [5]u8 = undefined;
        src.readAllAt(w.io, 0, &hdr) catch return w.notice(.malformed, "nest");
        var off: u64 = 5;
        for (0..hdr[4]) |_| {
            var nl: [1]u8 = undefined;
            src.readAllAt(w.io, off, &nl) catch return w.notice(.malformed, "nest");
            var name: [255]u8 = undefined;
            src.readAllAt(w.io, off + 1, name[0..nl[0]]) catch return w.notice(.malformed, "nest");
            var lb: [4]u8 = undefined;
            src.readAllAt(w.io, off + 1 + nl[0], &lb) catch return w.notice(.malformed, "nest");
            const len = std.mem.readInt(u32, &lb, .little);
            const body = src.slice(off + 5 + nl[0], len) catch return w.notice(.malformed, "nest");
            try w.child(name[0..nl[0]], body, .member);
            off += 5 + nl[0] + len;
        }
    }

    const Rle = struct {
        in: *Io.Reader,
        run: u16 = 0,
        byte: u8 = 0,
        interface: Io.Reader,

        pub fn fill(d: *Rle, dest: []u8) Io.Reader.Error!usize {
            if (d.run == 0) {
                const rec = d.in.takeArray(3) catch |e| switch (e) {
                    error.EndOfStream => return 0,
                    else => return e,
                };
                d.run = std.mem.readInt(u16, rec[0..2], .little);
                d.byte = rec[2];
            }
            const n = @min(dest.len, d.run);
            @memset(dest[0..n], d.byte);
            d.run -= @intCast(n);
            return n;
        }
    };

    fn rle(w: *Walker, in: *Io.Reader, pulled: *const u64) Error!void {
        in.discardAll(4) catch return;
        var dec: Rle = .{ .in = in, .interface = .{ .vtable = fillVTable(Rle), .buffer = &.{}, .seek = 0, .end = 0 } };
        const buf = w.alloc(u8, block_len) orelse return;
        var meter: Meter = .init(w, &dec.interface, pulled, buf);
        try w.child("rle", .{ .stream = .{ .reader = &meter.interface } }, .decompressed);
    }
};

fn nestBytes(gpa: std.mem.Allocator, members: []const struct { []const u8, []const u8 }) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "NEST");
    try out.append(gpa, @intCast(members.len));
    for (members) |m| {
        try out.append(gpa, @intCast(m[0].len));
        try out.appendSlice(gpa, m[0]);
        var lb: [4]u8 = undefined;
        std.mem.writeInt(u32, &lb, @intCast(m[1].len), .little);
        try out.appendSlice(gpa, &lb);
        try out.appendSlice(gpa, m[1]);
    }
    return out.toOwnedSlice(gpa);
}

fn rleBytes(gpa: std.mem.Allocator, runs: []const struct { u16, u8 }) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "RLE1");
    for (runs) |r| {
        var b: [3]u8 = undefined;
        std.mem.writeInt(u16, b[0..2], r[0], .little);
        b[2] = r[1];
        try out.appendSlice(gpa, &b);
    }
    return out.toOwnedSlice(gpa);
}

const TestRig = struct {
    scratch: Scratch,
    tracker: limits.Tracker,
    budget: Budget,
    rec: Recorder,
    tmp: std.testing.TmpDir,
    walker: Walker,

    fn init(rig: *TestRig, lim: limits.Limits, budget_capacity: u64) !void {
        rig.scratch = try Scratch.init(32 * 1024 * 1024);
        rig.tracker = .init(lim);
        rig.budget = .init(budget_capacity);
        rig.rec = .{ .gpa = std.testing.allocator };
        rig.tmp = std.testing.tmpDir(.{});
        rig.walker = .{
            .io = std.testing.io,
            .scratch = &rig.scratch,
            .tracker = &rig.tracker,
            .budget = &rig.budget,
            .spill_dir = rig.tmp.dir,
            .visitor = rig.rec.visitor(),
            .parse = toy.parse,
            .options = .{ .budget_wait_ms = 1 },
        };
    }

    fn deinit(rig: *TestRig) void {
        rig.rec.deinit();
        rig.tmp.cleanup();
        rig.scratch.deinit();
    }
};

test "nested containers report correct paths and bytes" {
    const gpa = std.testing.allocator;
    const inner = try nestBytes(gpa, &.{ .{ "a.txt", "hello" }, .{ "b.bin", "world!" } });
    defer gpa.free(inner);
    const outer = try nestBytes(gpa, &.{ .{ "inner.nest", inner }, .{ "c", "x" } });
    defer gpa.free(outer);
    var rig: TestRig = undefined;
    try rig.init(.{}, 64 << 20);
    defer rig.deinit();
    try rig.walker.scan(.{ .memory = outer }, "outer.nest");
    try std.testing.expectEqual(@as(usize, 5), rig.rec.objects.items.len);
    try std.testing.expectEqual(@as(u64, 5), rig.rec.find("outer.nest/inner.nest/a.txt").?.bytes);
    try std.testing.expectEqual(@as(u64, 6), rig.rec.find("outer.nest/inner.nest/b.bin").?.bytes);
    try std.testing.expectEqual(@as(u8, 2), rig.rec.find("outer.nest/inner.nest/b.bin").?.depth);
    try std.testing.expectEqual(@as(u64, 1), rig.rec.find("outer.nest/c").?.bytes);
    try std.testing.expectEqual(@as(u64, outer.len), rig.rec.find("outer.nest").?.bytes);
    try std.testing.expectEqual(@as(usize, 0), rig.rec.notices.items.len);
    // The child working sets were released.
    try std.testing.expectEqual(@as(usize, 0), rig.scratch.used());
}

test "recursion limit stops descent and is reported at the deepest path" {
    const gpa = std.testing.allocator;
    var cur = try gpa.dupe(u8, "leaf");
    for (0..6) |_| {
        const next = try nestBytes(gpa, &.{.{ "n", cur }});
        gpa.free(cur);
        cur = next;
    }
    defer gpa.free(cur);
    var rig: TestRig = undefined;
    try rig.init(.{ .max_recursion = 3 }, 64 << 20);
    defer rig.deinit();
    try rig.walker.scan(.{ .memory = cur }, "top");
    try std.testing.expect(rig.rec.hasLimit(.recursion));
    try std.testing.expectEqualStrings("top/n/n/n/n", rig.rec.notices.items[0].path);
    try std.testing.expect(rig.rec.find("top/n/n/n") != null);
    try std.testing.expect(rig.rec.find("top/n/n/n/n") == null);
}

test "file count, file size and scan size limits" {
    const gpa = std.testing.allocator;
    const many = try nestBytes(gpa, &.{ .{ "1", "a" }, .{ "2", "b" }, .{ "3", "c" }, .{ "4", "d" } });
    defer gpa.free(many);
    {
        var rig: TestRig = undefined;
        try rig.init(.{ .max_files = 2 }, 64 << 20);
        defer rig.deinit();
        try rig.walker.scan(.{ .memory = many }, "m");
        try std.testing.expect(rig.rec.hasLimit(.files));
        try std.testing.expect(rig.rec.find("m/2") != null);
        try std.testing.expect(rig.rec.find("m/3") == null);
        // Reported once, at the first member over the limit.
        try std.testing.expectEqual(@as(usize, 1), rig.rec.notices.items.len);
        try std.testing.expectEqualStrings("m/3", rig.rec.notices.items[0].path);
    }
    const sized = try nestBytes(gpa, &.{ .{ "small", "abc" }, .{ "big", "0123456789" } });
    defer gpa.free(sized);
    {
        // MaxFileSize at the top level: skipped and reported, nothing entered.
        var rig: TestRig = undefined;
        try rig.init(.{ .max_file_size = 16 }, 64 << 20);
        defer rig.deinit();
        try rig.walker.scan(.{ .memory = sized }, "s");
        try std.testing.expect(rig.rec.hasLimit(.file_size));
        try std.testing.expectEqual(@as(usize, 0), rig.rec.objects.items.len);
    }
    {
        var rig: TestRig = undefined;
        try rig.init(.{ .max_scan_size = 20 }, 64 << 20);
        defer rig.deinit();
        try std.testing.expectError(error.Halted, rig.walker.scan(.{ .memory = sized }, "s"));
        try std.testing.expectEqual(Halt.scan_size, rig.walker.halt.?);
        try std.testing.expect(rig.rec.hasLimit(.scan_size));
    }
}

test "decompressed children: ratio guard, total output and member size" {
    const gpa = std.testing.allocator;
    // 4 runs of 65535 zero bytes from 16 compressed bytes: past a 64 KiB floor at 16000:1.
    const bomb = try rleBytes(gpa, &.{ .{ 65535, 0 }, .{ 65535, 0 }, .{ 65535, 0 }, .{ 65535, 0 } });
    defer gpa.free(bomb);
    {
        var rig: TestRig = undefined;
        try rig.init(.{ .ratio_floor = 64 * 1024, .max_ratio = 100 }, 64 << 20);
        defer rig.deinit();
        try rig.walker.scan(.{ .memory = bomb }, "bomb.rle");
        try std.testing.expect(rig.rec.hasLimit(.ratio));
        try std.testing.expectEqualStrings("bomb.rle/rle", rig.rec.notices.items[0].path);
        // Output stopped near the floor, not at the full 256 KiB.
        try std.testing.expect(rig.rec.find("bomb.rle/rle").?.bytes <= 128 * 1024);
    }
    {
        var rig: TestRig = undefined;
        try rig.init(.{ .max_total_output = 100_000, .max_ratio = 1_000_000 }, 64 << 20);
        defer rig.deinit();
        try rig.walker.scan(.{ .memory = bomb }, "bomb.rle");
        try std.testing.expect(rig.rec.hasLimit(.total_output));
    }
    {
        var rig: TestRig = undefined;
        try rig.init(.{ .max_file_size = 70_000, .max_ratio = 1_000_000 }, 64 << 20);
        defer rig.deinit();
        try rig.walker.scan(.{ .memory = bomb }, "bomb.rle");
        try std.testing.expect(rig.rec.hasLimit(.file_size));
    }
}

test "stream children needing random access go to scratch or a spill file" {
    const gpa = std.testing.allocator;
    // RLE output that is itself a NEST: "NEST" 1 member "z" of 200 KiB of 'Z'.
    var runs: std.ArrayList(struct { u16, u8 }) = .empty;
    defer runs.deinit(gpa);
    for ("NEST\x01\x01z") |c| try runs.append(gpa, .{ 1, c });
    const member_len: u32 = 200 * 1024;
    var lb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lb, member_len, .little);
    for (lb) |c| try runs.append(gpa, .{ 1, c });
    var left: u32 = member_len;
    while (left > 0) {
        const n: u16 = @intCast(@min(left, 60000));
        try runs.append(gpa, .{ n, 'Z' });
        left -= n;
    }
    const packed_bytes = try rleBytes(gpa, runs.items);
    defer gpa.free(packed_bytes);
    for ([_]u64{ memory_child_max, 64 * 1024 }) |mem_max| {
        var rig: TestRig = undefined;
        try rig.init(.{ .max_ratio = 1_000_000 }, 64 << 20);
        defer rig.deinit();
        rig.walker.options.memory_child_max = mem_max;
        try rig.walker.scan(.{ .memory = packed_bytes }, "p.rle");
        const z = rig.rec.find("p.rle/rle/z") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(u64, member_len), z.bytes);
        try std.testing.expectEqual(Format.zip, rig.rec.find("p.rle/rle").?.format);
        try std.testing.expectEqual(@as(usize, 0), rig.rec.notices.items.len);
    }
}

test "big windows need a budget token; an exhausted budget costs no memory" {
    var rig: TestRig = undefined;
    try rig.init(.{}, 4 * 1024 * 1024);
    defer rig.deinit();
    // A window the pool can cover.
    try rig.walker.scan(.{ .memory = "WIN!\x00\x00\x30\x00" }, "w3m");
    try std.testing.expect(!rig.rec.hasLimit(.big_window_budget));
    try std.testing.expect(rig.scratch.high_water >= 3 * 1024 * 1024);
    // Exhaust the pool, then ask again: limit event, and scratch does not grow.
    const held = rig.budget.tryAcquire(4 * 1024 * 1024).?;
    defer held.release();
    rig.scratch.high_water = 0;
    try rig.walker.scan(.{ .memory = "WIN!\x00\x00\x30\x00" }, "w3m");
    try std.testing.expect(rig.rec.hasLimit(.big_window_budget));
    rig.scratch.reset();
    try std.testing.expect(rig.scratch.high_water < 64 * 1024);
    // A window over max_window is refused outright.
    try rig.walker.scan(.{ .memory = "WIN!\x00\x00\x00\x10" }, "w256m");
    try std.testing.expect(rig.rec.hasLimit(.window_size));
}

test "a visitor stop halts the walk" {
    const gpa = std.testing.allocator;
    const many = try nestBytes(gpa, &.{ .{ "1", "aaa" }, .{ "2", "EVIL" }, .{ "3", "ccc" } });
    defer gpa.free(many);
    var rig: TestRig = undefined;
    try rig.init(.{}, 64 << 20);
    defer rig.deinit();
    rig.rec.stop_at = "EVIL";
    try std.testing.expectError(error.Halted, rig.walker.scan(.{ .memory = many }, "m"));
    try std.testing.expectEqual(Halt.stop, rig.walker.halt.?);
}

test "path stack truncates and sanitises" {
    var p: PathStack = .{};
    p.push("a.zip");
    p.push("dir/x\x01y");
    try std.testing.expectEqualStrings("a.zip/dir/x?y", p.get());
    p.pop();
    try std.testing.expectEqualStrings("a.zip", p.get());
    p.push(&(@as([2000]u8, @splat('q'))));
    try std.testing.expectEqual(@as(usize, max_path_len), p.get().len);
    try std.testing.expect(std.mem.endsWith(u8, p.get(), "..."));
    p.pop();
    p.push("");
    try std.testing.expectEqualStrings("a.zip/?", p.get());
}
