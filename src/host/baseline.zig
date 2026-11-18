//! Drift baselines: what was true at the last accepted scan (authorized keys, SUID binaries,
//! systemd units, the kernel command line, bootloader files) so the next scan reports exactly
//! what was added or changed. Stored as text lines `kind<TAB>subject<TAB>value` under a versioned
//! header in the state directory.
//!
//! A kind with no entries in the stored baseline is new to it, so a first run records state and
//! reports nothing. Saving keeps the stored entries of kinds this run did not observe, so a run
//! filtered to some checks does not erase the others' baselines.
const std = @import("std");

pub const header = "zav-host-baseline 1\n";
pub const file_name = "baseline.zavb";
pub const max_bytes = 64 * 1024 * 1024;

pub const Baseline = struct {
    gpa: std.mem.Allocator,
    arena_state: std.heap.ArenaAllocator,
    /// "kind\tsubject\tvalue" lines from the stored file and from this run.
    old: std.StringHashMapUnmanaged(void) = .empty,
    new: std.StringHashMapUnmanaged(void) = .empty,
    /// "kind\tsubject" present in the stored file.
    old_subjects: std.StringHashMapUnmanaged(void) = .empty,
    old_kinds: std.StringHashMapUnmanaged(void) = .empty,
    new_kinds: std.StringHashMapUnmanaged(void) = .empty,
    /// A state directory exists, so drift can be tracked at all.
    enabled: bool = false,

    pub fn init(gpa: std.mem.Allocator) Baseline {
        return .{ .gpa = gpa, .arena_state = .init(gpa) };
    }

    pub fn deinit(b: *Baseline) void {
        b.old.deinit(b.gpa);
        b.new.deinit(b.gpa);
        b.old_subjects.deinit(b.gpa);
        b.old_kinds.deinit(b.gpa);
        b.new_kinds.deinit(b.gpa);
        b.arena_state.deinit();
    }

    fn arena(b: *Baseline) std.mem.Allocator {
        return b.arena_state.allocator();
    }

    pub fn load(b: *Baseline, io: std.Io, dir: std.Io.Dir) !void {
        b.enabled = true;
        const text = dir.readFileAlloc(io, file_name, b.arena(), .limited(max_bytes)) catch return;
        try b.loadText(text);
    }

    /// Parse stored text; malformed lines are skipped, a wrong header discards everything.
    pub fn loadText(b: *Baseline, text: []const u8) !void {
        b.enabled = true;
        if (!std.mem.startsWith(u8, text, header)) return;
        var lines = std.mem.splitScalar(u8, text[header.len..], '\n');
        while (lines.next()) |line| {
            const t1 = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
            const t2 = std.mem.indexOfScalarPos(u8, line, t1 + 1, '\t') orelse continue;
            try b.old.put(b.gpa, line, {});
            try b.old_subjects.put(b.gpa, line[0..t2], {});
            try b.old_kinds.put(b.gpa, line[0..t1], {});
        }
    }

    fn key(b: *Baseline, kind: []const u8, subject: []const u8, value: []const u8) ![]const u8 {
        return std.fmt.allocPrint(b.arena(), "{s}\t{s}\t{s}", .{ kind, clean(subject), clean(value) });
    }

    /// Record an observation for the next baseline.
    pub fn record(b: *Baseline, kind: []const u8, subject: []const u8, value: []const u8) !void {
        try b.new.put(b.gpa, try b.key(kind, subject, value), {});
        try b.new_kinds.put(b.gpa, try b.arena().dupe(u8, kind), {});
    }

    /// The stored baseline has this kind, so differences from it are drift.
    pub fn tracks(b: *const Baseline, kind: []const u8) bool {
        return b.old_kinds.contains(kind);
    }

    pub fn hasSubject(b: *Baseline, kind: []const u8, subject: []const u8) bool {
        var buf: [4096]u8 = undefined;
        const k = std.fmt.bufPrint(&buf, "{s}\t{s}", .{ kind, subject }) catch return false;
        return b.old_subjects.contains(k);
    }

    pub fn known(b: *Baseline, kind: []const u8, subject: []const u8, value: []const u8) bool {
        var buf: [8192]u8 = undefined;
        const k = std.fmt.bufPrint(&buf, "{s}\t{s}\t{s}", .{ kind, subject, value }) catch return false;
        return b.old.contains(k);
    }

    /// Record `value` and report whether it is new relative to a stored baseline that tracks the
    /// kind. False on a first run.
    pub fn observe(b: *Baseline, kind: []const u8, subject: []const u8, value: []const u8) !bool {
        try b.record(kind, subject, value);
        return b.tracks(kind) and !b.known(kind, subject, value);
    }

    /// Observed kinds the stored baseline does not track yet; a save adds them without
    /// accepting drift in the tracked ones.
    pub fn hasNewKinds(b: *const Baseline) bool {
        var it = b.new_kinds.keyIterator();
        while (it.next()) |k| if (!b.old_kinds.contains(k.*)) return true;
        return false;
    }

    /// The baseline to store. With `accept`, this run's observations replace the stored ones for
    /// every kind it observed; without, only kinds new to the baseline are added.
    pub fn serialize(b: *Baseline, out: *std.ArrayList(u8), accept: bool) !void {
        var lines: std.ArrayList([]const u8) = .empty;
        defer lines.deinit(b.gpa);
        var it = b.new.keyIterator();
        while (it.next()) |k| {
            const kind = k.*[0..std.mem.indexOfScalar(u8, k.*, '\t').?];
            if (accept or !b.old_kinds.contains(kind)) try lines.append(b.gpa, k.*);
        }
        var old = b.old.keyIterator();
        while (old.next()) |k| {
            const kind = k.*[0..std.mem.indexOfScalar(u8, k.*, '\t').?];
            if (!accept or !b.new_kinds.contains(kind)) try lines.append(b.gpa, k.*);
        }
        std.mem.sort([]const u8, lines.items, {}, struct {
            fn lt(_: void, x: []const u8, y: []const u8) bool {
                return std.mem.order(u8, x, y) == .lt;
            }
        }.lt);
        try out.appendSlice(b.gpa, header);
        for (lines.items) |l| {
            try out.appendSlice(b.gpa, l);
            try out.append(b.gpa, '\n');
        }
    }

    pub fn save(b: *Baseline, io: std.Io, dir: std.Io.Dir, accept: bool) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(b.gpa);
        try b.serialize(&out, accept);
        try dir.writeFile(io, .{ .sub_path = file_name ++ ".tmp", .data = out.items });
        try dir.rename(file_name ++ ".tmp", dir, file_name, io);
    }
};

/// Tabs and newlines would break the line format; values are hashes or paths in practice.
fn clean(text: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, text, "\t\n") orelse text.len;
    return text[0..end];
}

test "first run records, later runs report additions, partial runs keep other kinds" {
    const gpa = std.testing.allocator;
    var first = Baseline.init(gpa);
    defer first.deinit();
    try first.loadText("");
    try std.testing.expect(!try first.observe("ssh.key", "/root/.ssh/authorized_keys", "SHA256:aaa"));
    try std.testing.expect(!try first.observe("suid", "/usr/bin/sudo", "1"));
    var stored: std.ArrayList(u8) = .empty;
    defer stored.deinit(gpa);
    try std.testing.expect(first.hasNewKinds());
    try first.serialize(&stored, false);

    var second = Baseline.init(gpa);
    defer second.deinit();
    try second.loadText(stored.items);
    try std.testing.expect(!try second.observe("ssh.key", "/root/.ssh/authorized_keys", "SHA256:aaa"));
    try std.testing.expect(try second.observe("ssh.key", "/root/.ssh/authorized_keys", "SHA256:bbb"));
    try std.testing.expect(second.hasSubject("ssh.key", "/root/.ssh/authorized_keys"));
    try std.testing.expect(!second.hasNewKinds());
    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(gpa);
    try second.serialize(&kept, false); // not accepted: the drift stays reportable
    try std.testing.expect(std.mem.indexOf(u8, kept.items, "SHA256:bbb") == null);
    var again: std.ArrayList(u8) = .empty;
    defer again.deinit(gpa);
    try second.serialize(&again, true);
    // suid was not observed this run, so its stored entry survives.
    try std.testing.expect(std.mem.indexOf(u8, again.items, "suid\t/usr/bin/sudo\t1") != null);
    try std.testing.expect(std.mem.indexOf(u8, again.items, "SHA256:bbb") != null);

    var foreign = Baseline.init(gpa);
    defer foreign.deinit();
    try foreign.loadText("something else\nssh.key\tx\ty\n");
    try std.testing.expect(!foreign.tracks("ssh.key"));
}
