//! Native topology for the worker default and Linux affinity.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const cpu_limit = @sizeOf(linux.cpu_set_t) * 8;
pub const Selection = struct {
    cpus: [cpu_limit]u16 = undefined,
    cores: usize = 0,
    logical: usize = 0,
};

pub fn discover(gpa: std.mem.Allocator, io: std.Io) (std.mem.Allocator.Error || error{CpuTopologyUnavailable})!Selection {
    if (builtin.os.tag == .linux) return linuxSelection(io);
    if (builtin.os.tag == .windows) return .{ .cores = try windowsCoreCount(gpa) };
    if (builtin.os.tag.isDarwin()) {
        var physical: u32 = 0;
        var len: usize = @sizeOf(u32);
        if (std.c.sysctlbyname("hw.physicalcpu", &physical, &len, null, 0) != 0 or physical == 0)
            return error.CpuTopologyUnavailable;
        return .{ .cores = physical };
    }
    return error.CpuTopologyUnavailable;
}

fn linuxSelection(io: std.Io) !Selection {
    var allowed: linux.cpu_set_t = undefined;
    if (linux.errno(linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &allowed)) != .SUCCESS)
        return error.CpuTopologyUnavailable;
    var remaining = allowed;
    var out: Selection = .{};
    const cwd = std.Io.Dir.cwd();
    for (0..cpu_limit) |cpu| {
        if (!includes(remaining, cpu)) continue;
        out.cpus[out.cores] = @intCast(cpu);
        out.cores += 1;
        var path: [128]u8 = undefined;
        const name = std.fmt.bufPrint(&path, "/sys/devices/system/cpu/cpu{d}/topology/thread_siblings_list", .{cpu}) catch unreachable;
        var buf: [4096]u8 = undefined;
        const bytes = cwd.readFile(io, name, &buf) catch return error.CpuTopologyUnavailable;
        if (bytes.len == buf.len) return error.CpuTopologyUnavailable;
        try removeCpuList(&remaining, bytes);
    }
    if (out.cores == 0) return error.CpuTopologyUnavailable;
    // Assign one allowed CPU per physical core first. An explicit count can use
    // the remaining allowed siblings as well.
    out.logical = out.cores;
    for (out.cpus[0..out.cores]) |cpu| unset(&allowed, cpu);
    for (0..cpu_limit) |cpu| {
        if (!includes(allowed, cpu)) continue;
        out.cpus[out.logical] = @intCast(cpu);
        out.logical += 1;
    }
    return out;
}

const word_bits = @bitSizeOf(usize);

fn bit(cpu: usize) usize {
    return @as(usize, 1) << @intCast(cpu % word_bits);
}

fn includes(set: linux.cpu_set_t, cpu: usize) bool {
    return set[cpu / word_bits] & bit(cpu) != 0;
}

fn unset(set: *linux.cpu_set_t, cpu: usize) void {
    set[cpu / word_bits] &= ~bit(cpu);
}

fn removeCpuList(set: *linux.cpu_set_t, input: []const u8) !void {
    var entries = std.mem.splitScalar(u8, std.mem.trim(u8, input, " \t\r\n"), ',');
    while (entries.next()) |entry| {
        const dash = std.mem.indexOfScalar(u8, entry, '-');
        const first = std.fmt.parseInt(usize, entry[0 .. dash orelse entry.len], 10) catch return error.CpuTopologyUnavailable;
        const last = if (dash) |i| std.fmt.parseInt(usize, entry[i + 1 ..], 10) catch return error.CpuTopologyUnavailable else first;
        if (last < first) return error.CpuTopologyUnavailable;
        if (first >= cpu_limit) continue;
        for (first..@min(last, cpu_limit - 1) + 1) |cpu| unset(set, cpu);
    }
}

pub fn pinCurrent(cpu: u16) !void {
    if (builtin.os.tag != .linux) return error.CpuPinningUnavailable;
    var set: linux.cpu_set_t = @splat(0);
    set[cpu / word_bits] = bit(cpu);
    linux.sched_setaffinity(0, &set) catch return error.CpuPinningUnavailable;
}

// RelationProcessorCore returns one variable-sized record for each active core.
extern "kernel32" fn GetLogicalProcessorInformationEx(relationship: u32, buffer: ?[*]u8, len: *u32) callconv(.winapi) i32;

fn windowsCoreCount(gpa: std.mem.Allocator) !usize {
    var len: u32 = 0;
    _ = GetLogicalProcessorInformationEx(0, null, &len);
    if (len < 8) return error.CpuTopologyUnavailable;
    const buffer = try gpa.alignedAlloc(u8, .of(usize), len);
    defer gpa.free(buffer);
    if (GetLogicalProcessorInformationEx(0, buffer.ptr, &len) == 0 or len > buffer.len)
        return error.CpuTopologyUnavailable;
    var offset: usize = 0;
    var cores: usize = 0;
    while (offset < len) {
        if (len - offset < 8) return error.CpuTopologyUnavailable;
        const size = std.mem.readInt(u32, buffer[offset + 4 ..][0..4], .little);
        if (size < 8 or size > len - offset) return error.CpuTopologyUnavailable;
        cores += 1;
        offset += size;
    }
    if (cores == 0) return error.CpuTopologyUnavailable;
    return cores;
}

test "Linux sibling sets accept CPU numbers and ranges" {
    var cpus: linux.cpu_set_t = @splat(std.math.maxInt(usize));
    try removeCpuList(&cpus, "0,31-33,65-66\n");
    for ([_]usize{ 0, 31, 32, 33, 65, 66 }) |cpu| try std.testing.expect(!includes(cpus, cpu));
    for ([_]usize{ 1, 30, 34, 64, 67 }) |cpu| try std.testing.expect(includes(cpus, cpu));
}
