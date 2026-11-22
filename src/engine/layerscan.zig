//! The per-layer scan model used by the differential tools. Removed pending a clean-room rewrite
//! (docs/clean-room.md); this stub keeps the public interface compiling and scans nothing.
const std = @import("std");
const Io = std.Io;
const db = @import("../db/root.zig");
const bodyscan = @import("bodyscan.zig");
const hashscan = @import("hashscan.zig");
const limits = @import("limits.zig");
const ftm = @import("../fmt/ftm.zig");
const types = @import("../fmt/types.zig");
const detect = @import("../fmt/detect.zig");
const pe = @import("../fmt/pe.zig");
const elf = @import("../fmt/elf.zig");
const macho = @import("../fmt/macho.zig");
const html_norm = @import("../fmt/html_norm.zig");
const prog = @import("../match/prog.zig");
const vm = @import("../match/verify_vm.zig");

pub const Engine = struct {
    database: db.reader.Database,
    body: bodyscan.BodyIndex,
    hashes: hashscan.HashIndex,
    types: ?ftm.Ftm = null,

    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, options: db.reader.OpenOptions) !Engine {
        _ = gpa;
        const database = try db.reader.open(io, dir, path, options);
        errdefer database.close();
        var e: Engine = .{ .database = database, .body = try .load(database), .hashes = try .load(database) };
        if (database.section(.ftm_trie, 0)) |section| {
            const progs: ?prog.Programs = if (database.section(.subsig_prog, 1)) |p| try .init(p) else null;
            e.types = try .init(section, progs);
        }
        return e;
    }

    pub fn close(e: *Engine, gpa: std.mem.Allocator) void {
        _ = gpa;
        e.database.close();
    }

    pub fn fileType(e: *const Engine, data: []const u8) ?types.ClType {
        const f = e.types orelse return null;
        var budget: vm.Budget = .{};
        return ftm.classify(f, data, .{}, &budget).type;
    }
};

pub const Result = union(enum) {
    clean,
    found: u32,
    limited: limits.Event,
};

pub const Classified = struct {
    format: detect.Format,
    file: bodyscan.File,
};

pub const Scanner = struct {
    gpa: std.mem.Allocator,
    io: Io,
    pe_sections: []pe.Section,
    elf_segments: []elf.Segment,
    elf_sections: []elf.Section,
    macho_segments: []macho.Segment,
    macho_sections: []macho.Section,

    pub fn init(gpa: std.mem.Allocator, io: Io) !*Scanner {
        const s = try gpa.create(Scanner);
        errdefer gpa.destroy(s);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .pe_sections = try gpa.alloc(pe.Section, pe.max_sections),
            .elf_segments = try gpa.alloc(elf.Segment, elf.max_headers),
            .elf_sections = try gpa.alloc(elf.Section, elf.max_headers),
            .macho_segments = try gpa.alloc(macho.Segment, macho.max_segments),
            .macho_sections = try gpa.alloc(macho.Section, macho.max_sections),
        };
        return s;
    }

    pub fn deinit(s: *Scanner) void {
        s.gpa.free(s.pe_sections);
        s.gpa.free(s.elf_segments);
        s.gpa.free(s.elf_sections);
        s.gpa.free(s.macho_segments);
        s.gpa.free(s.macho_sections);
        s.gpa.destroy(s);
    }

    pub fn classify(s: *Scanner, data: []const u8) Classified {
        _ = s;
        return .{ .format = detect.detect(data[0..@min(data.len, detect.head_len)]), .file = .{ .info = .{ .size = data.len } } };
    }

    pub fn scan(s: *Scanner, e: *Engine, data: []const u8) !Result {
        _ = s;
        _ = e;
        _ = data;
        return .clean;
    }
};

pub const JavascriptFile = struct {
    out: html_norm.Output,

    pub fn pieces(j: *JavascriptFile) html_norm.Pieces {
        return .{ .ctx = j, .begin = nop, .data = nopData, .end = nop };
    }

    fn nop(ctx: *anyopaque) error{Stop}!void {
        _ = ctx;
    }

    fn nopData(ctx: *anyopaque, bytes: []const u8) error{Stop}!void {
        _ = ctx;
        _ = bytes;
    }
};
