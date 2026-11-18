//! The compile driver: signature sources in, one `.zavdb` out.
//!
//! Sources are added as named files (`main.hdb`, `local.ign2`, ...) or as a verified CVD/CLD whose
//! members are streamed straight from the archive. The large formats (hash databases, `.ndb`,
//! `.ldb`) are parsed line by line and turned into their database records at once: hash rules into
//! the external sort of `hash_build`, body and logical signatures into SUBSIG_PROG programs and
//! LDB_TABLE records, names into the SIGMETA table. No source text and no per-signature IR is kept,
//! so memory stays bounded however large the databases are (#105); with a spill directory the
//! large sections live in temporary files and are mapped read-only for the final write.
//!
//! Filtering happens while parsing, so `.ign2` lists must be known first: `preloadIgnores` reads
//! them from every container before any is compiled, and an ignore list added after signatures is
//! refused rather than silently applied to only some of them. Every signature that does not make it
//! into the database is counted in the coverage report, which is written into the database too.
const std = @import("std");
const Io = std.Io;
const ir = @import("ir.zig");
const hashsig = @import("hashsig.zig");
const hexsig = @import("hexsig.zig");
const ndb = @import("ndb.zig");
const prog_build = @import("prog_build.zig");
const anchored_build = @import("anchored_build.zig");
const ldb = @import("ldb.zig");
const ldb_build = @import("ldb_build.zig");
const ldb_table = @import("../match/ldb_table.zig");
const ftm = @import("ftm.zig");
const ftm_build = @import("ftm_build.zig");
const cdb = @import("cdb.zig");
const container = @import("../match/container.zig");
const regex_pool = @import("../match/regex_pool.zig");
const yara = @import("yara.zig");
const yara_cond = @import("../match/yara_cond.zig");
const prog = @import("../match/prog.zig");
const filters = @import("filters.zig");
const coverage_mod = @import("coverage.zig");
const atoms = @import("atoms.zig");
const prefilter_build = @import("prefilter_build.zig");
const gram_model = @import("gram_model.zig");
const hash_build = @import("hash_build.zig");
const names_mod = @import("names.zig");
const spill_mod = @import("spill.zig");
const lines_mod = @import("lines.zig");
const cvd = @import("cvd.zig");
const mbazaar = @import("mbazaar.zig");
const builtin_rules = @import("builtin.zig");
const hashidx = @import("../match/hashidx.zig");
const writer = @import("../db/writer.zig");
const format = @import("../db/format.zig");

/// Allowlist tables use the fp_tables section kind: hot halves at the table variant, cold halves
/// at this offset plus the table variant.
pub const fp_cold_variant_offset: u16 = 16;

pub const Options = struct {
    /// Where large sections and sort runs go while compiling. Null keeps everything on the heap.
    spill: ?*spill_mod.Spill = null,
    /// Sort buffer per hash table before a run is spilled.
    hash_budget: usize = hash_build.Builder.default_budget,
};

pub const Error = error{
    /// An `.ign2` list arrived after signatures it might have applied to.
    LateIgnoreList,
};

pub const Compiler = struct {
    gpa: std.mem.Allocator,
    /// Owns the small sources (allowlists, ignore lists, magic, container and YARA rules) and the
    /// names of database files; large sources are never copied.
    arena: std.heap.ArenaAllocator,
    /// Per-line scratch for the streamed formats, reset after every line.
    scratch: std.heap.ArenaAllocator,
    spill: ?*spill_mod.Spill,
    names: names_mod.NameTable,
    hashes: hash_build.Builder,
    programs: prog_build.Writer,
    logicals: ldb_build.Builder,
    /// Compiled regex programs (PCRE subsigs first, in rule order), owned by `arena`.
    regex_blobs: std.ArrayList([]const u8) = .empty,
    magics: std.ArrayList(ir.FtmRule) = .empty,
    containers: std.ArrayList(ir.CdbRule) = .empty,
    yara_rules: std.ArrayList(yara.Rule) = .empty,
    allow: std.ArrayList(ir.HashRule) = .empty,
    ignore: filters.Ignore = .{},
    /// Ignore lists already read by `preloadIgnores`; their container copies are skipped.
    ignores_preloaded: bool = false,
    /// A signature has been added, so a later ignore list could not apply to it.
    signatures_seen: bool = false,
    rejected: std.ArrayList(ir.Rejection) = .empty,
    coverage: coverage_mod.Coverage = .{},
    /// Benign 4-gram frequencies atom selection scores windows with.
    model: gram_model.Model,
    /// Programs by atom tier, for the coverage report.
    histogram: atoms.Histogram = .{},
    /// How atom selection weighs candidates against filters (E2 and E3 vary it).
    atom_costs: atoms.Costs = .{},
    sources: format.Sources = .{},
    hash_rules: u64 = 0,
    body_rules: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) Compiler {
        return initOptions(gpa, .{});
    }

    pub fn initOptions(gpa: std.mem.Allocator, options: Options) Compiler {
        return .{
            .gpa = gpa,
            .arena = .init(gpa),
            .scratch = .init(gpa),
            .spill = options.spill,
            .names = .init(gpa),
            .hashes = .init(gpa, options.spill, options.hash_budget),
            .programs = .init(gpa, options.spill),
            .logicals = .init(gpa),
            .model = .default(),
        };
    }

    /// Add one program with the atom atom selection gives it (atoms.zig).
    fn addProgram(c: *Compiler, in: prog_build.Input, planned: atoms.Planned) !void {
        var x = in;
        c.histogram.add(x, planned);
        x.atom = planned.atom(x.offset.kind);
        if (planned.deferred) x.flags |= prog.flag_deferred;
        _ = try c.programs.add(x);
    }

    fn addSearched(c: *Compiler, in: prog_build.Input) !void {
        try c.addProgram(in, .{ .choice = atoms.chooseFor(c.model, c.atom_costs, in) });
    }

    pub fn deinit(c: *Compiler) void {
        c.names.deinit();
        c.hashes.deinit();
        c.programs.deinit();
        c.logicals.deinit();
        c.regex_blobs.deinit(c.gpa);
        c.magics.deinit(c.gpa);
        c.containers.deinit(c.gpa);
        c.yara_rules.deinit(c.gpa);
        c.allow.deinit(c.gpa);
        c.ignore.deinit(c.gpa);
        c.rejected.deinit(c.gpa);
        c.coverage.deinit(c.gpa);
        c.scratch.deinit();
        c.arena.deinit();
    }

    /// Add one signature file. `name` decides the format by extension.
    pub fn addFile(c: *Compiler, name: []const u8, text: []const u8) !void {
        var r: Io.Reader = .fixed(text);
        return c.addStream(name, &r);
    }

    /// Add one signature file read from `reader`. The large formats are parsed as they stream;
    /// the small ones are read whole.
    pub fn addStream(c: *Compiler, name: []const u8, reader: *Io.Reader) !void {
        const arena = c.arena.allocator();
        const owned_name = try arena.dupe(u8, name);
        const ext = extension(owned_name);

        if (hashsig.formatFor(ext)) |fmt| return c.streamHashes(owned_name, fmt, reader);
        if (eql(ext, "ndb") or eql(ext, "ndu")) return c.streamBodies(owned_name, ext[2] == 'u', reader);
        if (eql(ext, "ldb") or eql(ext, "ldu")) return c.streamLogicals(owned_name, ext[2] == 'u', reader);
        if (eql(ext, "cbc")) {
            _ = try reader.discardRemaining();
            return c.coverage.skip(c.gpa, owned_name, .bytecode);
        }
        if (eql(ext, "info") or eql(owned_name, "COPYING")) {
            // Container metadata, verified by the CVD reader.
            _ = try reader.discardRemaining();
            return;
        }

        const text = try reader.allocRemaining(arena, .limited(small_source_limit));
        if (eql(ext, "ftm")) {
            try ftm.parse(c.gpa, arena, owned_name, text, .{ .rules = &c.magics, .rejected = &c.rejected });
        } else if (eql(ext, "cdb") or eql(ext, "cdu")) {
            try cdb.parse(c.gpa, arena, owned_name, text, ext[2] == 'u', .{ .rules = &c.containers, .rejected = &c.rejected });
        } else if (eql(ext, "yar") or eql(ext, "yara")) {
            try yara.parse(c.gpa, arena, owned_name, text, .{ .rules = &c.yara_rules, .rejected = &c.rejected });
        } else if (filters.allowlistFormat(ext)) |fmt| {
            try hashsig.parse(c.gpa, fmt, owned_name, text, .{ .rules = &c.allow, .rejected = &c.rejected });
        } else if (eql(ext, "ign2")) {
            try c.addIgnoreList(text);
        } else {
            // Known formats awaiting their parsers and unknown files are counted alike, per line.
            var lines = std.mem.splitScalar(u8, text, '\n');
            while (lines.next()) |line| {
                if (std.mem.trim(u8, line, " \r\t").len == 0) continue;
                try c.coverage.skip(c.gpa, owned_name, .unsupported_database);
            }
        }
    }

    /// The small formats are read whole; nothing in a ClamAV database comes near this.
    const small_source_limit = 64 * 1024 * 1024;

    fn addIgnoreList(c: *Compiler, text: []const u8) !void {
        if (c.signatures_seen) return error.LateIgnoreList;
        var entries: std.ArrayList(filters.IgnoreEntry) = .empty;
        defer entries.deinit(c.gpa);
        try filters.parseIgnore(c.gpa, text, &entries);
        for (entries.items) |e| try c.ignore.by_name.put(c.gpa, e.name, e.line_md5);
    }

    fn skipReason(c: *const Compiler, name: []const u8, line: []const u8, flevel_min: u16, flevel_max: u16) ?ir.Reason {
        return filters.skipReasonFor(name, line, flevel_min, flevel_max, &c.ignore, filters.engine_flevel);
    }

    fn reject(c: *Compiler, source_name: []const u8, line_number: u32, reason: ir.Reason, column: u32) !void {
        try c.rejected.append(c.gpa, .{ .source_name = source_name, .line_number = line_number, .reason = reason, .column = column });
    }

    /// One parsed hash rule through the filters into the hash tables.
    fn addHashRule(c: *Compiler, rule: *const ir.HashRule) !void {
        c.signatures_seen = true;
        if (c.skipReason(rule.name, rule.line, rule.flevel_min, rule.flevel_max)) |reason| {
            return c.coverage.skip(c.gpa, @tagName(rule.source), reason);
        }
        const sig = try c.names.intern(rule.name, rule.flags, rule.source);
        try c.hashes.addRule(rule, sig);
        c.hash_rules += 1;
        try c.coverage.include(c.gpa, @tagName(rule.source), 1);
    }

    fn streamHashes(c: *Compiler, name: []const u8, fmt: hashsig.Format, reader: *Io.Reader) !void {
        var lr = lines_mod.LineReader.init(c.gpa, reader);
        defer lr.deinit();
        while (try lr.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r \t");
            if (line.len == 0 or line[0] == '#') continue;
            var rule = hashsig.parseLine(fmt, line) catch |err| {
                try c.reject(name, lr.line_number, hashsig.reasonOf(err), 0);
                continue;
            };
            rule.line = line;
            try c.addHashRule(&rule);
        }
    }

    fn streamBodies(c: *Compiler, name: []const u8, pua: bool, reader: *Io.Reader) !void {
        var lr = lines_mod.LineReader.init(c.gpa, reader);
        defer lr.deinit();
        while (try lr.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r \t");
            if (line.len == 0 or line[0] == '#') continue;
            defer _ = c.scratch.reset(.retain_capacity);
            const scratch = c.scratch.allocator();
            c.signatures_seen = true;
            var column: u32 = 0;
            var rule = ndb.parseLine(scratch, line, &column) catch |err| {
                try c.reject(name, lr.line_number, ndb.reasonOf(err), column);
                continue;
            };
            rule.flags.pua = pua;
            if (c.skipReason(rule.name, line, rule.flevel_min, rule.flevel_max)) |reason| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), reason);
                continue;
            }
            const variants = hexsig.expand(scratch, rule.subsig.pattern, rule.subsig.mods) catch |err| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), hexsig.reasonOf(err));
                continue;
            };
            const sig = try c.names.intern(rule.name, rule.flags, rule.source);
            for (variants) |v| {
                var flags: u8 = 0;
                if (v.folded) flags |= prog.flag_folded;
                if (v.wide) flags |= prog.flag_wide;
                if (rule.subsig.mods.fullword) flags |= prog.flag_fullword;
                try c.addSearched(.{ .pattern = v.pattern, .offset = rule.subsig.offset, .target = rule.target, .sig = sig, .flags = flags });
            }
            c.body_rules += 1;
            try c.coverage.include(c.gpa, @tagName(rule.source), 1);
        }
    }

    fn streamLogicals(c: *Compiler, name: []const u8, pua: bool, reader: *Io.Reader) !void {
        var lr = lines_mod.LineReader.init(c.gpa, reader);
        defer lr.deinit();
        lines: while (try lr.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r \t");
            if (line.len == 0 or line[0] == '#') continue;
            defer _ = c.scratch.reset(.retain_capacity);
            const scratch = c.scratch.allocator();
            c.signatures_seen = true;
            var column: u32 = 0;
            var rule = ldb.parseLine(scratch, line, &column) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                try c.reject(name, lr.line_number, ldb.reasonOf(err), column);
                continue;
            };
            rule.flags.pua = pua;
            if (c.skipReason(rule.name, line, rule.flevel_min, rule.flevel_max)) |reason| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), reason);
                continue;
            }
            // Every hex subsig must expand or the rule is dropped.
            const per_subsig = try scratch.alloc([]hexsig.Variant, rule.subsigs.len);
            for (rule.subsigs, per_subsig) |sub, *out| switch (sub) {
                .hex => |h| out.* = hexsig.expand(scratch, h.pattern, h.mods) catch |err| {
                    try c.coverage.skip(c.gpa, @tagName(rule.source), hexsig.reasonOf(err));
                    continue :lines;
                },
                // Byte compares and PCRE run at evaluation time and have no verify program.
                .byte_compare, .pcre => out.* = &.{},
            };
            const sig = try c.names.intern(rule.name, rule.flags, rule.source);
            const record = c.logicals.count();
            const first = c.programs.count();
            var inputs: std.ArrayList(prog_build.Input) = .empty;
            for (rule.subsigs, per_subsig, 0..) |sub, variants, i| {
                if (sub != .hex) continue;
                const h = sub.hex;
                for (variants) |v| {
                    var flags: u8 = prog.flag_ldb;
                    if (v.folded) flags |= prog.flag_folded;
                    if (v.wide) flags |= prog.flag_wide;
                    if (h.mods.fullword) flags |= prog.flag_fullword;
                    try inputs.append(scratch, .{ .pattern = v.pattern, .offset = h.offset, .target = rule.tdb.target, .sig = record, .subsig = @intCast(i), .flags = flags });
                }
            }
            // Atoms for every variant, and the subsigs outside the expression's cheapest cover
            // deferred (atoms.zig).
            const planned = try atoms.plan(scratch, c.model, c.atom_costs, inputs.items, &.{.{ .rule = &rule, .first = 0, .count = @intCast(inputs.items.len) }});
            for (inputs.items, planned) |in, pl| try c.addProgram(in, pl);
            const regex_first: u32 = @intCast(c.regex_blobs.items.len);
            for (rule.subsigs) |sub| switch (sub) {
                .pcre => |p| try c.regex_blobs.append(c.gpa, try c.arena.allocator().dupe(u8, p.program)),
                else => {},
            };
            try c.logicals.add(.{ .rule = &rule, .sig = sig, .prog_first = first, .prog_count = c.programs.count() - first, .regex_first = regex_first });
            try c.coverage.include(c.gpa, @tagName(rule.source), 1);
        }
    }

    /// Add the signatures every database carries (EICAR).
    pub fn addBuiltin(c: *Compiler) !void {
        for (builtin_rules.rules()) |rule| try c.addHashRule(&rule);
    }

    /// Add a MalwareBazaar CSV export (opt-in feed).
    pub fn addMalwareBazaar(c: *Compiler, name: []const u8, text: []const u8, export_time: u64) !void {
        var arena: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena.deinit();
        var rules: std.ArrayList(ir.HashRule) = .empty;
        defer rules.deinit(c.gpa);
        const owned_name = try c.arena.allocator().dupe(u8, name);
        try mbazaar.parse(c.gpa, arena.allocator(), owned_name, text, &rules, &c.rejected);
        for (rules.items) |*rule| try c.addHashRule(rule);
        c.sources.malwarebazaar = export_time;
    }

    /// Read the `.ign2` lists of a container (verified first) so that they apply to every source
    /// compiled after, whatever order the containers come in. The container's `.info` lists its
    /// members, so the walk stops as soon as the ignore lists have been read.
    pub fn preloadIgnores(c: *Compiler, io: Io, dir: Io.Dir, sub_path: []const u8, options: cvd.VerifyOptions) !void {
        if (c.signatures_seen) return error.LateIgnoreList;
        const file = try dir.openFile(io, sub_path, .{});
        defer file.close(io);
        var header_buf: [cvd.header_len]u8 = undefined;
        const header = try verifyContainer(c.gpa, io, dir, sub_path, file, &header_buf, options);
        var buf: [64 * 1024]u8 = undefined;
        var r = file.reader(io, &buf);
        try r.seekTo(cvd.header_len);
        var visitor: IgnoreVisitor = .{ .compiler = c };
        cvd.walk(c.gpa, header, &r.interface, .{}, &visitor) catch |err| switch (err) {
            error.WalkDone => {},
            else => |e| return e,
        };
        c.ignores_preloaded = true;
    }

    const IgnoreVisitor = struct {
        compiler: *Compiler,
        remaining: usize = 0,

        pub fn infoListed(v: *IgnoreVisitor, info: *const cvd.Info) !void {
            for (info.entries) |e| {
                if (eql(extension(e.name), "ign2")) v.remaining += 1;
            }
            if (v.remaining == 0) return error.WalkDone;
        }

        pub fn member(v: *IgnoreVisitor, name: []const u8, _: u64, reader: *Io.Reader) !void {
            if (!eql(extension(name), "ign2")) return;
            const c = v.compiler;
            const text = try reader.allocRemaining(c.arena.allocator(), .limited(small_source_limit));
            try c.addIgnoreList(text);
            v.remaining -= 1;
            if (v.remaining == 0) return error.WalkDone;
        }
    };

    /// Verify a CVD (or, with `allow_unverified`, a CLD) and add its members. A detached
    /// `.sign` file next to it (`main-63.cvd.sign`) is verified too when present.
    pub fn addContainer(c: *Compiler, io: Io, dir: Io.Dir, sub_path: []const u8, options: cvd.VerifyOptions) !cvd.Header {
        const file = try dir.openFile(io, sub_path, .{});
        defer file.close(io);
        const header_buf = try c.arena.allocator().create([cvd.header_len]u8);
        const header = try verifyContainer(c.gpa, io, dir, sub_path, file, header_buf, options);

        var buf: [64 * 1024]u8 = undefined;
        var r = file.reader(io, &buf);
        try r.seekTo(cvd.header_len);
        var visitor: MemberVisitor = .{ .compiler = c };
        try cvd.walk(c.gpa, header, &r.interface, .{}, &visitor);

        const stem = std.fs.path.stem(sub_path);
        if (std.mem.startsWith(u8, stem, "main")) c.sources.clamav_main = header.version;
        if (std.mem.startsWith(u8, stem, "daily")) c.sources.clamav_daily = header.version;
        if (std.mem.startsWith(u8, stem, "bytecode")) c.sources.clamav_bytecode = header.version;
        return header;
    }

    const MemberVisitor = struct {
        compiler: *Compiler,

        pub fn member(v: *MemberVisitor, name: []const u8, _: u64, reader: *Io.Reader) !void {
            // Ignore lists were read by preloadIgnores already.
            if (v.compiler.ignores_preloaded and eql(extension(name), "ign2")) return;
            try v.compiler.addStream(name, reader);
        }
    };

    pub const Summary = struct {
        signatures: u32,
        hash_rules: u64,
        /// Body signatures compiled into verify programs.
        body_rules: u64,
        /// Logical signatures in LDB_TABLE.
        logical_rules: u64,
        /// File-type magic entries in FTM_TRIE.
        magic_rules: u64,
        /// Container metadata signatures in CDB_TABLE.
        container_rules: u64,
        /// YARA rules (LDB_TABLE records with YARA_COND conditions).
        yara_rules: u64,
        /// Verify programs: one per variant after modifier expansion.
        programs: u64,
        allowlist_rules: u64,
        duplicates: u64,
        /// Bytes of the hot region's hash sections (need maps and hot tables).
        hash_hot_bytes: u64,
    };

    /// Finish every section and write the database.
    pub fn write(c: *Compiler, io: Io, dir: Io.Dir, sub_path: []const u8, options: writer.Options) !Summary {
        const arena = c.arena.allocator();
        for (c.rejected.items) |r| try c.coverage.skip(c.gpa, r.source_name, r.reason);

        // Container metadata signatures share the id space; file-type magic has no names.
        var kept_containers: std.ArrayList(ir.CdbRule) = .empty;
        defer kept_containers.deinit(c.gpa);
        var container_sigs: std.ArrayList(u32) = .empty;
        defer container_sigs.deinit(c.gpa);
        for (c.containers.items) |*rule| {
            if (c.skipReason(rule.name, rule.line, rule.flevel_min, rule.flevel_max)) |reason| {
                try c.coverage.skip(c.gpa, @tagName(rule.source), reason);
                continue;
            }
            try kept_containers.append(c.gpa, rule.*);
            try container_sigs.append(c.gpa, try c.names.intern(rule.name, rule.flags, rule.source));
            try c.coverage.include(c.gpa, @tagName(rule.source), 1);
        }
        var kept_yara: std.ArrayList(*const yara.Rule) = .empty;
        defer kept_yara.deinit(c.gpa);
        var yara_sigs: std.ArrayList(u32) = .empty;
        defer yara_sigs.deinit(c.gpa);
        for (c.yara_rules.items) |*rule| {
            if (c.skipReason(rule.name, rule.text, 0, 0)) |reason| {
                try c.coverage.skip(c.gpa, "yara", reason);
                continue;
            }
            try kept_yara.append(c.gpa, rule);
            try yara_sigs.append(c.gpa, try c.names.intern(rule.name, .{}, .yara));
            try c.coverage.include(c.gpa, "yara", 1);
        }
        var kept_magics: std.ArrayList(ir.FtmRule) = .empty;
        defer kept_magics.deinit(c.gpa);
        for (c.magics.items) |*rule| {
            if (c.skipReason(rule.name, rule.line, rule.flevel_min, rule.flevel_max)) |reason| {
                try c.coverage.skip(c.gpa, "ftm", reason);
                continue;
            }
            try kept_magics.append(c.gpa, rule.*);
            try c.coverage.include(c.gpa, "ftm", 1);
        }

        // Every regex goes into one REGEX_POOL, referred to by index: PCRE programs (added while
        // streaming), then container filename regexes, then YARA regex strings.
        const cdb_regex = try arena.alloc(?u32, kept_containers.items.len);
        for (kept_containers.items, cdb_regex) |rule, *slot| {
            slot.* = null;
            if (rule.filename_program) |blob| {
                slot.* = @intCast(c.regex_blobs.items.len);
                try c.regex_blobs.append(c.gpa, blob);
            }
        }
        const cdb_raw = try container.build(c.gpa, kept_containers.items, container_sigs.items, cdb_regex);
        defer c.gpa.free(cdb_raw);
        const magic = try ftm_build.build(arena, kept_magics.items);
        const magic_programs = try prog_build.build(arena, magic.programs);

        // YARA rules: LDB records after the logical signatures, strings as subsigs, conditions
        // in YARA_COND, regex strings in REGEX_POOL.
        var yara_inputs: std.ArrayList(yara_cond.RuleInput) = .empty;
        defer yara_inputs.deinit(c.gpa);
        for (kept_yara.items, yara_sigs.items) |rule, sig| {
            const record = c.logicals.count();
            const first = c.programs.count();
            const strings = try arena.alloc(yara_cond.YaraString, rule.strings.len);
            for (rule.strings, strings, 0..) |str, *out, i| {
                if (str.regex) |blob| {
                    out.* = .{ .kind = yara_cond.kind_regex, .regex = @intCast(c.regex_blobs.items.len) };
                    try c.regex_blobs.append(c.gpa, blob);
                    continue;
                }
                out.* = .{ .kind = yara_cond.kind_program };
                for (str.variants) |v| {
                    var flags: u8 = prog.flag_ldb;
                    if (v.folded) flags |= prog.flag_folded;
                    if (v.wide) flags |= prog.flag_wide;
                    if (str.fullword) flags |= prog.flag_fullword;
                    try c.addSearched(.{ .pattern = v.pattern, .sig = record, .subsig = @intCast(i), .flags = flags });
                }
            }
            const subsigs = try arena.alloc(ir.LogicalSubsig, rule.strings.len);
            for (subsigs) |*sub| sub.* = .{ .hex = .{ .pattern = .{ .ops = &.{}, .data = &.{} } } };
            const shell: ir.LogicalRule = .{ .name = rule.name, .tdb = .{}, .expr = &.{}, .subsigs = subsigs, .source = .yara };
            try c.logicals.add(.{ .rule = &shell, .sig = sig, .prog_first = first, .prog_count = c.programs.count() - first, .yara = true });
            var flags: u8 = 0;
            if (rule.always) flags |= yara_cond.flag_always;
            if (rule.private) flags |= yara_cond.flag_private;
            try yara_inputs.append(c.gpa, .{ .ldb = record, .cond = rule.cond, .strings = strings, .flags = flags });
        }
        const yara_raw = try yara_cond.build(c.gpa, yara_inputs.items);
        defer c.gpa.free(yara_raw);
        const pool_raw = try regex_pool.build(c.gpa, c.regex_blobs.items);
        defer c.gpa.free(pool_raw);
        const logical_count = c.logicals.count();
        const ldb_raw = try c.logicals.finish(c.gpa);
        defer c.gpa.free(ldb_raw);

        const program_count = c.programs.count();
        const programs = try c.programs.finish();

        // One anchored-offset index per partition, each proven to reach all of its programs.
        var anchored_sections: [ndb.max_target + 1]?[]u8 = @splat(null);
        defer for (anchored_sections) |a| if (a) |bytes| c.gpa.free(bytes);
        // The prefilter of every partition (prefilter_build.zig).
        var prefilter_section: ?[]align(64) u8 = null;
        defer if (prefilter_section) |b| c.gpa.free(b);
        if (program_count > 0) {
            const progs = try prog.Programs.init(programs);
            for (&anchored_sections, 0..) |*slot, p| slot.* = try anchored_build.build(c.gpa, progs, @intCast(p));
            prefilter_section = try prefilter_build.buildAll(c.gpa, progs, c.programs.atoms.items, .{});
        }

        // Names are complete: no more interning.
        const sigmeta = try c.names.sigmeta(c.gpa);
        defer c.gpa.free(sigmeta);
        var built = try c.hashes.finish();
        defer built.deinit();
        var allow = try hash_build.build(c.gpa, c.allow.items);
        defer allow.deinit();

        var report: Io.Writer.Allocating = .init(c.gpa);
        defer report.deinit();
        try c.coverage.render(&report.writer);
        try c.histogram.render(&report.writer);

        var sections: std.ArrayList(writer.Section) = .empty;
        defer sections.deinit(c.gpa);
        var buf: [32]writer.Section = undefined;
        try sections.appendSlice(c.gpa, built.sections(&buf));
        try sections.append(c.gpa, .{ .kind = .sigmeta, .bytes = sigmeta });
        try sections.append(c.gpa, .{ .kind = .name_pool, .bytes = c.names.namePool() });
        for (allow.hot, 0..) |hot, t| if (hot) |bytes| {
            try sections.append(c.gpa, .{ .kind = .fp_tables, .variant = @intCast(t), .bytes = bytes });
            try sections.append(c.gpa, .{ .kind = .fp_tables, .variant = fp_cold_variant_offset + @as(u16, @intCast(t)), .bytes = allow.cold[t].? });
        };
        if (program_count > 0) try sections.append(c.gpa, .{ .kind = .subsig_prog, .bytes = programs });
        if (logical_count > 0) try sections.append(c.gpa, .{ .kind = .ldb_table, .align_log2 = 12, .bytes = ldb_raw });
        if (kept_containers.items.len > 0) try sections.append(c.gpa, .{ .kind = .cdb_table, .bytes = cdb_raw });
        if (yara_inputs.items.len > 0) try sections.append(c.gpa, .{ .kind = .yara_cond, .bytes = yara_raw });
        if (c.regex_blobs.items.len > 0) try sections.append(c.gpa, .{ .kind = .regex_pool, .bytes = pool_raw });
        if (kept_magics.items.len > 0) {
            try sections.append(c.gpa, .{ .kind = .ftm_trie, .hot = true, .bytes = magic.trie });
            if (magic.programs.len > 0) try sections.append(c.gpa, .{ .kind = .subsig_prog, .variant = 1, .bytes = magic_programs });
        }
        for (anchored_sections, 0..) |a, p| if (a) |bytes| {
            try sections.append(c.gpa, .{ .kind = .anchored_index, .variant = @intCast(p), .partition = @intCast(p), .hot = true, .bytes = bytes });
        };
        if (prefilter_section) |bytes| try sections.append(c.gpa, .{ .kind = .prefilter, .hot = true, .bytes = bytes });
        try sections.append(c.gpa, .{ .kind = .coverage_report, .bytes = report.written() });

        var opts = options;
        opts.sources = c.sources;
        opts.sources.engine_flevel = filters.engine_flevel;
        try writer.write(io, dir, sub_path, sections.items, opts);
        return .{
            .signatures = c.names.count(),
            .hash_rules = c.hash_rules,
            .body_rules = c.body_rules,
            .logical_rules = logical_count,
            .magic_rules = kept_magics.items.len,
            .container_rules = kept_containers.items.len,
            .yara_rules = yara_inputs.items.len,
            .programs = program_count,
            .allowlist_rules = c.allow.items.len,
            .duplicates = built.duplicates,
            .hash_hot_bytes = built.hotBytes(),
        };
    }
};

/// `cvd.verifyFile` with the container's detached signature file, when it has one.
pub fn verifyContainer(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, sub_path: []const u8, file: Io.File, header_buf: *[cvd.header_len]u8, options: cvd.VerifyOptions) !cvd.Header {
    if (try file.readPositionalAll(io, header_buf, 0) != cvd.header_len) return error.Truncated;
    const peek = try cvd.parseHeader(header_buf);
    var opts = options;
    const sign = if (options.sign == null) try cvd.readSignFile(gpa, io, dir, sub_path, peek.version) else null;
    defer if (sign) |text| gpa.free(text);
    if (sign) |text| opts.sign = text;
    return cvd.verifyFile(gpa, io, file, header_buf, opts);
}

fn extension(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "";
    return name[dot + 1 ..];
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test "compile files and a container, filter, and write a database" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const db = @import("../db/root.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "test.cld", .data = cvd.fixture_cld });

    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.addFile("local.ign2", "Local.Ignored-1-0\n");
    _ = try c.addContainer(io, tmp.dir, "test.cld", .{ .kind = .cld, .allow_unverified = true });
    try c.addFile("local.hdb", "00112233445566778899aabbccddeeff:10:Local.Ignored-1-0\nbad line\n");
    try c.addFile("local.fp", "44d88612fea8a8f36de82e1278abb02f:68:Allow.Eicar\n");
    try c.addFile("main.ndb", "Eicar:0:*:58354f\nBroken:0:*:58(35\n");
    try c.addFile("main.pdb", "R:example.com\n");
    try c.addFile("daily.ftm", "0:0:4d5a:DOS executable:CL_TYPE_ANY:CL_TYPE_MSEXE\n1:*:504b0304:ZIP-SFX:CL_TYPE_MSEXE:CL_TYPE_ZIPSFX\n7:0:00:Bad:CL_TYPE_ANY:CL_TYPE_ZIP\n");
    try c.addFile("daily.cdb", "Zip.Meta-1-0:CL_TYPE_ZIP:*:*:*:1000:*:1:*:*\nZip.Regex-2-0:CL_TYPE_ZIP:*:evil\\.exe:*:*:*:*:*:*\nZip.Behind-3-0:*:*:(?<=a+)b:*:*:*:*:*:*\n");
    try c.addFile("main.ldb", "Logical.Test-1-0;Target:0;0&1;4142;4344::i\nLogical.Bad-2-0;Target:0;0&2;4142;4344\n");
    // An ignore list after signatures could not apply to them: refused, not half applied.
    try std.testing.expectError(error.LateIgnoreList, c.addFile("late.ign2", "Eicar\n"));
    const summary = try c.write(io, tmp.dir, "out.zavdb", .{ .db_version = 1 });
    try std.testing.expectEqual(@as(u64, 2), summary.hash_rules); // two from the container
    try std.testing.expectEqual(@as(u64, 1), summary.allowlist_rules);
    try std.testing.expectEqual(@as(u64, 1), summary.body_rules);
    try std.testing.expectEqual(@as(u64, 1), summary.logical_rules);
    try std.testing.expectEqual(@as(u64, 2), summary.magic_rules);
    try std.testing.expectEqual(@as(u64, 2), summary.container_rules);
    try std.testing.expectEqual(@as(u64, 1 + 1 + 4), summary.programs); // ndb, then 1 + 4 nocase variants

    const opened = try db.reader.open(io, tmp.dir, "out.zavdb", .{ .allow_unsigned = true });
    defer opened.close();
    const report = opened.section(.coverage_report, 0).?;
    try std.testing.expect(std.mem.indexOf(u8, report, "hdb: 1 skipped (ignored)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "local.hdb: 1 skipped (field_count)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "ndb: 1 included") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "main.ndb: 1 skipped (hex_bad_alternation)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "main.pdb: 1 skipped (unsupported_database)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "main.ldb: 1 skipped (bad_expression)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "daily.ftm: 1 skipped (bad_magic_type)") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "daily.cdb: 1 skipped (regex_lookaround)") != null);
    const pool = try regex_pool.RegexPool.init(opened.section(.regex_pool, 0).?);
    const cdbt = try container.CdbTable.init(opened.section(.cdb_table, 0).?, pool);
    try std.testing.expectEqual(@as(usize, 2), cdbt.records.len);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    const magic_progs = try prog.Programs.init(opened.section(.subsig_prog, 1).?);
    _ = try @import("../fmt/ftm.zig").Ftm.init(opened.section(.ftm_trie, 0).?, magic_progs);
    const progs = try prog.Programs.init(opened.section(.subsig_prog, 0).?);
    try std.testing.expectEqual(@as(usize, 6), progs.count());
    const logical = try ldb_table.LdbTable.init(opened.section(.ldb_table, 0).?, progs);
    try std.testing.expectEqual(@as(usize, 1), logical.records.len);
    try std.testing.expectEqual(@as(u32, 1), logical.records[0].prog_first);
    try std.testing.expectEqual(@as(u32, 5), logical.records[0].prog_count);

    // The ignored signature is not in the database; the container's EICAR is.
    const t = hashidx.tableVariant(.md5, .file);
    const table = try hashidx.Table.init(opened.section(.hash_hot, t).?, opened.section(.hash_cold, t).?);
    var ignored: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ignored, "00112233445566778899aabbccddeeff");
    try std.testing.expectEqual(@as(?u32, null), table.lookup(10, &ignored));
    var eicar: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&eicar, "44d88612fea8a8f36de82e1278abb02f");
    const sig = table.lookup(68, &eicar).?;
    const meta = try hashidx.SigMeta.init(opened.section(.sigmeta, 0).?, opened.section(.name_pool, 0).?);
    var name_buf: [64]u8 = undefined;
    try std.testing.expect((try meta.name(sig, &name_buf)).len > 0);

    // The allowlist is a full-digest table of its own.
    const fp = try hashidx.Table.init(opened.section(.fp_tables, t).?, opened.section(.fp_tables, fp_cold_variant_offset + t).?);
    try std.testing.expect(fp.lookup(68, &eicar) != null);
}

test "spilled compile writes the same database as the in-memory one" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "spill");
    var spill_dir = try tmp.dir.openDir(io, "spill", .{});
    defer spill_dir.close(io);

    var hdb: std.ArrayList(u8) = .empty;
    defer hdb.deinit(gpa);
    var ndb_text: std.ArrayList(u8) = .empty;
    defer ndb_text.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(3);
    for (0..5000) |i| {
        var d: [16]u8 = undefined;
        prng.random().bytes(&d);
        try hdb.print(gpa, "{x}:{d}:Win.Trojan.Gen-{d}-0\n", .{ &d, 1000 + i % 300, i });
        if (i % 10 == 0) try ndb_text.print(gpa, "Win.Body.B-{d}:1:*:{x}\n", .{ i, &d });
    }
    var outputs: [2][]u8 = undefined;
    for (&outputs, 0..) |*out, pass| {
        var spill: spill_mod.Spill = .init(io, spill_dir);
        var c = Compiler.initOptions(gpa, .{ .spill = if (pass == 1) &spill else null, .hash_budget = 16 * 1024 });
        defer c.deinit();
        try c.addFile("x.hdb", hdb.items);
        try c.addFile("x.ndb", ndb_text.items);
        try c.addFile("x.ldb", "Logical.Test-1-0;Target:0;0&1;41424344;45464748\n");
        const name = if (pass == 0) "a.zavdb" else "b.zavdb";
        const summary = try c.write(io, tmp.dir, name, .{ .db_version = 1 });
        try std.testing.expectEqual(@as(u64, 5000), summary.hash_rules);
        out.* = try tmp.dir.readFileAlloc(io, name, gpa, .unlimited);
    }
    defer for (outputs) |o| gpa.free(o);
    try std.testing.expectEqualSlices(u8, outputs[0], outputs[1]);
}

test "ignore lists are preloaded from a container before anything is compiled" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "test.cld", .data = cvd.fixture_cld });
    var c = Compiler.init(gpa);
    defer c.deinit();
    try c.preloadIgnores(io, tmp.dir, "test.cld", .{ .kind = .cld, .allow_unverified = true });
    try std.testing.expect(c.ignores_preloaded);
    _ = try c.addContainer(io, tmp.dir, "test.cld", .{ .kind = .cld, .allow_unverified = true });
    try std.testing.expectError(error.LateIgnoreList, c.preloadIgnores(io, tmp.dir, "test.cld", .{ .kind = .cld, .allow_unverified = true }));
}
