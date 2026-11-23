const std = @import("std");
const hash_variants = @import("src/hash/variants.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The engine as a Zig module: `@import("zav")`.
    const zav = b.addModule("zav", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addHashVariants(b, zav, target, optimize);
    // zig-xml's incremental tokenizer reads OOXML package parts (src/fmt/ooxml.zig).
    const xml = b.dependency("xml", .{ .target = target, .optimize = optimize }).module("xml");
    zav.addImport("xml", xml);
    // zig-regex byte-mode programs: .cdb filename regexes, PCRE subsigs, YARA regex strings.
    const regex = b.dependency("regex", .{ .target = target, .optimize = optimize }).module("regex");
    zav.addImport("regex", regex);
    // zig-mime walks email messages (src/fmt/mime.zig).
    const mime = b.dependency("mime", .{ .target = target, .optimize = optimize }).module("mime");
    zav.addImport("mime", mime);

    const zig_cli = b.dependency("cli", .{ .target = target, .optimize = optimize }).module("zig_cli");
    zav.addImport("zig_cli", zig_cli);

    // Executables: the CLI and the daemon.
    var zav_exe: ?*std.Build.Step.Compile = null;
    for ([_][]const u8{ "zav", "zavd" }) |exe_name| {
        const exe = b.addExecutable(.{
            .name = exe_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("src/cli/{s}.zig", .{exe_name})),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "zav", .module = zav },
                    .{ .name = "zig_cli", .module = zig_cli },
                },
            }),
        });
        b.installArtifact(exe);
        if (std.mem.eql(u8, exe_name, "zav")) zav_exe = exe;
        const run = b.addRunArtifact(exe);
        run.step.dependOn(b.getInstallStep());
        run.addPassthruArgs();
        b.step(b.fmt("run-{s}", .{exe_name}), b.fmt("Run {s}", .{exe_name})).dependOn(&run.step);
    }

    // C ABI: static and shared libzav plus include/zav.h.
    const static_lib = b.addLibrary(.{ .linkage = .static, .name = "zav", .root_module = capiModule(b, target, optimize, zav) });
    const shared_lib = b.addLibrary(.{ .linkage = .dynamic, .name = "zav", .root_module = capiModule(b, target, optimize, zav) });
    const lib_step = b.step("lib", "Build the static and shared C ABI libraries and install the header");
    lib_step.dependOn(&b.addInstallArtifact(static_lib, .{}).step);
    lib_step.dependOn(&b.addInstallArtifact(shared_lib, .{}).step);
    lib_step.dependOn(&b.addInstallHeaderFile(b.path("include/zav.h"), "zav.h").step);

    // Tests: the whole module tree, the C ABI, and a C program linking libzav.
    const test_step = b.step("test", "Run all tests");
    const tree_tests = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addHashVariants(b, tree_tests, target, optimize);
    tree_tests.addImport("xml", xml);
    tree_tests.addImport("regex", regex);
    tree_tests.addImport("mime", mime);
    tree_tests.addImport("zig_cli", zig_cli);
    const test_filters = b.option([]const []const u8, "test-filter", "Run only module-tree tests whose names contain this") orelse &.{};
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = tree_tests, .filters = test_filters })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = capiModule(b, target, optimize, zav) })).step);

    const c_smoke = b.addExecutable(.{
        .name = "c-smoke",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    c_smoke.root_module.addCSourceFile(.{ .file = b.path("tests/c/smoke.c"), .flags = &.{ "-std=c99", "-Wall", "-Wextra", "-Werror" } });
    c_smoke.root_module.addIncludePath(b.path("include"));
    c_smoke.root_module.linkLibrary(static_lib);
    test_step.dependOn(&b.addRunArtifact(c_smoke).step);

    // CLI: PUA signatures (a .hdu rule here) are reported only with --detect-pua, as clamscan
    // reports them only with --detect-pua=yes; the database is the same either way.
    if (zav_exe) |exe| {
        const files = b.addWriteFiles();
        const hdu = files.add("pua.hdu", "9fae63efadf315eb302e089c73387a8b:16:Test.Pua.Hash-4-0\n");
        const sample = files.add("sample.bin", "PUA hash sample!");
        const compile_pua = b.addRunArtifact(exe);
        compile_pua.addArgs(&.{ "compile", "--no-builtin", "-o" });
        const pua_db = compile_pua.addOutputFileArg("pua.zavdb");
        compile_pua.addFileArg(hdu);
        compile_pua.expectExitCode(0);
        const pua_cases = [_]struct { extra: []const []const u8, code: u8, out: []const u8 }{
            .{ .extra = &.{}, .code = 0, .out = ": OK" },
            .{ .extra = &.{"--detect-pua"}, .code = 1, .out = "Test.Pua.Hash-4-0 FOUND" },
            .{ .extra = &.{"--detect-pua=yes"}, .code = 1, .out = "Test.Pua.Hash-4-0 FOUND" },
            .{ .extra = &.{"--detect-pua=no"}, .code = 0, .out = ": OK" },
        };
        for (pua_cases) |c| {
            const run = b.addRunArtifact(exe);
            run.addArgs(&.{ "scan", "--allow-unsigned", "--db" });
            run.addFileArg(pua_db);
            run.addArgs(c.extra);
            run.addFileArg(sample);
            run.expectExitCode(c.code);
            run.expectStdOutMatch(c.out);
            test_step.dependOn(&run.step);
        }
    }

    // CLI: compile the recorded CVE feeds, then check zav audit's severity exit codes on a
    // fixture Stacks app with a vulnerable lodash (medium: 12) and a patched one (0).
    // Host checks and audits support Linux and macOS only.
    if (zav_exe != null and target.result.os.tag != .windows) {
        const exe = zav_exe.?;
        const cve_index = blk: {
            const run = b.addRunArtifact(exe);
            run.addArgs(&.{ "cve", "compile", "--feeds" });
            run.addDirectoryArg(b.path("tests/fixtures/cve-feeds"));
            run.addArg("--out");
            const out = run.addOutputFileArg("fixture.zavcve");
            run.expectExitCode(0);
            break :blk out;
        };
        const cases = [_]struct { app: []const u8, extra: []const []const u8, code: u8, out: []const u8 = "", err: []const u8 = "" }{
            .{ .app = "tests/fixtures/stacks-app", .extra = &.{}, .code = 12, .out = "CVE-2021-23337" },
            .{ .app = "tests/fixtures/stacks-app", .extra = &.{"--json"}, .code = 12, .out = "\"exit_code\": 12" },
            .{ .app = "tests/fixtures/stacks-app", .extra = &.{ "--min-severity", "high" }, .code = 0 },
            .{ .app = "tests/fixtures/stacks-app", .extra = &.{ "--min-severity", "bogus" }, .code = 2, .err = "unknown severity" },
            .{ .app = "tests/fixtures/clean-app", .extra = &.{}, .code = 0, .out = "0 findings" },
        };
        for (cases) |c| {
            const run = b.addRunArtifact(exe);
            run.addArgs(&.{ "audit", "--cve-index" });
            run.addFileArg(cve_index);
            run.addArgs(c.extra);
            run.addDirectoryArg(b.path(c.app));
            run.expectExitCode(c.code);
            if (c.out.len > 0) run.expectStdOutMatch(c.out);
            if (c.err.len > 0) run.expectStdErrMatch(c.err);
            test_step.dependOn(&run.step);
        }

        // A signed index: `cve compile --signing-key` with a throwaway test seed, then
        // `audit --cve-key` requiring that signer and refusing every other index.
        const keys = b.addWriteFiles();
        const seed = keys.add("test-cve.seed", &@as([32]u8, @splat(7)));
        const short_seed = keys.add("short.seed", &@as([31]u8, @splat(7)));
        const pub_hex = testPublicKeyHex(b, 7);
        const other_hex = testPublicKeyHex(b, 8);
        const signed_index = blk: {
            const run = b.addRunArtifact(exe);
            run.addArgs(&.{ "cve", "compile", "--feeds" });
            run.addDirectoryArg(b.path("tests/fixtures/cve-feeds"));
            run.addArg("--signing-key");
            run.addFileArg(seed);
            run.addArg("--out");
            const out = run.addOutputFileArg("signed.zavcve");
            run.expectExitCode(0);
            run.expectStdOutMatch("ranges, signed");
            break :blk out;
        };
        const bad_seed = b.addRunArtifact(exe);
        bad_seed.addArgs(&.{ "cve", "compile", "--feeds" });
        bad_seed.addDirectoryArg(b.path("tests/fixtures/cve-feeds"));
        bad_seed.addArg("--signing-key");
        bad_seed.addFileArg(short_seed);
        bad_seed.addArg("--out");
        _ = bad_seed.addOutputFileArg("never.zavcve");
        bad_seed.expectExitCode(2);
        bad_seed.expectStdErrMatch("InvalidSigningKey");
        test_step.dependOn(&bad_seed.step);
        // Tampered copies of the signed index. The header signature still verifies, so only the
        // whole-body check under --cve-key can refuse them: one body byte (the last one) and one
        // byte of the unsigned header tail (offset 400).
        const flip_exe = b.addExecutable(.{
            .name = "flip_byte",
            .root_module = b.createModule(.{ .root_source_file = b.path("tools/flip_byte.zig"), .target = b.graph.host, .optimize = .Debug }),
        });
        const tampered = struct {
            fn copy(bb: *std.Build, tool: *std.Build.Step.Compile, index: std.Build.LazyPath, name: []const u8, offset: []const u8) std.Build.LazyPath {
                const run = bb.addRunArtifact(tool);
                run.addFileArg(index);
                const out = run.addOutputFileArg(name);
                run.addArg(offset);
                return out;
            }
        }.copy;
        const body_tampered = tampered(b, flip_exe, signed_index, "body.zavcve", "-1");
        const tail_tampered = tampered(b, flip_exe, signed_index, "tail.zavcve", "400");
        const keyed = [_]struct { index: std.Build.LazyPath, keys: []const []const u8, code: u8, out: []const u8 = "", err: []const u8 = "" }{
            .{ .index = signed_index, .keys = &.{pub_hex}, .code = 12, .out = "CVE-2021-23337" },
            .{ .index = signed_index, .keys = &.{ other_hex, pub_hex }, .code = 12, .out = "CVE-2021-23337" },
            .{ .index = signed_index, .keys = &.{other_hex}, .code = 2, .err = "UnknownKey" },
            .{ .index = cve_index, .keys = &.{pub_hex}, .code = 2, .err = "Unsigned" },
            .{ .index = signed_index, .keys = &.{"not-hex"}, .code = 2, .err = "InvalidPublicKey" },
            .{ .index = body_tampered, .keys = &.{pub_hex}, .code = 2, .err = "RootMismatch" },
            .{ .index = tail_tampered, .keys = &.{pub_hex}, .code = 2, .err = "UnsignedHeaderData" },
        };
        for (keyed) |c| {
            const run = b.addRunArtifact(exe);
            run.addArgs(&.{ "audit", "--cve-index" });
            run.addFileArg(c.index);
            for (c.keys) |k| run.addArgs(&.{ "--cve-key", k });
            run.addDirectoryArg(b.path("tests/fixtures/stacks-app"));
            run.expectExitCode(c.code);
            if (c.out.len > 0) run.expectStdOutMatch(c.out);
            if (c.err.len > 0) run.expectStdErrMatch(c.err);
            test_step.dependOn(&run.step);
        }
    }

    // Public Guardian CLI seam: compile the shipped source pack and expose every rule in coverage.
    if (zav_exe) |exe| {
        const compile_pack = b.addRunArtifact(exe);
        compile_pack.addArgs(&.{ "compile", "--no-builtin", "--guardian" });
        compile_pack.addDirectoryArg(b.path("rules"));
        compile_pack.addArg("--out");
        const pack_db = compile_pack.addOutputFileArg("guardian.zavdb");
        compile_pack.expectExitCode(0);
        const coverage_pack = b.addRunArtifact(exe);
        coverage_pack.addArgs(&.{ "coverage", "--allow-unsigned" });
        coverage_pack.addFileArg(pack_db);
        coverage_pack.expectExitCode(0);
        coverage_pack.expectStdOutMatch("zav coverage: 7 included, 0 skipped");
        test_step.dependOn(&coverage_pack.step);
    }

    // The differential suite against libclamav: zav-diff checks zav's verdicts on every case in
    // tests/differential against the expectations recorded from clamscan (tools/diff/README.md).
    // The clamscan side runs in .github/workflows/differential.yml.
    const diff_exe = b.addExecutable(.{
        .name = "zav-diff",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/diff/zav_diff.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    const install_diff = b.addInstallArtifact(diff_exe, .{});
    b.step("diff-tool", "Build zav-diff, the zav side of the differential suite").dependOn(&install_diff.step);
    const run_diff = b.addRunArtifact(diff_exe);
    run_diff.addArgs(&.{ "check", "--known" });
    run_diff.addFileArg(b.path("tests/differential/known.txt"));
    run_diff.addArg("--tmp");
    _ = run_diff.addOutputDirectoryArg("zav-diff-tmp");
    run_diff.addDirectoryArg(b.path("tests/differential/cases"));
    // Case files are read from a directory, which the cache does not hash: always run.
    run_diff.has_side_effects = true;
    run_diff.expectExitCode(0);
    b.step("diff", "Check zav against the recorded libclamav verdicts").dependOn(&run_diff.step);
    test_step.dependOn(&run_diff.step);
    const diff_tests = b.addTest(.{ .root_module = diff_exe.root_module });
    test_step.dependOn(&b.addRunArtifact(diff_tests).step);

    // E13: zig-regex byte mode against PCRE2 (tools/diff/e13.zig). Needs libpcre2-8: from the
    // system, or from -Dpcre2=PREFIX (its lib/libpcre2-8.a is linked statically).
    const e13_exe = b.addExecutable(.{
        .name = "e13",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/diff/e13.zig"),
            .target = target,
            .optimize = if (optimize == .debug) .safe else optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    if (b.option([]const u8, "pcre2", "PCRE2 install prefix for zig build e13")) |prefix| {
        e13_exe.root_module.addObjectFile(.{ .cwd_relative = b.fmt("{s}/lib/libpcre2-8.a", .{prefix}) });
    } else e13_exe.root_module.linkSystemLibrary("pcre2-8", .{});
    const run_e13 = b.addRunArtifact(e13_exe);
    run_e13.addPassthruArgs();
    b.step("e13", "Compare zig-regex byte mode with PCRE2 on a corpus (zig build e13 -- CORPUS)").dependOn(&run_e13.step);

    // Deterministic fuzzing.
    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/fuzz.zig"),
            .target = target,
            .optimize = if (optimize == .debug) .safe else optimize,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    const run_fuzz = b.addRunArtifact(fuzz_exe);
    const fuzz_iterations = b.option(usize, "fuzz-iterations", "Deterministic fuzz case count") orelse 10_000;
    const fuzz_seed = b.option(u64, "fuzz-seed", "Deterministic fuzz seed") orelse 0x5eed_5eed;
    run_fuzz.addArgs(&.{ b.fmt("{d}", .{fuzz_iterations}), b.fmt("{d}", .{fuzz_seed}) });
    if (b.option([]const u8, "fuzz-target", "Run only fuzz targets whose name contains this")) |only| run_fuzz.addArg(only);
    b.step("fuzz", "Run deterministic fuzz cases").dependOn(&run_fuzz.step);

    // E0: census of ClamAV databases (P3.02). Databases are passed as arguments, never committed.
    const census_exe = b.addExecutable(.{
        .name = "census",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/census.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    const run_census = b.addRunArtifact(census_exe);
    run_census.addPassthruArgs();
    b.step("census", "Count signatures in ClamAV databases (pass the .cvd files after --)").dependOn(&run_census.step);

    // E1: hash index lookup cost and hashing skipped (P3.09), on a compiled database.
    const e1_exe = b.addExecutable(.{
        .name = "e1",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/e1.zig"),
            .target = target,
            .optimize = .fast,
            .link_libc = true,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    const run_e1 = b.addRunArtifact(e1_exe);
    run_e1.addPassthruArgs();
    b.step("e1", "Hash index lookup cost and skipped hashing (pass db, CVD dir and corpus roots after --)").dependOn(&run_e1.step);

    // E2, E3, E4: prefilter census and measurements on a compiled database and the benign
    // corpora (bench/corpus). Installed with the step, so zig-out/bin/prefilter can be rerun.
    const prefilter_exe = b.addExecutable(.{
        .name = "prefilter",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/prefilter.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    const run_prefilter = b.addRunArtifact(prefilter_exe);
    run_prefilter.addPassthruArgs();
    const prefilter_step = b.step("prefilter", "Prefilter census and measurements (pass a command, db and corpus dirs after --)");
    prefilter_step.dependOn(&b.addInstallArtifact(prefilter_exe, .{}).step);
    prefilter_step.dependOn(&run_prefilter.step);

    // The 4-gram frequency model atom selection embeds (src/compile/gram_model.bin).
    const gram_model_exe = b.addExecutable(.{
        .name = "gram-model",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/gram_model.zig"),
            .target = target,
            .optimize = if (optimize == .debug) .fast else optimize,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    const run_gram_model = b.addRunArtifact(gram_model_exe);
    run_gram_model.addPassthruArgs();
    b.step("gram-model", "Build the 4-gram frequency model from benign corpus directories").dependOn(&run_gram_model.step);

    const io_check = b.addExecutable(.{
        .name = "io-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/io_check.zig"),
            .target = target,
            .optimize = .fast,
            .link_libc = true,
            .imports = &.{.{ .name = "zav", .module = zav }},
        }),
    });
    const run_io_check = b.addRunArtifact(io_check);
    run_io_check.addPassthruArgs();
    const io_check_step = b.step("io-check", "Verify the small-file I/O corpus (pass mode, directory and count after --)");
    io_check_step.dependOn(&b.addInstallArtifact(io_check, .{}).step);
    io_check_step.dependOn(&run_io_check.step);

    // Kernel benchmarks (zig-bench is a lazy dependency, fetched only by this step).
    const bench_step = b.step("bench", "Run kernel benchmarks and write a JSON result file");
    if (b.lazyDependency("bench", .{ .target = target, .optimize = .fast })) |bench_dep| {
        // The engine itself is built optimised for benchmarks, whatever -Doptimize says.
        const zav_fast = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = .fast,
        });
        addHashVariants(b, zav_fast, target, .fast);
        zav_fast.addImport("xml", b.dependency("xml", .{ .target = target, .optimize = .fast }).module("xml"));
        zav_fast.addImport("regex", b.dependency("regex", .{ .target = target, .optimize = .fast }).module("regex"));
        zav_fast.addImport("mime", b.dependency("mime", .{ .target = target, .optimize = .fast }).module("mime"));
        const bench_exe = b.addExecutable(.{
            .name = "bench",
            .root_module = b.createModule(.{
                .root_source_file = b.path("bench/main.zig"),
                .target = target,
                .optimize = .fast,
                .imports = &.{
                    .{ .name = "zav", .module = zav_fast },
                    .{ .name = "bench", .module = bench_dep.module("bench") },
                },
            }),
        });
        const run_bench = b.addRunArtifact(bench_exe);
        run_bench.addPassthruArgs();
        bench_step.dependOn(&run_bench.step);
    }
}

/// The public key, as 64 lowercase hex digits, of the test seed made of 32 `byte`s.
fn testPublicKeyHex(b: *std.Build, byte: u8) []const u8 {
    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(byte)) catch unreachable;
    return b.dupe(&std.fmt.bytesToHex(kp.public_key.toBytes(), .lower));
}

fn capiModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, zav: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/capi/capi.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zav", .module = zav }},
    });
}

/// Compile the hash kernels once per CPU variant of the target architecture (src/hash/variants.zig)
/// and link every object into `module`, so one binary carries all of them and src/hash/dispatch.zig
/// picks one at runtime. std.crypto only emits SHA-NI or ARMv8 SHA instructions when the target
/// enables them at compile time, which is why this cannot be a single object. The stage-one
/// prefilter kernel is built per variant the same way (AVX2 and SSSE3 shuffles, vector
/// multiplies), and match/prefilter.zig picks one at runtime.
fn addHashVariants(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) void {
    const arch = target.result.cpu.arch;
    for (hash_variants.forArch(arch)) |spec| {
        var query = target.query;
        query.cpu_arch = arch;
        query.cpu_model = .{ .explicit = arch.parseCpuModel(spec.model) orelse
            std.debug.panic("hash variant {s}: unknown CPU model {s}", .{ spec.name, spec.model }) };
        query.cpu_features_add = .empty;
        query.cpu_features_sub = .empty;
        for (spec.features) |name| query.cpu_features_add.addFeature(cpuFeatureIndex(arch, spec.name, name));
        for (spec.features_sub) |name| query.cpu_features_sub.addFeature(cpuFeatureIndex(arch, spec.name, name));
        const options = b.addOptions();
        options.addOption([]const u8, "name", spec.name);
        const object = b.addObject(.{
            .name = b.fmt("zav-hash-{s}", .{spec.name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/hash/variant_object.zig"),
                .target = b.resolveTargetQuery(query),
                .optimize = optimize,
                // Linked into the shared libzav too.
                .pic = true,
                .imports = &.{.{ .name = "zav_hash_variant", .module = options.createModule() }},
            }),
        });
        module.addObject(object);

        // The stage-one prefilter kernel (src/match/stage1.zig) for the same CPU model.
        const variant_target = b.resolveTargetQuery(query);
        const stage1_options = b.addOptions();
        stage1_options.addOption([]const u8, "name", spec.name);
        const regex_variant = b.dependency("regex", .{ .target = variant_target, .optimize = optimize }).module("regex");
        const stage1 = b.addObject(.{
            .name = b.fmt("zav-stage1-{s}", .{spec.name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/match/stage1_variant.zig"),
                .target = variant_target,
                .optimize = optimize,
                .pic = true,
                .imports = &.{
                    .{ .name = "zav_stage1_variant", .module = stage1_options.createModule() },
                    .{ .name = "regex", .module = regex_variant },
                },
            }),
        });
        module.addObject(stage1);
    }
}

fn cpuFeatureIndex(arch: std.Target.Cpu.Arch, variant: []const u8, name: []const u8) std.Target.Cpu.Feature.Set.Index {
    for (arch.allFeaturesList()) |f| if (std.mem.eql(u8, f.name, name)) return f.index;
    std.debug.panic("hash variant {s}: unknown CPU feature {s}", .{ variant, name });
}
