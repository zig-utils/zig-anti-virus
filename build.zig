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

    const zig_cli = b.dependency("cli", .{ .target = target, .optimize = optimize }).module("zig_cli");

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
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = tree_tests })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = capiModule(b, target, optimize, zav) })).step);

    const c_smoke = b.addExecutable(.{
        .name = "c-smoke",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    c_smoke.root_module.addCSourceFile(.{ .file = b.path("tests/c/smoke.c"), .flags = &.{ "-std=c99", "-Wall", "-Wextra", "-Werror" } });
    c_smoke.root_module.addIncludePath(b.path("include"));
    c_smoke.root_module.linkLibrary(static_lib);
    test_step.dependOn(&b.addRunArtifact(c_smoke).step);

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
/// enables them at compile time, which is why this cannot be a single object.
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
    }
}

fn cpuFeatureIndex(arch: std.Target.Cpu.Arch, variant: []const u8, name: []const u8) std.Target.Cpu.Feature.Set.Index {
    for (arch.allFeaturesList()) |f| if (std.mem.eql(u8, f.name, name)) return f.index;
    std.debug.panic("hash variant {s}: unknown CPU feature {s}", .{ variant, name });
}
