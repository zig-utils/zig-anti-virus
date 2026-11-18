const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The engine as a Zig module: `@import("zav")`.
    const zav = b.addModule("zav", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Executables: the CLI and the daemon.
    for ([_][]const u8{ "zav", "zavd" }) |exe_name| {
        const exe = b.addExecutable(.{
            .name = exe_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("src/cli/{s}.zig", .{exe_name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "zav", .module = zav }},
            }),
        });
        b.installArtifact(exe);
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
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    }) })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = capiModule(b, target, optimize, zav) })).step);

    const c_smoke = b.addExecutable(.{
        .name = "c-smoke",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    c_smoke.root_module.addCSourceFile(.{ .file = b.path("tests/c/smoke.c"), .flags = &.{ "-std=c99", "-Wall", "-Wextra", "-Werror" } });
    c_smoke.root_module.addIncludePath(b.path("include"));
    c_smoke.root_module.linkLibrary(static_lib);
    test_step.dependOn(&b.addRunArtifact(c_smoke).step);

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
    b.step("fuzz", "Run deterministic fuzz cases").dependOn(&run_fuzz.step);

    // Kernel benchmarks (zig-bench is a lazy dependency, fetched only by this step).
    const bench_step = b.step("bench", "Run kernel benchmarks and write a JSON result file");
    if (b.lazyDependency("bench", .{ .target = target, .optimize = .fast })) |bench_dep| {
        const bench_exe = b.addExecutable(.{
            .name = "bench",
            .root_module = b.createModule(.{
                .root_source_file = b.path("bench/main.zig"),
                .target = target,
                .optimize = .fast,
                .imports = &.{
                    .{ .name = "zav", .module = zav },
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
