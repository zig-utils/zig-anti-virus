//! Runtime CPU feature detection for variant dispatch. Zig only emits instruction-set extensions
//! the target enables at compile time, so a portable build gets software paths unless the hot code
//! is compiled once per variant and one copy is chosen here at startup (docs/DESIGN.md section 1).
//!
//! x86_64 reads cpuid (and xgetbv for the AVX state the OS saves). aarch64 asks the OS: sysctl on
//! Apple platforms, getauxval on Linux, IsProcessorFeaturePresent on Windows. Other targets report
//! what the compile-time target guarantees.
const std = @import("std");
const builtin = @import("builtin");

/// Instruction-set levels and extensions the running CPU (and OS) support.
pub const Features = struct {
    /// x86-64-v2 per the psABI: cx16, lahf/sahf, popcnt, sse3, ssse3, sse4.1, sse4.2.
    x86_64_v2: bool = false,
    /// x86-64-v3: v2 plus avx, avx2, bmi1, bmi2, f16c, fma, lzcnt, movbe, with AVX state enabled.
    x86_64_v3: bool = false,
    /// SHA-NI (sha1rnds4, sha256rnds2 and the message helpers).
    x86_sha: bool = false,
    /// ARMv8 AES and PMULL.
    aarch64_aes: bool = false,
    /// ARMv8 SHA-1 instructions (sha1c, sha1p, sha1m, sha1h, sha1su0, sha1su1).
    aarch64_sha1: bool = false,
    /// ARMv8 SHA-256 instructions (sha256h, sha256h2, sha256su0, sha256su1).
    aarch64_sha2: bool = false,
};

/// Detect the running CPU's features. Cheap but not free (cpuid serialises); cache the result.
pub fn detect() Features {
    return switch (builtin.cpu.arch) {
        .x86_64 => detectX86(),
        .aarch64 => detectAarch64(),
        else => .{},
    };
}

/// What the compile-time target alone guarantees. A detected feature set is always a superset.
pub fn compileTime() Features {
    const cpu = builtin.cpu;
    return switch (cpu.arch) {
        .x86_64 => .{
            .x86_64_v2 = cpu.hasAll(.x86, &.{ .cx16, .sahf, .popcnt, .sse3, .ssse3, .sse4_1, .sse4_2 }),
            .x86_64_v3 = cpu.hasAll(.x86, &.{ .cx16, .sahf, .popcnt, .sse4_2, .avx, .avx2, .bmi, .bmi2, .f16c, .fma, .lzcnt, .movbe }),
            .x86_sha = cpu.has(.x86, .sha),
        },
        .aarch64 => .{
            .aarch64_aes = cpu.has(.aarch64, .aes),
            .aarch64_sha1 = cpu.has(.aarch64, .sha2),
            .aarch64_sha2 = cpu.has(.aarch64, .sha2),
        },
        else => .{},
    };
}

fn cpuid(leaf: u32, subleaf: u32) [4]u32 {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );
    return .{ eax, ebx, ecx, edx };
}

fn xgetbv0() u32 {
    var eax: u32 = undefined;
    asm volatile ("xgetbv"
        : [eax] "={eax}" (eax),
        : [ecx] "{ecx}" (@as(u32, 0)),
        : .{ .edx = true });
    return eax;
}

fn bit(word: u32, comptime n: u5) bool {
    return (word >> n) & 1 == 1;
}

fn detectX86() Features {
    if (builtin.cpu.arch != .x86_64) return .{};
    const max_leaf = cpuid(0, 0)[0];
    const leaf1 = cpuid(1, 0);
    const ecx1 = leaf1[2];
    const ebx7 = if (max_leaf >= 7) cpuid(7, 0)[1] else 0;
    const max_ext = cpuid(0x8000_0000, 0)[0];
    const ecx_ext = if (max_ext >= 0x8000_0001) cpuid(0x8000_0001, 0)[2] else 0;

    var f: Features = .{};
    f.x86_64_v2 = bit(ecx1, 0) and // sse3
        bit(ecx1, 9) and // ssse3
        bit(ecx1, 13) and // cmpxchg16b
        bit(ecx1, 19) and // sse4.1
        bit(ecx1, 20) and // sse4.2
        bit(ecx1, 23) and // popcnt
        bit(ecx_ext, 0); // lahf/sahf in 64-bit mode
    // AVX needs the OS to save the YMM state: OSXSAVE set and XCR0 enabling SSE and AVX state.
    const os_avx = bit(ecx1, 27) and (xgetbv0() & 0b110) == 0b110;
    f.x86_64_v3 = f.x86_64_v2 and os_avx and
        bit(ecx1, 12) and // fma
        bit(ecx1, 22) and // movbe
        bit(ecx1, 28) and // avx
        bit(ecx1, 29) and // f16c
        bit(ebx7, 3) and // bmi1
        bit(ebx7, 5) and // avx2
        bit(ebx7, 8) and // bmi2
        bit(ecx_ext, 5); // lzcnt
    f.x86_sha = bit(ebx7, 29);
    return f;
}

extern "kernel32" fn IsProcessorFeaturePresent(feature: u32) callconv(.winapi) i32;

fn detectAarch64() Features {
    if (builtin.cpu.arch != .aarch64) return .{};
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => return .{
            .aarch64_aes = sysctlFlag("hw.optional.arm.FEAT_AES"),
            .aarch64_sha1 = sysctlFlag("hw.optional.arm.FEAT_SHA1"),
            .aarch64_sha2 = sysctlFlag("hw.optional.arm.FEAT_SHA256"),
        },
        .linux => {
            const hwcap = std.os.linux.getauxval(std.elf.AT_HWCAP);
            return .{
                .aarch64_aes = hwcap & (1 << 3) != 0, // HWCAP_AES
                .aarch64_sha1 = hwcap & (1 << 5) != 0, // HWCAP_SHA1
                .aarch64_sha2 = hwcap & (1 << 6) != 0, // HWCAP_SHA2
            };
        },
        .windows => {
            // PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE covers AES, PMULL, SHA-1 and SHA-256.
            const crypto = IsProcessorFeaturePresent(30) != 0;
            return .{ .aarch64_aes = crypto, .aarch64_sha1 = crypto, .aarch64_sha2 = crypto };
        },
        else => return compileTime(),
    }
}

fn sysctlFlag(comptime name: [:0]const u8) bool {
    var value: u32 = 0;
    var len: usize = @sizeOf(u32);
    if (std.c.sysctlbyname(name, &value, &len, null, 0) != 0) return false;
    return value != 0;
}

test "detected features include the compile-time target's" {
    const detected = detect();
    const static = compileTime();
    inline for (@typeInfo(Features).@"struct".field_names) |name| {
        if (@field(static, name)) try std.testing.expect(@field(detected, name));
    }
    // Levels nest.
    if (detected.x86_64_v3) try std.testing.expect(detected.x86_64_v2);
}

test "Apple silicon reports the ARMv8 crypto extensions" {
    if (builtin.cpu.arch != .aarch64 or !builtin.os.tag.isDarwin()) return error.SkipZigTest;
    const f = detect();
    try std.testing.expect(f.aarch64_aes and f.aarch64_sha1 and f.aarch64_sha2);
}
