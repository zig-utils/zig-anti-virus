# E8: hardware hashers, baseline vs native builds

Pass line (docs/DESIGN.md section 14): SHA-256 at least 1.5 GB/s and SHA-1 at least 2 GB/s with
hardware. If missed, keep the software paths and lean on size gating.

## Method

- `zig build bench -- zig-out/bench.json` (bench/main.zig, `hashBenchmarks`). The engine module is
  built `-O fast` for the bench whatever `-Doptimize` says.
- One core, a 1 MiB random buffer (L2 resident), one `update` plus `final` per call. Each cell is
  the best of 5 rounds of at least 100 ms. MB/s means 10^6 bytes per second.
- Rows: every kernel variant linked into the binary that the CPU can run (src/hash/variants.zig),
  `portable` (the kernels compiled into the engine for the bench target, which is the host CPU),
  and `std (bench target)` (std.crypto called directly, compiled for the host CPU). The last two
  are what a `-Dcpu=native` build would get, so they are the "native build" column of E8.
- x86 numbers come from the CI `Benchmarks` job (GitHub-hosted ubuntu runners, which land on
  different CPUs from run to run); the job was re-run to sample several. The CPU name is printed
  by `zav.simd.arch.brand`.

## Results

### Apple M3 Pro (macOS 27.2, this repository's development machine)

| Variant | MD5 | SHA-1 | SHA-256 | HW SHA-1 / SHA-256 |
|---|---:|---:|---:|---|
| aarch64_crypto (generic+aes+sha2) | 736 | 2592 | 2479 | yes / yes |
| aarch64_baseline (generic) | 734 | 1032 | 366 | no / no |
| portable (apple_m3) | 725 | 2550 | 2454 | yes / yes |
| std (apple_m3) | 733 | 1034 | 2451 | no / yes |

Fused MD5 + SHA-1 + SHA-256 (active variant): 461 MB/s. Three later runs on the same machine
under heavy concurrent load (load average 17 on 11 cores) read 10 to 20% lower across the board
(SHA-1 2179 to 2408, SHA-256 2161 to 2295); the table is the quiet run.

### AMD EPYC 9V45 (Zen 5), CI, two runs

| Variant | MD5 | SHA-1 | SHA-256 | HW |
|---|---:|---:|---:|---|
| x86_64_v3_sha | 762 / 763 | 2239 / 2319 | 1857 / 1916 | yes / yes |
| x86_64_v3 | 753 / 762 | 996 / 1007 | 426 / 423 | no / no |
| x86_64_v2 | 701 / 699 | 1023 / 1007 | 407 / 399 | no / no |
| x86_64_baseline | 704 / 698 | 1058 / 1051 | 397 / 397 | no / no |
| portable (native) | 820 / 817 | 2286 / 2313 | 1893 / 1968 | yes / yes |
| std (native) | 800 / 831 | 1076 / 1124 | 1889 / 1854 | no / yes |

Fused: 423 / 416 MB/s.

### Intel Xeon 6975P-C (Granite Rapids), CI

| Variant | MD5 | SHA-1 | SHA-256 | HW |
|---|---:|---:|---:|---|
| x86_64_v3_sha | 665 | 2104 | 1624 | yes / yes |
| x86_64_v3 | 665 | 858 | 332 | no / no |
| x86_64_v2 | 643 | 833 | 336 | no / no |
| x86_64_baseline | 643 | 855 | 328 | no / no |
| portable (native) | 796 | 2106 | 1668 | yes / yes |
| std (native) | 796 | 1004 | 1668 | no / yes |

Fused: 386 MB/s.

### AMD EPYC 9V74 (Zen 4), CI

| Variant | MD5 | SHA-1 | SHA-256 | HW |
|---|---:|---:|---:|---|
| x86_64_v3_sha | 625 | 1938 | 1600 | yes / yes |
| x86_64_v3 | 625 | 768 | 321 | no / no |
| x86_64_v2 | 601 | 764 | 305 | no / no |
| x86_64_baseline | 601 | 788 | 307 | no / no |
| portable (native) | 682 | 1935 | 1612 | yes / yes |
| std (native) | 683 | 809 | 1610 | no / yes |

Fused: 366 MB/s.

### AMD EPYC 7763 (Zen 3), CI, two runs, before the v2 fix below

| Variant | MD5 | SHA-1 | SHA-256 | HW |
|---|---:|---:|---:|---|
| x86_64_v3_sha | 550 / 548 | 1697 / 1697 | 1382 / 1396 | yes / yes |
| x86_64_v3 | 555 / 549 | 660 / 661 | 280 / 281 | no / no |
| x86_64_v2 (with shld rotates) | 453 / 454 | 360 / 360 | 144 / 144 | no / no |
| x86_64_baseline | 529 / 529 | 703 / 705 | 250 / 253 | no / no |
| portable (native) | 603 / 601 | 1697 / 1698 | 1370 / 1370 | yes / yes |
| std (native) | 603 / 603 | 694 / 693 | 1370 / 1369 | no / yes |

Fused: 320 / 320 MB/s.

### Rosetta 2 on the M3 Pro (x86_64-macos binary, emulated)

Used only to run the x86 variants and their dispatch locally (`zig build test -Dtarget=x86_64-macos
-frosetta`). Rosetta exposes x86-64-v2 without AVX2 or SHA-NI, so dispatch picks `x86_64_v2` and
skips the v3 objects; the vector, split-update and fuzz tests pass on both runnable x86 variants.
Its throughput (SHA-1 about 530 MB/s, SHA-256 about 270 MB/s) measures the translator, not a CPU.

## Pass line

| CPU | SHA-1 (HW) | SHA-256 (HW) | Verdict |
|---|---:|---:|---|
| Apple M3 Pro | 2.59 GB/s | 2.48 GB/s | pass |
| AMD EPYC 9V45 (Zen 5) | 2.24 to 2.32 GB/s | 1.86 to 1.92 GB/s | pass |
| Intel Xeon 6975P-C | 2.10 GB/s | 1.62 GB/s | pass |
| AMD EPYC 9V74 (Zen 4) | 1.94 GB/s | 1.60 GB/s | SHA-256 passes, SHA-1 3% short |
| AMD EPYC 7763 (Zen 3) | 1.70 GB/s | 1.38 to 1.40 GB/s | miss |

Where the line is missed, the variant matches std compiled for that exact CPU (Zen 3: 1382 vs
1370 MB/s SHA-256), so the shortfall is the CPU's SHA-NI throughput, not dispatch.

## Findings and decisions

1. **Keep the variant dispatch.** In the same distributed binary the hardware variant runs SHA-1
   2.1 to 2.5x and SHA-256 4.7 to 6.8x faster than the baseline object on every CPU tested, and
   matches a native build of std within noise. Without it a portable binary would hash SHA-256 at
   250 to 400 MB/s.
2. **Only the SHA variant matters for hashing.** x86-64-v2 and v3 without SHA are within a few
   percent of baseline for all three algorithms. v3 stays because it is the base of the SHA
   variant (std's SHA-256 hardware rounds also use AVX2) and the scan kernels can share it.
3. **x86-64-v2 needed a fix.** LLVM's x86-64-v2 model sets the `fast_shld_rotate` tuning flag, so
   every rotate in the v2 object became `shld` (676 of them, no `rol`). On Zen 3 that halved
   SHA-1 and SHA-256 against baseline (360 vs 705 and 144 vs 253 MB/s). The v2 spec now removes the
   flag (`features_sub` in src/hash/variants.zig); on Zen 4, Zen 5 and Granite Rapids v2 is back
   level with baseline. v3 rotates with BMI2 `rorx` and never had the problem.
4. **MD5 is the floor: 550 to 830 MB/s per core**, with no hardware help on any CPU, matching the
   design's 600 to 700 MB/s estimate. On x86 a native build is 8 to 20% faster on MD5 than any
   variant object (Granite Rapids 796 vs 665), which is scheduling for the exact microarchitecture, not
   ISA. Open: tune the variant objects (or add per-family tuning) if MD5 shows up in profiles.
5. **The fused pass costs the sum of its parts.** On the M3 Pro, 1/(1/736 + 1/2592 + 1/2479)
   predicts 465 MB/s and the fused pass ran at 461; Zen 5 predicts 435 and ran at 423. One pass
   saves memory traffic, not compute. An interleaved MD5 plus SHA kernel could fill the execution
   ports MD5's serial chain leaves idle; not pursued.
6. **Size gating is mandatory, hardware or not.** MD5 alone costs 1.2 to 1.8 ns per byte, already
   over the 1 ns per byte budget of the 1 GB/s per core scan target; all three cost 2.2 to 3.1 ns.
   Every byte the size-gated need map skips (E1) saves more than the byte's whole scan budget, and
   speculative mode (Multihash limits) stops each hasher at the largest signature size of its
   table for streams of unknown length.
7. **Dispatch overhead is negligible.** Detection runs once: 2.2 to 3.0 us on the M3 Pro (three
   sysctl calls) and 2.8 to 4.7 us on the CI VMs (cpuid traps to the hypervisor). Per message, a
   64-byte SHA-256 costs 62 vs 52 ns (M3 Pro) and 98 to 133 vs 91 to 128 ns (x86) against std
   called directly: two indirect calls, the chaining-state copy and the padding block, a few to 25
   ns per file. On 1 MiB the variant and native std are within noise.

## Reproduce

```sh
zig build bench -- zig-out/bench.json                   # this machine
zig build test -Dtarget=x86_64-macos -frosetta          # x86 variants under Rosetta (Apple silicon)
gh run view <run> --job <Benchmarks job> --log | grep 'hash:'   # CI runner numbers
```
