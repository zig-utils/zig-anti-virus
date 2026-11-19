# E2: the stage-one prefilter on the real atom set

Issue: zig-utils/zig-anti-virus#33. Pass line (docs/DESIGN.md section 14): the PE partition at
least 1 GB/s per core including stage two, and at least 3x clamd's raw throughput.

## Setup

- Database: ClamAV main 63, daily 28187 and bytecode 339, `zav compile` (1,628,243 verify
  programs; 392,145 searched through the prefilter after deferral, 1,178,274 deferred, 57,818
  pinned to offsets).
- Corpora: B1 (8,398 files, 356 MB), B2 (12 files, 366 MB), S1 (2,752 mails, 15 MB), from
  bench/corpus. Files are typed by magic only (MZ, ELF, Mach-O, OLE2, PDF; the rest type 0).
- `zig build prefilter -- stages|scan|census <db> <dirs>`: one thread, the whole file in memory,
  best of three passes for `stages`. `zig build bench`: stage one per tier over 1 MiB of random
  bytes with 100k random atoms of one length per partition.
- aarch64: Apple M3 Pro (6 performance cores, 16 MB L2 per cluster, 64 KB L1D), macOS 27.2.
  Other agents were compiling on the same machine throughout (load average 8 to 20 on 11
  cores), so times carry noise of up to 2x; the counters do not.
- x86_64: the `Benchmarks` job of CI (GitHub `ubuntu-latest`, AMD EPYC 9V74, Linux, native
  build), per tier only; the run's `bench-results` artifact has the rest.

## The structure measured

Per partition (target type, plus type 0): split-block Bloom filters (zig-regex `literals.Sbbf`,
16 bits per gram) for stride 8 (tier A), stride 4 (tier B), stride 1 (tier C), 3-byte and 2-byte
grams (tier D); a 64 KiB gate indexed by the first two bytes of every stride-one gram; one atom
table shared by every partition. PE partition (1):

| filter | atoms | grams | bytes | bits set |
|---|---:|---:|---:|---:|
| stride 8 | 284,804 | 1,628,545 | 3.26 MB | 39.4% |
| stride 4 | 74,192 | 255,046 | 510 KB | 39.3% |
| stride 1 | 8,566 | 7,395 | 15 KB | 39.3% |
| 3-gram | 2,297 | 126 | 2 KB | 5.9% |
| 2-gram | 27 | 18 | 2 KB | 0.9% |

Atom table: 1,048,576 slots (28.6% used), 396,964 entries, 331,709 checks, 22.7 MB. The whole
PREFILTER section is 32 MB, in the hot region.

## Results

Stage one alone and with stage two (no verify), B1, aarch64:

| | MB/s per core | candidates per MB | probes per MB |
|---|---:|---:|---:|
| sampled filters only (strides 8 and 4) | 2,261 | 1,731 | 10,485 |
| stride-one filters only, bit-test gate | 927 | 295 | 295 |
| stride-one filters only, byte gate | 1,318 | 295 | 295 |
| all filters, no gate | 269 | 9,232 | 29,061 |
| all filters, bit-test gate | 556 | 2,026 | 10,780 |
| **all filters, byte gate (shipped)** | **762 to 878** | 2,021 | 10,741 |
| all filters, byte gate, stages 1 and 2 | 692 to 703 | | |

The whole body scan (anchored index, prefilter, verify VM, deferred pass, logical evaluation),
best observed per core: B1 280 to 325 MB/s, B2 150 to 165 MB/s, S1 150 to 185 MB/s.

Per tier over 1 MiB of random data (`zig build bench`, MB/s per core):

| | tier A (stride 8, 100k atoms) | tier B (stride 4, 100k) | tier C (stride 1 behind the gate, 100k) | tier D (3-gram, 2k) | tiers A and B |
|---|---:|---:|---:|---:|---:|
| aarch64, M3 Pro | 1,676 | 1,218 | 468 | 2,112 | 2,185 |
| x86_64, EPYC 9V74 | 2,065 | 954 | 334 | 971 | 2,063 |

A tier C of 100k random atoms fills the gate (its 2-byte prefixes cover most of the 65,536
values), the worst case for the stride-one path; the real PE partition's gate passes 5.9% of B1
positions.

## Runtime-variant follow-up (2026-11-18)

Commits `299cd68` and `cb8f848` replaced the two sampled filters with one stride-3
filter, batched the gate passes and linked a stage-one object for every hash CPU variant.
The tables above describe the earlier layout and are retained as the bake-off baseline.

Synthetic stage-one throughput, MB/s per core over 1 MiB of random bytes, best of five:

| variant | stride 3, 11-byte atoms | stride 3, 7-byte atoms | stride 1 gated, 5-byte | tier D, 3-gram | strides 8+4 |
|---|---:|---:|---:|---:|---:|
| x86_64 baseline | 1,122 | 819 | 169 | 1,746 | 1,061 |
| x86_64 v2 | 1,655 | 1,043 | 195 | 1,772 | 1,652 |
| x86_64 v3 | 1,903 | 1,081 | 217 | 1,822 | 2,751 |
| x86_64 v3+sha | 1,869 | 1,069 | 213 | 1,787 | 2,712 |
| aarch64 baseline | 2,421 | 1,403 | 248 | 2,143 | 2,152 |
| aarch64+crypto | 2,390 | 1,383 | 246 | 2,141 | 2,160 |

The x86_64 rows are from the [successful CI run for cb8f848](https://github.com/zig-utils/zig-anti-virus/actions/runs/44406911252),
Benchmarks job, AMD EPYC 9V45 96-Core Processor, Linux. The ARM rows were measured
locally on Apple M3 Pro, macOS 27.2.1, with Zig 0.17.0-dev.1857 and a ReleaseFast
build of `ef2971f` plus the benchmark-reporting changes described below. Both ARM
objects use the generic CPU model; their crypto feature differences do not accelerate
this kernel. Differences between those rows include run-to-run noise.

The reference unit test in `src/match/prefilter.zig` calls every variant the runner can
execute, across sampled strides, gates, unaligned buffers and tails. That CI run passed
all CPU-variant jobs, including x86_64 v2, v3 and the aarch64 runner. A fresh local
`prefilter kernel` check also compared both ARM variants with the scalar reference over
B1, B2 and S1 plus equal-sized random buffers: 11,162 files, 1,473.7 MB total,
3,030,822 candidates, no differences.

Real-atom measurements on the same ARM machine, main 63 + daily 28187 + bytecode 339,
compiled from current source, best of five passes. Every file is forced through the PE
partition with `--partition 1`; stage two is atom-table confirmation, without the VM.
The synthetic benchmark ran concurrently, so these are observations from a shared
machine, not isolated latency guarantees.

| corpus | MB | stage 1 baseline | stage 1+2 baseline | stage 1 crypto | stage 1+2 crypto | candidates/MB | probes/MB | verifies/MB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B1, 8,398 files | 355.9 | 1,205.0 | 971.0 | 1,221.8 | 946.1 | 4,333.5 | 10,925.4 | 551.0 |
| B2, 12 files | 366.4 | 1,202.7 | 787.7 | 1,169.1 | 762.3 | 9,331.7 | 26,052.3 | 477.3 |
| S1, 2,752 files | 14.5 | 1,031.6 | 597.6 | 1,007.3 | 600.9 | 18,086.3 | 53,649.3 | 1,726.9 |

Rates are decimal MB/s per core. Counters agree between variants. These forced-PE
counters are not directly comparable with the earlier tables' magic-selected partitions.
The stride-one gate passes 0.73%, 0.92% and 0.40% of positions respectively. Current PE
filters hold 365,514 stride-3 atoms, 1,005 stride-one 4-byte atoms, 2,372 3-byte atoms and
32 2-byte atoms. PREFILTER occupies 26,536,768 bytes, including a 22,084,736-byte shared
atom table; its longest chain is 40. The bounded expansion and sparse-gram work in #107,
and the text-aware model in #108, remain outstanding.

The real-atom stage-one-plus-two pass line remains **unmet in this measurement**.
Synthetic stage-one rows above 1 GB/s do not establish that pass line, or the 3x clamd
comparison. The runtime-variant implementation and reference checks satisfy #109's
kernel coverage; real-database x86_64 and clamd measurements remain work for #33.

To reproduce, use `zig build prefilter -Doptimize=ReleaseFast -- stages <db> <corpus>
--partition 1 --rounds 5` and `prefilter kernel <db> <B1> <B2> <S1>`. `stages` now reports
both stages for every runnable variant. `zig build bench -- <results.json>` now keeps
all variant names in its JSON artifact; previously only console output kept those rows.

## PE partition after short-atom expansion

The Apple M3 Pro scanned the full B1 and B2 corpora with the PE partition forced
(8,410 files, 722.3 MB). The database used ClamAV main 63 and daily 28187. This
run used ReleaseFast with Zig `0.17.0-dev.1857+3c46da14d` and the best of five
rounds. The benchmark ran alongside other work on the same machine.

| ARM kernel | Stage one MB/s | Stages one and two MB/s | Candidates per MB |
|---|---:|---:|---:|
| aarch64_crypto | 1,142.1 | 683.3 | 6,837.4 |
| aarch64_baseline | 1,179.0 | 854.5 | 6,837.4 |

Both kernels recorded 18,565.9 probes and 509 verifies per MB. The stride-one
gate passed 0.83% of positions. Both runs fell short of the 1 GB/s target for
the two stages together. Real-corpus x86_64 and clamd measurements remain open.

### Hosted measurements

The manual `Prefilter benchmark` workflow measures B1 and B2 separately on
native Linux x86_64 and aarch64 runners. It pins each benchmark process to one
allowed logical CPU and records the CPU topology, Zig version, commit, and CVD
checksums. The timed stage-one-plus-two loop uses the same disabled telemetry
setting as a normal scan. A separate pass records candidate and probe counts.
Earlier tables include the cost of collecting those counters during the timed
pass. The workflow uploads measurements only. Compare CVD checksums when
interpreting results from the two runners.

A local run with this timing method over combined B1 and B2 measured 850.9 MB/s
for the ARM crypto kernel and 850.1 MB/s for the ARM baseline through stages
one and two. The candidate, probe and verify counts per MB matched the previous
combined run. The 1 GB/s target remains unmet on this ARM measurement.

The [native Linux run](https://github.com/zig-utils/zig-anti-virus/actions/runs/44454816241)
used Zig 0.17.0-dev.1857+3c46da14d and identical main and daily CVDs on both
runners. Each figure is the best of five rounds on one logical CPU, using the
active kernel reported by the run. Both stages operated on the same PE partition
of the full compiled database.

| CPU | Corpus | Stage 1 (MB/s) | Stages 1+2 (MB/s) | Candidates/MB | Probes/MB | Verifies/MB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| AMD EPYC 9V74, x86_64 v3 SHA | B1 | 653.3 | 555.2 | 4,308.2 | 10,900.1 | 546.8 |
| AMD EPYC 9V74, x86_64 v3 SHA | B2 | 647.0 | 454.4 | 9,294.4 | 26,013.2 | 472.3 |
| Arm Neoverse-N2, aarch64 crypto | B1 | 426.3 | 380.5 | 4,308.2 | 10,900.1 | 546.8 |
| Arm Neoverse-N2, aarch64 crypto | B2 | 407.2 | 318.2 | 9,294.4 | 26,013.2 | 472.3 |

B1 provided 8,398 nonempty files (355.9 MB) and B2 provided 12 (366.4 MB).
The x86_64 guest reported four logical CPUs with two threads per core. The
Arm guest reported four logical CPUs with one thread per core. The artifacts
contain measurements for every runnable kernel. Candidate, probe and verify
counts agreed across architectures and kernels. The Linux runs missed the
1 GB/s pass line in both corpora. A controlled SMT comparison, cache-miss
counts, a clamd raw baseline and the full alternative bake-off remain open.

## Against the other designs

The alternatives were measured in zig-regex (docs/BENCHMARKS.md, binary literal sets of 100k
and 400k, same machine class), whose `literals` module this prefilter reuses:

- **Dense Aho-Corasick** is not built past 256 MiB: 100k binary literals already exceed it, and
  the searched set here is 392k programs.
- **Sparse Aho-Corasick** builds (232 MiB, 3.4 s, 634 MiB peak) and scans 400k binary literals
  at 40 MB/s: the failure walks on binary input are the cost DESIGN.md predicted.
- **Teddy** holds at most 64 literals: no partition is that small (the smallest stride-one
  filter, partition 0's, has 154 atoms).
- **FDR** (shift-or over buckets) was not built: with the split-block filter's candidate rate
  already at 0.2% of positions on B1, the remaining cost is in reading short atoms at every
  position, which FDR also does.

## Initial decision

Split-block Bloom filters by tier, with tier-D deferral and the stride-one gate, are the stage
one. The pass line is **missed on this machine**: stage one on the PE partition runs at 0.76 to
0.88 GB/s per core and stage one plus two at 0.69 to 0.70 GB/s on B1, against 1 GB/s; the
sampled filters alone run at 2.26 GB/s. The difference is the stride-one tier (11k atoms in the
PE partition, mostly `.ndb` signatures with no literal of 7 bytes), which costs one gate load per
byte. Follow-ups: zig-utils/zig-anti-virus#107 (4-byte atoms for tier D, which removes most of
the 3-gram filter), zig-utils/zig-anti-virus#109 (CPU-variant builds of the kernel, x86-64-v3
and aarch64, dispatched at runtime) and zig-utils/zig-anti-virus#108 (a text-aware model for
mail and HTML). clamd's raw throughput on the same corpus is not measured yet (P6.15).

No losing variant is kept: the zig-regex structures stay in zig-regex, where their benchmarks
live.
