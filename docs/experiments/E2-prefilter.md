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

## Decision

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
