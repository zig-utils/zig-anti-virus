# E1: hash index lookup cost and the share of hashed bytes skipped

Pass line (docs/DESIGN.md section 14): a warm lookup takes at most 300 ns, and at least 70% of
MD5 bytes are skipped on the benign corpus B1. If missed: add a binary fuse filter or rework the
size map.

## Method

- `zig build e1 -Doptimize=fast -- <compiled.zavdb> <clamav-db-dir> <corpus-root>...`
  (bench/e1.zig). The database is compiled from main 63, daily 28187 and bytecode 339 with
  `zav compile` (hash index format version 2: bit-per-size need maps, 4-byte hot keys with a
  size radix, cold digest tails).
- Lookups go through the structures the scan path uses (`engine.hashscan.HashIndex`): need map,
  hot table, cold row, SIGMETA. One thread. Each figure is the mean over the whole probe set; the
  warm figure is the second of two passes, so the database pages are in the page cache (not in
  the CPU caches: probes are shuffled over 3.2 million entries).
  - Hits: every sized MD5 hash line of the CVDs (3,212,645 probes, file and PE section tables).
  - Misses: the same sizes with random digests (the costly miss: the size has entries).
  - Cold: 2,000 hits on a fresh copy of the database written with `F_NOCACHE` (macOS) or dropped
    with `POSIX_FADV_DONTNEED` (Linux), so first touches read from the SSD.
  - Synthetic: 4M MD5 plus 1M SHA-256 random digests over the real distinct sizes, 1M probes.
- Skipped hashing: every regular file under the corpus roots, asked `NeedMap.mask(size)` for the
  whole-file scope. B1 is every file; B2 is the files of 4 MiB or more among them. Each algorithm
  is counted with the real need map and with the size-less signatures left out.
- Hardware: Apple M3 Pro (11 cores), macOS 27.2, internal SSD. Other agents were compiling on
  the machine (load average 7 to 14), so absolute times carry some noise.
- Corpus: `/usr`, `/Applications`, `/Library` and `/System/Library/Frameworks` of a stock macOS
  27.2 install with developer tools: 307,243 files, 27.2 GB (B2: 825 files, 16.8 GB). The run's
  manifest digest is in the report below (it depends on walk order).

## Results

| tables | warm hit | warm miss (populated size) | cold hit |
|---|---:|---:|---:|
| real: 3.21M entries (2.67M section, 0.54M file) | 223 ns | 196 ns | 142 µs |
| synthetic: 4M MD5 + 1M SHA-256 | 192 ns | 107 ns | |

Before the size radix (same database otherwise) the real tables took 337 ns per hit and 300 ns per
miss: the size binary search over 70,000 to 174,000 sizes cost several cache misses. The radix
(65,537 u32 entries, only for tables with more than 4,096 sizes, 0.5 MB of hot region in total)
brings it to at most one.

| corpus | files | GB | MD5 skipped (files / bytes) | SHA-1 | SHA-256 | MD5 without size-less | SHA-256 without size-less |
|---|---:|---:|---:|---:|---:|---:|---:|
| B1 all files | 307,243 | 27.20 | 0% / 0% | 100% / 100% | 0% / 0% | 38.4% / 91.6% | 99.5% / 99.97% |
| B2 files of 4 MiB or more | 825 | 16.83 | 0% / 0% | 100% / 100% | 0% / 0% | 99.2% / 99.7% | 100% / 100% |

Database open (reader.open plus HashIndex.load, warm page cache): 0.8 ms (7.6 ms on the run right
after the database was written).

## Decisions

1. **Lookup cost passes**: 223 ns warm on the real tables, 192 ns on 4M + 1M, against 300 ns.
2. **No binary fuse filter.** Misses are already cheap (196 ns warm), and files whose size has no
   signature never reach a table at all. A filter only helps a miss whose hot pages were evicted,
   and then it trades one page fault on the keys for one on the filter: about 3.6 MB of filter
   (9 bits per key) against 13 MB of keys and 3.2 MB of need maps, which the hot region keeps
   resident anyway (and `mlock` can pin on small hosts, DESIGN risk 10). Cold lookups are
   dominated by SSD page-ins (142 µs for two or three pages), which a filter does not remove for
   hits.
3. **The MD5 skip line is missed only because of 13 size-less signatures.** The size map itself
   skips 91.6% of MD5 bytes on B1 and 99.7% on B2. But E0 found 11 size-less MD5 and 2 size-less
   SHA-256 signatures (all `*` with level 73, in main.hsb), and one size-less signature means the
   algorithm runs on every file. ClamAV's signature documentation notes the same cost for `*` sizes, so
   parity costs what it costs clamd, and SHA-1 is still skipped everywhere. What it does
   change is the throughput ceiling: MD5 runs at about 730 MB/s per core (E8), below the 1 GB/s
   per core raw-scan target, for every byte of every file. Options, for a maintainer decision:
   - keep parity (current behaviour, and the default);
   - an opt-in engine option that applies size-less hash signatures only to files up to a
     size cap, with the coverage report counting them as partially applied;
   - ask Talos to give these 13 signatures sizes (they are CVE exploit samples of known size).

## Report

# E1 run

- CPU: Apple M3 Pro, macos aarch64
- database: /private/tmp/claude-501/-Users-chris-Code-stacks/40dce3ee-e812-4472-98ab-ebe6cb8165ea/scratchpad/zav/gate.zavdb

## Open

reader.open plus HashIndex.load, warm page cache: 0.80 ms.

## Every hash signature (P3.15)

- hash lines: 3212898
- found under their own name: 3211373
- found under the name of an identical rule: 1518
- not found: 7 (expected: the hash rules the coverage report lists as ignored)

## Lookup cost

Nanoseconds per lookup, one thread, mean over the whole set (warm: second pass).

| tables | probes | warm hit | warm miss (populated size) | cold hit |
|---|---:|---:|---:|---:|
| main + daily (real, 3212898 MD5 entries) | 3212645 | 223 | 196 | 141849 |
| synthetic 4M MD5 + 1M SHA-256 | 1000000 | 192 | 107 | n/a |

Synthetic hot sections: 29.0 MB (need map plus hot tables).

## Hashing skipped by the need map

Corpus roots: `/usr`, `/Applications`, `/Library`, `/System/Library/Frameworks`. Manifest SHA-256 (root, path, size per file, walk order): `e7da859c7be2348de0d4cb03ee94e99822258ed80d554cc01cf93951b134105d`. Unreadable entries: 11.

| corpus | files | GB | MD5 files / bytes skipped | SHA-1 | SHA-256 | MD5 without size-less sigs | SHA-256 without size-less sigs |
|---|---:|---:|---:|---:|---:|---:|---:|
| B1 all files | 307243 | 27.20 | 0.0% / 0.0% | 100.0% / 100.0% | 0.0% / 0.0% | 38.41% / 91.59% | 99.48% / 99.97% |
| B2 files of 4 MiB or more | 825 | 16.83 | 0.0% / 0.0% | 100.0% / 100.0% | 0.0% / 0.0% | 99.15% / 99.69% | 100.00% / 100.00% |
