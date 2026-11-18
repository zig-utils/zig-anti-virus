# E7: decoders against C libraries

Pass line (docs/DESIGN.md section 14): std flate at least 60% of zlib-ng, otherwise optimise.
Linking C into the engine is out of scope (pure Zig, DESIGN section 13 risk 5), so a slow decoder
gets a follow-up to optimise it in our code or upstream.

## Method

- Corpus: `bun bench/e7/run.ts` writes two deterministic 16 MiB inputs to `zig-out/e7`.
  - `text` is English-like words with a Zipf-like frequency.
  - `binary` mixes slowly increasing u32 tables, repeated 24-byte records, noise and runs.
- Each input is compressed with the reference encoders: gzip -6 (node:zlib), bzip2 -9, xz -6
  (liblzma via Python), and zstd -3 and -19 (libzstd in Bun).
- C side: the same script drives libdeflate, Bun's zlib and libzstd through Bun, and the system
  zlib 1.2.12, libbz2 1.0.8 and liblzma through Python. Each call decodes one 16 MiB buffer, so
  the call overhead is negligible. C libraries appear only in this script.
- Zig side: `zig build bench -- zig-out/bench.json e7` (bench/main.zig, `decoderBenchmarks`). It
  measures the engine's own decoders over memory: std.compress.flate (gzip), std.compress.zstd,
  and our bzip2 and xz/LZMA2. The engine is built `-O fast`.
- Every cell is the best of 5 rounds of at least 300 ms, in decompressed MB/s (10^6 bytes per
  second), on one core.
- Machine: Apple M3 Pro (11 cores), macOS 27.2, shared with other build agents. Load averages ran
  from 10 to 40 during the runs, which accounts for most of the run-to-run spread.
- zlib-ng was not installed and nothing was downloaded. It decodes at least as fast as system
  zlib, so the flate verdict against zlib-ng can only be worse than against the zlib rows.

## Results

Run 2 (C and Zig back to back, load average about 16). Run 1 values are in parentheses where they
differ meaningfully.

| File (compressed size) | Engine decoder | MB/s | C reference | MB/s | Ratio |
|---|---|---:|---|---:|---:|
| text.gz (5.6 MB) | std.compress.flate | 261 | system zlib 1.2.12 | 1050 | 25% |
| | | | Bun zlib | 676 | 39% |
| | | | libdeflate | 1112 | 23% |
| binary.gz (7.9 MB) | std.compress.flate | 253 | system zlib 1.2.12 | 667 | 38% |
| | | | Bun zlib | 486 | 52% |
| | | | libdeflate | 749 | 34% |
| text.zst (5.6 MB) | std.compress.zstd | 106 | libzstd | 998 | 11% |
| binary.zst (7.8 MB) | std.compress.zstd | 14 | libzstd | 1459 | 1% |
| text.zst19 (4.5 MB) | std.compress.zstd | 104 | libzstd | 824 | 13% |
| binary.zst19 (6.0 MB) | std.compress.zstd | 21 | libzstd | 1098 | 2% |
| text.bz2 (3.9 MB) | zav bzip2 | 18 (25) | libbz2 | 35 (33) | 51% (76%) |
| binary.bz2 (9.3 MB) | zav bzip2 | 22 (31) | libbz2 | 33 (33) | 67% (94%) |
| text.xz (4.5 MB) | zav xz/LZMA2 | 69 (84) | liblzma | 79 (91) | 87% (92%) |
| binary.xz (5.6 MB) | zav xz/LZMA2 | 50 (64) | liblzma | 54 (53) | 93% (121%) |

## Findings

- **flate fails the pass line:** 23 to 52% of the C decoders. std's inflater reads bits through
  per-call reader helpers and copies matches byte by byte through `Writer`. Follow-up: #102
  (a table-driven inflater with a word-at-a-time bit buffer, upstream or in `src/fmt`).
- **zstd fails badly:** 1 to 13% of libzstd. `sample` puts almost all of the time in
  `decodeLiterals`. Huffman literals are decoded one tree step at a time
  (`readLiteralsBits` and `HuffmanTree.query` per prefix), with a memmove in the loop. The
  literal-heavy binary corpus suffers most. Follow-up: #103.
  - The window buffer was ruled out. std keeps the whole window in its buffer and slides it with a
    memmove when full. With one block of slack that is a window-sized copy per 128 KiB block, so
    `zstd.sizing` now allocates twice the window plus a block. That made no difference on
    literal-heavy input, but it removes a real per-block cost and stays.
- **bzip2 is borderline:** 51 to 94% of libbz2, with most of the spread from load. Its Huffman
  decode is bit-at-a-time. Follow-up: #104 (a lookup table, and the bit buffer in locals).
- **xz/LZMA2 passes:** 87 to 121% of liblzma. The first measurement was 47 / 36 MB/s, then two
  changes went into `lzma.zig`:
  - The range decoder runs in locals for the whole decode loop instead of through the decoder
    struct, so it stays in registers rather than memory behind a pointer.
  - Matches are copied in runs that neither wrap the dictionary nor overrun the distance, instead
    of byte by byte through `get`/`put`.

  Together these gave 84 / 64 MB/s on a quieter run.

## What this means for scanning

Decoders run inside the scan, so a 250 MB/s inflater is roughly the ceiling for a gzip-heavy
stream on one core. That is below the 1 GB/s raw-scan target but not the dominant cost for
mixed corpora. zstd at 14 to 106 MB/s is the outlier and the first thing to fix (#103). Until
then, zstd members cost about ten times their size in scan time, and the ratio and output limits
still bound them.
