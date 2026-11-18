# E7: decoders against C libraries

Pass line (docs/DESIGN.md section 14): flate at least 60% of zlib-ng, otherwise optimise. Linking
C into the engine is out of scope (pure Zig, DESIGN section 13 risk 5), so a slow decoder gets
optimised in our code or upstream. The follow-ups set the bar for each format: flate and zstd at
least 60% of the fastest C decoder in this bench (#102, #103), bzip2 at least 80% of libbz2
(#104).

**Verdict: every decoder passes.** flate is at 87 to 95% of libdeflate, zstd at 87 to 91% of
libzstd, bzip2 at 98 to 125% of libbz2 and xz/LZMA2 at 97 to 118% of liblzma. std's flate and
zstd decoders (23 to 52% and 1 to 13%) were replaced by our own.

## Method

- Corpus: `bun bench/e7/run.ts` writes two deterministic 16 MiB inputs to `zig-out/e7`.
  - `text` is English-like words with a Zipf-like frequency.
  - `binary` mixes slowly increasing u32 tables, repeated 24-byte records, noise and runs.
- Each input is compressed with the reference encoders: gzip -6 (node:zlib), bzip2 -9, xz -6
  (liblzma via Python), and zstd -3 and -19 (libzstd in Bun).
- C side: the same script drives libdeflate, Bun's zlib and libzstd through Bun, and the system
  zlib 1.2.12, libbz2 1.0.8 and liblzma through Python. Each call decodes one 16 MiB buffer, so
  the call overhead is negligible. C libraries appear only in this script.
- Zig side: `zig build bench -- zig-out/bench.json e7 [filter]` (bench/main.zig,
  `decoderBenchmarks`). It measures the engine's decoders over memory, through the same
  `Io.Reader` interface the scanner uses, and first checks each decoder's output once against
  the raw corpus file. The engine is built `-O fast`. The optional filter keeps only the corpus
  files whose name contains it (`e7 zst`).
- Every cell is the best of 5 rounds of at least 300 ms, in decompressed MB/s (10^6 bytes per
  second), on one core.
- Machine: Apple M3 Pro (11 cores), macOS 27.2, shared with other build agents. The load moves
  both sides by up to a third from run to run, so the C and Zig benches run interleaved and each
  cell is the best over the runs.
- zlib-ng was not installed and nothing was downloaded. It decodes at least as fast as system
  zlib; libdeflate is the fastest flate decoder in the bench and is the reference.

## Results

Best of 3 interleaved C and Zig runs (load average 8 to 13), plus a quieter run at the start of
the session (load about 5) for the C references, which is the higher of the two for libzstd. The
ratio is against the faster C figure of the two, so it is the conservative one. "Before" is the
engine's decoder before the follow-ups, measured in the quiet run.

| File (compressed size) | Engine decoder | Before | After | Fastest C | MB/s | Ratio |
|---|---|---:|---:|---|---:|---:|
| text.gz (5.6 MB) | zav inflate | 337 (std flate) | 1396 | libdeflate | 1467 | 95% |
| binary.gz (7.9 MB) | zav inflate | 287 (std flate) | 846 | libdeflate | 977 | 87% |
| text.zst (5.6 MB) | zav zstd | 84 (std zstd) | 1369 | libzstd | 1565 | 87% |
| binary.zst (7.8 MB) | zav zstd | 15 (std zstd) | 1779 | libzstd | 1964 | 91% |
| text.zst19 (4.5 MB) | zav zstd | 121 (std zstd) | 1713 | libzstd | 1968 | 87% |
| binary.zst19 (6.0 MB) | zav zstd | 28 (std zstd) | 1414 | libzstd | 1591 | 89% |
| text.bz2 (3.9 MB) | zav bzip2 | 28 to 42 | 54 | libbz2 | 55 | 98% |
| binary.bz2 (9.3 MB) | zav bzip2 | 43 to 46 | 56 | libbz2 | 45 | 125% |
| text.xz (4.5 MB) | zav xz/LZMA2 | 107 | 121 | liblzma | 125 | 97% |
| binary.xz (5.6 MB) | zav xz/LZMA2 | 76 | 80 | liblzma | 68 | 118% |

The other C decoders in the same runs: system zlib 1364 / 800 and Bun's zlib 887 / 592 MB/s on
text.gz / binary.gz. In the loaded runs libzstd measured 1450, 1945, 1222 and 1569 MB/s on the
four zstd files; against those our decoder is at 94, 91, 140 and 90%.

A fourth set of runs under heavier load (average 15 to 62) gave the same picture: every engine
decoder at 85% of its C reference or better.

### First E7 run (before the follow-ups)

Load average about 16: std.compress.flate 261 / 253 MB/s (23 to 52% of the C decoders),
std.compress.zstd 14 to 106 MB/s (1 to 13% of libzstd), our bzip2 18 to 31 MB/s (51 to 94% of
libbz2), our xz/LZMA2 50 to 84 MB/s (87 to 121% of liblzma).

## Findings

- **flate (#102): our own inflater, `src/fmt/inflate.zig`.** std's decoder reads every symbol
  through per-call bit-reader helpers (`takeBits`, `peekIntBitsShort`) and copies matches byte
  by byte through `Writer`. Ours is written from RFC 1951:
  - the hot loop keeps a 64-bit bit buffer in locals and refills it a word at a time straight
    from the input reader's buffer (one unaligned load, branch-free byte count);
  - literal/length symbols decode in one lookup of an 11-bit table (distances 8 bits), with
    second-level tables for longer codes; a length entry carries its base and extra-bit count;
  - up to three literals decode per refill;
  - matches copy 16 or 8 bytes at a time when the distance allows, into slack past the limit.

  It never takes an input byte it has not used (the hot loop gives back the bytes it loaded
  ahead), so gzip trailers, multi-member streams and trailing data stay in the reader. Memory
  is 108 KiB: 32 KiB of history, 64 KiB of output room (32 KiB costs 20%, 128 KiB gains
  nothing) and tables at zlib's enough.c bounds. gzip files, zip method 8, NSIS and DMG zlib
  chunks go through it. Error names match std's.
- **zstd (#103): our own decoder, `src/fmt/zstd/decode.zig`.** `sample` put nearly all of std's
  time in `decodeLiterals`, one Huffman tree step at a time with a memmove in the loop. Ours is
  written from RFC 8878:
  - literals: a single-lookup Huffman table (up to 11 bits) and the four streams decoded
    interleaved, five symbols per stream per refill of a 64-bit backward bit buffer;
  - sequences: FSE tables whose entries carry the next-state baseline and the length or offset
    base with its extra-bit count;
  - with literals fixed, sequence execution was the bottleneck on text: almost all short
    matches, far back in a 2 to 8 MiB window. Sequences are now decoded eight ahead of
    execution with each match source prefetched, and short sequences copy with one 16-byte
    move each. That alone took text.zst from 624 to 1096 MB/s under load.

  A compressed block is read whole, so every bit reader works on memory, and every length,
  offset and table index is checked against the caller's buffers. The output buffer stays twice
  the window plus a block (`zstd.sizing`). Dictionaries are reported as unsupported and the
  content checksum is skipped, both as std does.
- **bzip2 (#104).** A profile of text.bz2 before the change: output walk 39%, bit-at-a-time
  Huffman decode plus the MTF memmove 39%, inverse BWT vector build 11%, CRC 10%. Changes:
  a 10-bit lookup table per Huffman group (symbol and length in one u16, longer codes continue
  through limit/base), the bit buffer in locals for the block loop refilled a word at a time,
  an unrolled MTF shift instead of a memmove call, and a slicing-by-8 CRC-32/BZIP2. After:
  output walk (inverse BWT traversal and RLE1) 54%, Huffman and MTF 31%, BWT vector build 14%,
  CRC 1%. The output walk is a dependent load per byte over a 3.6 MB vector, as in libbz2.
- **xz/LZMA2** was already at liblzma's speed (the range decoder in locals, run-wise match
  copies; see the first run).

### Upstream

The decoders live in zav. std's flate and zstd decoders have a different structure (a reader
with per-call bit helpers, a Huffman tree walk), so the fix is a rewrite rather than a patch.
The rewrites keep std's error names and streaming shape, so they could be offered to Zig std.
The slicing-by-8 CRC in bzip2.zig keeps std's init/update/final shape and would speed up every
MSB-first CRC in `std.hash.crc.Generic`, which updates them a byte at a time.

## What this means for scanning

Decoders run inside the scan, on one core per stream. gzip and zip deflate members now decode at
0.8 to 1.4 GB/s and zstd at 1.4 to 1.8 GB/s, close to the 1 GB/s raw-scan target, so decoding
is no longer the bottleneck for those formats. bzip2 (about 55 MB/s) and xz (80 to 120 MB/s)
remain slow by nature, as their C libraries are.
