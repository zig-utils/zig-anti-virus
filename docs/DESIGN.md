# zav design: an mmap-first anti-malware engine in Zig

This document is the performance and memory design for `zav`.

How sure each claim is:
- **[R]**: read in source.
- **[K]**: well-established public fact.
- **[E]**: estimate. One of the experiments in section 14 must confirm it.
- **[M]**: measured; the experiment in section 14 that measured it has the method and hardware.

Every [E] figure is provisional until an experiment replaces it with a measurement. Database counts come from E0 ([census](experiments/E0-census.md): main 63, daily 28187, bytecode 339).

The [P3 hash gate](experiments/P3-hash-gate.md) records complete hash-rule lookup coverage,
raw benign-file scans, the EICAR verdict and the measured hash-only memory envelope.

## 0. Decisions

1. **Compile offline, mmap at runtime.**
   - One signed, versioned, little-endian blob holds offsets only and no pointers.
   - Loading it is `mmap(PROT_READ)` plus header checks: 0.8 ms with the hash index of the full ClamAV databases, warm page cache [M] (E1).
   - All signature data lives in clean file-backed pages, so signatures cost about 0 MB of private dirty memory.
   - Compiling from CVD happens in a separate short-lived process (`zav compile`), never inside the daemon.
2. **Hashes use a size-gated two-tier index.**
   - A per-file-size "which hashes are needed" map lets most files skip hashing entirely.
   - The hot tier is an 8-byte digest prefix; the full digest is read only on a hit.
   - Only the algorithms needed are computed, in one fused pass.
3. **Byte patterns use a prefilter with no loop-carried dependency, not Aho-Corasick.**
   - Each subsignature gets one rare 4-byte atom, chosen with a byte-frequency model.
   - Atoms go into a sampled q-gram split-block Bloom filter (SBBF), partitioned by target type.
   - Hits are confirmed in an atom hash table, then checked by a small pattern VM.
   - Signatures with fixed offsets (EP+n, EOF-n, Sx+n) are checked directly and never scanned for.
   - Logical signatures keep sparse per-file state and are evaluated only when touched.
4. **The hot loop allocates nothing.**
   - Each worker has a scratch arena: an anonymous reservation, faulted in lazily and trimmed with madvise when idle.
   - A global budget for large decoder windows bounds peak memory.
5. **The runtime is a work-stealing pool, one worker per physical core.**
   - A bounded injector queue stops socket reads when workers are saturated.
   - Database reloads use epoch-based reclamation, so a reload adds no private memory.
6. **I/O defaults to pread into a reused per-thread buffer.**
   - mmap is used only for large random-access members, because munmap in a multithreaded process triggers TLB-shootdown IPIs [K].
   - On Linux, io_uring batches open/statx/read/close for small files.
7. **File extensions:** the compiled database is `.zavdb` and the CVE index is `.zavcve`. ClamAV already uses `.gdb` for phishing signatures, and neither new extension collides with ClamAV's list.

## 1. Building blocks

| Block | Finding | Decision |
|---|---|---|
| zig-waf `src/phrase.zig` | [R] Lowercases ASCII and binary-searches edges per node. Every byte walks the failure chain. Matches don't say which pattern hit. Heap slices. | Not suitable for signatures. Replace it with the shared zig-regex `literals` module (binary-safe, pattern ids, relocatable), which zig-waf can also adopt. |
| zig-regex | [R] Has a real lazy DFA (i32 transitions, up to 16,384 states, so up to about 16 MiB per regex per thread), a step-bounded backtracker and literal prefilters. **No byte mode**: `\xHH` maps to that code point's UTF-8 bytes. Runtime heap NFA. The DFA is mutable per matcher. | Needed for PCRE subsignatures, YARA regex and container filename regexes. Upstream: byte mode, an allocation-free matcher with caller-supplied scratch, a configurable state cap (about 256), a required-literal extraction API, and serialisable programs. Until programs serialise, compile on first trigger into a bounded process-wide cache of about 4 MB. |
| zig-xml | [R] Pull tokenizer over a whole slice. | Use it for small OOXML parts. Upstream an incremental `Io.Reader` input. HTML normalisation is its own byte-level state machine. |
| zig-cli | [R] Typed command framework that also has TOML and JSON5 parsers. | Use it for the `zav` CLI and native config. `clamd.conf` gets its own small parser. |
| zig-benchmarks | [R] Timer micro-benchmarks with baseline comparison. Allocator-only memory profiling. Some pre-0.17 std calls. | Port it, and add external-process RSS/PSS/smaps sampling. The end-to-end harness is new. |
| Home language compression package | [R] gzip wraps `std.compress.flate`. The `zstd`, `brotli` and `lz4` modules do not implement the spec formats. | Do not use. All decoders are our own, streaming over `Io.Reader`: flate and zstd because std's ran at 23 to 52% and 1 to 13% of C (E7), xz and LZMA because std's lzma2 buffers without bound, and bzip2 because std has none. |
| mail MIME parser | [R] Whole-body multipart parsing, not recursive, allocates per part. Recognises only CRLF header terminators. | Build the streaming `zig-mime` walker: SIMD boundary search, a nested stack, streaming base64 and quoted-printable decoding, tolerant line endings. Reuse the ContentType and boundary validation. |
| `std.Io.File.MemoryMap` | [R] Defaults to read and write with populate. Silently falls back to heap allocation plus read if mmap fails. | Never use it for the database: a fallback would turn the blob into private memory. Call `posix.mmap(PROT_READ, MAP_PRIVATE)` directly and fail hard. |
| `std.crypto` | [R] SHA-256 uses SHA-NI or ARMv8 instructions only when they are enabled at compile time. SHA-1 and MD5 are software only. | Build CPU-variant objects (x86-64-v2, v3, v3+sha, aarch64+crypto) and choose one at runtime. Add hardware SHA-1 kernels. MD5 is inherently serial, about 600-700 MB/s per core [K]. |
| `std.zip`, `std.tar` | [R] zip handles store and deflate only and needs a seekable reader. tar streams. | Use std.tar, and std.tar with flate to read the CVD. Write our own zip parser: zip64, data descriptors, encryption, overlap detection, local-header fallback. |

**Toolchain:** Zig 0.17.0-dev.1857 or newer.

## 2. Scope and coverage

**In scope for phase 1:**
- Hash formats: `.hdb .hsb .mdb .msb .imp`.
- Allow and ignore lists: `.fp .sfp`, plus `.ign2`, which is applied at compile time.
- Byte and logical signatures: `.ndb` and `.ldb`, including PCRE and byte-compare subsignatures.
- Container and file-type signatures: `.cdb .ftm`.
- The YARA subset, Guardian rules and the MalwareBazaar feed.

**Phase 2:** `.pdb .wdb` (they need HTML and URL extraction), `.idb`, and `.crb .cat` (Authenticode trust).

**Out of scope:** `.cbc` bytecode.
- bytecode.cvd holds 85 programs [M]: family-specific decryptors and unpackers, plus a few PDF and JS heuristics.
- By signature count that is 0.0023% of 3.64 million [M]. By unique detections on a current corpus, it is estimated at under 0.5% [E].
- Experiment E9 measures it by comparing `clamscan --bytecode=no` with the default.

**Coverage report:** the compiler declares a functionality level and writes a report that counts every skipped signature by reason (unsupported target, PCRE feature, bytecode trigger, missing container parser). Coverage loss is therefore a measured number.

**The largest risk is parser and normaliser parity, not matching speed.** A signature for normalised HTML never fires unless we produce the same normalised stream ClamAV does. Section 6 phases this work, and E9 gates it.

## 3. `.zavdb` layout

- All integers are little-endian; big-endian hosts are refused.
- Every record is an `extern struct` with comptime size and alignment asserts.
- References are `u32` offsets relative to their section.
- Nothing is relocated at load, and nothing in the mapping is ever written.

### 3.1 Header (4096 bytes)

```
off  size  field
0    8     magic "ZAVDB\0\r\n"
8    2     format_major      10  2  format_minor
12   4     header_size = 4096
16   8     feature_flags (required engine features)
24   8     db_version (monotonic)
32   8     build_unix_time
40   8     total_size
48   4     section_count     52  4  section_table_off (= 512)
56   64    source versions: main, daily, bytecode (ignored), feed, yara set, guardian, engine level
256  32    blake3 root over [4096, total_size)
288  8     key_id
296  64    ed25519 signature over header[0..296]
512  64*N  section table: { kind u32, variant u16, flags u16, offset u64, size u64,
           xxh3_64 u64, align_log2 u8, partition u8, pad[22] }
```

**At daemon start:** check the magic, versions, the header signature, that section bounds fall inside the file, and the section-table xxh3.

**At install:** the full BLAKE3 over the body runs once. The result is recorded in a sidecar keyed by (dev, ino, size, mtime_ns), so starting from a warm page cache never re-reads the whole blob. `--verify-full` forces the full check.

### 3.2 Section order

The hot region comes first, starting on a 2 MiB boundary. Everything else follows, 4 KiB aligned.
- **Hot:** `HASH_NEED_MAP`, `PREFILTER[p]`, `ATOM_TABLE[p]`, `ANCHORED_INDEX[p]`, `FTM_TRIE`, `HASH_HOT[t]`.
- **Warm:** `SUBSIG_PROG`, `LITERAL_POOL`, `LDB_TABLE`, `CDB_TABLE`, `SIGMETA`.
- **Cold:** `HASH_COLD[t]`, `FP_TABLES`, `NAME_POOL`, `REGEX_POOL`, `YARA_COND`, `DELTA_INDEX`, `COVERAGE_REPORT`.

### 3.3 Hash tables

A table t is one combination of algorithm (MD5, SHA1, SHA256) and kind (whole file, PE section, import hash). MalwareBazaar goes into the SHA256 whole-file table, tagged with its own source.

**`HASH_NEED_MAP`** is the per-file gate, consulted before any hashing. One map per scope, and inside it one structure per algorithm, sized by how many distinct sizes that algorithm has (version 2, after E0):
- More than 4,096 distinct sizes (in practice only MD5): a bitmap, one bit per size below 2^24, as a top table of 2,048 block numbers and 1 KiB blocks for the 8,192-size ranges that have any size; larger sizes in a sorted u64 list.
- Up to 4,096 (SHA-1 and SHA-256 today): a sorted u64 list, at most 12 probes.
- A global `sizeless_mask` covers entries with `*` as the size. Any algorithm in it must be computed for every file.
- E0 found 13 such entries (11 MD5, 2 SHA-256, all whole-file, in main.hsb) [M]. So MD5 and SHA-256 run on every scanned file, as they do in ClamAV; the map still gates SHA-1, PE section hashing and which tables are probed.
- Sizes below 2^24 cover 98.7% of whole-file MD5 entries (174,283 distinct sizes) and 99.99% of PE section entries (69,636 distinct sizes) [M].

**`HASH_HOT[t]`** holds the keys:
```
sizes:   [D]u64 sorted distinct sizes
starts:  [D+1]u32 entry index per size
radix:   [65537]u32 first size index per 256-size range below 2^24 (tables with over 4,096 sizes)
keys:    [N]u32 first 4 digest bytes, big-endian, sorted within each size bucket
```
- The radix narrows the size search to at most 256 sizes; buckets are binary-searched. The largest real bucket holds 38,871 entries (E0), so a 32-bit prefix collision inside a bucket happens on about 1 lookup in 100,000 and costs one extra cold read; it can never become a detection.
- Measured on main 63 + daily 28187 [M]: 3.21 million entries, need maps 3.2 MB plus hot tables 16.3 MB, so 19.5 MB of hot region for hashes (version 1, with 4-bit need maps and 8-byte keys: 41 MB).

**`HASH_COLD[t]`** holds the rest of each digest (after its first 4 bytes) and the u32 signature id, in the same order: 16 bytes per MD5 row, 51 MB for the real databases. Rows are read only on a prefix hit, and the full digest is always compared.

**Other tables:**
- Size-less tables use interpolation search over uniformly distributed prefixes, about 2-3 probes [K].
- FP tables always store full digests.
- No `HASH_FILTER[t]` binary fuse filter: E1 measured 223 ns warm hits and 196 ns warm misses on the real tables, and a filter would only trade one evicted page for another [M] ([E1](experiments/E1-hash-index.md)).

**`SIGMETA`** tokenises signature names into 8-byte records:
- Fields: `{family u24, source u4, pua u1, shape u2, number u24, revision u8}`, then a table of family offsets into `NAME_POOL`.
- E0: every current name is `Family-N` (79%) or `Family-N-R` (21%) with canonical decimals, numbers below 2^24 [M]. 3.64 million names share 308,730 families: SIGMETA is 30 MB and NAME_POOL 5.8 MB (version 1: 58 MB and 65 MB).
- A name is rebuilt only when a result is reported. Names that don't tokenise, or whose number does not fit, are stored verbatim.

### 3.4 Pattern sections

**Partitions:** one per ClamAV target type (PE, OLE2, normalised HTML, mail, graphics, ELF, normalised ASCII, Mach-O, PDF, flash, Java). Each partition k ≥ 1 is built over its own atoms *plus* the type-0 atoms, so every stream is scanned exactly once. All partitions share one `PREFILTER` section (a directory, then each partition's region) so a database stays well inside the section table (src/match/prefilter.zig).

**`PREFILTER[p]`:**
- A 64-byte header: partition, filter count, the one hash seed every filter shares (one hash per position serves them all), the list of programs with no atom, the gate.
- Up to seven zig-regex split-block Bloom filters (32-byte blocks of 8 x u32 words, 16 bits per gram): sampled filters over 4-byte grams at stride 8, 4, 3 or 2, and stride 1 over 4-, 3- and 2-byte grams (4- and 5-byte runs, tier D). The compiler emits one sampled stride, 3 (section 4.2). Small filters get at least 2 KiB.
- The stride-one gate: 64 KiB, one byte per possible first two bytes, naming the stride-one filters that hold a gram starting with them [M: passes 0.94% of the positions of B1's PE files, 0.15% of B1].

**`ATOM_TABLE`:** one table shared by every partition, linear probing, at most 50% full. Slots are `{key u32, first u32}`; entries are `{prog u32, ext u32, back u32, ext_len u8, stride u8, q u8, flags u8}` with the program's target in the top nibble of `flags`, so a partition keeps only its own and type 0's entries and type 0's atoms are not copied per partition. `ext` holds up to 4 bytes after the key, or the index of a masked 8-byte check of the anchor part for atoms whose own bytes say little (zero padding beside a short opcode). Main + daily + bytecode: 524,288 slots (37.2% used), 394,953 entries, 198,715 checks, 15.3 MB; the whole PREFILTER section is 19.1 MB [M] (32 MB with strides 8 and 4, where an atom's 11-byte window put 8 grams in the filter and keyed the table on more distinct grams).

**`SUBSIG_PROG`:** one program per subsignature.
- Header: ldb, index, target, modifiers (nocase, wide, ascii, fullword), offset kind and values, anchor location, min and max length.
- Headers are packed (24 bytes, plus 12 for the offset fields only when the program has an offset): of the 1.63 million programs compiled from main and daily, 85% are one literal and 3.6% have an offset, so a fixed 40-byte header was the largest part of the section [M].
- Ops: `LIT`, `MASKED`, `ALT`, `NALT`, `GAPF n`, `PART_END min max`, `BOUND`.

**`ANCHORED_INDEX[p]`:** signatures with a non-"any" offset kind, grouped by (offset kind, offset value). Each group is a small hash table keyed by the 4 bytes at that offset.

**`LDB_TABLE`:**
- Per signature: subsignature count, an RPN expression and a predicate list (FileSize, EntryPoint, NumberOfSections, Container, Intermediates, Engine).
- Predicate lists (target descriptions) are stored once each and referenced by index: 322,204 logical signatures share 460 distinct ones [M].
- RPN ops: `HIT i`, `COUNT i`, `CMP{EQ,GT,LT} k`, `AND`, `OR`, `DISTINCT_GE k`, `OFFSETS i`.

## 4. Compiler pipeline

1. **Read the CVD.** It is a 512-byte header followed by tar.gz [K]; a CLD may be plain tar, detected by magic. Verify the MD5, the legacy digital signature and, when the mirror publishes one, the detached `.sign` PKCS#7 signature chained to Cisco's pinned root.
2. **Stream members into records.** `.ign2` lists are read from every container first. Each line of a hash, `.ndb` or `.ldb` member is parsed, filtered (ignore lists, functionality level) and turned straight into its database record: a fixed-size hash record, verify programs, an LDB_TABLE record, a SIGMETA entry. No source text and no per-signature IR is kept, and every dropped signature is recorded with its reason.
3. **Build hash tables** with an external merge sort: bounded sort buffers, runs spilled to a temporary directory next to the output, merged straight into the hot and cold sections.
4. **Select atoms** (4.2).
5. **Build the filters.** Partition, and size them for about 16 bits per key (roughly 0.1-0.3% false positives).
6. **Lay out sections.** Order signatures by benign-corpus hit frequency, hot ones first.
7. **Finish.** Write the BLAKE3 root and signature, then write to a temp file, fsync and rename. Optionally emit a delta blob.

Large sections (programs, cold rows, sort runs) live in spill files and are mapped read-only for the final write, so they are clean, reclaimable pages rather than heap. Measured on main 63 + daily 28187 + bytecode 339 on an Apple M3 Pro [M]: 5.8 s, 393 MB peak memory footprint, 600 MB maximum RSS (the first, all-in-memory compiler: 7.7-9.0 s, 4.38 GB footprint, 2.8-3.5 GB RSS). Always out of process, at low priority.

### 4.1 Hex-signature IR

- Hex bytes become `LIT`; nibble wildcards become `MASKED`; `{n}` becomes `GAPF`.
- `{n-m}`, `{-n}`, `{n-}`, `*` and `[n-m]` become part breaks.
- `(a|b)` becomes `ALT`, expanded into literals when small; `!(..)` becomes `NALT`.
- Modifiers `::i ::w ::a ::f`:
  - wide is expanded at compile time
  - nocase is expanded into variants when there are 16 or fewer, otherwise it goes into a folded partition

### 4.2 Atom selection and tiers

For each searched program (src/compile/atoms.zig), enumerate every window inside a literal at a fixed distance from its part's start, of `stride + 3` bytes for the sampled stride and for stride 1, then 3- and 2-byte windows. A window costs its grams' summed benign probability times a probe (20 ns), its key gram's probability times a verify (200 ns), a small bias for the filter its stride needs, and for stride-one windows the benign rate of their first two bytes times a gate pass (30 ns, see `Costs.gate_ns`); the cheapest wins. Probabilities come from a 4-gram model of the benign corpus B1 (src/compile/gram_model.zig: bigram costs plus the 32,768 most frequent 4-grams, 230 KB, deterministic). A run of zeros beside a rare 3-byte opcode therefore gets the 3-byte atom.

**One sampled stride.** A sampled filter costs one block test per `stride` bytes whatever it holds, and filters of several strides add up: strides 8 and 4 (the first design's tiers A and B) cost 6 tests per 16 bytes, and once 6-byte literals needed stride 2 that became 14. Every window long enough for the smallest stride present could share its filter at no extra test, with fewer grams per atom. So the compiler uses one sampled stride, 3 (5.3 tests per 16 bytes, windows of 6 bytes or more); E2 compared 2, 3 and 4 and the old tiers on B1's PE files, B1 and B2.

The windows chosen:
- **Sampled: stride 3**, the 3 4-grams of a 6-byte window in the filter.
- **C: stride 1**, 4- and 5-byte runs, behind the stride-one gate.
- **D: a 3-byte or 2-byte atom**, stride 1, behind the gate; no atom at all only for programs without a 2-byte literal (none in main + daily).

**Crowded keys.** Atom selection weighs expected cost, but a key many programs share is a worst case wherever it occurs: every occurrence walks the whole chain. Once a key holds 32 programs, later programs take their next cheapest window whose key is not crowded if it costs at most 0.002 ns per byte more (`VB5!` held 108,490 logical subsigs; longest chain now 40). Deferred programs are spread the same way over their anchor literals' prefixes.

**Deferral by covers** (P4.10, Hyperscan's Rose idea applied to ClamAV expressions): a cover of a logical expression is a set of subsigs one of which must match whenever it holds (`0&1`: either; `0|1`: both; `(0|1)>2`: both; byte compares by their trigger, PCRE by its trigger expression, pinned subsigs free). Only the cheapest cover is searched; every other subsig, of any tier, is deferred to a second pass over files whose signature was touched, all pending atoms in one batched pass: a bitmap of the keys' first two bytes at every position, a whole-key bit per key length at the positions it passes, then the table and the anchor literal's next four bytes before the verifier. A deferred program's anchor is the literal whose prefix is rarest (that prefix is its key), not the one holding its rarest window. On B1's PE files this pass was half of the whole scan; it is now one pass per file (2,048 keys) and 6% of the probes. Expressions without a cover defer nothing, so detections are those of searching everything (planted differential on the full database: no mismatch).

Main + daily [M, E3]: 1,570,219 searched programs, 1,178,274 deferred; searched A 299,544, B 81,108, C 9,158, D 2,335. Against ClamAV's depth-3 prefixes this gives 200x fewer candidates on B1 and 45x on B2; deferral alone divides candidates by 7 to 12 and verifies by about 90. Tier D: 60% deferred or anchored (pass line 90%: missed); the rest are `.ndb` signatures with no partner, held to 165 candidates per MB on B1 by 3- and 2-byte atoms (follow-up: bounded expansions and sparse grams, #107).

### 4.3 PCRE, YARA, Guardian rules, container signatures

- **PCRE subsignatures** run only when their trigger expression is true, over their offset window, with a step budget.
- **YARA subset:**
  - Strings: text (`nocase`, `wide`, `ascii`, `fullword`, small `xor` ranges), hex, and regex (atoms come from required literal factors).
  - Conditions: boolean logic, counts, `at` and `in` offsets, `N of`, `filesize`, `uintN(off)`, `@a[i]`.
  - No modules. Rules that use unsupported constructs are rejected and listed in the coverage report.
- **Guardian rules** are the same YARA subset plus TOML metadata.
- **Container signatures (`.cdb`)** are checked while iterating container members.

### 4.4 CVE index (`.zavcve`)

A separate blob, because it updates on its own schedule and stays off the scan path.
- **Sections:**
  - (ecosystem, name hash) pointing to version ranges
  - version tokens canonicalised per scheme (semver, dpkg, rpm, apk, PEP 440, Maven, Go)
  - a CPE index
  - CVE metadata, including a KEV bit
- **Inventory collectors:** dpkg, rpm, apk, Homebrew, pantry, lockfiles, pip, Go buildinfo, Cargo, macOS `Info.plist`.

## 5. Hot path for one file

```
open/stat -> cache probe (dev, ino, size, mtime_ns, ctime_ns, db_ver) -> hit: CLEAN
miss -> read first 4 KiB -> file-type trie
     -> need = HASH_NEED_MAP[size] | sizeless_mask
     -> format parse (entry point, sections, members) with targeted preads
     -> ANCHORED pass
     -> STREAM pass over 256 KiB blocks (64 KiB sub-blocks):
          stage 1 SBBF probes -> candidate ring
          hashers update only the algorithms in `need`
          stage 2 atom table probe -> masked anchor compare
          stage 3 verify VM -> ndb hit (early exit) or ldb touch
          normaliser taps feed the HTML/ASCII partitions
     -> children recurse through the same pipeline
     -> finalize: digests -> hash tables, section and import hashes,
        deferred tier-D pass, touched logical signatures, FP check
     -> cache insert (CLEAN only)
```

**Stage 1:**
- For each sampled position: load a u32, multiply-hash it, choose a block, and test 8 bits in one SIMD compare.
- Append the position to the ring without a branch.
- Positions are independent, so many misses stay in flight. An Aho-Corasick walk is a chain of dependent loads: zig-regex's sparse automaton over 400k binary literals scans at 40 MB/s, and the dense one is not built past 100k [M].
- Vectorise the hashing (overlapping loads from one vector via comptime shuffles), not the probes.
- The sampled filter hashes the lanes its stride lands on in one vector (stride 3 steps 48 bytes, three loads); each test sets a bit of a mask and the rare hits are appended afterwards, so no test waits on the ring position of the one before.
- The stride-one filters run only behind the gate, one byte load per position; passed positions are collected without a branch and tested once per batch against every gated filter, kept where the gate names it, so a pass costs block tests in L1 rather than mispredicted branches (a pass cost about 14 ns tested in place, 9 ns batched).
- Measured with the full database (E2) [M]: on B1's PE files the PE partition runs 1.1 GB/s per core in stage one and about 0.97 GB/s with stage two (before: 0.50 and 0.39-0.43); B1 as typed 1.29 and 1.19 GB/s; B2 1.16 and 0.88 GB/s (Apple M3 Pro, shared machine).

**Verify VM:**
- Starts at the anchor part and searches the other parts within their gap bounds, using SIMD memchr and masked compares.
- Has a per-subsignature step budget, a per-file step budget, and a per-file verify-count budget proportional to size (16,384 calls plus 64 per KiB; benign files make under 23 per KiB). When a budget runs out it is recorded as a limit event, never a silent pass. The count is what bounds crafted candidate density: verifies that fail at once cost almost no steps (E4: worst inputs 6 to 24 ms/MB).
- ClamAV semantics (wildcards, gap ranges, maxshift, `::f` boundaries, count and offset ordering) are checked differentially against libclamav.

**Logical state:** an 8192-slot open-addressing table per worker, reset through a touched list. Target predicates are checked on first touch. Overflow spills to an arena.

**Hashing:**
- Expected single-core speeds: MD5 about 700 MB/s, SHA-1 about 1 GB/s in software, SHA-256 1.5-2.5 GB/s with hardware [K/E].
- Size gating skips 91.6% of MD5 bytes on a 27 GB benign filesystem and 99.7% on its files of 4 MiB or more, and SHA-1 entirely [M] (E1). The 13 size-less signatures (E0) still make MD5 and SHA-256 run on every file, which caps hashing at MD5's 730 MB/s per core; E1 lists the options.
- For unknown-size streams, a hasher runs only while the byte count stays at or below the largest size in its table.

## 6. Containers and normalisers

**`Source`** is one of: a file-descriptor range, a memory slice, a decompressor over a parent `Source`, or a spill file.
- A child streams through the pipeline unless it needs random access.
- Random-access children of 8 MiB or less go to an arena slab; larger ones spill to `O_TMPFILE` (or an unlinked temp file on macOS).

**Limits:**
- clamd-equivalent defaults (recursion 17, file count, scan size, file size, embedded PE, normalisation caps).
- A per-member ratio guard.
- A per-scan output budget.
- Zip overlap detection, with a central-directory and local-header consistency check.

**Decoder windows:**
- flate needs 108 KiB (32 KiB history, 64 KiB output room, decode tables); bzip2 needs 4 bytes per
  block byte (3.6 MB at level 9).
- zstd and xz/LZMA are capped at 8 MiB by default.
- Any window over 1 MiB takes a token from a global 64 MiB big-window budget.

**Normalisers** (measured against libclamav 1.5.4 with `tools/diff/norm.py`, throughput from
`zig build bench`, arm64 macOS):
- HTML (target 3): nocomment.html and notags.html byte-identical on 702 of 702 local HTML files
  and 1,800 generated stress documents; 156 MB/s producing both from 1 MiB of markup [M]. The
  JavaScript form follows the JS normaliser (P5.13).
- Text (target 7): byte-identical including libclamav's buffer seams; 1,569 MB/s [M].
- File typing: 11,999 of 11,999 local system files and the realdb job's 10,000 Linux files get
  the root type `clamscan --gen-json --debug` reports (`tools/diff/ftm_check.py`) [M].

**Order of formats:**
1. gzip, zip, tar, bzip2, xz, zstd, OOXML, MIME, PE, ELF, Mach-O, HTML and ASCII normalisers.
2. OLE2/VBA, PDF, JS, RTF, CPIO, 7z.
3. CAB, CHM, NSIS, ISO9660, DMG, unpackers. RAR waits on a licence review.

## 7. Runtime

**Workers:** one per physical core. Each owns a scratch reservation, a Chase-Lev deque, and padded epoch and stats slots.

`Pool` uses native core topology on Linux, macOS and Windows. The worker count
is configurable. Linux can pin workers to the process's allowed CPUs, assigning
one logical CPU per physical core before using SMT siblings. Idle workers park
on the generation futex. Closing the pool drains accepted jobs before joining.

`zig build bench -Doptimize=ReleaseFast -- zig-out/deque.json deque` measures
128 uncontended push and last-item pop pairs per sample. On Apple M3 Pro,
the mean was 693 ns per batch, or 2.7 ns per operation including benchmark
loop overhead. The [hosted x86_64 benchmark](https://github.com/zig-utils/zig-anti-virus/actions/runs/44458256485)
measured 676 ns per batch, or 2.6 ns per operation, on an AMD EPYC 7763.

`ZAV_RUNTIME_STRESS=1 zig test src/rt/pool.zig -O ReleaseSafe -fsanitize-thread -lc`
ran 10 million jobs exactly once on macOS with 11 workers and 978,439 steals,
and on an aarch64 Linux VM with six workers and 237,987 steals. The
[engine CI run](https://github.com/zig-utils/zig-anti-virus/actions/runs/44459623107)
passed the macOS and Linux test suites and the hosted Linux ThreadSanitizer
stress check. In non-sanitized Linux backpressure runs, a million full offers
left resident memory flat in the integrated test (1,841 pages before and at
peak) and within one page in the focused test (260 before and 261 at peak).

**Injector and backpressure:**
- A bounded MPMC injector holds 4N jobs. A full result tells the producer to yield or pause its source.
- Directory walkers split subdirectories when their local deque has 64 or fewer jobs. They visit additional directories inline.

**Directory walking:**
- Linux: `getdents64` for directory entries and batched `statx` for file metadata. Volume identity carries the mount ID and, when the kernel supplies it, the subvolume ID.
- macOS: `getattrlistbulk` returns names, kinds, inode numbers and file lengths in batches.
- Entries are sorted by inode. Walkers reuse reserved directory scratch during traversal.

**I/O:**
- The positional walker reads files up to 1 MiB into reused scan scratch. Format detection and parsing share that copy.
- Larger root files are read in 256 KiB blocks, with sequential advice on Linux. The matcher still receives 64 KiB chunks for consistent limit accounting.
- Large random access uses the positional source. Use mmap only when a parser requires a contiguous view beyond the in-memory cap.
- Optional page-cache hygiene for bulk scans.
- On Linux with io_uring support, batches of up to 64 entries link directory-relative `statx` and direct `openat`, then fixed-file `read` and `close`. `statx` takes the directory descriptor and name. The open completion supplies the allocated slot for the second batch. If setup fails, the worker uses pread and logs the fallback once per process.

**Small-file verification:** `python3 bench/io_fixture.py ROOT 1000000` creates
the deterministic 4 KiB corpus. `zig build io-check -- MODE ROOT 1000000`
checks every path exactly once and compares all bytes against the independent
fixture pattern. Linux 6.8 (arm64) matched all 1,000,000 files and 4,096,000,000
bytes with both io_uring and pread. The io_uring run used zero positional
retries. A process-wide `strace -f -c` counted 62,706 syscalls (0.063 per file).
A separate trace found zero `mmap` or `munmap` calls from the first directory
read through the verification result. An Ubuntu 24.04 container using Docker's
default seccomp profile rejected io_uring setup and verified the same corpus
using `fallback` mode. On macOS (arm64), both `bulk` and `pread` modes verified
the entire corpus.

**Scan cache (`scan-cache.zavc`):**
- 8-way buckets of 32-byte entries, each `{ino, meta_fp, db_ver, dev, verdict, flags, seq, crc}`.
- Seqlock writers, CRC-checked readers. Only CLEAN verdicts are cached.
- Racy-timestamp rule: a file modified within 2 s is not cached. Caching is off on filesystems with coarse timestamps.
- Dirty pages are written back periodically.
- **Delta rescan:** a file clean under database version v can only be detected under v' by signatures added since v. So a cache hit from an older version is rescanned against a small delta filter instead of the full database.

**Reload:**
1. mmap the new file and validate its header.
2. Build a new 4 KB engine struct and swap it in atomically.
3. Workers publish their epoch; the old mapping is unmapped once every busy worker has moved past it.

The private dirty delta is about 0 [E].

## 8. Memory accounting

**Metrics:**
- Linux: `Private_Dirty + Anonymous + SwapPss` from `smaps_rollup`.
- macOS: `phys_footprint`.

Database pages are clean and reclaimable, so RSS and PSS are reported but never gated on.

| Component | Steady-state private dirty |
|---|---|
| Binary | 0 (clean) |
| Database mapping | 0 (hot set resident and clean) |
| Engine and config | under 1 MB |
| Per worker (read buffer, candidate ring, verify queue, logical table, normaliser buffers) | about 1.5 MB, trimmed when idle |
| Thread stacks | 64-128 KB touched each |
| Connections | 64 KB each, with INSTREAM spilling past 256 KiB |
| Regex cache | 4 MB cap |
| Big-window budget | 0 idle, 64 MiB maximum |

**Totals [E]:**
- Idle with 16 workers: about 12-20 MB.
- Nominal mixed load: about 30-45 MB.
- The big-window budget is reported separately as peak.

**Huge pages:** the 2 MiB alignment makes file-backed huge pages possible; E12 decides whether they help. Scratch arenas never use them.

**Cache lines:** layouts are padded to 128 bytes where false sharing matters, to cover Apple's 128-byte lines.

## 9. Interfaces

### 9.1 clamd-compatible daemon

**Listeners:** a Unix socket and TCP, configured through `clamd.conf` keys.

**Commands**, with `z`, `n` and bare prefixes:
- `PING`, `VERSION`, `VERSIONCOMMANDS`, `RELOAD`, `SHUTDOWN`, `STATS`
- `SCAN`, `CONTSCAN`, `MULTISCAN`, `ALLMATCHSCAN`
- `INSTREAM` (big-endian u32 length chunks, ending with a zero-length chunk [K])
- `FILDES` (fd passing over the Unix socket)
- `IDSESSION`/`END`, with request-number prefixed replies

**Concurrency:**
- One event loop per listener group: epoll or io_uring on Linux, kqueue on macOS.
- INSTREAM is scanned incrementally as chunks arrive, so p99 after the last byte covers only finalize and container work.

### 9.2 Native protocol `zavp/1`

- **Frame header:** 16 bytes, `{magic 'ZAV1', type, flags, rsv, req_id, len}`.
- **Requests:** `SCAN_FD`, `SCAN_PATH`, `STREAM_BEGIN/DATA/END`, `CANCEL`, `STATS`, `RELOAD`, `HELLO`.
- **Replies** come out of order, matched by `req_id`, with a fixed 48-byte result body followed by the name.

### 9.3 C ABI (`zav.h`)

```c
uint32_t zav_abi_version(void);
int zav_engine_open(const char *db_path, const zav_open_opts *o, zav_engine **out);
void zav_engine_retain(zav_engine*);  void zav_engine_release(zav_engine*);
int zav_engine_reload(zav_engine*, const char *db_path);
int zav_scratch_new(zav_engine*, zav_scratch **out);
void zav_scratch_free(zav_scratch*);
int zav_scan_buffer(zav_scratch*, const uint8_t *p, size_t n, uint32_t flags, zav_result *r);
int zav_scan_fd(zav_scratch*, int fd, uint32_t flags, zav_result *r);
int zav_scan_path(zav_scratch*, const char *path, uint32_t flags, zav_result *r);
int zav_stream_begin(zav_scratch*, uint32_t flags, zav_stream **out);
int zav_stream_write(zav_stream*, const uint8_t *p, size_t n);
int zav_stream_end(zav_stream*, zav_result *r);
int zav_queue_new(zav_engine*, uint32_t threads, zav_queue **out, int *notify_fd);
int zav_submit(zav_queue*, const zav_job *jobs, uint32_t n);
uint32_t zav_poll(zav_queue*, zav_completion *out, uint32_t cap);
```

- Structs begin with their size, for forward compatibility.
- Buffer scans read a TypedArray in place.
- Async work uses a completion queue plus a notify fd, so no JavaScript callback ever runs on the hot path.

### 9.4 Real-time watching

**Linux (fanotify):**
- Content-class marks on the filesystem or mount, with `FAN_OPEN_EXEC_PERM` (optionally `FAN_OPEN_PERM`) and `FAN_CLOSE_WRITE`.
- The scan reads the fd delivered in the event, so there is no reopen and no race.
- Each permission event has a deadline policy.
- A clean verdict adds an evictable ignore mark, which acts as an in-kernel clean cache. The kernel clears it when the file is modified.
- The daemon excludes itself.

**macOS:**
- FSEvents for unprivileged scanning after changes.
- Endpoint Security (`AUTH_EXEC`, `AUTH_OPEN`, `NOTIFY_CLOSE`) for blocking. It needs Apple's entitlement and a system extension, and must answer before each message's deadline. It uses the response cache and mutes itself and excluded paths.

## 10. Module map

```
src/db/        format, reader (raw mmap, validate), writer, verify (blake3, ed25519)
src/compile/   cvd, per-extension parsers, yara/, guardian/, mbazaar, ir, atoms,
               sbbf_build, hash_build (external sort), layout, delta, coverage
src/match/     hashidx, need_map, sbbf (probe kernels per arch), atom_table, verify_vm,
               anchored, logical, teddy (small partitions), regex_bridge
src/hash/      variants, kernel, sha1_hw, variant_object (one per CPU variant), dispatch,
               hasher, multihash
src/simd/      arch dispatch, byte shuffles
src/fmt/       ftm, pe, elf, macho, ole2, vba, ooxml, pdf, html_norm, text_norm, js_norm,
               mime, zip, gzip, bzip2, xz, zstd, tar
src/engine/    source, scan pipeline, limits, scratch, budget, result, cache
src/rt/        vm (file mappings and reserved regions, POSIX and Windows), deque, pool,
               epoch, ioloop, walk, io_small
src/daemon/    clamd_proto, native_proto, conn, server, clamd_conf
src/watch/     fanotify, endpoint_security, fsevents
src/host/      host checks
src/cve/       cve_build, cve_query, inventory/
src/capi/      zav.h, capi
src/cli/       scan | compile | daemon | update | audit | host | bench | coverage
bench/         corpus manifests, runner, memory sampler, clamd driver, gates
```

## 11. Targets

| Metric | Target |
|---|---|
| Startup, warm page cache | under 50 ms to accepting |
| Startup, cold page cache | under 300 ms to accepting |
| Private dirty, idle, 16 workers | 24 MB or less |
| Private dirty, nominal load | 64 MB or less |
| Reload peak delta | 2 MB or less |
| Raw scan, PE partition | at least 1 GB/s per core |
| Mixed corpus | at least 3x clamd, files/s and MB/s, same cores |
| Small files (16 KB or less) on Linux | at least 40k files/s per core |
| INSTREAM 1 MB, idle | p99 of 5 ms or less after the last byte |
| fanotify, cached clean file | 20 µs or less added |
| Parity on supported types | at least 99.5% of clamd `--bytecode=no` detections, no new false positives |
| Compile | 30 s or less, 1.5 GB peak or less, out of process |

## 12. Benchmarks and gates

**Corpora:** pinned manifests of SHA-256 values, never the samples themselves.
- **B1:** benign filesystem.
- **B2:** large benign files.
- **M1:** malware, run only in isolation.
- **A1:** adversarial (bombs, deep nesting, pathological PDF and HTML, VM worst cases).
- **S1:** mail streams.

**Baseline:** clamd on the same CVDs, with the same limits and threads, bytecode on and off.

**Metrics:**
- Throughput, and latency percentiles per INSTREAM.
- Startup time and reload peak.
- RSS, PSS, private dirty and anonymous memory at 10 Hz.
- Page faults and syscalls per file.
- Candidates and verify steps per MB, and the share of hashed bytes skipped.
- Detection diff against clamd.

**Gates:**
- Every PR: kernel benchmarks with a 10% threshold.
- Nightly macro run fails on any of:
  - a 5% throughput regression (median of 5 runs, significance tested)
  - private dirty over 24/64 MB
  - a reload delta over 2 MB
  - any new false positive
  - parity under 99.5%
  - any adversarial case over its bound

## 13. Risks

1. **Parser and normaliser parity decides the detection rate.** Formats are built in order of corpus impact and gated on parity.
2. **Signature semantics can drift from ClamAV's.** Mitigation: differential testing against libclamav.
3. **Short atoms inflate candidate counts.** Mitigation: deferral and anchoring.
4. **Size-less hash signatures** force hashing for every file. E0: 13 exist (11 MD5, 2 SHA-256), so MD5 and SHA-256 run on every file, exactly as in ClamAV.
5. **std decoder speed.** Mitigation: optimise in our code or upstream; no C fallback.
6. **zig-regex byte mode** is an upstream dependency.
7. **Zig 0.17-dev API churn.** Mitigation: thin internal wrappers.
8. **Endpoint Security needs Apple's approval.** Without it, macOS gets FSEvents only.
9. **Licensing.** Implement from format documentation and never copy GPL code. Compile signatures locally and never re-host ClamAV-derived blobs.
10. **Page-cache eviction on small hosts.** Mitigation: optional `mlock` of the hot region.
11. **DoS.** Mitigation: budgets everywhere, plus the adversarial gate.
12. **Cache staleness.** Mitigation: the racy-timestamp rule and filesystem detection.

## 14. Experiments

| # | Experiment | Pass line |
|---|---|---|
| E0 | Database census: counts by extension, target and offset kind; tier histogram; size-less hashes; size coverage; name tokenisation; PCRE count; functionality levels ([results](experiments/E0-census.md)) | produces the numbers that replace the [E] figures |
| E1 | Hash index lookup cost, warm and cold; share of hashed bytes skipped ([results](experiments/E1-hash-index.md)) | lookup ≤ 300 ns warm; ≥ 70% of MD5 bytes skipped on B1 |
| E2 | Prefilter bake-off: SBBF vs FDR shift-or vs double-array Aho-Corasick vs Teddy ([results](experiments/E2-prefilter.md)) | PE partition ≥ 1 GB/s per core including stage 2 |
| E3 | Atom selection vs prefix selection; tier-D deferral coverage ([results](experiments/E3-atoms.md)) | ≥ 10x fewer candidates; ≥ 90% of tier D deferrable or anchorable |
| E4 | Verify VM worst case on A1 ([results](experiments/E4-verify.md)) | no input over 50 ms/MB |
| E5 | Memory: idle, nominal, peak; reload under load | 24 / 64 MB; reload ≤ 2 MB |
| E6 | pread vs mmap vs io_uring; munmap shootdowns; cache hygiene | pick defaults; io_uring ≥ 2x fewer µs per small file |
| E7 | std flate, zstd, xz vs zlib-ng, libdeflate, libzstd ([results](experiments/E7-decoders.md)) | std flate ≥ 60% of zlib-ng, otherwise optimise |
| E8 | Hardware hashers, baseline vs native builds ([results](experiments/E8-hashers.md)) | SHA-256 ≥ 1.5 GB/s, SHA-1 ≥ 2 GB/s with hardware |
| E9 | Parity against clamd (bytecode on and off); false positives on B1 | ≥ 99.5% parity; 0 new false positives |
| E10 | Scan cache fault injection; warm-rescan speedup; delta rescan | 0 stale CLEAN results; ≥ 20x faster warm rescan |
| E11 | fanotify permission latency | cached ≤ 20 µs |
| E12 | Huge pages and 128-byte layouts | adopt only if ≥ 5% gain |
| E13 | zig-regex byte mode vs PCRE2 | ≥ 99% compile with identical results |
| E14 | 1000 concurrent INSTREAM connections | meets the INSTREAM targets |
