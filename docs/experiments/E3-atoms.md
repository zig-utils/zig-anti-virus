# E3: atom selection against prefix selection, and tier-D deferral coverage

Issue: zig-utils/zig-anti-virus#34. Pass line (docs/DESIGN.md section 14): at least 10x fewer
candidates than prefix selection, and at least 90% of tier-D subsigs deferrable or anchorable.

## Method

- Databases: ClamAV main 63 and daily 28187, compiled three ways with
  `zig build prefilter -- compile <out> main.cvd daily.cvd [--prefix | --no-defer]`
  (1,628,243 verify programs each; 1,570,219 of them searched, the rest pinned to an offset):
  - **atoms**: the default. Every searched program gets its rarest window under the benign
    4-gram model (src/compile/gram_model.zig, built from B1), and logical subsigs outside
    their expression's cheapest cover are deferred (src/compile/atoms.zig).
  - **no-defer**: the same atoms, nothing deferred.
  - **prefix-4**: the first 4 bytes of each program's first literal, stride 1, nothing
    deferred, through the same filters and verifier.
  - **prefix-3**: what ClamAV's depth-3 Aho-Corasick trie keys on: every position whose 3 bytes
    are the first 3 bytes of some searched program's first literal
    (`zig build prefilter -- prefix`). Counted, not scanned.
- Corpora: B1, B2 and S1 (bench/corpus), the full sets.
- Counters (deterministic, unlike times): stage-one **candidates** (positions where a filter
  fired), atom-table **probes**, **verifies** (entries whose extension or check matched, handed
  to the verify VM), and deferred programs searched in the second pass, all per MB.

## Results

Candidates and verifies per MB:

| Corpus | prefix-3 candidates | prefix-4 candidates | prefix-4 verifies | no-defer candidates | no-defer verifies | atoms candidates | atoms verifies |
|---|---:|---:|---:|---:|---:|---:|---:|
| B1 (356 MB) | 405,240 | 133,842 | 1,970,191 | 24,180 | 19,818 | **2,021** | **224** |
| B2 (366 MB) | 292,016 | 55,344 | 283,683 | 47,230 | 27,473 | **6,559** | **306** |
| S1 (15 MB) | 795,452 | 168,514 | 138,555 | 40,813 | 34,636 | **13,272** | **121** |

- Against ClamAV's prefix depth (prefix-3), atom selection with deferral produces **200x fewer
  candidates on B1, 45x on B2 and 60x on S1**, and 1,800x, 950x and 6,600x fewer positions
  that reach a verifier. Against 4-byte prefixes through the same machinery it is 66x, 8x and
  13x fewer candidates. **Pass line met.**
- Deferral alone (no-defer against atoms) divides candidates by 12, 7 and 3 and verifies by
  88, 90 and 290, and shrinks the shared atom table from 92 MB to 23 MB. The second pass
  searched 339 deferred programs per MB on B1 (21 on B2, 0.14 on S1), all batched into one
  pass per file.
- Time per core moves with the counters (measured on a shared machine, so noisy): prefix-4
  3.4 MB/s on B1 and 10 MB/s on B2, no-defer 130 and 87 MB/s, atoms 260 to 325 and 150 to
  165 MB/s.
- Limits: verify-budget events on B1 fall from 57 files (prefix-4) and 43 (no-defer) to 0; the
  6 left are PCRE step budgets.

By filter, atoms on B1 (per MB): stride 8, 887 candidates and 83 verifies; stride 4, 839 and 36;
stride 1, 130 and 6; 3-gram, 111 and 64; 2-gram, 54 and 35. On S1 the sampled filters carry
almost everything (7,875 and 5,162 candidates): English and mail words (`http`, `.com`, `mail`,
`list`) are grams of type-0 text signatures, which the B1 model rates rarer than mail shows.
Follow-up: zig-utils/zig-anti-virus#108.

## Deferral changes no detection

`zig build prefilter -- planted <db> --limit 2000` takes every 160th logical signature without a
pinned subsig (1,988 of them, 1,965 with deferred subsigs), synthesises each hex subsig's first
variant (shortest gaps, first alternatives) into one file per signature, and scans it with the
prefiltered path (deferral on) and the reference path (every program searched): 1,388 detected
by both (one of them reporting another signature of the same family first), 14 clean in both
(their PCRE or byte-compare subsigs are not synthesised), 586 where the reference path ran out
of logical state (it touches every short subsig the file contains) while the prefiltered path
detected the planted signature, and no file where the two disagree. There is no malware corpus
yet (M1, P5.17); this stands in for the differential on it.

### Compare production prefilters with deferral on and off

`deferral-diff` compares the two compiled prefilters over the same raw object
bytes. It uses the engine's native executable classification and layout for both
scans. Before scanning, it checks that the databases contain equivalent
signatures and that only the first database contains deferred programs. It
compares the first reported signature ID against the identical signature tables.
An empty corpus, a different verdict or any scan limit causes a nonzero exit.
This check covers body signatures. It excludes whole-file hashes, container
extraction and derived streams so those paths cannot mask a body verdict.

```sh
zig build prefilter -Doptimize=ReleaseFast -- compile defer.zavdb main.cvd daily.cvd
./zig-out/bin/prefilter compile no-defer.zavdb main.cvd daily.cvd --no-defer
./zig-out/bin/prefilter deferral-diff defer.zavdb no-defer.zavdb /path/to/corpus
```

Use the same CVD files for both builds. Use only an isolated environment for M1
and keep the corpus and per-sample output there.

With main 63 and daily 28187, the two builds had 1,628,441 equivalent verify
programs. On all 11,162 B1, B2 and S1 files, 11,101 were clean in both scans
and 61 were inconclusive because a scan reported a limit. No conclusive verdicts
differed. The command exited nonzero. The M1 acceptance check is still open.

## Tier D

Programs whose longest literal at a fixed distance is shorter than 4 bytes, by what happened
to them (the coverage report's histogram):

| | searched | deferred | anchored |
|---|---:|---:|---:|
| 3-byte literal | 2,307 | 866 | 426 |
| 2-byte literal | 28 | 200 | 1,992 |
| none | 0 | 0 | 0 |

Deferred or anchored: 3,484 of 5,819, **60%. Pass line missed.** Almost every searched one is an
`.ndb` body signature (2,289 in the PE partition, one generated family of
`e8??000000{-50}86xxxx{-15}88xx{-50}ffex`), and `.ndb` signatures have no partner to defer
behind. They are not left to the reference scanner: they get 3-byte or 2-byte atoms in their own
stride-one filters, behind the 64 KiB gate (the gate passes 5.9% of B1 positions), with masked
8-byte checks, and cost 165 candidates and 99 verifies per MB on B1 together. Follow-up:
zig-utils/zig-anti-virus#107 for bounded expansions (nibble masks, short alternations)
and sparse grams across single-byte wildcards, which would give most of this family 4-byte
atoms.

## Atoms by tier, whole database

| Tier | searched | deferred | anchored |
|---|---:|---:|---:|
| A (stride 8) | 299,544 | 371,481 | 52,690 |
| B (stride 4) | 81,108 | 301,654 | 410 |
| C (stride 1) | 9,158 | 504,073 | 2,306 |
| D (3-byte) | 2,307 | 866 | 426 |
| D (2-byte) | 28 | 200 | 1,992 |

1,178,274 of 1,570,219 searched programs are deferred. The tiers come from the window each
program's cost picked, not from its longest literal: a long literal of zero padding next to a
rare 3-byte opcode gets the 3-byte atom.

## Replaced estimates

- "at least 10x fewer candidates than prefix selection" [E]: 45x to 200x (B2, B1).
- "at least 90% of tier D deferrable or anchorable" [E]: 60%; the rest costs 165 candidates per
  MB on B1 through 3- and 2-byte atoms.
- "Type-0 duplication costs a few MB" [E] (P4.04): avoided. One atom table is shared by every
  partition (entries carry their target); each partition only repeats type 0's filters, about
  0.4 MB per partition, 4.7 MB in all.

## Bounded short-window expansion follow-up (2026-11-18)

Partial implementation of zig-utils/zig-anti-virus#107: short-literal programs can select a
contiguous 2-, 3- or 4-byte window across fixed-width masks and alternatives. At most 16
distinct variants are emitted into the existing filters and atom table. Alternatives retain
the correlation between their bytes; exceeding the bound rejects the entire window, and
variable-width alternatives do not provide a fixed position for later windows. The original
verify program remains the authority. Boundary widths use whole-pattern positions, including
the consumed byte at the start of a later part. Selection considers at most 512 starting
positions per part, and programs with a literal of four bytes or more keep their existing
selection path.
This adds no filter kind, disk layout change, or runtime allocation.

Recompiled main 63 and daily 28187, including built-ins, with Zig
0.17.0-dev.1857 in `fast` mode on an Apple M3 Pro with 18 GiB RAM: 1,628,441 programs.
Compared the existing local database with
the rebuilt database using `prefilter scan <db> B1 --rounds 1`, on all 8,398 B1 files
(355.9 MB):

| Counter per MB | Before | Expanded windows |
|---|---:|---:|
| All candidates | 1,460.2 | 1,450.6 |
| Sampled stride-3 candidates | 1,212.4 | 1,208.2 |
| Stride-one 4-byte candidates | 69.5 | 69.7 |
| Stride-one 3-byte candidates | 35.7 | 35.7 |
| Stride-one 2-byte candidates | 142.6 | 137.1 |
| All verifies | 212.9 | 212.6 |

Combined stride-one candidates fall from 247.8 to 242.5 per MB. Both scans report the same
11 PUA detections and seven PCRE step limits. The rebuild also includes the optional-alternative
preservation fix from #110, so the full-table differences above do not isolate expansion
alone; in particular the sampled filter also changes slightly. Single-pass times are not
evidence of a throughput improvement.

The rebuilt histogram has 5,343 tier-D programs: 2,316 (43.3%) still searched through 3- or
2-byte atoms, two through expanded 4-byte atoms, 606 deferred and 2,419 anchored. **The under-10%
acceptance criterion remains unmet.** Sparse grams across whole-byte wildcards, including the
`e8??000000` family, remain outstanding. Enumerating these as contiguous grams would require
256 variants and is explicitly refused by this bounded path.

The shared table gains 20 entries and 320 bytes; the whole PREFILTER section grows from
26,536,768 to 26,537,088 bytes. Compiler-only `AtomSpec` grows from four to eight bytes, adding
6,513,764 bytes for this program count. A direct optimized compile measured with
`/usr/bin/time -l` took 10.21 seconds, with 555,974,656 bytes maximum RSS and 412,795,792 bytes
peak memory footprint. This is one measurement of the updated compiler, not a before/after
memory comparison.

Correctness checks: all 256 values of a masked/alternative byte are planted at four offsets,
including odd alignments and the end of the buffer, then compared with the scalar VM scanner.
Both full public main/daily body patterns promoted to four-byte atoms are also planted at
40 offsets each, including the end of the buffer.
The tests also exercise later anchor parts, leading `(B)`/`(L)`/`(W)` boundaries, nonzero
atom-back offsets, the 16-variant bound, duplicate alternatives, correlated alternative bytes,
case variants and crowd tracking of every expanded key. The native kernels agree with the
scalar stage-one reference on B1,
B2 and S1 plus random buffers: 11,162 files, 1,473.7 MB, 3,021,243 candidates, both runnable
aarch64 variants.
An additional 32 real logical signatures (31 with deferred subsigs) have zero verdict
mismatches: 23 detected by both paths and nine where the reference exhausted logical state
while the filtered path detected the signature. This smaller sample supplements the exhaustive
expanded-window tests; it does not repeat the historical 1,988-rule deferral experiment above.

## Text gram model (zig-utils/zig-anti-virus#108)

The 4-gram model is built from B1 (executables, source, documents), so it rates mail and HTML
grams rarer than mail shows: on S1 the most frequent candidates were `2002`, `mail`, `=3D"`,
`src=`, `SMTP`, ` you` and `<br>`, all grams of stride-3 windows of type-0 text signatures. A
second model, `src/compile/gram_model_text.bin` (230 KB, the same format and builder), is built
from T1: SpamAssassin easy_ham_2, 1,401 messages that S1 does not contain (bench/corpus).
Programs of the text partitions (any type, HTML, mail, normalised ASCII) score every window
with the larger of the two probabilities (gram_model.zig `Model.with`), so a window must be
rare in both; other targets keep the binary model alone. `prefilter -- compile --no-text`
builds the comparison database.

Main 63 + daily 28187 + bytecode 339, `prefilter -- scan` over the full corpora (natural
typing), candidates per MB:

| Corpus | E3 baseline (strides 8 and 4) | stride 3, binary model only | stride 3, binary and text models |
|---|---:|---:|---:|
| S1 | 13,272 | 7,836 | **3,040** |
| B1 | 2,021 | 1,451 | 1,459 |
| B2 | 6,559 | 5,581 | 5,557 |

S1 falls 4.4x below the E3 baseline (2.6x below the same build without the text model), probes
from 84,969 to 8,984 per MB; B1 and B2 stay below the baseline (B1 rises by 8 candidates per MB,
0.6%, against the build without the text model; B2 falls). Verifies on S1 rise from 99 to 140
per MB (2-byte atoms of the text model's choices); stages one and two on S1 run at 1,234 MB/s
against 924 without the text model, and the whole scan 228 against 211 MB/s (M3 Pro, shared
machine). **Pass line met.**

## Sparse grams for the remaining tier D (#107, #27)

`prefilter -- tierd <db>` classifies the searched programs that still use 3- or 2-byte atoms
(PE partition and type 0, 2,622): 33 have a 4-byte window across masks or single-byte
alternations (four distinct keys; the bounded expansion above), 2,566 more only a sparse
4-gram across single-byte wildcards, 23 neither. The sparse grams fall on 79 keys, and one of
them, `e8 ?? 00 00 00` (a call with a short forward displacement), is shared by 2,278 programs:
the generated `.ndb` family `e8??000000{-50}86xxxx{-15}88xx{-50}ffex`, whose other literals
are separated by variable gaps. On B1's 43 PE files that sparse gram occurs 148 times per MB,
against 0.3 per MB for the family's current 3-byte keys (`860166`, `8a0166`, `860266`,
`880166`): a 4-byte atom 500 times more frequent than the 3-byte one it would replace, with a
chain of 2,278 programs behind it, the worst case the crowded-key limit (E4) exists to prevent.
The limit would admit 32 of them. Sparse grams would therefore move at most about 350 programs
off 3- and 2-byte atoms (tier D searched through them stays above 35%), and the ones they move
would cost more candidates, not fewer. They are not built.

Tier D by E3's definition (longest fixed literal under 4 bytes): 5,343 programs, 2,316 searched
through 3- or 2-byte atoms, 606 deferred, 2,419 anchored: 56.6% deferred or anchored. The 90%
line of #27 is out of reach for the same family: its programs are `.ndb` body signatures (no
logical expression, so no partner to defer behind) at offset `*` (nothing to anchor). Deferring
or anchoring all of tier D but this family would give 99%; with it, 56.6% is the ceiling of
deferral and anchoring, and the family is searched through 3-byte atoms behind the gate (35.7
candidates per MB on B1).
