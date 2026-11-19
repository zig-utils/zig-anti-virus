# P4 open-ticket qualification

Audit date: 2026-11-19 UTC. This records evidence against the issue text; it does not change
the issues' acceptance criteria. Historical benchmark observations are not new measurements.

| Issue | Proven | Remaining before closure |
|---|---|---|
| [#24, anchored index](https://github.com/zig-utils/zig-anti-virus/issues/24) | The compiler proves every anchored program reachable. PE and ELF offset verdict cases pass the grammar differential. The ARM benchmark now averages 1.67 microseconds per file. | Verify the updated build on the hosted x86_64 benchmark. |
| [#27, tier-D deferral](https://github.com/zig-utils/zig-anti-virus/issues/27) | Required-cover analysis, deferred second pass, fallback filters and coverage counts exist. E3 measures fewer candidates on B1, B2 and S1. | E3 explicitly substitutes planted samples for the requested malware corpus. That corpus differential remains unproven. |
| [#32, Guardian rules](https://github.com/zig-utils/zig-anti-virus/issues/32) | The [signed starter pack](../rules/guardian.md) passed CLI coverage, fixture detection, benign corpus, and tamper checks. | Complete. |
| [#35, E4](https://github.com/zig-utils/zig-anti-virus/issues/35) | E4's follow-up justifies the budgets; all four generated worst cases passed the 50 ms/MB threshold in the successful ab208d5 real-database CI job. | Qualified for the current generated A1 cases. Full-pipeline performance remains a later gate. |
| [#109, CPU variants](https://github.com/zig-utils/zig-anti-virus/issues/109) | E2 records x86_64 v2/v3 and ARM numbers; scalar-reference tests run every supported variant in CI. Both explicit acceptance criteria have evidence. | The scope's separate gate-versus-first-byte-shuffle timing comparison is not recorded. `stages` counts possible first-byte passes but does not time an alternate shuffle gate. |

## Anchored index (#24)

- `src/compile/anchored_build.zig:build` validates the emitted section through the runtime
  reader and calls `Index.reaches` for every anchored program. `src/compile/compiler.zig`
  invokes it for every target partition. `src/compile/prefilter_build.zig:searched` excludes
  anchored programs from stream filtering.
- `tests/differential/cases/ldb.case`, cases `ldb-subsig-offsets` and `offsets-elf`, test
  actual PE/ELF headers with EP, section, section-window and last-section signatures,
  including displaced negative samples. The [f1dcb45 grammar job](https://github.com/zig-utils/zig-anti-virus/actions/runs/44440951785/job/135281361539)
  passed. This is a verdict differential, distinct from the parser-layout comparison in
  `tools/diff/formats.py`.
- A fresh isolated ReleaseSafe test executable importing `compile/anchored_build.zig`
  passed all 30 discovered tests with Zig `0.17.0-dev.1857+3c46da14d`. These cover reachability,
  index corruption, shifted windows, synthetic EP/sections, VM offsets and budget exhaustion.
- `bench/main.zig` measures one 4 KiB random file against 20,000 keyed signatures in six
  offset groups plus 64 shifted-window signatures. The [cb8f848 benchmark job](https://github.com/zig-utils/zig-anti-virus/actions/runs/44406911252/job/135164463160)
  measured mean 2.53 microseconds, minimum 2.39 and median 2.41 on AMD EPYC 9V45. This is
  above the issue's under-2-microsecond acceptance estimate. A successful CI job alone does
  not establish this performance criterion: the benchmark does not fail on that threshold.
- Fresh Apple M3 Pro measurement with the same fixture, Zig `0.17.0-dev.1857+3c46da14d`,
  ReleaseFast, 10,000 iterations: mean 2,575.40 ns, minimum 2,292 ns, median 2,417 ns,
  p99 5,334 ns. The under-2-microsecond criterion remains unmet, including at the minimum.
  Reproduce with `zig build bench -Doptimize=ReleaseFast -- zig-out/ready-qualification-bench.json`;
  the JSON file records these values in ns. This shared-machine observation is not an
  isolated latency guarantee. Anchored runtime/compiler and fixture were unchanged from
  `ab208d5`; concurrent unrelated source edits were present.

## Other source and measurement evidence

- #27: `src/compile/atoms.zig` computes logical covers and records searched/deferred/anchored
  tiers; `src/engine/bodyscan.zig` scans deferred programs only for touched logical rules.
  [E3](E3-atoms.md) records candidate reductions of 12x, 7x and 3x against no deferral. Its
  planted comparison has 1,388 detections by both paths, 14 clean in both and 586 inconclusive
  reference-state limits. These are useful fixtures, not the requested malware-corpus proof.
- #32: `src/compile/ir.zig:Source.guardian` and `src/db/format.zig` reserve provenance fields;
  `src/compile/compiler.zig:addStream` accepts individual YARA files and tags their compiled
  logical records `.yara`. A reserved field is not pack support.
- #35: [E4](E4-verify.md), section "Bounding candidate density", records 24.4, 10.5, 18.0 and
  6.3 ms/MB and explicit limit verdicts. `.github/workflows/differential.yml` runs
  `prefilter worst <db> --max-ms 50` using freshly compiled main and daily databases.
  Both [f1dcb45](https://github.com/zig-utils/zig-anti-virus/actions/runs/44440951785) and
  [05f2f17](https://github.com/zig-utils/zig-anti-virus/actions/runs/44407461144) skipped it
  after earlier failures. The subsequent [ab208d5 real-database job](https://github.com/zig-utils/zig-anti-virus/actions/runs/44441441981/job/135282985567)
  passed E4: anchors 32.88, unbounded 25.56, subsigs 26.89 and zeros/opcodes 8.22 ms/MB.
  Historical "pass line missed" text in E4 precedes the measured follow-up.
- #109: `build.zig:addHashVariants` links stage-one objects from
  `src/match/stage1_variant.zig`; `src/match/prefilter.zig` dispatches and compares every
  runnable kernel with `stage1Reference`. The tests exercise all sampled strides, gated
  filters, odd slices and tails. [cb8f848 CI](https://github.com/zig-utils/zig-anti-virus/actions/runs/44406911252)
  passed all five CPU jobs and its benchmark job. [E2](E2-prefilter.md), section
  "Runtime-variant follow-up", records the actual per-variant numbers and their limits.

## Anchored group-window experiment (#24)

The validator requires identical offset kind, value and section within each group. Reusing
the group's resolved window for keyed members and deriving listed members' `hi` from their
individual shift is therefore semantically valid. `section_entire` keeps the section window
and ignores shift; other kinds use `min(file size, lo +| shift)`.

An independent VM Scanner comparison now checks every ordered `(program, start, end)` hit
for 180 keyed/listed programs across all anchored offset kinds, four shifts (including
maximum u32), EOF bounds, absent entry points and sections, empty/out-of-file sections and
saturating section lengths. The original scanner passed. An intentionally incorrect change
that reused the zero-shift group window without restoring each listed member's shift failed
with 104 hits instead of 191 in the first case; the correct derivation passed all 31 focused
ReleaseSafe tests.

The fresh ReleaseFast benchmark on the same Apple M3 Pro and pinned Zig, with the existing
fixture unchanged, measured mean 2,613.62 ns, minimum 2,291 ns, median 2,417 ns and p99
5,667 ns over 10,000 iterations (`zig-out/anchored-reused-window-bench.json`). Compared with
the preceding mean 2,575.40 ns, minimum 2,292 ns and median 2,417 ns, this establishes no
improvement. Both observations were on a shared machine. The runtime change was discarded,
and the complete-hit regression remains.

## Anchored verification setup (#24)

Single-part programs have no neighboring parts to search. They now skip
clearing the search memo and building the table of fixed-length parts. The
anchored search uses the single-byte search directly for one-byte literals.
The index layout, scan order, and verify budgets remain the same.

Using the original 20,000-signature fixture and 10,000 iterations on the Apple
M3 Pro, the ReleaseFast mean fell from 2,638 ns to 1,667 ns per file. The
median fell from 2,375 ns to 1,666 ns, and p99 from 5,334 ns to 1,750 ns.
Both measurements used Zig `0.17.0-dev.1857+3c46da14d`.
