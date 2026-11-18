# E4: verify VM worst cases with the full database

Issue: zig-utils/zig-anti-virus#35. Pass line (docs/DESIGN.md section 14): no input over 50 ms
per MB.

## Method

- Database: ClamAV main 63 and daily 28187 (1,628,243 programs), compiled with the default atom
  selection and deferral.
- Inputs: `zig build prefilter -- worst <db>` builds four 1 MiB inputs from the database itself,
  so they are regenerated rather than committed (no ClamAV-derived data in the repository):
  - **anchors**: the anchor literal of program after program (PE and type 0), each with its
    last byte changed: the densest stream of atoms that all reach the verifier and fail there.
  - **unbounded**: every part but the last of programs with an unbounded gap, back to back: each
    candidate searches to the end of the data for the missing part.
  - **subsigs**: logical subsigs, each complete but for its last byte.
  - **zeros_opcodes**: zero padding and the short opcodes of the tier-D `.ndb` family
    (`e8??000000 ... 860166 ... 8801 ... ffe9`), so the 3- and 2-byte filters fire everywhere.
  Matches the pieces happen to complete are broken (overwritten with noise) until the file
  scans clean, so the scan always runs to the end.
- Scanned as PE (target 1) with the default budgets (4,096 steps per verify, 2^24 per file),
  best of three, one thread, Apple M3 Pro shared with other agents' builds (load average 8 to
  20: times vary by up to 2.7x between runs; steps and verifies do not).

## Results

Per MB of input (times: best of three in two runs on the loaded machine, the lower first):

| Input | ms/MB | verify steps/MB | verifies/MB | candidates/MB | verdict |
|---|---:|---:|---:|---:|---|
| anchors | 89 / 240 | 375,147 | 281,335 | 44,777 | clean |
| unbounded | 20 / 35 | 18,939 | 10,174 | 2,317 | clean |
| subsigs | 192 (to the first match, 41% in) | 791,549 | 627,844 | 93,081 | infected after 2,000 broken matches |
| zeros_opcodes | 95 / 130 | 2,189,621 | 999,994 | 86,956 | clean |

No verify ran out of its own budget on any input: the cost is the number of verifies, at 0.1 to
0.3 microseconds each, not any one of them. Long unbounded parts (the case the budgets exist for)
stay cheap: 19k steps per MB.

## What changed in the VM (P4.06, perf commit e222cfd)

Before these changes the benign corpora themselves hit the verify budget: 573 files of B1 and 6
of B2 came back LIMITED, and B2 scanned at 37 MB/s. The causes and fixes:

- Each verify call copied the 800-byte VM struct (now built in place).
- A part search stepped at every occurrence of its edge literal's first byte; it now jumps
  between occurrences of the part's longest literal at a fixed distance from its edge (on a
  less common byte of it) and compares the literal before spending a step.
- The memo only recorded "part k never matches here"; it now records whole chains (no chain
  from part k starts at or after a position, none up to part k ends at or before one), which
  holds after any failed search, so unbounded searches are incremental over a file.
- A search that runs out of budget keeps the stretch it covered for the next candidate.
- Verification goes forwards from the anchor first: anchors chosen in a later part (the rarest
  window is often there) used to search back through megabytes before looking at the bytes
  next to the anchor. On a 94 MB B2 file one program went from 4,072 steps per candidate
  (budget exhausted on 143 of 144) to 1.
- The prefiltered path keeps verify memos per program across candidates (bodyscan.Scratch: a
  direct-mapped cache of 1,024 compact memos).

After them: 0 verify-budget events on B1, B2 and S1 (the remaining LIMITED files, 6 of B1 and 1
of B2, are PCRE step budgets).

## Budgets

- 4,096 steps per verify: no benign file of B1, B2 or S1 reaches it, and the worst inputs above
  stay under it per candidate.
- 2^24 steps per file: the worst input uses 2.19 million steps per MB, so the file budget ends a
  scan of such data after about 7.6 MB (reported as a limit, never as clean) and is not reached
  by any benign file. It bounds time per file, not per MB.

## Verdict

**Pass line missed** for three of the four inputs (89 to 192 ms/MB against 50), on a loaded
machine. Every one of them is candidate density, not verify depth: up to a million atoms per MB
that pass stage two and fail in the verifier. What would bound it, for the follow-up:

- A per-file verify-count budget proportional to size (for example 64 verifies per KB) that,
  once spent, ends the search with a limit event, the way the step budget does.
- Per-program throttling: a program verified thousands of times in a file without a match is
  the signature of crafted input.
- Cheaper verifies: the check stage already removes most (E3); the remaining cost is the VM's
  setup per call.

The inputs are not in CI yet: they need the ClamAV databases, which only the Differential
workflow fetches. `zig build prefilter -- worst <db>` regenerates them.
