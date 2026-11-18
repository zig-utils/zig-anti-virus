# AGENTS.md

`zav` is the scan engine and daemon behind [Guardian](https://github.com/stacksjs/guardian). Read
[docs/DESIGN.md](docs/DESIGN.md) before changing anything on a hot path; it is the contract for
data layouts, memory accounting and the performance targets the CI gates enforce.

## Work order

The plan is tracked as issues (labels `guardian`, `ready`, `blocked`). Take the lowest open `ready`
issue in phase order from the Guardian start issue (stacksjs/guardian#2). Its Scope is the work and
its Acceptance criteria are done. Commit with `Closes #N`, comment the decisions on the issue.

## Toolchain and commands

Zig `0.17.0-dev.1857` (pinned in build.zig.zon, deps.yaml, CI and the README; `pantry install`
provides it, and `bun scripts/check-pin.ts` checks they agree).

```sh
zig build                         # zav and zavd
zig build test                    # whole module tree, C ABI, C smoke test
zig build test -Doptimize=safe
zig build lib -Doptimize=fast     # libzav.a, shared libzav, include/zav.h
zig build fuzz -Dfuzz-iterations=100000 -Dfuzz-seed=1
zig build bench -- zig-out/bench.json
```

## Rules

- **No allocation in hot loops.** Scans use per-worker scratch arenas; allocation belongs to setup.
- **Offsets, not pointers, in anything on disk or mmapped.** On-disk records are `extern struct`s
  with comptime size and alignment asserts, little-endian, versioned.
- **The signature database is mapped read-only with `posix.mmap`, never `std.Io.File.MemoryMap`**
  (it silently falls back to heap plus read and turns the database into private memory).
- **Every input is hostile.** Bound every length, depth, ratio and step count; a budget running
  out is a reported limit event, never a silent pass. Every parser gets a fuzz target.
- **Memory and throughput claims need numbers** from the benchmark harness, against clamd.
- **Never copy GPL code.** Implement formats from their documentation. ClamAV signature databases
  are compiled on each host from the CVDs it downloads; compiled ClamAV-derived blobs are never
  redistributed.
- Small conventional commits straight to `main`; no em-dashes or en-dashes in docs or messages.
