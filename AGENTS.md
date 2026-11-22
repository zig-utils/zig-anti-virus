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

## CI

GitHub Actions is disabled for this repository for now, so CI runs on [ReviewOS](https://reviewos.org),
which mirrors it as `zig-utils/zig-anti-virus` and runs `.github/workflows/ci.yml` and
`differential.yml` as they are written, on every push (a minute or so after it lands). Each
workflow's verdict comes back to the commit on GitHub as the status `ReviewOS / CI` or
`ReviewOS / Differential`, linking to the run. The Linux jobs run on a self-hosted Linux runner;
the macOS, Windows and arm64 jobs and the fedora container job are skipped there with the reason
shown on the run (no such runner), and run again on GitHub once Actions is back. A newer commit
drops runs still waiting for the runner. The nightly fuzz and the dispatch-only workflows are not
started by pushes there. The mirror's runner mapping lives in ReviewOS's `mirrors.yml`.

Reading and starting runs, with the `reviewos` CLI (built from the ReviewOS repository with
`bun run build:cli`; sign in once with `reviewos login`):

```sh
export REVIEWOS_URL=https://reviewos.org REVIEWOS_REPOSITORY=zig-utils/zig-anti-virus
reviewos runs --limit 10                # recent runs: number, state, ref, commit
reviewos runs --sha <commit>            # the runs of one commit
reviewos watch <n>                      # follow a run; exits 0 when it passes, 1 otherwise
reviewos logs <n> [--job <name>] [--all] [--tail 200]   # what the failed (or all) jobs printed
reviewos sync                           # fetch from GitHub now rather than at the next sweep
reviewos rerun <n> [--all]              # run a run's failed (or all) jobs again
reviewos run differential.yml --ref main   # start a workflow that has workflow_dispatch
```

Keep the workflows runnable on both GitHub and ReviewOS: actions pinned to full commit SHAs (the
runner refuses tags), no `gh` with `github.token` (on ReviewOS it is not a GitHub token; public
release assets come over plain `curl`), no bare `sudo` (`tools/diff/install_clamav.sh` installs
with apt where sudo exists and unpacks into `$RUNNER_TEMP` where it does not), Python tools in a
venv, and steps that work under `sh` (ReviewOS ignores `shell: bash`).

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
