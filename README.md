# zig-anti-virus

`zav` is a low-memory, high-throughput anti-malware engine and daemon written in Zig. It is the scanning engine behind [Guardian](https://github.com/stacksjs/guardian).

> Pre-alpha. The plan is tracked as issues (see the [Guardian start issue](https://github.com/stacksjs/guardian/issues)). Nothing here is a production security boundary yet.

## What it is for

clamd keeps its whole signature set in RAM as parsed data structures, and needs 1.2 to 4 GiB. zav compiles signatures offline into one signed, versioned database that is memory-mapped read-only:
- the signatures cost no private memory
- the daemon stays within a few tens of MB
- a database reload never doubles memory

## Planned features

- **Signatures:** reads ClamAV databases (hash, body, logical, container, file-type, YARA subset), Guardian rules and an optional MalwareBazaar feed. They compile into a `.zavdb` blob, built on each host from the CVDs it downloads itself.
- **Matching:** rare-atom prefilters (sampled split-block Bloom filters) instead of an in-RAM Aho-Corasick automaton. Hits go through a verify VM with budgets. Logical signatures are evaluated over sparse hit sets.
- **Hashing:** gated by file size (no hashing when no signature exists for that size), and fused into a single pass with hardware SHA where the CPU has it.
- **Containers and normalisers:** streamed with bounded memory and bomb guards.
- **Daemon:** `zavd` speaks the **clamd protocol**, so existing clamd clients work unchanged. It also has a native multiplexed protocol.
- **Embedding:** a C ABI and a TypeScript package over bun:ffi.
- **Host protection:** host checks inspired by [linux-guardian](https://github.com/brammittendorff/linux-guardian), done without shelling out.
- **CVE automation:** from CISA KEV, NVD and OSV.
- **Real-time protection:** fanotify on Linux, FSEvents and Endpoint Security on macOS.

## Targets

These are design targets, to be proven by the benchmark gates:

| Metric | Target |
|---|---|
| Private memory, idle | 24 MB or less |
| Private memory, nominal load | 64 MB or less |
| Reload memory delta | 2 MB or less |
| Startup, warm page cache | under 50 ms |
| Throughput, mixed corpus | at least 3x clamd |
| Detection parity with clamd on supported types | at least 99.5%, with no new false positives |

See [docs/DESIGN.md](docs/DESIGN.md) for the full design.

## License

MIT
