# P3 hash-scanning gate

Measured on Apple M3 Pro, macOS, with Zig `0.17.0-dev.1857+3c46da14d` and the
locally downloaded ClamAV main 63, daily 28187 and bytecode 339 databases.
ClamAV-derived databases and corpus files remain local.

## Compilation and coverage

`zav compile` verifies the CVD inputs and compiles them together, including the
built-in EICAR hash rules. The complete database contains 3,641,172 signatures,
3,212,894 hash rules and 998 allowlist entries; 1,529 duplicate records are
removed. These are compiler summary counts, distinct from the input-line census.

`zig build e1 -Doptimize=fast -- DB CVD_DIR --check-only` checks every main and
daily hash line through the mapped index, including the size-need map. It
preloads the same ignore lists as compilation and applies functionality-level
filtering. Any unexplained missing rule fails the command.

| Result | Hash lines |
|---|---:|
| Found under their own name | 3,211,373 |
| Found under the name of an identical digest/size/scope rule | 1,518 |
| Explicitly ignored | 7 |
| Unexpectedly missing | 0 |
| Total | 3,212,898 |

The coverage report accounts for those seven exclusions: one `.hsb` and six
`.mdb` entries are ignored. No hash rule is outside functionality level 220.
As a negative check, running the same gate against a built-in-only database
fails with `HashGateFailed`, rather than treating missing tables as expected.

## Raw-file scans and memory

The shared B1 and B2 manifests identify 8,410 files (8,398 and 12). After the
fetcher verifies their hashes and lengths, `zav scan --json --allow-unsigned
--db DB FILE...` scans batches of 128 manifest entries. All 8,410 return `OK`,
with exit code zero and one result per input.

The known-hash test is the standard 68-byte EICAR file, isolated from the benign
corpus. Its MD5 is `44d88612fea8a8f36de82e1278abb02f`, SHA-1 is
`3395856ce81f2b7382dee72602f798b642f14140` and SHA-256 is
`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`.
The compiled database contains the three built-in rules, and the scan returns
`FOUND`, `Eicar-Test-Signature`, exit code one. No live malware was downloaded
for this gate.

Each benign batch is measured with macOS `/usr/bin/time -l`. The highest
reported **peak memory footprint is 1,769,976 bytes**, below the 24 MB hash-gate
budget. This is the macOS footprint metric specified by the design, not RSS or
Linux `Private_Dirty`. The complete database is mapped read-only; the raw hash
scan does not load pattern-matching working state. This result establishes
the P3 hash-only envelope, not the later full-pipeline memory or throughput
targets.

## Related measurements

- [E0 census](E0-census.md): source counts, name tokenisation and signature coverage.
- [E1 hash index](E1-hash-index.md): lookup cost and size-based hashing decisions.
- [E8 hardware hashers](E8-hashers.md): baseline/native algorithms and CPU dispatch.

The hash gate retains parity for size-less signatures. Their hashing cost and
the missed MD5 skip target remain documented in E1; this gate does not waive
the later performance qualification.
