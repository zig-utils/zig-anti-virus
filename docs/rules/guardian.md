# Guardian rules

Guardian source packs use the engine's existing YARA subset. They compile into
ordinary YARA condition/program sections, with `guardian` in SIGMETA and names
`Guardian.<family>.<rule identifier>`. Every included rule has its own coverage
line. No new matcher or runtime parser is involved.

A source tree contains `rules/<family>/*.yar` and `rules/<family>/meta.toml`.
A family and file stem contain only ASCII letters, digits, `_` and `-` (1 to
80 characters). Each family needs at least one public rule and exactly one
metadata file. Duplicate paths and duplicate fully qualified rule identifiers
are errors. A malformed or unsupported rule rejects the entire pack, rather
than distributing a partially working pack. Private rules are rejected because
they do not produce detections on their own.

Metadata has exactly these root fields, using the native zig-cli TOML parser:

```toml
category = "webshell"
severity = "high"
references = ["https://attack.mitre.org/techniques/T1505/003/"]
false_positive_notes = "Review authorized diagnostic scripts."
owner = "Guardian maintainers"
```

Categories are `webshell`, `skimmer`, `npm-install`, `miner-dropper`, and
`linux-backdoor`. Severities are `low`, `medium`, `high`, and `critical`.
Strings are nonempty and at most 2048 bytes. References are 1 to 16 HTTPS URLs.
Unknown fields, duplicate keys, wrong types, and missing fields are errors.
Metadata is reviewed source information; the scan record retains the source
and qualified name, and the signed bundle retains the complete metadata.

## Author and compile

Local authoring is an explicit trust decision:

```sh
zav compile --guardian rules --guardian-version 1 --out local.zavdb
zav coverage --allow-unsigned local.zavdb
```

The current `zav scan` CLI uses the hash stage only. Pattern and Guardian
fixture detection is verified through the public engine body scan API; the
streaming CLI pipeline is tracked separately in zig-utils/zig-anti-virus#61.
Do not use the current CLI hash result as a Guardian pattern verdict.

A local database is unsigned unless the embedding compiler caller supplies
its normal database signing options. Trust in a source bundle does not imply
trust in an unsigned compiled database.

## Sign and consume a distribution bundle

The distributor supplies a 32-byte raw Ed25519 seed file through its secret
management process. Never put private keys into this repository or a source
pack. `rule-pack` validates the metadata and YARA before signing:

```sh
zav rule-pack --source rules --version 1 --signing-key /private/seed --out guardian.zavrules
zav compile --guardian-bundle guardian.zavrules --guardian-key PUBLIC_KEY_HEX --out local.zavdb
```

`PUBLIC_KEY_HEX` is the trusted distributor's 32-byte public key encoded as 64
hex digits, obtained separately through a trusted channel. `--guardian-key` and
`--guardian-bundle` may be repeated. There is no embedded signing key, bundled
trust root, unsigned bundle mode, or trust-on-first-use. Unknown keys and
modified header, source, metadata, or signature bytes are rejected before
source parsing. The API takes the same `db.reader.TrustedKey` records and key-id
function as signed databases. Version is positive and fits `u32`, matching the
source version in the database header. The app must enforce its own persisted
minimum version to prevent replay; signature validity alone does not prevent
rollback to an older authentic pack.

The same seed file signs the distributed CVE index (`zav cve compile
--signing-key`), and hosts require it with `zav audit --cve-key PUBLIC_KEY_HEX`;
see the CVE index section of [DESIGN.md](../DESIGN.md).

## Bundle format version 1

The bounded source bundle is an in-memory view, never extracted to disk.
All integers are little endian. The exact file size must match the header.

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `ZAVRULE` followed by LF |
| 8 | 4 | format version, 1 |
| 12 | 4 | entry count |
| 16 | 8 | source pack version |
| 24 | 8 | total file size including signature |
| 32 | 8 | database-format key id of the signing public key |
| 40 | variable | file records in order |
| file size - 64 | 64 | Ed25519 signature over every preceding byte |

Each file record is a `u16` path length, zero `u16` reserved field, `u32` content length, path bytes, and
content bytes. Paths are exactly `<family>/meta.toml` or `<family>/<stem>.yar`.
Absolute paths, dot components, additional directories, backslashes, unknown
file types, duplicate paths, trailing bytes, and out-of-bounds records fail.
Limits: 16 MiB per bundle, 1024 entries, 4096 rules per pack, 256 KiB per YARA file, 16 KiB per
metadata file. Directory packaging sorts paths for deterministic output and
rejects symlinks. Parser and compiler allocations occur only during setup.

## Starter pack evidence and limits

All seven rules are original heuristics, informed by the public reports linked
in each family metadata file. The PHP/JSP/ASPX rules combine request execution
markers; JavaScript and npm rules combine collection/exfiltration or lifecycle
and credential signals. These indicate behavior requiring review, not proof of
a particular malware family. The miner rule combines the reported hidden
staging directory with download, executable-permission, and miner markers.
The Linux backdoor rule combines three XorDdos persistence paths documented by
Microsoft. Obfuscation and variations can evade these intentionally small
initial rules; public reports do not imply full family coverage.

`tests/fixtures/guardian/<family>/` has matching and near-miss benign text for
every rule. Matching fixtures are inert token collections and are never
executed. The public compile/bundle/scan test checks all seven matching
fixtures, the seven benign fixtures and the clean application lockfile against
the whole pack, plus SIGMETA provenance and every coverage name.

The pack also produced zero detections and zero limits when the body scanner
checked 11,162 files (736.8 MB) from the manifest-backed B1, B2, and S1 benign
corpora. See [the corpus manifests](../../bench/corpus/README.md) for the inputs.
