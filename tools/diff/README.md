# Differential testing against libclamav

zav reproduces libclamav's signature semantics, and the ClamAV documentation leaves much of
them out. This suite pins them down by running the same signatures and samples through
`clamscan` and through zav.

- `tests/differential/cases/*.case`: signatures, samples and the verdicts libclamav gives.
- `tests/differential/known.txt`: the intentional differences, each with its reason. Nothing is
  excluded silently: an entry that stops occurring fails the check.
- `zav-diff` (`tools/diff/zav_diff.zig`, `zig build diff-tool`): zav's side. `zav-diff check`
  compiles each signature on its own, scans each sample and compares with the case files. It
  runs in `zig build test` (and `zig build diff`), so a change to zav's semantics fails locally
  without ClamAV.
- `clamav.py`: libclamav's side. It materialises the cases with `zav-diff materialize`, runs
  `clamscan --allmatch` once per signature and checks the recorded verdicts. `--record`
  rewrites the case files with what clamscan says, which is how expectations are written.
- `.github/workflows/differential.yml`: both sides on Linux with the official ClamAV release
  named in the workflow.

## Case files

```
case hex-nibbles                         one case: signatures plus samples
ndb Diff.Hex.High:0:*:41424344a?45464748 a signature: ndb ndu ldb ldu hdb hsb mdb msb imp cdb
yara rule R { ... }                      a one-line YARA rule (or `yara <<` ... `>>`)
ndb! Diff.Bad:0:*:4142                   a signature libclamav refuses to load
ftm 0:0:4d5a:PE:CL_TYPE_ANY:CL_TYPE_MSEXE   context (ftm fp sfp ign2) goes into every database
sample bin "ABCD\xa0EFGH" bin => Diff.Hex.High
sample pe "AB" pad(0x600) => OK
```

Sample terms: `"text"` with `\xHH \0 \n \r \t \\ \"`, `x"41 42"` hex, `N*TERM` repetition,
`bin` (8 bytes with NULs, so libclamav types the file as binary data and scans only its raw
bytes), `pad(N)` (zero bytes up to offset N) and `pe` or `pe(EP)` (a valid PE32 header with
.text at file 0x200 / RVA 0x1000 and .data at 0x400 / 0x2000; pad to 0x600). `=> OK` or
`=> NAME...` is the set of signatures that match, as `clamscan --allmatch` names them (without
`.UNOFFICIAL`; YARA rules as `YARA.<rule>`).

Each signature is compiled and scanned on its own on both sides, so one signature's semantics
never depend on another's. Write a case with `=> ?`, then:

```sh
zig build diff-tool
python3 tools/diff/clamav.py --record tests/differential/cases   # fill in libclamav's verdicts
zig build diff                                                   # see where zav differs
```

Locally, `CLAMSCAN` and `CLAMAV_CERTS` point at a ClamAV build (the official macOS .pkg
unpacks with `pkgutil --expand-full`; give its binaries an rpath to their libraries).
clamscan runs with `LC_ALL=C`, since `(W)` follows the C library's `isalnum`.

## What the cases found

Every difference was fixed in zav or listed in `known.txt`:

- `(B)`, `(L)` and `(W)` are zero-width lookarounds at the start and end of a body and consume
  one byte in the middle; `(B)` accepts different bytes before a match, after it and inside it
  (`boundary.case`).
- A gap maximum of 0 means no maximum (`{0}`, `{-0}`, `{n-0}`); `{3-1}` loads and never matches.
- Every part needs two consecutive literal bytes; plain .ndb literals under three bytes are
  refused where libclamav uses Boyer-Moore; `[x-y]` needs a single byte on one side.
- Files of five bytes or fewer are not scanned.
