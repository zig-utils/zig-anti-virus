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

## Whole databases and normalisers

- `gate.py` (P4.21 gate): samples built from the target-0 bodies of the real databases
  (`realdb.py gate`), scanned with the whole databases by clamscan and by `zav-diff scan`, which
  uses the engine's layer scan (`src/engine/layerscan.zig`): file typing with the database's type
  magics, HTML through its normalised forms only, HandlerType re-scans. Every file must agree.
- `norm.py`: zav's normalisers against the files `clamscan --leave-temps` keeps: the text form
  (target 7) and, for HTML, nocomment.html, notags.html and `javascript`. `gen_html.py` writes
  stress documents that reach every state of libclamav's HTML normaliser, chunk cuts included.

### MIME messages

The `mail.case` differential checks target-4 matching on an intact message and
whole-file hash matching on a decoded attachment. Both tools agreed on the two
case messages and all 2,752 messages in the manifest-backed S1 corpus using the
case's signatures. The named-attachment path and the zig-mime evasion fixtures
are covered in `src/fmt/mime.zig`.

### Phase-three archive members

`zav-diff members FILE...` walks positional sources through the format dispatcher
with the default limits. Each JSON line lists the objects with their paths, sizes,
and CRC32 checksums, plus any notices and the walk's stop reason. Use ClamAV 1.5.4
with `--leave-temps --bytecode=no` and a signature that does not match the files.
Compare extracted member sizes and CRC32 values with the retained temporary files.
ClamAV also retains normalization artifacts, which should be excluded from member
counts. For NSIS, compare the `nulsft-tmp.*` outputs with the immediate children of
zav's `overlay` object. The parser walk checks extraction. The scan pipeline in
[Guardian P6.03](https://github.com/zig-utils/zig-anti-virus/issues/61) covers
end-to-end matching on the extracted children.

| Input | Member comparison against ClamAV 1.5.4 |
| --- | --- |
| CAB, MSZIP and LZX fixtures | All 7 members agreed by size and CRC32. |
| ISO 9660, primary, Joliet and Rock Ridge fixtures | All 9 file members agreed. zav also emitted the Joliet fixture's El Torito boot image. |
| DMG, mixed-codec UDIF fixture | The 512-byte first partition agreed. The second was 31,744 bytes in zav and 20,480 in ClamAV. |
| CHM, generated LZX fixture | zav emitted 6 file members. ClamAV recognized the format and retained no members. |
| NSIS, generated deflate and bzip2 fixtures | All 16 immediate members agreed, including the installer headers. |
| NSIS, generated LZMA fixtures | ClamAV retained one of four members for the non-solid case and none for the solid case. |

On the [Python 3.10.11 Windows help file](https://www.python.org/downloads/release/python-31011/),
all 554 nonempty CHM members from zav matched ClamAV's saved output and 7-Zip
17.05 by size and CRC32. 7-Zip also emitted the zero-byte `#ITBITS` entry.
The CHM's SHA-256 is `e66d2ce1b8a1cd16ae31e6f0e60ad1ce5edcf7851890bdee9333bfc52eb95561`.

On the [Notepad++ 8.8.9 x64 installer](https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.8.9),
zav matched all 256 immediate NSIS outputs retained by ClamAV. The parser also
emitted an empty data block and descended into a nested ZIP. 7-Zip identifies
the installer as solid LZMA. Its SHA-256 is
`2dd5473736ef51e4340cae005e3fc8cdf0e42ec649bc6ed186484a79be409928`.
Detection parity by format still needs a corpus run.

### Inline JavaScript

The HTML `javascript` form folds ASCII case after normalization. ClamAV 1.5.4
numbers names declared with `var`, function names, and function parameters.
At the end of a function, aliases from the enclosing scope are visible again.
`let` and `const` declarations keep their names. The HTML form discards block
comments and strips `//` delimiters while tokenizing their text.

On 674 script-bearing pages derived from the B1 manifest, function scoping and
line-comment tokenization raised the count of byte-identical JavaScript outputs
from 29 to 86. Both other HTML forms agreed on all 674 pages. The remaining
examples include hexadecimal literals and quotes in line comments, so the
JavaScript comparison still fails with `--strict-js`.

### Named HTML references

`src/fmt/html_named_refs.zig` contains the 743 names recognised by the official
ClamAV 1.5.4 binary, with code points independently taken from the W3C
[ISO 8879 declarations](https://www.w3.org/2003/entities/iso8879/) and
[HTML/MathML declarations](https://www.w3.org/2003/entities/2007/htmlmathml-f.ent).
`html-entities-sources.sha256` pins the source snapshots used for the table.
The ISO names carry their original permission notice in the generated table;
the W3C set permits use and derivative works under its HTML specification license.
No ClamAV source was used.

The supported set was measured by presenting 2,259 candidate names to
`clamscan --leave-temps` and checking `nocomment.html`: 743 decoded, 1,516
remained literal. The selected code points all matched the W3C declarations.
This is a legacy set, so adding every HTML5 name would break target-3 parity:
`Abreve`, `AMP`, `NotEqualTilde` and `fjlig`, for example, remain unknown.
`apos` decodes to an apostrophe. Names are case-sensitive before normalisation;
unknown names are written back in lowercase.

`src/fmt/fixtures/html_named_refs.html` independently lists every supported name
and several unsupported controls. Its `.html.hex` and `.notags.hex` companions
are the exact output saved by official ClamAV 1.5.4 on that input, encoded as hex
to preserve non-UTF-8 bytes. Public `Normalizer` tests compare both outputs across
one-byte and larger feeds. `gen_html.py` also copies this stable fixture into its
output directory, alongside random documents that exercise ISO references in
text, attributes and malformed input. Run `norm.py` over that directory as usual
for byte comparisons with the native binary.
