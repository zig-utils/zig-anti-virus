# Benign corpora

Pinned, reproducible benign corpora shared by the atom frequency model
(`src/compile/gram_model.zig`, P4.03) and the benchmarks (`tools/prefilter.zig` today, the
end-to-end harness of P6.15 when it lands). The manifests list files, never contain them: no
sample is ever committed, and no malware is ever listed here.

| Corpus | What | Files | Bytes | CI subset |
|---|---|---|---|---|
| B1 | Benign filesystem slice: ELF, PE and Mach-O executables and libraries, scripts, source, HTML, office documents, PDFs, archives (1 KiB to 8 MiB) | 8,398 | 356 MB | 578 files, 45 MB |
| B2 | Large benign files (8 MiB and up): executables, installers, an MSI | 12 | 366 MB | 1 file, 12 MB |
| S1 | Mail: RFC 822 messages with headers, MIME parts and attachments | 2,752 | 15 MB | 161 files, 1.2 MB |
| T1 | Mail held out from S1, for the text gram model (`src/compile/gram_model_text.bin`) | 1,401 | 5.9 MB | 76 files, 0.3 MB |

## Fetching

```sh
bun bench/fetch.ts B1 B2 S1             # everything, into ~/.cache/zav/corpus/<name>/<sha256>
bun bench/fetch.ts all --subset ci      # the CI subset, into ~/.cache/zav/corpus/<name>-ci/
bun bench/fetch.ts B1 --out /some/dir   # elsewhere
```

Each source archive is downloaded once into `<out>/dl`, extracted into `<out>/x`, and every
listed member is copied to `<out>/<name>/<sha256>` after its SHA-256 and byte count are checked; a mismatch
fails the run. Existing output files are rehashed on every run, so same-size cache corruption
is repaired from verified source bytes. Corrupt downloaded archives or extracted members fail
verification rather than being accepted from the cache. Files are named by hash, so a directory holds each distinct file once and every
tool reads them in the same (name) order. A clean fetch of the CI subset of all three corpora
requires downloading whole source archives (roughly 400 MB), even though only the selected
members are materialized. Network speed and extraction time affect the five-minute CI budget.

## Sampling and the CI subset

`bun bench/fetch.ts --generate` rebuilds the manifests from `sources.json`: it downloads every
source, keeps members within the corpus size limits (and a source's `include` prefixes),
drops duplicates by hash, and samples each source down to its `max_bytes` by keeping members
in SHA-256 order. The same sources give the same manifests.

Manifests list files in SHA-256 order. The CI subset is every file whose hash starts with `0`:
one sixteenth of each corpus, a prefix of the sorted list, and stable as files are added (a new
file joins the subset only if its own hash starts with `0`).

## Sources and licences

Most software sources use permissive licences. BusyBox is GPL-2.0-only, and the public mail
corpus retains the message authors' copyrights; this is not an all-permissive dataset. Only
manifest metadata is committed. Downloaded samples stay in the local cache, and the engine
does not incorporate their implementation code.

| Source | Corpus | Licence |
|---|---|---|
| [Go 1.22.5](https://go.dev/dl/) toolchains for linux/amd64, windows/amd64 and darwin/arm64, and the Windows MSI | B1, B2 | BSD-3-Clause |
| [Node.js 20.15.1](https://nodejs.org/dist/v20.15.1/) for win-x64 and darwin-arm64 | B1, B2 | MIT, with the bundled licences listed in the archive's LICENSE |
| [CPython 3.12.4](https://www.python.org/downloads/release/python-3124/) embeddable package and installer (amd64) | B1, B2 | PSF-2.0 |
| [Apache POI 5.2.5](https://github.com/apache/poi/tree/REL_5_2_5/test-data) test documents (OLE2, OOXML, PDF, images and more) | B1 | Apache-2.0 |
| [BusyBox 1.35.0](https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/) ([licence](https://busybox.net/license.html)) static x86_64 binary | B1 | GPL-2.0-only |
| [PuTTY 0.81](https://www.chiark.greenend.org.uk/~sgtatham/putty/) for w64 | B1 | MIT |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) easy_ham and hard_ham (2003-02-28) for S1, easy_ham_2 (2003-02-28) for T1 | S1, T1 | Published by the SpamAssassin project for testing mail filters; copyright in each message stays with its sender ([corpus terms](https://spamassassin.apache.org/old/publiccorpus/readme.html)). Fetched from the project, never redistributed here, and never sent into a live mail system. Only the ham (non-spam) sets are used |

GitHub tag archives are generated on demand and their bytes have changed in the past, so the
POI archive's hash is recorded but not enforced (`archive_hash_unstable`); every member it
yields is still checked against the manifest. Every other archive's hash is enforced.

## Known detections in B1

B1 is benign, but 11 of its members are OLE2 documents (10 that file(1) calls `CDFV2 Encrypted`,
one whose short stream it cannot read) that the ClamAV main + daily
databases match with `PUA.Doc.Packed.EncryptedDoc-6563700-0`, a potentially unwanted application
signature from `daily.ldu`. ClamAV 1.5.4 with the same CVDs reports them with `--detect-pua=yes`
and as OK by default, the same 11 files and the same signature (checked 2026-11-22). zav does the
same: PUA signatures are reported only with `zav scan --detect-pua` (`prefilter -- scan
--detect-pua`, zav-diff always), so a default scan of B1 detects nothing. They are expected
detections in that mode, not false positives:

- `24d908d34dd5248de420962ff88ff46fe1f5b6800ed1e00b88b04e98b4b390a4`
- `2a86a49c40cdb0e3568fbee2554dd02a19b3901d81bd89e190584662ff135561`
- `316aafa78433238ea38ecd39be718f3b64a81f54f95fa942a1038104ead99c5e`
- `32613e96db73590cb63c9194e5b1190ba7eb4552f4638afecd584dfd5931988f`
- `39ae9e6928ad91fa82a54d1aeac665337801ff73071bdfebd0e10d533e4b3cd9`
- `3c7cc047fae52016c6b89f5461411feb371cb71614bcd6422d92bf74b8141ccd`
- `6142dd1683ae8b566f26d7cc1f1bbb3e27563bd9cd7ca569867cdf39da26a030`
- `7141fb4db3698904c17d29d2da827ca9e453ed69599721a00fd05176ae13dd07`
- `98b0b87fd7f7e73669740b8a4dfd163e7d791308f08546c1c1340506fae9c3b5`
- `9d461633ab2d4b7b6b0689f098481481f7733357e09d71b1a2b40abca837018e`
- `9efe0f5df93e6aa76a583f7c2df6fd23132110cc2eb5d411ab2f358814716dc5`

## Who reads the manifests

- `zig build gram-model -- src/compile/gram_model.bin ~/.cache/zav/corpus/B1` builds the 4-gram
  frequency model from B1, and `zig build gram-model -- src/compile/gram_model_text.bin
  ~/.cache/zav/corpus/T1` the text model from T1.
- `zig build prefilter -- scan|stages|top|prefix <db> ~/.cache/zav/corpus/B1 ...` measures the
  byte-pattern prefilter on B1, B2 and S1 (docs/experiments/E2-prefilter.md, E3-atoms.md).
- The P6.15 harness must consume these same manifests and fetched directories when it lands.

TypeScript consumers share the validated loader and selector instead of implementing their own
sampling rule. Importing `bench/fetch.ts` has no download or generation side effects:

```ts
import { fetchCorpus, loadManifest, selectFiles } from '../bench/fetch'

const manifest = loadManifest('B1')
const files = selectFiles(manifest, 'ci') // the same stable prefix used by the fetch CLI
fetchCorpus(manifest, { subset: 'ci' }) // verifies/materializes those files in the default cache
```

The JSON contract records source archive URL, licence, SHA-256 and size, and each member's
archive id, path, SHA-256 and size. Entries are unique and sorted by digest. Consumers scanning
the materialized directory use that digest order; they must not enumerate extracted source
archives or mix a full corpus with its `-ci` directory. `loadManifest` validates references,
paths, ordering and full/CI byte totals. `bun test bench/fetch.test.ts` exercises this contract
without requiring public network access.
