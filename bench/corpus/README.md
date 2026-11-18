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

## Fetching

```sh
bun bench/fetch.ts B1 B2 S1             # everything, into ~/.cache/zav/corpus/<name>/<sha256>
bun bench/fetch.ts all --subset ci      # the CI subset, into ~/.cache/zav/corpus/<name>-ci/
bun bench/fetch.ts B1 --out /some/dir   # elsewhere
```

Each source archive is downloaded once into `<out>/dl`, extracted into `<out>/x`, and every
listed member is copied to `<out>/<name>/<sha256>` after its SHA-256 is checked; a mismatch
fails the run. Files are named by hash, so a directory holds each distinct file once and every
tool reads them in the same (name) order. A clean fetch of the CI subset of all three corpora
takes under three minutes (about 500 MB of downloads; 2 min 45 s measured on a residential
link).

## Sampling and the CI subset

`bun bench/fetch.ts --generate` rebuilds the manifests from `sources.json`: it downloads every
source, keeps members within the corpus size limits (and a source's `include` prefixes),
drops duplicates by hash, and samples each source down to its `max_bytes` by keeping members
in SHA-256 order. The same sources give the same manifests.

Manifests list files in SHA-256 order. The CI subset is every file whose hash starts with `0`:
one sixteenth of each corpus, a prefix of the sorted list, and stable as files are added (a new
file joins the subset only if its own hash starts with `0`).

## Sources and licences

| Source | Corpus | Licence |
|---|---|---|
| [Go 1.22.5](https://go.dev/dl/) toolchains for linux/amd64, windows/amd64 and darwin/arm64, and the Windows MSI | B1, B2 | BSD-3-Clause |
| [Node.js 20.15.1](https://nodejs.org/dist/v20.15.1/) for win-x64 and darwin-arm64 | B1, B2 | MIT, with the bundled licences listed in the archive's LICENSE |
| [CPython 3.12.4](https://www.python.org/downloads/release/python-3124/) embeddable package and installer (amd64) | B1, B2 | PSF-2.0 |
| [Apache POI 5.2.5](https://github.com/apache/poi/tree/REL_5_2_5/test-data) test documents (OLE2, OOXML, PDF, images and more) | B1 | Apache-2.0 |
| [BusyBox 1.35.0](https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/) static x86_64 binary | B1 | GPL-2.0-only |
| [PuTTY 0.81](https://www.chiark.greenend.org.uk/~sgtatham/putty/) for w64 | B1 | MIT |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) easy_ham and hard_ham (2003-02-28) | S1 | Published by the SpamAssassin project for testing mail filters; copyright in each message stays with its sender (see the corpus readme). Fetched from the project, never redistributed here, and never sent into a live mail system. Only the ham (non-spam) sets are used |

GitHub tag archives are generated on demand and their bytes have changed in the past, so the
POI archive's hash is recorded but not enforced (`archive_hash_unstable`); every member it
yields is still checked against the manifest. Every other archive's hash is enforced.

## Who reads the manifests

- `zig build gram-model -- src/compile/gram_model.bin ~/.cache/zav/corpus/B1` builds the 4-gram
  frequency model from B1.
- `zig build prefilter -- scan|stages|top|prefix <db> ~/.cache/zav/corpus/B1 ...` measures the
  byte-pattern prefilter on B1, B2 and S1 (docs/experiments/E2-prefilter.md, E3-atoms.md).
- The P6.15 harness reads the same manifests and the same fetched directories.
