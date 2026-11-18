#!/usr/bin/env python3
"""Executable layouts: zav's PE, ELF and Mach-O parsers against `clamscan --debug`.

  formats.py [--clamscan PATH] [--certs DIR] [--zav-diff PATH] [--show N] PATH...

PATHs are files or directories (searched recursively). For every PE, ELF or Mach-O file the
entry point file offset libclamav prints (`EntryPoint offset`, `ELF: Entry point offset`,
`Entry Point file offset`) is compared with zav's (`zav-diff info`), and for PE the section raw
ranges after the loader's alignment. libclamav resolves a Mach-O entry point only from a thread
state, so an LC_MAIN binary has none on both sides. Exit 0 when every file agrees.
"""
import argparse
import os
import re
import subprocess
import sys

EP = [re.compile(r"EntryPoint offset: 0x[0-9a-f]+ \((\d+)\)"),
      re.compile(r"ELF: Entry point offset: 0x[0-9a-f]+ \((\d+)\)"),
      re.compile(r"Entry Point file offset: (\d+)")]
PE_RAW = re.compile(r"PointerToRawData: 0x([0-9a-f]+) 0x([0-9a-f]+)")
PE_SIZE = re.compile(r"SizeOfRawData: 0x([0-9a-f]+) 0x([0-9a-f]+)")
MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def files_under(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for d, _, names in os.walk(p):
            for n in sorted(names):
                f = os.path.join(d, n)
                if os.path.islink(f) or not os.path.isfile(f):
                    continue
                try:
                    with open(f, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    continue
                if head.startswith(MAGIC):
                    yield f


def clamav_layout(clamscan, base, path):
    r = subprocess.run(base + ["--debug", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, LC_ALL="C"))
    text = r.stdout.decode("utf-8", "replace")
    ep = None
    for rx in EP:
        m = rx.search(text)
        if m:
            ep = int(m.group(1))
            break
    sections = None
    if "EntryPoint offset" in text or "Section name:" in text:
        raws = [int(m.group(2), 16) for m in PE_RAW.finditer(text)]
        sizes = [int(m.group(2), 16) for m in PE_SIZE.finditer(text)]
        if raws and len(raws) == len(sizes):
            sections = list(zip(raws, sizes))
    # libclamav stops listing at a section that starts beyond the end of the file ("Broken PE
    # file"); zav keeps it, cut to zero bytes. Matching agrees (an SL offset applies to neither),
    # so only the sections libclamav listed are compared.
    broken = "starts or exists beyond the end of file" in text
    return ep, sections, broken


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clamscan", default=os.environ.get("CLAMSCAN", "clamscan"))
    ap.add_argument("--certs", default=os.environ.get("CLAMAV_CERTS"))
    ap.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    ap.add_argument("--work", default=".zav-diff-work")
    ap.add_argument("--show", type=int, default=40)
    ap.add_argument("--limit", type=int, default=0, help="compare at most this many files")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()

    os.makedirs(args.work, exist_ok=True)
    db = os.path.join(args.work, "none.ndb")
    with open(db, "w") as f:
        f.write("Diff.Nothing:0:*:f1e2d3c4b5a69788796a5b4c3d2e1f00\n")
    base = [args.clamscan, "--no-summary", "--bytecode=no", "-d", db]
    if args.certs:
        base.append("--cvdcertsdir=" + args.certs)

    paths = list(files_under(args.paths))
    if args.limit:
        paths = paths[:args.limit]
    zav = {}
    for i in range(0, len(paths), 200):
        r = subprocess.run([args.zav_diff, "info"] + paths[i:i + 200], stdout=subprocess.PIPE)
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                zav[parts[0]] = parts[1:]

    counts = {}
    shown = 0
    failures = 0
    for path in paths:
        fmt, ep_text, secs_text = zav.get(path, ["?", "?", ""])
        if fmt not in ("pe", "elf", "macho"):
            counts.setdefault(fmt, [0, 0, 0])[0] += 1
            continue
        c = counts.setdefault(fmt, [0, 0, 0])
        c[0] += 1
        ep, sections, broken = clamav_layout(args.clamscan, base, path)
        zep = None if ep_text in ("-", "broken") else int(ep_text)
        ok = zep == ep
        if fmt == "pe" and sections is not None and ep_text != "broken":
            zsec = [tuple(int(x) for x in s.split("+")) for s in secs_text.split(",") if s]
            if broken:
                zsec = zsec[:len(sections)]
            # libclamav prints sections only for a PE it scans; compare when it did.
            if zsec != sections:
                ok = False
                if shown < args.show:
                    shown += 1
                    print("SECTIONS %s: libclamav %s, zav %s" % (path, sections, zsec))
        if ok:
            c[1] += 1
        else:
            c[2] += 1
            failures += 1
            if zep != ep and shown < args.show:
                shown += 1
                print("EP %s (%s): libclamav %s, zav %s" % (path, fmt, ep, zep))
    for fmt, (n, agree, disagree) in sorted(counts.items()):
        if fmt in ("pe", "elf", "macho"):
            print("formats.py: %s: %d files, %d agree, %d differ" % (fmt, n, agree, disagree))
        else:
            print("formats.py: %s: %d files skipped" % (fmt, n))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
