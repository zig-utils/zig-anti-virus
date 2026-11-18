#!/usr/bin/env python3
"""File typing: zav's (`zav-diff types`) against libclamav's (`clamscan --gen-json --debug`).

  ftm_check.py --ftm daily.ftm [--limit N] [--max-size BYTES] [--work DIR] [--known FILE] PATH...

Files under PATH (recursively, no symlinks) are copied into one flat directory under unique
names, so clamscan's JSON metadata, which names a file by its base name, is unambiguous. libclamav
types each file with the type magics in FTM (cli_determine_fmap_type, including the re-typing of
text and binary data by embedded types); its root layer's "FileType" is compared with zav's.
Mismatches are counted by (libclamav type, zav type). Pairs listed in KNOWN (`CLAM ZAV reason`
lines) are reported but do not fail. Exit 0 when every other file agrees.
"""
import argparse
import collections
import os
import re
import shutil
import subprocess
import sys

TOP_NAME = re.compile(r'^LibClamAV debug:   "FileName":"(.*)",?$')
TOP_TYPE = re.compile(r'^LibClamAV debug:   "FileType":"([A-Z0-9_]+)",?$')


def collect(paths, limit, max_size):
    seen = 0
    for p in paths:
        walker = [(os.path.dirname(p), [], [os.path.basename(p)])] if os.path.isfile(p) else os.walk(p)
        for d, dirs, names in walker:
            dirs.sort()
            for n in sorted(names):
                f = os.path.join(d, n)
                try:
                    if os.path.islink(f) or not os.path.isfile(f):
                        continue
                    size = os.path.getsize(f)
                except OSError:
                    continue
                if size < 6 or size > max_size:
                    continue
                yield f
                seen += 1
                if seen >= limit:
                    return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clamscan", default=os.environ.get("CLAMSCAN", "clamscan"))
    ap.add_argument("--certs", default=os.environ.get("CLAMAV_CERTS"))
    ap.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    ap.add_argument("--ftm", required=True)
    ap.add_argument("--work", default=".zav-diff-ftm")
    ap.add_argument("--limit", type=int, default=10000)
    ap.add_argument("--max-size", type=int, default=4 << 20)
    ap.add_argument("--known")
    ap.add_argument("--show", type=int, default=30)
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()

    shutil.rmtree(args.work, ignore_errors=True)
    corpus = os.path.join(args.work, "corpus")
    dbdir = os.path.join(args.work, "db")
    os.makedirs(corpus)
    os.makedirs(dbdir)
    origin = {}
    for i, f in enumerate(collect(args.paths, args.limit, args.max_size)):
        name = "f%06d" % i
        try:
            shutil.copyfile(f, os.path.join(corpus, name))
        except OSError:
            continue
        origin[name] = f
    shutil.copyfile(args.ftm, os.path.join(dbdir, os.path.basename(args.ftm)))
    with open(os.path.join(dbdir, "none.ndb"), "w") as fh:
        fh.write("Diff.Nothing:0:*:f1e2d3c4b5a69788796a5b4c3d2e1f00\n")

    cmd = [args.clamscan, "--gen-json", "--debug", "--no-summary", "--bytecode=no", "-d", dbdir, corpus]
    if args.certs:
        cmd.insert(1, "--cvdcertsdir=" + args.certs)
    clam = {}
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"))
    name = None
    for raw in proc.stderr:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        m = TOP_NAME.match(line)
        if m:
            name = m.group(1)
            continue
        m = TOP_TYPE.match(line)
        if m and name is not None:
            clam.setdefault(name, m.group(1))
            name = None
    proc.wait()

    out = subprocess.run([args.zav_diff, "types", "--tmp", os.path.join(args.work, "tmp"), args.ftm, "--", corpus],
                         stdout=subprocess.PIPE, check=True).stdout
    zav = dict(l.split("\t", 1) for l in out.decode().splitlines() if "\t" in l)

    known = {}
    if args.known:
        for l in open(args.known):
            l = l.strip()
            if l and not l.startswith("#"):
                c, z, reason = l.split(None, 2)
                known[(c, z)] = reason
    pairs = collections.Counter()
    examples = {}
    agree = 0
    for n in sorted(origin):
        c, z = clam.get(n), zav.get(n)
        if c is None or z is None:
            pairs[("(missing)" if c is None else c, "(missing)" if z is None else z)] += 1
            continue
        if c == z:
            agree += 1
            continue
        pairs[(c, z)] += 1
        examples.setdefault((c, z), origin[n])
    failures = 0
    for (c, z), k in pairs.most_common():
        tag = "known" if (c, z) in known else "DIFF"
        if tag == "DIFF" and "(missing)" not in (c, z):
            failures += k
        print("%s %6d libclamav %s, zav %s (e.g. %s)%s" % (tag, k, c, z, examples.get((c, z), "-"),
                                                          ": " + known[(c, z)] if (c, z) in known else ""))
    print("ftm_check.py: %d files, %d typed the same, %d differ (%d not listed)" % (
        len(origin), agree, sum(pairs.values()), failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
