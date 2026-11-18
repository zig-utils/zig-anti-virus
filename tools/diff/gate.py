#!/usr/bin/env python3
"""P4.21 gate: zav and clamscan --bytecode=no over a raw-file corpus with the whole databases.

  gate.py --cvd main.cvd --cvd daily.cvd --db DIR... [--zav-diff PATH] SAMPLES_DIR

clamscan runs with --allmatch; zav-diff scan compiles the extracted database files (DIR...) into
one database and reports each file's first detection. A file agrees when both are clean or zav's
detection is among clamscan's. The corpus is realdb.py gate's output (samples built from the
target-0 body and logical signatures). Exit 0 when every file agrees.
"""
import argparse
import collections
import os
import re
import subprocess
import sys

FOUND = re.compile(r"^(.*): (.+) FOUND$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clamscan", default=os.environ.get("CLAMSCAN", "clamscan"))
    ap.add_argument("--certs", default=os.environ.get("CLAMAV_CERTS"))
    ap.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    ap.add_argument("--cvd", action="append", required=True)
    ap.add_argument("--db", action="append", required=True)
    ap.add_argument("--tmp", default=".zav-diff-tmp")
    ap.add_argument("--show", type=int, default=40)
    ap.add_argument("samples")
    args = ap.parse_args()

    # PUA signatures (.ndu, .ldu) are reported by zav, so clamscan reports them too.
    cmd = [args.clamscan, "--no-summary", "--allmatch", "--bytecode=no", "--detect-pua=yes"]
    if args.certs:
        cmd.append("--cvdcertsdir=" + args.certs)
    # One database directory, as clamd and freshclam use: libclamav then takes the ignore lists
    # (daily.ign2) before the signatures they name. Loading main.cvd with its own -d before
    # daily.cvd would apply daily.ign2 too late.
    dbdir = os.path.join(args.tmp, "clamav-db")
    os.makedirs(dbdir, exist_ok=True)
    for c in args.cvd:
        for f in (c, c + ".sign"):
            link = os.path.join(dbdir, os.path.basename(f))
            if os.path.exists(f) and not os.path.exists(link):
                os.symlink(os.path.abspath(f), link)
    cmd += ["-d", dbdir]
    r = subprocess.run(cmd + [args.samples], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"))
    clam = collections.defaultdict(set)
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        m = FOUND.match(line)
        if m:
            clam[os.path.basename(m.group(1))].add(m.group(2))

    sigs = []
    for d in args.db:
        for n in sorted(os.listdir(d)):
            if n == "COPYING" or n.endswith((".info", ".cfg")):
                continue
            sigs.append(os.path.join(d, n))
    r = subprocess.run([args.zav_diff, "scan", "--tmp", args.tmp, "--sigs"] + sigs + ["--", args.samples], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    zav = {}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        m = FOUND.match(line)
        if m:
            zav[os.path.basename(m.group(1))] = m.group(2)
        elif line.endswith(": OK"):
            zav.setdefault(os.path.basename(line[:-4]), None)
        elif ": LIMITED(" in line:
            zav[os.path.basename(line.split(": LIMITED(")[0])] = "LIMITED"

    counts = collections.Counter()
    shown = 0
    files = sorted(os.listdir(args.samples))
    for f in files:
        c, z = clam.get(f, set()), zav.get(f)
        if not c and z is None:
            counts["both clean"] += 1
        elif z is not None and z in c:
            counts["same detection"] += 1
        else:
            kind = "missed by zav" if z is None else ("zav only" if not c else ("zav limited" if z == "LIMITED" else "different names"))
            counts[kind] += 1
            if shown < args.show:
                shown += 1
                print("%s %s: clamscan %s, zav %s" % (kind.upper(), f, sorted(c) or "OK", z or "OK"))
    agree = counts["both clean"] + counts["same detection"]
    print("gate.py: %d files, %d agree (%d detected by both, %d clean in both); %s" % (
        len(files), agree, counts["same detection"], counts["both clean"],
        ", ".join("%d %s" % (v, k) for k, v in counts.items() if k not in ("both clean", "same detection")) or "no differences"))
    return 0 if agree == len(files) else 1


if __name__ == "__main__":
    sys.exit(main())
