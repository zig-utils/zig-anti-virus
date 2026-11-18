#!/usr/bin/env python3
"""VBA source extraction: zav's (`zav-diff vba`) against olevba's (oletools).

  vba_check.py [--zav-diff PATH] [--show N] PATH...

For every file under PATH, oletools' VBA_Parser.extract_macros gives each module's stream and
source; zav-diff vba gives zav's. Modules are matched by stream name (olevba reports the path
only sometimes). Sources are compared as bytes: olevba decodes them with
the project code page, so they are encoded back the same way (cp1252 unless the dir stream says
otherwise; the generated corpus uses 1252). A module only one side finds is a difference. Run
with the Python that has oletools. Exit 0 when every module agrees.

With --clamscan, macro signatures are checked too: one .ndb signature per file, 16 random
characters from a string literal in one of its modules, and clamscan and zav-diff scan must both
report exactly that file's signature. The signatures use target type 0 (`--target`): libclamav
matches module sources with target 2 only when its legacy reader understands _VBA_PROJECT, and
otherwise scans the dumped project as a script, where target-0 signatures still apply.
"""
import argparse
import os
import subprocess
import sys

from oletools.olevba import VBA_Parser


def files_under(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        else:
            for d, _, names in os.walk(p):
                for n in sorted(names):
                    yield os.path.join(d, n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    ap.add_argument("--show", type=int, default=20)
    ap.add_argument("--clamscan", default=os.environ.get("CLAMSCAN"))
    ap.add_argument("--certs", default=os.environ.get("CLAMAV_CERTS"))
    ap.add_argument("--work", default=".zav-diff-vba")
    ap.add_argument("--target", default="0")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    files = list(files_under(args.paths))
    zav = {}
    out = subprocess.run([args.zav_diff, "vba"] + files, stdout=subprocess.PIPE, check=True).stdout.decode()
    for line in out.splitlines():
        f, stream, hexsrc = line.split("\t")
        zav[(f, stream.rsplit("/", 1)[-1])] = bytes.fromhex(hexsrc)
    ole = {}
    for f in files:
        try:
            vp = VBA_Parser(f)
            if not vp.detect_vba_macros():
                continue
            for _, stream, _, code in vp.extract_macros():
                ole[(f, stream.replace("\\", "/").rsplit("/", 1)[-1])] = code.encode("cp1252", "replace") if isinstance(code, str) else code
            vp.close()
        except Exception as e:  # olevba refuses the file: count it, zav's view stands alone
            ole[(f, "(olevba error)")] = repr(e).encode()
    shown = agree = 0
    keys = sorted(set(zav) | set(ole))
    for k in keys:
        if zav.get(k) == ole.get(k):
            agree += 1
            continue
        if shown < args.show:
            shown += 1
            z, o = zav.get(k), ole.get(k)
            i = next((j for j in range(min(len(z or b""), len(o or b""))) if z[j] != o[j]), min(len(z or b""), len(o or b"")))
            print("DIFF %s %s at byte %d: olevba %r, zav %r" % (k[0], k[1], i, (o or b"(none)")[i:i + 40], (z or b"(none)")[i:i + 40]))
    print("vba_check.py: %d files, %d modules, %d identical" % (len(files), len(keys), agree))
    ok = agree == len(keys)
    if args.clamscan:
        ok = signatures(args, files, ole) and ok
    return 0 if ok else 1


def signatures(args, files, ole):
    import re
    os.makedirs(args.work, exist_ok=True)
    want, lines = {}, []
    for i, f in enumerate(files):
        mods = [v for (g, _), v in ole.items() if g == f]
        pieces = [m.group(1)[:16] for v in mods for m in re.finditer(rb'"([0-9a-z]{16,})"', v)]
        if not pieces:
            continue
        name = "Diff.Macro.%d" % i
        lines.append("%s:%s:*:%s" % (name, args.target, pieces[len(pieces) // 2].hex()))
        want[os.path.basename(f)] = name
    db = os.path.join(args.work, "macro.ndb")
    with open(db, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    found = re.compile(r"^(.*): (.+) FOUND$")
    cmd = [args.clamscan, "--no-summary", "--allmatch", "--bytecode=no", "-d", db]
    if args.certs:
        cmd.append("--cvdcertsdir=" + args.certs)
    clam, zav = {}, {}
    out = subprocess.run(cmd + files, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C")).stdout
    for l in out.decode("utf-8", "replace").splitlines():
        m = found.match(l)
        if m:
            clam.setdefault(os.path.basename(m.group(1)), set()).add(m.group(2).replace(".UNOFFICIAL", ""))
    out = subprocess.run([args.zav_diff, "scan", "--tmp", os.path.join(args.work, "tmp"), "--sigs", db, "--"] + files, stdout=subprocess.PIPE).stdout
    for l in out.decode("utf-8", "replace").splitlines():
        m = found.match(l)
        if m:
            zav.setdefault(os.path.basename(m.group(1)), set()).add(m.group(2))
    agree = 0
    for f, name in sorted(want.items()):
        c, z = clam.get(f, set()), zav.get(f, set())
        if name in c and name in z:
            agree += 1
        else:
            print("MACRO %s: expected %s, clamscan %s, zav %s" % (f, name, sorted(c), sorted(z)))
    print("vba_check.py: macro signatures: %d files, %d detected by both" % (len(want), agree))
    return agree == len(want)


if __name__ == "__main__":
    sys.exit(main())
