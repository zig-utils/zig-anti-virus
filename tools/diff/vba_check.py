#!/usr/bin/env python3
"""VBA source extraction: zav's (`zav-diff vba`) against olevba's (oletools).

  vba_check.py [--zav-diff PATH] [--show N] PATH...

For every file under PATH, oletools' VBA_Parser.extract_macros gives each module's stream and
source; zav-diff vba gives zav's. Modules are matched by stream name (olevba reports the path
only sometimes). Sources are compared as bytes: olevba decodes them with
the project code page, so they are encoded back the same way (cp1252 unless the dir stream says
otherwise; the generated corpus uses 1252). A module only one side finds is a difference. Run
with the Python that has oletools. Exit 0 when every module agrees.
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
    return 0 if agree == len(keys) else 1


if __name__ == "__main__":
    sys.exit(main())
