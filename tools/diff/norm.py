#!/usr/bin/env python3
"""zav's text (target 7) and HTML (target 3) normalisers against libclamav's.

  norm.py [--clamscan PATH] [--certs DIR] [--zav-diff PATH] [--work DIR] [--show N] PATH...

For every file, clamscan --leave-temps keeps what libclamav normalised: for ASCII text the
file cli_scanscript saves; for HTML nocomment.html, notags.html and `javascript` (the scripts'
normalised JavaScript). zav-diff normalize gives zav's forms. They must be byte-identical
(`javascript` is counted but only fails with --strict-js: the JavaScript normaliser is P5.13).
PATHs are files or directories. Exit 0 when every file agrees.
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys


def clamav_normalized(base, path, tmp):
    """[(kind, bytes)] libclamav normalised the file into, or [] when it did not."""
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    subprocess.run(base + ["--leave-temps", "--tempdir=" + tmp, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   env=dict(os.environ, LC_ALL="C"))
    html = glob.glob(os.path.join(tmp, "*", "html-tmp.*", "nocomment.html"))
    if html:
        d = os.path.dirname(html[0])
        out = [("html", open(html[0], "rb").read())]
        notags = os.path.join(d, "notags.html")
        out.append(("notags", open(notags, "rb").read() if os.path.exists(notags) else b""))
        js = os.path.join(d, "javascript")
        out.append(("js", open(js, "rb").read() if os.path.exists(js) else b""))
        return out
    text = glob.glob(os.path.join(tmp, "*", "clamav-*.tmp"))
    if text:
        return [("text", open(text[0], "rb").read())]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clamscan", default=os.environ.get("CLAMSCAN", "clamscan"))
    ap.add_argument("--certs", default=os.environ.get("CLAMAV_CERTS"))
    ap.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    ap.add_argument("--work", default=".zav-diff-work")
    ap.add_argument("--show", type=int, default=20)
    ap.add_argument("--html-report-only", action="store_true", help="count HTML differences without failing")
    ap.add_argument("--strict-js", action="store_true", help="fail on JavaScript differences too")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    os.makedirs(args.work, exist_ok=True)
    db = os.path.join(args.work, "none.ndb")
    with open(db, "w") as f:
        f.write("Diff.Nothing:0:*:f1e2d3c4b5a69788796a5b4c3d2e1f00\n")
    base = [args.clamscan, "--no-summary", "--bytecode=no", "-d", db]
    if args.certs:
        base.append("--cvdcertsdir=" + args.certs)
    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(os.path.join(d, n) for d, _, ns in os.walk(p) for n in ns)
        else:
            files.append(p)
    counts, shown, failures = {}, 0, 0
    for path in files:
        forms = clamav_normalized(base, path, os.path.join(args.work, "norm-tmp"))
        if not forms:
            counts.setdefault("other", [0, 0, 0])[0] += 1
            continue
        for kind, want in forms:
            got = subprocess.run([args.zav_diff, "normalize", kind, path], stdout=subprocess.PIPE).stdout
            c = counts.setdefault(kind, [0, 0, 0])
            c[0] += 1
            if got == want:
                c[1] += 1
                continue
            # libclamav's text normaliser restarts whitespace collapsing at its internal buffer
            # seams (hundreds of KiB apart), leaving one extra space there; zav collapses throughout.
            if kind == "text" and want.replace(b"  ", b" ") == got:
                c[2] += 1
                continue
            if kind in ("html", "notags") and args.html_report_only:
                continue
            if kind == "js" and not args.strict_js:
                continue
            failures += 1
            if shown < args.show:
                shown += 1
                i = next((k for k in range(min(len(got), len(want))) if got[k] != want[k]), min(len(got), len(want)))
                print("DIFF %s (%s) at byte %d:\n  libclamav %r\n  zav       %r" % (path, kind, i, want[max(0, i - 30):i + 50], got[max(0, i - 30):i + 50]))
    for kind, c in sorted(counts.items()):
        extra = ", %d differ only by libclamav's buffer seams" % c[2] if kind == "text" else ""
        print("norm.py: %s: %d files, %d byte-identical%s" % (kind, c[0], c[1], extra))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
