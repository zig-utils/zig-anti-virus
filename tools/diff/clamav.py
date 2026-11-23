#!/usr/bin/env python3
"""The libclamav side of the differential suite.

Materialises the case files with zav-diff, runs clamscan on every case and checks that libclamav
still gives the verdicts recorded in the case files (`=>` after each sample, `!` after the
directive of a signature ClamAV refuses). zav's side of the same expectations is checked by
`zig build diff` (zav-diff check), so together they say zav agrees with libclamav.

  clamav.py [--clamscan PATH] [--certs DIR] [--zav-diff PATH] [--work DIR] [--record] CASES...

--record rewrites the case files with what clamscan reported instead of failing: that is how
expectations are written. Exit 0 when clamscan agrees with every expectation, 1 otherwise.
"""
import argparse
import os
import re
import subprocess
import sys

# Signatures that shape a scan rather than detect: they go into every database of their case.
CONTEXT = ("ftm", "fp", "sfp", "ign2")
FOUND = re.compile(r"^(.*): (.+) FOUND$")


def run(cmd, **kw):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, **kw)


# --raw: no format parsers, so embedded type triggers (HTML, mail, PDF...) cannot re-type a
# sample and every file is matched as the raw bytes it is. For signatures from the databases,
# whose samples are generated text.
RAW = ["--scan-mail=no", "--scan-html=no", "--scan-ole2=no", "--scan-pdf=no", "--scan-swf=no",
       "--scan-xmldocs=no", "--scan-hwp3=no", "--scan-onenote=no", "--scan-archive=no", "--scan-image=no"]


class Clamscan:
    def __init__(self, path, certs, raw=False):
        self.path = path
        # PUA signatures (.ndu, .ldu, .hdu, ...) count: zav-diff scans with PUA detection on.
        self.base = [path, "--no-summary", "--allmatch", "--bytecode=no", "--detect-pua=yes"] + (RAW if raw else [])
        if certs:
            self.base.append("--cvdcertsdir=" + certs)

    def loads(self, db, empty):
        """True when clamscan loads `db` without an error."""
        r = run(self.base + ["-d", db, empty])
        if r.returncode == 2:
            return False, (r.stderr.decode("utf-8", "replace").strip().splitlines() or [""])[0]
        return True, ""

    def scan(self, dbs, files):
        """{file: set(names)} with clamscan --allmatch over `dbs`."""
        out = {f: set() for f in files}
        if not dbs:
            return out
        cmd = list(self.base)
        for d in dbs:
            cmd += ["-d", d]
        r = run(cmd + files)
        if r.returncode not in (0, 1):
            raise RuntimeError("clamscan failed (%d) with %s on %s: %s" % (
                r.returncode, " ".join(dbs), " ".join(files), r.stderr.decode("utf-8", "replace")))
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            m = FOUND.match(line)
            if not m:
                continue
            name = m.group(2)
            if name.endswith(".UNOFFICIAL"):
                name = name[: -len(".UNOFFICIAL")]
            out.setdefault(m.group(1), set()).add(name)
        return out


def read_manifest(path):
    sigs, samples = [], []
    with open(path) as f:
        for line in f:
            parts = line.rstrip("\n").split(" ", 5)
            if parts[0] == "sig":
                # sig N FILE LINE loads|rejects NAME
                ext = parts[2].rsplit(".", 1)[-1]
                sigs.append({"n": int(parts[1]), "file": parts[2], "line": int(parts[3]), "loads": parts[4] == "loads",
                             "context": ext in CONTEXT})
            elif parts[0] == "sample":
                # sample N FILE LINE RESULT...
                rest = line.rstrip("\n").split(" ", 4)
                want = rest[4].split() if len(rest) > 4 else []
                samples.append({"n": int(rest[1]), "file": rest[2], "line": int(rest[3]), "want": sorted(set(w for w in want if w != "OK"))})
    return sigs, samples


def fmt(names):
    return " ".join(sorted(names)) if names else "OK"


def rewrite(case_file, sig_edits, sample_edits):
    """Apply recorded results to a case file: {line: loads} and {line: result}."""
    with open(case_file) as f:
        lines = f.read().split("\n")
    for line_no, loads in sig_edits.items():
        text = lines[line_no - 1]
        stripped = text.lstrip()
        indent = text[: len(text) - len(stripped)]
        word, _, rest = stripped.partition(" ")
        word = word.rstrip("!")
        lines[line_no - 1] = indent + word + ("" if loads else "!") + " " + rest
    for line_no, result in sample_edits.items():
        text = lines[line_no - 1]
        i = text.rfind("=>")
        lines[line_no - 1] = text[:i] + "=> " + result
    with open(case_file, "w") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clamscan", default=os.environ.get("CLAMSCAN", "clamscan"))
    ap.add_argument("--certs", default=os.environ.get("CLAMAV_CERTS"))
    ap.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    ap.add_argument("--work", default=".zav-diff-work")
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--raw", action="store_true", help="disable libclamav's format parsers")
    ap.add_argument("cases", nargs="+")
    args = ap.parse_args()

    r = run([args.zav_diff, "materialize", "--out", args.work] + args.cases)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode() + r.stdout.decode())
        return 2
    clam = Clamscan(args.clamscan, args.certs, args.raw)
    empty = os.path.join(args.work, "empty")
    open(empty, "w").close()

    checks = agree = 0
    failures = []
    edits = {}  # case file -> (sig edits, sample edits)
    with open(os.path.join(args.work, "cases")) as f:
        index = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    for case, case_file in index:
        d = os.path.join(args.work, case)
        sigs, samples = read_manifest(os.path.join(d, "manifest"))
        sig_edits, sample_edits = edits.setdefault(case_file, ({}, {}))
        loaded, context = [], []
        for s in sigs:
            ok, why = clam.loads(os.path.join(d, s["file"]), empty)
            checks += 1
            if ok == s["loads"]:
                agree += 1
            else:
                failures.append("%s sig%d (%s:%d): recorded %s, clamscan %s %s" % (case, s["n"], case_file, s["line"], "loads" if s["loads"] else "rejects", "loads" if ok else "rejects", why))
                sig_edits[s["line"]] = ok
            if ok:
                (context if s["context"] else loaded).append(os.path.join(d, s["file"]))
        files = [os.path.join(d, "s%d" % s["n"]) for s in samples]
        # One clamscan per signature, as zav-diff compiles one database per signature: patterns
        # sharing a matcher can change each other's results inside libclamav, and the suite is
        # about each signature's own semantics.
        got = {}
        for db in loaded:
            for path, names in clam.scan([db] + context, files).items():
                got.setdefault(path, set()).update(names)
        for s, path in zip(samples, files):
            checks += 1
            have = sorted(got.get(path, set()))
            if have == s["want"]:
                agree += 1
            else:
                failures.append("%s s%d (%s:%d): recorded %s, clamscan %s" % (case, s["n"], case_file, s["line"], fmt(s["want"]), fmt(have)))
                sample_edits[s["line"]] = fmt(have)

    for line in failures:
        print(("RECORD " if args.record else "FAIL ") + line)
    if args.record:
        for case_file, (sig_edits, sample_edits) in edits.items():
            if sig_edits or sample_edits:
                rewrite(case_file, sig_edits, sample_edits)
    print("clamav.py: %d cases, %d checks: %d agree with the recorded libclamav verdicts, %d %s" % (
        len(index), checks, agree, len(failures), "recorded" if args.record else "differ"))
    return 0 if args.record or not failures else 1


if __name__ == "__main__":
    sys.exit(main())
