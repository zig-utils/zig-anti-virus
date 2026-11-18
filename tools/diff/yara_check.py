#!/usr/bin/env python3
"""zav against yara on the YARA rules of the differential cases.

The case files record libclamav's verdicts; libclamav runs YARA rules with a reduced feature set
(it ignores regex modifiers, does not implement xor or the uintN reads), so zav follows yara on
YARA semantics and lists libclamav's differences in tests/differential/known.txt. This runner
checks the yara side: every YARA rule zav loads must load in yara, and on every sample zav and
yara must report the same rules. Differences yara and zav are allowed to have (rules zav refuses
by design) are in tests/differential/known-yara.txt, in known.txt's format.

  yara_check.py [--zav-diff PATH] [--work DIR] [--known FILE] CASES...

Needs yara-python (pip install yara-python). Exit 0 when everything agrees.
"""
import argparse
import os
import subprocess
import sys

import yara


def read_known(path):
    known = {}
    if not path or not os.path.exists(path):
        return known
    with open(path) as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            case, which, rest = line.split(None, 2)
            known[(case, which)] = rest[len("zav="):] if rest.startswith("zav=") else rest
    return known


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    ap.add_argument("--work", default=".zav-diff-work")
    ap.add_argument("--known", default="tests/differential/known-yara.txt")
    ap.add_argument("cases", nargs="+")
    args = ap.parse_args()

    r = subprocess.run([args.zav_diff, "materialize", "--out", args.work] + args.cases, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode())
        return 2
    r = subprocess.run([args.zav_diff, "check", "--print", "--tmp", os.path.join(args.work, ".tmp")] + args.cases,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    zav_load, zav_result = {}, {}
    for line in r.stdout.decode().splitlines():
        parts = line.split(" ", 3)
        if parts[0] == "LOAD":
            zav_load[(parts[1], parts[2])] = parts[3]
        elif parts[0] == "RESULT":
            zav_result[(parts[1], parts[2])] = set(n for n in parts[3].split() if n != "OK")

    known = read_known(args.known)
    used = set()
    checks = agree = known_hits = 0
    failures = []
    with open(os.path.join(args.work, "cases")) as f:
        index = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    for case, case_file in index:
        d = os.path.join(args.work, case)
        sigs, samples = [], []
        with open(os.path.join(d, "manifest")) as f:
            for line in f:
                parts = line.rstrip("\n").split(" ")
                if parts[0] == "sig" and parts[2].endswith(".yar"):
                    sigs.append((int(parts[1]), parts[2], parts[5]))
                elif parts[0] == "sample":
                    samples.append(int(parts[1]))
        if not sigs:
            continue
        yara_names = set()
        compiled = []
        for n, fname, name in sigs:
            which = "sig%d" % n
            try:
                rules = yara.compile(filepath=os.path.join(d, fname))
                got = "LOADS"
                compiled.append((name, rules))
            except yara.Error:
                got = "REJECTS"
            yara_names.add(name)
            zav = zav_load.get((case, which), "?")
            checks += 1
            if zav == got:
                agree += 1
                if (case, which) in known:
                    failures.append("%s %s: listed as a known difference, but zav agrees with yara" % (case, which))
                    used.add((case, which))
            elif known.get((case, which)) == zav:
                known_hits += 1
                used.add((case, which))
                # The refusal is the difference: the rule's matches are left out of the samples.
                if zav == "REJECTS":
                    compiled = [(nm, rl) for nm, rl in compiled if nm != name]
            else:
                failures.append("%s %s (%s): yara %s, zav %s" % (case, which, case_file, got.lower(), zav))
        for n in samples:
            which = "s%d" % n
            with open(os.path.join(d, which), "rb") as f:
                data = f.read()
            want = set()
            for name, rules in compiled:
                if rules.match(data=data):
                    want.add(name)
            got = set(x for x in zav_result.get((case, which), set()) if x in yara_names)
            checks += 1
            fmt = lambda s: " ".join(sorted(s)) if s else "OK"
            if want == got:
                agree += 1
                if (case, which) in known:
                    failures.append("%s %s: listed as a known difference, but zav agrees with yara" % (case, which))
                    used.add((case, which))
            elif known.get((case, which)) == fmt(got):
                known_hits += 1
                used.add((case, which))
            else:
                failures.append("%s %s (%s): yara %s, zav %s" % (case, which, case_file, fmt(want), fmt(got)))
    for k in known:
        if k not in used:
            failures.append("known difference %s %s matches nothing" % k)
    for line in failures:
        print("FAIL " + line)
    print("yara_check.py: yara %s, %d checks: %d agree, %d known differences, %d failures" % (
        yara.YARA_VERSION, checks, agree, known_hits, len(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
