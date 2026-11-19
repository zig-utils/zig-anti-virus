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
report exactly that file's signature. --known accepts only the exact named, content-pinned
scanner differences in its JSON file; missing/stale entries and new differences fail.
The signatures use target type 0 (`--target`): libclamav
matches module sources with target 2 only when its legacy reader understands _VBA_PROJECT, and
otherwise scans the dumped project as a script, where target-0 signatures still apply.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

from oletools.olevba import VBA_Parser


def files_under(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        else:
            for d, dirs, names in os.walk(p):
                dirs.sort()
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
    ap.add_argument("--known", help="JSON file of exact, content-pinned macro scan differences")
    ap.add_argument("--timeout", type=float, default=120, help="seconds per scanner invocation")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    if args.timeout <= 0:
        ap.error("--timeout must be positive")
    if args.known and not args.clamscan:
        ap.error("--known requires --clamscan")
    files = list(dict.fromkeys(os.path.abspath(f) for f in files_under(args.paths)))
    if not files:
        ap.error("no input files")
    zav = {}
    out = run_tool([args.zav_diff, "vba"] + files, args.timeout, (0,)).decode()
    for line in out.splitlines():
        f, stream, hexsrc = line.split("\t")
        zav[(f, stream.rsplit("/", 1)[-1])] = bytes.fromhex(hexsrc)
    ole = {}
    for f in files:
        vp = None
        try:
            vp = VBA_Parser(f)
            if not vp.detect_vba_macros():
                continue
            for _, stream, _, code in vp.extract_macros():
                ole[(f, stream.replace("\\", "/").rsplit("/", 1)[-1])] = code.encode("cp1252", "replace") if isinstance(code, str) else code
        except Exception as e:  # olevba refuses the file: count it, zav's view stands alone
            ole[(f, "(olevba error)")] = repr(e).encode()
        finally:
            if vp is not None:
                vp.close()
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


def run_tool(cmd, timeout, allowed):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(os.environ, LC_ALL="C"), timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("%s timed out after %g seconds" % (cmd[0], timeout)) from e
    if result.returncode not in allowed:
        raise RuntimeError("%s exited %d: %s" % (cmd[0], result.returncode,
                           result.stderr.decode("utf-8", "replace").strip()))
    return result.stdout


def scan_results(cmd, files, timeout, unofficial=False):
    out = run_tool(cmd, timeout, (0, 1))
    results = {}
    for line in out.decode("utf-8", "replace").splitlines():
        # Both tools print one OK or one or more FOUND lines per input. ERROR, LIMITED,
        # unknown paths and missing output must not be mistaken for clean verdicts.
        match = re.fullmatch(r"(.+): (OK|(.+) FOUND)", line)
        if not match:
            raise RuntimeError("invalid scanner result: " + line)
        path = os.path.abspath(match.group(1))
        if path not in files:
            raise RuntimeError("scanner reported an unknown input: " + path)
        name = match.group(3)
        if name is None:
            if path in results:
                raise RuntimeError("duplicate scanner verdict: " + path)
            results[path] = set()
        else:
            if path in results and not results[path]:
                raise RuntimeError("conflicting scanner verdicts: " + path)
            if unofficial:
                if name.endswith(".UNOFFICIAL"):
                    name = name[:-11]
            results.setdefault(path, set()).add(name)
    missing = set(files) - results.keys()
    if missing:
        raise RuntimeError("scanner omitted inputs: " + ", ".join(sorted(missing)))
    return results


def known_differences(path):
    if not path:
        return {}
    with open(path) as fh:
        data = json.load(fh)
    known = {}
    for entry in data["differences"]:
        key = (entry["file"], entry["sha256"])
        if key in known or not re.fullmatch(r"[0-9a-f]{64}", key[1]):
            raise ValueError("duplicate or invalid known difference: " + str(key))
        known[key] = (set(entry["clamscan"]), set(entry["zav"]))
    return known


def signatures(args, files, ole):
    os.makedirs(args.work, exist_ok=True)
    want, identities, lines = {}, {}, {}
    for f in files:
        with open(f, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        identities[f] = (os.path.basename(f), digest)
        mods = [v for (g, _), v in ole.items() if g == f]
        pieces = [m.group(1)[:16] for v in mods for m in re.finditer(rb'"([0-9a-z]{16,})"', v)]
        want[f] = set()
        if not pieces:
            continue
        # Content identity keeps signatures stable when unrelated files are added or directories
        # arrive in a different order. Full paths, rather than basenames, key scan verdicts.
        name = "Diff.Macro." + digest
        lines[name] = "%s:%s:*:%s" % (name, args.target, pieces[len(pieces) // 2].hex())
        want[f] = {name}
    db = os.path.join(args.work, "macro.ndb")
    if not lines:
        raise RuntimeError("no macro signatures generated")
    with open(db, "w") as fh:
        fh.write("\n".join(lines.values()) + "\n")
    known = known_differences(args.known)
    cmd = [args.clamscan, "--no-summary", "--allmatch", "--bytecode=no", "-d", db]
    if args.certs:
        cmd.append("--cvdcertsdir=" + args.certs)
    clam = scan_results(cmd + files, files, args.timeout, unofficial=True)
    zav = scan_results([args.zav_diff, "scan", "--tmp", os.path.join(args.work, "tmp"),
                        "--sigs", db, "--"] + files, files, args.timeout)
    agree = bad = 0
    seen = set()
    for f, expected in sorted(want.items()):
        c, z = clam[f], zav[f]
        key = identities[f]
        if c == z == expected:
            agree += bool(expected)
            continue
        # A known ClamAV miss cannot waive a wrong or missing zav detection. Compare the
        # complete sets, including extra signatures, and require each exception exactly once.
        if z == expected and key in known and known[key] == (c, z) and key not in seen:
            seen.add(key)
            continue
        bad += 1
        print("MACRO %s: expected %s, clamscan %s, zav %s" % (f, sorted(expected), sorted(c), sorted(z)))
    for key in sorted(known.keys() - seen):
        bad += 1
        print("STALE known macro difference: %s sha256=%s" % key)
    print("vba_check.py: macro signatures: %d files, %d detected by both, %d known differences" %
          (sum(bool(names) for names in want.values()), agree, len(seen)))
    return bad == 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError) as e:
        print("vba_check.py: " + str(e), file=sys.stderr)
        sys.exit(1)
