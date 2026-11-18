#!/usr/bin/env python3
"""Differential cases generated from the real ClamAV databases (never committed).

  realdb.py pcre --db DIR... --out FILE [--limit N]
      One case per PCRE subsignature of the .ldb/.ldu files under DIR: the subsig with its
      pattern and flags, behind a fixed trigger (subsig 0 = "TRIG"), offset dropped, and samples
      generated from the pattern (strings it should match, near misses, filler).
  realdb.py bytecompare --db DIR... --out FILE
      One case per byte-compare subsignature, with values on both sides of each comparison.
  realdb.py corpus [--db DIR...] [--yara PATH...] --out FILE
      The E13 corpus (tools/diff/e13.zig): every PCRE subsig and every YARA regex string, each
      with generated subjects.

The output is an ordinary case file: fill in libclamav's verdicts with
`clamav.py --raw --record FILE`, then compare zav with `zav-diff check FILE`. Signatures from the
databases are compiled on the host and must not be redistributed, so these files stay in the
work directory.
"""
import argparse
import os
import random
import sys

try:
    import re._parser as sre_parse  # Python 3.11+
    import re._constants as sre_constants
except ImportError:  # Python 3.9, 3.10
    import sre_parse
    import sre_constants


def ldb_fields(line):
    """Split an .ldb line on ';', rejoining PCRE subsigs that contain ';' (as libclamav does)."""
    raw = line.split(";")
    out = []
    i = 0
    while i < len(raw):
        f = raw[i]
        i += 1
        if len(out) >= 3:
            while pcre_open(f) and i < len(raw):
                f += ";" + raw[i]
                i += 1
        out.append(f)
    return out


def is_byte_compare(f):
    o = f.find("(")
    return o > 0 and f.endswith(")") and f[:o].isdigit() and "#" in f


def pcre_open(f):
    if is_byte_compare(f) or f.startswith("${") or f.startswith("fuzzy_img#"):
        return False
    slashes, i = 0, 0
    while i < len(f):
        if f[i] == "\\":
            i += 1
        elif f[i] == "/":
            slashes += 1
        i += 1
    return slashes == 1


def is_pcre(f):
    return "/" in f and not is_byte_compare(f) and not f.startswith("${") and not f.startswith("fuzzy_img#")


def split_pcre(f):
    """[offset:]trigger/pattern/flags -> (offset, trigger, pattern, flags)."""
    first = f.index("/")
    last = f.rindex("/")
    head, pattern, flags = f[:first], f[first + 1:last], f[last + 1:]
    offset, trigger = "", head
    if ":" in head:
        offset, trigger = head.rsplit(":", 1)
    return offset, trigger, pattern, flags


def db_lines(dirs, exts):
    for d in dirs:
        for name in sorted(os.listdir(d)):
            if name.rsplit(".", 1)[-1] not in exts:
                continue
            with open(os.path.join(d, name), "rb") as fh:
                for n, raw in enumerate(fh.read().decode("latin-1").split("\n"), 1):
                    line = raw.rstrip("\r")
                    if line and not line.startswith("#"):
                        yield name, n, line


# Generating strings from a pattern ---------------------------------------------------------------

class Gen:
    """Walk an sre_parse tree and produce a string the pattern should match."""

    def __init__(self, rng, more):
        self.rng = rng
        self.more = more  # repeat beyond the minimum
        self.groups = {}
        self.steps = 0

    def run(self, tree):
        out = []
        for op, av in tree:
            self.steps += 1
            if self.steps > 20000:
                raise ValueError("too large")
            out.append(self.node(op, av))
        return "".join(out)

    def node(self, op, av):
        c = sre_constants
        if op == c.LITERAL:
            return chr(av)
        if op == c.NOT_LITERAL:
            return chr((av + 1) % 256) if av != ord("x") else "y"
        if op == c.ANY:
            return "x"
        if op == c.IN:
            return self.cls(av)
        if op in (c.MAX_REPEAT, c.MIN_REPEAT) or op == getattr(c, "POSSESSIVE_REPEAT", None):
            lo, hi, sub = av
            n = lo
            if self.more and (hi == c.MAXREPEAT or hi > lo):
                n = lo + 1 if lo < 64 else lo
            if n > 4096:
                raise ValueError("repeat too large")
            return "".join(self.run(sub) for _ in range(n))
        if op == c.BRANCH:
            _, alts = av
            pick = alts[-1] if self.more else alts[0]
            return self.run(pick)
        if op == c.SUBPATTERN:
            group, sub = av[0], av[-1]
            s = self.run(sub)
            if group:
                self.groups[group] = s
            return s
        if op == getattr(c, "ATOMIC_GROUP", None):
            return self.run(av)
        if op == c.GROUPREF:
            return self.groups.get(av, "")
        if op == c.AT:
            return ""
        if op in (c.ASSERT, c.ASSERT_NOT):
            return ""
        if op == c.CATEGORY:
            return self.category(av)
        if op == c.GROUPREF_EXISTS:
            return ""
        raise ValueError("unsupported op %s" % op)

    def category(self, av):
        c = sre_constants
        table = {c.CATEGORY_DIGIT: "7", c.CATEGORY_NOT_DIGIT: "x", c.CATEGORY_SPACE: " ",
                 c.CATEGORY_NOT_SPACE: "x", c.CATEGORY_WORD: "w", c.CATEGORY_NOT_WORD: "-"}
        return table.get(av, "x")

    def cls(self, items):
        c = sre_constants
        negate = any(op == c.NEGATE for op, _ in items)
        allowed = set()
        for op, av in items:
            if op == c.LITERAL:
                allowed.add(av)
            elif op == c.RANGE:
                allowed.update(range(av[0], av[1] + 1))
            elif op == c.CATEGORY:
                allowed.add(ord(self.category(av)))
        if negate:
            for b in (ord("x"), ord("Q"), ord("5"), ord(" "), 0x80):
                if b not in allowed:
                    return chr(b)
            return chr(next(b for b in range(256) if b not in allowed))
        if not allowed:
            return "x"
        printable = sorted(b for b in allowed if 0x20 < b < 0x7f)
        pool = printable or sorted(allowed)
        return chr(pool[-1] if self.more else pool[0])


def generate(pattern, flags, rng):
    """Strings for a PCRE pattern: matches (minimal and longer) and near misses."""
    pyflags = 0
    if "i" in flags:
        pyflags |= sre_constants.SRE_FLAG_IGNORECASE
    if "s" in flags:
        pyflags |= sre_constants.SRE_FLAG_DOTALL
    if "m" in flags:
        pyflags |= sre_constants.SRE_FLAG_MULTILINE
    if "x" in flags:
        pyflags |= sre_constants.SRE_FLAG_VERBOSE
    tree = sre_parse.parse(pattern, pyflags)
    out = []
    for more in (False, True):
        s = Gen(rng, more).run(tree)
        if s not in out:
            out.append(s)
    base = out[0]
    if base:
        # A near miss: one byte changed in the middle.
        k = len(base) // 2
        miss = base[:k] + chr((ord(base[k]) ^ 0x01)) + base[k + 1:]
        out.append(miss)
        out.append(base[:-1])
    return out


def hexstr(s):
    return " ".join("%02x" % (ord(ch) & 0xff) for ch in s)


def gen_pcre(args):
    rng = random.Random(1)
    cases, skipped = [], {}
    n = 0
    for name, line_no, line in db_lines(args.db, ("ldb", "ldu")):
        fields = ldb_fields(line)
        if len(fields) < 4:
            continue
        for sub in fields[3:]:
            if not is_pcre(sub):
                continue
            n += 1
            if args.limit and len(cases) >= args.limit:
                break
            try:
                offset, trigger, pattern, flags = split_pcre(sub)
            except ValueError:
                skipped["split"] = skipped.get("split", 0) + 1
                continue
            try:
                samples = generate(pattern, flags, rng)
            except Exception:
                skipped["generate"] = skipped.get("generate", 0) + 1
                samples = []
            case = ["case realpcre-%d" % n,
                    "# %s:%d %s" % (name, line_no, fields[0]),
                    "ldb Diff.RealPcre.%d;Engine:81-255,Target:0;0&1;54524947;0/%s/%s" % (n, pattern, flags)]
            for s in samples:
                if len(s) > 60000:
                    continue
                case.append('sample bin "TRIG " x"%s" " " bin => ?' % hexstr(s))
                case.append('sample bin "TRIG\\n" x"%s" "\\n" bin => ?' % hexstr(s))
            case.append('sample bin "TRIG filler" bin => ?')
            cases.append("\n".join(case))
    with open(args.out, "w") as f:
        f.write("# PCRE subsignatures of the ClamAV databases, isolated (tools/diff/realdb.py).\n\n")
        f.write("\n\n".join(cases) + "\n")
    print("realdb.py: %d PCRE subsigs, %d cases, skipped %s" % (n, len(cases), skipped))


def gen_bytecompare(args):
    cases = []
    n = 0
    for name, line_no, line in db_lines(args.db, ("ldb", "ldu")):
        fields = ldb_fields(line)
        for sub in fields[3:]:
            if not is_byte_compare(sub):
                continue
            n += 1
            inner = sub[sub.index("(") + 1:-1]
            off, opts, cmps = inner.split("#")
            case = ["case realbc-%d" % n, "# %s:%d %s" % (name, line_no, fields[0]),
                    "ldb Diff.RealBc.%d;Engine:81-255,Target:0;0&1;54524947;0(%s)" % (n, inner)]
            width = int("".join(ch for ch in opts if ch.isdigit()) or "1")
            dist = int(off[2:], 0)
            values = set()
            for c in cmps.split(","):
                v = int(c[1:], 0)
                values.update((max(v - 1, 0), v, v + 1))
            kind = opts[0]
            for v in sorted(values):
                if kind == "i":
                    big = "b" in opts[1:2]
                    data = v.to_bytes(width, "big" if big else "little", signed=False) if v < 256 ** width else b"\xff" * width
                elif kind == "d" or (kind == "a" and v < 10 ** width):
                    data = str(v).rjust(width, "0").encode()[:width]
                else:
                    data = ("%x" % v).rjust(width, "0").encode()[:width]
                if off.startswith(">>"):
                    body = 'x"54 52 49 47" %d*"." x"%s"' % (max(dist - 4, 0), hexstr(data.decode("latin-1")))
                else:
                    body = 'x"%s" %d*"." x"54 52 49 47"' % (hexstr(data.decode("latin-1")), max(dist - width, 0))
                case.append("sample bin %s bin => ?" % body)
            cases.append("\n".join(case))
    with open(args.out, "w") as f:
        f.write("# Byte-compare subsignatures of the ClamAV databases (tools/diff/realdb.py).\n\n")
        f.write("\n\n".join(cases) + "\n")
    print("realdb.py: %d byte-compare subsigs" % n)


def yara_regexes(paths):
    """(pattern, flags, origin) for every regex string in the YARA files under `paths`."""
    import re as _re
    rx = _re.compile(r'^\s*\$\w*\s*=\s*/((?:\\.|[^/\\])+)/([is]*)(.*)$')
    for root in paths:
        files = [root] if os.path.isfile(root) else [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs]
        for path in sorted(files):
            if not path.endswith((".yar", ".yara")):
                continue
            with open(path, "rb") as fh:
                for n, line in enumerate(fh.read().decode("latin-1").splitlines(), 1):
                    m = rx.match(line)
                    if not m:
                        continue
                    flags = m.group(2)
                    if "nocase" in m.group(3) and "i" not in flags:
                        flags += "i"
                    yield m.group(1), flags, "%s:%d" % (os.path.relpath(path, root) if os.path.isdir(root) else path, n)


def subjects(pattern, flags, rng):
    try:
        gen = generate(pattern, flags, rng)
    except Exception:
        gen = []
    out = []
    for g in gen:
        out += [g, "ab " + g + " cd", g + "\n", "\n" + g, g + g]
    out += ["", "filler text 0123456789", "\x00\xff" * 8]
    return out


def gen_corpus(args):
    rng = random.Random(1)
    lines = []
    n = 0
    if args.db:
        for name, line_no, line in db_lines(args.db, ("ldb", "ldu")):
            fields = ldb_fields(line)
            for sub in fields[3:]:
                if not is_pcre(sub):
                    continue
                try:
                    _, _, pattern, flags = split_pcre(sub)
                except ValueError:
                    continue
                n += 1
                lines.append("P %s %s clamav" % (flags or "-", pattern.encode("latin-1").hex()))
                for subj in subjects(pattern, flags, rng):
                    lines.append("S " + subj.encode("latin-1", "replace").hex())
    if args.yara:
        for pattern, flags, origin in yara_regexes(args.yara):
            n += 1
            lines.append("P %s %s yara" % (flags or "-", pattern.encode("latin-1").hex()))
            for subj in subjects(pattern, flags, rng):
                lines.append("S " + subj.encode("latin-1", "replace").hex())
    with open(args.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("realdb.py: %d patterns in the E13 corpus" % n)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pcre")
    p.add_argument("--db", action="append", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--limit", type=int, default=0)
    b = sub.add_parser("bytecompare")
    b.add_argument("--db", action="append", required=True)
    b.add_argument("--out", required=True)
    c = sub.add_parser("corpus")
    c.add_argument("--db", action="append", default=[])
    c.add_argument("--yara", action="append", default=[])
    c.add_argument("--out", required=True)
    args = ap.parse_args()
    return {"pcre": gen_pcre, "bytecompare": gen_bytecompare, "corpus": gen_corpus}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
