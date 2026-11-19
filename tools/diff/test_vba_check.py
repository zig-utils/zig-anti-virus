"""CLI contract tests. Fake external readers/scanners isolate gate policy from engines."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).with_name("vba_check.py").resolve()


class VbaCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        package = self.root / "oletools"
        package.mkdir()
        (package / "__init__.py").write_text("")
        (package / "olevba.py").write_text('''
from pathlib import Path
class VBA_Parser:
    def __init__(self, path): self.path = path
    def detect_vba_macros(self): return True
    def extract_macros(self): yield self.path, "VBA/Module1", "Module1.bas", Path(self.path).read_bytes()
    def close(self): pass
''')
        self.scanner = self.root / "scanner"
        self.scanner.write_text("#!" + sys.executable + '\n' + '''
import os, pathlib, sys, time
mode = os.environ.get("FAKE_MODE", "")
if sys.argv[1] == "vba":
    if mode == "extract-error":
        print("deliberate scanner error", file=sys.stderr)
        sys.exit(2)
    if mode == "extract-timeout": time.sleep(10)
    for f in sys.argv[2:]: print(f + "\\tModule1\\t" + pathlib.Path(f).read_bytes().hex())
    sys.exit(0)
if mode == "timeout": time.sleep(10)
if mode == "error":
    print("deliberate scanner error", file=sys.stderr)
    sys.exit(2)
is_zav = sys.argv[1] == "scan"
db = sys.argv[sys.argv.index("--sigs" if is_zav else "-d") + 1]
files = sys.argv[sys.argv.index("--") + 1:] if is_zav else sys.argv[sys.argv.index("-d") + 2:]
sigs = [line.split(":") for line in pathlib.Path(db).read_text().splitlines() if line]
found = False
for f in files:
    if mode == "missing": continue
    hits = [s[0] for s in sigs if bytes.fromhex(s[3]) in pathlib.Path(f).read_bytes()]
    if (mode == "miss" and not is_zav) or (mode == "zav-miss" and is_zav): hits = []
    if mode == "extra" or (mode == "clam-extra" and not is_zav): hits.append("Diff.Unexpected")
    if mode == "limited" and is_zav:
        print(f + ": LIMITED(depth)")
        continue
    for name in hits: print(f + ": " + name + ("" if is_zav else ".UNOFFICIAL") + " FOUND")
    if not hits: print(f + ": OK")
    found = found or bool(hits)
sys.exit(int(found))
''')
        self.scanner.chmod(0o755)
        self.sample = self.root / "one.doc"
        self.sample.write_bytes(b'"abcdefghijklmnop"')

    def run_check(self, mode="", known=None, paths=None, timeout="2"):
        cmd = [sys.executable, str(CHECK), "--zav-diff", str(self.scanner),
               "--clamscan", str(self.scanner), "--work", str(self.root / "work"),
               "--timeout", timeout]
        if known:
            cmd += ["--known", str(known)]
        cmd += [str(p) for p in (paths or [self.sample])]
        return subprocess.run(cmd, capture_output=True, text=True,
                              env=dict(os.environ, PYTHONPATH=str(self.root), FAKE_MODE=mode))

    def known(self):
        digest = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        path = self.root / "known.json"
        path.write_text(json.dumps({"differences": [{"file": "one.doc", "sha256": digest,
            "clamscan": [], "zav": ["Diff.Macro." + digest]}]}))
        return path

    def test_exact_detection_passes_and_same_basenames_remain_separate(self):
        other = self.root / "nested" / "one.doc"
        other.parent.mkdir()
        other.write_bytes(b'"zyxwvutsrqponmlk"')
        result = self.run_check(paths=[self.sample, other])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("2 detected by both", result.stdout)

    def test_known_miss_is_accepted_but_new_or_stale_misses_fail(self):
        self.assertNotEqual(self.run_check("miss").returncode, 0)
        known = self.known()
        result = self.run_check("miss", known)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 known differences", result.stdout)
        result = self.run_check(known=known)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STALE", result.stdout)
        self.sample.write_bytes(b'"abcdefghijklmnopq"')
        result = self.run_check("miss", known)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MACRO", result.stdout)
        self.assertIn("STALE", result.stdout)

    def test_known_miss_never_accepts_extra_detections(self):
        for mode in ["extra", "clam-extra"]:
            result = self.run_check(mode, self.known())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Diff.Unexpected", result.stdout)
        self.assertNotEqual(self.run_check("zav-miss", self.known()).returncode, 0)

    def test_scanner_failure_and_timeout_fail_with_diagnostics(self):
        for mode in ["error", "timeout", "extract-error", "extract-timeout"]:
            with self.subTest(mode=mode):
                result = self.run_check(mode, timeout="0.2")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("deliberate scanner error" if mode.endswith("error") else "timed out", result.stderr)

    def test_missing_results_and_limits_fail(self):
        for mode in ["missing", "limited"]:
            with self.subTest(mode=mode):
                result = self.run_check(mode)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
