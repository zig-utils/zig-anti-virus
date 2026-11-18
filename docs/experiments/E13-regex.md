# E13: zig-regex byte mode against PCRE2

Issue: zig-utils/zig-anti-virus#36. Harness: `tools/diff/e13.zig` (`zig build e13 -- CORPUS`), with
the corpus written by `tools/diff/realdb.py corpus`. The differential workflow's `realdb` job runs
it on every push against the current databases and the public rule set below.

## Setup

- Patterns: every PCRE subsignature of ClamAV main 63 and daily 28187 (1223), and every regex string
  of the Yara-Rules public rule set (github.com/Yara-Rules/rules, 366). Nothing derived from either is
  committed.
- zav side: each pattern compiled exactly as zav compiles it (`compile.cdb.compileRegex`: zig-regex
  0.3.1 byte mode, flags `i s m x` mapped, a leading `(?i)`-style option group taken as the compile
  flag), searched with `Program.findFrom` from offset 0.
- PCRE2 10.49 (Linux CI: the distribution's libpcre2), no UTF, the same flags plus `E`
  (DOLLAR_ENDONLY) and `U` (UNGREEDY), match limit 1,000,000.
- Subjects: for each pattern, strings generated from its parse tree (a minimal match, a longer one,
  near misses with one byte changed and the last byte cut), each also embedded in text, followed by a
  newline, preceded by one and doubled; plus fixed filler. 31,140 subjects.

## Results

| | patterns | compile in both | PCRE2 only | subjects | agree | same start, other end | disagree | limited |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ClamAV PCRE | 1223 | 1159 | 64 | 23,867 | 23,789 | 71 | 6 | 1 |
| YARA regex | 366 | 366 | 0 | 7,273 | 7,223 | 8 | 42 | 0 |

zig-regex never compiles a pattern PCRE2 refuses. Separately, the isolated libclamav differential
(`realdb.py pcre` with `clamav.py`) runs all 1223 PCRE subsigs through clamscan: the 1159 zav compiles
agree with libclamav on all 9,867 generated samples (4,140 of them matches).

## Every difference, and what happens to it

1. **64 patterns PCRE2 compiles and zig-regex refuses.** Named groups with backreferences
   (`(?P<n>..)..(?P=n)`, 41 reported as `regex_syntax` because zig-regex does not parse the `(?P<`
   and `(?P=` spellings), numbered backreferences, lookbehind, lookahead, atomic groups and scoped
   inline modifiers (`regex_unsupported`). **Unsupported, with a reason:** these need a backtracking
   matcher, and zav runs only allocation-free byte-mode programs with step budgets. Each refusal is a
   named reason in the coverage report; the signatures are counted, never silently dropped.
2. **79 subjects with the same match start and a different end.** zig-regex's Thompson programs
   report leftmost-longest ends; PCRE is leftmost-first. Starts and the match/no-match decision agree,
   so a signature's verdict is the same except for PCRE `/g` counts of patterns like `a|aba`
   (`pcre-global` in tests/differential/cases/pcre.case, listed in known.txt). **Pending upstream:**
   a leftmost-first mode is being added to zig-regex; zav adopts it with the release that ships it.
3. **6 ClamAV subjects: `$` before a final newline.** PCRE's `$` (without `E` or `m`) also matches
   before a newline that ends the subject; zig-regex's matches only at the end. Affects
   `/<\/svg>$/`-style subsigs on data ending in LF. **Unsupported for now, listed:** known.txt
   `pcre-basic s8`; zig-regex needs an opt-in PCRE-dollar flag (zig-utils/zig-regex#51).
4. **42 YARA subjects.** Two causes:
   - `{,n}` (empty lower bound): yara and PCRE2 10.43+ read `{0,n}`, zig-regex reads it literally,
     so `/\/gate.php\?token=.{,10}&host=/` and similar never match. **Upstream:** zig-regex needs
     `{,n}` (zig-utils/zig-regex#51); until then these YARA strings miss.
   - `^`/`$` around newlines: PCRE2 matches `$` before a final newline where yara does not. Here
     zig-regex agrees with yara (checked with yara-python), so this is a PCRE2-versus-yara
   difference, not a zav one.
5. **1 limited search.** One subject hit zig-regex's step budget; zav reports `regex_steps` as a
   limit event, never a clean verdict.

## Decisions

- zav keeps zig-regex byte mode for PCRE subsigs and YARA regexes; every pattern it cannot run
  exactly is refused with a reason rather than approximated.
- The one semantic difference that changes verdicts on real signatures today is the `$`-before-LF
  case (six generated subjects across 1223 subsigs); the `/g` count difference needs alternations
  whose alternatives overlap, which no generated subject of the real subsigs exposed.
