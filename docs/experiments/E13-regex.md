# E13: zig-regex byte mode against PCRE2

Issue: zig-utils/zig-anti-virus#36. Harness: `tools/diff/e13.zig` (`zig build e13 -- CORPUS`), with
the corpus written by `tools/diff/realdb.py corpus`. The differential workflow's `realdb` job runs
it on every push against the current databases and the public rule set below.

## Setup

- Patterns: every PCRE subsignature of ClamAV main 63 and daily 28187 (1223), and every regex string
  of the Yara-Rules public rule set (github.com/Yara-Rules/rules, 366). Nothing derived from either is
  committed.
- zav side: each pattern compiled exactly as zav compiles it (`compile.cdb.compileRegexKind`:
  zig-regex 0.4.0 byte mode, leftmost-first, flags `i s m x` mapped, `U` as a leading `(?U)`, a
  leading `(?i)`-style option group taken as the compile flag), searched with `Program.findFrom` from
  offset 0; for PCRE subsigs without `E` or `m`, a `$` may also match before a final newline, as zav
  runs them (`PcreFlags.dollar_eol`).
- PCRE2 10.49 (Linux CI: the distribution's libpcre2), no UTF, the same flags plus `E`
  (DOLLAR_ENDONLY) and `U` (UNGREEDY), match limit 1,000,000.
- Subjects: for each pattern, strings generated from its parse tree (a minimal match, a longer one,
  near misses with one byte changed and the last byte cut), each also embedded in text, followed by a
  newline, preceded by one and doubled; plus fixed filler. 31,140 subjects.

## Results

| | patterns | compile in both | PCRE2 only | subjects | agree | same start, other end | disagree | limited |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ClamAV PCRE | 1223 | 1159 | 64 | 23,867 | 23,866 | 0 | 0 | 1 |
| YARA regex | 366 | 366 | 0 | 7,273 | 7,231 | 0 | 42 | 0 |

With zig-regex 0.3.1 (leftmost-longest only, `$` end-only, `U` ignored) the same corpus gave 79
subjects with a different match end and 6 ClamAV disagreements; zig-regex 0.4.0's leftmost-first
programs, `(?U)` for `U` and the final-newline search for `$` remove all of them.

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
2. **Match ends** (79 subjects under 0.3.1). zig-regex's Thompson programs reported
   leftmost-longest ends; PCRE and yara are leftmost-first. **Fixed upstream:** zig-regex 0.4.0's
   `MatchKind.leftmost_first`, which zav uses for PCRE subsigs and YARA regex strings (`.cdb` filename
   regexes are only asked whether they match and keep the default). PCRE's `U` flag, accepted but
   ignored before, now compiles as a leading `(?U)`, so ungreedy ends agree too; `U` with `g` is no
   longer refused. `pcre-global` in tests/differential/cases/pcre.case now agrees with libclamav.
3. **`$` before a final newline** (6 ClamAV subjects under 0.3.1). PCRE's `$` without `E` or `m` also
   matches before a newline that ends the subject; zig-regex's `$` is end-only, as yara's is.
   **Fixed in zav:** a PCRE subsig with such a `$` is searched a second time without the final
   newline when the first search finds nothing (or, with `g`, the larger count wins), which gives
   `$` exactly PCRE's extra position. `pcre-basic` agrees with libclamav.
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
- Every PCRE subsig zav compiles now agrees with PCRE2 on every generated subject; what is left are
  the 64 refusals (backtracking constructs, item 1) and yara's `{,n}` (item 4, zig-utils/zig-regex#51).
