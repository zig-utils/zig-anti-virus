# Clean-room notes

zav reproduces some of libclamav's normalised forms byte for byte, because ClamAV signatures
are written against them. Those parts are written black-box: from what libclamav *outputs*
for inputs we choose, never from ClamAV's source. This file records the method and the
observations, one section per normaliser, so the rules in the code can be traced to evidence.

## Rules for this work

Every part below was (re)written under these rules:

1. No ClamAV source code is opened, fetched or searched (libclamav, the clamav repository,
   tarballs, mirrors, code search), and no third-party write-up that quotes or paraphrases it.
2. Code written after reading ClamAV source is not read either: for the earlier zav code that
   this work replaced, only its public interface (lines starting with `pub`, and field names,
   extracted mechanically with grep) was looked at, plus its call sites in other files, and
   none of its git history.
3. Allowed sources: public format specifications (WHATWG HTML and its entities.json, HTML 4.01,
   RFC 2397, Unicode/UTF-8/UTF-16, ECMAScript, MS-CFB), ClamAV's user documentation at
   docs.clamav.net (signature format, target types, file types, HandlerType), and black-box
   observation of the official ClamAV 1.5.4 binaries: running `clamscan` on inputs we generate
   (`--leave-temps --tempdir`, `--debug --gen-json`, `--allmatch` with signatures we write)
   and reading its output files and verdicts, never its code.

## The November 2026 rewrite

The HTML normaliser and its named-reference table, the file typing in `src/fmt/ftm.zig`, the
text normaliser's rounds, and the per-layer scan model in `src/engine/layerscan.zig` (with the
walker's re-typing and normalisation in `src/fmt/scan.zig`, and HandlerType) had been written
by an earlier session after reading libclamav. They were deleted (commit "chore: remove
ClamAV-derived implementations for a clean-room rewrite") and rewritten by a session that had
not seen ClamAV's source or those implementations, following the rules above.

What that session did see of the old code, recorded so it can be weighed: the `pub` lines and
field names of the deleted files (including public constant values such as an 8191-byte chunk
and a 128 KiB window); call sites in files that stayed, with their comments (a call-site comment
in `src/fmt/scan.zig` said text and binary data are re-typed by embedded type magics in their
first 1024 bytes and HTML is not matched raw; one in `src/compile/ldb.zig` said a HandlerType
signature matches again in the re-scan and reports; one in `tools/diff/zav_diff.zig` said the
text rounds are page dependent); test names and two test bodies in `src/compile/ftm_build.zig`
that exercised the old typing; and the harness docstrings in `tools/diff/` (which mention an
8191-byte chunk). Every such statement was treated as a hypothesis and confirmed or replaced by
the observations below; none was used as a rule without one.

### Harness

Probes were Python scripts in a scratch directory (not committed except where noted): each
writes a set of files, runs `clamscan --bytecode=no` over the directory once, and reads either
the root `FileType` from `--debug --gen-json`, the files `--leave-temps` keeps
(`html-tmp.*/nocomment.html`, `notags.html`, `javascript`, the text form `clamav-*.tmp`), or
`--allmatch` verdicts for signatures written for the probe. zav's side is `zav-diff types`,
`zav-diff normalize` and `zav-diff scan`. Differences in random documents were shrunk with
batched delta debugging (every candidate run through clamscan) until one small input showed
one rule, which was then checked with a handful of hand-written probes.

## File typing (`src/fmt/ftm.zig`, `src/fmt/subtype.zig`)

Observations, all with the official `daily.ftm` loaded and an otherwise empty database:

- Text test, from the first 1024 bytes (a byte at offset 1024 changes nothing; at 1023 it
  does). All 256 byte values inserted into ASCII text: 07 08 09 0A 0C 0D 1B, 20-7E and every
  byte from 80 keep `CL_TYPE_TEXT_ASCII`; the others (00-06, 0B, 0E-1A, 1C-1F, 7F) do not.
  UTF-8 text, with or without a BOM, stays ASCII; `CL_TYPE_TEXT_UTF8` was never produced.
- Not ASCII: `FF FE` first gives UTF16LE whatever follows (zeros, random bytes); `FE FF` gives
  UTF16BE. Otherwise big-endian 16-bit units from offset 2 decide (the unit at offset 0 is
  never looked at): a unit below 0x80 that is not an ASCII text byte (0000, 0001, 000B, 001F,
  007F) or FFFE makes binary data; any other unit (0009, 0041, 0080, D800 unpaired, DC00,
  FFFF, FEFF) keeps UTF16BE. A trailing odd byte is not looked at. Random data is therefore
  usually UTF16BE.
- Fixed magics (type 0): when several match, the last in the file wins: `[aliases]` matches
  both the mirc-ini (SCRIPT) and TAR-POSIX-CVE (POSIX_TAR) lines and gives POSIX_TAR; MZ with
  `ustar` at 257 gives POSIX_TAR; GIF with `ustar` gives GIF; GPT beats MZ and tar; HWPOLE2
  beats OLE2.
- Body magics (type 1) re-type text and binary data (and GIF, for HTML) when they lie wholly
  in the first 1024 bytes: HTML at offset 1018 (ends at 1024) re-types binary data, at 1019 not;
  ranged magics (the 0,1024 mail magics) need their start in range and their end in the head
  for binary data. Fifteen embedded types were placed pairwise (each pair in both orders, in
  binary data and in ASCII text, 420 files) and the results fitted exactly by the combination
  in `Combiner`: ranked low types (SIS and Mach-O universal < PDF < Java, pyc, LHA < MBR < HTML
  < MAIL < Excel/Word/HWP XML and APM), self-extractor markers that leave the base type,
  MSEXE replaced by anything after it, AUTOIT/NULSFT/ISHIELD_MSI, XDP/MHTML, IGNORED that is
  never replaced; order is the order matches end. XDP or MHTML at offset 0 combine like
  installers, UDF at 0 like a high low type, UDF elsewhere in the head like a top type.
- An IGNORED magic in the head (the PDF-image magic at 0..128) stops all whole-file re-typing,
  whatever the base type.
- Whole file: ISO 9660 anywhere (tested up to 5 MB), UDF in its range and DMG at EOF-512
  re-type nearly every base type (matrix of 50 fixed-magic base types against every body
  magic): not GZ, IGNORED, ZIP, TNEF, POSIX_TAR, CPIO_OLD, XZ or HTML, and DMG not MSEXE, ELF
  or Mach-O; the last such magic in the file wins. XDP and MHTML anywhere re-type text and
  binary data (the first wins) and win over HTML. In ASCII text only, the head combination is
  run again over the whole file and applies when it yields HTML or MAIL (HTML at 5 MB still
  re-types; an installer or self-extractor magic after it cancels it).
- OLE2 sub-types: streams named WordDocument, Workbook, PowerPoint Document (case ignored;
  storages and "Book" do not count) give MSWORD, MSXL, MSPPT; with several, the last one in a
  walk that visits an entry, its children, its right sibling, then its left sibling (directory
  trees built by a small MS-CFB writer with permuted sibling links).
- OOXML sub-types from local file header names (`word/`, `xl/`, `ppt/` prefixes, exact
  `Contents/content.hpf`): headers found by searching for the signature after the previous
  name (a signature inside member data counts; data descriptors and junk do not matter), the
  first three members not under `docProps/` (`d0 d1 xl/` types, `d0 d1 d2 xl/` does not), a
  header start of at most 30221 bytes (found by bisection: 30221 types, 30222 does not, for any
  name length and file size), and no member limit once `[Content_Types].xml` is among those
  looked at in an archive that has an end of central directory record.
- Binary data whose first 512 bytes are a tar header with a valid unsigned checksum (signed
  sums do not count) is OLD_TAR, before body magics are considered.

Known differences: two XDP/MHTML magics followed by a self-extractor marker in the same head
(the first document type wins in clamscan); a disk image magic inside a fully formed RAR or
PDF header; one OLE2 file that clamscan leaves as MSOLE2.

## Text normalisation (`src/fmt/text_norm.zig`)

- All 256 byte values between letters: 09-0D and 20 become one collapsed space, `A-Z` lower
  case, 21-7F kept, everything else dropped, and a dropped byte does not end a whitespace run
  (`abc \x01 def` gives `abc def `). UTF-16 text is normalised the same way (its zero bytes are
  dropped).
- Rounds: on large files a whitespace run sometimes yields two spaces. Files built so that
  every page boundary falls inside a whitespace run showed the restart points as page
  multiples, every 32 to 60 pages depending on the output ratio: a round reads whole pages
  while its output plus one more page fits in 128 KiB (checked on seven ratios). On Apple
  silicon the page is 16 KiB, so rounds are counted in 16 KiB pages; on x86-64 Linux 4 KiB.

## HTML normalisation (`src/fmt/html_norm.zig`, `src/fmt/html_named_refs.zig`)

- Chunks: a single space at offsets 8191, 16382, 24573 of a document without other
  whitespace is dropped, and with periodic whitespace the drop points move: a chunk is 8191
  bytes, ends after its last whitespace byte when the byte after it is not whitespace, and its
  leading whitespace is dropped (in both forms). A newline does not end a chunk.
- nocomment: lower case; whitespace runs to one space written before the next character
  (none at the end of the input, none right after a tag or declaration, written at once before
  a declaration); CR and NUL dropped; other control bytes kept; `<!...>` dropped up to the next
  `>` (`<!-- a > b -->` ends at the first `>`); `<?...>` kept as a tag.
- Tags: whitespace after `<` skipped; `=` inside the tag name belongs to the name; whitespace
  around `=` dropped; values requoted with `"`; a quote of either kind inside a value written
  as `"`; a closing quote followed by a space unless the value held whitespace or `>`; in a
  quoted value a second whitespace run leaves the value and a `>` after whitespace ends the
  tag (probes over every combination of quote, leading `>`, whitespace, `<i>` in values).
- References: names from `html_named_refs.zig` (generated, below) decoded only with `;` (and
  at the end of the input); numeric references with or without `;`, `x` switching to hex while
  the value is still 0, digits until the value would overflow 64 bits; code points below FF as one byte
  (lower-cased only after `;`), U+3002 U+FE52 U+FF0E as `.`, others as `&#xhhhh;`, values over
  FFFF reduced to 16 bits; unknown names written back in lower case (case-sensitive table).
- notags: text only, every tag and reference a space, spaces collapsed; a reference there runs
  over letters, digits, `-`, `_`, `:` (at most 1024 bytes); the `href` of an `a` and the `src` of
  an `img` are written in their own case when the next byte arrives.
- High bytes come in groups of three, each written when the byte after it arrives (a last
  group is dropped at the end of the input): in nocomment as they are, in notags as the
  first, the second and the second again (a group of two as the first twice, one as a NUL),
  without changing the space state; a group that is U+3002, U+FF0E or U+FE52 in UTF-8 is `.`, and
  Big5 A1 43, A1 44, A1 4F are `.` followed by a NUL when another byte follows (a probe over all
  24,448 pairs of a high byte and a second byte). In attribute values the bytes wait across
  tags and text for the next value byte.
- `script` and `style` content: all whitespace removed, `'` written as `"`, references decoded
  except inside `<!...>`, until `</script` (or `</style`, or `</script` for style); the byte after
  a `<` (whitespace skipped) is written as it is and cannot start the end tag. Each script is
  handed to the JavaScript normaliser with its end tag.
- Data URIs (RFC 2397): a value starting with lower-case `data:` is written as `data` and the
  rest swallowed (to the closing quote or `&` when quoted, to whitespace or `>` when not, a `%`
  taking the next two bytes), unless the tag ends right after `data:`.
- Named references: `tools/diff/html_named_refs.py` writes every candidate name from the
  WHATWG `entities.json` and the W3C ISO 8879 and HTML/MathML sets (2,216 names) into one
  document and reads back what clamscan decodes: 743 names, with the code point clamscan
  prints for each. The table is that observation.

Not reproduced (known differences): some combinations of data URIs and references, a `'` quote
whose value starts with whitespace inside a tag named `'`, the notags capture of a quoted value
holding a NUL reference, and the tag text clamscan writes in notags after some script end tags.

## Scan model (`src/engine/layerscan.zig`, `src/fmt/js_file.zig`)

From `--allmatch` verdicts of signatures for every target type over files of each type:

- Text (ASCII and both UTF-16 forms): raw with target 0; the text form with targets 7 and 0.
- HTML: never raw (target-0 signatures on the original case or spacing never match); the
  nocomment and notags forms with targets 3 and 0 (an `href` in its original case matches
  target 3, so notags is matched); the `javascript` file with targets 3 and 0, and again as a
  text child with targets 7 and 0.
- PE with 1, OLE2 with 2, mail with 4, GIF/PNG/JPEG/TIFF/BMP with 5, ELF with 6, Mach-O with 9,
  PDF with 10, SWF with 11, Java with 12; ZIP, RTF, PostScript with 0 only.
- HandlerType: a matching signature does not alert; the file is scanned again as that type
  (re-scanned as HTML: normalised forms matched, raw not), and in a scan as that type the
  signature alerts (a HandlerType equal to the file's own type alerts at once).

### Parity after the rewrite (macOS arm64, ClamAV 1.5.4, November 2026)

| Area | Corpus | Byte-identical or same verdict |
| --- | --- | --- |
| File typing (`FileType`) | 12,000 files of the B1, B2, S1, T1 and dl corpora | 11,999 |
| File typing | 14,294 generated probes (bytes, BOMs, windows, magic mixes) | 14,292 |
| Text form | 1,355 text files (Python stdlib sources, four seam files of up to 1.2 MB) | 1,355 |
| HTML nocomment | 196 system HTML files | 196 |
| HTML notags | 196 system HTML files | 195 |
| HTML nocomment | 600 `gen_html.py` stress documents | 510 |
| HTML notags | 600 `gen_html.py` stress documents | 570 |
| P4.21 gate (`realdb.py gate`, whole main and daily) | 35,309 samples | 35,309 |

The stress documents that still differ combine constructs listed under "Not reproduced".

## JavaScript normaliser (`src/fmt/js_norm.zig`)

### Method

- Inputs are pages `<html><body><script>SCRIPT</script></body></html>`: one construct per probe
  page, random token mixes, and every `.js` member of the B1 corpus wrapped the same way
  (`tools/diff/js_goldens.py pages`).
- The official ClamAV release (`tools/diff/install_clamav.sh`, the `clamscan` binary only) scans
  each page with an empty signature set and `--leave-temps`; the `javascript` file it leaves
  is the golden (`js_goldens.py record`). `js_goldens.py compare` checks zav-diff against them.
- Differences are reduced by delta debugging over the script text, re-running clamscan on each
  candidate, until one small input shows one rule. The rule is then confirmed with a handful of
  hand-written probes around it.
- No ClamAV source, tests or history were read for this work.

Result (Nov 2026): js_norm fed each probe or corpus script (plus the end tag that follows it in
the page) matches 447 of 461 probe pages and 656 of 663 corpus pages byte for byte. Pages whose
script the HTML layer cuts differently, and pages with more than one script, are left to the
HTML side.

### The `javascript` file

- It holds `<script>`, the normalised script, and `</script>` unless the normalised text already
  ends with it. The script's own end tag reaches the normaliser and is normalised like the rest
  (`</script>`, or `</n000>` when a declaration is pending), so a well-formed script's file ends
  with exactly one `</script>`.
- Bytes are ASCII-lowercased; NUL is written as 0x01 and \t..\r as a space.
- Parentheses still open when the script ends are closed with one `)` each, after the end tag:
  `x=f((a);` gives `<script>x=f((a);</script>)</script>`.

### Tokens and spacing

- Tokens are written with no separator except one space between two word-like tokens (names,
  keywords, numbers). Punctuation is never spaced: `a+ +b` gives `a++b`, `a- -b` gives `a--b`.
- Separators: bytes 0x01-0x20, `#`, `@`, the backtick, 0x7f and every byte from 0x80 (so
  UTF-8 in names splits them: `var é=1` gives `var=1`). NUL vanishes: `a\0b` gives `ab`.
- Numbers: decimal integers are reprinted as 32-bit signed values; `0x10` is `0` and the word
  `x10`; a fraction is printed with six significant digits.
- There are no regular expression literals: `/` is always an operator and a pattern's
  characters are ordinary tokens, so a quote inside a pattern starts a string
  (`y=/A"B/;` runs a string to the end of the script).
- `/* */` comments vanish. A `//` comment ends at the first space or line feed (not at tab, CR,
  VT or FF), so `// comment with words` keeps `comment with words` as tokens and `//c\n` vanishes.

### Backslashes outside strings

- A backslash ends the word before it and the words on either side are separate names:
  `var a,b;x=a\b;` gives `x=n000 n001`.
- It leaves a space before a following word or number that would not get one (`(\b` is
  `( b`, `a\b` is `a b`, `a\(b` is `a(b`), and a space whatever follows when it comes after a
  number (`1\)` is `1 )`, `1\2` is `1  2`), after white space that follows a word (`a \)` is
  `a )`), or before another backslash (`(\\(` is `( (`).
- Right after a `.` it leaves nothing, and the following word is no longer a property:
  `a.\nb` is `a.nb`, and `var d;x=.\d` renames d.
- `\u` stays in the word as a backslash, the `u` dropped: `x=aAb` is `x=a\0041b`.

### Strings

- Single- and double-quoted strings are written double-quoted, their content as decoded, with
  quotes and backslashes not escaped (`'say "hi"'` is `"say "hi""`).
- A string ends at the first quote that is not right after a backslash, even an escaped one:
  `x='\\';y=1;'z';` is one string `\';y=1;` followed by `z` and a new string. A line break does
  not end a string; the end of the script does (closed with `"`, no space).
- Escapes: `\n \r \t \b \f \v`; `\0` is NUL; there are no octal escapes (`\101` is `101`,
  `\9` is `9`); any other escaped character, a line break included, stands for itself.
- `\xHH` is the byte HH (not UTF-8: `\xe9` is 0xE9); two non-hex characters give 0xFF.
  `\uHHHH` is UTF-8, a lone surrogate encoded on its own (`\uD800` is ED A0 80); four non-hex
  characters give U+FFFF (`\u{41}` is U+FFFF).
- An escape cut off by the closing quote leaves a backslash, and after `\u` the digits read:
  `'\x4'` is `"\"`, `'\u00'` is `"\00"`.

### Folding

- `"a"+"b"` folds to `"ab"` first. Then `unescape(STRING)` folds to its decoded string, which
  folds no further (`'a'+unescape('%62')+'c'` gives `"a"+"b"+"c"`, `unescape(unescape('%2541'))`
  gives `unescape("%41")`). Not after a `.`.
- `eval(STRING)` (or `eval(unescape(STRING))`) is replaced by the tokens of its code, lexed by a
  lexer of its own, and a `;` right after the call goes with it. A word or number the code
  leaves unfinished is not written but continued by the next eval's code:
  `eval('a=1');b;x=eval('c')+1;eval(unescape('d=2;'));` gives `a=b;x=1+1;cd=2;`.
  Not `EVAL`, not `window.eval`, not with two arguments.
- A call cut off by the end of the script (`unescape('...` with no `)`) still folds.

### Names

- Keywords (never renamed): the ECMAScript 3 reserved and future reserved words: abstract
  boolean break byte case catch char class const continue debugger default delete do double else
  enum export extends false final finally float for function goto if implements import in
  instanceof int interface long native new null package private protected public return short
  static super switch synchronized this throw throws transient true try typeof var void volatile
  while with. `let`, `yield`, `async`, `await`, `of` and `undefined` are names.
- Declarations get numbers n000, n001, ... in declaration order. Every use of a name refers to
  its own scope's entry; a redeclaration takes a new number for all uses in the scope, earlier
  ones too (`var a;var b;var a;` gives `var n002;var n001;var n002;`), and a use before the
  declaration is renumbered with it (`a=1;var a;` gives `n000=1;var n000;`, object keys
  included). When a function ends, a name it never declared refers to the enclosing scope's
  entry (`function f(){b=1}var b;` renames b inside f). The script's end ends open functions.
  A name no scope declares keeps its spelling.
- Only `function` makes a scope (blocks and arrows do not). It runs from the keyword to the
  `}` matching the first `{` after it; a `}` before any `{` ends it at once. The function's
  name is declared in its own scope (`f(a);function f(a){}` leaves the first f alone).
- `var` declares the next name, waiting across any tokens, keywords included, and across a `;`
  nested in `{` or `[` deeper than its function. After a name, `,` declares the next one only
  at its function's `{` nesting and not inside a `[` opened since the last name: `var a=[b,c],d`
  declares a and d, and inside a function body only the first name of a list is declared
  (`function f(){var a,b}` leaves b). A `;` at that nesting ends the list.
- Function headers: `function` and the `(` after the name each make the next name a
  declaration until a `{` or `;`; `)` changes nothing (`function()n` declares n). Once a
  parameter is declared, a `,` outside the body's braces and the header's `[` makes the next
  name one too, and that one survives a `{` (`function(r,{s,t` declares r and s, not t;
  `function({u` declares nothing). After `=` nothing is declared until the next `,`
  (`function f(a=g(b,c))` declares a and c). `var` ends the header.
- A call that may fold is seen by the declarations as it comes, except its closing `)`:
  `var unescape('%41'),b` numbers unescape (n000) and b (n001), and in
  `function f unescape('a') b` the `(` opens the parameters, so b is one.
- Braces never nest below zero (`}{var o,b` does not declare b), nor do brackets.

### Not reproduced

- Dean Edwards packer calls (`eval(function(p,a,c,k,e,d){...}('...',n,n,'...'.split('|'),0,{}))`)
  are unpacked by libclamav; zav leaves them.
- `eval` of code that is only punctuation, and some `eval` sequences after an unfinished
  number, are not expanded by libclamav; zav expands them.
- A few runs of two or three backslashes after a number or a `.` differ by a space.
