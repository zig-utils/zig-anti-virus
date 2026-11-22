# Clean-room notes

zav reproduces some of libclamav's normalised forms byte for byte, because ClamAV signatures
are written against them. Those parts are written black-box: from what libclamav *outputs*
for inputs we choose, never from ClamAV's source. This file records the method and the
observations, one section per normaliser, so the rules in the code can be traced to evidence.

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
