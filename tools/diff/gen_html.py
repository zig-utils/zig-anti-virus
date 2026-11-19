#!/usr/bin/env python3
"""HTML stress documents for norm.py: the quirks of libclamav's normaliser, in random mixes.

  gen_html.py OUTDIR [--count N] [--seed S]

Each document strings together tokens chosen to reach every state of htmlnorm.c: quoted and
unquoted values with spaces, quotes and backslashes inside them, references (named, numeric,
unterminated, overlong), bytes from 0x80 up in text and in values, NULs, CR/LF, comments,
scripts and styles (closed, unclosed, with tags inside), data: URIs, and runs long enough to
cross libclamav's 8191-byte chunks with and without whitespace near the cut.
"""
import argparse
import os
import random
from pathlib import Path

TOKENS = [
    b"<html>", b"<HTML LANG='en'>", b"</html>", b"<body bgcolor=#fff onload=\"go( 'a b' )\">", b"<p>", b"</p>",
    b"<a href=http://Example.com/X>", b"<A HREF='x y'>", b"<a href=\"q&amp;r\" title='t'>", b"</a>", b"<img src=Pic.PNG>",
    b"<IMG SRC=\"a b.gif\" alt=x>", b"<img>", b"<a>", b"<a href>", b"<a href=\"\">",
    b"<!-- c -->", b"<!-- a > b -->", b"<!DOCTYPE html>", b"<!>", b"<!-", b"<",  b">", b"< p >", b"</ p>",
    b"<script>", b"<SCRIPT language=javascript>", b"</script>", b"</SCRIPT >", b"</script foo>", b"<script src=x.js></script>",
    b"var A = 'x' + \"y\";", b"if (a<b) c();", b"</b>", b"<!-- in -->", b"document.write('<p>');",
    b"<style>", b"</style>", b"b { c: 'd' }", b"<style type=text/css>p{}</style>",
    b"&Agr;", b"&Acy;", b"&boxh;", b"&frac13;", b"&tdot;", b"&DotDot;", b"&apos;",
    b"&Abreve;", b"&NotEqualTilde;", b"&fjlig;",
    b"&amp;", b"&AMP;", b"&nbsp;", b"&lt;", b"&eacute;", b"&Eacute;", b"&bogus;", b"&amp", b"&", b"&#65;", b"&#x41;",
    b"&#0;", b"&#x;", b"&#65", b"&#xffff;", b"&#x3002;", b"&#300;", b"&#99999999999999999999;", b"&#X4a;", b"&x-y_z:w;",
    b"&" + b"a" * 1100 + b";",
    b"\x80", b"\xc3\xa9", b"\xe3\x80\x82", b"\xa1C", b"\xa1\xa1", b"\xff\xfe\xfd\xfc", b"\xef\xbc\x8e",
    b"<p title='\xc3\xa9'>", b"<p a=\xe9 b=c>", b"<p a=\"x\xe9\" b='y'>",
    b"\x00", b"\x00\x00\x00", b"\r\n", b"\n", b"\r", b"\t", b"   ", b"\x0b\x0c", b"\x01\x1f",
    b"<p a = b>", b"<p a=b=c>", b"<p a='b\"c'>", b"<p a=\"b'c\">", b"<p a='b\\'c'>", b"<p a=\"b\\\"c\">", b"<p a=b\\c>",
    b"<p a=\"x y z\" b=w>", b"<p a='{ x = 1 }'>", b"<p a=>", b"<p =x>", b"<p a b c>", b"<p a\t=\n'v'>",
    b"<img src=\"data:image/png;base64,iVBORw0KGgo=\">", b"<a href=data:text/plain,hi%20there%2>", b"<p x='data:a,b\"c'>",
    b"<a href=\"data:text/html;charset=utf-8,%3Cb%3E&amp;x\">", b"<p x=DATA:y>", b"<p x=data:>",
    b"Hello", b"World", b"Text with  spaces", b"UPPER lower", b"tab\there", b"'quoted'", b"\"dq\"",
]


def doc(rng):
    out = []
    size = rng.choice([200, 2000, 9000, 20000])
    while sum(len(t) for t in out) < size:
        r = rng.random()
        if r < 0.03:
            # A long run with no whitespace, so libclamav's chunk cut finds none (or only far back).
            out.append(bytes(rng.choice(b"abcXYZ<>=\"'&;#") for _ in range(rng.randint(100, 9000))))
        elif r < 0.05:
            out.append(b" " * rng.randint(1, 40))
        else:
            out.append(rng.choice(TOKENS))
        if rng.random() < 0.3:
            out.append(rng.choice([b" ", b"\n", b""]))
    return b"".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--seed", type=int, default=45)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    rng = random.Random(args.seed)
    for i in range(args.count):
        # Starting with a tag keeps libclamav's file typing on HTML.
        with open(os.path.join(args.out, "h%04d.html" % i), "wb") as f:
            f.write(b"<html><script>" + doc(rng))
    # Stable native-binary fixture independently lists all 743 supported names.
    # Keep it in the byte differential run so removed or mistyped entries fail CI.
    fixture = Path(__file__).resolve().parents[2] / "src/fmt/fixtures/html_named_refs.html"
    (Path(args.out) / "named-references.html").write_bytes(fixture.read_bytes())
    print("gen_html.py: %d documents" % (args.count + 1))


if __name__ == "__main__":
    main()
