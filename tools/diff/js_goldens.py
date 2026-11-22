#!/usr/bin/env python3
"""Reference outputs of libclamav's JavaScript normaliser, for the black-box parity work on
src/fmt/js_norm.zig (P5.13).

  js_goldens.py pages OUT [--probes] [--manifest M --corpus DIR] [SRC...]
                                                  write script-bearing HTML pages
  js_goldens.py record OUT PAGES...              save clamscan's `javascript` form per page
  js_goldens.py compare GOLDENS [--show N]       zav-diff normalize js against the saved forms

`pages` wraps every .js file under SRC (and every .js member a corpus manifest lists, read from
the fetched corpus directory, where files are named by SHA-256) in `<html><body><script>...</script></body></html>`,
copies .html files that contain a script, and with --probes adds generated pages that each
exercise one construct (tokens, strings, escapes, comments, numbers, regular expressions,
scoping, folding), so a difference points at one rule.

`record` runs `clamscan --leave-temps` on each page (no signature matches) and keeps the
`javascript` file libclamav wrote, as OUT/<name>.html and OUT/<name>.js. Run it where the official
ClamAV release is installed (.github/workflows/js-goldens.yml). Only outputs are kept; no ClamAV
source is read or copied.

`compare` prints how many pages zav reproduces byte for byte and the first differences.
"""
import argparse
import glob
import hashlib
import os
import random
import shutil
import subprocess
import sys


def page(script):
    return b"<html><body><script>" + script + b"</script></body></html>\n"


PROBES = [
    # Tokens and spacing.
    b"a=b+c;d=e-f;g=h*i;j=k/l;m=n%o;", b"a++;b--;++c;--d;a+ +b;a- -b;a+++b;", b"x=a<b>c<=d>=e==f!=g===h!==i;",
    b"x=a&&b||c&d|e^f;x=~a;x=!b;x=a<<b>>c>>>d;", b"x+=1;x-=2;x*=3;x/=4;x%=5;x<<=6;x>>=7;x>>>=8;x&=9;x|=10;x^=11;",
    b"x=a?b:c;y={a:1,b:[2,3]};z=(a,b);", b"x=a**b;x**=2;x=a??b;x=a?.b;y=(a)=>a*2;", b"if(a){b()}else{c()}",
    b"for(var i=0;i<10;i++){x[i]=i}", b"while(a){break;continue}do{a--}while(a)", b"switch(a){case 1:b();break;default:c()}",
    b"try{a()}catch(e){b(e)}finally{c()}", b"x=typeof a;y=a instanceof B;z=new C(1);delete a.b;void 0;",
    b"label:for(;;){break label}", b"return a", b"with(a){b}", b"x = y\n\n\nz = w", b"a\tb\fc\vd\re",
    # Strings and escapes.
    b"x='single';y=\"double\";", b"x='it\\'s';y=\"say \\\"hi\\\"\";", b"x='\\x41\\x42';y='\\u0043\\u0044';",
    b"x='\\101\\102\\0';", b"x='\\n\\r\\t\\b\\f\\v';", b"x='line\\\ncontinued';", b"x='\\q\\z\\%';",
    b"x='\\u{41}';", b"x='tab\there';y='  spaces  ';", b"x='<script>';y='</'+'script>';", b"x='\xc3\xa9\xe2\x82\xac';",
    b"x='a'+'b'+'c';", b"x='a'+b+'c';", b"x=1+'a';y='a'+1;", b"x='a'\n+\n'b';", b"x=('a')+('b');",
    b"x=`template ${a} literal`;", b"x='unterminated\ny=1;",
    # unescape, fromCharCode, eval.
    b"x=unescape('%41%42%u0043');", b"x=unescape(\"%3Cscript%3E\");", b"x=unescape(y);", b"x=String.fromCharCode(72,105);",
    b"x=String.fromCharCode(0x48,0x69);", b"x=String.fromCharCode(a,105);", b"eval('alert(1)');", b"eval(unescape('%61%6c%65%72%74'));",
    b"document.write(unescape('%3C%69%66%72%61%6D%65%3E'));", b"window['ev'+'al']('x');",
    # Comments.
    b"a=1;// line comment\nb=2;", b"a=1;/* block */b=2;", b"a=1;/* multi\nline */b=2;", b"a=1;/*/ odd */b=2;",
    b"a=1;// comment with / slashes // and */ ends\nb=2;", b"<!-- hidden\na=1;\n-->", b"a=1;/* unterminated",
    # Numbers.
    b"x=0;y=12;z=345678;", b"x=1.5;y=0.25;z=3.14159265358979;", b"x=1e3;y=2.5e-3;z=1E10;", b"x=0x1f;y=0XFF;z=017;",
    b"x=.5;y=5.;z=1.0;", b"x=123456789012;y=0.000001;", b"x=1n;y=0b101;z=0o17;", b"x=1_000;",
    # Regular expressions.
    b"x=/ab+c/gi;", b"x=/[/]/;", b"x=a/b/c;", b"x=/\\//;y=1;", b"if(/re/.test(s)){}", b"x=s.replace(/a/g,'b');",
    # Identifiers and scoping.
    b"var a=1;b=a;", b"var a=1,b=2;c=a+b;", b"var a;var a;a=1;", b"function f(x,y){return x+y}f(1,2);",
    b"function f(x){var y=x;return y}var z=f(1);", b"var a=1;function f(a){return a}a;", b"var f=function(x){return x};",
    b"(function(){var a=1})();var b=2;", b"let a=1;const b=2;c=a+b;", b"var $a=1,_b=2,c3=3;", b"Var A=1;a=A;VAR b;",
    b"var obj={a:1};obj.a=2;var a=obj.a;", b"function outer(){function inner(p){return p}return inner}",
    b"var x=1;{var y=2}x+y;", b"function f(){var a;function g(){var b;a+b}a}",
    b"var \xc3\xa9t\xc3\xa9=1;", b"var AbC=1;abc=2;ABC=3;",
    # Keywords and case.
    b"VAR x=1;FUNCTION f(){};", b"Document.Write('X');", b"IF(a){}ELSE{}", b"x=TRUE;y=False;z=NULL;",
    # Packers and obfuscation shapes.
    b"eval(function(p,a,c,k,e,d){e=function(c){return c};return p}('0 1',2,2,'a|b'.split('|'),0,{}))",
    b"var _0x12ab=['\\x65\\x76\\x61\\x6c'];window[_0x12ab[0]]('1');",
    b"a\x00b;", b"a\x01b;", b"#!x\n@y;", b"a\\b;",
]


def manifest_files(manifest, corpus):
    import json
    for f in json.load(open(manifest))["files"]:
        yield os.path.join(corpus, f["sha256"]), f["member"]


def write_pages(out, probes, srcs, manifest=None, corpus=None):
    os.makedirs(out, exist_ok=True)
    n = 0
    if probes:
        for i, p in enumerate(PROBES):
            open(os.path.join(out, "probe-%03d.html" % i), "wb").write(page(p))
            n += 1
        # Random scripts over a token alphabet, for interactions between rules.
        r = random.Random(51)
        alphabet = [b"var ", b"a", b"b", b"x1", b"=", b"+", b"-", b"*", b"/", b"(", b")", b"{", b"}", b"[", b"]",
                    b";", b",", b".", b"'s'", b"\"t\"", b"1", b"2.5", b"0x10", b" ", b"\n", b"/*c*/", b"//c\n",
                    b"function ", b"return ", b"unescape('%41')", b"++", b"<", b">", b"!", b"?", b":"]
        for i in range(400):
            s = b"".join(r.choice(alphabet) for _ in range(r.randint(5, 60)))
            open(os.path.join(out, "random-%03d.html" % i), "wb").write(page(s))
            n += 1
    entries = []
    for src in srcs:
        for d, _, names in os.walk(src):
            entries += [(os.path.join(d, name), name) for name in sorted(names)]
    if manifest:
        entries += list(manifest_files(manifest, corpus))
    if True:
        for path, name in entries:
                low = name.lower()
                try:
                    data = open(path, "rb").read()
                except OSError:
                    continue
                if low.endswith(".js") or low.endswith(".mjs"):
                    body = page(data)
                elif low.endswith((".html", ".htm")) and b"<script" in data.lower():
                    body = data
                else:
                    continue
                digest = hashlib.sha256(body).hexdigest()[:16]
                open(os.path.join(out, "page-%s.html" % digest), "wb").write(body)
                n += 1
    print("wrote", n, "pages")


def record(out, pages, clamscan, certs):
    os.makedirs(out, exist_ok=True)
    work = os.path.join(out, ".tmp")
    db = os.path.join(out, ".none.ndb")
    open(db, "w").write("Diff.Nothing:0:*:f1e2d3c4b5a69788796a5b4c3d2e1f00\n")
    base = [clamscan, "--no-summary", "--bytecode=no", "-d", db]
    if certs:
        base.append("--cvdcertsdir=" + certs)
    files = []
    for p in pages:
        files += sorted(glob.glob(os.path.join(p, "*.html"))) if os.path.isdir(p) else [p]
    kept = 0
    for path in files:
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)
        subprocess.run(base + ["--leave-temps", "--tempdir=" + work, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=dict(os.environ, LC_ALL="C"))
        js = glob.glob(os.path.join(work, "*", "html-tmp.*", "javascript"))
        name = os.path.splitext(os.path.basename(path))[0]
        shutil.copyfile(path, os.path.join(out, name + ".html"))
        # A page without a `javascript` file gets an empty golden: libclamav emitted nothing.
        open(os.path.join(out, name + ".js"), "wb").write(open(js[0], "rb").read() if js else b"")
        kept += 1
    shutil.rmtree(work, ignore_errors=True)
    os.remove(db)
    print("recorded", kept, "pages")


def compare(goldens, zav_diff, show):
    pages = sorted(glob.glob(os.path.join(goldens, "*.html")))
    same = 0
    shown = 0
    for path in pages:
        want = open(path[:-5] + ".js", "rb").read()
        got = subprocess.run([zav_diff, "normalize", "js", path], stdout=subprocess.PIPE).stdout
        if got == want:
            same += 1
            continue
        if shown < show:
            shown += 1
            i = next((k for k in range(min(len(got), len(want))) if got[k] != want[k]), min(len(got), len(want)))
            print("%s: first difference at %d" % (os.path.basename(path), i))
            print("  clamav: %r" % want[max(0, i - 40):i + 60])
            print("  zav:    %r" % got[max(0, i - 40):i + 60])
    print("%d of %d pages identical" % (same, len(pages)))
    return 0 if same == len(pages) else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pages")
    p.add_argument("out")
    p.add_argument("--probes", action="store_true")
    p.add_argument("--manifest")
    p.add_argument("--corpus")
    p.add_argument("src", nargs="*")
    r = sub.add_parser("record")
    r.add_argument("out")
    r.add_argument("pages", nargs="+")
    r.add_argument("--clamscan", default=os.environ.get("CLAMSCAN", "clamscan"))
    r.add_argument("--certs", default=os.environ.get("CLAMAV_CERTS"))
    c = sub.add_parser("compare")
    c.add_argument("goldens")
    c.add_argument("--zav-diff", default="zig-out/bin/zav-diff")
    c.add_argument("--show", type=int, default=20)
    args = ap.parse_args()
    if args.cmd == "pages":
        write_pages(args.out, args.probes, args.src, args.manifest, args.corpus)
    elif args.cmd == "record":
        record(args.out, args.pages, args.clamscan, args.certs)
    else:
        sys.exit(compare(args.goldens, args.zav_diff, args.show))


if __name__ == "__main__":
    main()
