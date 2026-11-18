#!/bin/bash
# Executables for formats.py: one small C program and one shared library for each target zig cc
# can build, at three optimisation levels. Usage: build_corpus.sh OUTDIR
set -u
out="$1"
mkdir -p "$out"
src=$(mktemp -d)
cat > "$src/p.c" <<'X'
#include <stdio.h>
static int table[4096] = {1, 2, 3};
int helper(int x) { return table[x & 4095] * x; }
int main(int argc, char **argv) { printf("%d\n", helper(argc)); return 0; }
X
printf 'int exported(int x) { return x * 3; }\n' > "$src/l.c"
n=0
for t in x86_64-windows-gnu x86-windows-gnu aarch64-windows-gnu x86_64-linux-musl aarch64-linux-musl arm-linux-musleabihf x86-linux-musl riscv64-linux-musl powerpc64le-linux-musl x86_64-linux-gnu aarch64-linux-gnu x86_64-macos aarch64-macos; do
  for o in 0 s 2; do
    zig cc -target "$t" "-O$o" "$src/p.c" -o "$out/p-$t-O$o" 2>/dev/null && n=$((n + 1))
    zig cc -target "$t" "-O$o" -shared "$src/l.c" -o "$out/l-$t-O$o.so" 2>/dev/null && n=$((n + 1))
  done
done
echo "build_corpus.sh: $n files"
