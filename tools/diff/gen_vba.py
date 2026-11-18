#!/usr/bin/env python3
"""OLE2 documents with VBA projects for vba_check.py: random modules, compressed with MS-OVBA.

  gen_vba.py OUTDIR [--count N] [--seed S]

Each file is a version-3 compound file ([MS-CFB], 512-byte sectors, mini stream below 4096
bytes) holding a Word-like document stream and a Macros/VBA storage: _VBA_PROJECT, the dir
stream ([MS-OVBA] 2.3.4.2, compressed) and one to six modules, each a random-length module cache
followed by its compressed source. Sources range from a few bytes to several 4 KiB chunks, with
repetition (copy tokens at every offset width) and noise (literal runs), so both the CFB layer
(mini and regular streams) and the decompressor are exercised. Benign, synthetic content only.
"""
import argparse
import os
import random
import struct


def ovba_compress(data):
    """[MS-OVBA] 2.4.1 compression: greedy matches within each 4096-byte chunk."""
    out = bytearray([1])
    starts = range(0, len(data), 4096) if data else [0]
    for start in starts:
        chunk = data[start:start + 4096]
        body = bytearray()
        pos = 0
        # Earlier positions of each 3-byte prefix in the chunk, latest last.
        seen = {}

        def remember(upto, state=[0]):
            while state[0] < upto:
                k = chunk[state[0]:state[0] + 3]
                if len(k) == 3:
                    seen.setdefault(k, []).append(state[0])
                state[0] += 1
        while pos < len(chunk):
            flag_at = len(body)
            body.append(0)
            for bit in range(8):
                if pos >= len(chunk):
                    break
                bit_count = max((max(pos, 1) - 1).bit_length(), 4)
                max_len = (0xFFFF >> bit_count) + 3
                max_off = 1 << bit_count
                best_len, best_off = 0, 0
                remember(pos)
                for cand in reversed(seen.get(chunk[pos:pos + 3], [])[-64:]):
                    off = pos - cand
                    if off > max_off:
                        break
                    n = 0
                    while n < max_len and pos + n < len(chunk) and chunk[pos + n] == chunk[pos + n - off]:
                        n += 1
                    if n > best_len:
                        best_len, best_off = n, off
                if best_len >= 3:
                    token = ((best_off - 1) << (16 - bit_count)) | (best_len - 3)
                    body += struct.pack("<H", token)
                    body[flag_at] |= 1 << bit
                    pos += best_len
                else:
                    body.append(chunk[pos])
                    pos += 1
        header = 0x8000 | 0x3000 | (len(body) + 2 - 3)
        out += struct.pack("<H", header) + body
    return bytes(out)


def cfb(top):
    """A compound file from a tree of (name, bytes) and (name, [children]) nodes."""
    S = 512
    entries = [dict(name="Root Entry", kind=5, child=-1, right=-1, start=-2, size=0)]
    regular, mini = [], []

    def add(nodes):
        first = prev = -1
        for name, payload in nodes:
            i = len(entries)
            is_dir = isinstance(payload, list)
            entries.append(dict(name=name, kind=1 if is_dir else 2, child=-1, right=-1, start=-2,
                                size=0 if is_dir else len(payload)))
            if is_dir:
                entries[i]["child"] = add(payload)
            elif len(payload) >= 4096:
                regular.append((i, payload))
            elif payload:
                mini.append((i, payload))
            if prev >= 0:
                entries[prev]["right"] = i
            else:
                first = i
            prev = i
        return first

    entries[0]["child"] = add(top)
    minifat, mini_parts = [], []
    for i, payload in mini:
        n = (len(payload) + 63) // 64
        entries[i]["start"] = len(minifat)
        for k in range(n):
            minifat.append(0xFFFFFFFE if k == n - 1 else len(minifat) + 1)
        mini_parts.append(payload + bytes(n * 64 - len(payload)))
    mini_stream = b"".join(mini_parts)
    pad = lambda b: b + bytes((S - len(b) % S) % S)
    chains, owners = [], []
    for i, payload in regular:
        chains.append(pad(payload))
        owners.append(i)
    if mini_stream:
        chains.append(pad(mini_stream))
        owners.append(0)
    if minifat:
        mf = bytearray(b"\xff" * (((len(minifat) * 4 + S - 1) // S) * S))
        for k, v in enumerate(minifat):
            mf[k * 4:k * 4 + 4] = struct.pack("<I", v)
        chains.append(bytes(mf))
        owners.append(-3)
    dir_bytes = bytearray(((len(entries) * 128 + S - 1) // S) * S)
    chains.append(None)
    owners.append(-4)
    sizes = [len(c) // S if c is not None else len(dir_bytes) // S for c in chains]
    data_sectors = sum(sizes)
    fat_sectors = 1
    while (data_sectors + fat_sectors + 127) // 128 > fat_sectors:
        fat_sectors += 1
    fat = [0xFFFFFFFF] * (fat_sectors * 128)
    sector, starts = 0, []
    for n in sizes:
        starts.append(sector)
        for k in range(n):
            fat[sector + k] = 0xFFFFFFFE if k == n - 1 else sector + k + 1
        sector += n
    fat_start = sector
    for k in range(fat_sectors):
        fat[fat_start + k] = 0xFFFFFFFD
    for c, o in enumerate(owners):
        if o > 0:
            entries[o]["start"] = starts[c]
        elif o == 0:
            entries[0]["start"] = starts[c]
            entries[0]["size"] = len(mini_stream)
    minifat_start = starts[owners.index(-3)] if -3 in owners else 0xFFFFFFFE
    dir_start = starts[owners.index(-4)]
    for i, e in enumerate(entries):
        o = i * 128
        name = e["name"][:31]
        dir_bytes[o:o + 2 * len(name)] = name.encode("utf-16-le")
        struct.pack_into("<H", dir_bytes, o + 64, (len(name) + 1) * 2)
        dir_bytes[o + 66] = e["kind"]
        dir_bytes[o + 67] = 1
        struct.pack_into("<III", dir_bytes, o + 68, 0xFFFFFFFF, e["right"] & 0xFFFFFFFF, e["child"] & 0xFFFFFFFF)
        struct.pack_into("<II", dir_bytes, o + 116, e["start"] & 0xFFFFFFFF, e["size"])
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<II", header, 44, fat_sectors, dir_start)
    struct.pack_into("<IIIII", header, 56, 4096, minifat_start, (len(minifat) * 4 + S - 1) // S, 0xFFFFFFFE, 0)
    for k in range(109):
        struct.pack_into("<I", header, 76 + k * 4, fat_start + k if k < fat_sectors else 0xFFFFFFFF)
    body = b"".join(c if c is not None else bytes(dir_bytes) for c in chains)
    return bytes(header) + body + struct.pack("<%dI" % len(fat), *fat)


def rec(rid, data):
    return struct.pack("<HI", rid, len(data)) + data


WORDS = ["Dim", "As", "String", "Long", "If", "Then", "Else", "End", "For", "Next", "Call", "MsgBox", "Set",
         "Range", "Cells", "Value", "Worksheets", "Application", "Chr", "Mid", "Len", "Replace", "Split"]


def source(rng, name):
    lines = ['Attribute VB_Name = "%s"' % name]
    target = rng.choice([20, 300, 3000, 9000, 20000])
    while sum(len(l) + 2 for l in lines) < target:
        r = rng.random()
        if r < 0.6:
            lines.append("    " + " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 12))))
        elif r < 0.8:
            lines.append('    s = s & "%s"' % "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(5, 120))))
        elif r < 0.9:
            lines.append("Sub Proc%d()" % rng.randint(0, 999))
        else:
            lines.append("    ' " + "-=" * rng.randint(1, 60))
    return ("\r\n".join(lines) + "\r\n").encode("latin-1")


def project(rng):
    n = rng.randint(1, 6)
    names = ["Module%d" % (k + 1) for k in range(n)]
    streams, modrecs = [], b""
    for name in names:
        cache = bytes([rng.randrange(256) for _ in range(rng.choice([0, 37, 500, 5000]))])
        streams.append((name, cache + ovba_compress(source(rng, name))))
        uname = name.encode("utf-16-le")
        modrecs += (rec(0x19, name.encode()) + rec(0x47, uname) + rec(0x1A, name.encode()) + rec(0x32, uname) +
                    rec(0x1C, b"") + rec(0x48, b"") + rec(0x31, struct.pack("<I", len(cache))) + rec(0x1E, struct.pack("<I", 0)) +
                    rec(0x2C, struct.pack("<H", 0)) + rec(0x21, b"") + rec(0x2B, b""))
    dir_stream = (rec(0x01, struct.pack("<I", 1)) + rec(0x02, struct.pack("<I", 0x409)) + rec(0x14, struct.pack("<I", 0x409)) +
                  rec(0x03, struct.pack("<H", 1252)) + rec(0x04, b"VBAProject") + rec(0x05, b"") + rec(0x40, b"") +
                  rec(0x06, b"") + rec(0x3D, b"") + rec(0x07, struct.pack("<I", 0)) + rec(0x08, struct.pack("<I", 0)) +
                  struct.pack("<HIIH", 0x09, 4, 0x5F, 0x0B) + rec(0x0C, struct.pack("<H", 1252)) + rec(0x3C, b"") +
                  rec(0x0F, struct.pack("<H", n)) + rec(0x13, struct.pack("<H", 0xFFFF)) + modrecs + rec(0x10, b""))
    vba = [("_VBA_PROJECT", bytes([0xCC, 0x61, 0xFF, 0xFF, 0x00, 0x00, 0x00])), ("dir", ovba_compress(dir_stream))] + streams
    proj = ('ID="{00000000-0000-0000-0000-000000000000}"\r\n' + "".join("Module=%s\r\n" % m for m in names)).encode()
    doc = bytes(rng.randrange(32, 127) for _ in range(rng.choice([600, 6000])))
    return cfb([("WordDocument", doc), ("Macros", [("PROJECT", proj), ("VBA", vba)])])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--seed", type=int, default=49)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    rng = random.Random(args.seed)
    for i in range(args.count):
        with open(os.path.join(args.out, "v%04d.doc" % i), "wb") as f:
            f.write(project(rng))
    print("gen_vba.py: %d documents" % args.count)


if __name__ == "__main__":
    main()
