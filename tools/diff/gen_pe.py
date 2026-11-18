#!/usr/bin/env python3
"""Write PE32 files with layout edge cases for formats.py: unaligned raw pointers and sizes,
small and odd file alignments, entry points in the headers, outside every section and in the
last byte of a section, truncated and empty sections, PE32+ and many sections.

  gen_pe.py OUTDIR
"""
import os
import struct
import sys


def pe(sections, ep, file_align=0x200, sect_align=0x1000, plus=False, size_of_headers=0x200, total=None, nsect_field=None):
    """sections: [(name, va, vsize, raw_ptr, raw_size, flags)]"""
    opt_size = 0xF0 if plus else 0xE0
    h = bytearray(max(size_of_headers, 0x400))
    h[0:2] = b"MZ"
    struct.pack_into("<I", h, 0x3C, 0x40)
    h[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", h, 0x44, 0x8664 if plus else 0x14C, nsect_field if nsect_field is not None else len(sections), 0, 0, 0, opt_size, 0x0102 if not plus else 0x0022)
    o = 0x58
    struct.pack_into("<H", h, o, 0x20B if plus else 0x10B)
    struct.pack_into("<I", h, o + 16, ep)
    struct.pack_into("<I", h, o + 20, 0x1000)
    if plus:
        struct.pack_into("<Q", h, o + 24, 0x140000000)
    else:
        struct.pack_into("<I", h, o + 24, 0x2000)
        struct.pack_into("<I", h, o + 28, 0x400000)
    struct.pack_into("<II", h, o + 32, sect_align, file_align)
    struct.pack_into("<HH", h, o + 40, 6, 0)
    struct.pack_into("<HH", h, o + 48, 6, 0)
    image = max([s[1] + s[2] for s in sections] + [0x1000])
    struct.pack_into("<II", h, o + 56, (image + sect_align - 1) // sect_align * sect_align, size_of_headers)
    struct.pack_into("<H", h, o + 68, 3)
    struct.pack_into("<I", h, o + (108 if plus else 92), 16)
    t = 0x58 + opt_size
    for i, (name, va, vsize, raw, rsize, flags) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", h, t + 40 * i, name, vsize, va, rsize, raw, 0, 0, 0, 0, flags)
    end = max([s[3] + s[4] for s in sections] + [len(h)])
    data = bytearray(h) + bytearray(max(0, end - len(h)))
    for i, s in enumerate(sections):
        for k in range(s[3], min(s[3] + s[4], len(data))):
            data[k] = (k * 7 + i) & 0xFF
    if total is not None:
        data = data[:total] if total < len(data) else data + bytearray(total - len(data))
    return bytes(data)


TEXT = 0x60000020
DATA = 0xC0000040


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    cases = {
        "plain": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT), (b".data", 0x2000, 0x200, 0x600, 0x200, DATA)], 0x1010),
        "raw-unaligned": pe([(b".text", 0x1000, 0x300, 0x410, 0x200, TEXT), (b".data", 0x2000, 0x200, 0x7FF, 0x200, DATA)], 0x1020),
        "size-unaligned": pe([(b".text", 0x1000, 0x300, 0x400, 0x123, TEXT), (b".data", 0x2000, 0x200, 0x600, 0x77, DATA)], 0x1100),
        "small-filealign": pe([(b".text", 0x1000, 0x80, 0x200, 0x80, TEXT), (b".data", 0x2000, 0x40, 0x280, 0x40, DATA)], 0x1040, file_align=0x20, sect_align=0x1000),
        "low-align": pe([(b".text", 0x400, 0x200, 0x400, 0x200, TEXT)], 0x410, file_align=0x200, sect_align=0x200),
        "ep-in-headers": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT)], 0x100),
        "ep-outside": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT)], 0x5000),
        "ep-in-bss": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT), (b".bss", 0x2000, 0x1000, 0, 0, DATA)], 0x2010),
        "ep-vsize-tail": pe([(b".text", 0x1000, 0x800, 0x400, 0x200, TEXT)], 0x1300),
        "ep-last-byte": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT)], 0x11FF),
        "truncated-section": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT), (b".data", 0x2000, 0x400, 0x600, 0x400, DATA)], 0x1010, total=0x700),
        "raw-beyond-eof": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT), (b".data", 0x2000, 0x200, 0x4000, 0x200, DATA)], 0x1010, total=0x600),
        "empty-section": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT), (b".empty", 0x2000, 0x100, 0x0, 0x0, DATA), (b".data", 0x3000, 0x200, 0x600, 0x200, DATA)], 0x1010),
        "overlap": pe([(b".text", 0x1000, 0x400, 0x400, 0x400, TEXT), (b".data", 0x2000, 0x200, 0x600, 0x200, DATA)], 0x1010),
        "pe32plus": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT), (b".data", 0x2000, 0x200, 0x600, 0x200, DATA)], 0x1008, plus=True),
        "many-sections": pe([(b".s%d" % i, 0x1000 * (i + 1), 0x200, 0x800 + 0x200 * i, 0x200, TEXT) for i in range(20)], 0x5010, size_of_headers=0x800),
        "headers-0x400": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT)], 0x1010, size_of_headers=0x400),
        "zero-sections": pe([], 0x100),
        "big-filealign": pe([(b".text", 0x1000, 0x200, 0x1000, 0x200, TEXT)], 0x1010, file_align=0x1000),
        "odd-filealign": pe([(b".text", 0x1000, 0x200, 0x400, 0x200, TEXT)], 0x1010, file_align=0x300),
    }
    for name, data in cases.items():
        with open(os.path.join(out, name + ".exe"), "wb") as f:
            f.write(data)
    print("gen_pe.py: %d files" % len(cases))


if __name__ == "__main__":
    main()
