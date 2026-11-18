// Generates the format fixtures used by the src/fmt tests and fuzz targets.
//
//   bun src/fmt/fixtures/make-fixtures.ts
//
// Plain inputs are deterministic (a seeded generator), so the output is reproducible given the
// same compressor versions. Compressed vectors come from reference encoders: node:zlib for gzip
// and zstd, the system bzip2 for bzip2, and Python's lzma module (liblzma) for xz and LZMA.
// Archives (zip, tar, cpio) and executables (PE, ELF, Mach-O) are built byte by byte here from
// their specifications, so malformed and adversarial variants are exact. fixtures.zig is written
// last: it embeds every file with its expected plain length and CRC-32.
import { spawnSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import zlib from 'node:zlib'
import * as containers from './containers.ts'

const dir = dirname(new URL(import.meta.url).pathname)
mkdirSync(dir, { recursive: true })

// ---------------------------------------------------------------------------------------------
// Helpers

let seed = 0x12345678
function rand(): number {
  // xorshift32
  seed ^= seed << 13
  seed >>>= 0
  seed ^= seed >>> 17
  seed ^= seed << 5
  seed >>>= 0
  return seed
}

/** Mixed content: English-ish words, runs and noise, so every coder path gets exercised. */
function plain(len: number, s: number): Uint8Array {
  seed = s
  const words = ['alpha', 'beta', 'gamma', 'delta', 'scan', 'engine', 'zip', 'malware', 'the', 'of', '\n']
  const out = new Uint8Array(len)
  let i = 0
  while (i < len) {
    const r = rand() % 100
    if (r < 70) {
      const w = words[rand() % words.length] + ' '
      for (let k = 0; k < w.length && i < len; k++) out[i++] = w.charCodeAt(k)
    } else if (r < 85) {
      const b = rand() & 0xff
      const n = 1 + (rand() % 300)
      for (let k = 0; k < n && i < len; k++) out[i++] = b
    } else {
      const n = 1 + (rand() % 64)
      for (let k = 0; k < n && i < len; k++) out[i++] = rand() & 0xff
    }
  }
  return out
}

const crcTable = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()

function crc32(data: Uint8Array): number {
  let c = 0xffffffff
  for (const b of data) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function run(cmd: string, args: string[], input: Uint8Array): Uint8Array {
  const r = spawnSync(cmd, args, { input, maxBuffer: 1 << 28 })
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')}: ${r.stderr}`)
  return new Uint8Array(r.stdout)
}

function py(code: string, input: Uint8Array): Uint8Array {
  return run('python3', ['-I', '-c', `import sys,lzma\ndata=sys.stdin.buffer.read()\n${code}`], input)
}

interface Vector { name: string, file: string, plainLen: number, plainCrc: number }
const groups: Record<string, Vector[]> = {}

function vector(group: string, name: string, compressed: Uint8Array, data: Uint8Array) {
  const file = `${group}-${name}.bin`
  writeFileSync(join(dir, file), compressed)
  ;(groups[group] ??= []).push({ name, file, plainLen: data.length, plainCrc: crc32(data) })
}

// ---------------------------------------------------------------------------------------------
// Compression vectors (P5.02)

const small = plain(5000, 1)
const medium = plain(300_000, 2)
const runs = new Uint8Array(70_000).fill(0x61)

function gzipHeader(flags: number, extra: { name?: string, comment?: string, extra?: Uint8Array }): Uint8Array {
  const parts: number[] = [0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 3]
  if (flags & 4) {
    const e = extra.extra!
    parts.push(e.length & 0xff, e.length >> 8, ...e)
  }
  if (flags & 8) parts.push(...new TextEncoder().encode(extra.name!), 0)
  if (flags & 16) parts.push(...new TextEncoder().encode(extra.comment!), 0)
  const head = new Uint8Array(parts)
  if (flags & 2) {
    const c = crc32(head) & 0xffff
    return concat(head, new Uint8Array([c & 0xff, c >> 8]))
  }
  return head
}

function gzipTrailer(data: Uint8Array): Uint8Array {
  const t = new Uint8Array(8)
  const v = new DataView(t.buffer)
  v.setUint32(0, crc32(data), true)
  v.setUint32(4, data.length >>> 0, true)
  return t
}

vector('gzip', 'small', zlib.gzipSync(small), small)
vector('gzip', 'medium', zlib.gzipSync(medium, { level: 9 }), medium)
vector('gzip', 'stored', zlib.gzipSync(small, { level: 0 }), small)
vector('gzip', 'multi-member', concat(zlib.gzipSync(small), zlib.gzipSync(runs)), concat(small, runs))
vector('gzip', 'header-fields', concat(
  gzipHeader(2 | 4 | 8 | 16, { name: 'inner.txt', comment: 'a comment', extra: new Uint8Array([65, 66, 2, 0, 1, 2]) }),
  zlib.deflateRawSync(small),
  gzipTrailer(small),
), small)

vector('bzip2', 'small', run('bzip2', ['-c', '-9'], small), small)
vector('bzip2', 'multi-block', run('bzip2', ['-c', '-1'], medium), medium)
vector('bzip2', 'runs', run('bzip2', ['-c'], runs), runs)
vector('bzip2', 'concatenated', concat(run('bzip2', ['-c'], small), run('bzip2', ['-c', '-2'], runs)), concat(small, runs))
const oneByte = new Uint8Array([0x7a])
vector('bzip2', 'one-byte', run('bzip2', ['-c'], oneByte), oneByte)

vector('xz', 'crc64', py('sys.stdout.buffer.write(lzma.compress(data, check=lzma.CHECK_CRC64))', medium), medium)
vector('xz', 'crc32', py('sys.stdout.buffer.write(lzma.compress(data, check=lzma.CHECK_CRC32, preset=1))', small), small)
vector('xz', 'sha256', py('sys.stdout.buffer.write(lzma.compress(data, check=lzma.CHECK_SHA256))', runs), runs)
vector('xz', 'none', py('sys.stdout.buffer.write(lzma.compress(data, check=lzma.CHECK_NONE))', small), small)
vector('xz', 'concatenated', concat(
  py('sys.stdout.buffer.write(lzma.compress(data))', small),
  new Uint8Array(8),
  py('sys.stdout.buffer.write(lzma.compress(data, preset=0))', runs),
), concat(small, runs))
const noise = (() => {
  seed = 99
  const a = new Uint8Array(70_000)
  for (let i = 0; i < a.length; i++) a[i] = rand() & 0xff
  return a
})()
vector('xz', 'uncompressed-chunks', py(
  'sys.stdout.buffer.write(lzma.compress(data, filters=[{"id": lzma.FILTER_LZMA2, "preset": 0}]))',
  noise,
), noise)
vector('xz', 'dict-64m', py('sys.stdout.buffer.write(lzma.compress(data, preset=9))', small), small)
vector('xz', 'bcj-x86', py(
  'sys.stdout.buffer.write(lzma.compress(data, filters=[{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2, "preset": 6}]))',
  small,
), small)
vector('lzma', 'alone', py('sys.stdout.buffer.write(lzma.compress(data, format=lzma.FORMAT_ALONE))', medium), medium)

vector('zstd', 'small', zlib.zstdCompressSync(small), small)
vector('zstd', 'medium', zlib.zstdCompressSync(medium, { params: { [zlib.constants.ZSTD_c_compressionLevel]: 19 } }), medium)
vector('zstd', 'checksum', zlib.zstdCompressSync(runs, { params: { [zlib.constants.ZSTD_c_checksumFlag]: 1 } }), runs)
vector('zstd', 'multi-frame', concat(zlib.zstdCompressSync(small), zlib.zstdCompressSync(runs)), concat(small, runs))
vector('zstd', 'skippable', concat(new Uint8Array([0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3]), zlib.zstdCompressSync(small)), small)
// A frame declaring a 128 MiB window (window descriptor exponent 17): the encoder shrinks the
// window to the input, so the descriptor byte is raised by hand. Still a valid frame.
const bigWindow = zlib.zstdCompressSync(small, { params: { [zlib.constants.ZSTD_c_contentSizeFlag]: 0 } })
if ((bigWindow[4] & 0x20) !== 0) throw new Error('expected a window descriptor')
bigWindow[5] = 17 << 3
vector('zstd', 'window-128m', bigWindow, small)

// Decompression bombs: 64 MiB of zeros in each wrapper.
const zeros = new Uint8Array(64 * 1024 * 1024)
vector('bomb', 'gzip', zlib.gzipSync(zeros, { level: 9 }), zeros)
vector('bomb', 'bzip2', run('bzip2', ['-c', '-9'], zeros), zeros)
vector('bomb', 'xz', py('sys.stdout.buffer.write(lzma.compress(data, preset=1))', zeros), zeros)
vector('bomb', 'zstd', zlib.zstdCompressSync(zeros, { params: { [zlib.constants.ZSTD_c_compressionLevel]: 19 } }), zeros)

// ---------------------------------------------------------------------------------------------
// Archives (P5.04 tar and cpio, P5.03 zip): built byte by byte from the specifications.

interface Member { path: string, data: Uint8Array }
interface Archive { name: string, file: string, members: Member[], malformed: boolean }
const archives: Archive[] = []

function archive(name: string, bytes: Uint8Array, members: Member[], malformed = false) {
  // A .bin suffix keeps global ignore rules for *.tar, *.zip and *.gz away from fixtures.
  const file = `archive-${name}.bin`
  writeFileSync(join(dir, file), bytes)
  archives.push({ name, file, members, malformed })
}

const enc = new TextEncoder()
const fileA = enc.encode('first member\n')
const fileB = plain(3000, 7)
const evil = enc.encode('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')

function octalField(v: number, len: number): string {
  return v.toString(8).padStart(len - 1, '0') + '\0'
}

function tarHeader(o: { name: string, size: number, type?: string, prefix?: string, magic?: 'ustar' | 'gnu' | 'v7', linkname?: string, base256?: boolean }): Uint8Array {
  const h = new Uint8Array(512)
  const put = (off: number, s: string | Uint8Array) => h.set(typeof s === 'string' ? enc.encode(s) : s, off)
  put(0, o.name.slice(0, 100))
  put(100, octalField(0o644, 8))
  put(108, octalField(1000, 8))
  put(116, octalField(1000, 8))
  if (o.base256) {
    h[124] = 0x80
    new DataView(h.buffer).setUint32(132, o.size)
  } else {
    put(124, octalField(o.size, 12))
  }
  put(136, octalField(1700000000, 12))
  h[156] = (o.type ?? '0').charCodeAt(0)
  if (o.linkname) put(157, o.linkname)
  const magic = o.magic ?? 'ustar'
  if (magic === 'ustar') {
    put(257, 'ustar\x0000')
    put(265, 'user')
    put(297, 'group')
    if (o.prefix) put(345, o.prefix)
  } else if (magic === 'gnu') {
    put(257, 'ustar  \x00')
  }
  h.fill(0x20, 148, 156)
  let sum = 0
  for (const b of h) sum += b
  put(148, sum.toString(8).padStart(6, '0') + '\0 ')
  return h
}

function pad512(d: Uint8Array): Uint8Array {
  const n = (512 - (d.length % 512)) % 512
  return concat(d, new Uint8Array(n))
}

function tarEntry(name: string, data: Uint8Array, opts: Partial<Parameters<typeof tarHeader>[0]> = {}): Uint8Array {
  return concat(tarHeader({ name, size: data.length, ...opts }), pad512(data))
}

const tarEnd = new Uint8Array(1024)

function paxRecord(key: string, value: string): string {
  let len = key.length + value.length + 3
  for (;;) {
    const s = `${len} ${key}=${value}\n`
    if (enc.encode(s).length === len) return s
    len = enc.encode(s).length
  }
}

const longName = `deep/${'d'.repeat(120)}/file-with-a-long-name.txt`
const tarUstar = concat(
  tarEntry('dir/', new Uint8Array(0), { type: '5' }),
  tarEntry('a.txt', fileA),
  tarEntry('b.bin', fileB, { prefix: 'some/prefix' }),
  tarEntry('link', new Uint8Array(0), { type: '2', linkname: 'a.txt' }),
  tarEntry('eicar.com', evil),
  tarEnd,
)
archive('ustar.tar', tarUstar, [
  { path: 'a.txt', data: fileA },
  { path: 'some/prefix/b.bin', data: fileB },
  { path: 'eicar.com', data: evil },
])
const gnuLong = enc.encode(`${longName}\0`)
archive('gnu.tar', concat(
  tarEntry('././@LongLink', gnuLong, { type: 'L', magic: 'gnu' }),
  tarEntry(longName.slice(0, 99), fileB, { magic: 'gnu' }),
  tarEntry('sized', fileA, { magic: 'gnu', base256: true }),
  tarEnd,
), [{ path: longName, data: fileB }, { path: 'sized', data: fileA }])
const pax = enc.encode(paxRecord('path', longName) + paxRecord('mtime', '1700000000.5'))
archive('pax.tar', concat(
  tarEntry('PaxHeaders/x', pax, { type: 'x' }),
  tarEntry('truncated-name', fileB),
  tarEntry('global', enc.encode(paxRecord('comment', 'hi')), { type: 'g' }),
  tarEntry('a.txt', fileA),
  tarEnd,
), [{ path: longName, data: fileB }, { path: 'a.txt', data: fileA }])
archive('v7.tar', concat(tarEntry('old.txt', fileA, { magic: 'v7' }), tarEntry('evil', evil, { magic: 'v7' }), tarEnd), [
  { path: 'old.txt', data: fileA },
  { path: 'evil', data: evil },
])
const badSum = tarEntry('a.txt', fileA)
badSum[148] = '7'.charCodeAt(0)
archive('bad-checksum.tar', concat(tarEntry('ok.txt', fileA), badSum, tarEnd), [{ path: 'ok.txt', data: fileA }], true)
const truncatedTar = tarEntry('big.bin', fileB).slice(0, 512 + 1000)
archive('truncated.tar', concat(tarEntry('a.txt', fileA), truncatedTar), [
  { path: 'a.txt', data: fileA },
  { path: 'big.bin', data: fileB.slice(0, 1000) },
], true)
archive('ustar.tar.gz', zlib.gzipSync(tarUstar), [
  { path: 'ustar.tar/a.txt', data: fileA },
  { path: 'ustar.tar/some/prefix/b.bin', data: fileB },
  { path: 'ustar.tar/eicar.com', data: evil },
])
archive('ustar.tar.xz', py('sys.stdout.buffer.write(lzma.compress(data))', tarUstar), [
  { path: 'ustar.tar/a.txt', data: fileA },
  { path: 'ustar.tar/some/prefix/b.bin', data: fileB },
  { path: 'ustar.tar/eicar.com', data: evil },
])

function hex8(v: number): string {
  return v.toString(16).padStart(8, '0')
}

function cpioNewc(entries: { name: string, data: Uint8Array, mode?: number }[], magic = '070701', trailer = true): Uint8Array {
  const parts: Uint8Array[] = []
  const all = trailer ? [...entries, { name: 'TRAILER!!!', data: new Uint8Array(0), mode: 0 }] : entries
  let ino = 1
  for (const e of all) {
    const name = enc.encode(`${e.name}\0`)
    const header = magic + [ino++, e.mode ?? 0o100644, 0, 0, 1, 1700000000, e.data.length, 0, 0, 0, 0, name.length, 0].map(hex8).join('')
    const head = concat(enc.encode(header), name)
    parts.push(head, new Uint8Array((4 - (head.length % 4)) % 4), e.data, new Uint8Array((4 - (e.data.length % 4)) % 4))
  }
  return concat(...parts)
}

function cpioOdc(entries: { name: string, data: Uint8Array, mode?: number }[]): Uint8Array {
  const parts: Uint8Array[] = []
  for (const e of [...entries, { name: 'TRAILER!!!', data: new Uint8Array(0), mode: 0 }]) {
    const name = enc.encode(`${e.name}\0`)
    const o = (v: number, n: number) => v.toString(8).padStart(n, '0')
    const header = `070707${o(1, 6)}${o(2, 6)}${o(e.mode ?? 0o100644, 6)}${o(0, 6)}${o(0, 6)}${o(1, 6)}${o(0, 6)}${o(1700000000, 11)}${o(name.length, 6)}${o(e.data.length, 11)}`
    parts.push(enc.encode(header), name, e.data)
  }
  return concat(...parts)
}

function cpioBin(entries: { name: string, data: Uint8Array, mode?: number }[], little: boolean): Uint8Array {
  const parts: Uint8Array[] = []
  for (const e of [...entries, { name: 'TRAILER!!!', data: new Uint8Array(0), mode: 0 }]) {
    const name = enc.encode(`${e.name}\0`)
    const h = new Uint8Array(26)
    const v = new DataView(h.buffer)
    const words = [0o070707, 1, 2, e.mode ?? 0o100644, 0, 0, 1, 0, 0, 0, name.length, e.data.length >>> 16, e.data.length & 0xffff]
    words.forEach((w, i) => v.setUint16(i * 2, w, little))
    parts.push(h, name, new Uint8Array(name.length % 2), e.data, new Uint8Array(e.data.length % 2))
  }
  return concat(...parts)
}

const cpioEntries = [
  { name: 'dir', data: new Uint8Array(0), mode: 0o040755 },
  { name: 'a.txt', data: fileA },
  { name: 'sym', data: enc.encode('a.txt'), mode: 0o120777 },
  { name: 'b.bin', data: fileB },
  { name: 'eicar.com', data: evil },
]
const cpioMembers = [{ path: 'a.txt', data: fileA }, { path: 'b.bin', data: fileB }, { path: 'eicar.com', data: evil }]
archive('newc.cpio', cpioNewc(cpioEntries), cpioMembers)
archive('crc.cpio', cpioNewc(cpioEntries, '070702'), cpioMembers)
archive('odc.cpio', cpioOdc(cpioEntries), cpioMembers)
archive('bin-le.cpio', cpioBin(cpioEntries, true), cpioMembers)
archive('bin-be.cpio', cpioBin(cpioEntries, false), cpioMembers)
archive('no-trailer.cpio', cpioNewc(cpioEntries, '070701', false), cpioMembers, true)
archive('newc.cpio.gz', zlib.gzipSync(cpioNewc(cpioEntries)), cpioMembers.map(m => ({ path: `newc.cpio/${m.path}`, data: m.data })))

// zip (APPNOTE.TXT). The writer takes per-entry options so malformed variants are exact.
interface ZipEntry {
  name: string
  data: Uint8Array
  method?: number
  /** Compressed bytes; computed from `method` when absent. */
  packed?: Uint8Array
  flags?: number
  descriptor?: boolean
  zip64?: boolean
  /** Leave the entry out of the central directory. */
  unlisted?: boolean
  /** Method written into the local header when it should disagree with the directory. */
  localMethod?: number
}

function compressFor(method: number, data: Uint8Array): Uint8Array {
  switch (method) {
    case 0: return data
    case 8: return zlib.deflateRawSync(data)
    case 12: return run('bzip2', ['-c'], data)
    case 14: {
      // zip LZMA: version 2 bytes, properties size, then an LZMA "alone" stream without its size.
      const alone = py('sys.stdout.buffer.write(lzma.compress(data, format=lzma.FORMAT_ALONE))', data)
      return concat(new Uint8Array([9, 20, 5, 0]), alone.slice(0, 5), alone.slice(13))
    }
    case 93: return zlib.zstdCompressSync(data)
    case 95: return py('sys.stdout.buffer.write(lzma.compress(data))', data)
    default: return data
  }
}

function u16(v: number): Uint8Array {
  return new Uint8Array([v & 0xff, (v >> 8) & 0xff])
}
function u32(v: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, v >>> 0, true)
  return b
}
function u64(v: number): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(v), true)
  return b
}

function zipBytes(entries: ZipEntry[], o: { prefix?: Uint8Array, noDirectory?: boolean, zip64End?: boolean, comment?: string } = {}): Uint8Array {
  const parts: Uint8Array[] = []
  const central: Uint8Array[] = []
  let off = 0
  const push = (b: Uint8Array) => {
    parts.push(b)
    off += b.length
  }
  if (o.prefix) push(o.prefix)
  const zipStart = off
  let listed = 0
  for (const e of entries) {
    const method = e.method ?? 8
    const packed = e.packed ?? compressFor(method, e.data)
    const name = enc.encode(e.name)
    const crc = crc32(e.data)
    const flags = (e.flags ?? 0) | (e.descriptor ? 8 : 0)
    const local = off - zipStart
    const z64 = e.zip64 ?? false
    const extraLocal = z64 ? concat(u16(1), u16(16), u64(e.data.length), u64(packed.length)) : new Uint8Array(0)
    push(concat(
      u32(0x04034b50), u16(z64 ? 45 : 20), u16(flags), u16(e.localMethod ?? method), u16(0), u16(0x5821),
      u32(e.descriptor ? 0 : crc), u32(e.descriptor ? 0 : z64 ? 0xffffffff : packed.length), u32(e.descriptor ? 0 : z64 ? 0xffffffff : e.data.length),
      u16(name.length), u16(extraLocal.length), name, extraLocal,
    ))
    push(packed)
    if (e.descriptor) push(concat(u32(0x08074b50), u32(crc), u32(packed.length), u32(e.data.length)))
    if (e.unlisted) continue
    listed++
    const extraCentral = z64 ? concat(u16(1), u16(24), u64(e.data.length), u64(packed.length), u64(local)) : new Uint8Array(0)
    central.push(concat(
      u32(0x02014b50), u16(0x031e), u16(z64 ? 45 : 20), u16(flags), u16(method), u16(0), u16(0x5821),
      u32(crc), u32(z64 ? 0xffffffff : packed.length), u32(z64 ? 0xffffffff : e.data.length),
      u16(name.length), u16(extraCentral.length), u16(0), u16(0), u16(0), u32(0o100644 << 16), u32(z64 ? 0xffffffff : local),
      name, extraCentral,
    ))
  }
  if (o.noDirectory) return concat(...parts)
  const cdOff = off - zipStart
  const cd = concat(...central)
  push(cd)
  if (o.zip64End) {
    const recOff = off - zipStart
    push(concat(u32(0x06064b50), u64(44), u16(45), u16(45), u32(0), u32(0), u64(listed), u64(listed), u64(cd.length), u64(cdOff)))
    push(concat(u32(0x07064b50), u32(0), u64(recOff), u32(1)))
  }
  const comment = enc.encode(o.comment ?? '')
  push(concat(
    u32(0x06054b50), u16(0), u16(0), u16(o.zip64End ? 0xffff : listed), u16(o.zip64End ? 0xffff : listed),
    u32(o.zip64End ? 0xffffffff : cd.length), u32(o.zip64End ? 0xffffffff : cdOff), u16(comment.length), comment,
  ))
  return concat(...parts)
}

const zipMembers = [{ path: 'a.txt', data: fileA }, { path: 'b.bin', data: fileB }, { path: 'eicar.com', data: evil }]
const zipBasic = (method: number) => zipBytes([
  { name: 'dir/', data: new Uint8Array(0), method: 0 },
  { name: 'a.txt', data: fileA, method },
  { name: 'b.bin', data: fileB, method },
  { name: 'eicar.com', data: evil, method },
])
archive('stored.zip', zipBasic(0), zipMembers)
archive('deflate.zip', zipBasic(8), zipMembers)
archive('bzip2.zip', zipBasic(12), zipMembers)
archive('lzma.zip', zipBasic(14), zipMembers)
archive('zstd.zip', zipBasic(93), zipMembers)
archive('xz.zip', zipBasic(95), zipMembers)
const eicarZip = zipBytes([{ name: 'eicar.com', data: evil, method: 0 }])
archive('eicar_com.zip', eicarZip, [{ path: 'eicar.com', data: evil }])
archive('eicarcom2.zip', zipBytes([{ name: 'eicar_com.zip', data: eicarZip, method: 0 }]), [
  { path: 'eicar_com.zip', data: eicarZip },
  { path: 'eicar_com.zip/eicar.com', data: evil },
])
archive('zip64.zip', zipBytes([
  { name: 'a.txt', data: fileA, zip64: true },
  { name: 'b.bin', data: fileB, method: 0, zip64: true },
], { zip64End: true }), zipMembers.slice(0, 2))
archive('descriptor.zip', zipBytes([
  { name: 'a.txt', data: fileA, descriptor: true },
  { name: 'b.bin', data: fileB, method: 0, descriptor: true },
  { name: 'eicar.com', data: evil, descriptor: true },
], { comment: 'archive comment' }), zipMembers)
archive('sfx.zip', zipBytes([{ name: 'a.txt', data: fileA }, { name: 'eicar.com', data: evil }], { prefix: new Uint8Array(4096).fill(0x4d) }), [
  { path: 'a.txt', data: fileA },
  { path: 'eicar.com', data: evil },
])
archive('no-directory.zip', zipBytes([
  { name: 'a.txt', data: fileA },
  { name: 'b.bin', data: fileB, method: 0, descriptor: true },
  { name: 'eicar.com', data: evil, descriptor: true },
], { noDirectory: true }), zipMembers, true)
archive('hidden-entry.zip', zipBytes([
  { name: 'a.txt', data: fileA },
  { name: 'eicar.com', data: evil, unlisted: true },
  { name: 'b.bin', data: fileB },
]), zipMembers)
archive('encrypted.zip', zipBytes([
  { name: 'a.txt', data: fileA },
  { name: 'secret.bin', data: fileB, flags: 1, method: 0, packed: plain(3012, 5) },
]), [{ path: 'a.txt', data: fileA }])
archive('method-mismatch.zip', zipBytes([{ name: 'a.txt', data: fileA, method: 8, localMethod: 0 }]), [{ path: 'a.txt', data: fileA }])
archive('deflate64.zip', zipBytes([{ name: 'odd.bin', data: fileA, method: 9, packed: fileA }]), [{ path: 'odd.bin', data: fileA }])

// Overlapping-file bombs (David Fifield, "A better zip bomb", 2019). The kernel is 8 MiB of
// zeros; every file's deflate stream quotes the next file's local header in a stored block and
// then continues into the shared kernel, so N files decode to N times the kernel.
function overlapBomb(n: number): Uint8Array {
  const kernelData = new Uint8Array(8 * 1024 * 1024)
  const kernel = zlib.deflateRawSync(kernelData, { level: 9 })
  const names = Array.from({ length: n }, (_, i) => enc.encode(`f${i.toString().padStart(4, '0')}`))
  const lfh = (i: number, csize: number, usize: number) => concat(
    u32(0x04034b50), u16(20), u16(0), u16(8), u16(0), u16(0x5821), u32(0), u32(csize), u32(usize),
    u16(names[i].length), u16(0), names[i],
  )
  // Built back to front: file i's data is [stored block quoting LFH(i+1)] + data(i+1).
  const headers: Uint8Array[] = new Array(n)
  const csizes: number[] = new Array(n)
  const usizes: number[] = new Array(n)
  csizes[n - 1] = kernel.length
  usizes[n - 1] = kernelData.length
  headers[n - 1] = lfh(n - 1, csizes[n - 1], usizes[n - 1])
  for (let i = n - 2; i >= 0; i--) {
    const q = headers[i + 1]
    csizes[i] = 5 + q.length + csizes[i + 1]
    usizes[i] = q.length + usizes[i + 1]
    headers[i] = lfh(i, csizes[i], usizes[i])
  }
  const body: Uint8Array[] = []
  for (let i = 0; i < n - 1; i++) {
    const q = headers[i + 1]
    body.push(headers[i], new Uint8Array([0, q.length & 0xff, q.length >> 8, ~q.length & 0xff, (~q.length >> 8) & 0xff]))
  }
  body.push(headers[n - 1], kernel)
  const data = concat(...body)
  let offs = 0
  const central: Uint8Array[] = []
  for (let i = 0; i < n; i++) {
    central.push(concat(
      u32(0x02014b50), u16(0x031e), u16(20), u16(0), u16(8), u16(0), u16(0x5821), u32(0), u32(csizes[i]), u32(usizes[i]),
      u16(names[i].length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offs), names[i],
    ))
    offs += headers[i].length + (i < n - 1 ? 5 : 0)
  }
  const cd = concat(...central)
  return concat(data, cd, u32(0x06054b50), u16(0), u16(0), u16(n), u16(n), u32(cd.length), u32(data.length), u16(0))
}
archive('overlap-bomb.zip', overlapBomb(250), [], false)

// Many directory entries naming one local entry: the simplest overlap.
function sameEntryBomb(n: number): Uint8Array {
  const kernel = zlib.deflateRawSync(new Uint8Array(8 * 1024 * 1024), { level: 9 })
  const name = enc.encode('k')
  const local = concat(u32(0x04034b50), u16(20), u16(0), u16(8), u16(0), u16(0), u32(0), u32(kernel.length), u32(8 << 20), u16(1), u16(0), name, kernel)
  const cdEntry = concat(u32(0x02014b50), u16(20), u16(20), u16(0), u16(8), u16(0), u16(0), u32(0), u32(kernel.length), u32(8 << 20), u16(1), u16(0), u16(0), u16(0), u16(0), u32(0), u32(0), name)
  const cd = concat(...Array.from({ length: n }, () => cdEntry))
  return concat(local, cd, u32(0x06054b50), u16(0), u16(0), u16(n), u16(n), u32(cd.length), u32(local.length), u16(0))
}
archive('same-entry-bomb.zip', sameEntryBomb(1000), [], false)

// Adversarial corpus (P5.17). A recursive bomb in the style of 42.zip: four levels of 16
// identical deflated zips over a leaf of 64 MiB of zeros, claiming 4 TiB.
function nestedBomb(levels: number, fanout: number): Uint8Array {
  let inner = zipBytes([{ name: 'zeros.bin', data: new Uint8Array(64 * 1024 * 1024) }])
  for (let l = 0; l < levels; l++) {
    inner = zipBytes(Array.from({ length: fanout }, (_, i) => ({ name: `l${l}-${i.toString(16)}.zip`, data: inner })))
  }
  return inner
}
archive('nested-bomb.zip', nestedBomb(4, 16), [], false)

// Nesting far past MaxRecursion (17): a zip in a zip, 40 deep, and a gzip in a gzip, 40 deep.
function deepZip(depth: number): Uint8Array {
  let b: Uint8Array = evil
  for (let d = 0; d < depth; d++) b = zipBytes([{ name: `d${d}`, data: b, method: d % 2 === 0 ? 0 : 8 }])
  return b
}
archive('deep-40.zip', deepZip(40), [], false)
let deepGz: Uint8Array = evil
for (let d = 0; d < 40; d++) deepGz = zlib.gzipSync(deepGz)
archive('deep-40.gz', deepGz, [], false)

// OLE2 compound files ([MS-CFB], version 3, 512-byte sectors) with a VBA project whose dir
// stream and module source are MS-OVBA compressed ([MS-OVBA] 2.4.1).
function ovbaCompress(data: Uint8Array): Uint8Array {
  const out: number[] = [1]
  for (let start = 0; start < data.length || (start === 0 && data.length === 0); start += 4096) {
    const chunk = data.subarray(start, start + 4096)
    const body: number[] = []
    let pos = 0
    while (pos < chunk.length) {
      const flagAt = body.length
      body.push(0)
      for (let bit = 0; bit < 8 && pos < chunk.length; bit++) {
        const bitCount = Math.max(Math.ceil(Math.log2(Math.max(pos, 1))), 4)
        const maxLen = (0xffff >> bitCount) + 3
        const maxOff = 1 << bitCount
        let bestLen = 0
        let bestOff = 0
        for (let off = 1; off <= Math.min(pos, maxOff); off++) {
          let len = 0
          while (len < maxLen && pos + len < chunk.length && chunk[pos + len] === chunk[pos + len - off]) len++
          if (len > bestLen) {
            bestLen = len
            bestOff = off
          }
        }
        if (bestLen >= 3) {
          const token = ((bestOff - 1) << (16 - bitCount)) | (bestLen - 3)
          body.push(token & 0xff, token >> 8)
          body[flagAt] |= 1 << bit
          pos += bestLen
        } else {
          body.push(chunk[pos++])
        }
      }
    }
    const header = 0x8000 | 0x3000 | (body.length + 2 - 3)
    out.push(header & 0xff, header >> 8, ...body)
    if (data.length === 0) break
  }
  return new Uint8Array(out)
}

interface CfbNode { name: string, data?: Uint8Array, children?: CfbNode[] }

function cfb(top: CfbNode[]): Uint8Array {
  const S = 512
  const entries: { name: string, kind: number, child: number, right: number, start: number, size: number }[] = []
  entries.push({ name: 'Root Entry', kind: 5, child: -1, right: -1, start: -2, size: 0 })
  const regular: { id: number, data: Uint8Array }[] = []
  const mini: { id: number, data: Uint8Array }[] = []
  const add = (nodes: CfbNode[]): number => {
    let first = -1
    let prev = -1
    for (const n of nodes) {
      const id = entries.length
      entries.push({ name: n.name, kind: n.children ? 1 : 2, child: -1, right: -1, start: -2, size: n.data?.length ?? 0 })
      if (n.children) entries[id].child = add(n.children)
      else if (n.data!.length >= 4096) regular.push({ id, data: n.data! })
      else if (n.data!.length > 0) mini.push({ id, data: n.data! })
      if (prev >= 0) entries[prev].right = id
      else first = id
      prev = id
    }
    return first
  }
  entries[0].child = add(top)
  // Mini stream and mini FAT.
  const miniParts: Uint8Array[] = []
  const minifat: number[] = []
  for (const m of mini) {
    const n = Math.ceil(m.data.length / 64)
    entries[m.id].start = minifat.length
    for (let k = 0; k < n; k++) minifat.push(k === n - 1 ? 0xfffffffe : minifat.length + 1)
    miniParts.push(concat(m.data, new Uint8Array(n * 64 - m.data.length)))
  }
  const miniStream = concat(...miniParts)
  // Chains of regular sectors, laid out contiguously.
  const chains: Uint8Array[] = []
  const chainOwner: number[] = []
  const pad = (b: Uint8Array) => concat(b, new Uint8Array((S - (b.length % S)) % S))
  for (const r of regular) {
    chains.push(pad(r.data))
    chainOwner.push(r.id)
  }
  if (miniStream.length > 0) {
    chains.push(pad(miniStream))
    chainOwner.push(0)
  }
  const minifatBytes = new Uint8Array(Math.ceil((minifat.length * 4) / S) * S).fill(0xff)
  new DataView(minifatBytes.buffer).setUint32(0, 0, true)
  minifat.forEach((v, i) => new DataView(minifatBytes.buffer).setUint32(i * 4, v, true))
  if (minifat.length > 0) {
    chains.push(minifatBytes)
    chainOwner.push(-3)
  }
  const dirBytes = new Uint8Array(Math.ceil((entries.length * 128) / S) * S)
  chains.push(dirBytes)
  chainOwner.push(-4)
  const dataSectors = chains.reduce((n, c) => n + c.length / S, 0)
  let fatSectors = 1
  while (Math.ceil((dataSectors + fatSectors) / 128) > fatSectors) fatSectors++
  const fat = new Uint32Array(fatSectors * 128).fill(0xffffffff)
  let sector = 0
  const starts: number[] = []
  for (const c of chains) {
    const n = c.length / S
    starts.push(sector)
    for (let k = 0; k < n; k++) fat[sector + k] = k === n - 1 ? 0xfffffffe : sector + k + 1
    sector += n
  }
  const fatStart = sector
  for (let k = 0; k < fatSectors; k++) fat[fatStart + k] = 0xfffffffd
  chains.forEach((_, i) => {
    const o = chainOwner[i]
    if (o > 0) entries[o].start = starts[i]
    if (o === 0) {
      entries[0].start = starts[i]
      entries[0].size = miniStream.length
    }
  })
  const minifatStart = chainOwner.indexOf(-3) >= 0 ? starts[chainOwner.indexOf(-3)] : 0xfffffffe
  const dirStart = starts[chainOwner.indexOf(-4)]
  const dv = new DataView(dirBytes.buffer)
  entries.forEach((e, i) => {
    const o = i * 128
    const name = e.name
    for (let k = 0; k < name.length && k < 31; k++) dv.setUint16(o + k * 2, name.charCodeAt(k), true)
    dv.setUint16(o + 64, (Math.min(name.length, 31) + 1) * 2, true)
    dirBytes[o + 66] = e.kind
    dirBytes[o + 67] = 1
    dv.setUint32(o + 68, 0xffffffff, true)
    dv.setUint32(o + 72, e.right < 0 ? 0xffffffff : e.right, true)
    dv.setUint32(o + 76, e.child < 0 ? 0xffffffff : e.child, true)
    dv.setUint32(o + 116, e.start < 0 ? 0xfffffffe : e.start, true)
    dv.setUint32(o + 120, e.size, true)
  })
  const header = new Uint8Array(512)
  const hv = new DataView(header.buffer)
  header.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
  hv.setUint16(24, 0x3e, true)
  hv.setUint16(26, 3, true)
  hv.setUint16(28, 0xfffe, true)
  hv.setUint16(30, 9, true)
  hv.setUint16(32, 6, true)
  hv.setUint32(44, fatSectors, true)
  hv.setUint32(48, dirStart, true)
  hv.setUint32(56, 4096, true)
  hv.setUint32(60, minifatStart, true)
  hv.setUint32(64, Math.ceil((minifat.length * 4) / S), true)
  hv.setUint32(68, 0xfffffffe, true)
  hv.setUint32(72, 0, true)
  for (let k = 0; k < 109; k++) hv.setUint32(76 + k * 4, k < fatSectors ? fatStart + k : 0xffffffff, true)
  const fatBytes = new Uint8Array(fat.buffer)
  return concat(header, ...chains, fatBytes)
}

function dirRecord(id: number, data: Uint8Array): Uint8Array {
  return concat(u16(id), u32(data.length), data)
}

const macroSource = enc.encode('Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n  Shell "cmd /c powershell -enc AAAA", 0\r\n  MsgBox "hello hello hello hello"\r\nEnd Sub\r\n')
const moduleCache = new Uint8Array(37).fill(0xcc)
const moduleStream = concat(moduleCache, ovbaCompress(macroSource))
const dirStream = ovbaCompress(concat(
  dirRecord(0x0001, u32(1)),
  dirRecord(0x0003, u16(1252)),
  dirRecord(0x0004, enc.encode('VBAProject')),
  u16(0x0009), u32(4), u32(0x5f), u16(0x0b),
  dirRecord(0x000f, u16(1)),
  dirRecord(0x0013, u16(0xffff)),
  dirRecord(0x0019, enc.encode('Module1')),
  dirRecord(0x0047, new Uint8Array([0x4d, 0, 0x6f, 0, 0x64, 0, 0x75, 0, 0x6c, 0, 0x65, 0, 0x31, 0])),
  dirRecord(0x001a, enc.encode('Module1')),
  dirRecord(0x0032, new Uint8Array([0x4d, 0, 0x6f, 0, 0x64, 0, 0x75, 0, 0x6c, 0, 0x65, 0, 0x31, 0])),
  dirRecord(0x001c, new Uint8Array(0)),
  dirRecord(0x0031, u32(moduleCache.length)),
  dirRecord(0x001e, u32(0)),
  dirRecord(0x002c, u16(0)),
  dirRecord(0x0021, new Uint8Array(0)),
  dirRecord(0x002b, new Uint8Array(0)),
  dirRecord(0x0010, new Uint8Array(0)),
))
const wordDoc = concat(plain(6000, 21), evil)
archive('macro.doc', cfb([
  { name: 'WordDocument', data: wordDoc },
  { name: '\x05SummaryInformation', data: plain(300, 22) },
  { name: 'Macros', children: [
    { name: 'PROJECT', data: enc.encode('ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=Module1\r\n') },
    { name: 'VBA', children: [
      { name: '_VBA_PROJECT', data: new Uint8Array([0xcc, 0x61, 0xff, 0xff, 0x00, 0x00, 0x00]) },
      { name: 'dir', data: dirStream },
      { name: 'Module1', data: moduleStream },
    ] },
  ] },
]), [
  { path: 'WordDocument', data: wordDoc },
  { path: '?SummaryInformation', data: plain(300, 22) },
  { path: 'Macros/VBA/Module1', data: moduleStream },
  { path: 'Macros/VBA/macro/Module1', data: macroSource },
])

// OOXML (ECMA-376 / OPC): a macro-enabled .docm whose vbaProject.bin is a compound file with
// the VBA storage at its root, an external template relationship and an embedded object; and
// a plain .docx for contrast.
const vbaProjectBin = cfb([
  { name: 'PROJECT', data: enc.encode('ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=Module1\r\n') },
  { name: 'VBA', children: [
    { name: '_VBA_PROJECT', data: new Uint8Array([0xcc, 0x61, 0xff, 0xff, 0x00, 0x00, 0x00]) },
    { name: 'dir', data: dirStream },
    { name: 'Module1', data: moduleStream },
  ] },
])
const ctMacro = enc.encode('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>')
const ctPlain = enc.encode('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
const rootRels = enc.encode('<?xml version="1.0" encoding="UTF-8"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
const docRels = enc.encode('<?xml version="1.0" encoding="UTF-8"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://templates.example/evil.dotm" TargetMode="External"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/></Relationships>')
const docXml = enc.encode('<?xml version="1.0" encoding="UTF-8"?>\n<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Enable content</w:t></w:r></w:p></w:body></w:document>')
archive('macro.docm', zipBytes([
  { name: '[Content_Types].xml', data: ctMacro },
  { name: '_rels/.rels', data: rootRels },
  { name: 'word/document.xml', data: docXml },
  { name: 'word/_rels/document.xml.rels', data: docRels },
  { name: 'word/vbaProject.bin', data: vbaProjectBin },
  { name: 'word/embeddings/oleObject1.bin', data: evil, method: 0 },
]), [
  { path: 'word/document.xml', data: docXml },
  { path: 'word/vbaProject.bin', data: vbaProjectBin },
  { path: 'word/vbaProject.bin/VBA/macro/Module1', data: macroSource },
  { path: 'word/embeddings/oleObject1.bin', data: evil },
])
archive('plain.docx', zipBytes([
  { name: '[Content_Types].xml', data: ctPlain },
  { name: '_rels/.rels', data: rootRels },
  { name: 'word/document.xml', data: docXml },
]), [{ path: 'word/document.xml', data: docXml }])

// ---------------------------------------------------------------------------------------------
// Executables (P5.05 PE, P5.06 ELF and Mach-O), built from the format specifications.

interface Exe { name: string, file: string, entry: number | null, sections: number, imphash: string, impsize: number, members: Member[], malformed: boolean }
const exes: Exe[] = []
// Executable fixtures are stored behind a text prefix so they are not executables on disk (CI
// rejects tracked binaries by type); fixtures.zig strips it when embedding.
const exePrefix = 'zav fixture, not an executable\n'

function exe(name: string, bytes: Uint8Array, o: { entry: number | null, sections: number, imphash?: string, impsize?: number, members?: Member[], malformed?: boolean }) {
  const file = `exe-${name}.bin`
  writeFileSync(join(dir, file), concat(enc.encode(exePrefix), bytes))
  exes.push({ name, file, entry: o.entry, sections: o.sections, imphash: o.imphash ?? '', impsize: o.impsize ?? 0, members: o.members ?? [], malformed: o.malformed ?? false })
}

interface PeOptions {
  is64?: boolean
  entryRva?: number
  overlay?: Uint8Array
  resource?: Uint8Array
  sectionChars?: number[]
  truncateAt?: number
  sectionCount?: number
  overlapSections?: boolean
}

/**
 * A PE with .text, .rdata (imports: kernel32!ExitProcess, user32!MessageBoxA) and .rsrc (one
 * RCDATA resource holding `resource`), then `overlay`. FileAlignment 0x200, SectionAlignment
 * 0x1000. Its import hash is the ClamAV documentation's clam.exe example.
 */
function buildPe(o: PeOptions = {}): Uint8Array {
  const is64 = o.is64 ?? false
  const optSize = is64 ? 240 : 224
  const peOff = 0x80
  const tableOff = peOff + 24 + optSize
  const fileAlign = 0x200
  const align = (n: number) => Math.ceil(n / fileAlign) * fileAlign

  // .text
  const text = new Uint8Array(0x100)
  text.set([0x55, 0x89, 0xe5, 0x6a, 0x00, 0xe8, 0, 0, 0, 0, 0xc3], 0x10)
  // .rdata at RVA 0x2000: descriptors, lookup tables, hint/name entries, DLL names.
  const rd = new Uint8Array(0x200)
  const rdv = new DataView(rd.buffer)
  const thunk = is64 ? 8 : 4
  const iltK = 0x60
  const iltU = iltK + 2 * thunk
  const hnExit = 0x100
  const hnMsg = 0x110
  const nameK = 0x130
  const nameU = 0x140
  const setThunk = (off: number, v: number) => is64 ? rdv.setBigUint64(off, BigInt(v), true) : rdv.setUint32(off, v, true)
  // kernel32 descriptor
  rdv.setUint32(0, 0x2000 + iltK, true)
  rdv.setUint32(12, 0x2000 + nameK, true)
  rdv.setUint32(16, 0x2000 + iltK, true)
  // user32 descriptor
  rdv.setUint32(20, 0x2000 + iltU, true)
  rdv.setUint32(32, 0x2000 + nameU, true)
  rdv.setUint32(36, 0x2000 + iltU, true)
  setThunk(iltK, 0x2000 + hnExit)
  setThunk(iltU, 0x2000 + hnMsg)
  rd.set(enc.encode('\x00\x00ExitProcess\x00'), hnExit)
  rd.set(enc.encode('\x00\x00MessageBoxA\x00'), hnMsg)
  rd.set(enc.encode('KERNEL32.dll\x00'), nameK)
  rd.set(enc.encode('USER32.dll\x00'), nameU)
  // .rsrc at RVA 0x3000: root -> type 10 (RCDATA) -> id 101 -> language 1033 -> data entry.
  const payload = o.resource ?? new Uint8Array(0)
  const rs = new Uint8Array(0x60 + payload.length)
  const rsv = new DataView(rs.buffer)
  const dirAt = (off: number, id: number, target: number) => {
    rsv.setUint16(off + 14, 1, true)
    rsv.setUint32(off + 16, id, true)
    rsv.setUint32(off + 20, target, true)
  }
  dirAt(0x00, 10, 0x80000000 | 0x18)
  dirAt(0x18, 101, 0x80000000 | 0x30)
  dirAt(0x30, 1033, 0x48)
  rsv.setUint32(0x48, 0x3000 + 0x60, true)
  rsv.setUint32(0x4c, payload.length, true)
  rs.set(payload, 0x60)

  const bodies = [text, rd, rs]
  const names = ['.text', '.rdata', '.rsrc']
  const chars = o.sectionChars ?? [0x60000020, 0x40000040, 0x40000040]
  const raws: number[] = []
  let raw = 0x200
  for (const b of bodies) {
    raws.push(raw)
    raw += align(b.length)
  }
  if (o.overlapSections) raws[1] = raws[0]
  const sizeOfImage = 0x4000 + Math.ceil(rs.length / 0x1000) * 0x1000

  const h = new Uint8Array(0x200)
  const hv = new DataView(h.buffer)
  h.set(enc.encode('MZ'), 0)
  hv.setUint32(0x3c, peOff, true)
  h.set(enc.encode('PE\0\0'), peOff)
  const coff = peOff + 4
  hv.setUint16(coff, is64 ? 0x8664 : 0x14c, true)
  hv.setUint16(coff + 2, o.sectionCount ?? 3, true)
  hv.setUint32(coff + 4, 0x5f000000, true)
  hv.setUint16(coff + 16, optSize, true)
  hv.setUint16(coff + 18, is64 ? 0x22 : 0x102, true)
  const opt = peOff + 24
  hv.setUint16(opt, is64 ? 0x20b : 0x10b, true)
  hv.setUint32(opt + 4, 0x200, true)
  hv.setUint32(opt + 16, o.entryRva ?? 0x1010, true)
  hv.setUint32(opt + 20, 0x1000, true)
  if (is64) hv.setBigUint64(opt + 24, 0x140000000n, true)
  else hv.setUint32(opt + 28, 0x400000, true)
  hv.setUint32(opt + 32, 0x1000, true)
  hv.setUint32(opt + 36, fileAlign, true)
  hv.setUint16(opt + 40, 6, true)
  hv.setUint16(opt + 48, 6, true)
  hv.setUint32(opt + 56, sizeOfImage, true)
  hv.setUint32(opt + 60, 0x200, true)
  hv.setUint16(opt + 68, 2, true)
  const ndirs = is64 ? opt + 108 : opt + 92
  hv.setUint32(ndirs, 16, true)
  hv.setUint32(ndirs + 4 + 8, 0x2000, true)
  hv.setUint32(ndirs + 4 + 12, 40, true)
  hv.setUint32(ndirs + 4 + 16, 0x3000, true)
  hv.setUint32(ndirs + 4 + 20, rs.length, true)
  for (let i = 0; i < 3; i++) {
    const t = tableOff + i * 40
    h.set(enc.encode(names[i]), t)
    hv.setUint32(t + 8, bodies[i].length, true)
    hv.setUint32(t + 12, 0x1000 * (i + 1), true)
    hv.setUint32(t + 16, align(bodies[i].length), true)
    hv.setUint32(t + 20, raws[i], true)
    hv.setUint32(t + 36, chars[i], true)
  }
  const parts: Uint8Array[] = [h]
  for (const b of bodies) parts.push(concat(b, new Uint8Array(align(b.length) - b.length)))
  if (o.overlay) parts.push(o.overlay)
  const out = concat(...parts)
  return o.truncateAt ? out.slice(0, o.truncateAt) : out
}

const clamImp = { imphash: '98c88d882f01a3f6ac1e5f7dfd761624', impsize: 39 }
const overlayZip = zipBytes([{ name: 'a.txt', data: fileA }, { name: 'eicar.com', data: evil }])
exe('pe32.exe', buildPe({ resource: eicarZip, overlay: overlayZip }), {
  entry: 0x210,
  sections: 3,
  ...clamImp,
  members: [
    { path: 'resource/10/101/1033', data: eicarZip },
    { path: 'resource/10/101/1033/eicar.com', data: evil },
    { path: 'overlay', data: overlayZip },
    { path: 'overlay/a.txt', data: fileA },
    { path: 'overlay/eicar.com', data: evil },
  ],
})
exe('pe64.exe', buildPe({ is64: true }), { entry: 0x210, sections: 3, ...clamImp })
exe('pe-ep-outside.exe', buildPe({ entryRva: 0x9000 }), { entry: null, sections: 3, ...clamImp })
exe('pe-wx.exe', buildPe({ sectionChars: [0xe0000020, 0x40000040, 0x40000040] }), { entry: 0x210, sections: 3, ...clamImp })
exe('pe-overlap.exe', buildPe({ overlapSections: true }), { entry: 0x210, sections: 3 })
exe('pe-truncated.exe', buildPe({ truncateAt: 0x300 }), { entry: 0x210, sections: 3, malformed: true })
exe('pe-many-sections.exe', buildPe({ sectionCount: 0xffff }), { entry: 0x210, sections: 12, malformed: true })

/** An ELF executable: PT_LOAD text (R+X) at 0x400000, PT_LOAD data (R+W), four sections. */
function buildElf(o: { is64?: boolean, big?: boolean, entry?: number, relocatable?: boolean, truncateAt?: number, wx?: boolean } = {}): Uint8Array {
  const is64 = o.is64 ?? true
  const le = !(o.big ?? false)
  const b = new Uint8Array(0x480)
  const v = new DataView(b.buffer)
  const w16 = (off: number, x: number) => v.setUint16(off, x, le)
  const w32 = (off: number, x: number) => v.setUint32(off, x, le)
  const wA = (off: number, x: number) => is64 ? v.setBigUint64(off, BigInt(x), le) : v.setUint32(off, x, le)
  b.set([0x7f, 0x45, 0x4c, 0x46, is64 ? 2 : 1, le ? 1 : 2, 1, 0])
  const relocatable = o.relocatable ?? false
  w16(16, relocatable ? 1 : 2)
  w16(18, is64 ? 62 : 20)
  w32(20, 1)
  const A = is64 ? 8 : 4
  const ehsize = is64 ? 64 : 52
  const phsize = is64 ? 56 : 32
  const shsize = is64 ? 64 : 40
  const entryOff = 24
  wA(entryOff, relocatable ? 0 : (o.entry ?? 0x400100))
  const phoff = ehsize
  const shoff = 0x340
  wA(entryOff + A, relocatable ? 0 : phoff)
  wA(entryOff + 2 * A, shoff)
  const tail = entryOff + 3 * A
  w32(tail, 0)
  w16(tail + 4, ehsize)
  w16(tail + 6, phsize)
  w16(tail + 8, relocatable ? 0 : 2)
  w16(tail + 10, shsize)
  w16(tail + 12, 4)
  w16(tail + 14, 3)
  const phdr = (i: number, flags: number, off: number, vaddr: number, size: number) => {
    const p = phoff + i * phsize
    w32(p, 1)
    if (is64) {
      w32(p + 4, flags)
      wA(p + 8, off)
      wA(p + 16, vaddr)
      wA(p + 24, vaddr)
      wA(p + 32, size)
      wA(p + 40, size)
      wA(p + 48, 0x1000)
    } else {
      w32(p + 4, off)
      w32(p + 8, vaddr)
      w32(p + 12, vaddr)
      w32(p + 16, size)
      w32(p + 20, size)
      w32(p + 24, flags)
      w32(p + 28, 0x1000)
    }
  }
  if (!relocatable) {
    phdr(0, o.wx ? 7 : 5, 0, 0x400000, 0x200)
    phdr(1, 6, 0x200, 0x600200, 0x100)
  }
  b.set([0x48, 0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05], 0x100)
  const strtab = enc.encode('\0.text\0.data\0.shstrtab\0')
  b.set(strtab, 0x300)
  const shdr = (i: number, name: number, type: number, flags: number, addr: number, off: number, size: number) => {
    const p = shoff + i * shsize
    w32(p, name)
    w32(p + 4, type)
    wA(p + 8, flags)
    wA(p + 8 + A, addr)
    wA(p + 8 + 2 * A, off)
    wA(p + 8 + 3 * A, size)
  }
  shdr(1, 1, 1, 6, relocatable ? 0 : 0x400100, 0x100, 0x40)
  shdr(2, 7, 1, 3, relocatable ? 0 : 0x600200, 0x200, 0x100)
  shdr(3, 13, 3, 0, 0, 0x300, strtab.length)
  return o.truncateAt ? b.slice(0, o.truncateAt) : b
}
exe('x86_64.elf', buildElf(), { entry: 0x100, sections: 4 })
exe('ppc32-be.elf', buildElf({ is64: false, big: true }), { entry: 0x100, sections: 4 })
exe('i386-32.elf', buildElf({ is64: false }), { entry: 0x100, sections: 4 })
exe('relocatable.elf', buildElf({ relocatable: true }), { entry: null, sections: 4 })
exe('ep-outside.elf', buildElf({ entry: 0x900000 }), { entry: null, sections: 4 })
exe('truncated.elf', buildElf({ truncateAt: 0x90 }), { entry: 0x100, sections: 0, malformed: true })
exe('wx.elf', buildElf({ wx: true }), { entry: 0x100, sections: 4 })

/**
 * A thin Mach-O: one text segment (file 0..0x400 at `vmaddr`) with a __text section at 0x300,
 * entered through LC_MAIN or an LC_UNIXTHREAD thread state whose PC is vmaddr + 0x300.
 */
function buildMachO(o: { cpu: 'x86_64' | 'i386' | 'arm64' | 'ppc', main?: boolean, entryoff?: number, initprot?: number }): Uint8Array {
  const is64 = o.cpu === 'x86_64' || o.cpu === 'arm64'
  const le = o.cpu !== 'ppc'
  const cputype = { x86_64: 0x01000007, i386: 7, arm64: 0x0100000c, ppc: 18 }[o.cpu]
  const vmaddr = is64 ? 0x100000000 : 0x1000
  const b = new Uint8Array(0x400)
  const v = new DataView(b.buffer)
  const w32 = (off: number, x: number) => v.setUint32(off, x >>> 0, le)
  const w64 = (off: number, x: number) => v.setBigUint64(off, BigInt(x), le)
  w32(0, is64 ? 0xfeedfacf : 0xfeedface)
  w32(4, cputype)
  w32(12, 2)
  let off = is64 ? 32 : 28
  const start = off
  // Segment with one section.
  const segLen = is64 ? 72 : 56
  const sectLen = is64 ? 80 : 68
  w32(off, is64 ? 0x19 : 0x1)
  w32(off + 4, segLen + sectLen)
  b.set(enc.encode('__TEXT'), off + 8)
  if (is64) {
    w64(off + 24, vmaddr)
    w64(off + 32, 0x1000)
    w64(off + 40, 0)
    w64(off + 48, 0x400)
    w32(off + 56, 7)
    w32(off + 60, o.initprot ?? 5)
    w32(off + 64, 1)
  } else {
    w32(off + 24, vmaddr)
    w32(off + 28, 0x1000)
    w32(off + 32, 0)
    w32(off + 36, 0x400)
    w32(off + 40, 7)
    w32(off + 44, o.initprot ?? 5)
    w32(off + 48, 1)
  }
  const sect = off + segLen
  b.set(enc.encode('__text'), sect)
  b.set(enc.encode('__TEXT'), sect + 16)
  if (is64) {
    w64(sect + 32, vmaddr + 0x300)
    w64(sect + 40, 0x80)
    w32(sect + 48, 0x300)
  } else {
    w32(sect + 32, vmaddr + 0x300)
    w32(sect + 36, 0x80)
    w32(sect + 40, 0x300)
  }
  off += segLen + sectLen
  let ncmds = 1
  if (o.main) {
    w32(off, 0x80000028)
    w32(off + 4, 24)
    w64(off + 8, o.entryoff ?? 0x300)
    off += 24
  } else {
    const flavor = { x86_64: 4, i386: 1, arm64: 6, ppc: 1 }[o.cpu]
    const words = { x86_64: 42, i386: 16, arm64: 68, ppc: 40 }[o.cpu]
    w32(off, 0x5)
    w32(off + 4, 16 + words * 4)
    w32(off + 8, flavor)
    w32(off + 12, words)
    const pc = vmaddr + 0x300
    const state = off + 16
    if (o.cpu === 'x86_64') w64(state + 16 * 8, pc)
    if (o.cpu === 'arm64') w64(state + 32 * 8, pc)
    if (o.cpu === 'i386') w32(state + 10 * 4, pc)
    if (o.cpu === 'ppc') w32(state, pc)
    off += 16 + words * 4
  }
  ncmds++
  w32(16, ncmds)
  w32(20, off - start)
  b.set([0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3], 0x300)
  return b
}
const machoX64 = buildMachO({ cpu: 'x86_64', main: true })
const machoArm64 = buildMachO({ cpu: 'arm64' })
exe('x86_64-main.macho', machoX64, { entry: 0x300, sections: 1 })
exe('arm64-thread.macho', machoArm64, { entry: 0x300, sections: 1 })
exe('i386-thread.macho', buildMachO({ cpu: 'i386' }), { entry: 0x300, sections: 1 })
exe('ppc-be-thread.macho', buildMachO({ cpu: 'ppc' }), { entry: 0x300, sections: 1 })
exe('ep-outside.macho', buildMachO({ cpu: 'x86_64', main: true, entryoff: 0x10000 }), { entry: null, sections: 1 })
exe('wx.macho', buildMachO({ cpu: 'x86_64', main: true, initprot: 7 }), { entry: 0x300, sections: 1 })

function fat(slicesIn: { cpu: number, data: Uint8Array }[]): Uint8Array {
  const head = new Uint8Array(0x1000)
  const v = new DataView(head.buffer)
  v.setUint32(0, 0xcafebabe)
  v.setUint32(4, slicesIn.length)
  const parts: Uint8Array[] = [head]
  let off = 0x1000
  slicesIn.forEach((sl, i) => {
    const e = 8 + i * 20
    v.setUint32(e, sl.cpu)
    v.setUint32(e + 8, off)
    v.setUint32(e + 12, sl.data.length)
    v.setUint32(e + 16, 12)
    const padded = concat(sl.data, new Uint8Array((0x1000 - (sl.data.length % 0x1000)) % 0x1000))
    parts.push(padded)
    off += padded.length
  })
  return concat(...parts)
}
const evilMacho = concat(machoArm64.slice(0, 0x380), evil, new Uint8Array(0x400 - 0x380 - evil.length))
exe('universal.fat', fat([{ cpu: 0x01000007, data: machoX64 }, { cpu: 0x0100000c, data: evilMacho }]), {
  entry: null,
  sections: 0,
  members: [{ path: 'slice/x86_64', data: machoX64 }, { path: 'slice/arm64', data: evilMacho }],
})

// ---------------------------------------------------------------------------------------------
// Phase-three containers and unpackers (P5.18, P5.19): see containers.ts.

containers.build({ archive, exe, concat, plain, crc32, run, py, deflateRaw: d => zlib.deflateRawSync(d), evil, fileA, fileB })

// ---------------------------------------------------------------------------------------------
// fixtures.zig

const lines = [
  '//! Generated by make-fixtures.ts; do not edit. Every vector embeds a file in this directory with',
  '//! the length and CRC-32 of the bytes it must decode to.',
  '',
  'pub const Vector = struct { name: []const u8, compressed: []const u8, plain_len: usize, plain_crc: u32 };',
  '',
]
for (const [group, vs] of Object.entries(groups)) {
  lines.push(`pub const ${group}_vectors = [_]Vector{`)
  for (const v of vs) lines.push(`    .{ .name = "${v.name}", .compressed = @embedFile("${v.file}"), .plain_len = ${v.plainLen}, .plain_crc = 0x${v.plainCrc.toString(16).padStart(8, '0')} },`)
  lines.push('};', '')
}
lines.push(
  'pub const Member = struct { path: []const u8, len: usize, crc: u32 };',
  'pub const Archive = struct { name: []const u8, bytes: []const u8, members: []const Member, malformed: bool };',
  '',
  'pub const archives = [_]Archive{',
)
for (const a of archives) {
  const head = `    .{ .name = "${a.name}", .bytes = @embedFile("${a.file}"), .malformed = ${a.malformed}, .members = &.{`
  if (a.members.length === 0) {
    lines.push(`${head}} },`)
    continue
  }
  lines.push(head)
  for (const m of a.members) lines.push(`        .{ .path = "${m.path}", .len = ${m.data.length}, .crc = 0x${crc32(m.data).toString(16).padStart(8, '0')} },`)
  lines.push('    } },')
}
lines.push('};', '')
lines.push(
  'pub const Exe = struct { name: []const u8, bytes: []const u8, entry: ?u64, sections: usize, imphash: []const u8, impsize: u64, members: []const Member, malformed: bool };',
  '',
  `/// Stored in front of each executable fixture so the files are not executables on disk.`,
  `pub const exe_prefix = "${exePrefix.replace('\n', '\\n')}";`,
  '',
  'pub const exes = [_]Exe{',
)
for (const e of exes) {
  const head = `    .{ .name = "${e.name}", .bytes = @embedFile("${e.file}")[exe_prefix.len..], .entry = ${e.entry ?? 'null'}, .sections = ${e.sections}, .imphash = "${e.imphash}", .impsize = ${e.impsize}, .malformed = ${e.malformed}, .members = &.{`
  if (e.members.length === 0) {
    lines.push(`${head}} },`)
    continue
  }
  lines.push(head)
  for (const m of e.members) lines.push(`        .{ .path = "${m.path}", .len = ${m.data.length}, .crc = 0x${crc32(m.data).toString(16).padStart(8, '0')} },`)
  lines.push('    } },')
}
lines.push('};', '')
writeFileSync(join(dir, 'fixtures.zig'), lines.join('\n'))
console.log('wrote', Object.values(groups).flat().length, 'vectors')
