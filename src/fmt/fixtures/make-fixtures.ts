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
writeFileSync(join(dir, 'fixtures.zig'), lines.join('\n'))
console.log('wrote', Object.values(groups).flat().length, 'vectors')
