// Document fixtures (P5.12 to P5.14): PDF, RTF and 7z, built byte by byte from their
// specifications so every malformed and evasive variant is exact.
//
//   bun src/fmt/fixtures/documents.ts
//
// Writes docs/*.bin and docs.zig: every document with the children a scan must produce (path,
// length, CRC-32) and the notices it must raise. Compression comes from node:zlib (deflate) and
// Python's lzma module in raw mode (LZMA and LZMA2 coder streams for 7z). Encryption uses
// node:crypto (MD5, SHA-2, AES); RC4 is implemented here.
import { spawnSync } from 'node:child_process'
import { createCipheriv, createHash } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import zlib from 'node:zlib'

const here = dirname(new URL(import.meta.url).pathname)
const out = join(here, 'docs')
mkdirSync(out, { recursive: true })

const enc = new TextEncoder()
const eicar = enc.encode('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')

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
function concat(...parts: (Uint8Array | string)[]): Uint8Array {
  const bufs = parts.map(p => (typeof p === 'string' ? latin1(p) : p))
  const o = new Uint8Array(bufs.reduce((n, p) => n + p.length, 0))
  let i = 0
  for (const p of bufs) {
    o.set(p, i)
    i += p.length
  }
  return o
}
function latin1(s: string): Uint8Array {
  const o = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 0xff
  return o
}
function hex(b: Uint8Array): string {
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
}
function py(code: string, input: Uint8Array): Uint8Array {
  const r = spawnSync('python3', ['-c', `import sys, lzma\ndata = sys.stdin.buffer.read()\n${code}`], { input, maxBuffer: 1 << 28 })
  if (r.status !== 0) throw new Error(`python failed: ${r.stderr}`)
  return new Uint8Array(r.stdout)
}

interface Member { path: string, data: Uint8Array }
interface Doc { name: string, file: string, members: Member[], notices: string[] }
const docs: Doc[] = []
function doc(name: string, bytes: Uint8Array, members: Member[], notices: string[] = []) {
  const file = `${name}.bin`
  writeFileSync(join(out, file), bytes)
  docs.push({ name, file, members, notices })
}

// ---------------------------------------------------------------------------------------------
// Encoders for the PDF filters.

function asciiHex(d: Uint8Array): Uint8Array {
  // Line breaks and an odd final digit, as permitted.
  let s = ''
  for (let i = 0; i < d.length; i++) s += d[i].toString(16).padStart(2, '0') + (i % 16 === 15 ? '\n' : '')
  return latin1(`${s}>`)
}
function ascii85(d: Uint8Array): Uint8Array {
  let s = ''
  for (let i = 0; i < d.length; i += 4) {
    const chunk = d.slice(i, i + 4)
    const n = chunk.length
    const p = new Uint8Array(4)
    p.set(chunk)
    let v = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0
    if (v === 0 && n === 4) {
      s += 'z'
      continue
    }
    const c: string[] = []
    for (let k = 0; k < 5; k++) {
      c.unshift(String.fromCharCode(33 + (v % 85)))
      v = Math.floor(v / 85)
    }
    s += c.slice(0, n + 1).join('')
    if (i % 60 === 56) s += '\n'
  }
  return latin1(`${s}~>`)
}
function runLength(d: Uint8Array): Uint8Array {
  const o: number[] = []
  let i = 0
  while (i < d.length) {
    let r = 1
    while (i + r < d.length && d[i + r] === d[i] && r < 128) r++
    if (r >= 3) {
      o.push(257 - r, d[i])
      i += r
      continue
    }
    const start = i
    while (i < d.length && i - start < 128 && !(i + 2 < d.length && d[i] === d[i + 1] && d[i] === d[i + 2])) i++
    o.push(i - start - 1, ...d.slice(start, i))
  }
  o.push(128)
  return new Uint8Array(o)
}
function lzw(d: Uint8Array, early = 1): Uint8Array {
  const o: number[] = []
  let bits = 0
  let nbits = 0
  let width = 9
  let next = 258
  const dict = new Map<string, number>()
  const put = (code: number) => {
    bits = (bits << width) | code
    nbits += width
    while (nbits >= 8) {
      nbits -= 8
      o.push((bits >>> nbits) & 0xff)
    }
    bits &= (1 << nbits) - 1
  }
  const grow = () => {
    if (next < 4096) {
      next++
      if (next + early > 1 << width && width < 12) width++
    }
  }
  put(256)
  let w = ''
  let wCode = -1
  for (const b of d) {
    const c = String.fromCharCode(b)
    if (wCode < 0) {
      w = c
      wCode = b
      continue
    }
    const cand = w + c
    const hit = dict.get(cand)
    if (hit !== undefined) {
      w = cand
      wCode = hit
      continue
    }
    put(wCode)
    if (next < 4096) dict.set(cand, next)
    grow()
    w = c
    wCode = b
  }
  if (wCode >= 0) {
    put(wCode)
    grow()
  }
  put(257)
  if (nbits > 0) o.push((bits << (8 - nbits)) & 0xff)
  return new Uint8Array(o)
}
/** PNG "Up" predictor rows (filter byte 2) over `columns`-byte rows. */
function pngUp(d: Uint8Array, columns: number): Uint8Array {
  const rows = Math.ceil(d.length / columns)
  const o = new Uint8Array(rows * (columns + 1))
  const prev = new Uint8Array(columns)
  for (let r = 0; r < rows; r++) {
    o[r * (columns + 1)] = 2
    for (let c = 0; c < columns; c++) {
      const v = d[r * columns + c] ?? 0
      o[r * (columns + 1) + 1 + c] = (v - prev[c]) & 0xff
      prev[c] = v
    }
  }
  return o
}

// ---------------------------------------------------------------------------------------------
// PDF writer with optional standard-handler encryption.

function rc4(key: Uint8Array, data: Uint8Array): Uint8Array {
  const s = new Uint8Array(256)
  for (let i = 0; i < 256; i++) s[i] = i
  let j = 0
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff
    ;[s[i], s[j]] = [s[j], s[i]]
  }
  const o = new Uint8Array(data.length)
  let i = 0
  j = 0
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 0xff
    j = (j + s[i]) & 0xff
    ;[s[i], s[j]] = [s[j], s[i]]
    o[k] = data[k] ^ s[(s[i] + s[j]) & 0xff]
  }
  return o
}
const md5 = (...p: Uint8Array[]) => new Uint8Array(createHash('md5').update(concat(...p)).digest())
const pad = new Uint8Array([0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A])
function padPw(pw: string): Uint8Array {
  return concat(latin1(pw), pad).slice(0, 32)
}
function aesCbc(bits: 128 | 256, key: Uint8Array, iv: Uint8Array, data: Uint8Array, padding = true): Uint8Array {
  const c = createCipheriv(`aes-${bits}-cbc`, key, iv)
  c.setAutoPadding(padding)
  return new Uint8Array(Buffer.concat([c.update(data), c.final()]))
}
function hash2B(pw: Uint8Array, salt: Uint8Array, udata: Uint8Array): Uint8Array {
  let k = new Uint8Array(createHash('sha256').update(concat(pw, salt, udata)).digest())
  for (let round = 0; ; round++) {
    const k1 = concat(...Array(64).fill(concat(pw, k, udata)))
    const e = aesCbc(128, k.slice(0, 16), k.slice(16, 32), k1, false)
    let sum = 0
    for (let i = 0; i < 16; i++) sum += e[i]
    k = new Uint8Array(createHash(['sha256', 'sha384', 'sha512'][sum % 3]).update(e).digest())
    if (round >= 63 && e[e.length - 1] <= round - 31) break
  }
  return k.slice(0, 32)
}

interface Security {
  revision: 3 | 4 | 6
  user: string
  owner: string
}

class Pdf {
  parts: Uint8Array[] = [latin1('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')]
  len = this.parts[0].length
  offsets = new Map<number, number>()
  /** Bytes in front of the header: offsets in the xref are relative to "%PDF-". */
  shift = 0
  id = md5(latin1('zav fixture id'))
  sec?: Security
  fileKey = new Uint8Array(0)
  encryptDict = ''

  constructor(sec?: Security) {
    if (!sec) return
    this.sec = sec
    const P = -1028
    const pBytes = new Uint8Array(4)
    new DataView(pBytes.buffer).setInt32(0, P, true)
    if (sec.revision === 6) {
      this.fileKey = concat(md5(latin1('file key a')), md5(latin1('file key b')))
      const vs = latin1('valsaltU')
      const ks = latin1('keysaltU')
      const u = concat(hash2B(latin1(sec.user), vs, new Uint8Array(0)), vs, ks)
      const ue = aesCbc(256, hash2B(latin1(sec.user), ks, new Uint8Array(0)), new Uint8Array(16), this.fileKey, false)
      const ovs = latin1('valsaltO')
      const oks = latin1('keysaltO')
      const o = concat(hash2B(latin1(sec.owner), ovs, u), ovs, oks)
      const oe = aesCbc(256, hash2B(latin1(sec.owner), oks, u), new Uint8Array(16), this.fileKey, false)
      this.encryptDict = `<< /Filter /Standard /V 5 /R 6 /Length 256 /P ${P} /O <${hex(o)}> /U <${hex(u)}> /OE <${hex(oe)}> /UE <${hex(ue)}> /Perms <${hex(new Uint8Array(16))}> /CF << /StdCF << /CFM /AESV3 /AuthEvent /DocOpen /Length 32 >> >> /StmF /StdCF /StrF /StdCF >>`
      return
    }
    const n = 16
    // Algorithm 3: O from the owner password.
    let ok = md5(padPw(sec.owner))
    for (let i = 0; i < 50; i++) ok = md5(ok.slice(0, n))
    ok = ok.slice(0, n)
    let o = rc4(ok, padPw(sec.user))
    for (let i = 1; i <= 19; i++) o = rc4(ok.map(b => b ^ i), o)
    // Algorithm 2: the file key.
    let k = md5(padPw(sec.user), o, pBytes, this.id)
    for (let i = 0; i < 50; i++) k = md5(k.slice(0, n))
    this.fileKey = k.slice(0, n)
    // Algorithm 5: U.
    let u = rc4(this.fileKey, md5(pad, this.id))
    for (let i = 1; i <= 19; i++) u = rc4(this.fileKey.map(b => b ^ i), u)
    u = concat(u, new Uint8Array(16))
    const cf = sec.revision === 4 ? ' /CF << /StdCF << /CFM /AESV2 /AuthEvent /DocOpen /Length 16 >> >> /StmF /StdCF /StrF /StdCF' : ''
    this.encryptDict = `<< /Filter /Standard /V ${sec.revision === 4 ? 4 : 2} /R ${sec.revision} /Length 128 /P ${P} /O <${hex(o)}> /U <${hex(u)}>${cf} >>`
  }

  objectKey(num: number): Uint8Array {
    if (this.sec?.revision === 6) return this.fileKey
    const ng = new Uint8Array([num & 0xff, (num >>> 8) & 0xff, (num >>> 16) & 0xff, 0, 0])
    const salt = this.sec?.revision === 4 ? latin1('sAlT') : new Uint8Array(0)
    return md5(this.fileKey, ng, salt).slice(0, Math.min(this.fileKey.length + 5, 16))
  }

  crypt(num: number, data: Uint8Array): Uint8Array {
    if (!this.sec) return data
    const key = this.objectKey(num)
    if (this.sec.revision === 3) return rc4(key, data)
    const iv = md5(latin1(`iv ${num} ${data.length}`))
    return concat(iv, aesCbc(this.sec.revision === 6 ? 256 : 128, key, iv, data))
  }

  /** A string literal for object `num`: encrypted (as hex) when the file is. */
  str(num: number, s: string | Uint8Array): string {
    const b = typeof s === 'string' ? latin1(s) : s
    if (!this.sec) return `<${hex(b)}>`
    return `<${hex(this.crypt(num, b))}>`
  }

  raw(b: Uint8Array | string) {
    const x = typeof b === 'string' ? latin1(b) : b
    this.parts.push(x)
    this.len += x.length
  }

  obj(num: number, body: string, header = `${num} 0 obj\n`) {
    this.offsets.set(num, this.len - this.shift)
    this.raw(`${header}${body}\nendobj\n`)
  }

  stream(num: number, dict: string, data: Uint8Array, o: { length?: string, noEndstream?: boolean, eol?: string } = {}) {
    const body = this.crypt(num, data)
    this.offsets.set(num, this.len - this.shift)
    const len = o.length ?? `${body.length}`
    this.raw(`${num} 0 obj\n<< ${dict} /Length ${len} >>\nstream${o.eol ?? '\n'}`)
    this.raw(body)
    this.raw(o.noEndstream ? '\nendobj\n' : '\nendstream\nendobj\n')
  }

  /** A classic xref table and trailer. */
  finish(root: number, extraTrailer = ''): Uint8Array {
    const nums = [...this.offsets.keys()]
    const size = Math.max(...nums) + 1
    const xref = this.len - this.shift
    let t = `xref\n0 ${size}\n0000000000 65535 f\r\n`
    for (let i = 1; i < size; i++) {
      const off = this.offsets.get(i)
      t += off === undefined ? '0000000000 00000 f\r\n' : `${String(off).padStart(10, '0')} 00000 n\r\n`
    }
    let enc = ''
    if (this.sec) {
      this.obj(size, this.encryptDict)
      enc = ` /Encrypt ${size} 0 R`
      t = t.replace(`0 ${size}\n`, `0 ${size + 1}\n`) + `${String(this.offsets.get(size)).padStart(10, '0')} 00000 n\r\n`
    }
    this.raw(t)
    this.raw(`trailer\n<< /Size ${size + (this.sec ? 1 : 0)} /Root ${root} 0 R /ID [<${hex(this.id)}> <${hex(this.id)}>]${enc}${extraTrailer} >>\nstartxref\n${xref}\n%%EOF\n`)
    return concat(...this.parts)
  }
}

const deflate = (d: Uint8Array) => new Uint8Array(zlib.deflateSync(d))
const jsAlert = enc.encode('app.alert({cMsg: "zav", cTitle: unescape("%7a%61%76")}); var x = eval("1+1");')
const jsStream = enc.encode('function payload() { var s = ""; for (var i = 0; i < 4; i++) s += String.fromCharCode(65 + i); return s; }\npayload();\n')
const page = enc.encode('BT /F1 12 Tf 72 712 Td (Hello from zav) Tj ET\n')

/** Catalog, pages, one page with a Flate content stream, plus whatever the caller adds. */
function basic(p: Pdf, extraCatalog = '') {
  p.obj(1, `<< /Type /Catalog /Pages 2 0 R${extraCatalog} >>`)
  p.obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>')
  p.obj(3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>')
  p.stream(4, '/Filter /FlateDecode', deflate(page))
}

// A JavaScript action with a string, an indirect JS stream through a filter chain, and an
// embedded EICAR file.
for (const sec of [undefined, { revision: 3, user: '', owner: 'owner' }, { revision: 4, user: '', owner: 'owner' }, { revision: 6, user: '', owner: 'owner' }] as (Security | undefined)[]) {
  const p = new Pdf(sec)
  basic(p, ' /OpenAction 5 0 R /Names << /EmbeddedFiles << /Names [(eicar.com) 7 0 R] >> >>')
  p.obj(5, `<< /Type /Action /S /JavaScript /JS ${p.str(5, jsAlert)} /Next 6 0 R >>`)
  p.obj(6, '<< /Type /Action /S /JavaScript /JS 8 0 R >>')
  p.obj(7, `<< /Type /Filespec /F ${p.str(7, 'eicar.com')} /EF << /F 9 0 R >> >>`)
  p.stream(8, '/Filter [/ASCIIHexDecode /FlateDecode]', asciiHex(deflate(jsStream)))
  p.stream(9, '/Type /EmbeddedFile /Filter /FlateDecode', deflate(eicar))
  const name = sec ? `js-embedded-r${sec.revision}.pdf` : 'js-embedded.pdf'
  doc(name, p.finish(1), [
    { path: 'obj/4', data: page },
    { path: 'js/s0', data: jsAlert },
    { path: 'js/8', data: jsStream },
    { path: 'embedded/9', data: eicar },
  ])
}

// The user password is not empty: reported, streams scanned undecrypted.
{
  const p = new Pdf({ revision: 3, user: 'secret', owner: 'owner' })
  basic(p)
  doc('user-password.pdf', p.finish(1), [], ['encrypted'])
}

// Every filter, chains, predictors.
{
  const p = new Pdf()
  basic(p)
  const text = concat(enc.encode('filters '.repeat(40)), eicar)
  p.stream(5, '/Filter /LZWDecode', lzw(text))
  p.stream(6, '/Filter /LZWDecode /DecodeParms << /EarlyChange 0 >>', lzw(text, 0))
  p.stream(7, '/Filter /ASCII85Decode', ascii85(text))
  p.stream(8, '/Filter /RunLengthDecode', runLength(text))
  p.stream(9, '/Filter [/ASCII85Decode /FlateDecode]', ascii85(deflate(text)))
  p.stream(10, '/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >>', deflate(pngUp(text, 7)))
  p.stream(11, '/Filter [/FlateDecode] /DecodeParms [<< /Predictor 12 /Columns 5 >>]', deflate(pngUp(text, 5)))
  // A raw deflate stream without the zlib header, as some writers produce.
  p.stream(12, '/Filter /FlateDecode', new Uint8Array(zlib.deflateRawSync(text)))
  // An image codec: passed on as it is.
  p.stream(13, '/Filter /DCTDecode /Subtype /Image', eicar)
  doc('filters.pdf', p.finish(1), [
    { path: 'obj/5', data: text },
    { path: 'obj/6', data: text },
    { path: 'obj/7', data: text },
    { path: 'obj/8', data: text },
    { path: 'obj/9', data: text },
    // Predictors decode whole rows: the encoder's zero padding comes back.
    { path: 'obj/10', data: concat(text, new Uint8Array((7 - (text.length % 7)) % 7)) },
    { path: 'obj/11', data: concat(text, new Uint8Array((5 - (text.length % 5)) % 5)) },
    { path: 'obj/12', data: text },
    { path: 'obj/13', data: eicar },
  ])
}

// Object streams and a cross-reference stream (PNG Up predictor, as writers use).
{
  const p = new Pdf()
  p.raw('% object stream fixture\n')
  // Objects 1, 2, 3 and the action 5 live in object stream 10.
  const inner = [
    [1, '<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>'],
    [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'],
    [3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>'],
    [5, `<< /S /JavaScript /J#53 (${'app.alert(\\(1\\));'}) /Next << /S /JavaScript /JS 6 0 R >> >>`],
    [6, `(${'this.print\\({bUI: false}\\);'})`],
  ] as [number, string][]
  let head = ''
  let body = ''
  for (const [num, text] of inner) {
    head += `${num} ${body.length} `
    body += `${text}\n`
  }
  const objstm = enc.encode(head + body)
  p.stream(10, `/Type /ObjStm /N ${inner.length} /First ${head.length} /Filter /FlateDecode`, deflate(objstm))
  // Cross-reference stream: W [1 4 2], type 1 for object 10, type 2 for the others.
  const entries: number[][] = []
  const off10 = p.offsets.get(10)!
  for (let i = 0; i < 12; i++) {
    const at = inner.findIndex(x => x[0] === i)
    if (i === 10) entries.push([1, off10, 0])
    else if (at >= 0) entries.push([2, 10, at])
    else if (i === 11) entries.push([1, p.len, 0])
    else entries.push([0, 0, 0])
  }
  const rows = new Uint8Array(entries.length * 7)
  entries.forEach(([t, f2, f3], i) => {
    rows[i * 7] = t
    new DataView(rows.buffer).setUint32(i * 7 + 1, f2)
    new DataView(rows.buffer).setUint16(i * 7 + 5, f3)
  })
  const xrefAt = p.len
  p.stream(11, `/Type /XRef /Size 12 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >>`, deflate(pngUp(rows, 7)))
  p.raw(`startxref\n${xrefAt}\n%%EOF\n`)
  doc('objstm.pdf', concat(...p.parts), [
    { path: 'objstm/10', data: objstm },
    { path: 'xref/11', data: rows },
    { path: 'js/s0', data: enc.encode('app.alert((1));') },
    { path: 'js/6', data: enc.encode('this.print({bUI: false});') },
  ])
}

// Damaged lengths: too short, too long, indirect, missing endstream; a lone CR after "stream";
// junk before the header; UTF-16BE JavaScript; an object hidden from the header scan that only
// the xref table finds.
{
  const p = new Pdf()
  p.parts[0] = concat('junk before the header\n', p.parts[0])
  p.len = p.parts[0].length
  p.shift = 'junk before the header\n'.length
  basic(p, ' /OpenAction 9 0 R')
  const text = concat(enc.encode('lengths '), eicar)
  p.stream(5, '', text, { length: '10' })
  p.stream(6, '', text, { length: '99999' })
  p.stream(7, '', text, { length: '12 0 R' })
  p.obj(12, `${text.length}`)
  p.stream(8, '', text, { eol: '\r' })
  const utf16 = new Uint8Array(2 + jsAlert.length * 2)
  utf16[0] = 0xfe
  utf16[1] = 0xff
  jsAlert.forEach((b, i) => {
    utf16[3 + i * 2] = b
  })
  p.obj(9, `<< /S /JavaScript /JS <${hex(utf16)}> >>`)
  // "13 0 %c\nobj": the header scan wants "N G obj", the xref entry finds it anyway.
  p.obj(13, `<< /S /JavaScript /JS (hidden.alert\\(13\\)) >>`, '13 0 %comment\nobj\n')
  p.stream(14, '', text, { noEndstream: true })
  doc('damaged.pdf', p.finish(1), [
    { path: 'obj/5', data: text },
    { path: 'obj/6', data: text },
    { path: 'obj/7', data: text },
    { path: 'obj/8', data: text },
    { path: 'js/s0', data: jsAlert },
    { path: 'js/s1', data: enc.encode('hidden.alert(13)') },
  ], ['mismatch'])
}

// ---------------------------------------------------------------------------------------------
// RTF with embedded objects ([MS-OLEDS] OLE1 ObjectHeader, the OLE Packager).

function u32le(v: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, v, true)
  return b
}
function lpstr(s: string): Uint8Array {
  return s.length === 0 ? u32le(0) : concat(u32le(s.length + 1), s, new Uint8Array(1))
}
function ole1(cls: string, native: Uint8Array): Uint8Array {
  return concat(u32le(0x501), u32le(2), lpstr(cls), lpstr(''), lpstr(''), u32le(native.length), native)
}
function packager(label: string, data: Uint8Array): Uint8Array {
  const path = `C:\\Users\\x\\${label}`
  const tmp = `C:\\Temp\\${label}\0`
  return concat(new Uint8Array([2, 0]), `${label}\0${path}\0`, new Uint8Array([0, 0, 3, 0]), u32le(tmp.length), tmp, u32le(data.length), data, new Uint8Array(8))
}
/** Hex with the obfuscations Word tolerates: mixed case, line breaks, spaces, ignored groups. */
function rtfHex(d: Uint8Array): string {
  let s = ''
  for (let i = 0; i < d.length; i++) {
    const h = d[i].toString(16).padStart(2, '0')
    s += i % 3 === 0 ? h.toUpperCase() : h
    if (i % 29 === 28) s += '\r\n'
    if (i === 10) s += ' {\\*\\zavjunk 4142} '
    if (i === 20) s += '\\par '
  }
  return s
}
{
  const obj = ole1('Package', packager('eicar.com', eicar))
  doc('package.rtf', latin1(`{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}\\pard Hello {\\b world}\\par\n{\\object\\objemb\\objw100\\objh100{\\*\\objclass Package}{\\*\\objdata\n${rtfHex(obj)}\n}}\n}`), [
    { path: 'object/0/eicar.com', data: eicar },
  ])
}
{
  // \bin: raw bytes inside objdata, then more hex.
  const native = concat(enc.encode('native '), eicar)
  const obj = ole1('Word.Document.8', native)
  const cut = 30
  doc('bin.rtf', concat(`{\\rtf1{\\object\\objemb{\\*\\objdata ${hex(obj.slice(0, cut))}\\bin${obj.length - cut - 4} `, obj.slice(cut, obj.length - 4), `${hex(obj.slice(obj.length - 4))}}}}`), [
    { path: 'object/0', data: native },
  ])
}
{
  // Not OLE1: scanned whole. The second object is never closed; an odd last digit is dropped.
  doc('raw.rtf', latin1(`{\\rtf1{\\*\\objdata ${hex(eicar)}}{\\object{\\*\\objdata ${hex(eicar)}f`), [
    { path: 'objdata/0', data: eicar },
    { path: 'objdata/1', data: eicar },
  ])
}

// ---------------------------------------------------------------------------------------------
// 7z (7zFormat.txt), with coder streams from liblzma (Python's lzma, raw mode), zlib and bz2.

function num7(v: number): number[] {
  // The first byte's leading 1 bits count the extra little-endian bytes.
  for (let n = 0; n < 8; n++) {
    if (v < 2 ** (7 * (n + 1))) {
      const bytes: number[] = []
      let x = v
      for (let k = 0; k < n; k++) {
        bytes.push(x % 256)
        x = Math.floor(x / 256)
      }
      const mask = (0xff << (8 - n)) & 0xff
      return [mask | x, ...bytes]
    }
  }
  const out = [0xff]
  let x = v
  for (let k = 0; k < 8; k++) {
    out.push(x % 256)
    x = Math.floor(x / 256)
  }
  return out
}
function u64le(v: number): number[] {
  const o: number[] = []
  let x = v
  for (let k = 0; k < 8; k++) {
    o.push(x % 256)
    x = Math.floor(x / 256)
  }
  return o
}
interface Coder7 { id: number[], props?: Uint8Array }
interface Folder7 {
  /** Coders from the folder's main output down to the packed stream; each feeds the one before. */
  coders: Coder7[]
  packed: Uint8Array
  /** Unpacked size of each coder's output, in the same order. */
  sizes: number[]
  /** Sizes of the files in this folder. */
  files: number[]
}
function streamsInfo(packPos: number, folders: Folder7[]): number[] {
  const h: number[] = [0x06, ...num7(packPos), ...num7(folders.length), 0x09]
  for (const f of folders) h.push(...num7(f.packed.length))
  h.push(0x00, 0x07, 0x0b, ...num7(folders.length), 0x00)
  for (const f of folders) {
    h.push(...num7(f.coders.length))
    for (const c of f.coders) {
      h.push(c.id.length | (c.props ? 0x20 : 0), ...c.id)
      if (c.props) h.push(...num7(c.props.length), ...c.props)
    }
    // Coder k's input is bound to coder k+1's output.
    for (let k = 0; k + 1 < f.coders.length; k++) h.push(...num7(k), ...num7(k + 1))
  }
  h.push(0x0c)
  for (const f of folders) for (const s of f.sizes) h.push(...num7(s))
  h.push(0x00, 0x08, 0x0d)
  for (const f of folders) h.push(...num7(f.files.length))
  h.push(0x09)
  for (const f of folders) for (const s of f.files.slice(0, -1)) h.push(...num7(s))
  h.push(0x00, 0x00)
  return h
}
interface File7 { name: string, empty?: boolean }
function sevenZip(folders: Folder7[], files: File7[], o: { encodeHeader?: boolean, corruptHeaderCrc?: boolean } = {}): Uint8Array {
  const packed = concat(...folders.map(f => f.packed))
  const h: number[] = [0x01, 0x04, ...streamsInfo(0, folders), 0x05, ...num7(files.length)]
  if (files.some(f => f.empty)) {
    const bits = new Uint8Array(Math.ceil(files.length / 8))
    files.forEach((f, i) => {
      if (f.empty) bits[i >> 3] |= 0x80 >> (i & 7)
    })
    h.push(0x0e, ...num7(bits.length), ...bits)
  }
  const names = concat(new Uint8Array([0]), ...files.map(f => {
    const b = new Uint8Array((f.name.length + 1) * 2)
    for (let i = 0; i < f.name.length; i++) new DataView(b.buffer).setUint16(i * 2, f.name.charCodeAt(i), true)
    return b
  }))
  h.push(0x11, ...num7(names.length), ...names, 0x00, 0x00)
  let header = new Uint8Array(h)
  let extra = new Uint8Array(0)
  if (o.encodeHeader) {
    const enc = lzmaRaw(header)
    extra = enc.data
    header = new Uint8Array([0x17, ...streamsInfo(packed.length, [{ coders: [{ id: [3, 1, 1], props: enc.props }], packed: enc.data, sizes: [header.length], files: [header.length] }])])
  }
  const body = concat(packed, extra)
  const start = new Uint8Array(20)
  start.set(u64le(body.length), 0)
  start.set(u64le(header.length), 8)
  start.set(u32le(crc32(header)), 16)
  const sig = concat(latin1('7z\xbc\xaf\x27\x1c'), new Uint8Array([0, 4]), u32le(crc32(start)), start)
  return concat(sig, body, header)
}
function lzmaRaw(d: Uint8Array): { data: Uint8Array, props: Uint8Array } {
  const data = py('sys.stdout.buffer.write(lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}]))', d)
  return { data, props: concat(new Uint8Array([93]), u32le(1 << 16)) }
}
function lzma2Raw(d: Uint8Array, bcj = false): Uint8Array {
  const filters = `${bcj ? '{"id": lzma.FILTER_X86}, ' : ''}{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 16}`
  return py(`sys.stdout.buffer.write(lzma.compress(data, format=lzma.FORMAT_RAW, filters=[${filters}]))`, d)
}
{
  const a = concat(enc.encode('first member\n'))
  const b = concat(enc.encode('second '.repeat(500)), eicar)
  // x86-like code: calls and jumps with nearby targets among other bytes.
  const code = new Uint8Array(6000)
  let seed = 7
  for (let i = 0; i < code.length; i++) {
    seed = (seed * 1103515245 + 12345) >>> 0
    code[i] = seed >>> 24
    if (i % 37 === 0 && i + 5 < code.length) {
      code[i] = i % 2 ? 0xe8 : 0xe9
      new DataView(code.buffer).setInt32(i + 1, ((seed >>> 8) % 4000) - 2000, true)
      i += 4
    }
  }
  const lz = lzmaRaw(eicar)
  doc('lzma.7z', sevenZip([{ coders: [{ id: [3, 1, 1], props: lz.props }], packed: lz.data, sizes: [eicar.length], files: [eicar.length] }], [{ name: 'eicar.com' }]), [
    { path: 'eicar.com', data: eicar },
  ])
  // A solid LZMA2 folder of three files, plus an empty file and a directory.
  const solid = concat(a, b, eicar)
  doc('solid.7z', sevenZip([{ coders: [{ id: [0x21], props: new Uint8Array([8]) }], packed: lzma2Raw(solid), sizes: [solid.length], files: [a.length, b.length, eicar.length] }], [
    { name: 'dir', empty: true },
    { name: 'dir\\a.txt' },
    { name: 'empty.txt', empty: true },
    { name: 'b.txt' },
    { name: 'eicar.com' },
  ], { encodeHeader: true }), [
    { path: 'dir/a.txt', data: a },
    { path: 'b.txt', data: b },
    { path: 'eicar.com', data: eicar },
  ])
  // BCJ x86 over LZMA2, then Deflate, BZip2 and Copy folders.
  const bz = py('import bz2\nsys.stdout.buffer.write(bz2.compress(data, 9))', b)
  doc('coders.7z', sevenZip([
    { coders: [{ id: [3, 3, 1, 3] }, { id: [0x21], props: new Uint8Array([8]) }], packed: lzma2Raw(code, true), sizes: [code.length, code.length], files: [code.length] },
    { coders: [{ id: [4, 1, 8] }], packed: new Uint8Array(zlib.deflateRawSync(b)), sizes: [b.length], files: [b.length] },
    { coders: [{ id: [4, 2, 2] }], packed: bz, sizes: [b.length], files: [b.length] },
    { coders: [{ id: [0] }], packed: eicar, sizes: [eicar.length], files: [eicar.length] },
  ], [{ name: 'code.bin' }, { name: 'deflate.txt' }, { name: 'bzip2.txt' }, { name: 'stored.com' }]), [
    { path: 'code.bin', data: code },
    { path: 'deflate.txt', data: b },
    { path: 'bzip2.txt', data: b },
    { path: 'stored.com', data: eicar },
  ])
  // AES-256: reported, not decrypted.
  doc('encrypted.7z', sevenZip([{ coders: [{ id: [0x21], props: new Uint8Array([8]) }, { id: [6, 0xf1, 7, 1], props: new Uint8Array([0x13, 0x07]) }], packed: new Uint8Array(64).fill(0x5a), sizes: [eicar.length, 64], files: [eicar.length] }], [{ name: 'secret.com' }]), [], ['encrypted'])
}

// ---------------------------------------------------------------------------------------------
// docs.zig

const lines = [
  '//! Generated by documents.ts; do not edit. Each document lists the children a scan must',
  '//! produce (path below the document, length, CRC-32) and the notices it must raise.',
  '',
  'pub const Member = struct { path: []const u8, len: usize, crc: u32 };',
  'pub const Doc = struct { name: []const u8, bytes: []const u8, members: []const Member, notices: []const []const u8 };',
  '',
  'pub const docs = [_]Doc{',
]
for (const d of docs) {
  const notices = d.notices.map(n => `"${n}"`).join(', ')
  lines.push(`    .{ .name = "${d.name}", .bytes = @embedFile("docs/${d.file}"), .notices = &.{${notices}}, .members = &.{`)
  for (const m of d.members) lines.push(`        .{ .path = "${m.path}", .len = ${m.data.length}, .crc = 0x${crc32(m.data).toString(16).padStart(8, '0')} },`)
  lines.push('    } },')
}
lines.push('};', '')
writeFileSync(join(here, 'docs.zig'), lines.join('\n'))
console.log('wrote', docs.length, 'documents')
