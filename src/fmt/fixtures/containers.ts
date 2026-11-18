// Phase-three container fixtures (P5.18 and P5.19): ISO 9660, CAB, DMG, NSIS, CHM and UPX.
// Called from make-fixtures.ts, which owns the output list; every builder here works from the
// format's public specification, byte by byte, so malformed and adversarial variants are exact.

import zlib from 'node:zlib'

export interface Member { path: string, data: Uint8Array }

export interface Helpers {
  archive: (name: string, bytes: Uint8Array, members: Member[], malformed?: boolean) => void
  exe: (name: string, bytes: Uint8Array, o: { entry: number | null, sections: number, members?: Member[], malformed?: boolean }) => void
  concat: (...parts: Uint8Array[]) => Uint8Array
  plain: (len: number, s: number) => Uint8Array
  crc32: (data: Uint8Array) => number
  run: (cmd: string, args: string[], input: Uint8Array) => Uint8Array
  py: (code: string, input: Uint8Array) => Uint8Array
  deflateRaw: (data: Uint8Array) => Uint8Array
  evil: Uint8Array
  fileA: Uint8Array
  fileB: Uint8Array
}

const enc = new TextEncoder()

function le16(v: number): number[] {
  return [v & 0xff, (v >>> 8) & 0xff]
}
function le32(v: number): number[] {
  return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]
}
function be16(v: number): number[] {
  return [(v >>> 8) & 0xff, v & 0xff]
}
function be32(v: number): number[] {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]
}
/** ECMA-119 "both-byte orders" fields. */
function both16(v: number): number[] {
  return [...le16(v), ...be16(v)]
}
function both32(v: number): number[] {
  return [...le32(v), ...be32(v)]
}

// ---------------------------------------------------------------------------------------------
// ISO 9660 (ECMA-119) with a Joliet supplementary volume descriptor, Rock Ridge NM names and an
// El Torito boot catalog. 2048-byte logical blocks throughout.

const sector = 2048

interface IsoNode {
  name: string
  /** Files carry data; directories carry children. */
  data?: Uint8Array
  children?: IsoNode[]
  /** Extent of a file, or of the directory's records (one per tree for directories). */
  lba?: number
  size?: number
}

interface IsoOptions {
  joliet?: boolean
  rockRidge?: boolean
  boot?: Uint8Array
  /** Extra records in the root naming the first file again (hard links, or an amplification bomb). */
  dupes?: number
  /** Add a directory whose record points back at the root. */
  loop?: boolean
  /** A chain of directories, each listing the next one twice. */
  dagDepth?: number
  /** Drop everything after this many bytes. */
  truncateAt?: number
}

function isoTree(files: Member[]): IsoNode {
  const root: IsoNode = { name: '', children: [] }
  for (const f of files) {
    const parts = f.path.split('/')
    let dir = root
    for (const p of parts.slice(0, -1)) {
      let next = dir.children!.find(c => c.name === p && c.children)
      if (!next) {
        next = { name: p, children: [] }
        dir.children!.push(next)
      }
      dir = next
    }
    dir.children!.push({ name: parts[parts.length - 1], data: f.data })
  }
  return root
}

function primaryName(name: string, dir: boolean): string {
  const up = name.toUpperCase().replace(/[^A-Z0-9_.]/g, '_')
  return dir ? up.replace(/\./g, '_') : `${up.includes('.') ? up : `${up}.`};1`
}

function ucs2(name: string): Uint8Array {
  const out: number[] = []
  for (const ch of name) out.push(...be16(ch.charCodeAt(0)))
  return new Uint8Array(out)
}

const isoDate = [124, 1, 1, 0, 0, 0, 0] // 2024-01-01 00:00:00 GMT

function dirRecord(lba: number, size: number, flags: number, id: Uint8Array, su: Uint8Array = new Uint8Array(0)): Uint8Array {
  const base = 33 + id.length + (id.length % 2 === 0 ? 1 : 0)
  const len = base + su.length
  const r = new Uint8Array(len)
  r[0] = len
  r.set(both32(lba), 2)
  r.set(both32(size), 10)
  r.set(isoDate, 18)
  r[25] = flags
  r.set(both16(1), 28)
  r[32] = id.length
  r.set(id, 33)
  r.set(su, base)
  return r
}

/** A Rock Ridge NM entry (SUSP "NM", version 1, no flags). */
function nmEntry(name: string): Uint8Array {
  const n = enc.encode(name)
  return new Uint8Array([0x4e, 0x4d, 5 + n.length, 1, 0, ...n])
}

/** Pack records into sectors; a record never crosses a sector boundary. */
function packRecords(records: Uint8Array[]): Uint8Array[] {
  const sectors: Uint8Array[] = []
  let cur = new Uint8Array(sector)
  let pos = 0
  for (const r of records) {
    if (pos + r.length > sector) {
      sectors.push(cur)
      cur = new Uint8Array(sector)
      pos = 0
    }
    cur.set(r, pos)
    pos += r.length
  }
  sectors.push(cur)
  return sectors
}

export function isoImage(files: Member[], o: IsoOptions = {}): Uint8Array {
  const root = isoTree(files)
  const trees = o.joliet ? ['primary', 'joliet'] : ['primary']
  // Directories in breadth-first order (path table order).
  const dirs: { node: IsoNode, parent: number }[] = []
  const queue: { node: IsoNode, parent: number }[] = [{ node: root, parent: 0 }]
  while (queue.length) {
    const d = queue.shift()!
    const idx = dirs.length
    dirs.push(d)
    for (const c of d.node.children!) if (c.children) queue.push({ node: c, parent: idx })
  }
  if (o.dagDepth) {
    // Each level lists the next one twice, so a walker without a visited set takes 2^depth steps.
    let parent = 0
    for (let i = 0; i < o.dagDepth; i++) {
      const node: IsoNode = { name: `L${i}`, children: [] }
      dirs.push({ node, parent })
      parent = dirs.length - 1
    }
  }
  const nd = dirs.length
  const descriptors = 1 + (o.boot ? 1 : 0) + (o.joliet ? 1 : 0) + 1
  let next = 16 + descriptors
  const bootCatalogLba = o.boot ? next++ : 0
  const bootImageLba = o.boot ? next++ : 0
  // Path tables: L then M per tree, one sector each (enough for these fixtures).
  const pathTables: Record<string, { l: number, m: number }> = {}
  for (const t of trees) pathTables[t] = { l: next++, m: next++ }
  // Directory extents: sized after building their records, so lay out records first with
  // placeholder extents, then assign, then rebuild.
  const dirLba: Record<string, number[]> = {}
  const dirSize: Record<string, number[]> = {}
  const recordsFor = (t: string, i: number): Uint8Array[] => {
    const d = dirs[i]
    const self = dirRecord(dirLba[t]?.[i] ?? 0, dirSize[t]?.[i] ?? sector, 2, new Uint8Array([0]), t === 'primary' && o.rockRidge && i === 0 ? new Uint8Array([0x53, 0x50, 7, 1, 0xbe, 0xef, 0, 0x45, 0x52, 18, 1, 10, 0, 0, 1, ...enc.encode('RRIP_1991A')]) : undefined)
    const parentRec = dirRecord(dirLba[t]?.[d.parent] ?? 0, dirSize[t]?.[d.parent] ?? sector, 2, new Uint8Array([1]))
    const recs = [self, parentRec]
    const kids = [...d.node.children!]
    const ident = (c: IsoNode, isDir: boolean) => t === 'joliet' ? ucs2(isDir ? c.name : `${c.name};1`) : enc.encode(primaryName(c.name, isDir))
    kids.sort((a, b) => {
      const x = ident(a, !!a.children)
      const y = ident(b, !!b.children)
      return Buffer.compare(Buffer.from(x), Buffer.from(y))
    })
    for (const c of kids) {
      const isDir = !!c.children
      const su = t === 'primary' && o.rockRidge ? nmEntry(c.name) : new Uint8Array(0)
      if (isDir) {
        const ci = dirs.findIndex(x => x.node === c)
        recs.push(dirRecord(dirLba[t]?.[ci] ?? 0, dirSize[t]?.[ci] ?? sector, 2, ident(c, true), su))
      } else {
        recs.push(dirRecord(c.lba ?? 0, c.data!.length, 0, ident(c, false), su))
      }
    }
    if (i === 0 && o.dupes) {
      const first = d.node.children!.find(c => c.data)!
      for (let k = 0; k < o.dupes; k++) {
        const name = t === 'joliet' ? ucs2(`dup${k};1`) : enc.encode(`DUP${k}.;1`)
        recs.push(dirRecord(first.lba ?? 0, first.data!.length, 0, name))
      }
    }
    if (i === 0 && o.loop) {
      const name = t === 'joliet' ? ucs2('loop') : enc.encode('LOOP')
      recs.push(dirRecord(dirLba[t]?.[0] ?? 0, dirSize[t]?.[0] ?? sector, 2, name))
    }
    if (o.dagDepth && dirs[i].node.name.startsWith('L') && i >= nd - o.dagDepth - 0) {
      // The DAG chain: list the next level twice.
      const level = Number(dirs[i].node.name.slice(1))
      if (level + 1 < o.dagDepth) {
        const ni = i + 1
        for (const suffix of ['A', 'B']) {
          const name = t === 'joliet' ? ucs2(`n${suffix}`) : enc.encode(`N${suffix}`)
          recs.push(dirRecord(dirLba[t]?.[ni] ?? 0, dirSize[t]?.[ni] ?? sector, 2, name))
        }
      }
    }
    if (o.dagDepth && i === 0) {
      const name = t === 'joliet' ? ucs2('dag') : enc.encode('DAG')
      const ni = nd - o.dagDepth
      recs.push(dirRecord(dirLba[t]?.[ni] ?? 0, dirSize[t]?.[ni] ?? sector, 2, name))
    }
    return recs
  }
  for (const t of trees) {
    dirLba[t] = []
    dirSize[t] = []
    for (let i = 0; i < nd; i++) {
      const sectors = packRecords(recordsFor(t, i)).length
      dirLba[t][i] = next
      dirSize[t][i] = sectors * sector
      next += sectors
    }
  }
  // File extents.
  const fileNodes: IsoNode[] = []
  for (const d of dirs) for (const c of d.node.children!) if (c.data) fileNodes.push(c)
  for (const f of fileNodes) {
    f.lba = next
    next += Math.max(1, Math.ceil(f.data!.length / sector))
  }
  const total = next
  const img = new Uint8Array(total * sector)
  const put = (lba: number, bytes: Uint8Array) => img.set(bytes, lba * sector)
  // Volume descriptors.
  const volume = (type: number, t: string): Uint8Array => {
    const v = new Uint8Array(sector)
    v[0] = type
    v.set(enc.encode('CD001'), 1)
    v[6] = 1
    const id = (s: string, len: number) => t === 'joliet' ? ucs2(s.padEnd(len / 2, ' ')) : enc.encode(s.padEnd(len, ' '))
    v.set(id('ZAV', 32), 8)
    v.set(id('FIXTURE', 32), 40)
    v.set(both32(total), 80)
    if (t === 'joliet') v.set([0x25, 0x2f, 0x45], 88) // "%/E": UCS-2 level 3
    v.set(both16(1), 120)
    v.set(both16(1), 124)
    v.set(both16(sector), 128)
    const ptSize = pathTable(t, true).length
    v.set(both32(ptSize), 132)
    v.set(le32(pathTables[t].l), 140)
    v.set(be32(pathTables[t].m), 148)
    v.set(dirRecord(dirLba[t][0], dirSize[t][0], 2, new Uint8Array([0])), 156)
    for (const off of [190, 318, 446, 574]) v.set(id('', 128), off)
    for (const off of [702, 739, 776]) v.set(id('', 36).slice(0, 37), off)
    for (const off of [813, 830, 847, 864]) v.set(enc.encode('2024010100000000'), off)
    v[881] = 1
    return v
  }
  const pathTable = (t: string, little: boolean): Uint8Array => {
    const out: number[] = []
    for (let i = 0; i < nd; i++) {
      const id = i === 0 ? new Uint8Array([0]) : t === 'joliet' ? ucs2(dirs[i].node.name) : enc.encode(primaryName(dirs[i].node.name, true))
      out.push(id.length, 0, ...(little ? le32(dirLba[t][i]) : be32(dirLba[t][i])), ...(little ? le16(dirs[i].parent + 1) : be16(dirs[i].parent + 1)), ...id)
      if (id.length % 2) out.push(0)
    }
    return new Uint8Array(out)
  }
  let vd = 16
  put(vd++, volume(1, 'primary'))
  if (o.boot) {
    const b = new Uint8Array(sector)
    b[0] = 0
    b.set(enc.encode('CD001'), 1)
    b[6] = 1
    b.set(enc.encode('EL TORITO SPECIFICATION'), 7)
    b.set(le32(bootCatalogLba), 0x47)
    put(vd++, b)
  }
  if (o.joliet) put(vd++, volume(2, 'joliet'))
  const term = new Uint8Array(sector)
  term[0] = 255
  term.set(enc.encode('CD001'), 1)
  term[6] = 1
  put(vd++, term)
  if (o.boot) {
    // Validation entry (checksum makes the 16-bit word sum zero), then the initial entry: no
    // emulation, `boot.length / 512` virtual sectors.
    const cat = new Uint8Array(sector)
    cat[0] = 1
    cat.set(enc.encode('ZAV'), 4)
    cat[30] = 0x55
    cat[31] = 0xaa
    let sum = 0
    for (let i = 0; i < 32; i += 2) sum = (sum + cat[i] + (cat[i + 1] << 8)) & 0xffff
    cat.set(le16((0x10000 - sum) & 0xffff), 28)
    cat[32] = 0x88
    cat[33] = 0
    cat.set(le16(Math.ceil(o.boot.length / 512)), 38)
    cat.set(le32(bootImageLba), 40)
    put(bootCatalogLba, cat)
    put(bootImageLba, o.boot)
  }
  for (const t of trees) {
    put(pathTables[t].l, pathTable(t, true))
    put(pathTables[t].m, pathTable(t, false))
    for (let i = 0; i < nd; i++) {
      const sectors = packRecords(recordsFor(t, i))
      sectors.forEach((s, k) => put(dirLba[t][i] + k, s))
    }
  }
  for (const f of fileNodes) put(f.lba!, f.data!)
  // Negative: that many bytes off the end.
  return o.truncateAt ? img.slice(0, o.truncateAt < 0 ? img.length + o.truncateAt : o.truncateAt) : img
}

// ---------------------------------------------------------------------------------------------
// LZX ([MS-PATCH] section 2, the cabinet LZX format): an encoder good enough to exercise every
// decoder path. One block per 32 KiB frame, rotating verbatim, aligned-offset and uncompressed
// blocks; greedy matching with the three repeated offsets; delta-coded pretree path lengths
// with all three run codes; optional E8 call translation.

class BitWriter {
  words: number[] = []
  cur = 0
  n = 0
  bits(v: number, count: number): void {
    for (let i = count - 1; i >= 0; i--) {
      this.cur = (this.cur << 1) | ((v >>> i) & 1)
      if (++this.n === 16) {
        this.words.push(this.cur)
        this.cur = 0
        this.n = 0
      }
    }
  }
  /** Pad to a word boundary; `strict` adds a whole zero word when already aligned. */
  align(strict = false): void {
    if (this.n === 0) {
      if (strict) this.words.push(0)
      return
    }
    this.bits(0, 16 - this.n)
  }
  rawBytes: number[] = []
  bytes(): Uint8Array {
    const out: number[] = []
    for (const w of this.words) out.push(w & 0xff, w >>> 8)
    return new Uint8Array(out)
  }
}

/** Huffman code lengths limited to `max` bits; at least two symbols get a code. */
function huffLengths(freqIn: number[], max: number): number[] {
  const freq = [...freqIn]
  const used = freq.filter(f => f > 0).length
  if (used < 2) {
    for (let i = 0, added = 0; i < freq.length && used + added < 2; i++) {
      if (freq[i] === 0) {
        freq[i] = 1
        added++
      }
    }
  }
  for (;;) {
    type Node = { f: number, sym?: number, l?: Node, r?: Node }
    let nodes: Node[] = freq.map((f, sym) => ({ f, sym })).filter(n => n.f > 0)
    while (nodes.length > 1) {
      nodes.sort((a, b) => a.f - b.f)
      const [a, b] = nodes
      nodes = [{ f: a.f + b.f, l: a, r: b }, ...nodes.slice(2)]
    }
    const lens = new Array(freq.length).fill(0)
    const walk = (n: Node, d: number) => {
      if (n.sym !== undefined) lens[n.sym] = Math.max(d, 1)
      else {
        walk(n.l!, d + 1)
        walk(n.r!, d + 1)
      }
    }
    walk(nodes[0], 0)
    if (Math.max(...lens) <= max) return lens
    for (let i = 0; i < freq.length; i++) if (freq[i] > 0) freq[i] = (freq[i] >> 1) | 1
  }
}

function canonicalCodes(lens: number[]): number[] {
  const codes = new Array(lens.length).fill(0)
  let code = 0
  for (let l = 1; l <= 16; l++) {
    for (let s = 0; s < lens.length; s++) if (lens[s] === l) codes[s] = code++
    code <<= 1
  }
  return codes
}

function lzxExtra(slot: number): number {
  return slot < 4 ? 0 : Math.min((slot - 2) >> 1, 17)
}
const lzxBase: number[] = (() => {
  const t = [0]
  for (let i = 0; i < 50; i++) t.push(t[i] + (1 << lzxExtra(i)))
  return t
})()

/** Forward E8 translation (what an encoder applies; the decoder undoes it). */
function e8Forward(data: Uint8Array, size: number): Uint8Array {
  const out = data.slice()
  for (let f = 0; f < out.length; f += 32768) {
    const end = Math.min(f + 32768, out.length)
    if (end - f <= 10) continue
    for (let i = f; i < end - 10;) {
      if (out[i] !== 0xe8) {
        i++
        continue
      }
      const dv = new DataView(out.buffer, out.byteOffset + i + 1, 4)
      const rel = dv.getInt32(0, true)
      const cur = i
      if (rel >= -cur && rel < size - cur) dv.setInt32(0, rel + cur, true)
      else if (rel >= size - cur && rel < size) dv.setInt32(0, rel - size, true)
      i += 5
    }
  }
  return out
}

interface LzxSym { lit?: number, len?: number, slot?: number, extra?: number, extraBits?: number }

export function lzxCompress(input: Uint8Array, windowBits: number, o: { e8?: number, blockTypes?: number[] } = {}): Uint8Array {
  return lzxFrames(input, windowBits, o).bytes
}

/** The stream and the byte offset where each frame's data ends. */
export function lzxFrames(input: Uint8Array, windowBits: number, o: { e8?: number, blockTypes?: number[] } = {}): { bytes: Uint8Array, ends: number[] } {
  const ends: number[] = []
  const data = o.e8 ? e8Forward(input, o.e8) : input
  const slots = { 15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50 }[windowBits]!
  const mainSyms = 256 + slots * 8
  const windowSize = 1 << windowBits
  const bw = new BitWriter()
  const out: number[] = [] // final bytes, interleaving bit words and raw blocks
  const flushBits = () => {
    for (const w of bw.words) out.push(w & 0xff, w >>> 8)
    bw.words = []
  }
  if (o.e8) {
    bw.bits(1, 1)
    bw.bits(o.e8 >>> 16, 16)
    bw.bits(o.e8 & 0xffff, 16)
  } else bw.bits(0, 1)
  const R = [1, 1, 1]
  const prevMain = new Array(mainSyms).fill(0)
  const prevLen = new Array(249).fill(0)
  const head = new Map<number, number[]>()
  const types = o.blockTypes ?? [1, 2, 3]
  for (let f = 0, frame = 0; f < data.length; f += 32768, frame++) {
    const end = Math.min(f + 32768, data.length)
    const type = types[frame % types.length]
    if (type === 3) {
      bw.bits(3, 3)
      bw.bits((end - f) >>> 8, 16)
      bw.bits((end - f) & 0xff, 8)
      bw.align(true)
      flushBits()
      for (const r of R) out.push(r & 0xff, (r >>> 8) & 0xff, (r >>> 16) & 0xff, r >>> 24)
      for (let i = f; i < end; i++) out.push(data[i])
      if ((end - f) & 1) out.push(0)
      ends.push(out.length)
      for (let i = f; i + 2 < end; i++) {
        const k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16)
        let c = head.get(k)
        if (!c) head.set(k, c = [])
        c.push(i)
      }
      continue
    }
    // Greedy parse of this frame; matches never cross the frame's end.
    const syms: LzxSym[] = []
    for (let i = f; i < end;) {
      let bestLen = 0
      let bestOff = 0
      for (const rOff of R) {
        if (rOff > i || rOff > windowSize) continue
        let l = 0
        while (l < 257 && i + l < end && data[i + l] === data[i + l - rOff]) l++
        if (l > bestLen) {
          bestLen = l
          bestOff = rOff
        }
      }
      if (i + 2 < end) {
        const k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16)
        const chain = head.get(k) ?? []
        for (let c = chain.length - 1, tries = 0; c >= 0 && tries < 32; c--, tries++) {
          const p = chain[c]
          const off = i - p
          if (off > windowSize - 3) break
          let l = 0
          while (l < 257 && i + l < end && data[i + l] === data[p + l]) l++
          if (l > bestLen + 1) {
            bestLen = l
            bestOff = off
          }
        }
      }
      const step = bestLen >= 3 ? bestLen : 1
      for (let k2 = i; k2 < i + step && k2 + 2 < data.length; k2++) {
        const k = data[k2] | (data[k2 + 1] << 8) | (data[k2 + 2] << 16)
        let c = head.get(k)
        if (!c) head.set(k, c = [])
        c.push(k2)
      }
      if (bestLen < 3) {
        syms.push({ lit: data[i] })
        i++
        continue
      }
      const ri = R.indexOf(bestOff)
      let slot: number
      let extra = 0
      let extraBits = 0
      if (ri === 0) slot = 0
      else if (ri === 1) {
        slot = 1
        ;[R[0], R[1]] = [R[1], R[0]]
      } else if (ri === 2) {
        slot = 2
        ;[R[0], R[2]] = [R[2], R[0]]
      } else {
        const formatted = bestOff + 2
        slot = 3
        while (slot + 1 < slots && lzxBase[slot + 1] <= formatted) slot++
        extraBits = lzxExtra(slot)
        extra = formatted - lzxBase[slot]
        R[2] = R[1]
        R[1] = R[0]
        R[0] = bestOff
      }
      syms.push({ len: bestLen, slot, extra, extraBits })
      i += bestLen
    }
    // Frequencies, trees, header.
    const mainFreq = new Array(mainSyms).fill(0)
    const lenFreq = new Array(249).fill(0)
    const alFreq = new Array(8).fill(0)
    for (const sy of syms) {
      if (sy.lit !== undefined) mainFreq[sy.lit]++
      else {
        const lh = Math.min(sy.len! - 2, 7)
        mainFreq[256 + sy.slot! * 8 + lh]++
        if (lh === 7) lenFreq[sy.len! - 9]++
        if (type === 2 && sy.extraBits! >= 3) alFreq[sy.extra! & 7]++
      }
    }
    const mainLens = huffLengths(mainFreq, 16)
    const lenLens = huffLengths(lenFreq, 16)
    const alLens = huffLengths(alFreq, 7)
    bw.bits(type, 3)
    bw.bits((end - f) >>> 8, 16)
    bw.bits((end - f) & 0xff, 8)
    if (type === 2) for (const l of alLens) bw.bits(l, 3)
    writeLengths(bw, prevMain.slice(0, 256), mainLens.slice(0, 256))
    writeLengths(bw, prevMain.slice(256), mainLens.slice(256))
    writeLengths(bw, prevLen, lenLens)
    for (let i = 0; i < mainSyms; i++) prevMain[i] = mainLens[i]
    for (let i = 0; i < 249; i++) prevLen[i] = lenLens[i]
    const mainCodes = canonicalCodes(mainLens)
    const lenCodes = canonicalCodes(lenLens)
    const alCodes = canonicalCodes(alLens)
    for (const sy of syms) {
      if (sy.lit !== undefined) {
        bw.bits(mainCodes[sy.lit], mainLens[sy.lit])
        continue
      }
      const lh = Math.min(sy.len! - 2, 7)
      const m = 256 + sy.slot! * 8 + lh
      bw.bits(mainCodes[m], mainLens[m])
      if (lh === 7) bw.bits(lenCodes[sy.len! - 9], lenLens[sy.len! - 9])
      if (sy.slot! >= 3) {
        if (type === 2 && sy.extraBits! >= 3) {
          bw.bits(sy.extra! >>> 3, sy.extraBits! - 3)
          bw.bits(alCodes[sy.extra! & 7], alLens[sy.extra! & 7])
        } else bw.bits(sy.extra!, sy.extraBits!)
      }
    }
    // Every frame ends on a 16-bit boundary.
    bw.align()
    flushBits()
    ends.push(out.length)
  }
  flushBits()
  return { bytes: new Uint8Array(out), ends }
}

function writeLengths(bw: BitWriter, prev: number[], cur: number[]): void {
  type Code = { sym: number, extra?: number, extraBits?: number, then?: number }
  const codes: Code[] = []
  for (let x = 0; x < cur.length;) {
    let run = 1
    while (x + run < cur.length && cur[x + run] === cur[x]) run++
    if (cur[x] === 0 && run >= 20) {
      const r = Math.min(run, 51)
      codes.push({ sym: 18, extra: r - 20, extraBits: 5 })
      x += r
    } else if (cur[x] === 0 && run >= 4) {
      const r = Math.min(run, 19)
      codes.push({ sym: 17, extra: r - 4, extraBits: 4 })
      x += r
    } else if (run >= 4) {
      const r = Math.min(run, 5)
      codes.push({ sym: 19, extra: r - 4, extraBits: 1, then: (prev[x] - cur[x] + 17) % 17 })
      x += r
    } else {
      codes.push({ sym: (prev[x] - cur[x] + 17) % 17 })
      x++
    }
  }
  const freq = new Array(20).fill(0)
  for (const c of codes) {
    freq[c.sym]++
    if (c.then !== undefined) freq[c.then]++
  }
  const lens = huffLengths(freq, 15)
  const pcodes = canonicalCodes(lens)
  for (const l of lens) bw.bits(l, 4)
  for (const c of codes) {
    bw.bits(pcodes[c.sym], lens[c.sym])
    if (c.extraBits) bw.bits(c.extra!, c.extraBits)
    if (c.then !== undefined) bw.bits(pcodes[c.then], lens[c.then])
  }
}

// ---------------------------------------------------------------------------------------------
// Cabinet files ([MS-CAB]): CFHEADER, CFFOLDER, CFFILE, CFDATA with checksums; folders stored,
// MSZIP (one deflate stream per CFDATA, the previous 32 KiB as its dictionary) or LZX.

export function cabChecksum(data: Uint8Array, seed: number): number {
  let csum = seed >>> 0
  const n = data.length >>> 2
  for (let i = 0; i < n; i++) csum = (csum ^ (data[4 * i] | (data[4 * i + 1] << 8) | (data[4 * i + 2] << 16) | (data[4 * i + 3] << 24))) >>> 0
  let ul = 0
  let p = n * 4
  switch (data.length & 3) {
    case 3: ul |= data[p++] << 16
    // falls through
    case 2: ul |= data[p++] << 8
    // falls through
    case 1: ul |= data[p++]
  }
  return (csum ^ ul) >>> 0
}

interface CabFolder {
  /** 0 stored, 1 MSZIP, 3 LZX (window bits in `lzxBits`). */
  type: number
  lzxBits?: number
  lzxE8?: number
  files: Member[]
  /** Corrupt the checksum of this block. */
  badChecksum?: number
}

export function cabBytes(folders: CabFolder[], o: { reserve?: { header: number, folder: number, data: number }, extraFiles?: { name: string, folder: number, offset: number, size: number }[], typeOverride?: number } = {}): Uint8Array {
  const deflateRawDict = (chunk: Uint8Array, dict: Uint8Array) => new Uint8Array(zlib.deflateRawSync(chunk, dict.length ? { dictionary: dict } : {}))
  const res = o.reserve
  const headerLen = 36 + (res ? 4 + res.header : 0)
  const folderLen = 8 + (res?.folder ?? 0)
  const fileRecs: Uint8Array[] = []
  const folderData: Uint8Array[][] = []
  for (const [fi, folder] of folders.entries()) {
    let off = 0
    for (const f of folder.files) {
      const name = enc.encode(f.path.replace(/\//g, '\\'))
      fileRecs.push(new Uint8Array([...le32(f.data.length), ...le32(off), ...le16(fi), ...le16(0x5821), ...le16(0x6000), ...le16(0x20), ...name, 0]))
      off += f.data.length
    }
    const all = new Uint8Array(off)
    let p = 0
    for (const f of folder.files) {
      all.set(f.data, p)
      p += f.data.length
    }
    const blocks: Uint8Array[] = []
    if (folder.type === 3) {
      // One LZX stream across the folder; CFDATA k holds frame k's bytes.
      const { bytes: stream, ends } = lzxFrames(all, folder.lzxBits ?? 16, { e8: folder.lzxE8 })
      let from = 0
      for (const [k, to] of ends.entries()) {
        const u = Math.min(32768, all.length - k * 32768)
        blocks.push(dataBlock(stream.slice(from, to), u, res?.data ?? 0, folder.badChecksum === k))
        from = to
      }
    } else {
      for (let k = 0; k * 32768 < all.length || (k === 0 && all.length === 0); k++) {
        const chunk = all.slice(k * 32768, (k + 1) * 32768)
        let c = chunk
        if (folder.type === 1) {
          const dict = all.slice(Math.max(0, k * 32768 - 32768), k * 32768)
          c = new Uint8Array([0x43, 0x4b, ...deflateRawDict(chunk, dict)])
        }
        blocks.push(dataBlock(c, chunk.length, res?.data ?? 0, folder.badChecksum === k))
      }
    }
    folderData.push(blocks)
  }
  for (const x of o.extraFiles ?? []) {
    fileRecs.push(new Uint8Array([...le32(x.size), ...le32(x.offset), ...le16(x.folder), ...le16(0x5821), ...le16(0x6000), ...le16(0x20), ...enc.encode(x.name), 0]))
  }
  const filesOff = headerLen + folderLen * folders.length
  const filesLen = fileRecs.reduce((n, r) => n + r.length, 0)
  let dataOff = filesOff + filesLen
  const folderRecs: Uint8Array[] = []
  for (const [fi, folder] of folders.entries()) {
    const type = o.typeOverride ?? (folder.type === 3 ? 3 | ((folder.lzxBits ?? 16) << 8) : folder.type)
    folderRecs.push(new Uint8Array([...le32(dataOff), ...le16(folderData[fi].length), ...le16(type), ...new Array(res?.folder ?? 0).fill(0xaa)]))
    dataOff += folderData[fi].reduce((n, b) => n + b.length, 0)
  }
  const total = dataOff
  const nfiles = fileRecs.length
  const hdr = [
    ...enc.encode('MSCF'), ...le32(0), ...le32(total), ...le32(0), ...le32(filesOff), ...le32(0),
    3, 1, ...le16(folders.length), ...le16(nfiles), ...le16(res ? 4 : 0), ...le16(0x1234), ...le16(0),
  ]
  if (res) hdr.push(...le16(res.header), res.folder, res.data, ...new Array(res.header).fill(0xbb))
  const parts: Uint8Array[] = [new Uint8Array(hdr), ...folderRecs, ...fileRecs]
  for (const blocks of folderData) parts.push(...blocks)
  const out = new Uint8Array(total)
  let p = 0
  for (const part of parts) {
    out.set(part, p)
    p += part.length
  }
  return out
}

function dataBlock(c: Uint8Array, u: number, reserve: number, bad: boolean): Uint8Array {
  const head = new Uint8Array([...le16(c.length), ...le16(u), ...new Array(reserve).fill(0xcc)])
  let csum = cabChecksum(head, cabChecksum(c, 0))
  if (bad) csum ^= 1
  const b = new Uint8Array(4 + head.length + c.length)
  b.set(le32(csum), 0)
  b.set(head, 4)
  b.set(c, 4 + head.length)
  return b
}

export function build(h: Helpers): void {
  const { archive, evil, fileA, fileB } = h
  // ISO 9660.
  const isoFiles: Member[] = [
    { path: 'readme.txt', data: fileA },
    { path: 'docs/manual/b.bin', data: fileB },
    { path: 'tools/eicar.com', data: evil },
  ]
  const bootImage = h.concat(enc.encode('boot sector '), new Uint8Array(2048 - 12).fill(0x90))
  archive('joliet.iso', isoImage(isoFiles, { joliet: true, boot: bootImage }), [
    ...isoFiles,
    { path: 'boot/0', data: bootImage },
  ])
  archive('primary.iso', isoImage(isoFiles), isoFiles.map(f => ({ path: primaryName(f.path.split('/').pop()!, false).replace(/;1$/, ''), data: f.data })).map((m, i) => ({
    path: [...isoFiles[i].path.split('/').slice(0, -1).map(p => primaryName(p, true)), m.path].join('/'),
    data: m.data,
  })))
  archive('rockridge.iso', isoImage(isoFiles, { rockRidge: true }), isoFiles)
  archive('loop.iso', isoImage(isoFiles, { joliet: true, loop: true, dupes: 50 }), isoFiles, true)
  // The last extent (docs/manual/b.bin, 3000 bytes) loses its tail.
  archive('truncated.iso', isoImage(isoFiles, { joliet: true, truncateAt: -2000 }), [isoFiles[0], isoFiles[2]], true)
  // Cabinets.
  const big = h.plain(100_000, 31)
  // Code-like bytes: CALL rel32 instructions (E8) between runs, so E8 translation has work.
  const code = new Uint8Array(70_000)
  for (let i = 0; i < code.length; i++) code[i] = (i * 7) & 0xff
  for (let i = 0; i + 5 <= code.length; i += 37) {
    code[i] = 0xe8
    new DataView(code.buffer).setInt32(i + 1, ((i * 13) % 4000) - 2000, true)
  }
  const cabFiles: Member[] = [
    { path: 'a.txt', data: fileA },
    { path: 'dir/b.bin', data: fileB },
    { path: 'eicar.com', data: evil },
  ]
  archive('stored.cab', cabBytes([{ type: 0, files: cabFiles }]), cabFiles)
  const mszipFiles: Member[] = [{ path: 'big.bin', data: big }, { path: 'eicar.com', data: evil }]
  archive('mszip.cab', cabBytes([
    { type: 1, files: mszipFiles },
    { type: 1, files: [cabFiles[0], cabFiles[1]] },
  ]), [...mszipFiles, cabFiles[0], cabFiles[1]])
  const lzxFiles: Member[] = [{ path: 'code.exe', data: code }, { path: 'big.bin', data: big }, { path: 'eicar.com', data: evil }]
  archive('lzx.cab', cabBytes([{ type: 3, lzxBits: 15, lzxE8: 12_000_000, files: lzxFiles }]), lzxFiles)
  archive('lzx21.cab', cabBytes([{ type: 3, lzxBits: 21, files: cabFiles }]), cabFiles)
  archive('reserve.cab', cabBytes([{ type: 1, files: cabFiles }], { reserve: { header: 20, folder: 4, data: 8 } }), cabFiles)
  archive('badsum.cab', cabBytes([{ type: 1, files: cabFiles, badChecksum: 0 }]), cabFiles, true)
  archive('quantum.cab', cabBytes([{ type: 0, files: cabFiles }], { typeOverride: 2 | (21 << 8) }), [])
  archive('overlap.cab', cabBytes([{ type: 0, files: cabFiles }], {
    extraFiles: [
      ...Array.from({ length: 40 }, (_, i) => ({ name: `again${i}.bin`, folder: 0, offset: fileA.length, size: fileB.length })),
      { name: 'past-end.bin', folder: 0, offset: 3000, size: 5000 },
    ],
  }), cabFiles, true)
  // 64 MiB of zeros in 2048 MSZIP blocks.
  archive('zeros-bomb.cab', cabBytes([{ type: 1, files: [{ path: 'zeros.bin', data: new Uint8Array(64 * 1024 * 1024) }] }]), [])
  archive('dag-bomb.iso', isoImage([{ path: 'x.txt', data: fileA }], { joliet: true, dagDepth: 24 }), [])
}
