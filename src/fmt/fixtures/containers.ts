// Phase-three container fixtures (P5.18 and P5.19): ISO 9660, CAB, DMG, NSIS, CHM and UPX.
// Called from make-fixtures.ts, which owns the output list; every builder here works from the
// format's public specification, byte by byte, so malformed and adversarial variants are exact.

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
  archive('dag-bomb.iso', isoImage([{ path: 'x.txt', data: fileA }], { joliet: true, dagDepth: 24 }), [])
}
