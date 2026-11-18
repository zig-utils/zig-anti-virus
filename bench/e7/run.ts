// E7: std and our decoders against C libraries. This script builds the corpus and measures the
// C side; `zig build bench` measures the Zig side over the same files.
//
//   bun bench/e7/run.ts            # from the repository root; writes zig-out/e7/
//   zig build bench -- zig-out/bench.json
//
// The corpus is deterministic: 16 MiB of English-like text and 16 MiB of structured binary
// (integer tables, repeated records, noise), each compressed with the reference encoders:
// gzip -6 (node:zlib), bzip2 -9, xz -6 (liblzma via Python), zstd -3 and -19 (Bun's libzstd).
// C decoders are driven through Bun (libdeflate, Bun's zlib, libzstd) and Python (the system
// zlib, libbz2 and liblzma); one call per 16 MiB buffer, so call overhead is noise. C libraries
// are used here only: the engine stays pure Zig.
import { spawnSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import zlib from 'node:zlib'

const out = 'zig-out/e7'
mkdirSync(out, { recursive: true })
const size = 16 * 1024 * 1024

let seed = 0x2545f491
function rand(): number {
  seed ^= seed << 13
  seed >>>= 0
  seed ^= seed >>> 17
  seed ^= seed << 5
  seed >>>= 0
  return seed
}

function text(): Uint8Array {
  seed = 7
  const syll = ['an', 'ber', 'co', 'de', 'el', 'fa', 'gi', 'ho', 'in', 'ju', 'ka', 'lo', 'mi', 'no', 'or', 'pe', 'qu', 're', 'st', 'th', 'un', 'ver', 'wa', 'ex', 'yo', 'ze']
  const vocab: string[] = []
  for (let i = 0; i < 3000; i++) {
    let w = ''
    for (let k = 1 + (rand() % 4); k > 0; k--) w += syll[rand() % syll.length]
    vocab.push(w)
  }
  const b = new Uint8Array(size)
  let i = 0
  let sentence = 0
  while (i < size) {
    // Zipf-ish: small indices far more often.
    const r = rand() / 0xffffffff
    let w = vocab[Math.floor(vocab.length * r * r * r)]
    if (sentence === 0) w = w[0].toUpperCase() + w.slice(1)
    sentence++
    let s = w
    if (sentence > 6 + (rand() % 12)) {
      s += rand() % 5 === 0 ? '.\n' : '. '
      sentence = 0
    } else s += rand() % 9 === 0 ? ', ' : ' '
    for (let k = 0; k < s.length && i < size; k++) b[i++] = s.charCodeAt(k)
  }
  return b
}

function binary(): Uint8Array {
  seed = 11
  const b = new Uint8Array(size)
  const v = new DataView(b.buffer)
  let i = 0
  let counter = 0x401000
  while (i < size) {
    const kind = rand() % 10
    if (kind < 4) {
      // A table of slowly increasing little-endian u32 values (offsets, addresses).
      const n = 16 + (rand() % 256)
      for (let k = 0; k < n && i + 4 <= size; k++, i += 4) {
        counter += rand() % 64
        v.setUint32(i, counter, true)
      }
    } else if (kind < 7) {
      // A repeated fixed-size record with a few varying bytes (structs, instructions).
      const rec = new Uint8Array(24).map(() => rand() & 0xff)
      const n = 4 + (rand() % 64)
      for (let k = 0; k < n; k++) {
        rec[rand() % 24] = rand() & 0xff
        for (let j = 0; j < 24 && i < size; j++) b[i++] = rec[j]
      }
    } else if (kind < 9) {
      const n = 32 + (rand() % 2048)
      for (let k = 0; k < n && i < size; k++) b[i++] = rand() & 0xff
    } else {
      const n = 64 + (rand() % 4096)
      const c = rand() & 0xff
      for (let k = 0; k < n && i < size; k++) b[i++] = c
    }
  }
  return b
}

function run(cmd: string, args: string[], input: Uint8Array): Uint8Array {
  const r = spawnSync(cmd, args, { input, maxBuffer: 1 << 30 })
  if (r.status !== 0) throw new Error(`${cmd}: ${r.stderr}`)
  return new Uint8Array(r.stdout)
}

const corpora: Record<string, Uint8Array> = { text: text(), binary: binary() }
const files: { name: string, codec: string, compressed: Uint8Array, plain: Uint8Array }[] = []
for (const [name, data] of Object.entries(corpora)) {
  writeFileSync(`${out}/${name}.raw`, data)
  const add = (codec: string, ext: string, c: Uint8Array) => {
    writeFileSync(`${out}/${name}.${ext}`, c)
    files.push({ name: `${name}.${ext}`, codec, compressed: c, plain: data })
  }
  add('gzip', 'gz', zlib.gzipSync(data, { level: 6 }))
  add('bzip2', 'bz2', run('bzip2', ['-c', '-9'], data))
  add('xz', 'xz', run('python3', ['-I', '-c', 'import sys,lzma; sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(), preset=6))'], data))
  add('zstd', 'zst', zlib.zstdCompressSync(data, { params: { [zlib.constants.ZSTD_c_compressionLevel]: 3 } }))
  add('zstd', 'zst19', zlib.zstdCompressSync(data, { params: { [zlib.constants.ZSTD_c_compressionLevel]: 19 } }))
}

/** Best-of-5 MB/s (uncompressed output), each round at least 300 ms. */
function measure(f: () => number, plainLen: number): number {
  let best = Infinity
  for (let r = 0; r < 5; r++) {
    let calls = 0
    const start = performance.now()
    let elapsed = 0
    while (elapsed < 300) {
      if (f() !== plainLen) throw new Error('length mismatch')
      calls++
      elapsed = performance.now() - start
    }
    best = Math.min(best, elapsed / calls)
  }
  return plainLen / (best / 1000) / 1e6
}

const results: { file: string, decoder: string, mbps: number }[] = []
for (const f of files) {
  const n = f.plain.length
  if (f.codec === 'gzip') {
    results.push({ file: f.name, decoder: 'libdeflate (Bun)', mbps: measure(() => Bun.gunzipSync(f.compressed, { library: 'libdeflate' }).length, n) })
    results.push({ file: f.name, decoder: 'zlib (Bun)', mbps: measure(() => Bun.gunzipSync(f.compressed, { library: 'zlib' }).length, n) })
  }
  if (f.codec === 'zstd') results.push({ file: f.name, decoder: 'libzstd (Bun)', mbps: measure(() => Bun.zstdDecompressSync(f.compressed).length, n) })
}

// Python: the system zlib, libbz2 and liblzma.
const pyScript = `
import sys, time, json, zlib, bz2, lzma
out = []
for name, codec in json.loads(sys.argv[1]):
    data = open('${out}/' + name, 'rb').read()
    dec = {'gzip': lambda d: zlib.decompress(d, 31), 'bzip2': bz2.decompress, 'xz': lzma.decompress}[codec]
    n = len(dec(data))
    best = 1e9
    for _ in range(5):
        calls, start = 0, time.perf_counter()
        while time.perf_counter() - start < 0.3:
            dec(data); calls += 1
        best = min(best, (time.perf_counter() - start) / calls)
    out.append({'file': name, 'decoder': {'gzip': 'zlib ' + zlib.ZLIB_RUNTIME_VERSION + ' (system)', 'bzip2': 'libbz2 (system)', 'xz': 'liblzma (system)'}[codec], 'mbps': n / best / 1e6})
print(json.dumps(out))
`
const pyFiles = files.filter(f => f.codec !== 'zstd').map(f => [f.name, f.codec])
const py = spawnSync('python3', ['-I', '-c', pyScript, JSON.stringify(pyFiles)], { maxBuffer: 1 << 24 })
if (py.status !== 0) throw new Error(String(py.stderr))
results.push(...JSON.parse(String(py.stdout)))

writeFileSync(`${out}/c-results.json`, JSON.stringify({ sizes: Object.fromEntries(files.map(f => [f.name, f.compressed.length])), results }, null, 2))
for (const r of results) console.log(`${r.file.padEnd(14)} ${r.decoder.padEnd(26)} ${r.mbps.toFixed(0).padStart(6)} MB/s`)
console.log(`\nwrote ${out}/ (corpus and c-results.json)`)

