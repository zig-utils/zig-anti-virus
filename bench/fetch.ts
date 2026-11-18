// Benign corpora (B1, B2, S1) for the atom frequency model and the benchmarks.
//
//   bun bench/fetch.ts B1 [B2 S1 | all] [--out DIR] [--subset ci]   fetch and verify
//   bun bench/fetch.ts --generate [--out DIR]                        rebuild the manifests
//
// A manifest (bench/corpus/<name>.json) lists every file by SHA-256, size, source archive and
// member path; the files themselves are never committed. Fetching downloads each source archive
// once into DIR/dl, extracts it, and copies every listed member to DIR/<name>/<sha256>, checking
// its hash. A file whose hash does not match fails the run.
//
// Manifests list files in SHA-256 order. The CI subset is the files whose hash starts with "0":
// one sixteenth of the corpus, a prefix of the sorted list, and stable when files are added.
//
// `--generate` reads bench/corpus/sources.json, downloads every source, picks members by the
// corpus size limits and each source's include prefixes, drops duplicates (same hash), samples
// each source down to its `max_bytes` by keeping members in hash order, and writes the
// manifests. Same sources, same manifests.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, relative } from 'node:path'

interface Source {
  id: string
  url: string
  format: 'tar.gz' | 'tar.bz2' | 'zip' | 'file'
  license: string
  project: string
  include?: string[]
  max_bytes?: number
  /** GitHub tag archives are generated on demand: members are checked, the archive is not. */
  archive_hash_unstable?: boolean
}

interface CorpusSpec {
  description: string
  min_size: number
  max_size: number
  sources: Source[]
}

interface Archive extends Source {
  sha256: string
  size: number
}

interface Entry {
  sha256: string
  size: number
  archive: string
  member: string
}

interface Manifest {
  name: string
  description: string
  sampling: string
  file_count: number
  total_bytes: number
  ci_file_count: number
  ci_total_bytes: number
  archives: Archive[]
  files: Entry[]
}

const root = new URL('..', import.meta.url).pathname
const corpusDir = join(root, 'bench', 'corpus')
const args = process.argv.slice(2)
const flag = (name: string) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : undefined
}
const out = flag('--out') ?? join(homedir(), '.cache', 'zav', 'corpus')
const subset = flag('--subset')
const valued = new Set(['--out', '--subset'])
const names = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && valued.has(args[i - 1])))

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function run(cmd: string, argv: string[]): void {
  const r = spawnSync(cmd, argv, { stdio: ['ignore', 'inherit', 'inherit'] })
  if (r.status !== 0) throw new Error(`${cmd} ${argv.join(' ')} failed`)
}

/** Download `url` into DIR/dl once; the file name is the source id. */
function download(src: Source): string {
  const dl = join(out, 'dl')
  mkdirSync(dl, { recursive: true })
  const path = join(dl, src.id)
  if (!existsSync(path)) {
    console.error(`download ${src.url}`)
    run('curl', ['-fsSL', '--retry', '3', '-o', `${path}.part`, src.url])
    renameSync(`${path}.part`, path)
  }
  return path
}

/** Extract an archive into DIR/x/<id> once and return that directory. */
function extract(src: Source, archive: string): string {
  const dir = join(out, 'x', src.id)
  if (existsSync(join(dir, '.done'))) return dir
  rmSync(dir, { recursive: true, force: true })
  mkdirSync(dir, { recursive: true })
  if (src.format === 'zip') run('unzip', ['-q', '-o', archive, '-d', dir])
  else if (src.format === 'tar.gz') run('tar', ['-xzf', archive, '-C', dir])
  else if (src.format === 'tar.bz2') run('tar', ['-xjf', archive, '-C', dir])
  writeFileSync(join(dir, '.done'), '')
  return dir
}

function walk(dir: string, base = dir, acc: string[] = []): string[] {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, name.name)
    if (name.isDirectory()) walk(p, base, acc)
    else if (name.isFile() && name.name !== '.done') acc.push(relative(base, p))
  }
  return acc
}

/** Where a member lives on disk after download and extraction. */
function memberPath(src: Source, member: string): string {
  const archive = download(src)
  if (src.format === 'file') return archive
  return join(extract(src, archive), member)
}

function generate(): void {
  const spec = JSON.parse(readFileSync(join(corpusDir, 'sources.json'), 'utf8')) as { corpora: Record<string, CorpusSpec> }
  for (const [name, corpus] of Object.entries(spec.corpora)) {
    const seen = new Set<string>()
    const archives: Archive[] = []
    const files: Entry[] = []
    for (const src of corpus.sources) {
      const archive = download(src)
      archives.push({ ...src, sha256: sha256File(archive), size: statSync(archive).size })
      const members = src.format === 'file' ? [''] : walk(extract(src, archive)).sort()
      const picked: Entry[] = []
      for (const member of members) {
        if (src.include && !src.include.some(p => member.startsWith(p))) continue
        const path = memberPath(src, member)
        const size = statSync(path).size
        if (size < corpus.min_size || size > corpus.max_size) continue
        const sha256 = sha256File(path)
        if (seen.has(sha256)) continue
        seen.add(sha256)
        picked.push({ sha256, size, archive: src.id, member })
      }
      // Deterministic sample: members in hash order until the source's byte budget is spent.
      picked.sort((a, b) => (a.sha256 < b.sha256 ? -1 : 1))
      let bytes = 0
      for (const e of picked) {
        if (src.max_bytes !== undefined && bytes + e.size > src.max_bytes) {
          seen.delete(e.sha256)
          continue
        }
        bytes += e.size
        files.push(e)
      }
    }
    files.sort((a, b) => (a.sha256 < b.sha256 ? -1 : 1))
    const ci = files.filter(inCi)
    const manifest: Manifest = {
      name,
      description: corpus.description,
      sampling: 'files in SHA-256 order; the CI subset is every file whose hash starts with 0',
      file_count: files.length,
      total_bytes: files.reduce((n, e) => n + e.size, 0),
      ci_file_count: ci.length,
      ci_total_bytes: ci.reduce((n, e) => n + e.size, 0),
      archives: archives.map(({ max_bytes, include, ...a }) => ({ ...a, ...(include ? { include } : {}) })) as Archive[],
      files,
    }
    writeFileSync(join(corpusDir, `${name}.json`), render(manifest))
    console.log(`${name}: ${files.length} files, ${manifest.total_bytes} bytes (CI subset ${ci.length} files, ${manifest.ci_total_bytes} bytes)`)
  }
}

/** Pretty JSON with one file entry per line, so manifest diffs stay readable. */
function render(m: Manifest): string {
  const { files, ...head } = m
  const top = JSON.stringify(head, null, 2).replace(/\n}$/, '')
  return `${top},\n  "files": [\n${files.map(f => `    ${JSON.stringify(f)}`).join(',\n')}\n  ]\n}\n`
}

function inCi(e: Entry): boolean {
  return e.sha256.startsWith('0')
}

function fetch(name: string): void {
  const manifest = JSON.parse(readFileSync(join(corpusDir, `${name}.json`), 'utf8')) as Manifest
  const files = subset === 'ci' ? manifest.files.filter(inCi) : manifest.files
  const dest = join(out, subset === 'ci' ? `${name}-ci` : name)
  mkdirSync(dest, { recursive: true })
  const archives = new Map(manifest.archives.map(a => [a.id, a]))
  const checked = new Set<string>()
  let bad = 0
  let bytes = 0
  for (const e of files) {
    const target = join(dest, e.sha256)
    bytes += e.size
    if (existsSync(target) && statSync(target).size === e.size) continue
    const src = archives.get(e.archive)
    if (!src) throw new Error(`${name}: unknown archive ${e.archive}`)
    if (!checked.has(src.id)) {
      checked.add(src.id)
      const got = sha256File(download(src))
      if (got !== src.sha256) {
        if (!src.archive_hash_unstable) throw new Error(`${src.id}: archive hash ${got}, manifest says ${src.sha256}`)
        console.error(`${src.id}: archive bytes changed upstream; members are still checked one by one`)
      }
    }
    const path = memberPath(src, e.member)
    const got = existsSync(path) ? sha256File(path) : 'missing'
    if (got !== e.sha256) {
      console.error(`${name}: ${e.archive}:${e.member} has hash ${got}, manifest says ${e.sha256}`)
      bad++
      continue
    }
    copyFileSync(path, target)
  }
  console.log(`${name}${subset === 'ci' ? ' (CI subset)' : ''}: ${files.length - bad} of ${files.length} files verified, ${bytes} bytes in ${dest}`)
  if (bad > 0) process.exit(1)
}

if (args.includes('--generate')) generate()
else {
  const list = names.length === 0 || names.includes('all') ? ['B1', 'B2', 'S1'] : names
  for (const name of list) fetch(name)
}
