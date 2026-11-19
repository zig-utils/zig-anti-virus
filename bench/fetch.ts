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
import { fileURLToPath } from 'node:url'

export interface Source {
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

export interface Archive extends Source {
  sha256: string
  size: number
}

export interface Entry {
  sha256: string
  size: number
  archive: string
  member: string
}

export interface Manifest {
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

const corpusDir = fileURLToPath(new URL('corpus/', import.meta.url))
const defaultOut = join(homedir(), '.cache', 'zav', 'corpus')

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function run(cmd: string, argv: string[]): void {
  const r = spawnSync(cmd, argv, { stdio: ['ignore', 'inherit', 'inherit'] })
  if (r.status !== 0) throw new Error(`${cmd} ${argv.join(' ')} failed`)
}

/** Download `url` into DIR/dl once; the file name is the source id. */
function download(src: Source, out: string): string {
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
function extract(src: Source, archive: string, out: string): string {
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
function memberPath(src: Source, member: string, out: string): string {
  const archive = download(src, out)
  if (src.format === 'file') return archive
  return join(extract(src, archive, out), member)
}

function generate(out: string): void {
  const spec = JSON.parse(readFileSync(join(corpusDir, 'sources.json'), 'utf8')) as { corpora: Record<string, CorpusSpec> }
  for (const [name, corpus] of Object.entries(spec.corpora)) {
    const seen = new Set<string>()
    const archives: Archive[] = []
    const files: Entry[] = []
    for (const src of corpus.sources) {
      const archive = download(src, out)
      archives.push({ ...src, sha256: sha256File(archive), size: statSync(archive).size })
      const members = src.format === 'file' ? [''] : walk(extract(src, archive, out)).sort()
      const picked: Entry[] = []
      for (const member of members) {
        if (src.include && !src.include.some(p => member.startsWith(p))) continue
        const path = memberPath(src, member, out)
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

export function inCi(e: Entry): boolean {
  return e.sha256.startsWith('0')
}

export function fetchCorpus(manifest: Manifest, options: { out?: string, subset?: 'ci' } = {}): void {
  const { out = defaultOut, subset } = options
  validateManifest(manifest)
  const { name } = manifest
  const files = selectFiles(manifest, subset)
  const dest = join(out, subset === 'ci' ? `${name}-ci` : name)
  mkdirSync(dest, { recursive: true })
  const archives = new Map(manifest.archives.map(a => [a.id, a]))
  const checked = new Set<string>()
  let bad = 0
  let bytes = 0
  for (const e of files) {
    const target = join(dest, e.sha256)
    bytes += e.size
    if (existsSync(target) && statSync(target).size === e.size && sha256File(target) === e.sha256) continue
    const src = archives.get(e.archive)
    if (!src) throw new Error(`${name}: unknown archive ${e.archive}`)
    if (!checked.has(src.id)) {
      checked.add(src.id)
      const got = sha256File(download(src, out))
      if (got !== src.sha256 || statSync(download(src, out)).size !== src.size) {
        if (!src.archive_hash_unstable) throw new Error(`${src.id}: archive hash ${got}, manifest says ${src.sha256}`)
        console.error(`${src.id}: archive bytes changed upstream; members are still checked one by one`)
      }
    }
    const path = memberPath(src, e.member, out)
    const size = existsSync(path) ? statSync(path).size : -1
    const got = size >= 0 ? sha256File(path) : 'missing'
    if (got !== e.sha256 || size !== e.size) {
      console.error(`${name}: ${e.archive}:${e.member} has hash ${got}, size ${size}; expected ${e.sha256}, size ${e.size}`)
      bad++
      continue
    }
    copyFileSync(path, `${target}.part`)
    renameSync(`${target}.part`, target)
  }
  console.log(`${name}${subset === 'ci' ? ' (CI subset)' : ''}: ${files.length - bad} of ${files.length} files verified, ${bytes} bytes in ${dest}`)
  if (bad > 0) throw new Error(`${name}: ${bad} corpus member(s) failed verification`)
}

/** Shared manifest boundary for corpus consumers; importing this module performs no I/O. */
export function loadManifest(name: string, directory = corpusDir): Manifest {
  if (!['B1', 'B2', 'S1'].includes(name)) throw new Error(`unknown benign corpus: ${name}`)
  const manifest = JSON.parse(readFileSync(join(directory, `${name}.json`), 'utf8')) as Manifest
  validateManifest(manifest)
  if (manifest.name !== name) throw new Error(`${name}: manifest name mismatch`)
  return manifest
}

/** Validate metadata before it can name any path or create a misleading benchmark input. */
export function validateManifest(manifest: Manifest): void {
  const fail = (message: string): never => { throw new Error(`invalid corpus manifest: ${message}`) }
  if (!['B1', 'B2', 'S1'].includes(manifest.name)) fail('unknown name')
  if (!Array.isArray(manifest.archives) || !Array.isArray(manifest.files)) fail('missing archives or files')
  const digest = /^[a-f0-9]{64}$/
  const size = (n: number) => Number.isSafeInteger(n) && n >= 0
  const archives = new Map<string, Archive>()
  for (const source of manifest.archives) {
    if (!/^[a-zA-Z0-9_-]+$/.test(source.id) || archives.has(source.id)) fail('invalid or duplicate archive id')
    if (!digest.test(source.sha256) || !size(source.size)) fail(`invalid archive digest or size: ${source.id}`)
    if (!['file', 'zip', 'tar.gz', 'tar.bz2'].includes(source.format)) fail(`unknown archive format: ${source.id}`)
    if (!source.url || !source.license || !source.project) fail(`missing source provenance: ${source.id}`)
    archives.set(source.id, source)
  }
  let previous = ''
  for (const file of manifest.files) {
    if (!digest.test(file.sha256) || !size(file.size)) fail('invalid file digest or size')
    if (file.sha256 <= previous) fail('files must be unique and in SHA-256 order')
    previous = file.sha256
    const source = archives.get(file.archive)
    if (!source) fail(`unknown archive: ${file.archive}`)
    if (typeof file.member !== 'string' || file.member.startsWith('/') || file.member.includes('\\') || file.member.split('/').some(part => part === '..')) fail('unsafe member path')
    if (source.format === 'file' && file.member !== '') fail('direct file must have an empty member')
    if (source.format !== 'file' && !file.member) fail('archive member is required')
  }
  const ci = manifest.files.filter(inCi)
  if (manifest.file_count !== manifest.files.length || manifest.total_bytes !== manifest.files.reduce((n, file) => n + file.size, 0)) fail('file totals disagree')
  if (manifest.ci_file_count !== ci.length || manifest.ci_total_bytes !== ci.reduce((n, file) => n + file.size, 0)) fail('CI totals disagree')
}

export function selectFiles(manifest: Manifest, subset?: 'ci'): Entry[] {
  return subset === 'ci' ? manifest.files.filter(inCi) : manifest.files.slice()
}

function main(args: string[]): void {
  let out = defaultOut
  let subset: 'ci' | undefined
  let regenerate = false
  const names: string[] = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '--out') {
      if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error('--out requires a directory')
      out = args[++i]
    }
    else if (arg === '--subset') {
      if (args[++i] !== 'ci') throw new Error('--subset must be ci')
      subset = 'ci'
    }
    else if (arg === '--generate') regenerate = true
    else if (['B1', 'B2', 'S1', 'all'].includes(arg)) names.push(arg)
    else throw new Error(`unknown argument: ${arg}`)
  }
  if (regenerate) {
    if (subset || names.length) throw new Error('--generate cannot select corpora or a subset')
    generate(out)
  }
  else {
    const list = !names.length || names.includes('all') ? ['B1', 'B2', 'S1'] : [...new Set(names)]
    for (const name of list) fetchCorpus(loadManifest(name), { out, subset })
  }
}

if (import.meta.main) {
  try { main(process.argv.slice(2)) }
  catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
  }
}
