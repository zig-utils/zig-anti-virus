import { afterEach, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { fetchCorpus, loadManifest, selectFiles, type Manifest } from './fetch'

const scratch: string[] = []
afterEach(() => {
  for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function fixture(): { manifest: Manifest, out: string, digest: string } {
  const out = mkdtempSync(join(tmpdir(), 'zav-corpus-test-'))
  scratch.push(out)
  const payload = 'benign public corpus fixture\n'
  const digest = createHash('sha256').update(payload).digest('hex')
  const source = join(out, 'source.txt')
  writeFileSync(source, payload)
  return {
    out, digest,
    manifest: {
      name: 'B1', description: 'fixture', sampling: 'SHA-256 prefix',
      file_count: 1, total_bytes: payload.length, ci_file_count: 0, ci_total_bytes: 0,
      archives: [{ id: 'fixture', url: pathToFileURL(source).href, format: 'file', license: 'CC0-1.0', project: 'test fixture', sha256: digest, size: payload.length }],
      files: [{ sha256: digest, size: payload.length, archive: 'fixture', member: '' }],
    },
  }
}

test('fetching repairs same-size corruption instead of trusting a cached target', () => {
  const { manifest, out, digest } = fixture()
  mkdirSync(join(out, 'B1'))
  writeFileSync(join(out, 'B1', digest), 'x'.repeat(manifest.files[0].size))
  fetchCorpus(manifest, { out })
  expect(readFileSync(join(out, 'B1', digest), 'utf8')).toBe('benign public corpus fixture\n')
})

test('fetching rejects corrupt cached source bytes', () => {
  const { manifest, out } = fixture()
  mkdirSync(join(out, 'dl'))
  writeFileSync(join(out, 'dl', 'fixture'), 'x'.repeat(manifest.total_bytes))
  expect(() => fetchCorpus(manifest, { out })).toThrow('archive hash')
})

test('fetching verifies member size as well as digest', () => {
  const { manifest, out } = fixture()
  manifest.files[0].size++
  manifest.total_bytes++
  expect(() => fetchCorpus(manifest, { out })).toThrow('failed verification')
})

test('fetching rejects a member that escapes the extraction directory', () => {
  const { manifest, out } = fixture()
  manifest.files[0].member = '../outside.txt'
  expect(() => fetchCorpus(manifest, { out })).toThrow('unsafe member')
})

for (const name of ['B1', 'B2', 'S1']) {
  test(`${name} CI selection is the stable SHA-256 prefix of its validated manifest`, () => {
    const manifest = loadManifest(name)
    const ci = selectFiles(manifest, 'ci')
    expect(ci.length).toBeGreaterThan(0)
    expect(selectFiles(manifest).slice(0, ci.length)).toEqual(ci)
    expect(ci.every(file => file.sha256.startsWith('0'))).toBe(true)
    expect(selectFiles(manifest)[ci.length].sha256.startsWith('0')).toBe(false)
  })
}

test('the loader only permits the three benign corpora', () => {
  expect(() => loadManifest('../M1')).toThrow('unknown benign corpus')
  expect(() => loadManifest('M1')).toThrow('unknown benign corpus')
  expect(() => loadManifest('A1')).toThrow('unknown benign corpus')
})

test('the CLI rejects a misspelled subset before any download', async () => {
  const process = Bun.spawn(['bun', 'bench/fetch.ts', 'B1', '--subset', 'ic'], { stdout: 'pipe', stderr: 'pipe' })
  expect(await process.exited).toBe(1)
  expect(await new Response(process.stderr).text()).toContain('--subset must be ci')
})
