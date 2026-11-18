// Generates the synthetic CVD and CLD fixtures used by src/compile/cvd.zig tests.
//
//   bun src/compile/fixtures/make-cvd.ts
//
// The RSA key below is a TEST-ONLY 1024-bit key generated for these fixtures. It signs nothing
// real; production verification uses Talos's public key compiled into cvd.zig. The fixtures follow
// the legacy CVD layout: a 512-byte colon-separated header, then a gzip (CVD) or plain (CLD) tar
// whose first member is COPYING, a .info file listing name:size:sha256, and the databases.
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'

const n = 133858472367480942443681375244325039297796719834729923401740862235236999747033109001156180011182520596364364281889200693323506963825754670767974268097512630853385426987303214292459162046967283983663000290115505224996352052960256345736447220280094796699090787902085401043109924945571488108869367233953422280099n
const d = 6921988538587254740705802534492234282622535110241538526458333187592019655197754038251953767458039920977140097217182677719049774942482606454867705183064074149404741099755291551930832680645061645502656221891441767763974341344361813619880575977366920769133099695946898134601165995371463343000594132123556857065n
const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n
  base %= mod
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod
    base = (base * base) % mod
    exp >>= 1n
  }
  return result
}

/** ClamAV's signature encoding: 6-bit digits, least significant first. */
function encodeSig(value: bigint): string {
  let out = ''
  while (value > 0n) {
    out += alphabet[Number(value & 63n)]
    value >>= 6n
  }
  return out
}

function tarEntry(name: string, data: Uint8Array): Uint8Array {
  const header = new Uint8Array(512)
  const enc = new TextEncoder()
  header.set(enc.encode(name), 0)
  header.set(enc.encode('0000644\0'), 100)
  header.set(enc.encode('0000000\0'), 108)
  header.set(enc.encode('0000000\0'), 116)
  header.set(enc.encode(`${data.length.toString(8).padStart(11, '0')}\0`), 124)
  header.set(enc.encode('00000000000\0'), 136)
  header.set(enc.encode('        '), 148)
  header[156] = 0x30
  header.set(enc.encode('ustar\x0000'), 257)
  let sum = 0
  for (const b of header) sum += b
  header.set(enc.encode(`${sum.toString(8).padStart(6, '0')}\0 `), 148)
  const padded = new Uint8Array(Math.ceil(data.length / 512) * 512)
  padded.set(data)
  return concat([header, padded])
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

const enc = new TextEncoder()
const version = 7
const sigs = 2
const flevel = 90
const stime = 1700000000
const buildTime = '14 Nov 2023 22-13 +0000'

const hdb = enc.encode('44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n')
const extra = enc.encode('aa0dbbb5a26ee5d6e0a72ca1aeb7e5a9:12:Zav.Fixture.Two\n')
const files: Array<[string, Uint8Array]> = [['test.hdb', hdb], ['test2.hdb', extra]]
const info = enc.encode([
  `ClamAV-VDB:${buildTime}:${version}:${sigs}:${flevel}:X:X:fixture:${stime}`,
  ...files.map(([name, data]) => `${name}:${data.length}:${createHash('sha256').update(data).digest('hex')}`),
  '',
].join('\n'))
const tar = concat([
  tarEntry('COPYING', enc.encode('Fixture data for zav tests. Not a real signature database.\n')),
  tarEntry('test.info', info),
  ...files.map(([name, data]) => tarEntry(name, data)),
  new Uint8Array(1024),
])

function header(body: Uint8Array, signed: boolean): Uint8Array {
  const md5 = createHash('md5').update(body).digest()
  const md5hex = md5.toString('hex')
  const dsig = signed ? encodeSig(modpow(BigInt(`0x${md5hex}`), d, n)) : 'X'
  const text = `ClamAV-VDB:${buildTime}:${version}:${sigs}:${flevel}:${md5hex}:${dsig}:fixture:${stime}`
  const out = new Uint8Array(512).fill(0x20)
  out.set(enc.encode(text))
  return out
}

const gz = new Uint8Array(gzipSync(tar))
await Bun.write(new URL('test.cvd', import.meta.url), concat([header(gz, true), gz]))
await Bun.write(new URL('test.cld', import.meta.url), concat([header(tar, false), tar]))
console.log('wrote test.cvd and test.cld')
