import { bytesToHex } from './util.js'

// MD5 is not in Web Crypto. Compact implementation, used for display/lookups only.
function md5(bytes) {
  const K = new Uint32Array(64)
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21]
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0
  const len = bytes.length
  const padded = new Uint8Array(((len + 8) >> 6 << 6) + 64)
  padded.set(bytes)
  padded[len] = 0x80
  const dv = new DataView(padded.buffer)
  dv.setUint32(padded.length - 8, (len << 3) >>> 0, true)
  dv.setUint32(padded.length - 4, Math.floor(len / 0x20000000), true)
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476
  const M = new Uint32Array(16)
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true)
    let A = a0, B = b0, C = c0, D = d0
    for (let i = 0; i < 64; i++) {
      let F, g
      if (i < 16) { F = (B & C) | (~B & D); g = i }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15 }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15 }
      else { F = C ^ (B | ~D); g = (7 * i) & 15 }
      F = (F + A + K[i] + M[g]) >>> 0
      A = D; D = C; C = B
      const s = S[((i >> 4) << 2) | (i & 3)]
      B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0
  }
  const out = new Uint8Array(16)
  const odv = new DataView(out.buffer)
  odv.setUint32(0, a0, true); odv.setUint32(4, b0, true); odv.setUint32(8, c0, true); odv.setUint32(12, d0, true)
  return bytesToHex(out)
}

export async function hashAll(bytes, withMd5 = true) {
  const out = withMd5 ? { md5: md5(bytes) } : {}
  // Web Crypto only exists in secure contexts (https, localhost). Skip SHA otherwise.
  if (!globalThis.crypto || !globalThis.crypto.subtle) return out
  for (const [key, algo] of [['sha1', 'SHA-1'], ['sha256', 'SHA-256']]) {
    out[key] = bytesToHex(new Uint8Array(await crypto.subtle.digest(algo, bytes)))
  }
  return out
}
