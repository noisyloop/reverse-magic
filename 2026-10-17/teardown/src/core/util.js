// Small helpers shared by every parser. Parsers only ever read bytes; nothing
// in this project executes, evaluates or renders content from the dropped file.

export class Reader {
  constructor(bytes, littleEndian = true) {
    this.bytes = bytes
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    this.le = littleEndian
    this.length = bytes.byteLength
  }
  has(off, n = 1) {
    return off >= 0 && n >= 0 && off + n <= this.length
  }
  u8(o) {
    if (!this.has(o, 1)) throw new RangeError(`read past end at 0x${o.toString(16)}`)
    return this.bytes[o]
  }
  u16(o) {
    if (!this.has(o, 2)) throw new RangeError(`read past end at 0x${o.toString(16)}`)
    return this.view.getUint16(o, this.le)
  }
  u32(o) {
    if (!this.has(o, 4)) throw new RangeError(`read past end at 0x${o.toString(16)}`)
    return this.view.getUint32(o, this.le)
  }
  // 64-bit values are returned as Numbers. Anything above 2^53 loses precision,
  // which is fine for display and bounds checks.
  u64(o) {
    if (!this.has(o, 8)) throw new RangeError(`read past end at 0x${o.toString(16)}`)
    const lo = this.view.getUint32(o + (this.le ? 0 : 4), this.le)
    const hi = this.view.getUint32(o + (this.le ? 4 : 0), this.le)
    return hi * 4294967296 + lo
  }
  // NUL-terminated ASCII string, capped so a malformed file cannot make us scan forever.
  cstr(o, max = 260) {
    let s = ''
    for (let i = o; i < this.length && i < o + max; i++) {
      const c = this.bytes[i]
      if (c === 0) break
      s += c >= 32 && c < 127 ? String.fromCharCode(c) : '�'
    }
    return s
  }
  fixed(o, n) {
    let s = ''
    for (let i = o; i < o + n && i < this.length; i++) {
      const c = this.bytes[i]
      if (c === 0) break
      s += c >= 32 && c < 127 ? String.fromCharCode(c) : '�'
    }
    return s
  }
}

export const hex = (n, w = 0) => '0x' + (n >>> 0 === n ? (n >>> 0) : n).toString(16).toUpperCase().padStart(w, '0')

export function bytesToHex(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}

export function startsWith(bytes, sig, at = 0) {
  if (at + sig.length > bytes.length) return false
  for (let i = 0; i < sig.length; i++) if (bytes[at + i] !== sig[i]) return false
  return true
}

export const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0))

export function shannon(bytes, start = 0, end = bytes.length) {
  const n = end - start
  if (n <= 0) return 0
  const counts = new Uint32Array(256)
  for (let i = start; i < end; i++) counts[bytes[i]]++
  let h = 0
  for (let i = 0; i < 256; i++) {
    const c = counts[i]
    if (c) {
      const p = c / n
      h -= p * Math.log2(p)
    }
  }
  return h
}

// A finding is the unit the UI renders. `incomplete` marks results where the
// absence of data must not be read as absence of the thing.
export function finding(id, severity, title, detail, extra = {}) {
  return { id, severity, title, detail, ...extra }
}
