import { shannon } from './util.js'
import { EMBED_SIGS } from './signatures.js'

const MAX_STRINGS = 20000

// ASCII + UTF-16LE strings, each with its file offset so the UI can jump to it.
export function extractStrings(bytes, minLen = 5) {
  const out = []
  let truncated = false

  let start = -1
  for (let i = 0; i <= bytes.length; i++) {
    const c = i < bytes.length ? bytes[i] : 0
    const printable = (c >= 32 && c < 127) || c === 9
    if (printable) {
      if (start < 0) start = i
    } else if (start >= 0) {
      if (i - start >= minLen) {
        out.push({ off: start, enc: 'ascii', text: latin(bytes, start, i) })
        if (out.length >= MAX_STRINGS) { truncated = true; break }
      }
      start = -1
    }
  }

  if (!truncated) {
    let s = -1
    let chars = 0
    for (let i = 0; i + 1 <= bytes.length; i += 1) {
      const lo = bytes[i]
      const hi = i + 1 < bytes.length ? bytes[i + 1] : 1
      const ok = hi === 0 && ((lo >= 32 && lo < 127) || lo === 9)
      if (ok) {
        if (s < 0) { s = i; chars = 0 }
        chars++
        i++ // consume the pair
      } else if (s >= 0) {
        if (chars >= minLen) {
          out.push({ off: s, enc: 'utf16', text: utf16(bytes, s, chars) })
          if (out.length >= MAX_STRINGS * 1.25) { truncated = true; break }
        }
        s = -1
        chars = 0
      }
    }
  }

  out.sort((a, b) => a.off - b.off)
  return { strings: out, truncated }
}

function latin(bytes, a, b) {
  let s = ''
  for (let i = a; i < b; i++) s += String.fromCharCode(bytes[i])
  return s
}
function utf16(bytes, a, chars) {
  let s = ''
  for (let i = 0; i < chars; i++) s += String.fromCharCode(bytes[a + i * 2])
  return s
}

// Sliding-window Shannon entropy, downsampled to at most `windows` buckets.
export function entropyProfile(bytes, windows = 128) {
  const n = bytes.length
  const overall = shannon(bytes)
  if (n === 0) return { overall: 0, windows: [], windowSize: 0 }
  const size = Math.max(256, Math.ceil(n / windows))
  const out = []
  for (let off = 0; off < n; off += size) {
    const end = Math.min(n, off + size)
    out.push({ off, end, h: shannon(bytes, off, end) })
  }
  return { overall, windows: out, windowSize: size }
}

// Look for other file formats appearing past offset 0 (droppers, overlays, polyglots).
export function carveEmbedded(bytes, limit = 200) {
  const hits = []
  const n = bytes.length
  const firstBytes = new Set(EMBED_SIGS.map((s) => s.sig[0]))
  for (let i = 1; i < n && hits.length < limit; i++) {
    if (!firstBytes.has(bytes[i])) continue
    for (const s of EMBED_SIGS) {
      if (i + s.sig.length > n) continue
      let ok = true
      for (let j = 0; j < s.sig.length; j++) {
        if (bytes[i + j] !== s.sig[j]) { ok = false; break }
      }
      if (ok && s.validate(bytes, i)) {
        hits.push({ off: i, name: s.name })
        break
      }
    }
  }
  return hits
}

const TLDS = 'com|net|org|io|co|info|biz|xyz|top|ru|cn|de|uk|fr|jp|br|in|me|tv|cc|app|dev|ai|gg|sh|onion|us|eu|nl|se|ch|pl|it|es|kr|ir|su|tk|ml|ga|cf|gq|pw|club|online|site|live|cloud|tech|shop|store|link|click|work'

const IOC_PATTERNS = {
  url: /\b(?:https?|ftp|wss?):\/\/[^\s"'<>\\^`{|}]{4,200}/gi,
  email: /\b[A-Za-z0-9._%+-]{2,40}@[A-Za-z0-9.-]{2,60}\.[A-Za-z]{2,10}\b/g,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  winpath: /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]{1,60}\\){0,8}[^\\/:*?"<>|\r\n\s]{1,60}/g,
  registry: /\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[\w\\ .\-{}]{3,120}/g,
  unixpath: /(?:^|[\s"'=])(\/(?:etc|usr|var|tmp|bin|opt|home|proc|dev|root|Library|System|Applications)\/[\w.\-/]{2,100})/g,
}

// Domains are found by tokenising runs of hostname characters and checking the
// labels, not with one nested-quantifier regex: that regex backtracks
// quadratically on input like "a.a.a.a…", and a crafted file could stall the
// worker for minutes. This pass is linear in the length of the string.
const TLD_SET = new Set(TLDS.split('|'))
const HOST_RUN = /[a-z0-9][a-z0-9.-]*/gi
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?$/i
const WORD = /\w/

function findDomains(text, emit) {
  HOST_RUN.lastIndex = 0
  let m
  while ((m = HOST_RUN.exec(text))) {
    const run = m[0]
    const end = m.index + run.length
    // Same boundary rule as \b: the run must not touch another word character ("_").
    if ((m.index > 0 && WORD.test(text[m.index - 1])) || (end < text.length && WORD.test(text[end]))) continue
    if (run.length > 1024 || run.indexOf('.') < 0) continue
    const labels = run.split('.')
    // Split into stretches of valid labels; in each, keep up to the last TLD label.
    let segStart = 0
    for (let i = 0; i <= labels.length; i++) {
      if (i < labels.length && LABEL.test(labels[i])) continue
      let last = -1
      for (let j = i - 1; j > segStart; j--) if (TLD_SET.has(labels[j].toLowerCase())) { last = j; break }
      if (last > segStart) {
        const d = labels.slice(segStart, last + 1).join('.')
        if (d.length <= 253 && emit(d)) return
      }
      segStart = i + 1
    }
  }
}

const DOMAIN_NOISE = /^(?:\d+(?:\.\d+)+|.*\.(?:dll|exe|sys|so|dylib|py|js|c|h|cpp|rs|go|txt|json|xml|png|jpg))$/i

export function defang(s) {
  return s.replace(/^http/i, 'hxxp').replace(/\./g, '[.]')
}

// IOCs come from the extracted strings, not raw bytes, so every hit has an offset.
export function extractIocs(strings) {
  const buckets = Object.fromEntries([...Object.keys(IOC_PATTERNS), 'domain'].map((k) => [k, new Map()]))
  const add = (kind, val, off) => {
    if (!buckets[kind].has(val)) buckets[kind].set(val, { value: val, off, count: 1 })
    else buckets[kind].get(val).count++
  }
  for (const s of strings) {
    const text = s.text
    if (text.length < 4) continue
    for (const [kind, re] of Object.entries(IOC_PATTERNS)) {
      re.lastIndex = 0
      let m
      let guard = 0
      while ((m = re.exec(text)) && guard++ < 20) {
        const val = (kind === 'unixpath' ? m[1] : m[0]).replace(/[.,;)\]]+$/, '')
        if (kind === 'ipv4' && /^(?:0\.|255\.|127\.0\.0\.1$)/.test(val)) continue
        add(kind, val, s.off)
      }
    }
    let n = 0
    findDomains(text, (d) => {
      if (!DOMAIN_NOISE.test(d)) add('domain', d, s.off)
      return ++n >= 20
    })
  }
  const out = {}
  for (const [kind, map] of Object.entries(buckets)) out[kind] = [...map.values()].slice(0, 300)
  return out
}
