import { ascii, startsWith } from './util.js'

// Each entry: kind (internal id), label, mime-ish group, and a matcher.
// Matching is a best-effort hint, never a guarantee.
const SIGS = [
  { kind: 'pe', label: 'Windows PE executable (EXE/DLL/SYS)', group: 'executable', sig: ascii('MZ'), check: isPE },
  { kind: 'elf', label: 'ELF executable / shared object', group: 'executable', sig: [0x7f, 0x45, 0x4c, 0x46] },
  { kind: 'macho', label: 'Mach-O binary', group: 'executable', sig: [0xfe, 0xed, 0xfa, 0xce] },
  { kind: 'macho', label: 'Mach-O binary', group: 'executable', sig: [0xfe, 0xed, 0xfa, 0xcf] },
  { kind: 'macho', label: 'Mach-O binary', group: 'executable', sig: [0xce, 0xfa, 0xed, 0xfe] },
  { kind: 'macho', label: 'Mach-O binary', group: 'executable', sig: [0xcf, 0xfa, 0xed, 0xfe] },
  { kind: 'macho-fat', label: 'Mach-O universal (fat) binary', group: 'executable', sig: [0xca, 0xfe, 0xba, 0xbe], check: isFatNotJava },
  { kind: 'java-class', label: 'Java class file', group: 'executable', sig: [0xca, 0xfe, 0xba, 0xbe], check: (b) => !isFatNotJava(b) },
  { kind: 'wasm', label: 'WebAssembly module', group: 'executable', sig: [0x00, 0x61, 0x73, 0x6d] },
  { kind: 'dex', label: 'Android DEX', group: 'executable', sig: ascii('dex\n') },
  { kind: 'zip', label: 'ZIP container (also APK/JAR/DOCX/XLSX/IPA/EPUB)', group: 'archive', sig: [0x50, 0x4b, 0x03, 0x04] },
  { kind: 'zip', label: 'ZIP container (empty)', group: 'archive', sig: [0x50, 0x4b, 0x05, 0x06] },
  { kind: 'gzip', label: 'gzip', group: 'archive', sig: [0x1f, 0x8b, 0x08] },
  { kind: 'bzip2', label: 'bzip2', group: 'archive', sig: ascii('BZh') },
  { kind: 'xz', label: 'xz', group: 'archive', sig: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { kind: 'zstd', label: 'Zstandard', group: 'archive', sig: [0x28, 0xb5, 0x2f, 0xfd] },
  { kind: '7z', label: '7-Zip', group: 'archive', sig: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { kind: 'rar', label: 'RAR', group: 'archive', sig: ascii('Rar!\x1a\x07') },
  { kind: 'pdf', label: 'PDF document', group: 'document', sig: ascii('%PDF-') },
  { kind: 'ole2', label: 'OLE2 compound file (legacy Office, MSI)', group: 'document', sig: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] },
  { kind: 'rtf', label: 'Rich Text Format', group: 'document', sig: ascii('{\\rtf') },
  { kind: 'png', label: 'PNG image', group: 'image', sig: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { kind: 'jpeg', label: 'JPEG image', group: 'image', sig: [0xff, 0xd8, 0xff] },
  { kind: 'gif', label: 'GIF image', group: 'image', sig: ascii('GIF8') },
  { kind: 'bmp', label: 'BMP image', group: 'image', sig: ascii('BM'), check: (b) => b.length > 14 && b[6] === 0 && b[7] === 0 },
  { kind: 'webp', label: 'WebP image', group: 'image', sig: ascii('RIFF'), check: (b) => startsWith(b, ascii('WEBP'), 8) },
  { kind: 'wav', label: 'WAV audio', group: 'media', sig: ascii('RIFF'), check: (b) => startsWith(b, ascii('WAVE'), 8) },
  { kind: 'mp3', label: 'MP3 audio (ID3)', group: 'media', sig: ascii('ID3') },
  { kind: 'ogg', label: 'Ogg container', group: 'media', sig: ascii('OggS') },
  { kind: 'flac', label: 'FLAC audio', group: 'media', sig: ascii('fLaC') },
  { kind: 'mp4', label: 'MP4 / QuickTime container', group: 'media', sig: [], check: (b) => startsWith(b, ascii('ftyp'), 4) || startsWith(b, ascii('moov'), 4) },
  { kind: 'sqlite', label: 'SQLite database', group: 'data', sig: ascii('SQLite format 3\0') },
  { kind: 'tar', label: 'TAR archive', group: 'archive', sig: [], check: (b) => startsWith(b, ascii('ustar'), 257) },
  { kind: 'iso', label: 'ISO 9660 image', group: 'archive', sig: [], check: (b) => startsWith(b, ascii('CD001'), 0x8001) },
  { kind: 'script', label: 'Script with shebang', group: 'script', sig: ascii('#!') },
]

function isPE(b) {
  if (b.length < 0x40) return false
  const peOff = b[0x3c] | (b[0x3d] << 8) | (b[0x3e] << 16) | (b[0x3f] << 24)
  return peOff > 0 && peOff + 4 <= b.length && startsWith(b, [0x50, 0x45, 0, 0], peOff)
}

// 0xCAFEBABE is shared by Java class files and Mach-O fat headers. A fat header's
// next 4 bytes are an arch count (small), a Java class has a major version >= 45.
function isFatNotJava(b) {
  if (b.length < 8) return false
  const n = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]
  return n > 0 && n < 20
}

function looksLikeText(bytes) {
  const n = Math.min(bytes.length, 8192)
  if (n === 0) return false
  let printable = 0
  for (let i = 0; i < n; i++) {
    const c = bytes[i]
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 0xc2) printable++
  }
  return printable / n > 0.95
}

export function detect(bytes) {
  for (const s of SIGS) {
    if (s.sig.length && !startsWith(bytes, s.sig)) continue
    if (s.check && !s.check(bytes)) continue
    if (!s.sig.length && !s.check) continue
    return { kind: s.kind, label: s.label, group: s.group, confident: true }
  }
  if (looksLikeText(bytes)) return { kind: 'text', label: 'Plain text (heuristic)', group: 'text', confident: false }
  return { kind: 'unknown', label: 'Unknown / raw binary data', group: 'unknown', confident: false }
}

// Secondary magic numbers used to carve embedded objects past offset 0.
export const EMBED_SIGS = [
  { name: 'PE executable', sig: ascii('MZ'), validate: (b, i) => isPE(b.subarray(i, Math.min(b.length, i + 4096))) },
  { name: 'ELF binary', sig: [0x7f, 0x45, 0x4c, 0x46], validate: (b, i) => b[i + 4] === 1 || b[i + 4] === 2 },
  { name: 'ZIP / archive entry', sig: [0x50, 0x4b, 0x03, 0x04], validate: (b, i) => i + 30 <= b.length },
  { name: 'PDF document', sig: ascii('%PDF-'), validate: (b, i) => b[i + 5] === 0x31 || b[i + 5] === 0x32 },
  { name: 'PNG image', sig: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], validate: () => true },
  { name: 'gzip stream', sig: [0x1f, 0x8b, 0x08], validate: (b, i) => b[i + 3] < 0x20 },
  { name: '7-Zip archive', sig: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], validate: () => true },
  { name: 'RAR archive', sig: ascii('Rar!\x1a\x07'), validate: () => true },
  { name: 'SQLite database', sig: ascii('SQLite format 3\0'), validate: () => true },
]
