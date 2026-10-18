import { Reader, hex, finding } from './util.js'

const METHODS = { 0: 'stored', 8: 'deflate', 9: 'deflate64', 12: 'bzip2', 14: 'lzma', 93: 'zstd', 95: 'xz', 98: 'ppmd' }

// Walks the central directory only. No entry is extracted to disk or executed.
export function parseZip(bytes) {
  const r = new Reader(bytes, true)
  const findings = []
  // Find End Of Central Directory (scan back up to the max comment size).
  let eocd = -1
  const lo = Math.max(0, bytes.length - 22 - 65535)
  for (let i = bytes.length - 22; i >= lo; i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 5 && bytes[i + 3] === 6) { eocd = i; break }
  }
  if (eocd < 0) throw new Error('No end-of-central-directory record (truncated or not a ZIP)')

  let total = r.u16(eocd + 10)
  let cdSize = r.u32(eocd + 12)
  let cdOff = r.u32(eocd + 16)
  // ZIP64
  if ((total === 0xffff || cdOff === 0xffffffff) && eocd >= 20 && r.u32(eocd - 20) === 0x07064b50) {
    const z64 = r.u64(eocd - 20 + 8)
    if (r.has(z64, 56) && r.u32(z64) === 0x06064b50) {
      total = r.u64(z64 + 32)
      cdSize = r.u64(z64 + 40)
      cdOff = r.u64(z64 + 48)
    }
  }

  const entries = []
  let o = cdOff
  const cap = Math.min(total, 20000)
  for (let i = 0; i < cap; i++) {
    if (!r.has(o, 46) || r.u32(o) !== 0x02014b50) break
    const flags = r.u16(o + 8)
    const method = r.u16(o + 10)
    const csize = r.u32(o + 20)
    const usize = r.u32(o + 24)
    const nameLen = r.u16(o + 28)
    const extraLen = r.u16(o + 30)
    const commentLen = r.u16(o + 32)
    const localOff = r.u32(o + 42)
    const nameBytes = bytes.subarray(o + 46, o + 46 + nameLen)
    const name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes)
    entries.push({
      name,
      method: METHODS[method] || String(method),
      csize,
      usize,
      crc: hex(r.u32(o + 16), 8),
      localOff,
      encrypted: !!(flags & 1),
    })
    o += 46 + nameLen + extraLen + commentLen
  }

  const names = new Set(entries.map((e) => e.name))
  const has = (p) => entries.some((e) => e.name === p || e.name.startsWith(p))
  let kind = 'ZIP archive'
  if (names.has('AndroidManifest.xml') && has('classes')) kind = 'Android APK'
  else if (names.has('META-INF/MANIFEST.MF') && !names.has('AndroidManifest.xml')) kind = 'Java JAR'
  else if (has('Payload/') && entries.some((e) => /\.app\/Info\.plist$/.test(e.name))) kind = 'iOS app (IPA)'
  else if (has('word/')) kind = 'Word document (DOCX/DOCM)'
  else if (has('xl/')) kind = 'Excel workbook (XLSX/XLSM)'
  else if (has('ppt/')) kind = 'PowerPoint (PPTX/PPTM)'
  else if (names.has('mimetype') && has('META-INF/container.xml')) kind = 'EPUB'
  else if (has('xpi') || names.has('manifest.json') && names.has('background.js')) kind = 'Browser extension (probable)'
  else if (has('Contents/') && names.has('Contents/Info.plist')) kind = 'macOS bundle archive'

  const info = { format: 'ZIP', kind, entries: total }

  let csTotal = 0
  let usTotal = 0
  for (const e of entries) { csTotal += e.csize; usTotal += e.usize }
  const ratio = csTotal ? usTotal / csTotal : 0

  if (ratio > 100 && usTotal > 100 * 1024 * 1024) {
    findings.push(finding('zip.bomb', 'warn', 'Extreme compression ratio',
      `Declared ${usTotal.toLocaleString()} bytes from ${csTotal.toLocaleString()} compressed (${ratio.toFixed(0)}:1). Be careful extracting this elsewhere; it can exhaust disk or memory.`, { confidence: 'medium' }))
  }
  if (entries.some((e) => e.encrypted)) findings.push(finding('zip.enc', 'notice', 'Encrypted entries', 'Some entries are password-protected, so their contents cannot be inspected here.', { incomplete: true }))
  if (entries.some((e) => /(^|\/)\.\.(\/|$)/.test(e.name) || e.name.startsWith('/'))) {
    findings.push(finding('zip.slip', 'warn', 'Path traversal entry names', 'At least one entry uses ".." or an absolute path. Naive extractors can write outside the target folder ("zip slip").', { confidence: 'high' }))
  }
  const macro = entries.find((e) => /vbaProject\.bin$/i.test(e.name))
  if (macro) findings.push(finding('zip.macro', 'warn', 'Office macro project present', `${macro.name}. Macros run code when enabled; inspect before opening in Office.`, { confidence: 'high' }))
  const nested = entries.filter((e) => /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jar|msi|apk|dex|so|dylib)$/i.test(e.name))
  if (nested.length) findings.push(finding('zip.exec', 'notice', 'Executable or script entries', `${nested.length} entr${nested.length === 1 ? 'y' : 'ies'}: ${nested.slice(0, 8).map((e) => e.name).join(', ')}${nested.length > 8 ? ', …' : ''}`))
  if (entries.length < total) findings.push(finding('zip.partial', 'notice', 'Central directory only partly read', `Parsed ${entries.length} of ${total} declared entries.`, { incomplete: true }))
  if (kind === 'Android APK') findings.push(finding('zip.apk', 'info', 'Android APK', 'AndroidManifest.xml is binary XML and classes*.dex hold Dalvik bytecode. Use a dedicated APK tool for decompilation.', { incomplete: true }))

  return { info, entries, findings, cdOff }
}
