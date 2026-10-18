import { Reader, finding, hex } from './util.js'

// PDF: a raw keyword scan. Streams are NOT decompressed, so anything hidden
// inside compressed object streams will not be seen. That limit is reported.
export function parsePDF(bytes) {
  const findings = []
  const head = latin(bytes, 0, Math.min(bytes.length, 1024))
  const version = (head.match(/%PDF-(\d\.\d)/) || [])[1] || '?'
  const text = latin(bytes, 0, Math.min(bytes.length, 64 * 1024 * 1024))
  const count = (re) => (text.match(re) || []).length
  const keys = {
    '/JavaScript': count(/\/JavaScript\b/g) + count(/\/JS\b/g),
    '/OpenAction': count(/\/OpenAction\b/g),
    '/AA (additional actions)': count(/\/AA\b/g),
    '/Launch': count(/\/Launch\b/g),
    '/EmbeddedFile': count(/\/EmbeddedFile\b/g),
    '/URI': count(/\/URI\b/g),
    '/AcroForm': count(/\/AcroForm\b/g),
    '/Encrypt': count(/\/Encrypt\b/g),
    '/ObjStm (object streams)': count(/\/ObjStm\b/g),
    '/RichMedia': count(/\/RichMedia\b/g),
  }
  const objects = count(/\d+\s+\d+\s+obj\b/g)
  const info = { format: 'PDF', version, objects, eof_markers: count(/%%EOF/g) }

  if (keys['/JavaScript']) findings.push(finding('pdf.js', 'warn', 'Embedded JavaScript keywords', `${keys['/JavaScript']} occurrence(s). PDF JavaScript is a long-standing abuse vector.`, { confidence: 'medium' }))
  if (keys['/OpenAction'] || keys['/AA (additional actions)']) findings.push(finding('pdf.auto', 'notice', 'Auto-run actions', 'OpenAction or AA entries run when the document opens or a page is viewed.', { confidence: 'medium' }))
  if (keys['/Launch']) findings.push(finding('pdf.launch', 'warn', 'Launch action', 'A /Launch action can start an external program.', { confidence: 'medium' }))
  if (keys['/EmbeddedFile']) findings.push(finding('pdf.embed', 'notice', 'Embedded file(s)', `${keys['/EmbeddedFile']} attachment marker(s).`))
  if (keys['/Encrypt']) findings.push(finding('pdf.enc', 'notice', 'Encrypted document', 'Content may be unreadable without a password.', { incomplete: true }))
  if (keys['/ObjStm (object streams)']) findings.push(finding('pdf.objstm', 'info', 'Compressed object streams', 'Keywords inside compressed streams were not scanned. Absence of the markers above is not proof they are absent.', { incomplete: true }))
  if (info.eof_markers > 1) findings.push(finding('pdf.incr', 'info', 'Multiple %%EOF markers', 'Incremental updates or appended data. Earlier revisions may contain content that was later changed.'))

  const uris = [...new Set((text.match(/\/URI\s*\(([^)]{3,200})\)/g) || []).map((m) => m.replace(/^\/URI\s*\(/, '').replace(/\)$/, '')))].slice(0, 100)
  return { info, keywords: keys, uris, findings }
}

export function parsePNG(bytes) {
  const r = new Reader(bytes, false)
  const info = { format: 'PNG' }
  const findings = []
  if (r.has(8, 25)) {
    info.width = r.u32(16)
    info.height = r.u32(20)
    info.bitDepth = r.u8(24)
    info.colorType = ['Grayscale', '', 'RGB', 'Palette', 'Grayscale+alpha', '', 'RGBA'][r.u8(25)] || String(r.u8(25))
  }
  // Walk chunks for text metadata and trailing data after IEND.
  let o = 8
  const textChunks = []
  let iend = -1
  for (let n = 0; n < 5000 && r.has(o, 12); n++) {
    const len = r.u32(o)
    const type = String.fromCharCode(bytes[o + 4], bytes[o + 5], bytes[o + 6], bytes[o + 7])
    if (type === 'tEXt' || type === 'iTXt' || type === 'zTXt') textChunks.push({ type, off: o + 8, len })
    if (type === 'IEND') { iend = o + 12; break }
    o += 12 + len
  }
  if (iend >= 0 && bytes.length - iend > 16) findings.push(finding('png.trailer', 'warn', 'Data after IEND', `${(bytes.length - iend).toLocaleString()} bytes follow the PNG end marker. Appended payloads and steganography often live here.`, { off: iend, confidence: 'high' }))
  if (textChunks.length) findings.push(finding('png.text', 'info', 'Text metadata chunks', `${textChunks.length} chunk(s): ${textChunks.slice(0, 5).map((c) => `${c.type}@${hex(c.off)}`).join(', ')}`))
  return { info, findings }
}

export function parseJPEG(bytes) {
  const r = new Reader(bytes, false)
  const info = { format: 'JPEG' }
  const findings = []
  let o = 2
  let hasExif = false
  let hasXmp = false
  let hasGps = false
  while (r.has(o, 4) && r.u8(o) === 0xff) {
    const marker = r.u8(o + 1)
    if (marker === 0xd9 || marker === 0xda) break
    const len = r.u16(o + 2)
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      info.height = r.u16(o + 5)
      info.width = r.u16(o + 7)
    }
    if (marker === 0xe1) {
      const tag = r.fixed(o + 4, 6)
      if (tag.startsWith('Exif')) {
        hasExif = true
        // GPS is a sub-IFD pointer (tag 0x8825). Scan the APP1 payload for it.
        const end = Math.min(bytes.length, o + 2 + len)
        for (let i = o + 10; i + 1 < end; i++) {
          if ((bytes[i] === 0x88 && bytes[i + 1] === 0x25) || (bytes[i] === 0x25 && bytes[i + 1] === 0x88)) { hasGps = true; break }
        }
      } else if (latin(bytes, o + 4, Math.min(bytes.length, o + 33)).startsWith('http://ns.adobe.com/xap')) hasXmp = true
    }
    o += 2 + len
  }
  info.exif = hasExif
  info.xmp = hasXmp
  if (hasGps) findings.push(finding('jpeg.gps', 'notice', 'EXIF may contain GPS location', 'A GPS tag pointer was found in the EXIF block. Check before sharing the image; this is a heuristic byte match, not a full EXIF parse.', { confidence: 'low' }))
  else if (hasExif) findings.push(finding('jpeg.exif', 'info', 'EXIF metadata present', 'Camera or editing metadata may be embedded.'))
  const tail = lastIndexOf(bytes, [0xff, 0xd9])
  if (tail >= 0 && bytes.length - (tail + 2) > 16) findings.push(finding('jpeg.trailer', 'warn', 'Data after JPEG end marker', `${(bytes.length - tail - 2).toLocaleString()} trailing bytes. Thumbnails, appended payloads and steganography can all appear here.`, { off: tail + 2, confidence: 'medium' }))
  return { info, findings }
}

export function parseWasm(bytes) {
  const r = new Reader(bytes, true)
  const info = { format: 'WebAssembly', version: r.u32(4) }
  const names = { 0: 'custom', 1: 'type', 2: 'import', 3: 'function', 4: 'table', 5: 'memory', 6: 'global', 7: 'export', 8: 'start', 9: 'element', 10: 'code', 11: 'data', 12: 'datacount' }
  const sections = []
  let o = 8
  while (r.has(o, 2) && sections.length < 64) {
    const id = r.u8(o)
    let p = o + 1
    let size = 0
    let shift = 0
    for (let k = 0; k < 5 && r.has(p, 1); k++) {
      const b = r.u8(p++)
      size |= (b & 0x7f) << shift
      shift += 7
      if (!(b & 0x80)) break
    }
    sections.push({ name: names[id] || String(id), offset: p, size })
    o = p + size
  }
  return { info, sections, findings: [] }
}

export function parseClass(bytes) {
  const r = new Reader(bytes, false)
  const major = r.u16(6)
  const java = major >= 49 ? `Java ${major - 44}` : `Java 1.${major - 44}`
  return { info: { format: 'Java class', major, targets: java, constants: r.u16(8) }, findings: [] }
}

function latin(bytes, a, b) {
  let s = ''
  for (let i = a; i < b; i++) s += String.fromCharCode(bytes[i])
  return s
}
function lastIndexOf(bytes, sig) {
  for (let i = bytes.length - sig.length; i >= 0; i--) {
    let ok = true
    for (let j = 0; j < sig.length; j++) if (bytes[i + j] !== sig[j]) { ok = false; break }
    if (ok) return i
  }
  return -1
}
