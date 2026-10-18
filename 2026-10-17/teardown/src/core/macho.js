import { Reader, hex, bytesToHex, finding } from './util.js'

const CPUS = {
  7: 'x86', 0x01000007: 'x86-64', 12: 'ARM', 0x0100000c: 'ARM64', 0x0200000c: 'ARM64_32', 18: 'PowerPC', 0x01000012: 'PowerPC64',
}
const FILETYPES = { 1: 'Object', 2: 'Executable', 3: 'Fixed VM library', 4: 'Core', 5: 'Preloaded', 6: 'Dylib', 7: 'Dynamic linker', 8: 'Bundle', 9: 'Dylib stub', 10: 'Debug symbols', 11: 'Kext bundle' }
const LC = {
  0x1: 'SEGMENT', 0x2: 'SYMTAB', 0xb: 'DYSYMTAB', 0xc: 'LOAD_DYLIB', 0xd: 'ID_DYLIB', 0xe: 'LOAD_DYLINKER', 0x19: 'SEGMENT_64',
  0x1b: 'UUID', 0x1d: 'CODE_SIGNATURE', 0x1e: 'SEGMENT_SPLIT_INFO', 0x1f: 'REEXPORT_DYLIB', 0x80000018: 'LOAD_WEAK_DYLIB', 0x80000022: 'DYLD_INFO_ONLY',
  0x80000028: 'MAIN', 0x2a: 'SOURCE_VERSION', 0x32: 'BUILD_VERSION', 0x80000034: 'DYLD_EXPORTS_TRIE', 0x80000033: 'DYLD_CHAINED_FIXUPS',
  0x8000001c: 'RPATH', 0x24: 'VERSION_MIN_MACOSX', 0x25: 'VERSION_MIN_IPHONEOS', 0x26: 'FUNCTION_STARTS', 0x29: 'DATA_IN_CODE', 0x2c: 'ENCRYPTION_INFO_64', 0x21: 'ENCRYPTION_INFO',
}
const PLATFORMS = { 1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator', 8: 'tvOS Simulator', 9: 'watchOS Simulator', 11: 'visionOS' }

export function parseMachO(bytes, base = 0, sliceLen = bytes.length - base) {
  const slice = bytes.subarray(base, base + sliceLen)
  const magicBE = new DataView(slice.buffer, slice.byteOffset, 4).getUint32(0, false)
  const is64 = magicBE === 0xfeedfacf || magicBE === 0xcffaedfe
  const le = magicBE === 0xcefaedfe || magicBE === 0xcffaedfe
  const r = new Reader(slice, le)
  const findings = []
  const cpu = r.u32(4)
  const ftype = r.u32(12)
  const ncmds = Math.min(r.u32(16), 2048)
  const flags = r.u32(24)
  const info = {
    format: `Mach-O ${is64 ? '64' : '32'}-bit`,
    cpu: CPUS[cpu] || hex(cpu),
    type: FILETYPES[ftype] || String(ftype),
    flags: hex(flags),
  }
  const segments = []
  const dylibs = []
  const rpaths = []
  const cmds = []
  let o = is64 ? 32 : 28
  let entryOff = null
  let signed = false
  let encrypted = false

  for (let i = 0; i < ncmds; i++) {
    if (!r.has(o, 8)) break
    const cmd = r.u32(o)
    const size = r.u32(o + 4)
    if (size < 8 || !r.has(o, size)) break
    const name = LC[cmd] || hex(cmd)
    cmds.push(name)
    if (cmd === 0x19 || cmd === 0x1) {
      const seg = {
        name: r.fixed(o + 8, 16),
        vmaddr: cmd === 0x19 ? r.u64(o + 24) : r.u32(o + 24),
        vmsize: cmd === 0x19 ? r.u64(o + 32) : r.u32(o + 28),
        fileoff: cmd === 0x19 ? r.u64(o + 40) : r.u32(o + 32),
        filesize: cmd === 0x19 ? r.u64(o + 48) : r.u32(o + 36),
        sections: [],
      }
      const nsects = cmd === 0x19 ? r.u32(o + 64) : r.u32(o + 48)
      let so = o + (cmd === 0x19 ? 72 : 56)
      const ssz = cmd === 0x19 ? 80 : 68
      for (let k = 0; k < Math.min(nsects, 128) && r.has(so, ssz); k++, so += ssz) {
        seg.sections.push({
          name: r.fixed(so, 16),
          size: cmd === 0x19 ? r.u64(so + 40) : r.u32(so + 36),
          offset: r.u32(so + (cmd === 0x19 ? 48 : 40)),
        })
      }
      segments.push(seg)
    } else if (cmd === 0xc || cmd === 0xd || cmd === 0x1f || cmd === 0x80000018) {
      const nameOff = r.u32(o + 8)
      const entry = { name: r.cstr(o + nameOff, 256), kind: name }
      if (cmd !== 0xd) dylibs.push(entry)
      else info.installName = entry.name
    } else if (cmd === 0x8000001c) {
      rpaths.push(r.cstr(o + r.u32(o + 8), 256))
    } else if (cmd === 0x80000028) {
      entryOff = r.u64(o + 8)
    } else if (cmd === 0x1b) {
      info.uuid = bytesToHex(slice.subarray(o + 8, o + 24)).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5')
    } else if (cmd === 0x1d) {
      signed = true
    } else if (cmd === 0x2c || cmd === 0x21) {
      encrypted = r.u32(o + 16) !== 0
    } else if (cmd === 0x32) {
      info.platform = PLATFORMS[r.u32(o + 8)] || String(r.u32(o + 8))
      const v = r.u32(o + 12)
      info.minOS = `${v >>> 16}.${(v >>> 8) & 255}.${v & 255}`
    }
    o += size
  }

  const entry = entryOff != null ? { off: base + entryOff, rva: entryOff } : null

  if (signed) findings.push(finding('macho.signed', 'info', 'Code signature load command present', 'A signature blob exists. Validity and signer were not verified here.', { incomplete: true }))
  else findings.push(finding('macho.unsigned', 'notice', 'No code signature', 'Apple Silicon will refuse unsigned arm64 code unless ad-hoc signed; many build outputs are unsigned.'))
  if (encrypted) findings.push(finding('macho.encrypted', 'warn', 'Encrypted segment (FairPlay-style)', 'cryptid is non-zero, so the __TEXT contents are not readable until decrypted. Static analysis will be limited.', { incomplete: true, confidence: 'high' }))
  if (flags & 0x200000) findings.push(finding('macho.pie', 'info', 'PIE', 'Position-independent executable (ASLR-capable).'))
  if (rpaths.length) findings.push(finding('macho.rpath', 'info', 'Runtime search paths', rpaths.join('\n')))
  const wx = segments.filter((s) => s.name !== '__PAGEZERO')
  if (wx.length === 0) findings.push(finding('macho.noseg', 'notice', 'No segments parsed', 'Load commands may be malformed or truncated.', { incomplete: true }))

  return { info, segments, dylibs, rpaths, cmds: [...new Set(cmds)], entry, findings }
}

export function parseFat(bytes) {
  const r = new Reader(bytes, false)
  const n = Math.min(r.u32(4), 16)
  const archs = []
  for (let i = 0; i < n; i++) {
    const o = 8 + i * 20
    if (!r.has(o, 20)) break
    archs.push({ cpu: CPUS[r.u32(o)] || hex(r.u32(o)), offset: r.u32(o + 8), size: r.u32(o + 12) })
  }
  return archs
}
