import { Reader, hex, shannon, finding } from './util.js'

const MACHINES = {
  0x03: 'x86', 0x3e: 'x86-64', 0x28: 'ARM', 0xb7: 'AArch64', 0xf3: 'RISC-V', 0x08: 'MIPS', 0x14: 'PowerPC',
  0x15: 'PowerPC64', 0x16: 'S390', 0x2a: 'SuperH', 0xa4: 'Hexagon', 0x102: 'LoongArch',
}
const TYPES = { 1: 'Relocatable', 2: 'Executable', 3: 'Shared object / PIE', 4: 'Core dump' }
const OSABI = { 0: 'System V', 3: 'Linux', 6: 'Solaris', 9: 'FreeBSD', 12: 'OpenBSD' }
const PT = { 0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY' }
const SHT = { 0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY', 0x6ffffff6: 'GNU_HASH', 0x6fffffff: 'VERSYM', 0x6ffffffe: 'VERNEED' }

export function parseELF(bytes) {
  const findings = []
  const is64 = bytes[4] === 2
  const le = bytes[5] !== 2
  const r = new Reader(bytes, le)
  const info = {
    format: `ELF${is64 ? '64' : '32'}`,
    endian: le ? 'little' : 'big',
    osabi: OSABI[bytes[7]] || String(bytes[7]),
  }
  const type = r.u16(16)
  const machine = r.u16(18)
  info.type = TYPES[type] || hex(type)
  info.machine = MACHINES[machine] || hex(machine, 4)
  const entry = is64 ? r.u64(24) : r.u32(24)
  const phoff = is64 ? r.u64(32) : r.u32(28)
  const shoff = is64 ? r.u64(40) : r.u32(32)
  const phentsize = r.u16(is64 ? 54 : 42)
  const phnum = Math.min(r.u16(is64 ? 56 : 44), 256)
  const shentsize = r.u16(is64 ? 58 : 46)
  const shnum = Math.min(r.u16(is64 ? 60 : 48), 1024)
  const shstrndx = r.u16(is64 ? 62 : 50)
  info.entry = hex(entry)

  // Program headers
  const segments = []
  let interp = null
  let stackExec = null
  let relro = false
  const loads = []
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize
    if (!r.has(o, phentsize) || phentsize < (is64 ? 56 : 32)) break
    const ptype = r.u32(o)
    const flags = r.u32(is64 ? o + 4 : o + 24)
    const offset = is64 ? r.u64(o + 8) : r.u32(o + 4)
    const vaddr = is64 ? r.u64(o + 16) : r.u32(o + 8)
    const filesz = is64 ? r.u64(o + 32) : r.u32(o + 16)
    const memsz = is64 ? r.u64(o + 40) : r.u32(o + 20)
    const flagStr = (flags & 4 ? 'R' : '-') + (flags & 2 ? 'W' : '-') + (flags & 1 ? 'X' : '-')
    segments.push({ type: PT[ptype] || hex(ptype), flags: flagStr, offset, vaddr, filesz, memsz })
    if (ptype === 1) loads.push({ offset, vaddr, filesz })
    if (ptype === 3 && r.has(offset, filesz)) interp = r.cstr(offset, Math.min(filesz, 256))
    if (ptype === 0x6474e551) stackExec = !!(flags & 1)
    if (ptype === 0x6474e552) relro = true
  }
  if (interp) info.interpreter = interp

  // Section headers
  const sections = []
  const raw = []
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize
    if (!shoff || !r.has(o, shentsize) || shentsize < (is64 ? 64 : 40)) break
    raw.push({
      nameOff: r.u32(o),
      type: r.u32(o + 4),
      flags: is64 ? r.u64(o + 8) : r.u32(o + 8),
      addr: is64 ? r.u64(o + 16) : r.u32(o + 12),
      offset: is64 ? r.u64(o + 24) : r.u32(o + 16),
      size: is64 ? r.u64(o + 32) : r.u32(o + 20),
      link: r.u32(o + (is64 ? 40 : 24)),
      entsize: is64 ? r.u64(o + 56) : r.u32(o + 36),
    })
  }
  const strOff = raw[shstrndx]?.offset
  for (const s of raw) {
    const name = strOff != null && r.has(strOff + s.nameOff) ? r.cstr(strOff + s.nameOff, 64) : ''
    const end = Math.min(bytes.length, s.offset + s.size)
    sections.push({
      name: name || '(null)',
      type: SHT[s.type] || hex(s.type),
      addr: s.addr,
      offset: s.offset,
      size: s.size,
      flags: (s.flags & 4 ? 'X' : '-') + (s.flags & 2 ? 'A' : '-') + (s.flags & 1 ? 'W' : '-'),
      entropy: s.type !== 8 && s.size > 0 && s.offset < bytes.length ? shannon(bytes, s.offset, end) : 0,
    })
  }

  // Dynamic section: needed libraries, soname, RPATH
  const needed = []
  const imports = []
  const dyn = raw.find((s) => s.type === 6)
  if (dyn) {
    const strtab = raw[dyn.link]
    const step = is64 ? 16 : 8
    for (let o = dyn.offset; o + step <= dyn.offset + dyn.size && r.has(o, step); o += step) {
      const tag = is64 ? r.u64(o) : r.u32(o)
      const val = is64 ? r.u64(o + 8) : r.u32(o + 4)
      if (tag === 0) break
      if (tag === 1 && strtab) needed.push(r.cstr(strtab.offset + val, 128))
      if ((tag === 15 || tag === 29) && strtab) info[tag === 29 ? 'runpath' : 'rpath'] = r.cstr(strtab.offset + val, 256)
      if (tag === 14 && strtab) info.soname = r.cstr(strtab.offset + val, 128)
    }
  }

  // Undefined dynamic symbols are the functions the binary expects from other libraries.
  const dynsym = raw.find((s) => s.type === 11)
  if (dynsym) {
    const strtab = raw[dynsym.link]
    const ent = dynsym.entsize || (is64 ? 24 : 16)
    const n = Math.min(Math.floor(dynsym.size / ent), 6000)
    for (let i = 1; i < n; i++) {
      const o = dynsym.offset + i * ent
      if (!r.has(o, ent) || !strtab) break
      const nameOff = r.u32(o)
      const shndx = r.u16(o + (is64 ? 6 : 14))
      if (shndx === 0 && nameOff) imports.push(r.cstr(strtab.offset + nameOff, 128))
    }
  }

  // Findings
  if (interp) findings.push(finding('elf.interp', 'info', 'Dynamic loader', interp))
  else if (type === 2 || type === 3) findings.push(finding('elf.static', 'info', 'No interpreter segment', 'Statically linked, or a shared library. Statically linked Go and Rust binaries look like this.'))

  if (stackExec === true) findings.push(finding('elf.nx', 'warn', 'Executable stack requested', 'PT_GNU_STACK has the execute flag. Modern builds clear it.', { confidence: 'high' }))
  else if (stackExec === false) findings.push(finding('elf.nx.ok', 'info', 'Non-executable stack (NX)', 'PT_GNU_STACK is read/write only.'))
  findings.push(finding('elf.hardening', 'info', 'Hardening hints', `PIE/shared object: ${type === 3 ? 'yes' : 'no'} · RELRO segment: ${relro ? 'yes' : 'no'}${info.rpath || info.runpath ? ` · RPATH/RUNPATH: ${info.runpath || info.rpath}` : ''}`))

  const stripped = sections.length > 0 && !sections.some((s) => s.type === 'SYMTAB')
  if (stripped) findings.push(finding('elf.stripped', 'info', 'Symbol table stripped', 'No .symtab section. Function names are mostly gone; only dynamic symbols remain.'))
  if (!sections.length) findings.push(finding('elf.nosections', 'notice', 'No section headers', 'Stripped section table is common in packed or hand-crafted binaries, but also in some embedded builds.', { incomplete: true }))

  const hot = sections.filter((s) => s.entropy > 7.2 && s.size > 4096)
  if (hot.length) findings.push(finding('elf.entropy', 'warn', 'High-entropy sections', `${hot.map((s) => `${s.name} (${s.entropy.toFixed(2)})`).join(', ')}. Heuristic only; compressed data triggers it too.`, { confidence: 'low' }))
  if (segments.some((s) => s.type === 'LOAD' && s.flags === 'RWX')) findings.push(finding('elf.rwx', 'warn', 'Writable and executable segment', 'A LOAD segment is mapped RWX.', { confidence: 'medium' }))

  // Entry offset via LOAD segments
  let entryObj = null
  for (const l of loads) {
    if (entry >= l.vaddr && entry < l.vaddr + l.filesz) {
      entryObj = { off: entry - l.vaddr + l.offset, rva: entry }
      break
    }
  }

  return { info, segments, sections, needed, imports, entry: entryObj, findings }
}
