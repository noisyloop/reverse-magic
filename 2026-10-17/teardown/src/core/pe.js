import { Reader, hex, shannon, finding } from './util.js'

const MACHINES = {
  0x14c: 'x86 (i386)', 0x8664: 'x86-64 (AMD64)', 0x1c0: 'ARM', 0x1c4: 'ARM Thumb-2', 0xaa64: 'ARM64',
  0x200: 'Itanium', 0x5064: 'RISC-V 64', 0x6232: 'LoongArch 32', 0x6264: 'LoongArch 64',
}
const SUBSYSTEMS = {
  1: 'Native', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console', 7: 'POSIX console',
  9: 'Windows CE', 10: 'EFI application', 11: 'EFI boot driver', 12: 'EFI runtime driver', 14: 'Xbox',
}
const DIR_NAMES = ['Export', 'Import', 'Resource', 'Exception', 'Certificate', 'Base relocation', 'Debug', 'Architecture',
  'Global ptr', 'TLS', 'Load config', 'Bound import', 'IAT', 'Delay import', 'CLR runtime (.NET)', 'Reserved']

// API names that are common in many kinds of software. Presence is a hint about
// capability, not evidence of intent; legitimate programs import these too.
const API_HINTS = {
  'Process injection / memory': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection', 'QueueUserAPC', 'SetThreadContext', 'VirtualProtect', 'VirtualAlloc'],
  'Anti-analysis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA', 'GetTickCount'],
  'Networking': ['WSAStartup', 'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'URLDownloadToFileA', 'URLDownloadToFileW', 'WinHttpOpen', 'HttpSendRequestA', 'socket', 'connect', 'send', 'recv'],
  'Persistence / registry': ['RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW', 'CreateServiceA', 'CreateServiceW', 'RegOpenKeyExA', 'RegOpenKeyExW'],
  'Crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA', 'CryptAcquireContextW', 'BCryptEncrypt', 'BCryptDecrypt'],
  'Process / execution': ['CreateProcessA', 'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW', 'WinExec', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress'],
  'Keyboard / screen': ['SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState', 'BitBlt'],
}

export function parsePE(bytes) {
  const r = new Reader(bytes, true)
  const findings = []
  const info = {}
  const peOff = r.u32(0x3c)
  if (!r.has(peOff, 24)) throw new Error('PE header offset is outside the file')

  const machine = r.u16(peOff + 4)
  const nSections = r.u16(peOff + 6)
  const timestamp = r.u32(peOff + 8)
  const optSize = r.u16(peOff + 20)
  const characteristics = r.u16(peOff + 22)
  const optOff = peOff + 24
  const magic = r.u16(optOff)
  const is64 = magic === 0x20b
  if (magic !== 0x10b && magic !== 0x20b) throw new Error(`Unknown optional header magic ${hex(magic)}`)

  const entryRva = r.u32(optOff + 16)
  const imageBase = is64 ? r.u64(optOff + 24) : r.u32(optOff + 28)
  const subsystem = r.u16(optOff + 68)
  const dllChars = r.u16(optOff + 70)
  const dirBase = optOff + (is64 ? 112 : 96)
  const nDirs = Math.min(r.u32(dirBase - 4), 16)
  const dirs = []
  for (let i = 0; i < nDirs; i++) {
    if (!r.has(dirBase + i * 8, 8)) break
    dirs.push({ name: DIR_NAMES[i], rva: r.u32(dirBase + i * 8), size: r.u32(dirBase + i * 8 + 4) })
  }

  const isDll = !!(characteristics & 0x2000)
  info.format = `PE${is64 ? '32+' : '32'}`
  info.machine = MACHINES[machine] || hex(machine, 4)
  info.type = isDll ? 'DLL' : (characteristics & 0x0002 ? 'Executable' : 'Object / other')
  info.subsystem = SUBSYSTEMS[subsystem] || String(subsystem)
  info.imageBase = hex(imageBase)
  info.entryRva = hex(entryRva)
  info.timestamp = timestamp
  info.timestampISO = timestamp ? new Date(timestamp * 1000).toISOString() : null

  // Sections
  const secOff = optOff + optSize
  const sections = []
  for (let i = 0; i < nSections; i++) {
    const o = secOff + i * 40
    if (!r.has(o, 40)) break
    const rawSize = r.u32(o + 16)
    const rawPtr = r.u32(o + 20)
    const chars = r.u32(o + 36)
    const end = Math.min(bytes.length, rawPtr + rawSize)
    sections.push({
      name: r.fixed(o, 8) || '(unnamed)',
      vaddr: r.u32(o + 12),
      vsize: r.u32(o + 8),
      rawPtr,
      rawSize,
      flags: [chars & 0x20000000 ? 'X' : '-', chars & 0x40000000 ? 'R' : '-', chars & 0x80000000 ? 'W' : '-'].join(''),
      entropy: rawSize && rawPtr < bytes.length ? shannon(bytes, rawPtr, end) : 0,
    })
  }

  const rvaToOff = (rva) => {
    for (const s of sections) {
      if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawSize)) return rva - s.vaddr + s.rawPtr
    }
    return rva < (sections[0]?.rawPtr ?? 0) ? rva : -1
  }

  // Imports
  const imports = []
  const impDir = dirs[1]
  if (impDir && impDir.rva) {
    let o = rvaToOff(impDir.rva)
    for (let n = 0; o >= 0 && r.has(o, 20) && n < 512; n++, o += 20) {
      const nameRva = r.u32(o + 12)
      const thunkRva = r.u32(o) || r.u32(o + 16)
      if (!nameRva && !thunkRva) break
      const dllOff = rvaToOff(nameRva)
      const dll = dllOff >= 0 ? r.cstr(dllOff, 128) : '?'
      const funcs = []
      let t = rvaToOff(thunkRva)
      const step = is64 ? 8 : 4
      for (let k = 0; t >= 0 && r.has(t, step) && k < 4000; k++, t += step) {
        const val = is64 ? r.u64(t) : r.u32(t)
        if (val === 0) break
        const byOrdinal = is64 ? val >= 2 ** 63 : val >= 0x80000000
        if (byOrdinal) funcs.push(`#${val % 65536}`)
        else {
          const no = rvaToOff(val % 0x80000000)
          funcs.push(no >= 0 ? r.cstr(no + 2, 128) : '?')
        }
      }
      imports.push({ dll, funcs })
    }
  }

  // Exports
  const exportsList = []
  const expDir = dirs[0]
  if (expDir && expDir.rva) {
    const o = rvaToOff(expDir.rva)
    if (o >= 0 && r.has(o, 40)) {
      const nNames = Math.min(r.u32(o + 24), 5000)
      const namesOff = rvaToOff(r.u32(o + 32))
      for (let i = 0; namesOff >= 0 && i < nNames && r.has(namesOff + i * 4, 4); i++) {
        const no = rvaToOff(r.u32(namesOff + i * 4))
        if (no >= 0) exportsList.push(r.cstr(no, 128))
      }
    }
  }

  // Overlay: bytes after the last section's raw data. Installers and signed files have these.
  let lastEnd = 0
  for (const s of sections) lastEnd = Math.max(lastEnd, s.rawPtr + s.rawSize)
  const certDir = dirs[4]
  const overlaySize = bytes.length - lastEnd
  const signed = !!(certDir && certDir.rva && certDir.size)
  const overlayUnsigned = overlaySize - (signed ? certDir.size : 0)

  // Findings
  const aslr = !!(dllChars & 0x40)
  const nx = !!(dllChars & 0x100)
  const cfg = !!(dllChars & 0x4000)
  findings.push(finding('pe.hardening', aslr && nx ? 'info' : 'notice', 'Exploit mitigations',
    `ASLR: ${aslr ? 'yes' : 'no'} · DEP/NX: ${nx ? 'yes' : 'no'} · Control Flow Guard: ${cfg ? 'yes' : 'no'}`))

  if (dirs[14]?.rva) findings.push(finding('pe.dotnet', 'info', '.NET assembly', 'A CLR runtime header is present. Native disassembly will show only a small loader stub; use a .NET decompiler for the managed code.', { confidence: 'high' }))

  if (signed) findings.push(finding('pe.signed', 'info', 'Authenticode signature present', 'A certificate table exists. Signature validity was not checked here.', { incomplete: true }))
  else findings.push(finding('pe.unsigned', 'info', 'No Authenticode signature', 'No certificate table. Common for unsigned or internal tools.'))

  if (overlayUnsigned > 1024) {
    findings.push(finding('pe.overlay', 'notice', 'Overlay data after the last section',
      `${overlayUnsigned.toLocaleString()} bytes at ${hex(lastEnd)}. Installers, self-extractors and appended payloads all look like this.`, { off: lastEnd, confidence: 'high' }))
  }

  const hot = sections.filter((s) => s.entropy > 7.2 && s.rawSize > 2048)
  if (hot.length) {
    findings.push(finding('pe.entropy', 'warn', 'High-entropy sections',
      `${hot.map((s) => `${s.name} (${s.entropy.toFixed(2)})`).join(', ')}. Heuristic: this is typical of packed, compressed or encrypted data, but compressed resources trigger it too.`, { confidence: 'low' }))
  }
  const rwx = sections.filter((s) => s.flags === 'XRW')
  if (rwx.length) findings.push(finding('pe.rwx', 'warn', 'Writable and executable section', rwx.map((s) => s.name).join(', '), { confidence: 'medium' }))

  if (!imports.length && !dirs[14]?.rva) {
    findings.push(finding('pe.noimports', 'notice', 'No import table found',
      'Either the file resolves APIs at runtime (often a packer), or the import table was not parseable. This is not proof of either.', { incomplete: true }))
  }
  if (sections.length && !sections.some((s) => entryRva >= s.vaddr && entryRva < s.vaddr + Math.max(s.vsize, s.rawSize)) && entryRva) {
    findings.push(finding('pe.entry', 'warn', 'Entry point outside every section', `Entry RVA ${hex(entryRva)} does not fall in a mapped section.`, { confidence: 'medium' }))
  }
  if (timestamp && (timestamp < 631152000 || timestamp > Date.now() / 1000 + 86400 * 2)) {
    findings.push(finding('pe.timestamp', 'notice', 'Implausible compile timestamp', `${info.timestampISO}. Often zeroed or forged; reproducible builds also set fixed values.`))
  }

  // Capability hints from imported API names
  const allFuncs = new Set(imports.flatMap((i) => i.funcs))
  const hints = []
  for (const [group, names] of Object.entries(API_HINTS)) {
    const hit = names.filter((n) => allFuncs.has(n))
    if (hit.length) hints.push({ group, apis: hit })
  }
  if (hints.length) {
    findings.push(finding('pe.apis', 'info', 'Capability hints from imported APIs',
      hints.map((h) => `${h.group}: ${h.apis.join(', ')}`).join('\n') + '\nThese APIs are used by plenty of legitimate software; treat as leads, not verdicts.', { confidence: 'low' }))
  }

  // Entry point bytes
  const epOff = rvaToOff(entryRva)
  const entry = epOff >= 0 ? { off: epOff, rva: entryRva } : null

  return {
    info,
    sections,
    dirs: dirs.filter((d) => d.rva || d.size),
    imports,
    exports: exportsList,
    entry,
    findings,
  }
}
