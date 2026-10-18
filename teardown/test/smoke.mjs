// Smoke tests for the analyzer core. Run with: node test/smoke.mjs
// Uses real files already on disk where possible and builds the rest in memory.
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { analyze } from '../src/core/analyze.js'
import { detect } from '../src/core/signatures.js'

let failed = 0
const ok = (cond, msg) => {
  if (!cond) { failed++; console.error('  FAIL', msg) } else console.log('  ok  ', msg)
}
const u8 = (b) => new Uint8Array(b.buffer, b.byteOffset, b.byteLength)

// ---- hashes agree with Node's crypto
{
  console.log('hashes')
  const data = new Uint8Array(100000).map((_, i) => (i * 31 + 7) & 255)
  const r = await analyze(data, { name: 'blob.bin' })
  for (const algo of ['md5', 'sha1', 'sha256']) {
    ok(r.hashes[algo] === createHash(algo).update(data).digest('hex'), `${algo} matches node:crypto`)
  }
  ok(r.type.kind === 'unknown', 'random-ish bytes are "unknown"')
}

// ---- ELF: a real binary
{
  console.log('elf (/bin/ls)')
  const p = ['/bin/ls', '/usr/bin/ls'].find(existsSync)
  const b = u8(readFileSync(p))
  const r = await analyze(b, { name: 'ls' })
  ok(r.type.kind === 'elf', 'detected as ELF')
  ok(r.parsed?.kind === 'elf' && r.parsed.sections.length > 5, 'sections parsed')
  ok(r.parsed.needed.some((n) => /libc/.test(n)), `needs libc (${r.parsed.needed.join(', ')})`)
  ok(r.parsed.imports.length > 10, `dynamic imports found (${r.parsed.imports.length})`)
  ok(r.parsed.entry && r.parsed.entry.off > 0, 'entry point mapped to a file offset')
  ok(r.strings.length > 100 && r.entropy.windows.length > 0, 'strings and entropy produced')
  ok(r.stageErrors.length === 0, 'no stage errors')
}

// ---- PE: real launcher stubs shipped with uv/pip (benign)
{
  console.log('pe (launcher stub)')
  const root = '/root/.cache/uv/archive-v0'
  let file = null
  if (existsSync(root)) {
    const walk = (d, depth = 0) => {
      if (file || depth > 5) return
      for (const e of readdirSync(d, { withFileTypes: true })) {
        const full = `${d}/${e.name}`
        if (e.isDirectory()) walk(full, depth + 1)
        else if (/w64\.exe$/.test(e.name)) { file = full; return }
      }
    }
    walk(root)
  }
  if (!file) console.log('  skip (no sample PE on this machine)')
  else {
    const r = await analyze(u8(readFileSync(file)), { name: 'w64.exe' })
    ok(r.type.kind === 'pe', 'detected as PE')
    ok(r.parsed?.sections.length >= 3, `sections parsed (${r.parsed?.sections.map((s) => s.name).join(' ')})`)
    ok(r.parsed.imports.some((i) => /kernel32/i.test(i.dll)), 'imports kernel32')
    ok(/AMD64|x86|ARM/.test(r.parsed.info.machine), `machine = ${r.parsed.info.machine}`)
    ok(r.parsed.entry, 'entry point mapped')
    ok(r.stageErrors.length === 0, 'no stage errors')
  }
}

// ---- Mach-O: hand-built minimal 64-bit executable
{
  console.log('mach-o (synthetic)')
  const dylib = 'libSystem.B.dylib'
  const dlen = 24 + Math.ceil((dylib.length + 1) / 8) * 8
  const segCmdSize = 72
  const total = 32 + segCmdSize + dlen + 24
  const buf = new Uint8Array(total + 64)
  const dv = new DataView(buf.buffer)
  dv.setUint32(0, 0xfeedfacf, true)
  dv.setUint32(4, 0x0100000c, true) // arm64
  dv.setUint32(12, 2, true) // executable
  dv.setUint32(16, 3, true) // ncmds
  dv.setUint32(20, segCmdSize + dlen + 24, true)
  dv.setUint32(24, 0x200000, true)
  let o = 32
  dv.setUint32(o, 0x19, true); dv.setUint32(o + 4, segCmdSize, true)
  buf.set(new TextEncoder().encode('__TEXT'), o + 8)
  o += segCmdSize
  dv.setUint32(o, 0xc, true); dv.setUint32(o + 4, dlen, true); dv.setUint32(o + 8, 24, true)
  buf.set(new TextEncoder().encode(dylib), o + 24)
  o += dlen
  dv.setUint32(o, 0x80000028, true); dv.setUint32(o + 4, 24, true); dv.setUint32(o + 8, 0x1234, true)
  const r = await analyze(buf, { name: 'a.out' })
  ok(r.type.kind === 'macho', 'detected as Mach-O')
  ok(r.parsed?.dylibs?.[0]?.name === dylib, 'LC_LOAD_DYLIB parsed')
  ok(r.parsed?.info.cpu === 'ARM64', 'cpu = ARM64')
  ok(r.parsed?.entry?.rva === 0x1234, 'LC_MAIN entry parsed')
  ok(r.findings.some((f) => f.id === 'macho.unsigned'), 'flags missing code signature')
}

// ---- ZIP via Python's zipfile (stdlib), with a path-traversal name and an exe entry
{
  console.log('zip (synthetic)')
  const { execFileSync } = await import('node:child_process')
  const py = `
import zipfile, io, sys
b = io.BytesIO()
with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('word/document.xml', '<w:document/>' * 50)
    z.writestr('word/vbaProject.bin', b'\\x00' * 100)
    z.writestr('../evil.exe', b'MZ' + b'\\x00' * 200)
sys.stdout.buffer.write(b.getvalue())
`
  const buf = u8(execFileSync('python3', ['-c', py], { maxBuffer: 1 << 20 }))
  const r = await analyze(buf, { name: 'doc.docm' })
  ok(r.type.kind === 'zip', 'detected as ZIP')
  ok(r.parsed?.info.kind.startsWith('Word'), `kind = ${r.parsed?.info.kind}`)
  ok(r.findings.some((f) => f.id === 'zip.slip'), 'flags path traversal entry')
  ok(r.findings.some((f) => f.id === 'zip.macro'), 'flags macro project')
}

// ---- PDF, PNG, text
{
  console.log('pdf / png / text')
  const pdf = new TextEncoder().encode('%PDF-1.7\n1 0 obj<</OpenAction<</S/JavaScript/JS(app.alert(1))>>>>endobj\n/URI (http://example.com/x)\n%%EOF')
  const r1 = await analyze(pdf, { name: 'x.pdf' })
  ok(r1.type.kind === 'pdf', 'detected as PDF')
  ok(r1.findings.some((f) => f.id === 'pdf.js'), 'flags JavaScript keyword')
  ok(r1.parsed.uris.includes('http://example.com/x'), 'extracts /URI')
  ok(r1.iocs.url.some((u) => u.value.startsWith('http://example.com')), 'URL found as IOC')

  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 2, 0, 0, 0, 3, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0, ...new TextEncoder().encode('TRAILING PAYLOAD DATA HERE')])
  const r2 = await analyze(png, { name: 'x.png' })
  ok(r2.parsed?.info.width === 2 && r2.parsed?.info.height === 3, 'PNG dimensions')
  ok(r2.findings.some((f) => f.id === 'png.trailer'), 'flags data after IEND')

  ok(detect(new TextEncoder().encode('hello world, plain text\n'.repeat(20))).kind === 'text', 'plain text detected')
  ok((await analyze(new Uint8Array(0), { name: 'empty' })).type.kind === 'unknown', 'empty file does not crash')
}

// ---- Robustness: truncated and corrupt headers must not throw out of analyze()
{
  console.log('robustness')
  const base = u8(readFileSync(['/bin/ls', '/usr/bin/ls'].find(existsSync)))
  for (const cut of [4, 20, 64, 200, 5000]) {
    const r = await analyze(base.slice(0, cut), { name: `ls.${cut}` })
    ok(r && r.type, `truncated ELF (${cut} bytes) returns a report`)
  }
  const mz = new Uint8Array(512); mz[0] = 0x4d; mz[1] = 0x5a; mz[0x3c] = 0x80; mz.set([0x50, 0x45, 0, 0], 0x80)
  ok((await analyze(mz, { name: 'bad.exe' })).stageErrors.length > 0, 'corrupt PE is reported as a stage error, not a crash')
}

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed')
process.exit(failed ? 1 : 0)
