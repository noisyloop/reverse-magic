// Disassembler tests. Run with: node test/disasm.mjs
// Fixed byte vectors, plus an optional cross-check against objdump when present.
import '../vendor/wasm_exec.js'
import { readFileSync, existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { loadEngine } from '../src/disasm/engine.js'
import { analyze } from '../src/core/analyze.js'

let failed = 0
const ok = (c, m) => { if (!c) { failed++; console.error('  FAIL', m) } else console.log('  ok  ', m) }
const hex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)))
const eng = await loadEngine(readFileSync(new URL('../wasm/disasm.wasm', import.meta.url)))
const dis = (arch, h, syn = 'intel', base = 0x1000) => eng.disasm(arch, hex(h), base, 50, syn)

console.log('x86-64')
{
  const r = dis('x86-64', 'f30f1efa31ed4889e2')
  ok(r.map((i) => i.text).join('|') === 'endbr64|xor ebp, ebp|mov rdx, rsp', 'endbr64 / xor / mov decode')
  ok(r.map((i) => i.len).join() === '4,2,3' && r[1].addr === 0x1004, 'lengths and addresses advance')
  const neg = dis('x86-64', '488b45f0')[0].text
  ok(/-0x10/.test(neg), `negative displacement is signed (${neg})`)
  ok(/^ret/.test(dis('x86-64', 'c3')[0].text), 'ret')
  const vz = dis('x86-64', 'c5f877c3')
  ok(vz[0].len === 3 && vz[0].text === 'vzeroupper' && vz[1].text === 'ret', 'vzeroupper decodes and the next instruction stays aligned')
  const avx = dis('x86-64', 'c5f96fc1c3')
  ok(avx[0].len === 4 && avx[0].partial && avx[1].text === 'ret', 'other AVX: correct length, flagged as not decoded, stream stays aligned')
  const bad = dis('x86-64', '06')
  ok(bad[0].bad && bad[0].len === 1, 'invalid opcode is flagged and advances one byte')
}
console.log('other architectures')
{
  ok(dis('arm64', 'c0035fd6', 'gnu')[0].text === 'ret', 'arm64 ret')
  ok(dis('riscv64', '67800000', 'gnu')[0].text.startsWith('ret') || dis('riscv64', '67800000', 'gnu')[0].text.includes('jalr'), 'riscv64 ret/jalr')
  ok(dis('arm', '1eff2fe1', 'gnu')[0].text.toLowerCase().includes('bx'), 'arm bx lr')
  const tail = dis('arm64', 'c0035fd6c0035f', 'gnu').at(-1)
  ok(tail.bad && tail.len === 3, 'truncated tail is flagged bad and consumes the remaining bytes')
}
console.log('input handling')
{
  let threw = false
  try { eng.disasm('mips', new Uint8Array(4)) } catch { threw = true }
  ok(threw, 'unsupported architecture throws')
  ok(eng.disasm('x86-64', new Uint8Array(0), 0, 10, 'intel').length === 0, 'empty input gives no instructions')
}
console.log('analysis wiring')
{
  const ls = new Uint8Array(readFileSync('/bin/ls'))
  const rep = await analyze(ls, { name: 'ls' })
  const t = rep.disasm.targets[0]
  ok(t && t.arch === 'x86-64' && t.entry && t.layout.some((l) => l.exec), 'ELF exposes a disassembly target with entry and code layout')
  ok(rep.findings.some((f) => f.id === 'gen.nodisasm' && f.incomplete), 'limits finding is present and marked incomplete')
}
if (existsSync('/usr/bin/objdump') && existsSync('/bin/ls')) {
  console.log('objdump cross-check (optional)')
  const ls = new Uint8Array(readFileSync('/bin/ls'))
  const { entry } = (await analyze(ls, { name: 'ls' })).parsed
  const ours = eng.disasm('x86-64', ls.subarray(entry.off, entry.off + 4000), entry.rva, 300, 'intel')
  const od = execFileSync('objdump', ['-d', '-M', 'intel', '--no-show-raw-insn', `--start-address=0x${entry.rva.toString(16)}`, `--stop-address=0x${(entry.rva + 1200).toString(16)}`, '/bin/ls'], { encoding: 'utf8' })
  const theirs = od.split('\n').map((l) => l.match(/^\s*([0-9a-f]+):\s+\S/)).filter(Boolean).map((m) => parseInt(m[1], 16))
  const n = Math.min(theirs.length, ours.length)
  let same = 0
  for (let i = 0; i < n; i++) if (ours[i].addr === theirs[i]) same++
  ok(n > 50 && same === n, `instruction boundaries match objdump (${same}/${n})`)
}
console.log(failed ? `\n${failed} failed` : '\nall checks passed')
process.exit(failed ? 1 : 0)
