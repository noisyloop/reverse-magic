// Loads the Go-compiled disassembler (WebAssembly) and wraps it.
//
// The caller must already have loaded vendor/wasm_exec.js (it defines globalThis.Go).
// In the browser this runs inside disasm-worker.js; the tests run it under Node.
// The module only decodes bytes into text. It never executes the bytes.

export const ARCHS = {
  'x86-64': { label: 'x86-64', syntaxes: ['intel', 'gnu'], fixed: 0 },
  'x86-32': { label: 'x86 (32-bit)', syntaxes: ['intel', 'gnu'], fixed: 0 },
  arm64: { label: 'ARM64 (AArch64)', syntaxes: ['gnu'], fixed: 4 },
  arm: { label: 'ARM (32-bit)', syntaxes: ['gnu'], fixed: 4 },
  riscv64: { label: 'RISC-V 64', syntaxes: ['gnu'], fixed: 0 },
  ppc64: { label: 'PowerPC64 (big-endian)', syntaxes: ['gnu'], fixed: 4 },
  ppc64le: { label: 'PowerPC64 (little-endian)', syntaxes: ['gnu'], fixed: 4 },
}

export async function loadEngine(wasmBytes) {
  if (!globalThis.Go) throw new Error('wasm_exec.js must be loaded before the disassembler')
  const go = new globalThis.Go()
  const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject)
  go.run(instance) // runs for the life of the engine; deliberately not awaited
  for (let i = 0; i < 200 && !globalThis.teardownDisasmReady; i++) await new Promise((r) => setTimeout(r, 5))
  if (!globalThis.teardownDisasmReady) throw new Error('disassembler did not start')

  return {
    // Linear sweep: decodes instruction after instruction from the start of `bytes`.
    disasm(arch, bytes, baseAddr = 0, maxInsns = 200, syntax = 'intel') {
      if (!ARCHS[arch]) throw new Error(`unsupported architecture: ${arch}`)
      const res = globalThis.teardownDisasm(arch, bytes, baseAddr, maxInsns, syntax)
      if (typeof res === 'string') throw new Error(res)
      return res
    },
  }
}
