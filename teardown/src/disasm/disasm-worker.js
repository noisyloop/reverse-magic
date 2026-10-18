// Loaded lazily, only when the user opens the Disassembly tab. The WebAssembly
// module is embedded in this bundle, so nothing is fetched at runtime.
import '../lockdown.js'
import '../../vendor/wasm_exec.js'
import wasmBytes from '../../wasm/disasm.wasm'
import { loadEngine } from './engine.js'

let engine = null
const ready = loadEngine(wasmBytes).then((e) => { engine = e }).catch((err) => { throw err })

self.onmessage = async (e) => {
  const { id, arch, bytes, base, max, syntax } = e.data
  try {
    await ready
    const insns = engine.disasm(arch, bytes, base, max, syntax)
    self.postMessage({ id, insns })
  } catch (err) {
    self.postMessage({ id, error: String(err && err.message ? err.message : err) })
  }
}
