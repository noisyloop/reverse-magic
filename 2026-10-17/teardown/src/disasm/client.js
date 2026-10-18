// Main-thread side: starts the disassembler worker on first use and turns its
// message protocol into promises. Reads only the bytes it needs from the File.
let worker = null
let nextId = 1
const pending = new Map()

function ensureWorker() {
  if (worker) return worker
  worker = new Worker('./disasm-worker.js')
  worker.onmessage = (e) => {
    const { id, insns, error } = e.data
    const p = pending.get(id)
    if (!p) return
    pending.delete(id)
    error ? p.reject(new Error(error)) : p.resolve(insns)
  }
  worker.onerror = (e) => {
    for (const p of pending.values()) p.reject(new Error(e.message || 'disassembler worker failed'))
    pending.clear()
    worker = null
  }
  return worker
}

export async function disassemble(file, { arch, off, base, max, syntax }) {
  const win = Math.min(file.size - off, Math.max(4096, max * 15 + 16)) // 15 = longest x86 instruction
  const bytes = new Uint8Array(await file.slice(off, off + win).arrayBuffer())
  const id = nextId++
  const w = ensureWorker()
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    w.postMessage({ id, arch, bytes, base, max, syntax }, [bytes.buffer])
  })
}
