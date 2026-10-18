// Runs the analysis off the main thread so parsing untrusted bytes can never
// freeze the UI. lockdown.js removes the worker's network APIs first; the CSP
// header (public/_headers) is the real network control for workers.
import './lockdown.js'
import { analyze, MAX_BYTES } from './core/analyze.js'

self.onmessage = async (e) => {
  const { file } = e.data
  try {
    if (file.size > MAX_BYTES) {
      self.postMessage({ type: 'error', message: `File is ${(file.size / 1048576).toFixed(0)} MB. The limit is ${MAX_BYTES / 1048576} MB.` })
      return
    }
    self.postMessage({ type: 'stage', stage: 'Reading file' })
    const bytes = new Uint8Array(await file.arrayBuffer())
    const result = await analyze(bytes, { name: file.name, lastModified: file.lastModified }, (stage) => {
      self.postMessage({ type: 'stage', stage })
    })
    self.postMessage({ type: 'done', result })
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err && err.message ? err.message : err) })
  }
}
