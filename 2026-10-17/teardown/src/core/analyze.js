import { detect } from './signatures.js'
import { hashAll } from './hashes.js'
import { extractStrings, entropyProfile, carveEmbedded, extractIocs } from './scan.js'
import { parsePE } from './pe.js'
import { parseELF } from './elf.js'
import { parseMachO, parseFat } from './macho.js'
import { parseZip } from './zip.js'
import { parsePDF, parsePNG, parseJPEG, parseWasm, parseClass } from './misc.js'
import { finding, hex } from './util.js'

export const MAX_BYTES = 256 * 1024 * 1024
const MD5_LIMIT = 64 * 1024 * 1024

// Runs the whole static pipeline over one in-memory buffer. Pure function of the
// bytes: no network, no eval, no execution. Every stage is wrapped so one bad
// header never takes down the rest of the report.
export async function analyze(bytes, meta = {}, onStage = () => {}) {
  const started = Date.now()
  const findings = []
  const stageErrors = []

  const stage = async (name, fn) => {
    onStage(name)
    try {
      return await fn()
    } catch (e) {
      stageErrors.push({ stage: name, message: String(e && e.message ? e.message : e) })
      return null
    }
  }

  const type = detect(bytes)

  // MD5 needs a padded copy of the data, so very large files get SHA digests only.
  const sha = await stage('Hashing', () => hashAll(bytes, bytes.length <= MD5_LIMIT))

  const parsed = await stage('Parsing structure', async () => {
    switch (type.kind) {
      case 'pe': return { kind: 'pe', ...parsePE(bytes) }
      case 'elf': return { kind: 'elf', ...parseELF(bytes) }
      case 'macho': return { kind: 'macho', ...parseMachO(bytes) }
      case 'macho-fat': {
        const archs = parseFat(bytes)
        const slices = []
        for (const a of archs) {
          try {
            slices.push({ arch: a.cpu, offset: a.offset, size: a.size, ...parseMachO(bytes, a.offset, a.size) })
          } catch (e) {
            slices.push({ arch: a.cpu, offset: a.offset, size: a.size, error: String(e.message || e), findings: [] })
          }
        }
        return { kind: 'macho-fat', archs, slices, info: { format: 'Mach-O universal', architectures: archs.map((a) => a.cpu).join(', ') }, findings: slices.flatMap((s) => s.findings || []) }
      }
      case 'zip': return { kind: 'zip', ...parseZip(bytes) }
      case 'pdf': return { kind: 'pdf', ...parsePDF(bytes) }
      case 'png': return { kind: 'png', ...parsePNG(bytes) }
      case 'jpeg': return { kind: 'jpeg', ...parseJPEG(bytes) }
      case 'wasm': return { kind: 'wasm', ...parseWasm(bytes) }
      case 'java-class': return { kind: 'java-class', ...parseClass(bytes) }
      default: return null
    }
  })

  const strRes = await stage('Extracting strings', () => extractStrings(bytes))
  const strings = strRes ? strRes.strings : []
  const iocs = await stage('Finding indicators', () => extractIocs(strings))
  const entropy = await stage('Measuring entropy', () => entropyProfile(bytes))
  const embedded = await stage('Scanning for embedded files', () => carveEmbedded(bytes))

  // Format-agnostic findings
  if (entropy && entropy.overall > 7.5 && bytes.length > 4096 && type.group !== 'archive' && type.group !== 'image' && type.group !== 'media') {
    findings.push(finding('gen.entropy', 'warn', 'Very high overall entropy', `${entropy.overall.toFixed(2)} bits/byte. Heuristic: consistent with encrypted, compressed or packed content.`, { confidence: 'low' }))
  }
  if (embedded && embedded.length) {
    const first = embedded.slice(0, 6).map((h) => `${h.name} @ ${hex(h.off)}`).join('\n')
    const sev = type.group === 'executable' || type.group === 'document' ? 'notice' : 'info'
    findings.push(finding('gen.embedded', sev, `${embedded.length} possible embedded file signature${embedded.length === 1 ? '' : 's'}`,
      `${first}${embedded.length > 6 ? '\n…' : ''}\nSignature matches are leads: short magic numbers occur by chance, especially inside compressed data.`, { off: embedded[0].off, confidence: 'low' }))
  }
  if (iocs) {
    const nUrl = iocs.url.length, nIp = iocs.ipv4.length
    if (nUrl || nIp) findings.push(finding('gen.network', 'info', 'Network indicators in strings', `${nUrl} URL(s), ${nIp} IPv4 address(es). Shown defanged in the Indicators tab.`))
  }
  if (strRes && strRes.truncated) findings.push(finding('gen.strtrunc', 'notice', 'String list truncated', 'Too many strings to list; the list was capped. Indicators were extracted only from the listed strings.', { incomplete: true }))
  if (type.kind === 'unknown') findings.push(finding('gen.unknown', 'notice', 'Format not recognised', 'No known signature matched. Entropy, strings and the hex view still apply.', { incomplete: true }))
  if (!['pe', 'elf', 'macho', 'macho-fat'].includes(type.kind) && type.group === 'executable') findings.push(finding('gen.noparser', 'info', 'No deep parser for this format', 'Detected by signature only.', { incomplete: true }))
  if (['pe', 'elf', 'macho', 'macho-fat'].includes(type.kind)) findings.push(finding('gen.nodisasm', 'info', 'Disassembly not performed', 'This build shows headers, imports, strings and entry-point bytes. It does not disassemble or decompile code, so the absence of a finding here is not evidence the code is benign.', { incomplete: true }))
  for (const e of stageErrors) findings.push(finding(`err.${e.stage}`, 'notice', `Stage failed: ${e.stage}`, e.message, { incomplete: true }))

  const all = [...(parsed?.findings || []), ...findings]
  const order = { warn: 0, notice: 1, info: 2 }
  all.sort((a, b) => order[a.severity] - order[b.severity])

  return {
    meta: { name: meta.name || 'file', size: bytes.length, lastModified: meta.lastModified || null, analyzedMs: Date.now() - started },
    type,
    hashes: sha,
    parsed,
    strings,
    stringsTruncated: !!strRes?.truncated,
    iocs,
    entropy,
    embedded,
    findings: all,
    stageErrors,
  }
}
