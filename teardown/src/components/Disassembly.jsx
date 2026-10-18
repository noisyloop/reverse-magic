import React, { useEffect, useMemo, useState } from 'react'
import { ARCHS } from '../disasm/engine.js'
import { disassemble } from '../disasm/client.js'

const COUNTS = [100, 200, 500, 1000]
const BRANCH = /^(call|jmp|j[a-z]{1,3}|loop[a-z]*|b|bl|b\.[a-z]+|cbn?z|tbn?z|beq|bne|blt|bge|bgt|ble|bltu|bgeu|jal)\b/i

const hx = (n) => '0x' + Number(n).toString(16)

// File offset -> virtual address using the section/segment layout, and back.
function offToVa(layout, off) {
  const s = layout.find((l) => off >= l.off && off < l.off + l.size)
  return s ? s.va + (off - s.off) : off
}
function vaToOff(layout, va) {
  const s = layout.find((l) => va >= l.va && va < l.va + l.size)
  return s ? s.off + (va - s.va) : null
}

export default function Disassembly({ r, file, start, onHex }) {
  const targets = r.disasm?.targets || []
  const [ti, setTi] = useState(0)
  const t = targets[ti]
  const [arch, setArch] = useState(t?.arch)
  const [syntax, setSyntax] = useState('intel')
  const [max, setMax] = useState(200)
  const [startText, setStartText] = useState('')
  const [from, setFrom] = useState(null)
  const [insns, setInsns] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)

  const layout = t?.layout || []
  const execRegions = layout.filter((l) => l.exec && l.size > 0)

  // Pick an initial location: an explicit request, else the entry point, else the first code region.
  useEffect(() => {
    if (!t) return
    setArch(t.arch)
    const first = start != null && start > 0 ? start : t.entry ? t.entry.off : execRegions[0]?.off ?? 0
    setFrom(first)
    setStartText(first.toString(16))
  }, [ti, start, r])

  const spec = ARCHS[arch]
  useEffect(() => { if (spec && !spec.syntaxes.includes(syntax)) setSyntax(spec.syntaxes[0]) }, [arch])

  useEffect(() => {
    if (!t || from == null || !spec) return
    let live = true
    setBusy(true)
    setErr('')
    disassemble(file, { arch, off: from, base: offToVa(layout, from), max, syntax: spec.syntaxes.includes(syntax) ? syntax : spec.syntaxes[0] })
      .then((x) => { if (live) { setInsns(x); setBusy(false) } })
      .catch((e) => { if (live) { setErr(e.message); setBusy(false) } })
    return () => { live = false }
  }, [file, arch, from, max, syntax, ti])

  const listing = useMemo(
    () => (insns || []).map((i) => `${i.addr.toString(16).padStart(8, '0')}  ${i.bytes.padEnd(24)} ${i.text}`).join('\n'),
    [insns]
  )

  if (!t) {
    return <p className="muted">No supported code architecture was found in this file, so there is nothing to disassemble. Use the Hex tab for raw bytes.</p>
  }

  const submit = (e) => {
    e.preventDefault()
    const v = parseInt(startText.replace(/^0x/i, ''), 16)
    if (Number.isFinite(v) && v >= 0 && v < file.size) setFrom(v)
  }
  const follow = (text) => {
    // Only direct branches: the operand must be a bare address. Memory operands such as
    // "call qword ptr [rip+0x10]" hold a displacement, not a target, so they are not followed.
    if (!BRANCH.test(text) || text.includes('[')) return null
    const m = text.match(/(?:^|[\s,#])(0x[0-9a-f]+)$/i)
    if (!m) return null
    const va = parseInt(m[1], 16)
    const off = vaToOff(layout, va)
    return off == null ? null : { va, off }
  }
  const copy = async () => {
    try { await navigator.clipboard.writeText(listing); setCopied(true); setTimeout(() => setCopied(false), 1200) } catch { /* clipboard unavailable */ }
  }

  return (
    <div className="disasm">
      <div className="controls">
        {targets.length > 1 && (
          <select value={ti} onChange={(e) => setTi(+e.target.value)} aria-label="Architecture slice">
            {targets.map((x, i) => <option key={i} value={i}>{x.label} ({x.arch})</option>)}
          </select>
        )}
        <select value={arch} onChange={(e) => setArch(e.target.value)} aria-label="Architecture">
          {Object.entries(ARCHS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        {spec && spec.syntaxes.length > 1 && (
          <select value={syntax} onChange={(e) => setSyntax(e.target.value)} aria-label="Syntax">
            <option value="intel">Intel syntax</option>
            <option value="gnu">AT&amp;T syntax</option>
          </select>
        )}
        <form onSubmit={submit} className="goto">
          <input value={startText} onChange={(e) => setStartText(e.target.value)} placeholder="File offset (hex)" aria-label="Start at file offset in hex" />
          <button className="ghost" type="submit">Go</button>
        </form>
        {t.entry && <button className="ghost" onClick={() => { setFrom(t.entry.off); setStartText(t.entry.off.toString(16)) }}>Entry point</button>}
        {execRegions.length > 0 && (
          <select value="" onChange={(e) => { if (e.target.value !== '') { const o = +e.target.value; setFrom(o); setStartText(o.toString(16)) } }} aria-label="Jump to code section">
            <option value="">Code section…</option>
            {execRegions.map((l, i) => <option key={i} value={l.off}>{l.name || 'region'} @ {hx(l.off)}</option>)}
          </select>
        )}
        <select value={max} onChange={(e) => setMax(+e.target.value)} aria-label="Instruction count">
          {COUNTS.map((c) => <option key={c} value={c}>{c} instructions</option>)}
        </select>
        <button className="ghost" onClick={copy} disabled={!insns?.length}>{copied ? 'Copied' : 'Copy listing'}</button>
        <button className="ghost" onClick={() => onHex(from || 0)}>View bytes</button>
      </div>

      <p className="muted note">
        Linear sweep from the chosen offset. It does not follow control flow, find function boundaries or tell code from data, so data bytes may appear as nonsense instructions.
        {arch.startsWith('x86') && ' AVX and AVX-512 instructions get the correct length but are shown as "not decoded".'}
        {' '}ARM Thumb is not supported.
      </p>

      {err && <p className="err">{err}</p>}
      {busy && !insns && <p className="muted" role="status">Loading disassembler…</p>}
      {insns && (
        <div className="tablewrap tall" style={busy ? { opacity: 0.6 } : undefined}>
          <table className="dis mono">
            <thead><tr><th>Address</th><th>Bytes</th><th>Instruction</th></tr></thead>
            <tbody>
              {insns.map((i, k) => {
                const f = !i.bad && !i.partial ? follow(i.text) : null
                return (
                  <tr key={k} className={i.bad ? 'bad' : i.partial ? 'partial' : ''}>
                    <td className="addr">{i.addr.toString(16).padStart(8, '0')}</td>
                    <td className="ibytes">{i.bytes}</td>
                    <td>
                      {i.text}
                      {f && <> <button className="mini" title={`Go to ${hx(f.va)}`} onClick={() => { setFrom(f.off); setStartText(f.off.toString(16)) }}>{'→'} follow</button></>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
