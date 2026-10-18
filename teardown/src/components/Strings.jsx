import React, { useMemo, useState } from 'react'

const PAGE = 400

export default function Strings({ r, onHex }) {
  const [q, setQ] = useState('')
  const [enc, setEnc] = useState('all')
  const [min, setMin] = useState(5)
  const [limit, setLimit] = useState(PAGE)

  const rows = useMemo(() => {
    const needle = q.toLowerCase()
    return r.strings.filter((s) => (enc === 'all' || s.enc === enc) && s.text.length >= min && (!needle || s.text.toLowerCase().includes(needle)))
  }, [r.strings, q, enc, min])

  return (
    <div className="strings">
      <div className="controls">
        <input type="search" placeholder="Filter strings…" value={q} onChange={(e) => { setQ(e.target.value); setLimit(PAGE) }} aria-label="Filter strings" />
        <select value={enc} onChange={(e) => { setEnc(e.target.value); setLimit(PAGE) }} aria-label="Encoding">
          <option value="all">ASCII + UTF-16</option>
          <option value="ascii">ASCII only</option>
          <option value="utf16">UTF-16 only</option>
        </select>
        <label className="range">min length {min}
          <input type="range" min="4" max="40" value={min} onChange={(e) => { setMin(+e.target.value); setLimit(PAGE) }} />
        </label>
        <span className="muted">{rows.length.toLocaleString()} match{rows.length === 1 ? '' : 'es'}</span>
      </div>
      {r.stringsTruncated && <p className="muted small">The string list was capped on this large file.</p>}
      <div className="tablewrap tall">
        <table>
          <thead><tr><th>Offset</th><th>Enc</th><th>String</th></tr></thead>
          <tbody>
            {rows.slice(0, limit).map((s, i) => (
              <tr key={`${s.off}-${i}`} className="click" onClick={() => onHex(s.off)}>
                <td className="mono">0x{s.off.toString(16)}</td>
                <td className="mono">{s.enc === 'utf16' ? 'u16' : 'asc'}</td>
                <td className="mono wrap">{s.text.length > 300 ? `${s.text.slice(0, 300)}…` : s.text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > limit && <button className="ghost" onClick={() => setLimit(limit + PAGE * 2)}>Show more ({(rows.length - limit).toLocaleString()} left)</button>}
    </div>
  )
}
