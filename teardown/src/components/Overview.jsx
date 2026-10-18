import React, { useState } from 'react'

const TAG = { warn: 'WARN', notice: 'NOTE', info: 'INFO' }

function Copy({ text }) {
  const [done, setDone] = useState(false)
  return (
    <button
      className="mini"
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200) } catch { /* clipboard may be blocked */ }
      }}
    >{done ? 'copied' : 'copy'}</button>
  )
}

export default function Overview({ r, onHex }) {
  const warn = r.findings.filter((f) => f.severity === 'warn').length
  const note = r.findings.filter((f) => f.severity === 'notice').length
  const info = r.parsed?.info || {}
  const facts = Object.entries(info).filter(([k, v]) => v != null && v !== '' && k !== 'timestamp' && k !== 'timestampISO')
  if (info.timestampISO) facts.push(['compiled', info.timestampISO])

  return (
    <div className="overview">
      <div className="stats">
        <div className="stat"><b>{warn}</b><span>warnings</span></div>
        <div className="stat"><b>{note}</b><span>notes</span></div>
        <div className="stat"><b>{r.entropy ? r.entropy.overall.toFixed(2) : '–'}</b><span>entropy (bits/byte)</span></div>
        <div className="stat"><b>{(r.embedded?.length ?? 0).toLocaleString()}</b><span>embedded signatures</span></div>
      </div>

      <div className="cols">
        <div>
          <h3>Findings</h3>
          <p className="muted small">Heuristics and leads. A missing finding is not proof of absence, and items marked incomplete could not be fully checked.</p>
          <ul className="findings">
            {r.findings.map((f) => (
              <li key={f.id} className={`f ${f.severity}`}>
                <div className="f-head">
                  <span className={`tag ${f.severity}`}>{TAG[f.severity]}</span>
                  <strong>{f.title}</strong>
                  {f.confidence && <span className="conf">confidence: {f.confidence}</span>}
                  {f.incomplete && <span className="conf inc">incomplete</span>}
                  {f.off != null && <button className="mini" onClick={() => onHex(f.off)}>hex @ 0x{f.off.toString(16)}</button>}
                </div>
                <pre className="f-body">{f.detail}</pre>
              </li>
            ))}
            {r.findings.length === 0 && <li className="muted">No findings.</li>}
          </ul>
        </div>

        <div>
          <h3>Identity</h3>
          <dl className="kv">
            <dt>Type</dt><dd>{r.type.label}</dd>
            <dt>Size</dt><dd>{r.meta.size.toLocaleString()} bytes</dd>
            {Object.entries(r.hashes || {}).map(([k, v]) => (
              <React.Fragment key={k}>
                <dt>{k.toUpperCase()}</dt><dd className="mono hash">{v} <Copy text={v} /></dd>
              </React.Fragment>
            ))}
          </dl>
          {facts.length > 0 && (
            <>
              <h3>Format facts</h3>
              <dl className="kv">
                {facts.map(([k, v]) => (<React.Fragment key={k}><dt>{k}</dt><dd className="mono">{String(v)}</dd></React.Fragment>))}
              </dl>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
