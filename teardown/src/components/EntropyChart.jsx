import React, { useState } from 'react'

const W = 900
const H = 220
const PAD = { l: 34, r: 8, t: 8, b: 22 }

export default function EntropyChart({ r, onHex }) {
  const e = r.entropy
  const [hover, setHover] = useState(null)
  if (!e || !e.windows.length) return <p className="muted">No data.</p>
  const n = e.windows.length
  const bw = (W - PAD.l - PAD.r) / n
  const y = (v) => PAD.t + (1 - v / 8) * (H - PAD.t - PAD.b)
  const total = r.meta.size

  return (
    <div className="entropy">
      <p className="muted">
        Shannon entropy per {e.windowSize.toLocaleString()}-byte window. Plain text sits near 4–5, machine code near 5–6.5, and compressed or encrypted data approaches 8.
        High entropy is a heuristic, not proof: images, archives and installers are high by design. Click a bar to open that region in the hex view.
      </p>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img" aria-label={`Entropy profile across the file, overall ${e.overall.toFixed(2)} bits per byte`}>
        {[0, 2, 4, 6, 8].map((v) => (
          <g key={v}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(v)} y2={y(v)} className="grid" />
            <text x={PAD.l - 6} y={y(v) + 4} textAnchor="end" className="axis">{v}</text>
          </g>
        ))}
        <line x1={PAD.l} x2={W - PAD.r} y1={y(7.2)} y2={y(7.2)} className="thresh" />
        <text x={W - PAD.r} y={y(7.2) - 4} textAnchor="end" className="axis hotlabel">7.2 · likely compressed / encrypted</text>
        {e.windows.map((w, i) => {
          const top = y(w.h)
          const cls = w.h > 7.2 ? 'hot' : w.h > 6.5 ? 'warm' : 'cool'
          return (
            <rect
              key={i}
              x={PAD.l + i * bw + 0.5}
              y={top}
              width={Math.max(1, bw - 1)}
              height={H - PAD.b - top}
              className={`bar ${cls}`}
              onMouseEnter={() => setHover(w)}
              onMouseLeave={() => setHover(null)}
              onClick={() => onHex(w.off)}
            >
              <title>{`0x${w.off.toString(16)}: ${w.h.toFixed(2)} bits/byte`}</title>
            </rect>
          )
        })}
        <text x={PAD.l} y={H - 6} className="axis">0x0</text>
        <text x={W - PAD.r} y={H - 6} textAnchor="end" className="axis">0x{total.toString(16)}</text>
      </svg>
      <div className="legend">
        <span><i className="sw cool" /> below 6.5</span>
        <span><i className="sw warm" /> 6.5 to 7.2</span>
        <span><i className="sw hot" /> above 7.2</span>
        <span className="muted">{hover ? `0x${hover.off.toString(16)} – 0x${hover.end.toString(16)} · ${hover.h.toFixed(2)}` : `overall ${e.overall.toFixed(3)} bits/byte`}</span>
      </div>
    </div>
  )
}
