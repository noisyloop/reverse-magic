import React, { useEffect, useState } from 'react'

const PAGE = 4096

// Reads one page at a time from the File handle, so the hex view works on large
// files without holding a second copy in memory.
export default function HexView({ file, size, offset, entry, onDisasm }) {
  const [base, setBase] = useState(Math.floor(offset / PAGE) * PAGE)
  const [bytes, setBytes] = useState(null)
  const [goto, setGoto] = useState('')
  const [mark, setMark] = useState(offset)

  useEffect(() => {
    setBase(Math.floor(offset / PAGE) * PAGE)
    setMark(offset)
  }, [offset])

  useEffect(() => {
    let live = true
    file.slice(base, Math.min(size, base + PAGE)).arrayBuffer().then((b) => live && setBytes(new Uint8Array(b)))
    return () => { live = false }
  }, [file, base, size])

  const go = (e) => {
    e.preventDefault()
    const v = parseInt(goto.replace(/^0x/i, ''), 16)
    if (Number.isFinite(v) && v >= 0 && v < size) { setBase(Math.floor(v / PAGE) * PAGE); setMark(v) }
  }

  const rows = []
  if (bytes) {
    for (let i = 0; i < bytes.length; i += 16) {
      const cells = []
      let txt = ''
      for (let j = 0; j < 16; j++) {
        const idx = i + j
        if (idx < bytes.length) {
          const b = bytes[idx]
          const isMark = base + idx === mark
          cells.push(<span key={j} className={isMark ? 'b hit' : 'b'}>{b.toString(16).padStart(2, '0')}</span>)
          txt += b >= 32 && b < 127 ? String.fromCharCode(b) : '.'
        } else cells.push(<span key={j} className="b pad">  </span>)
      }
      rows.push(
        <div className="hrow" key={i}>
          <span className="off">{(base + i).toString(16).padStart(8, '0')}</span>
          <span className="bytes">{cells}</span>
          <span className="asc">{txt}</span>
        </div>
      )
    }
  }

  return (
    <div className="hex">
      <div className="controls">
        <button className="ghost" disabled={base <= 0} onClick={() => setBase(Math.max(0, base - PAGE))}>{'←'} Prev</button>
        <button className="ghost" disabled={base + PAGE >= size} onClick={() => setBase(base + PAGE)}>Next {'→'}</button>
        <form onSubmit={go} className="goto">
          <input value={goto} onChange={(e) => setGoto(e.target.value)} placeholder="Go to offset (hex)" aria-label="Go to offset in hex" />
          <button className="ghost" type="submit">Go</button>
        </form>
        {entry && <button className="ghost" onClick={() => { setBase(Math.floor(entry.off / PAGE) * PAGE); setMark(entry.off) }}>Entry point</button>}
        {onDisasm && <button className="ghost" onClick={() => onDisasm(mark)}>Disassemble here</button>}
        <span className="muted">0x{base.toString(16)} – 0x{Math.min(size, base + PAGE).toString(16)} of 0x{size.toString(16)}</span>
      </div>
      <div className="hexbox mono" aria-label="Hex dump">{rows}</div>
    </div>
  )
}
