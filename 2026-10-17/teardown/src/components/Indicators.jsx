import React, { useState } from 'react'
import { defang } from '../core/scan.js'

const LABEL = {
  url: 'URLs', domain: 'Domains', ipv4: 'IPv4 addresses', email: 'Email addresses',
  winpath: 'Windows paths', registry: 'Registry keys', unixpath: 'Unix paths',
}
const DEFANGED = new Set(['url', 'domain', 'ipv4', 'email'])

export default function Indicators({ r, onHex }) {
  const [raw, setRaw] = useState(false)
  const iocs = r.iocs || {}
  const kinds = Object.keys(LABEL).filter((k) => iocs[k]?.length)
  const show = (k, v) => (!raw && DEFANGED.has(k) ? (k === 'email' ? v.replace('@', '[at]').replace(/\./g, '[.]') : defang(v)) : v)

  return (
    <div className="indicators">
      <div className="controls">
        <label className="check"><input type="checkbox" checked={raw} onChange={(e) => setRaw(e.target.checked)} /> show raw (clickable-looking) values</label>
        <span className="muted">Pulled from extracted strings. Defanged by default so they are safe to copy into reports.</span>
      </div>
      {kinds.length === 0 && <p className="muted">No indicators found in the extracted strings.</p>}
      {kinds.map((k) => (
        <section className="block" key={k}>
          <h3>{LABEL[k]}<i>{iocs[k].length}</i></h3>
          <div className="tablewrap">
            <table>
              <tbody>
                {iocs[k].map((x) => (
                  <tr key={x.value} className="click" onClick={() => onHex(x.off)}>
                    <td className="mono wrap">{show(k, x.value)}</td>
                    <td className="mono num muted">{x.count > 1 ? `×${x.count}` : ''}</td>
                    <td className="mono muted">0x{x.off.toString(16)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  )
}
