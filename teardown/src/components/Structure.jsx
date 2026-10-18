import React, { useState } from 'react'

const h = (n) => '0x' + Number(n).toString(16)

function Bar({ v }) {
  const pct = Math.min(100, (v / 8) * 100)
  const cls = v > 7.2 ? 'hot' : v > 6.5 ? 'warm' : ''
  return (
    <span className="ebar" title={`${v.toFixed(2)} bits/byte`}>
      <span className={`fill ${cls}`} style={{ width: `${pct}%` }} />
      <em>{v.toFixed(2)}</em>
    </span>
  )
}

function Table({ cols, rows, onRow }) {
  return (
    <div className="tablewrap">
      <table>
        <thead><tr>{cols.map((c) => <th key={c.k} className={c.cls}>{c.t}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} onClick={onRow ? () => onRow(row) : undefined} className={onRow ? 'click' : ''}>
              {cols.map((c) => <td key={c.k} className={c.cls}>{c.f ? c.f(row) : row[c.k]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Imports({ imports }) {
  const [open, setOpen] = useState(() => new Set())
  const toggle = (i) => setOpen((s) => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n })
  return (
    <ul className="imports">
      {imports.map((d, i) => (
        <li key={i}>
          <button className="dll" onClick={() => toggle(i)} aria-expanded={open.has(i)}>
            <span>{open.has(i) ? '▾' : '▸'}</span> {d.dll} <i>{d.funcs.length}</i>
          </button>
          {open.has(i) && <div className="funcs mono">{d.funcs.join('  ')}</div>}
        </li>
      ))}
    </ul>
  )
}

function Section({ title, count, children }) {
  return (
    <section className="block">
      <h3>{title}{count != null && <i>{count}</i>}</h3>
      {children}
    </section>
  )
}

export default function Structure({ r, onHex, onDisasm }) {
  const p = r.parsed
  if (!p) return <p className="muted">No structural parser applies to this file type. Use Strings, Entropy and Hex.</p>
  const entry = p.entry

  return (
    <div className="structure">
      {entry && (
        <Section title="Entry point">
          <p>RVA / address <span className="mono">{h(entry.rva)}</span> maps to file offset <span className="mono">{h(entry.off)}</span>{' '}
            <button className="mini" onClick={() => onHex(entry.off)}>view bytes</button>{onDisasm && <> <button className="mini" onClick={() => onDisasm(entry.off)}>disassemble</button></>}</p>
          <p className="muted small">Raw bytes only. This build does not disassemble.</p>
        </Section>
      )}

      {p.kind === 'pe' && (
        <>
          <Section title="Sections" count={p.sections.length}>
            <Table
              cols={[
                { k: 'name', t: 'Name', cls: 'mono' },
                { k: 'vaddr', t: 'Virtual addr', cls: 'mono', f: (s) => h(s.vaddr) },
                { k: 'vsize', t: 'Virtual size', cls: 'mono num', f: (s) => s.vsize.toLocaleString() },
                { k: 'rawPtr', t: 'Raw offset', cls: 'mono', f: (s) => h(s.rawPtr) },
                { k: 'rawSize', t: 'Raw size', cls: 'mono num', f: (s) => s.rawSize.toLocaleString() },
                { k: 'flags', t: 'XRW', cls: 'mono' },
                { k: 'entropy', t: 'Entropy', f: (s) => <Bar v={s.entropy} /> },
              ]}
              rows={p.sections}
              onRow={(s) => onHex(s.rawPtr)}
            />
          </Section>
          <Section title="Imports" count={p.imports.reduce((n, d) => n + d.funcs.length, 0)}>
            {p.imports.length ? <Imports imports={p.imports} /> : <p className="muted">None found.</p>}
          </Section>
          {p.exports.length > 0 && (
            <Section title="Exports" count={p.exports.length}>
              <div className="funcs mono">{p.exports.slice(0, 400).join('  ')}</div>
            </Section>
          )}
          <Section title="Data directories" count={p.dirs.length}>
            <Table cols={[{ k: 'name', t: 'Directory' }, { k: 'rva', t: 'RVA', cls: 'mono', f: (d) => h(d.rva) }, { k: 'size', t: 'Size', cls: 'mono num', f: (d) => d.size.toLocaleString() }]} rows={p.dirs} />
          </Section>
        </>
      )}

      {p.kind === 'elf' && (
        <>
          <Section title="Segments" count={p.segments.length}>
            <Table
              cols={[
                { k: 'type', t: 'Type', cls: 'mono' },
                { k: 'flags', t: 'RWX', cls: 'mono' },
                { k: 'offset', t: 'File offset', cls: 'mono', f: (s) => h(s.offset) },
                { k: 'vaddr', t: 'Virtual addr', cls: 'mono', f: (s) => h(s.vaddr) },
                { k: 'filesz', t: 'File size', cls: 'mono num', f: (s) => s.filesz.toLocaleString() },
                { k: 'memsz', t: 'Mem size', cls: 'mono num', f: (s) => s.memsz.toLocaleString() },
              ]}
              rows={p.segments}
              onRow={(s) => onHex(s.offset)}
            />
          </Section>
          <Section title="Sections" count={p.sections.length}>
            <Table
              cols={[
                { k: 'name', t: 'Name', cls: 'mono' },
                { k: 'type', t: 'Type', cls: 'mono' },
                { k: 'addr', t: 'Address', cls: 'mono', f: (s) => h(s.addr) },
                { k: 'offset', t: 'Offset', cls: 'mono', f: (s) => h(s.offset) },
                { k: 'size', t: 'Size', cls: 'mono num', f: (s) => s.size.toLocaleString() },
                { k: 'flags', t: 'XAW', cls: 'mono' },
                { k: 'entropy', t: 'Entropy', f: (s) => (s.entropy ? <Bar v={s.entropy} /> : '–') },
              ]}
              rows={p.sections}
              onRow={(s) => onHex(s.offset)}
            />
          </Section>
          <Section title="Needed libraries" count={p.needed.length}>
            <div className="funcs mono">{p.needed.join('  ') || 'none'}</div>
          </Section>
          <Section title="Imported symbols" count={p.imports.length}>
            <div className="funcs mono">{p.imports.slice(0, 600).join('  ') || 'none'}</div>
          </Section>
        </>
      )}

      {p.kind === 'macho' && <MachO p={p} onHex={onHex} />}
      {p.kind === 'macho-fat' && p.slices.map((s, i) => (
        <Section key={i} title={`Slice: ${s.arch}`}>
          {s.error ? <p className="muted">{s.error}</p> : <MachO p={s} onHex={onHex} />}
        </Section>
      ))}

      {p.kind === 'zip' && (
        <Section title="Entries" count={p.info.entries}>
          <Table
            cols={[
              { k: 'name', t: 'Path', cls: 'mono wrap' },
              { k: 'method', t: 'Method' },
              { k: 'csize', t: 'Packed', cls: 'mono num', f: (e) => e.csize.toLocaleString() },
              { k: 'usize', t: 'Unpacked', cls: 'mono num', f: (e) => e.usize.toLocaleString() },
              { k: 'crc', t: 'CRC32', cls: 'mono' },
            ]}
            rows={p.entries.slice(0, 500)}
            onRow={(e) => onHex(e.localOff)}
          />
          {p.entries.length > 500 && <p className="muted small">Showing the first 500 of {p.entries.length.toLocaleString()}.</p>}
        </Section>
      )}

      {p.kind === 'pdf' && (
        <>
          <Section title="Keyword counts">
            <Table cols={[{ k: 'k', t: 'Marker', cls: 'mono' }, { k: 'v', t: 'Count', cls: 'num mono' }]} rows={Object.entries(p.keywords).map(([k, v]) => ({ k, v }))} />
          </Section>
          {p.uris.length > 0 && <Section title="URIs" count={p.uris.length}><div className="funcs mono">{p.uris.join('\n')}</div></Section>}
        </>
      )}

      {p.kind === 'wasm' && (
        <Section title="Sections" count={p.sections.length}>
          <Table cols={[{ k: 'name', t: 'Section', cls: 'mono' }, { k: 'offset', t: 'Offset', cls: 'mono', f: (s) => h(s.offset) }, { k: 'size', t: 'Size', cls: 'mono num', f: (s) => s.size.toLocaleString() }]} rows={p.sections} onRow={(s) => onHex(s.offset)} />
        </Section>
      )}

      {r.embedded?.length > 0 && (
        <Section title="Embedded signatures" count={r.embedded.length}>
          <Table cols={[{ k: 'off', t: 'Offset', cls: 'mono', f: (e) => h(e.off) }, { k: 'name', t: 'Looks like' }]} rows={r.embedded.slice(0, 200)} onRow={(e) => onHex(e.off)} />
        </Section>
      )}
    </div>
  )
}

function MachO({ p, onHex }) {
  return (
    <>
      <Section title="Segments" count={p.segments.length}>
        <Table
          cols={[
            { k: 'name', t: 'Segment', cls: 'mono' },
            { k: 'vmaddr', t: 'VM addr', cls: 'mono', f: (s) => h(s.vmaddr) },
            { k: 'vmsize', t: 'VM size', cls: 'mono num', f: (s) => s.vmsize.toLocaleString() },
            { k: 'fileoff', t: 'File offset', cls: 'mono', f: (s) => h(s.fileoff) },
            { k: 'sections', t: 'Sections', cls: 'mono wrap', f: (s) => s.sections.map((x) => x.name).join(' ') },
          ]}
          rows={p.segments}
          onRow={(s) => onHex(s.fileoff)}
        />
      </Section>
      <Section title="Linked libraries" count={p.dylibs.length}>
        <div className="funcs mono">{p.dylibs.map((d) => d.name).join('\n') || 'none'}</div>
      </Section>
      <Section title="Load commands"><div className="funcs mono">{p.cmds.join('  ')}</div></Section>
    </>
  )
}
