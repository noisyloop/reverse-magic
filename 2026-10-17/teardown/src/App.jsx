import React, { useCallback, useEffect, useRef, useState } from 'react'
import Overview from './components/Overview.jsx'
import Structure from './components/Structure.jsx'
import Strings from './components/Strings.jsx'
import Indicators from './components/Indicators.jsx'
import EntropyChart from './components/EntropyChart.jsx'
import HexView from './components/HexView.jsx'
import Disassembly from './components/Disassembly.jsx'

const TABS = ['Overview', 'Structure', 'Disassembly', 'Strings', 'Indicators', 'Entropy', 'Hex']

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function App() {
  const [phase, setPhase] = useState('idle') // idle | working | done | error
  const [stage, setStage] = useState('')
  const [result, setResult] = useState(null)
  const [file, setFile] = useState(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState('Overview')
  const [jump, setJump] = useState(0)
  const [disStart, setDisStart] = useState(null)
  const [dragging, setDragging] = useState(false)
  const workerRef = useRef(null)
  const depth = useRef(0)
  const inputRef = useRef(null)

  const analyzeFile = useCallback((f) => {
    if (!f) return
    workerRef.current?.terminate()
    const w = new Worker('./worker.js')
    workerRef.current = w
    setFile(f)
    setPhase('working')
    setStage('Starting')
    setError('')
    setTab('Overview')
    setJump(0)
    setDisStart(null)
    w.onmessage = (e) => {
      const m = e.data
      if (m.type === 'stage') setStage(m.stage)
      else if (m.type === 'done') { setResult(m.result); setPhase('done'); w.terminate() }
      else if (m.type === 'error') { setError(m.message); setPhase('error'); w.terminate() }
    }
    w.onerror = (e) => { setError(e.message || 'The analysis worker crashed.'); setPhase('error') }
    w.postMessage({ file: f })
  }, [])

  // Window-level drag and drop so the whole page is a drop target.
  useEffect(() => {
    const prevent = (e) => e.preventDefault()
    const enter = (e) => { e.preventDefault(); depth.current++; setDragging(true) }
    const leave = () => { depth.current = Math.max(0, depth.current - 1); if (!depth.current) setDragging(false) }
    const drop = (e) => {
      e.preventDefault()
      depth.current = 0
      setDragging(false)
      const f = e.dataTransfer?.files?.[0]
      if (f) analyzeFile(f)
    }
    window.addEventListener('dragover', prevent)
    window.addEventListener('dragenter', enter)
    window.addEventListener('dragleave', leave)
    window.addEventListener('drop', drop)
    return () => {
      window.removeEventListener('dragover', prevent)
      window.removeEventListener('dragenter', enter)
      window.removeEventListener('dragleave', leave)
      window.removeEventListener('drop', drop)
    }
  }, [analyzeFile])

  const goHex = (off) => { setJump(Math.max(0, off | 0)); setTab('Hex') }
  const goDis = (off) => { setDisStart(Math.max(0, off | 0)); setTab('Disassembly') }
  const reset = () => { workerRef.current?.terminate(); setPhase('idle'); setResult(null); setFile(null) }

  return (
    <div className="shell">
      <header className="bar">
        <div className="logo" onClick={reset} role="button" tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && reset()}>
          <span className="mark" aria-hidden="true">{'◧'}</span>
          <span className="word">Teardown</span>
        </div>
        <div className="privacy" title="Parsing runs in a Web Worker with its network APIs removed. Production hosting should also send the CSP header in public/_headers.">
          <span className="dot" /> Local only · never executed
        </div>
        {phase === 'done' && (
          <div className="bar-actions">
            <button className="ghost" onClick={() => inputRef.current?.click()}>Open another</button>
            <button className="ghost" onClick={() => download(`${result.meta.name}.teardown.json`, JSON.stringify(result, null, 2))}>Export JSON</button>
          </div>
        )}
      </header>

      <input ref={inputRef} type="file" hidden onChange={(e) => { analyzeFile(e.target.files?.[0]); e.target.value = '' }} />

      {phase === 'idle' && (
        <main className="hero">
          <h1>Drop a file.<br />See what is inside.</h1>
          <p className="lede">Static reverse-engineering triage for executables, archives, documents and anything else. Headers, imports, strings, entropy, indicators, a hex view and disassembly. Nothing is uploaded and nothing is run.</p>
          <div
            className="dropzone"
            role="button"
            tabIndex={0}
            onClick={() => inputRef.current?.click()}
            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && inputRef.current?.click()}
          >
            <div className="dz-icon" aria-hidden="true">{'↓'}</div>
            <strong>Drag and drop any file here</strong>
            <span>or click to choose one · up to 256 MB</span>
          </div>
          <ul className="chips">
            {['PE / EXE / DLL', 'ELF', 'Mach-O', 'ZIP / APK / DOCX', 'PDF', 'PNG / JPEG', 'WASM', 'anything else'].map((c) => <li key={c}>{c}</li>)}
          </ul>
        </main>
      )}

      {phase === 'working' && (
        <main className="hero working">
          <div className="spinner" aria-hidden="true" />
          <h2>{file?.name}</h2>
          <p className="lede" role="status">{stage}…</p>
        </main>
      )}

      {phase === 'error' && (
        <main className="hero">
          <h2>Could not analyze that file</h2>
          <p className="lede err">{error}</p>
          <button className="primary" onClick={reset}>Try another file</button>
        </main>
      )}

      {phase === 'done' && result && (
        <main className="report">
          <div className="titleline">
            <h2 title={result.meta.name}>{result.meta.name}</h2>
            <span className="pill">{result.type.label}{result.type.confident ? '' : ' (guess)'}</span>
            <span className="muted">{result.meta.size.toLocaleString()} bytes · analyzed in {result.meta.analyzedMs} ms</span>
          </div>
          <nav className="tabs" role="tablist">
            {TABS.map((t) => (
              <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'on' : ''} onClick={() => setTab(t)}>{t}
                {t === 'Strings' && <i>{result.strings.length.toLocaleString()}</i>}
                {t === 'Indicators' && <i>{Object.values(result.iocs || {}).reduce((s, a) => s + a.length, 0)}</i>}
              </button>
            ))}
          </nav>
          <section className="panel" role="tabpanel">
            {tab === 'Overview' && <Overview r={result} onHex={goHex} />}
            {tab === 'Structure' && <Structure r={result} onHex={goHex} onDisasm={result.disasm?.targets?.length ? goDis : null} />}
            {tab === 'Disassembly' && <Disassembly r={result} file={file} start={disStart} onHex={goHex} />}
            {tab === 'Strings' && <Strings r={result} onHex={goHex} />}
            {tab === 'Indicators' && <Indicators r={result} onHex={goHex} />}
            {tab === 'Entropy' && <EntropyChart r={result} onHex={goHex} />}
            {tab === 'Hex' && <HexView file={file} size={result.meta.size} offset={jump} entry={result.parsed?.entry} onDisasm={result.disasm?.targets?.length ? goDis : null} />}
          </section>
        </main>
      )}

      <footer className="foot">
        Static analysis only. Findings are heuristics and leads, not verdicts, and this is not antivirus. Only examine files you are authorized to examine.
      </footer>

      {dragging && <div className="overlay"><div>Drop to analyze</div></div>}
    </div>
  )
}
