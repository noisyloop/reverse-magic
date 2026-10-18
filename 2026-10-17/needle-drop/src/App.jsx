import React, { useEffect, useMemo, useState } from 'react'
import WorldMap from './WorldMap.jsx'
import {
  ROUNDS,
  MAX_PER_ROUND,
  buildResults,
  completeToday,
  dateKey,
  loadDay,
  loadStreak,
  msUntilTomorrow,
  questionsFor,
  saveDay,
  shareText,
} from './game.js'

function formatKm(km) {
  return `${Math.round(km).toLocaleString()} km`
}

function useCountdown() {
  const [ms, setMs] = useState(msUntilTomorrow())
  useEffect(() => {
    const id = setInterval(() => setMs(msUntilTomorrow()), 1000)
    return () => clearInterval(id)
  }, [])
  const s = Math.floor(ms / 1000)
  const pad = (n) => String(n).padStart(2, '0')
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`
}

export default function App() {
  const key = useMemo(() => dateKey(), [])
  const questions = useMemo(() => questionsFor(key), [key])

  const [guesses, setGuesses] = useState(() => loadDay(key))
  const [pending, setPending] = useState(null)
  const [stage, setStage] = useState('guess') // 'guess' | 'reveal'
  const [streak, setStreak] = useState(() => loadStreak())
  const [copied, setCopied] = useState(false)

  const done = guesses.length >= ROUNDS
  const idx = stage === 'reveal' ? guesses.length - 1 : guesses.length
  const q = questions[Math.min(idx, ROUNDS - 1)]
  const results = useMemo(() => buildResults(questions, guesses), [questions, guesses])
  const total = results.reduce((s, r) => s + r.points, 0)
  const countdown = useCountdown()

  useEffect(() => {
    if (done && stage === 'guess') setStreak(completeToday(key))
  }, [done, stage, key])

  const lockIn = () => {
    if (!pending) return
    const next = [...guesses, pending]
    setGuesses(next)
    saveDay(key, next)
    setPending(null)
    setStage('reveal')
  }

  const next = () => {
    setStage('guess')
  }

  const share = async () => {
    const text = shareText(key, results)
    try {
      if (navigator.share) {
        await navigator.share({ text })
      } else {
        await navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      }
    } catch {
      /* user cancelled */
    }
  }

  const showingResult = stage === 'reveal' ? results[guesses.length - 1] : null
  const lastGuess = stage === 'reveal' ? guesses[guesses.length - 1] : null

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <span className="vinyl" aria-hidden="true" />
          <div>
            <h1>Needle Drop</h1>
            <p>Daily music geography</p>
          </div>
        </div>
        <div className="meta">
          <span className="chip">{key}</span>
          <span className="chip">{'\u{1F525}'} {streak.count}</span>
        </div>
      </header>

      {!done || stage === 'reveal' ? (
        <main className="stage">
          <section className="card question">
            <div className="progress" aria-label={`Round ${Math.min(idx + 1, ROUNDS)} of ${ROUNDS}`}>
              {questions.map((_, i) => (
                <span
                  key={i}
                  className={`seg ${i < guesses.length - (stage === 'reveal' ? 0 : 0) ? 'done' : ''} ${i === idx ? 'now' : ''}`}
                />
              ))}
            </div>
            <p className="round">Round {Math.min(idx + 1, ROUNDS)} / {ROUNDS}</p>
            <h2>{q.prompt}</h2>

            {stage === 'guess' && (
              <div className="actions">
                <button className="primary" disabled={!pending} onClick={lockIn}>
                  {pending ? 'Drop the needle' : 'Tap the map to place your pin'}
                </button>
              </div>
            )}

            {stage === 'reveal' && showingResult && (
              <div className="reveal">
                <div className="score-row">
                  <span className="tier">{showingResult.tier.dot} {showingResult.tier.label}</span>
                  <span className="pts">+{showingResult.points}</span>
                </div>
                <p className="dist">{formatKm(showingResult.km)} away from <strong>{q.place}</strong></p>
                <p className="fact">{q.fact}</p>
                <button className="primary" onClick={next}>
                  {guesses.length >= ROUNDS ? 'See results' : 'Next round'}
                </button>
              </div>
            )}
          </section>

          <WorldMap
            guess={stage === 'reveal' ? lastGuess : pending}
            answer={stage === 'reveal' ? q : null}
            locked={stage === 'reveal'}
            onPick={setPending}
          />
        </main>
      ) : (
        <main className="stage final">
          <section className="card results">
            <p className="round">Today’s set complete</p>
            <h2 className="big">{total.toLocaleString()} <small>/ {(ROUNDS * MAX_PER_ROUND).toLocaleString()}</small></h2>
            <p className="dots" aria-label="Round results">{results.map((r) => r.tier.dot).join(' ')}</p>
            <ul className="breakdown">
              {questions.map((qq, i) => (
                <li key={qq.id}>
                  <span>{results[i].tier.dot} {qq.place}</span>
                  <span>{formatKm(results[i].km)} {'·'} {results[i].points}</span>
                </li>
              ))}
            </ul>
            <div className="actions">
              <button className="primary" onClick={share}>{copied ? 'Copied!' : 'Share result'}</button>
            </div>
            <p className="next">Next set in <strong>{countdown}</strong></p>
          </section>
        </main>
      )}

      <footer className="foot">
        Original game concept inspired by daily map-guessing games. Prototype, not deployed.
      </footer>
    </div>
  )
}
