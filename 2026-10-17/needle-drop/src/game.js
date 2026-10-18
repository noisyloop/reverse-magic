import { QUESTIONS } from './questions.js'

export const ROUNDS = 5
export const MAX_PER_ROUND = 1000

const toRad = (d) => (d * Math.PI) / 180

export function haversineKm(a, b) {
  const R = 6371
  const dLat = toRad(b.lat - a.lat)
  const dLng = toRad(b.lng - a.lng)
  const s =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLng / 2) ** 2
  return 2 * R * Math.asin(Math.sqrt(s))
}

export function scoreFor(km) {
  if (km < 100) return MAX_PER_ROUND
  return Math.round(MAX_PER_ROUND * Math.exp(-km / 1800))
}

export function tierFor(km) {
  if (km < 300) return { dot: '\u{1F7E2}', label: 'Spot on' }
  if (km < 1000) return { dot: '\u{1F7E1}', label: 'Close' }
  if (km < 2500) return { dot: '\u{1F7E0}', label: 'Far-ish' }
  return { dot: '\u{1F534}', label: 'Way off' }
}

// Local calendar date, YYYY-MM-DD.
export function dateKey(d = new Date()) {
  const y = d.getFullYear()
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
}

export function yesterdayKey(d = new Date()) {
  const y = new Date(d)
  y.setDate(y.getDate() - 1)
  return dateKey(y)
}

function hashString(str) {
  let h = 1779033703 ^ str.length
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353)
    h = (h << 13) | (h >>> 19)
  }
  return () => {
    h = Math.imul(h ^ (h >>> 16), 2246822507)
    h = Math.imul(h ^ (h >>> 13), 3266489909)
    return (h ^= h >>> 16) >>> 0
  }
}

function mulberry32(seed) {
  return () => {
    seed |= 0
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// Same date => same five questions for everyone, no server required.
export function questionsFor(key) {
  const rand = mulberry32(hashString(`needle-drop:${key}`)())
  const pool = QUESTIONS.map((_, i) => i)
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1))
    ;[pool[i], pool[j]] = [pool[j], pool[i]]
  }
  return pool.slice(0, ROUNDS).map((i) => QUESTIONS[i])
}

export function buildResults(questions, guesses) {
  return guesses.map((g, i) => {
    const km = haversineKm(g, questions[i])
    return { km, points: scoreFor(km), tier: tierFor(km) }
  })
}

export function shareText(key, results) {
  const total = results.reduce((s, r) => s + r.points, 0)
  const dots = results.map((r) => r.tier.dot).join('')
  return `Needle Drop ${key}\n${dots}  ${total}/${ROUNDS * MAX_PER_ROUND}\nDrop the needle where it happened.`
}

const STORE = 'needledrop:v1'

export function loadDay(key) {
  try {
    const raw = JSON.parse(localStorage.getItem(`${STORE}:day:${key}`) || 'null')
    return raw && Array.isArray(raw.guesses) ? raw.guesses : []
  } catch {
    return []
  }
}

export function saveDay(key, guesses) {
  try {
    localStorage.setItem(`${STORE}:day:${key}`, JSON.stringify({ guesses }))
  } catch {
    /* storage can be unavailable; the game still works */
  }
}

export function loadStreak() {
  try {
    return JSON.parse(localStorage.getItem(`${STORE}:streak`) || 'null') || { last: null, count: 0 }
  } catch {
    return { last: null, count: 0 }
  }
}

export function completeToday(key) {
  const s = loadStreak()
  if (s.last === key) return s
  const next = { last: key, count: s.last === yesterdayKey(new Date(`${key}T12:00:00`)) ? s.count + 1 : 1 }
  try {
    localStorage.setItem(`${STORE}:streak`, JSON.stringify(next))
  } catch {
    /* ignore */
  }
  return next
}

export function msUntilTomorrow(now = new Date()) {
  const t = new Date(now)
  t.setHours(24, 0, 0, 0)
  return t - now
}
