import React, { useMemo, useRef, useState } from 'react'
import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'

const W = 960
const H = 500
const MIN_K = 1
const MAX_K = 8

// The map is drawn from bundled country shapes, so it needs no tile server,
// API key or network access.
const projection = geoNaturalEarth1().fitSize([W, H], { type: 'Sphere' })
const path = geoPath(projection)
const land = feature(world, world.objects.countries)
const spherePath = path({ type: 'Sphere' })
const gratPath = path(geoGraticule10())
const landPath = path(land)

function clampView(v) {
  const k = Math.min(MAX_K, Math.max(MIN_K, v.k))
  const minX = W - W * k
  const minY = H - H * k
  return {
    k,
    tx: Math.min(0, Math.max(minX, v.tx)),
    ty: Math.min(0, Math.max(minY, v.ty)),
  }
}

export default function WorldMap({ guess, answer, locked, onPick }) {
  const svgRef = useRef(null)
  const drag = useRef(null)
  const [view, setView] = useState({ k: 1, tx: 0, ty: 0 })

  const guessXY = useMemo(() => (guess ? projection([guess.lng, guess.lat]) : null), [guess])
  const answerXY = useMemo(() => (answer ? projection([answer.lng, answer.lat]) : null), [answer])

  const toSvg = (clientX, clientY) => {
    const svg = svgRef.current
    const pt = svg.createSVGPoint()
    pt.x = clientX
    pt.y = clientY
    return pt.matrixTransform(svg.getScreenCTM().inverse())
  }

  const zoomAt = (factor, cx = W / 2, cy = H / 2) => {
    setView((v) => {
      const k = Math.min(MAX_K, Math.max(MIN_K, v.k * factor))
      const f = k / v.k
      return clampView({ k, tx: cx - (cx - v.tx) * f, ty: cy - (cy - v.ty) * f })
    })
  }

  const onWheel = (e) => {
    const p = toSvg(e.clientX, e.clientY)
    zoomAt(e.deltaY < 0 ? 1.25 : 0.8, p.x, p.y)
  }

  const onPointerDown = (e) => {
    e.currentTarget.setPointerCapture(e.pointerId)
    drag.current = { x: e.clientX, y: e.clientY, moved: false, view }
  }

  const onPointerMove = (e) => {
    const d = drag.current
    if (!d) return
    const dx = e.clientX - d.x
    const dy = e.clientY - d.y
    if (!d.moved && Math.hypot(dx, dy) < 6) return
    d.moved = true
    const rect = svgRef.current.getBoundingClientRect()
    const scale = W / rect.width
    setView(clampView({ k: d.view.k, tx: d.view.tx + dx * scale, ty: d.view.ty + dy * scale }))
  }

  const onPointerUp = (e) => {
    const d = drag.current
    drag.current = null
    if (!d || d.moved || locked) return
    const p = toSvg(e.clientX, e.clientY)
    const x = (p.x - view.tx) / view.k
    const y = (p.y - view.ty) / view.k
    const lngLat = projection.invert([x, y])
    if (!lngLat || Number.isNaN(lngLat[0])) return
    onPick({ lng: lngLat[0], lat: lngLat[1] })
  }

  const r = (n) => n / view.k

  return (
    <div className="map-wrap">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className={`map ${locked ? 'locked' : ''}`}
        role="img"
        aria-label="World map. Tap or click to drop your pin."
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={() => (drag.current = null)}
      >
        <g transform={`translate(${view.tx} ${view.ty}) scale(${view.k})`}>
          <path d={spherePath} className="sphere" />
          <path d={gratPath} className="graticule" strokeWidth={r(0.6)} />
          <path d={landPath} className="land" strokeWidth={r(0.5)} />

          {guessXY && answerXY && (
            <line
              x1={guessXY[0]}
              y1={guessXY[1]}
              x2={answerXY[0]}
              y2={answerXY[1]}
              className="link"
              strokeWidth={r(2)}
              strokeDasharray={`${r(6)} ${r(5)}`}
            />
          )}

          {answerXY && (
            <g transform={`translate(${answerXY[0]} ${answerXY[1]})`}>
              <circle r={r(16)} className="pulse" />
              <circle r={r(7)} className="pin-answer" strokeWidth={r(2.5)} />
            </g>
          )}

          {guessXY && (
            <g transform={`translate(${guessXY[0]} ${guessXY[1]})`}>
              <circle r={r(8)} className="pin-guess" strokeWidth={r(2.5)} />
              <circle r={r(2.5)} className="pin-guess-dot" />
            </g>
          )}
        </g>
      </svg>

      <div className="zoom">
        <button type="button" aria-label="Zoom in" onClick={() => zoomAt(1.5)}>+</button>
        <button type="button" aria-label="Zoom out" onClick={() => zoomAt(1 / 1.5)}>{'−'}</button>
        <button type="button" aria-label="Reset view" onClick={() => setView({ k: 1, tx: 0, ty: 0 })}>{'↺'}</button>
      </div>
    </div>
  )
}
