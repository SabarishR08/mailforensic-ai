import { useEffect, useMemo, useRef, useState } from 'react'
import L from 'leaflet'
import { socket } from '../lib/socket'
import { riskColor } from '../lib/format'

type ConnState = 'disconnected' | 'connected' | 'scanning'

type CardData = {
  email_id: string
  snippet: string
  ml: any
  geo: any
  forensic: any
  risk_assessment: any
  urls_checked: number
}

type Stats = { scanned: number; phishing: number; legit: number; high: number; riskSum: number }

export default function DemoPage() {
  const [conn, setConn] = useState<ConnState>('disconnected')
  const [count, setCount] = useState(5)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState({ label: 'Ready', pct: 0, counter: '' })
  const [cards, setCards] = useState<CardData[]>([])
  const [stats, setStats] = useState<Stats>({ scanned: 0, phishing: 0, legit: 0, high: 0, riskSum: 0 })
  const [toasts, setToasts] = useState<{ id: number; msg: string; kind: string }[]>([])
  const mapRef = useRef<L.Map | null>(null)
  const markersRef = useRef<L.CircleMarker[]>([])
  const toastId = useRef(0)

  // ---------- Map ----------
  useEffect(() => {
    const el = document.getElementById('demo-map')
    if (!el || mapRef.current) return
    const map = L.map(el, { zoomControl: false, attributionControl: false, preferCanvas: true }).setView([20, 0], 2)
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
      maxZoom: 16,
      attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
    }).addTo(map)
    mapRef.current = map
    return () => {
      map.remove()
      mapRef.current = null
      markersRef.current = []
    }
  }, [])

  const showToast = useMemo(
    () => (msg: string, kind: 'info' | 'success' | 'danger' = 'info') => {
      const id = ++toastId.current
      setToasts((t) => [...t, { id, msg, kind }])
      setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000)
    },
    [],
  )

  // ---------- Socket lifecycle ----------
  useEffect(() => {
    socket.connect()
    socket.on('connect', () => {
      setConn('connected')
      socket.emit('join_demo')
    })
    socket.on('disconnect', () => setConn('disconnected'))
    socket.on('connected', (data: any) => showToast(data.message, 'info'))

    socket.on('scan_started', (data: any) => {
      setScanning(true)
      setConn('scanning')
      setProgress({ label: data.message, pct: 0, counter: '' })
      showToast(data.message, 'info')
    })

    socket.on('scan_progress', (data: any) => {
      const pct = Math.round((data.current / data.total) * 100)
      setProgress({ label: data.message, pct, counter: `${data.current} / ${data.total}` })
    })

    socket.on('scan_result', (data: any) => {
      const risk = data.risk_assessment || {}
      const ml = data.ml || {}
      const geo = data.geo || {}
      const auth = (data.forensic || {}).authentication || {}
      const riskLevel = String(risk.risk_level || 'Unknown').toLowerCase()
      const prediction = ml.prediction || 'unknown'

      setStats((s) => {
        const next = { ...s, scanned: s.scanned + 1, riskSum: s.riskSum + (risk.risk_score || 0) }
        if (prediction === 'phishing') next.phishing += 1
        else if (prediction === 'legitimate') next.legit += 1
        if (riskLevel === 'high' || riskLevel === 'critical') next.high += 1
        return next
      })

      const card: CardData = {
        email_id: data.email_id || '',
        snippet: data.snippet || '',
        ml,
        geo,
        forensic: data.forensic || {},
        risk_assessment: risk,
        urls_checked: data.urls_checked || 0,
      }
      setCards((c) => [card, ...c].slice(0, 60))

      // Map marker
      const map = mapRef.current
      if (map && geo.latitude && geo.longitude) {
        const color =
          riskLevel === 'critical' ? '#ef4444' : riskLevel === 'high' ? '#ffa726' : '#ffee58'
        const marker = L.circleMarker([geo.latitude, geo.longitude], {
          radius: 8,
          color,
          fillColor: color,
          fillOpacity: 0.8,
        })
          .bindPopup(
            `<b>${geo.city || ''}, ${geo.country || ''}</b><br>Risk: ${
              risk.risk_level || '?'
            } (${risk.risk_score || 0})<br>Prediction: ${prediction}`,
          )
          .addTo(map)
        markersRef.current.push(marker)
        if (markersRef.current.length > 1) {
          map.fitBounds(L.featureGroup(markersRef.current).getBounds().pad(0.2))
        } else {
          map.setView([geo.latitude, geo.longitude], 5)
        }
      }
      showToast(data.message, prediction === 'phishing' ? 'danger' : 'success')
    })

    socket.on('scan_error', (data: any) => {
      showToast(data.message || 'Scan error', 'danger')
    })

    socket.on('scan_complete', (data: any) => {
      setScanning(false)
      setConn('connected')
      setProgress({ label: 'Scan complete!', pct: 100, counter: '' })
      showToast(data.message, 'info')
      if (data.phishing_detected > 0)
        showToast(`${data.phishing_detected} PHISHING emails detected!`, 'danger')
    })

    return () => {
      socket.off('connect')
      socket.off('disconnect')
      socket.off('connected')
      socket.off('scan_started')
      socket.off('scan_progress')
      socket.off('scan_result')
      socket.off('scan_error')
      socket.off('scan_complete')
      socket.disconnect()
    }
  }, [showToast])

  const startScan = () => {
    socket.emit('start_demo_scan', { limit: count })
  }

  const resetDemo = () => {
    setStats({ scanned: 0, phishing: 0, legit: 0, high: 0, riskSum: 0 })
    setCards([])
    setProgress({ label: 'Ready', pct: 0, counter: '' })
    setScanning(false)
    const map = mapRef.current
    if (map) {
      markersRef.current.forEach((m) => map.removeLayer(m))
      markersRef.current = []
      map.setView([20, 0], 2)
    }
  }

  const avgRisk =
    stats.scanned > 0 ? String(Math.round(stats.riskSum / stats.scanned)) : '—'

  const pillClass =
    conn === 'connected' ? 'status-connected' : conn === 'scanning' ? 'status-scanning' : 'status-disconnected'
  const pillText =
    conn === 'connected' ? 'Connected' : conn === 'scanning' ? 'Scanning...' : 'Disconnected'

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h4 className="mb-0">
          <i className="fas fa-bolt"></i> Live Demo
        </h4>
        <span className={'status-pill ' + pillClass}>
          <i className="fas fa-circle" style={{ fontSize: '0.5rem', verticalAlign: 'middle' }}></i>{' '}
          {pillText}
        </span>
      </div>

      <div className="demo-body">
        {/* Left: scan area */}
        <div className="scan-area">
          <div className="control-bar">
            <label style={{ fontSize: '0.85rem', color: '#8892a4' }}>Emails:</label>
            <input
              type="number"
              value={count}
              min={1}
              max={20}
              onChange={(e) => setCount(Number(e.target.value) || 5)}
            />
            <button className="btn-scan" onClick={startScan} disabled={scanning}>
              <i className="fas fa-bolt"></i> Start Live Scan
            </button>
            <button className="btn-reset" onClick={resetDemo}>
              Reset
            </button>
            <div style={{ flex: 1 }} />
            <span style={{ fontSize: '0.85rem', color: '#64748b' }}>{progress.counter}</span>
          </div>

          <div className="progress-section">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.85rem', color: '#8892a4' }}>{progress.label}</span>
              <span style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                {progress.pct}%
              </span>
            </div>
            <div className="progress-bar-wrapper">
              <div className="progress-bar-fill" style={{ width: progress.pct + '%' }} />
            </div>
          </div>

          <div className="cards-grid">
            {cards.map((c, i) => {
              const risk = c.risk_assessment || {}
              const riskLevel = String(risk.risk_level || 'unknown').toLowerCase()
              const prediction = c.ml.prediction || 'unknown'
              const auth = c.forensic.authentication || {}
              return (
                <div key={c.email_id + i} className={'scan-card ' + prediction}>
                  <div className="card-header-row">
                    <span className="card-email-id">
                      <i className="fas fa-envelope"></i> {c.email_id}
                    </span>
                    <span className={'card-prediction ' + prediction}>
                      {String(prediction).toUpperCase()}
                    </span>
                  </div>
                  <div className="card-snippet">{c.snippet}</div>
                  <div className="card-metrics">
                    <div className="metric">
                      <div className="metric-value" style={{ color: riskColor(riskLevel) }}>
                        {risk.risk_score || 0}
                      </div>
                      <div className="metric-label">Risk</div>
                    </div>
                    <div className="metric">
                      <div className="metric-value">
                        {((c.ml.confidence || 0) * 100).toFixed(0)}%
                      </div>
                      <div className="metric-label">Confidence</div>
                    </div>
                    <div className="metric">
                      <div className="metric-value">{c.urls_checked || 0}</div>
                      <div className="metric-label">URLs</div>
                    </div>
                  </div>
                  <div className="card-auth">
                    <span className={'risk-badge ' + riskClass2(riskLevel)}>{risk.risk_level}</span>
                    {c.geo.country_code && (
                      <span className="auth-badge auth-missing">
                        <i className="fas fa-map-pin"></i> {c.geo.country_code}
                      </span>
                    )}
                    {auth.spf && (
                      <span className={'auth-badge ' + (auth.spf === 'PASS' ? 'auth-pass' : 'auth-fail')}>
                        SPF {auth.spf}
                      </span>
                    )}
                    {auth.dkim && (
                      <span className={'auth-badge ' + (auth.dkim === 'PASS' ? 'auth-pass' : 'auth-fail')}>
                        DKIM {auth.dkim}
                      </span>
                    )}
                    {auth.dmarc && (
                      <span className={'auth-badge ' + (auth.dmarc === 'PASS' ? 'auth-pass' : 'auth-fail')}>
                        DMARC {auth.dmarc}
                      </span>
                    )}
                  </div>
                </div>
              )
            })}
            {cards.length === 0 && (
              <div className="text-muted" style={{ padding: 40, textAlign: 'center', gridColumn: '1 / -1' }}>
                Results appear here as emails are scanned live…
              </div>
            )}
          </div>
        </div>

        {/* Right: stats + map */}
        <div className="side-panel">
          <div className="stats-card">
            <h6
              style={{
                color: '#8892a4',
                marginBottom: 12,
                textTransform: 'uppercase',
                fontSize: '0.75rem',
                letterSpacing: 1,
              }}
            >
              Live Statistics
            </h6>
            <div className="stat-row">
              <span className="stat-label">Scanned</span>
              <span className="stat-value">{stats.scanned}</span>
            </div>
            <div className="stat-row">
              <span className="stat-label">Phishing</span>
              <span className="stat-value" style={{ color: '#ef5350' }}>
                {stats.phishing}
              </span>
            </div>
            <div className="stat-row">
              <span className="stat-label">Legitimate</span>
              <span className="stat-value" style={{ color: '#66bb6a' }}>
                {stats.legit}
              </span>
            </div>
            <div className="stat-row">
              <span className="stat-label">Avg Risk Score</span>
              <span className="stat-value">{avgRisk}</span>
            </div>
            <div className="stat-row">
              <span className="stat-label">High/Critical</span>
              <span className="stat-value" style={{ color: '#ffa726' }}>
                {stats.high}
              </span>
            </div>
          </div>

          <div className="stats-card map-container">
            <h6
              style={{
                color: '#8892a4',
                marginBottom: 8,
                textTransform: 'uppercase',
                fontSize: '0.75rem',
                letterSpacing: 1,
              }}
            >
              Threat Origins
            </h6>
            <div id="demo-map" style={{ height: 'calc(100% - 30px)', borderRadius: 8 }} />
          </div>
        </div>
      </div>

      <div className="toast-area">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="toast-msg"
            style={{
              borderLeftColor:
                t.kind === 'danger' ? '#ef4444' : t.kind === 'success' ? '#22c55e' : 'var(--accent-cyan)',
            }}
          >
            {t.msg}
          </div>
        ))}
      </div>
    </div>
  )
}

function riskClass2(level: string): string {
  return 'risk-' + level
}
