import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import L from 'leaflet'
import { api, ScanRow } from '../lib/api'
import { fmtClock, predBadgeBg, riskBadgeBg, riskClass } from '../lib/format'

type Stats = { total_scans: number; phishing_detected: number; total_threats: number }

const GEO_COLOR: Record<string, string> = {
  Critical: '#d32f2f',
  High: '#f57c00',
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [scans, setScans] = useState<ScanRow[]>([])
  const [mlOnline, setMlOnline] = useState<boolean | null>(null)
  const [geoPoints, setGeoPoints] = useState<any[]>([])
  const [error, setError] = useState('')
  const mapRef = useRef<L.Map | null>(null)
  const markersRef = useRef<L.CircleMarker[]>([])

  // Load stats + scans + health once
  useEffect(() => {
    api
      .stats()
      .then(setStats)
      .catch((e) => setError(String(e.message || e)))
    api
      .recentScans(20)
      .then((d) => setScans(d.scans || []))
      .catch(() => setScans([]))
    api.health().then(
      () => setMlOnline(true),
      () => setMlOnline(false),
    )
    api
      .geoThreats()
      .then((d) => setGeoPoints(d.points || []))
      .catch(() => setGeoPoints([]))
  }, [])

  // Mini geo map — init once, then render circles as points arrive
  useEffect(() => {
    if (mapRef.current) return
    const el = document.getElementById('geo-map')
    if (!el) return
    const map = L.map(el, { preferCanvas: true }).setView([20, 0], 2)
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

  useEffect(() => {
    const map = mapRef.current
    if (!map || geoPoints.length === 0) return
    markersRef.current.forEach((m) => map.removeLayer(m))
    markersRef.current = []
    geoPoints.forEach((p) => {
      const color = GEO_COLOR[p.risk_level] || '#fbc02d'
      const marker = L.circleMarker([p.lat, p.lon], {
        radius: 6,
        color,
        fillColor: color,
        fillOpacity: 0.7,
      })
        .bindPopup(
          `<b>${p.city || ''}, ${p.country || ''}</b><br>Risk: ${p.risk_level} (${p.risk_score})`,
        )
        .addTo(map)
      markersRef.current.push(marker)
    })
  }, [geoPoints])

  return (
    <div className="container-fluid">
      {/* 🚀 Hero Banner Section (Obsidian AI Forensics Platform v2.0) */}
      <div className="command-hero mb-4 position-relative overflow-hidden">
        <div className="hero-orb hero-orb--one"></div><div className="hero-orb hero-orb--two"></div>
        <div className="d-flex justify-content-center mb-3">
          <div
            className="d-inline-flex align-items-center gap-2 px-3 py-1 rounded-pill border border-secondary bg-dark text-light font-monospace"
            style={{ fontSize: '0.82rem' }}
          >
            <span className="hero-live-dot"></span>
            <i className="fas fa-shield-alt me-1"></i> INTELLIGENCE CONSOLE · v2.0
          </div>
        </div>
        <h1 className="fw-extrabold text-light display-5 mb-3" style={{ letterSpacing: '-0.02em' }}>
          Your inbox, under <br />
          <span
            style={{
              backgroundImage: 'linear-gradient(90deg, #60a5fa, #c084fc, #38bdf8)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            active protection
          </span>
        </h1>
        <p className="text-muted fs-5 mx-auto mb-4" style={{ maxWidth: '720px', lineHeight: '1.6' }}>
          A forensic workspace for detecting phishing, tracing suspicious routing, and preserving the evidence trail.
        </p>
        <div className="d-flex justify-content-center align-items-center gap-3 flex-wrap">
          <Link to="/email/scan" className="btn btn-primary btn-lg font-monospace fw-semibold px-4 py-2">
            <i className="fas fa-radar me-2"></i> Start Email Scan
          </Link>
          <Link to="/forensic/scan" className="btn btn-outline-light btn-lg font-monospace fw-semibold px-4 py-2">
            <i className="fas fa-microscope me-2 text-info"></i> .EML Forensics
          </Link>
          <Link to="/email/demo" className="btn btn-outline-danger btn-lg font-monospace fw-semibold px-4 py-2">
            <i className="fas fa-satellite-dish me-2 text-danger"></i> Live Stream
          </Link>
          <Link to="/threat-map" className="btn btn-outline-secondary btn-lg font-monospace px-4 py-2">
            <i className="fas fa-globe me-2 text-success"></i> Global Threat Map
          </Link>
        </div>
        <div className="hero-readout"><span>LIVE ANALYSIS</span><strong>EMAIL · URL · HEADER</strong><span>FORENSIC-GRADE SIGNALS</span></div>
      </div>

      <div className="section-heading mb-4"><div><span>OVERVIEW</span><h4><i className="fas fa-chart-line"></i> Threat activity</h4></div><small>Last updated in real time</small></div>

      {error && (
        <div className="alert alert-danger py-2">
          <i className="fas fa-exclamation-triangle"></i> {error}
        </div>
      )}

      <div className="row mb-4 g-3">
        <div className="col-md-3">
          <div className="card stat-card h-100">
            <div className="number">{stats?.total_scans ?? '—'}</div>
            <div className="label">Total Emails Scanned</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card stat-card h-100">
            <div className="number text-danger">{stats?.phishing_detected ?? '—'}</div>
            <div className="label">Phishing Detected</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card stat-card h-100">
            <div className="number text-warning">{stats?.total_threats ?? '—'}</div>
            <div className="label">High/Critical Threats</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card stat-card h-100">
            <div className={'number ' + (mlOnline === true ? 'text-success' : mlOnline === false ? 'text-danger' : '')}>
              {mlOnline === true ? '✓ Online' : mlOnline === false ? '✗ Offline' : '—'}
            </div>
            <div className="label">ML Model Status</div>
          </div>
        </div>
      </div>

      <div className="row g-3">
        <div className="col-md-8">
          <div className="card p-4">
            <h6>
              <i className="fas fa-list"></i> Recent Email Scans
            </h6>
            <div className="table-responsive">
              <table className="table table-sm mt-3">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Email</th>
                    <th>ML Prediction</th>
                    <th>Risk</th>
                    <th>Trust</th>
                    <th>Geo</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id}>
                      <td className="text-muted" style={{ fontSize: '0.8rem' }}>
                        {fmtClock(s.timestamp) || '-'}
                      </td>
                      <td style={{ wordBreak: 'break-all' }}>{String(s.email_id || '').slice(0, 40)}</td>
                      <td>
                        <span className={'badge bg-' + predBadgeBg(s.ml_prediction)}>{s.ml_prediction}</span>
                      </td>
                      <td>
                        <span className={'badge-risk ' + riskClass(s.risk_level)}>
                          {s.risk_level} ({s.risk_score})
                        </span>
                      </td>
                      <td>{s.forensic_trust_score ?? 0}/100</td>
                      <td>{s.geo_country || '-'}</td>
                      <td>
                        <Link to={`/forensic/report/${s.id}`} className="btn btn-sm btn-outline-primary">
                          <i className="fas fa-search"></i>
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan={7} className="text-center text-muted py-4">
                        No scans yet. Go to{' '}
                        <Link to="/email/scan">Email Scanner</Link> to begin.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="col-md-4">
          <div className="card p-4 mb-3">
            <h6>
              <i className="fas fa-globe"></i> Threat Origins
            </h6>
            <div
              id="geo-map"
              style={{ height: 250, borderRadius: 8, marginTop: 10, background: '#12141c' }}
            />
            {geoPoints.length === 0 && (
              <div className="text-muted text-center mt-2" style={{ fontSize: '0.8rem' }}>
                No geolocated threats yet
              </div>
            )}
          </div>
          <div className="card p-4">
            <h6>
              <i className="fas fa-bolt text-cyan me-1"></i> Demo Quick Launchpad
            </h6>
            <div className="d-flex flex-column gap-2 mt-3">
              <Link to="/email/scan" className="btn btn-primary d-flex align-items-center justify-content-between px-3 py-2 text-decoration-none">
                <span><i className="fas fa-envelope-open-text me-2"></i> Email Threat Scanner</span>
                <span className="badge bg-dark font-monospace text-cyan" style={{ fontSize: '0.68rem' }}>NS-BCT</span>
              </Link>
              <Link to="/forensic/scan" className="btn btn-outline-light d-flex align-items-center justify-content-between px-3 py-2 text-decoration-none">
                <span><i className="fas fa-microscope me-2 text-info"></i> Raw .EML Forensics</span>
                <span className="badge bg-secondary font-monospace" style={{ fontSize: '0.68rem' }}>1-CLICK</span>
              </Link>
              <Link to="/email/demo" className="btn btn-outline-danger d-flex align-items-center justify-content-between px-3 py-2 text-decoration-none">
                <span><i className="fas fa-satellite-dish me-2 text-danger"></i> Live Stream Demo</span>
                <span className="badge bg-danger text-white font-monospace" style={{ fontSize: '0.68rem' }}>LIVE</span>
              </Link>
              <Link to="/threat-map" className="btn btn-outline-secondary d-flex align-items-center justify-content-between px-3 py-2 text-decoration-none">
                <span><i className="fas fa-globe me-2 text-success"></i> Global Threat Map</span>
                <span className="badge bg-dark font-monospace text-muted" style={{ fontSize: '0.68rem' }}>60 FPS</span>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
