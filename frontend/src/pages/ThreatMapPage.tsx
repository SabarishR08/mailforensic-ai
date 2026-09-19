import { useEffect, useRef, useState } from 'react'
import L from 'leaflet'
import { api } from '../lib/api'
import { fmtTime } from '../lib/format'

const PRED_COLORS: Record<string, string> = {
  phishing: '#e74c3c',
  legitimate: '#2ecc71',
  suspicious: '#f39c12',
  unknown: '#f39c12',
}
const RISK_BAR_COLORS: Record<string, string> = {
  Critical: '#e74c3c',
  High: '#e67e22',
  Medium: '#f1c40f',
  Low: '#3498db',
  Safe: '#2ecc71',
  Unknown: '#95a5a6',
}

const TIME_BUTTONS = [
  { days: 1, label: '24h' },
  { days: 7, label: '7d' },
  { days: 30, label: '30d' },
  { days: 365, label: 'All' },
]
const RISK_BUTTONS = [
  { value: '', label: 'All' },
  { value: 'Critical', label: 'Critical' },
  { value: 'High', label: 'High' },
  { value: 'Medium', label: 'Medium' },
]

export default function ThreatMapPage() {
  const mapDivRef = useRef<HTMLDivElement | null>(null)
  const mapRef = useRef<L.Map | null>(null)
  const originLayerRef = useRef<L.LayerGroup | null>(null)
  const payloadLayerRef = useRef<L.LayerGroup | null>(null)
  const correlationLayerRef = useRef<L.LayerGroup | null>(null)
  const routeLayerRef = useRef<L.LayerGroup | null>(null)
  const heatLayerRef = useRef<L.LayerGroup | null>(null)
  const heatPointsRef = useRef<[number, number, number][]>([])

  const [days, setDays] = useState(1)
  const [riskFilter, setRiskFilter] = useState('')
  const [layers, setLayers] = useState({ origin: true, payload: true, correlation: true, route: true, heat: false })
  const [stats, setStats] = useState<any>(null)
  const [countries, setCountries] = useState<any[]>([])
  const [feed, setFeed] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  const [reconQuery, setReconQuery] = useState('')
  const [reconLoading, setReconLoading] = useState(false)
  const [reconResult, setReconResult] = useState<any>(null)
  const [reconError, setReconError] = useState('')

  const handleRecon = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()
    const q = reconQuery.trim()
    if (!q) return
    setReconLoading(true)
    setReconError('')
    try {
      const data = await api.geoLookup(q)
      const res = data.result || {}
      setReconResult(res)
      setReconLoading(false)
      const map = mapRef.current
      if (map && res.latitude && res.longitude && res.latitude !== 0) {
        map.flyTo([res.latitude, res.longitude], 6)
        const isTor = res.anonymizer?.is_tor
        const color = isTor ? '#9b59b6' : '#38bdf8'
        const marker = L.circleMarker([res.latitude, res.longitude], {
          radius: 12,
          color: '#ffffff',
          fillColor: color,
          fillOpacity: 0.9,
          weight: 3,
        }).addTo(map)
        marker.bindPopup(
          `<div style="font-size:12px;font-family:'Inter',sans-serif;color:#1e293b;padding:4px;">` +
            `<strong style="color:#2563eb;">🎯 Live Target Recon: ${q}</strong><br/>` +
            `<strong>IP:</strong> ${res.ip || q}<br/>` +
            `<strong>Location:</strong> ${res.city || '?'}, ${res.country || '?'}<br/>` +
            `<strong>ISP/ASN:</strong> ${res.org || res.asn || '?'}<br/>` +
            `<strong>Reverse DNS:</strong> ${res.reverse_dns || 'None'}<br/>` +
            `<strong>Anonymizer:</strong> ${isTor ? '⚠️ Active Tor Exit Node' : (res.anonymizer?.anonymizer_type || 'None')}<br/>` +
            `<strong>Risk Score:</strong> ${res.risk_score || 0}/100` +
          `</div>`
        ).openPopup()
      }
    } catch (err: any) {
      setReconError(err.message || 'Lookup failed')
      setReconLoading(false)
    }
  }

  // --- Init map once ---
  useEffect(() => {
    const el = mapDivRef.current
    if (!el || mapRef.current) return
    const map = L.map(el, {
      center: [20, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: false,
      preferCanvas: true,
    })
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
      maxZoom: 16,
      attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
    }).addTo(map)
    mapRef.current = map
    originLayerRef.current = L.layerGroup().addTo(map)
    payloadLayerRef.current = L.layerGroup().addTo(map)
    correlationLayerRef.current = L.layerGroup().addTo(map)
    routeLayerRef.current = L.layerGroup().addTo(map)
    heatLayerRef.current = L.layerGroup()
    return () => {
      map.remove()
      mapRef.current = null
    }
  }, [])

  // --- Load data whenever days/risk change ---
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [pointsData, statsData, recentData] = await Promise.all([
          api.mapPoints(days, riskFilter),
          api.mapStats(days),
          api.mapRecent(10),
        ])
        if (cancelled) return
        setStats(statsData)
        setCountries(statsData.top_countries || [])
        setFeed(recentData.recent || [])
        setLoading(false)

        const map = mapRef.current
        if (!map || !originLayerRef.current || !payloadLayerRef.current || !correlationLayerRef.current || !routeLayerRef.current) return
        const originLayer = originLayerRef.current
        const payloadLayer = payloadLayerRef.current
        const correlationLayer = correlationLayerRef.current
        const routeLayer = routeLayerRef.current

        originLayer.clearLayers()
        payloadLayer.clearLayers()
        correlationLayer.clearLayers()
        routeLayer.clearLayers()
        heatPointsRef.current = []

        for (const p of pointsData.points || []) {
          if (p.type === 'origin' && p.lat && p.lon) {
            createMarker(p).addTo(originLayer)
            heatPointsRef.current.push([p.lat, p.lon, (p.risk_score || 0) / 100])
          } else if (p.type === 'payload_infra' && p.lat && p.lon) {
            createPayloadMarker(p).addTo(payloadLayer)
            heatPointsRef.current.push([p.lat, p.lon, 0.9])
          } else if (p.type === 'correlation_vector') {
            const line = createCorrelationLine(p)
            if (line) line.addTo(correlationLayer)
          } else if (p.type === 'route' && p.hops && p.hops.length > 1) {
            const line = createRouteLine(p.hops)
            if (line) line.addTo(routeLayer)
          }
        }
      } catch (e) {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    const timer = setInterval(load, 30000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [days, riskFilter])

  // --- Heat layer visibility ---
  useEffect(() => {
    const map = mapRef.current
    const heat = heatLayerRef.current
    if (!map || !heat) return
    if (layers.heat) {
      heat.clearLayers()
      for (const [lat, lon, intensity] of heatPointsRef.current) {
        L.circle([lat, lon], {
          radius: 50000 + intensity * 100000,
          color: '#e67e22',
          fillColor: '#e67e22',
          fillOpacity: 0.15 + intensity * 0.2,
          weight: 0,
        }).addTo(heat)
      }
      map.addLayer(heat)
    } else if (map.hasLayer(heat)) {
      map.removeLayer(heat)
    }
  }, [layers.heat])

  const toggleLayer = (key: 'origin' | 'payload' | 'correlation' | 'route' | 'heat') => {
    const map = mapRef.current
    if (!map) return
    const layerMap: Record<string, L.LayerGroup | null> = {
      origin: originLayerRef.current,
      payload: payloadLayerRef.current,
      correlation: correlationLayerRef.current,
      route: routeLayerRef.current,
    }
    if (key !== 'heat' && layerMap[key]) {
      const target = layerMap[key]!
      map.hasLayer(target) ? map.removeLayer(target) : map.addLayer(target)
    }
    setLayers((l) => ({ ...l, [key]: !l[key] }))
  }

  const maxCount = countries[0]?.count || 1
  const maxZoom = 19

  return (
    <div className="map-wrapper">
      <div ref={mapDivRef} id="map" />
      <div className="map-sidebar">
        <h5>
          <i className="fas fa-globe-americas"></i> THREAT MAP
        </h5>

        <div className="stat-row">
          <span className="stat-label">Total Scans</span>
          <span className="stat-value">{stats?.total_scans ?? '…'}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Geo-Tagged</span>
          <span className="stat-value">{stats?.geo_tagged ?? '…'}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Countries</span>
          <span className="stat-value">{stats?.countries ?? '…'}</span>
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-circle" style={{ fontSize: 8 }}></i> Legend
        </h5>
        <div className="pred-legend">
          <div className="pred-legend-item">
            <div className="pred-dot" style={{ background: '#e74c3c' }}></div> Phishing
          </div>
          <div className="pred-legend-item">
            <div className="pred-dot" style={{ background: '#2ecc71' }}></div> Legitimate
          </div>
          <div className="pred-legend-item">
            <div className="pred-dot" style={{ background: '#f39c12' }}></div> Unknown
          </div>
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-search-location"></i> Live Target Recon
        </h5>
        <form onSubmit={handleRecon} style={{ marginBottom: 10 }}>
          <div style={{ display: 'flex', gap: 6 }}>
            <input
              type="text"
              placeholder="IP, domain, or URL..."
              value={reconQuery}
              onChange={(e) => setReconQuery(e.target.value)}
              className="form-control form-control-sm"
              style={{
                background: 'rgba(255,255,255,0.08)',
                border: '1px solid rgba(255,255,255,0.2)',
                color: '#fff',
                fontSize: '11px',
              }}
            />
            <button
              type="submit"
              disabled={reconLoading || !reconQuery.trim()}
              className="btn btn-sm btn-primary"
              style={{ fontSize: '11px', padding: '2px 8px' }}
            >
              {reconLoading ? '...' : 'Inspect'}
            </button>
          </div>
        </form>
        {reconResult && (
          <div
            style={{
              background: 'rgba(56, 189, 248, 0.08)',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              borderRadius: 6,
              padding: 8,
              fontSize: 11,
              marginBottom: 10,
            }}
          >
            <div style={{ fontWeight: 'bold', color: '#38bdf8' }}>
              📍 {reconResult.city || '?'}, {reconResult.country || '?'} ({reconResult.country_code || 'XX'})
            </div>
            <div style={{ color: '#94a3b8' }}>IP: {reconResult.ip}</div>
            <div style={{ color: '#94a3b8' }}>ASN: {reconResult.org || reconResult.asn || 'Cloud'}</div>
            {reconResult.reverse_dns && (
              <div style={{ color: '#cbd5e1', fontSize: 10 }}>PTR: {reconResult.reverse_dns}</div>
            )}
            {reconResult.anonymizer?.is_tor && (
              <div style={{ color: '#c084fc', fontWeight: 'bold' }}>⚠️ Active Tor Exit Node</div>
            )}
            {reconResult.is_residential_pool && (
              <div style={{ color: '#f59e0b', fontWeight: 'bold' }}>⚠️ Residential Dynamic Pool</div>
            )}
          </div>
        )}
        {reconError && (
          <div style={{ color: '#f87171', fontSize: 11, marginBottom: 8 }}>{reconError}</div>
        )}

        <div className="section-divider" />
        <h5>
          <i className="fas fa-layer-group"></i> Layers
        </h5>
        {(
          [
            ['origin', 'Threat Origins (Relays)'],
            ['payload', 'Phishing Landing Infra'],
            ['correlation', 'Cross-Border Vectors'],
            ['route', 'Routing Hops'],
            ['heat', 'Heat Density'],
          ] as const
        ).map(([key, label]) => (
          <div className="layer-toggle" key={key}>
            <input
              type="checkbox"
              id={'layer-' + key}
              checked={layers[key]}
              onChange={() => toggleLayer(key)}
            />
            <label htmlFor={'layer-' + key}>{label}</label>
          </div>
        ))}

        <div className="section-divider" />
        <h5>
          <i className="fas fa-clock"></i> Time Range
        </h5>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {TIME_BUTTONS.map((b) => (
            <button
              key={b.days}
              className={'btn btn-sm btn-outline-light time-btn' + (days === b.days ? ' active' : '')}
              onClick={() => setDays(b.days)}
            >
              {b.label}
            </button>
          ))}
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-filter"></i> Risk Filter
        </h5>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {RISK_BUTTONS.map((b) => (
            <button
              key={b.label}
              className={
                'btn btn-sm btn-outline-danger risk-btn' +
                (riskFilter === b.value ? ' active' : '')
              }
              onClick={() => setRiskFilter(b.value)}
            >
              {b.label}
            </button>
          ))}
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-flag"></i> Top Threat Sources
        </h5>
        <div id="country-list">
          {countries.slice(0, 10).map((c) => (
            <div className="country-bar" key={c.country}>
              <span className="bar-name">{c.country}</span>
              <div className="bar">
                <div
                  className="bar-fill"
                  style={{
                    width: (c.count / maxCount) * 100 + '%',
                    background: RISK_BAR_COLORS[c.avg_risk > 50 ? 'High' : 'Medium'],
                  }}
                />
              </div>
              <span className="bar-label">{c.count}</span>
            </div>
          ))}
          {countries.length === 0 && !loading && (
            <div style={{ color: '#888', fontSize: 12 }}>No geo data in this range</div>
          )}
        </div>

        <div className="section-divider" />
        <h5>
          <i className="fas fa-exclamation-triangle"></i> Recent Phishing
        </h5>
        <div className="live-feed" id="live-feed">
          {feed.map((r, i) => (
            <div key={i} className={'feed-item ' + String(r.risk_level || '').toLowerCase()}>
              <div className="feed-from">{r.from || 'Unknown'}</div>
              <div className="feed-subject">{r.subject || 'No subject'}</div>
              <div className="feed-meta">
                {r.country || '?'} ·{' '}
                <span className={'risk-badge risk-' + String(r.risk_level || '').toLowerCase()}>
                  {r.risk_level}
                </span>{' '}
                · {r.timestamp ? fmtTime(r.timestamp) : ''}
              </div>
            </div>
          ))}
          {feed.length === 0 && !loading && (
            <div style={{ color: '#888', fontSize: 12 }}>No recent phishing</div>
          )}
        </div>
      </div>
    </div>
  )

  // --- helpers (closure-safe; leaflet objects built imperatively) ---
  function createMarker(p: any) {
    const isTor = p.anonymizer?.is_tor
    const color = isTor ? '#9b59b6' : (PRED_COLORS[p.prediction] || RISK_BAR_COLORS[p.risk_level] || '#95a5a6')
    const size = p.risk_score > 70 ? 10 : p.risk_score > 40 ? 8 : 6
    const marker = L.circleMarker([p.lat, p.lon], {
      radius: size,
      fillColor: color,
      color: isTor ? '#d8b4fe' : '#ffffff',
      weight: isTor ? 2.5 : 1.5,
      fillOpacity: 0.9,
    })
    const predLabel = (p.prediction || 'unknown').toLowerCase()
    const predClass = predLabel === 'phishing' ? 'popup-pred-phishing' : (predLabel === 'legitimate' ? 'popup-pred-legitimate' : 'popup-pred-suspicious')
    const displayId = p.from || p.email_id || 'Unknown Threat Origin'
    const shortId = displayId.length > 26 ? displayId.substring(0, 24) + '...' : displayId
    const subjectText = p.subject || '(No Subject Available)'

    function getAuthTag(val?: string) {
      const v = (val || '?').toUpperCase()
      const cls = v === 'PASS' ? 'pass' : (v === 'FAIL' ? 'fail' : 'neutral')
      return `<span class="auth-tag ${cls}">${v}</span>`
    }

    const authHtml = `<span class="popup-auth-pills">SPF ${getAuthTag(p.auth?.spf)} DKIM ${getAuthTag(p.auth?.dkim)} DMARC ${getAuthTag(p.auth?.dmarc)}</span>`
    const riskClass = (p.risk_level || 'low').toLowerCase()
    const riskBadge = `<span class="badge-risk risk-${riskClass}">${p.risk_level || 'Low'} (${p.risk_score || 0}/100)</span>`
    const trustVal = p.trust_score !== undefined ? p.trust_score : 50
    const trustColor = trustVal >= 80 ? '#34D399' : (trustVal >= 60 ? '#FBBF24' : '#FB7185')
    const trustHtml = `<span style="color:${trustColor};font-weight:700;font-family:'JetBrains Mono',monospace;">${trustVal}/100</span>`
    const timeStr = p.timestamp ? fmtTime(p.timestamp) : 'Just now'
    
    let alertRows = ''
    if (isTor) {
      alertRows += `<div class="popup-row" style="background:rgba(155,89,182,0.15);padding:3px 6px;border-radius:4px;"><strong style="color:#9b59b6;">⚠️ Tor Exit Node</strong><span class="popup-val" style="color:#9b59b6;font-weight:700;">Active Relay</span></div>`
    }
    if (p.temporal_analysis?.has_anomaly) {
      alertRows += `<div class="popup-row" style="background:rgba(243,156,18,0.15);padding:3px 6px;border-radius:4px;"><strong style="color:#f39c12;">⏰ Clock Anomaly</strong><span class="popup-val" style="color:#f39c12;font-weight:700;">${p.temporal_analysis.drift_hours}h Drift</span></div>`
    }

    const popup =
      `<div class="popup-card">` +
        `<div class="popup-header">` +
          `<span class="popup-id-badge" title="${displayId}">${shortId}</span>` +
          `<span class="popup-pred-badge ${predClass}">${predLabel.toUpperCase()}</span>` +
        `</div>` +
        `<div class="popup-subject">${subjectText}</div>` +
        `<div class="popup-grid">` +
          `<div class="popup-row"><strong>Location</strong><span class="popup-val">${p.city || '?'}, ${p.country || '?'}</span></div>` +
          `<div class="popup-row"><strong>Risk Score</strong>${riskBadge}</div>` +
          alertRows +
          `<div class="popup-row"><strong>Auth</strong>${authHtml}</div>` +
          `<div class="popup-row"><strong>Trust</strong>${trustHtml}</div>` +
          `<div class="popup-row"><strong>Timestamp</strong><span class="popup-val" style="font-size:10.5px;color:#94A3B8;">${timeStr}</span></div>` +
        `</div>` +
      `</div>`
    return marker.bindPopup(popup, { minWidth: 260, maxWidth: 320 })
  }

  function createPayloadMarker(p: any) {
    const isTor = p.anonymizer?.is_tor
    const marker = L.circleMarker([p.lat, p.lon], {
      radius: 9,
      fillColor: '#e74c3c',
      color: '#ffffff',
      weight: 2.5,
      fillOpacity: 0.95,
    })
    const popup =
      `<div class="popup-card" style="border-top:3px solid #e74c3c;">` +
        `<div class="popup-header">` +
          `<span class="popup-id-badge" style="background:rgba(231,76,60,0.2);color:#e74c3c;font-weight:bold;">🎯 PHISHING LANDING HOST</span>` +
        `</div>` +
        `<div class="popup-subject" style="color:#e74c3c;word-break:break-all;font-size:11.5px;">${p.target_url || p.hostname}</div>` +
        `<div class="popup-grid">` +
          `<div class="popup-row"><strong>Server Location</strong><span class="popup-val">${p.city || '?'}, ${p.country || '?'} (${p.country_code || 'XX'})</span></div>` +
          `<div class="popup-row"><strong>Host / ASN</strong><span class="popup-val" style="font-size:11px;">${p.org || p.asn || 'Cloud/VPS'}</span></div>` +
          `<div class="popup-row"><strong>Divergence</strong><span class="popup-val" style="color:#e67e22;font-weight:700;">${Math.round(p.distance_km || 0).toLocaleString()} km from Sender</span></div>` +
          `<div class="popup-row"><strong>Anonymizer</strong><span class="popup-val">${isTor ? '⚠️ Active Tor Exit Node' : (p.anonymizer?.anonymizer_type || 'Standard Datacenter')}</span></div>` +
        `</div>` +
      `</div>`
    return marker.bindPopup(popup, { minWidth: 280, maxWidth: 340 })
  }

  function createCorrelationLine(v: any) {
    if (!v.origin || !v.target) return null
    const coords: [number, number][] = [
      [v.origin.lat, v.origin.lon],
      [v.target.lat, v.target.lon],
    ]
    const line = L.polyline(coords, {
      color: '#e67e22',
      weight: 3,
      opacity: 0.85,
      dashArray: '6, 6',
    })
    const popup =
      `<div style="font-size:12px;font-family:'Inter',sans-serif;color:#1e293b;padding:4px;">` +
        `<strong style="color:#d97706;">⚡ Cross-Border Infrastructure Divergence</strong><br/>` +
        `<strong>Mail Relay:</strong> ${v.origin.city || '?'}, ${v.origin.country || '?'}<br/>` +
        `<strong>Phishing Host:</strong> ${v.target.city || '?'}, ${v.target.country || '?'}<br/>` +
        `<strong>Physical Distance:</strong> <span style="font-weight:700;color:#e11d48;">${Math.round(v.distance_km || 0).toLocaleString()} km</span>` +
      `</div>`
    line.bindPopup(popup)
    return line
  }

  function createRouteLine(hops: any[]) {
    if (hops.length < 2) return null
    const coords = hops.map((h) => [h.lat, h.lon] as [number, number])
    const hasSuspicious = hops.some((h) => h.suspicious)
    return L.polyline(coords, {
      color: hasSuspicious ? '#e74c3c' : '#3498db',
      weight: hasSuspicious ? 3 : 2,
      opacity: 0.6,
      dashArray: hasSuspicious ? '8, 4' : undefined,
    })
  }
}
