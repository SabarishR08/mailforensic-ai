import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import L from 'leaflet'
import { api } from '../lib/api'
import { fmtTime, riskClass, escapeHtml } from '../lib/format'
import RouteTimeline from '../components/RouteTimeline'
import RiskRadar from '../components/RiskRadar'

export default function ForensicReportPage() {
  const { scanId } = useParams()
  const [data, setData] = useState<any | null>(null)
  const [error, setError] = useState('')
  const mapRef = useRef<L.Map | null>(null)

  useEffect(() => {
    setData(null)
    setError('')
    api
      .forensicReport(scanId || '')
      .then((d) => setData(d))
      .catch((e) => setError(String(e.message || e)))
  }, [scanId])

  // Sender geo map
  useEffect(() => {
    const result = data?.result || {}
    const geo = result.geo || {}
    if (!data || !geo.latitude) return
    if (mapRef.current) return
    const el = document.getElementById('forensic-map')
    if (!el) return
    const map = L.map(el, { preferCanvas: true }).setView([geo.latitude, geo.longitude], 8)
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
      maxZoom: 16,
      attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
    }).addTo(map)
    L.marker([geo.latitude, geo.longitude])
      .addTo(map)
      .bindPopup(`<b>${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}</b><br>Risk Score: ${geo.risk_score || 0}/100`)
      .openPopup()
    mapRef.current = map
    return () => {
      map.remove()
      mapRef.current = null
    }
  }, [data])

  if (error) {
    return (
      <div className="container-fluid">
        <h4 className="mb-4">
          <i className="fas fa-microscope text-cyan"></i> Forensic Intelligence Report
        </h4>
        <div className="alert alert-danger shadow-sm">
          <i className="fas fa-exclamation-triangle me-2"></i> {error}
        </div>
        <Link to="/forensic/scan" className="btn btn-outline-secondary">
          <i className="fas fa-arrow-left me-2"></i> Back to Analysis
        </Link>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="text-center py-5 my-5">
        <i className="fas fa-spinner fa-spin fa-2x text-cyan mb-3"></i>
        <p className="text-muted">Loading deep forensic intelligence report...</p>
      </div>
    )
  }

  const { scan, result } = data
  const risk = result.risk_assessment || {}
  const breakdown = risk.breakdown || {}
  const ml = result.ml || {}
  const auth = (result.forensic || {}).authentication || {}
  const mismatches = (result.forensic || {}).mismatches || []
  const routing = (result.forensic || {}).routing || {}
  const hops = routing.hops || []
  const geo = result.geo || {}
  const urlResults = result.url_results || {}

  const getAuthBadgeClass = (val?: string) => {
    if (!val) return 'missing'
    const v = val.toUpperCase()
    if (v === 'PASS' || v === 'OK') return 'pass'
    if (v === 'FAIL' || v === 'SOFTFAIL') return 'fail'
    return 'missing'
  }

  return (
    <div className="container-fluid">
      <div className="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
          <h4 className="mb-1 text-white fw-bold">
            <i className="fas fa-shield-alt text-info me-2"></i> Forensic Intelligence Report
          </h4>
          <span className="text-muted small">Scan ID: {scan.email_id}</span>
        </div>
        <div className="d-flex gap-2">
          <a
            href={api.forensicPdfUrl(scan.id)}
            className="btn btn-outline-danger"
            target="_blank"
            rel="noreferrer"
          >
            <i className="fas fa-file-pdf me-2"></i> Export Forensic PDF
          </a>
          <Link to="/forensic/scan" className="btn btn-outline-secondary">
            <i className="fas fa-arrow-left me-2"></i> Back
          </Link>
        </div>
      </div>

      <div className="row g-4">
        {/* Risk summary & Signals */}
        <div className="col-lg-4">
          <div className="card p-4 mb-4">
            <h6 className="text-uppercase small text-muted font-monospace mb-2">Composite Risk Assessment</h6>
            <div className="text-center my-3">
              <div
                style={{ fontSize: '3.5rem', fontWeight: 800, lineHeight: 1 }}
                className={riskClass(risk.risk_level)}
              >
                {risk.risk_score || 0}
              </div>
              <div className="text-muted small mt-1 mb-2">Composite Threat Score / 100</div>
              <div className={'badge-risk ' + riskClass(risk.risk_level)} style={{ fontSize: '1rem' }}>
                <i className="fas fa-shield-virus me-1"></i> {risk.risk_level || 'Unknown'} Risk
              </div>
            </div>

            <RiskRadar breakdown={breakdown} riskLevel={risk.risk_level || ''} />
          </div>

          <div className="card p-4 mb-4">
            <h6 className="text-uppercase small text-muted font-monospace mb-3">ML Threat Classification</h6>
            <div className="d-flex justify-content-between align-items-center mb-3">
              <span className="text-muted">Prediction</span>
              <span
                className={'badge-risk ' + (ml.prediction === 'phishing' ? 'risk-critical' : 'risk-low')}
              >
                {ml.prediction ? ml.prediction.toUpperCase() : 'UNKNOWN'}
              </span>
            </div>

            <div className="mb-2">
              <div className="d-flex justify-content-between text-muted small mb-1">
                <span>Ensemble Model Confidence</span>
                <span className="text-light font-monospace">{(((ml.confidence || 0)) * 100).toFixed(1)}%</span>
              </div>
              <div className="progress" style={{ height: '6px', background: 'rgba(255, 255, 255, 0.08)' }}>
                <div
                  className="progress-bar bg-cyan"
                  style={{
                    width: `${((ml.confidence || 0) * 100).toFixed(1)}%`,
                    backgroundColor: 'var(--glow-cyan)',
                    boxShadow: '0 0 10px var(--glow-cyan)',
                  }}
                />
              </div>
            </div>

            {scan.timestamp && (
              <div className="mt-3 pt-3 border-top border-secondary border-opacity-25 text-muted small">
                <i className="fas fa-clock me-1"></i> Analysis Date: {fmtTime(scan.timestamp)}
              </div>
            )}
          </div>
        </div>

        <div className="col-lg-8">
          {/* Email Authentication Pills */}
          <div className="card p-4 mb-4">
            <h6 className="text-uppercase small text-muted font-monospace mb-3">
              <i className="fas fa-key me-2 text-warning"></i> Authentication Protocol Verification
            </h6>
            <div className="row g-3">
              {[
                { name: 'SPF Alignment', value: auth.spf, desc: 'Sender Policy Framework' },
                { name: 'DKIM Signature', value: auth.dkim, desc: 'DomainKeys Identified Mail' },
                { name: 'DMARC Policy', value: auth.dmarc, desc: 'Domain Message Auth & Reporting' },
              ].map((a) => (
                <div className="col-md-4" key={a.name}>
                  <div className={`auth-badge ${getAuthBadgeClass(a.value)}`}>
                    <div className="auth-name">{a.name}</div>
                    <div className="auth-status font-monospace mt-1">
                      {a.value ? a.value.toUpperCase() : 'MISSING / UNCONFIGURED'}
                    </div>
                    <small className="text-muted mt-2 text-center" style={{ fontSize: '0.75rem' }}>
                      {a.desc}
                    </small>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Mismatches */}
          {mismatches.length > 0 && (
            <div className="card p-4 mb-4 border-danger border-opacity-50">
              <h6 className="text-danger mb-3">
                <i className="fas fa-exclamation-triangle me-2"></i> Header Mismatches & Anomaly Warnings
              </h6>
              <div className="d-flex flex-column gap-2">
                {mismatches.map((mm: any, i: number) => (
                  <div
                    key={i}
                    className={
                      'p-3 rounded border ' +
                      (mm.severity === 'HIGH'
                        ? 'bg-danger bg-opacity-10 border-danger border-opacity-25 text-danger-emphasis'
                        : 'bg-warning bg-opacity-10 border-warning border-opacity-25 text-warning-emphasis')
                    }
                  >
                    <div className="d-flex align-items-center gap-2 mb-1">
                      <span className={'badge ' + (mm.severity === 'HIGH' ? 'bg-danger' : 'bg-warning text-dark')}>
                        {mm.severity} SEVERITY
                      </span>
                      <strong className="text-white">{mm.type}</strong>
                    </div>
                    <div className="small text-light text-opacity-75">{mm.detail}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Interactive Routing Chain */}
          {hops.length > 0 && (
            <div className="card p-4 mb-4">
              <div className="d-flex justify-content-between align-items-center mb-3">
                <h6 className="text-uppercase small text-muted font-monospace mb-0">
                  <i className="fas fa-route me-2 text-info"></i> Interactive Hop-by-Hop Routing Chain
                </h6>
                <span className="badge bg-dark text-info border border-info border-opacity-25">
                  {routing.hop_count || hops.length} Total Hops Traced
                </span>
              </div>

              <RouteTimeline hops={hops} />
            </div>
          )}

          {/* Geolocation */}
          {geo && geo.latitude ? (
            <div className="card p-4 mb-4">
              <h6 className="text-uppercase small text-muted font-monospace mb-3">
                <i className="fas fa-globe-americas me-2 text-primary"></i> Origin Server Geolocation Analysis
              </h6>
              <div id="forensic-map" style={{ height: 240, borderRadius: 10, background: '#0b0f19' }} />
              <div className="mt-3 p-3 bg-dark bg-opacity-50 rounded border border-secondary border-opacity-25 d-flex justify-content-between flex-wrap gap-2 text-muted small">
                <div>
                  <i className="fas fa-city text-cyan me-1"></i> {geo.city || 'Unknown City'}, {geo.country || 'Unknown Country'}
                </div>
                <div>
                  <i className="fas fa-server text-cyan me-1"></i> ASN: {geo.asn || 'N/A'} ({geo.org || 'Unknown Provider'})
                </div>
                <div>
                  <i className="fas fa-shield-alt text-warning me-1"></i> Country Risk: <span className="text-light font-monospace">{geo.risk_score || 0}/100</span>
                </div>
              </div>
            </div>
          ) : null}

          {/* URL threat intelligence */}
          {Object.keys(urlResults).length > 0 && (
            <div className="card p-4">
              <h6 className="text-uppercase small text-muted font-monospace mb-3">
                <i className="fas fa-link me-2 text-cyan"></i> Extracted Embedded URL Threat Intelligence
              </h6>
              <div className="table-responsive">
                <table className="table table-hover">
                  <thead>
                    <tr>
                      <th>Target URL</th>
                      <th>VirusTotal Detection</th>
                      <th>SafeBrowsing Status</th>
                      <th>Risk Level</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(urlResults).map(([url, ti]: any[]) => (
                      <tr key={url}>
                        <td
                          style={{
                            maxWidth: 240,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={url}
                          className="font-monospace small text-cyan"
                        >
                          {escapeHtml(url)}
                        </td>
                        <td>
                          <span className="badge bg-dark text-light border border-secondary">
                            {ti.threat_score ?? 0} Detections
                          </span>
                        </td>
                        <td>
                          <span className="badge bg-dark text-info border border-info border-opacity-25">
                            {ti.sources?.safebrowsing?.status ?? 'Clean'}
                          </span>
                        </td>
                        <td>
                          <span className={'badge-risk ' + riskClass(ti.threat_level)}>
                            {ti.threat_level ? ti.threat_level.toUpperCase() : 'UNKNOWN'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
