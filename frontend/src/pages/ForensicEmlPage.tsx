import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { escapeHtml, riskClass, riskColor } from '../lib/format'
import ForensicRouteMap from '../components/ForensicRouteMap'

type Phase = 'upload' | 'loading' | 'error' | 'results'

export default function ForensicEmlPage() {
  const [phase, setPhase] = useState<Phase>('upload')
  const [fileName, setFileName] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [report, setReport] = useState<any | null>(null)
  const [dragover, setDragover] = useState(false)
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const analyzeFile = (file: File) => {
    const name = file.name.toLowerCase()
    if (!name.endsWith('.eml') && !name.endsWith('.txt')) {
      alert('Please upload a valid .eml file')
      return
    }
    setFileName(file.name)
    setPhase('loading')
    api
      .analyzeEml(file)
      .then((data) => {
        if (data.error) {
          setErrorMsg(data.error)
          setPhase('error')
        } else {
          setReport(data)
          setPhase('results')
        }
      })
      .catch((e: any) => {
        setErrorMsg('Network error: ' + String(e.message || e))
        setPhase('error')
      })
  }

  const resetPage = () => {
    setPhase('upload')
    setReport(null)
    setErrorMsg('')
    setFileName('')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  return (
    <div className="container-fluid p-0">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 className="fw-bold mb-1">
            <i className="fas fa-microscope text-info me-2"></i> Raw .EML Forensic Inspection
          </h4>
          <p className="text-muted mb-0" style={{ fontSize: '0.88rem' }}>
            Upload exported email messages to deconstruct headers, check cryptographic signatures, and map relay transit hops.
          </p>
        </div>
      </div>

      {phase === 'upload' && (
        <div className="card p-4">
          <div
            className={'upload-zone' + (dragover ? ' dragover' : '')}
            onDragOver={(e) => {
              e.preventDefault()
              setDragover(true)
            }}
            onDragLeave={() => setDragover(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragover(false)
              if (e.dataTransfer.files.length > 0) analyzeFile(e.dataTransfer.files[0])
            }}
            onClick={() => fileInputRef.current?.click()}
          >
            <div className="icon">
              <i className="fas fa-file-import"></i>
            </div>
            <h5>Drop .EML or .TXT email file here</h5>
            <p>or click to browse from your computer — no Gmail credentials needed</p>
            <p className="text-muted mt-2" style={{ fontSize: '0.78rem' }}>
              Standard RFC 822/2822 email format supported
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".eml,.txt"
              style={{ display: 'none' }}
              onChange={(e) => {
                if (e.target.files?.[0]) analyzeFile(e.target.files[0])
              }}
            />
          </div>
        </div>
      )}

      {phase === 'loading' && (
        <div className="card p-5 text-center">
          <div className="spinner-border text-info mb-3 mx-auto" style={{ width: '2.5rem', height: '2.5rem' }} role="status"></div>
          <div className="fw-semibold">Deconstructing {fileName}…</div>
          <p className="text-muted mt-2 mb-0" style={{ fontSize: '0.85rem' }}>
            Evaluating SPF/DKIM/DMARC headers, relay hop latencies, and machine learning threat models.
          </p>
        </div>
      )}

      {phase === 'error' && (
        <div className="card p-4">
          <div className="text-center py-4">
            <i className="fas fa-triangle-exclamation text-danger mb-3" style={{ fontSize: '2.5rem' }}></i>
            <h5 className="fw-bold">Forensic Extraction Failed</h5>
            <p className="text-danger mb-3">{errorMsg}</p>
            <button className="btn btn-primary" onClick={resetPage}>
              <i className="fas fa-rotate-left me-1"></i> Try Another File
            </button>
          </div>
        </div>
      )}

      {phase === 'results' && report && <Results report={report} onReset={resetPage} />}
    </div>
  )
}

function Results({ report, onReset }: { report: any; onReset: () => void }) {
  const risk = report.risk_assessment || {}
  const forensic = report.forensic || {}
  const auth = forensic.authentication || {}
  const routing = forensic.routing || {}
  const geo = report.geo || {}
  const geoCorr = report.geo_correlation || {}
  const temporal = forensic.temporal_analysis || {}
  const anon = geo.anonymizer || {}
  const ml = report.ml || {}
  const riskLevel = String(risk.risk_level || 'unknown').toLowerCase()
  const mlPred = ml.prediction || 'unknown'
  const mlConf = (ml.confidence || 0) * 100
  const urlResults = report.url_results || {}

  const breakdown = risk.breakdown || {}
  const breakdownLabels: Record<string, string> = {
    ml_prediction: 'ML Prediction',
    threat_intel: 'Threat Intel',
    authentication: 'Authentication',
    geolocation: 'Geolocation',
    forensic: 'Forensic Trust',
    content: 'Content Analysis',
  }
  const BREAKDOWN_ORDER = [
    'ml_prediction',
    'threat_intel',
    'authentication',
    'geolocation',
    'forensic',
    'content',
  ]

  const authBadge = (label: string, value?: string) => {
    if (!value) return null
    const isPass = value === 'PASS'
    return (
      <span
        key={label}
        className="auth-badge me-2 mb-2"
        style={{
          background: isPass ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
          color: isPass ? '#34D399' : '#F87171',
          border: `1px solid ${isPass ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          padding: '6px 14px',
        }}
      >
        <i className={`fas ${isPass ? 'fa-circle-check' : 'fa-circle-xmark'} me-1`}></i>
        {label}: {value}
      </span>
    )
  }

  return (
    <div>
      {/* Top 2 Summary Cards */}
      <div className="row g-3 mb-3">
        {/* Risk Assessment Card */}
        <div className="col-md-6">
          <div className="card p-4 h-100" style={{ borderTop: `3px solid ${riskColor(riskLevel)}` }}>
            <div className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style={{ borderColor: 'var(--border)' }}>
              <h6 className="fw-bold mb-0 text-uppercase" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
                <i className="fas fa-shield-halved text-info me-2"></i> Overall Risk Assessment
              </h6>
              <span className={`badge-risk ${riskClass(riskLevel)}`}>
                {risk.risk_level || 'Unknown'}
              </span>
            </div>
            <div className="text-center my-3">
              <div style={{ fontSize: '3.6rem', fontWeight: 800, lineHeight: 1 }} className={riskClass(riskLevel)}>
                {risk.risk_score ?? 0}
              </div>
              <div className="text-muted mt-2 font-monospace" style={{ fontSize: '0.8rem' }}>Score out of 100</div>
            </div>
          </div>
        </div>

        {/* ML Inference Card */}
        <div className="col-md-6">
          <div
            className="card p-4 h-100"
            style={{
              borderTop: `3px solid ${mlPred === 'phishing' ? '#EF4444' : mlPred === 'legitimate' ? '#10B981' : '#F59E0B'}`,
            }}
          >
            <div className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style={{ borderColor: 'var(--border)' }}>
              <h6 className="fw-bold mb-0 text-uppercase" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
                <i className="fas fa-brain text-info me-2"></i> ML Classifier Model
              </h6>
              <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                {ml.model_loaded ? 'DistilBERT Active' : 'Heuristic Mode'}
              </span>
            </div>
            <div className="text-center my-2">
              <span
                className={`badge-risk ${mlPred === 'phishing' ? 'risk-critical' : mlPred === 'suspicious' ? 'risk-medium' : 'risk-safe'}`}
                style={{ fontSize: '1.2rem', padding: '8px 24px', fontWeight: 800 }}
              >
                {String(mlPred).toUpperCase()}
              </span>
              <div className="mt-3 font-monospace" style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                Confidence: <b>{mlConf.toFixed(1)}%</b>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Auth & Metadata Cards */}
      <div className="row g-3 mb-3">
        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
              <i className="fas fa-key text-info me-2"></i> Cryptographic Signatures
            </h6>
            <div>
              {authBadge('SPF', auth.spf)}
              {authBadge('DKIM', auth.dkim)}
              {authBadge('DMARC', auth.dmarc)}
            </div>
            {auth.all_pass && (
              <div className="mt-2 text-success" style={{ fontSize: '0.82rem', fontWeight: 600 }}>
                <i className="fas fa-circle-check me-1"></i> All domain verification protocols passed.
              </div>
            )}
          </div>
        </div>

        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
              <i className="fas fa-envelope text-info me-2"></i> Message Envelope Metadata
            </h6>
            <table className="table table-sm mb-0">
              <tbody>
                <tr>
                  <td className="text-muted ps-0" style={{ width: '110px' }}>Subject</td>
                  <td className="fw-medium text-truncate" style={{ maxWidth: '240px' }}>{report.subject || '—'}</td>
                </tr>
                <tr>
                  <td className="text-muted ps-0">From</td>
                  <td className="mono text-truncate" style={{ maxWidth: '240px', fontSize: '0.8rem' }}>{report.from || '—'}</td>
                </tr>
                <tr>
                  <td className="text-muted ps-0">Message-ID</td>
                  <td className="mono text-truncate" style={{ maxWidth: '240px', fontSize: '0.78rem' }}>{report.email_id || '—'}</td>
                </tr>
                <tr>
                  <td className="text-muted ps-0">Body Length</td>
                  <td className="font-monospace">{(report.body_length || 0).toLocaleString()} characters</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Global Routing & Cross-Border Infrastructure Map */}
      <ForensicRouteMap originGeo={geo} hops={routing.hops} geoCorrelation={geoCorr} />

      {/* Geolocation & Real-Time Intelligence */}
      <div className="row g-3 mb-3">
        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
              <i className="fas fa-globe text-info me-2"></i> Origin Geolocation & Cyber Intelligence
            </h6>
            {geo.ip && geo.source !== 'unknown' ? (
              <table className="table table-sm mb-0">
                <tbody>
                  <tr><td className="text-muted ps-0">Origin IP</td><td className="mono text-info">{geo.ip}</td></tr>
                  <tr><td className="text-muted ps-0">Location</td><td>{geo.city || '—'}, {geo.country || '—'} ({geo.country_code || 'XX'})</td></tr>
                  <tr><td className="text-muted ps-0">ISP / ASN</td><td>{geo.org || '—'} {geo.asn ? `(${geo.asn})` : ''}</td></tr>
                  <tr>
                    <td className="text-muted ps-0">Anonymizer Status</td>
                    <td>
                      {anon.is_tor ? (
                        <span className="badge bg-danger text-white"><i className="fas fa-shield-virus me-1"></i> Tor Exit Node Detected</span>
                      ) : anon.is_vpn_proxy ? (
                        <span className="badge bg-warning text-dark"><i className="fas fa-user-secret me-1"></i> VPN / Proxy Detected</span>
                      ) : anon.is_bulletproof ? (
                        <span className="badge bg-danger text-white"><i className="fas fa-server me-1"></i> Bulletproof / High-Abuse Host</span>
                      ) : geo.is_hosting ? (
                        <span className="badge bg-secondary text-white">Cloud / VPS Datacenter</span>
                      ) : (
                        <span className="badge bg-success text-white"><i className="fas fa-check-circle me-1"></i> Direct Residential ISP</span>
                      )}
                    </td>
                  </tr>
                  <tr>
                    <td className="text-muted ps-0">Clock Alignment</td>
                    <td>
                      {temporal.has_anomaly ? (
                        <span className="text-warning fw-bold" style={{ fontSize: '0.8rem' }}>
                          <i className="fas fa-clock me-1"></i> Timezone Drift: {temporal.drift_hours}h discrepancy
                        </span>
                      ) : (
                        <span className="text-success" style={{ fontSize: '0.8rem' }}>
                          <i className="fas fa-check-circle me-1"></i> Aligned with physical timezone
                        </span>
                      )}
                    </td>
                  </tr>
                </tbody>
              </table>
            ) : (
              <p className="text-muted mb-0" style={{ fontSize: '0.85rem' }}>No geolocation data extracted from headers.</p>
            )}
          </div>
        </div>

        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
              <i className="fas fa-route text-warning me-2"></i> Relay Routing Chain
            </h6>
            <div>
              {(routing.hops || []).map((hop: any) => (
                <div key={hop.hop_number} className="d-flex align-items-center gap-2 mb-2 p-2 rounded" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)' }}>
                  <span className="badge" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                    #{hop.hop_number}
                  </span>
                  <div className="flex-grow-1 text-truncate" style={{ fontSize: '0.82rem' }}>
                    <span className="mono text-info">{hop.ip || 'Unknown IP'}</span>
                    <span className="text-muted ms-2">({hop.by_host || 'Direct'})</span>
                  </div>
                  {hop.suspicious ? (
                    <span className="badge-risk risk-critical" style={{ fontSize: '0.7rem' }}>Anomaly</span>
                  ) : (
                    <span className="text-success" style={{ fontSize: '0.78rem' }}>✓ Clean</span>
                  )}
                </div>
              ))}
              {(routing.hops || []).length === 0 && (
                <p className="text-muted mb-0" style={{ fontSize: '0.85rem' }}>No relay Received: headers identified.</p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Cross-Border Payload Infrastructure Correlation */}
      {geoCorr.correlated && (
        <div className="card p-4 mb-3" style={{ borderLeft: '4px solid #e74c3c' }}>
          <div className="d-flex justify-content-between align-items-center mb-2">
            <h6 className="fw-bold text-uppercase mb-0" style={{ fontSize: '0.8rem', letterSpacing: '0.8px', color: '#e74c3c' }}>
              <i className="fas fa-satellite-dish me-2"></i> Cross-Border Infrastructure Divergence Matrix
            </h6>
            <span className="badge bg-danger text-white">
              {Math.round(geoCorr.max_distance_km || 0).toLocaleString()} km Physical Divergence
            </span>
          </div>
          <p className="text-muted mb-3" style={{ fontSize: '0.84rem' }}>
            Attacker relayed email via <strong>{geoCorr.sender_origin?.country || 'Unknown'}</strong>, but malicious landing payload is hosted on remote infrastructure.
          </p>
          <div className="row g-2">
            {(geoCorr.targets || []).map((t: any, idx: number) => (
              <div className="col-md-6" key={idx}>
                <div className="p-3 rounded" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)' }}>
                  <div className="d-flex justify-content-between align-items-start mb-1">
                    <span className="mono text-danger fw-bold" style={{ fontSize: '0.82rem' }}>🎯 {t.hostname || t.ip}</span>
                    <span className="badge bg-dark text-warning">{t.country_code}</span>
                  </div>
                  <div className="text-muted small mb-1">
                    Location: <strong>{t.city}, {t.country}</strong> · ASN: <strong>{t.asn || t.org || 'Cloud'}</strong>
                  </div>
                  <div className="text-muted small">
                    Physical Distance: <span className="text-danger fw-bold">{Math.round(t.distance_km).toLocaleString()} km</span> from Mail Relay
                  </div>
                </div>
              </div>
            ))}
          </div>
          {geoCorr.anomalies?.length > 0 && (
            <div className="mt-3 p-2 rounded" style={{ background: 'rgba(231,76,60,0.1)', border: '1px solid rgba(231,76,60,0.3)' }}>
              {geoCorr.anomalies.map((anom: string, i: number) => (
                <div key={i} className="text-danger small fw-semibold">
                  <i className="fas fa-radiation-alt me-1"></i> {anom}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Risk Breakdown */}
      <div className="card p-4 mb-3">
        <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
          <i className="fas fa-chart-simple text-info me-2"></i> Composite Risk Factor Weights
        </h6>
        <div className="row g-3">
          {BREAKDOWN_ORDER.map((key) => {
            const val = breakdown[key] || 0
            const barColor = val > 60 ? 'var(--status-critical)' : val > 30 ? 'var(--status-warning)' : 'var(--status-safe)'
            return (
              <div className="col-md-4 col-sm-6" key={key}>
                <div className="p-3 rounded" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)' }}>
                  <div className="d-flex justify-content-between align-items-center mb-1">
                    <span className="text-muted" style={{ fontSize: '0.78rem', fontWeight: 600 }}>{breakdownLabels[key] || key}</span>
                    <span className="font-monospace fw-bold" style={{ fontSize: '0.82rem' }}>{val}</span>
                  </div>
                  <div style={{ height: '5px', background: 'var(--bg-input)', borderRadius: '3px', overflow: 'hidden', border: '1px solid var(--border)' }}>
                    <div style={{ height: '100%', width: `${Math.min(100, val)}%`, background: barColor }}></div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* URL Threat Intelligence */}
      {(report.urls_found || []).length > 0 && (
        <div className="card p-4 mb-3">
          <h6 className="fw-bold text-uppercase mb-3" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
            <i className="fas fa-link text-info me-2"></i> Extracted URLs Threat Intelligence ({(report.urls_found || []).length})
          </h6>
          <div className="table-responsive">
            <table className="table table-hover align-middle mb-0">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>VirusTotal</th>
                  <th>Google SafeBrowsing</th>
                  <th>Threat Level</th>
                </tr>
              </thead>
              <tbody>
                {(report.urls_found || []).map((url: string) => {
                  const r = urlResults[url] || {}
                  const level = r.threat_level || 'low'
                  return (
                    <tr key={url}>
                      <td className="mono" style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.82rem' }} title={url}>
                        {escapeHtml(url)}
                      </td>
                      <td className="font-monospace fw-bold">{r.threat_score || 0}</td>
                      <td>
                        <span className="badge" style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                          {r.sources?.safebrowsing?.status || 'Clean'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge-risk ${riskClass(level)}`}>
                          {level}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Email Body Preview */}
      <div className="card p-4 mb-4">
        <h6 className="fw-bold text-uppercase mb-2" style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}>
          <i className="fas fa-file-lines text-info me-2"></i> Parsed Message Body
        </h6>
        <div className="mono p-3 rounded" style={{ maxHeight: '200px', overflowY: 'auto', background: 'var(--bg-input)', border: '1px solid var(--border)', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>
          {report.body_preview || '(Empty message body)'}
        </div>
      </div>

      {/* Bottom Action Footer */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <button className="btn btn-outline-secondary" onClick={onReset}>
          <i className="fas fa-rotate-left me-1"></i> Inspect Another .EML File
        </button>
        {report.scan_id && (
          <a
            href={api.forensicPdfUrl(report.scan_id)}
            target="_blank"
            rel="noreferrer"
            className="btn btn-primary"
          >
            <i className="fas fa-file-pdf me-1"></i> Download Forensic PDF Report
          </a>
        )}
      </div>
    </div>
  )
}
