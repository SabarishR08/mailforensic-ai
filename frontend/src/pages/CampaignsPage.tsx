import { useEffect, useState } from 'react'

interface Campaign {
  campaign_id: string
  name: string
  sender_domain: string
  origin_country: string
  email_count: number
  phishing_count: number
  avg_risk_score: number
  risk_level: string
  mitre_attack: { id: string; name: string; tactic: string }[]
  last_active: string
}

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [searchResults, setSearchResults] = useState<any[]>([])
  const [searching, setSearching] = useState<boolean>(false)
  const [searchError, setSearchError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/campaigns')
      .then((res) => res.json())
      .then((data) => {
        setCampaigns(data.campaigns || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!searchQuery.trim()) return

    setSearching(true)
    setSearchError(null)
    try {
      const res = await fetch(`/api/campaigns/search?q=${encodeURIComponent(searchQuery)}`)
      if (!res.ok) throw new Error(`Search failed: HTTP ${res.status}`)
      const data = await res.json()
      setSearchResults(data.results || [])
    } catch (e: any) {
      setSearchError(e.message || 'IOC Search failed')
    } finally {
      setSearching(false)
    }
  }

  return (
    <div className="container-fluid px-0">
      <div className="d-flex align-items-center justify-content-between mb-4 flex-wrap gap-2">
        <div>
          <h2 className="fw-bold mb-1" style={{ letterSpacing: '-0.02em' }}>
            <i className="fas fa-sitemap text-primary me-2"></i>
            Campaign Intelligence & Infrastructure Correlation
          </h2>
          <p className="text-muted small mb-0">
            Cluster isolated email threats into enterprise campaigns, correlate IOCs, and map adversary techniques to MITRE ATT&CK.
          </p>
        </div>
      </div>

      {/* Global IOC Search Bar */}
      <div className="card p-4 mb-4">
        <form onSubmit={handleSearch}>
          <label className="form-label fw-semibold text-main mb-2">
            <i className="fas fa-search me-2 text-cyan"></i>
            Global IOC & Evidence Search (Search IP, Domain, Hash, Sender, or Subject):
          </label>
          {searchError && (
            <div className="alert alert-danger py-1 px-3 mb-2 small">
              <i className="fas fa-exclamation-circle me-1"></i> {searchError}
            </div>
          )}
          <div className="input-group">
            <input
              type="text"
              className="form-control font-monospace"
              placeholder="e.g. 185.220.101.5 or paypa1-alerts.com or Password Reset"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <button className="btn btn-primary" type="submit" disabled={searching}>
              {searching ? (
                <>
                  <span className="spinner-border spinner-border-sm me-2"></span>Searching...
                </>
              ) : (
                <>
                  <i className="fas fa-search me-1"></i> Search IOC
                </>
              )}
            </button>
          </div>
        </form>

        {searchResults.length > 0 && (
          <div className="mt-4">
            <h6 className="fw-bold text-main mb-3">
              <i className="fas fa-filter text-warning me-2"></i>
              IOC Search Results ({searchResults.length} matches found):
            </h6>
            <div className="table-responsive">
              <table className="table table-hover align-middle mb-0">
                <thead>
                  <tr>
                    <th>Email ID</th>
                    <th>Subject</th>
                    <th>Sender</th>
                    <th>ML Prediction</th>
                    <th>Risk Score</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {searchResults.map((r, i) => (
                    <tr key={i}>
                      <td className="font-monospace text-muted small">{r.email_id}</td>
                      <td className="fw-semibold text-main">{r.subject}</td>
                      <td className="font-monospace small">{r.from}</td>
                      <td>
                        <span className={`badge ${r.ml_prediction === 'phishing' ? 'bg-danger-subtle text-danger border border-danger-subtle' : 'bg-success-subtle text-success border border-success-subtle'}`}>
                          {r.ml_prediction?.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span className="fw-bold font-monospace">{r.risk_score}/100</span>
                      </td>
                      <td className="text-muted font-monospace small">{r.timestamp}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Campaigns List */}
      <div className="card p-4">
        <h5 className="fw-bold mb-3">
          <i className="fas fa-shield-virus text-danger me-2"></i>
          Active Threat Campaigns ({campaigns.length})
        </h5>

        {loading ? (
          <div className="text-center py-5">
            <span className="spinner-border text-primary" role="status"></span>
            <p className="text-muted small mt-2">Clustering threat infrastructure...</p>
          </div>
        ) : campaigns.length === 0 ? (
          <div className="alert alert-secondary py-3 text-center">
            <i className="fas fa-info-circle me-2"></i> No active threat campaigns detected yet.
          </div>
        ) : (
          <div className="row g-3">
            {campaigns.map((c) => (
              <div key={c.campaign_id} className="col-md-6">
                <div className="card p-4 h-100 border-glow">
                  <div className="d-flex align-items-center justify-content-between mb-2">
                    <span className="badge bg-secondary font-monospace">{c.campaign_id}</span>
                    <span className={`badge ${c.risk_level === 'Critical' ? 'bg-danger text-white' : 'bg-warning text-dark'}`}>
                      {c.risk_level.toUpperCase()} THREAT
                    </span>
                  </div>

                  <h6 className="fw-bold text-main mb-1">{c.name}</h6>
                  <p className="text-muted small font-monospace mb-3">
                    Target Domain: <strong className="text-cyan">{c.sender_domain}</strong>
                  </p>

                  <div className="row g-2 mb-3">
                    <div className="col-4">
                      <div className="p-2 rounded bg-dark border border-secondary text-center">
                        <small className="text-muted d-block" style={{ fontSize: '0.7rem' }}>EMAILS</small>
                        <strong className="text-main fs-6">{c.email_count}</strong>
                      </div>
                    </div>
                    <div className="col-4">
                      <div className="p-2 rounded bg-dark border border-secondary text-center">
                        <small className="text-muted d-block" style={{ fontSize: '0.7rem' }}>PHISHING</small>
                        <strong className="text-danger fs-6">{c.phishing_count}</strong>
                      </div>
                    </div>
                    <div className="col-4">
                      <div className="p-2 rounded bg-dark border border-secondary text-center">
                        <small className="text-muted d-block" style={{ fontSize: '0.7rem' }}>AVG RISK</small>
                        <strong className="text-warning fs-6">{c.avg_risk_score}</strong>
                      </div>
                    </div>
                  </div>

                  <h6 className="fw-semibold text-muted mb-2 font-monospace" style={{ fontSize: '0.75rem' }}>
                    MITRE ATT&CK TECHNIQUES MAPPED:
                  </h6>
                  <div className="d-flex flex-wrap gap-1">
                    {c.mitre_attack.map((m) => (
                      <span key={m.id} className="badge bg-primary-subtle text-primary border border-primary-subtle font-monospace" style={{ fontSize: '0.72rem' }}>
                        {m.id}: {m.name}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
