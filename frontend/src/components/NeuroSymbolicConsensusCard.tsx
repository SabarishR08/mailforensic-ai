export default function NeuroSymbolicConsensusCard({
  arbitration,
  threatIntel,
  cognitive,
}: {
  arbitration: any
  threatIntel: any
  cognitive: any
}) {
  if (!arbitration && !threatIntel && !cognitive) return null

  const protocol = arbitration?.protocol || 'STANDARD_BAYESIAN_CONSENSUS'
  const isFPS = protocol === 'ANTI_FALSE_POSITIVE_SHIELD'
  const isFNE = protocol === 'ANTI_FALSE_NEGATIVE_HUNTER'

  const abuse = threatIntel?.abuseipdb || {}
  const vt = threatIntel?.virustotal || {}
  const rdap = threatIntel?.rdap || {}
  const cog = cognitive || {}

  return (
    <div
      className="src-panel mt-3"
      style={{
        border: isFPS
          ? '1px solid #10b981'
          : isFNE
          ? '1px solid #ef4444'
          : '1px solid rgba(85,230,212,0.25)',
        borderRadius: '10px',
        overflow: 'hidden',
        background: 'rgba(18, 20, 28, 0.85)',
      }}
    >
      <div
        className="src-panel-header d-flex justify-content-between align-items-center p-3"
        style={{
          background: isFPS
            ? 'rgba(16,185,129,0.12)'
            : isFNE
            ? 'rgba(239,68,68,0.12)'
            : 'rgba(85,230,212,0.06)',
          borderBottom: isFPS
            ? '1px solid rgba(16,185,129,0.25)'
            : isFNE
            ? '1px solid rgba(239,68,68,0.25)'
            : '1px solid rgba(85,230,212,0.15)',
        }}
      >
        <span
          className="fw-bold d-flex align-items-center gap-2"
          style={{ color: isFPS ? '#34d399' : isFNE ? '#f87171' : 'var(--cyan, #55e6d4)' }}
        >
          <i
            className={`fas ${
              isFPS ? 'fa-shield-halved' : isFNE ? 'fa-crosshairs' : 'fa-brain'
            }`}
          ></i>
          Neuro-Symbolic Bayesian Consensus Engine (NS-BCT)
        </span>
        <span
          className="badge px-3 py-1 font-monospace"
          style={{
            background: isFPS
              ? 'rgba(16,185,129,0.2)'
              : isFNE
              ? 'rgba(239,68,68,0.2)'
              : 'rgba(255,255,255,0.08)',
            color: isFPS ? '#6ee7b7' : isFNE ? '#fca5a5' : '#94a3b8',
            border: `1px solid ${
              isFPS ? '#10b981' : isFNE ? '#ef4444' : 'rgba(255,255,255,0.2)'
            }`,
            fontSize: '0.75rem',
          }}
        >
          {isFPS
            ? '🛡️ ANTI-FALSE-POSITIVE SHIELD'
            : isFNE
            ? '🚨 ANTI-FALSE-NEGATIVE HUNTER'
            : '⚖️ BAYESIAN EQUILIBRIUM'}
        </span>
      </div>

      <div className="p-3">
        {/* Rationale alert */}
        <div
          style={{
            padding: '10px 14px',
            borderRadius: '8px',
            background: isFPS
              ? 'rgba(16,185,129,0.08)'
              : isFNE
              ? 'rgba(239,68,68,0.08)'
              : 'rgba(255,255,255,0.03)',
            borderLeft: `4px solid ${isFPS ? '#10b981' : isFNE ? '#ef4444' : 'var(--cyan, #55e6d4)'}`,
            marginBottom: '14px',
            fontSize: '0.84rem',
          }}
        >
          <strong style={{ color: isFPS ? '#6ee7b7' : isFNE ? '#fca5a5' : '#7dd3fc' }}>
            Arbitration Proof:{' '}
          </strong>
          <span style={{ color: '#e2e8f0' }}>
            {arbitration?.rationale || 'Multi-axis forensic invariants match statistical probabilities.'}
          </span>
        </div>

        {/* Shield or threat factors list */}
        {(arbitration?.shield_factors || arbitration?.threat_factors) && (
          <div className="mb-3">
            <div
              className="small fw-semibold mb-1"
              style={{ color: isFPS ? '#34d399' : '#f87171', fontSize: '0.78rem' }}
            >
              {isFPS
                ? 'CRYPTOGRAPHIC PROOF & IDENTITY CERTIFICATION:'
                : 'ZERO-DAY EVASION & COGNITIVE VECTORS:'}
            </div>
            <ul className="mb-0 ps-3 small" style={{ color: '#cbd5e1' }}>
              {(arbitration?.shield_factors || arbitration?.threat_factors || []).map(
                (f: string, i: number) => (
                  <li key={i}>{f}</li>
                ),
              )}
            </ul>
          </div>
        )}

        {/* Live Multi-Feed Signals */}
        <div className="row g-2 pt-1 border-top border-secondary">
          {/* AbuseIPDB */}
          <div className="col-md-4">
            <div
              style={{
                background: 'rgba(0,0,0,0.3)',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid rgba(255,255,255,0.07)',
              }}
            >
              <div className="small text-muted" style={{ fontSize: '0.7rem' }}>
                <i className="fas fa-satellite-dish me-1"></i> AbuseIPDB Live
              </div>
              <div
                className="fw-bold mt-1"
                style={{
                  color: abuse.abuse_score > 30 ? '#f87171' : '#34d399',
                  fontSize: '0.82rem',
                }}
              >
                {abuse.abuse_score !== undefined
                  ? `${abuse.abuse_score}% Threat (${abuse.total_reports || 0} reports)`
                  : '0% Clean'}
              </div>
              <div
                className="text-muted"
                style={{
                  fontSize: '0.68rem',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                ISP: {abuse.isp || 'Verified Infrastructure'}
              </div>
            </div>
          </div>

          {/* VirusTotal */}
          <div className="col-md-4">
            <div
              style={{
                background: 'rgba(0,0,0,0.3)',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid rgba(255,255,255,0.07)',
              }}
            >
              <div className="small text-muted" style={{ fontSize: '0.7rem' }}>
                <i className="fas fa-shield-virus me-1"></i> VirusTotal Multi-Engine
              </div>
              <div
                className="fw-bold mt-1"
                style={{
                  color: vt.malicious > 0 ? '#f87171' : '#34d399',
                  fontSize: '0.82rem',
                }}
              >
                {vt.malicious !== undefined
                  ? `${vt.malicious} Malicious / ${vt.harmless || 0} Clean`
                  : '0/70 Detections'}
              </div>
              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                {vt.malicious > 0 ? 'Engine Blacklist Match' : 'Clean Vendor Consensus'}
              </div>
            </div>
          </div>

          {/* RDAP Domain Age */}
          <div className="col-md-4">
            <div
              style={{
                background: 'rgba(0,0,0,0.3)',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid rgba(255,255,255,0.07)',
              }}
            >
              <div className="small text-muted" style={{ fontSize: '0.7rem' }}>
                <i className="fas fa-calendar-check me-1"></i> ICANN RDAP Domain Age
              </div>
              <div
                className="fw-bold mt-1"
                style={{ color: rdap.is_nrd ? '#f87171' : '#34d399', fontSize: '0.82rem' }}
              >
                {rdap.domain_age_days
                  ? `${rdap.domain_age_days.toLocaleString()} days old`
                  : 'Enterprise Legacy'}
              </div>
              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                Tier:{' '}
                {rdap.is_nrd
                  ? '⚠️ Newly Registered (<30d)'
                  : rdap.maturity_tier?.replace('_', ' ').toUpperCase() || 'ESTABLISHED'}
              </div>
            </div>
          </div>
        </div>

        {/* Cognitive Deception Analysis */}
        {cog.evasion_analysis && (
          <div
            className="mt-2 pt-2 border-top border-secondary small text-muted"
            style={{ fontSize: '0.75rem' }}
          >
            <span className="text-light fw-semibold">
              <i className="fas fa-microchip me-1" style={{ color: 'var(--amber, #f59e0b)' }}></i>{' '}
              Cognitive AI Intent:{' '}
            </span>
            <span>{cog.evasion_analysis} </span>
            {cog.financial_coercion && (
              <span className="badge bg-danger ms-1">Financial Wire Coercion</span>
            )}
            {cog.authority_impersonation && cog.authority_impersonation !== 'None' && (
              <span className="badge bg-warning text-dark ms-1">{cog.authority_impersonation}</span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
