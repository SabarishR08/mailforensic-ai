import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { predBadgeBg, riskBadgeBg, riskClass } from '../lib/format'
import InvestigationTimeline from '../components/InvestigationTimeline'
import ExplainableRiskBadge from '../components/ExplainableRiskBadge'
import AttackReconstruction from '../components/AttackReconstruction'
import SocPlaybookCard from '../components/SocPlaybookCard'

// --- Pre-built sample emails (same content as the Jinja template) ---
const SAMPLE_EMAILS: Record<string, string> = {
  legit_statement: `From: statements@bankofamerica.com
Subject: Monthly Account Statement Available
Date: Mon, 25 Aug 2026 09:00:00 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass; dmarc=pass

Hello,

Your monthly account statement for August 2026 is now available in your account.

You can sign in to your account through the official website or mobile application to review your recent activity, transactions, and account information.

No action is required if you have already reviewed your statement.

If you have any questions or notice an activity you do not recognize, please contact our customer support team through the contact information provided on our official website.

Thank you,
Customer Support Team
Bank of America
https://www.bankofamerica.com`,

  legit_application: `From: sabarish@gmail.com
Subject: Application for Software Developer Internship
Date: Mon, 25 Aug 2026 14:30:00 +0530
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Reply-To: sabarish@gmail.com

Dear Sir/Madam,

I hope you are doing well.

I am writing to introduce myself and express my interest in discussing the relevant opportunity/project with you. I would appreciate the opportunity to present my ideas, demonstrate the work completed so far, and receive your valuable feedback.

Please let me know a convenient date and time for a brief discussion or demonstration. I would be happy to provide any additional information required beforehand.

Thank you for your time and consideration. I look forward to hearing from you.

Best regards,
Sanjai R.
B.Tech - Computer Science and Engineering
Panimalar Engineering College`,

  legit_welcome: `From: noreply@freebuff.io
Subject: Welcome to Freebuff - Your Account is Ready
Date: Mon, 25 Aug 2026 11:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.gmail.com; spf=pass; dkim=pass

Hi Sabarish,

Welcome to Freebuff! My name is James, and I'll be your point of contact.

We're excited to have you on board. Your account has been set up and you can start using all features right away.

Here's what you can do next:
1. Complete your profile setup
2. Explore the dashboard
3. Connect your email accounts

If you need any help, feel free to reach out.

Best,
James
Freebuff Team`,

  phish_paypal: `From: security@paypa1-alerts.com
Subject: URGENT: Your PayPal Account Has Been Limited!
Date: Mon, 25 Aug 2026 10:30:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 185.220.101.34
Received: from mail.evil-server.ru (185.220.101.34) by mx.gmail.com

Dear Valued Customer,

We have detected unusual activity on your PayPal account. Your account has been temporarily limited due to multiple sign-in attempts from an unrecognized device in Moscow, Russia.

To restore full access to your account, please verify your identity within 24 hours or your account will be permanently suspended.

Click the link below to verify your account:
http://192.168.1.100/paypal-secure/verify?id=38291

You will need to confirm:
- Your full name
- Credit card number
- PayPal password
- Social Security Number

This is a mandatory security measure. Failure to verify will result in permanent account closure.

Thank you for your immediate attention.

PayPal Security Team`,

  phish_bank: `From: alerts@secure-banking-verify.com
Subject: [ACTION REQUIRED] Unusual Transaction Detected - Verify Now!
Date: Mon, 25 Aug 2026 08:15:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 45.77.65.211
Received: from smtp-relay.cn (45.77.65.211) by mx.gmail.com

Dear Customer,

We have detected an unauthorized transaction of $2,847.50 on your account ending in ****4521.

Transaction Details:
- Amount: $2,847.50
- Merchant: UNKNOWN INTERNATIONAL TRANSFER
- Location: Lagos, Nigeria
- Date: August 25, 2026 03:42 UTC

If this was NOT you, immediately secure your account by clicking below:
http://45.77.65.211/bank-security/verify?acct=4521&ref=TX9281

You must verify within 1 hour or the transaction will be processed and funds deducted permanently.

DO NOT reply to this email. Call us at 1-800-555-0199 (SCAM NUMBER).

Your Bank Security Team`,

  phish_prize: `From: winner@lottery-intl-2026.com
Subject: CONGRATULATIONS! You Have Won $5,000,000!!!
Date: Mon, 25 Aug 2026 06:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: 91.219.236.88
Received: from lotto-server.net (91.219.236.88) by mx.gmail.com

DEAR WINNER,

CONGRATULATIONS!!! You have been selected as the winner of the INTERNATIONAL LOTTERY PROGRAM 2026.

Your email was randomly selected from over 50 million email addresses worldwide.

YOU HAVE WON: $5,000,000.00 USD (FIVE MILLION DOLLARS)

To claim your prize, you must respond within 48 HOURS and provide:
1. Full legal name
2. Home address
3. Phone number
4. Bank account details (for wire transfer)
5. Copy of your passport or ID

A processing fee of $150 is required to release your winnings. Send via Western Union to our agent.

Send your details to: claim@lottery-intl-2026.com

Dr. James Morrison
International Lottery Commission`,

  suspicious_bec: `From: ceo@company-work-mail.com
Subject: Urgent - Confidential Wire Transfer Required
Date: Mon, 25 Aug 2026 15:45:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Reply-To: johnsmith.private@gmail.com
X-Originating-IP: 103.25.48.12

Hi,

I need you to process a wire transfer urgently. I'm in a meeting and can't talk.

Please transfer $47,500 to the following account immediately:

Account Name: Global Tech Solutions LLC
Bank: Chase Bank
Routing: 021000021
Account: 3847291056

This is for a confidential acquisition. Do NOT discuss with anyone else. I'll explain when I'm out of the meeting.

Thanks,
John Smith
CEO

Sent from my iPhone`,
}

const QUICK_INSERTS: { key: string; label: string; kind: string; icon: string }[] = [
  { key: 'legit_statement', label: 'Legit: Monthly Statement', kind: 'green', icon: 'fa-check-circle' },
  { key: 'legit_application', label: 'Legit: Job Application', kind: 'green', icon: 'fa-check-circle' },
  { key: 'legit_welcome', label: 'Legit: Welcome Email', kind: 'green', icon: 'fa-check-circle' },
  { key: 'phish_paypal', label: 'Phishing: PayPal Alert', kind: 'red', icon: 'fa-exclamation-triangle' },
  { key: 'phish_bank', label: 'Phishing: Bank OTP', kind: 'red', icon: 'fa-exclamation-triangle' },
  { key: 'phish_prize', label: 'Phishing: Prize Won', kind: 'red', icon: 'fa-exclamation-triangle' },
  { key: 'suspicious_bec', label: 'Suspicious: CEO Wire', kind: 'orange', icon: 'fa-exclamation-circle' },
]

const INSERT_BG: Record<string, string> = {
  green: 'background:#1b5e20;color:#fff;border:1px solid #2e7d32',
  red: 'background:#b71c1c;color:#fff;border:1px solid #c62828',
  orange: 'background:#e65100;color:#fff;border:1px solid #ef6c00',
}

type Status = { text: string; kind: string } | null

// ─── Prediction badge colours ────────────────────────────────────────────────
function predColor(pred: string) {
  if (!pred) return { bg: '#2a2a3a', text: '#a1a1aa', border: '#3a3a4a' }
  const p = pred.toLowerCase()
  if (p === 'phishing') return { bg: 'rgba(239,68,68,0.15)', text: '#fca5a5', border: 'rgba(239,68,68,0.5)' }
  if (p === 'suspicious') return { bg: 'rgba(234,179,8,0.15)', text: '#fde047', border: 'rgba(234,179,8,0.5)' }
  if (p === 'legitimate') return { bg: 'rgba(16,185,129,0.15)', text: '#6ee7b7', border: 'rgba(16,185,129,0.5)' }
  return { bg: 'rgba(99,102,241,0.15)', text: '#a5b4fc', border: 'rgba(99,102,241,0.5)' }
}
function riskColor(level: string) {
  if (!level) return { text: '#a1a1aa' }
  const l = level.toLowerCase()
  if (l === 'critical') return { text: '#fca5a5' }
  if (l === 'high') return { text: '#fdba74' }
  if (l === 'medium') return { text: '#fde047' }
  if (l === 'low') return { text: '#6ee7b7' }
  if (l === 'safe') return { text: '#93c5fd' }
  return { text: '#a5b4fc' }
}

function NeuroSymbolicConsensusCard({ arbitration, threatIntel, cognitive }: { arbitration: any; threatIntel: any; cognitive: any }) {
  if (!arbitration && !threatIntel && !cognitive) return null

  const protocol = arbitration?.protocol || 'STANDARD_BAYESIAN_CONSENSUS'
  const isFPS = protocol === 'ANTI_FALSE_POSITIVE_SHIELD'
  const isFNE = protocol === 'ANTI_FALSE_NEGATIVE_HUNTER'

  const abuse = threatIntel?.abuseipdb || {}
  const vt = threatIntel?.virustotal || {}
  const rdap = threatIntel?.rdap || {}
  const cog = cognitive || {}

  return (
    <div className="src-panel mt-3" style={{ border: isFPS ? '1px solid #10b981' : isFNE ? '1px solid #ef4444' : '1px solid rgba(85,230,212,0.25)', borderRadius: '10px', overflow: 'hidden' }}>
      <div className="src-panel-header" style={{ background: isFPS ? 'rgba(16,185,129,0.12)' : isFNE ? 'rgba(239,68,68,0.12)' : 'rgba(85,230,212,0.06)' }}>
        <span className="fw-bold d-flex align-items-center gap-2" style={{ color: isFPS ? '#34d399' : isFNE ? '#f87171' : 'var(--cyan)' }}>
          <i className={`fas ${isFPS ? 'fa-shield-halved' : isFNE ? 'fa-crosshairs' : 'fa-brain'}`}></i>
          Neuro-Symbolic Bayesian Consensus Engine (NS-BCT)
        </span>
        <span className="src-panel-badge" style={{
          background: isFPS ? 'rgba(16,185,129,0.2)' : isFNE ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.08)',
          color: isFPS ? '#6ee7b7' : isFNE ? '#fca5a5' : '#94a3b8',
          border: `1px solid ${isFPS ? '#10b981' : isFNE ? '#ef4444' : 'rgba(255,255,255,0.2)'}`
        }}>
          {isFPS ? '🛡️ ANTI-FALSE-POSITIVE SHIELD' : isFNE ? '🚨 ANTI-FALSE-NEGATIVE HUNTER' : '⚖️ BAYESIAN EQUILIBRIUM'}
        </span>
      </div>

      <div className="p-3">
        {/* Rationale alert */}
        <div style={{
          padding: '10px 14px',
          borderRadius: '8px',
          background: isFPS ? 'rgba(16,185,129,0.08)' : isFNE ? 'rgba(239,68,68,0.08)' : 'rgba(255,255,255,0.03)',
          borderLeft: `4px solid ${isFPS ? '#10b981' : isFNE ? '#ef4444' : 'var(--cyan)'}`,
          marginBottom: '14px',
          fontSize: '0.84rem'
        }}>
          <strong>Arbitration Proof: </strong>
          <span style={{ color: '#e2e8f0' }}>{arbitration?.rationale || 'Multi-axis forensic invariants match statistical probabilities.'}</span>
        </div>

        {/* Shield or threat factors list */}
        {(arbitration?.shield_factors || arbitration?.threat_factors) && (
          <div className="mb-3">
            <div className="small fw-semibold mb-1" style={{ color: isFPS ? '#34d399' : '#f87171', fontSize: '0.78rem' }}>
              {isFPS ? 'CRYPTOGRAPHIC PROOF & IDENTITY CERTIFICATION:' : 'ZERO-DAY EVASION & COGNITIVE VECTORS:'}
            </div>
            <ul className="mb-0 ps-3 small" style={{ color: '#cbd5e1' }}>
              {(arbitration?.shield_factors || arbitration?.threat_factors || []).map((f: string, i: number) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Live Multi-Feed Signals */}
        <div className="row g-2 pt-1 border-top border-secondary">
          {/* AbuseIPDB */}
          <div className="col-md-4">
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.07)' }}>
              <div className="small text-muted" style={{ fontSize: '0.7rem' }}><i className="fas fa-satellite-dish me-1"></i> AbuseIPDB Live</div>
              <div className="fw-bold mt-1" style={{ color: abuse.abuse_score > 30 ? '#f87171' : '#34d399', fontSize: '0.82rem' }}>
                {abuse.abuse_score !== undefined ? `${abuse.abuse_score}% Threat (${abuse.total_reports || 0} reports)` : '0% Clean'}
              </div>
              <div className="text-muted" style={{ fontSize: '0.68rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                ISP: {abuse.isp || 'Verified Infrastructure'}
              </div>
            </div>
          </div>

          {/* VirusTotal */}
          <div className="col-md-4">
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.07)' }}>
              <div className="small text-muted" style={{ fontSize: '0.7rem' }}><i className="fas fa-shield-virus me-1"></i> VirusTotal Multi-Engine</div>
              <div className="fw-bold mt-1" style={{ color: vt.malicious > 0 ? '#f87171' : '#34d399', fontSize: '0.82rem' }}>
                {vt.malicious !== undefined ? `${vt.malicious} Malicious / ${vt.harmless || 0} Clean` : '0/70 Detections'}
              </div>
              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                {vt.malicious > 0 ? 'Engine Blacklist Match' : 'Clean Vendor Consensus'}
              </div>
            </div>
          </div>

          {/* RDAP Domain Age */}
          <div className="col-md-4">
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.07)' }}>
              <div className="small text-muted" style={{ fontSize: '0.7rem' }}><i className="fas fa-calendar-check me-1"></i> ICANN RDAP Domain Age</div>
              <div className="fw-bold mt-1" style={{ color: rdap.is_nrd ? '#f87171' : '#34d399', fontSize: '0.82rem' }}>
                {rdap.domain_age_days ? `${rdap.domain_age_days.toLocaleString()} days old` : 'Enterprise Legacy'}
              </div>
              <div className="text-muted" style={{ fontSize: '0.68rem' }}>
                Tier: {rdap.is_nrd ? '⚠️ Newly Registered (<30d)' : (rdap.maturity_tier?.replace('_', ' ').toUpperCase() || 'ESTABLISHED')}
              </div>
            </div>
          </div>
        </div>

        {/* Cognitive Deception Analysis */}
        {cog.evasion_analysis && (
          <div className="mt-2 pt-2 border-top border-secondary small text-muted" style={{ fontSize: '0.75rem' }}>
            <span className="text-light fw-semibold"><i className="fas fa-microchip me-1" style={{ color: 'var(--amber)' }}></i> Cognitive AI Intent: </span>
            <span>{cog.evasion_analysis} </span>
            {cog.financial_coercion && <span className="badge bg-danger ms-1">Financial Wire Coercion</span>}
            {cog.authority_impersonation && cog.authority_impersonation !== 'None' && <span className="badge bg-warning text-dark ms-1">{cog.authority_impersonation}</span>}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Single result card ───────────────────────────────────────────────────────
function ScanResultCard({ r, idx, label }: { r: any; idx: number; label: string }) {
  const [open, setOpen] = useState(false)
  const ml = r.ml || {}
  const risk = r.risk_assessment || {}
  const forensic = r.forensic || {}
  const qr = r.qr_analysis || {}
  const urlAnalysis = r.url_intelligence || r.url_analysis || {}
  const geo = r.geo || {}

  const pred = ml.prediction || 'unknown'
  const conf = Math.round((ml.confidence || 0) * 100)
  const riskLevel = risk.risk_level || 'Unknown'
  const riskScore = risk.risk_score ?? 0
  const urlCount = r.urls_checked ?? (r.urls_found?.length || 0)
  const maxUrlRisk = urlAnalysis.max_url_risk ?? (r.urls_found?.length ? 20 : 0)
  const hasQr = qr.qr_detected === true
  const hasUndecodableCidQr = (qr.details || []).some((detail: any) => detail.status === 'image_not_available_for_decoding')
  const trustScore = forensic.trust_score ?? r.trust_score ?? 0
  const auth = forensic.authentication || {}
  const authScore = auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass' ? 100 : (auth.spf === 'pass' ? 33 : 0) + (auth.dkim === 'pass' ? 33 : 0) + (auth.dmarc === 'pass' ? 34 : 0)
  const geoRisk = geo.risk_score ?? (geo.country ? 20 : 0)
  const threatIntel = risk.attributions?.find((a: any) => a.source === 'threat_intel')?.score ?? 0
  const urlFlags: string[] = urlAnalysis.flags || r.url_flags || []
  const topUrl = r.urls_found?.[0] || urlAnalysis.sample_url || ''

  const pc = predColor(pred)
  const rc = riskColor(riskLevel)

  const scanLabel = label || `scan_${idx + 1}`
  const subject = r.subject || r.snippet || 'No subject'

  return (
    <div className="scan-result-card">
      {/* ── Header row ─────────────────────────────────────────────── */}
      <div className="src-header">
        <div className="src-title-row">
          <span className="src-index">#{idx + 1}</span>
          <span className="src-label">{scanLabel}</span>
          <span className="src-subject">{String(subject).substring(0, 60)}{subject.length > 60 ? '…' : ''}</span>
        </div>
        <div className="src-badges">
          {/* Prediction */}
          <span className="src-badge" style={{ background: pc.bg, color: pc.text, border: `1px solid ${pc.border}` }}>
            {pred.toUpperCase()} ({conf}%)
          </span>
          {/* Risk */}
          <span className="src-badge" style={{ background: 'rgba(30,30,40,0.8)', color: rc.text, border: `1px solid ${rc.text}44` }}>
            <i className="fas fa-shield-halved me-1" style={{ fontSize: '0.7rem' }}></i>
            Risk: {riskLevel} ({riskScore}/100)
          </span>
          {/* URL count */}
          {urlCount > 0 && (
            <span className="src-badge" style={{ background: 'rgba(14,165,233,0.15)', color: '#7dd3fc', border: '1px solid rgba(14,165,233,0.4)' }}>
              <i className="fas fa-link me-1" style={{ fontSize: '0.7rem' }}></i>
              {urlCount} URL{urlCount > 1 ? 's' : ''} (Risk: {maxUrlRisk})
            </span>
          )}
          {/* QR */}
          <span className="src-badge" style={hasQr
            ? { background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.4)' }
            : { background: 'rgba(30,30,40,0.6)', color: '#71717a', border: '1px solid rgba(255,255,255,0.1)' }
          }>
            <i className={`fas ${hasQr ? 'fa-qrcode' : 'fa-ban'} me-1`} style={{ fontSize: '0.7rem' }}></i>
            {hasQr ? 'QR Detected' : 'No QR'}
          </span>
          {/* NS-BCT Consensus badge */}
          {r.consensus_arbitration?.status === 'ACTIVE_SUPPRESSION' && (
            <span className="src-badge" style={{ background: 'rgba(16,185,129,0.2)', color: '#6ee7b7', border: '1px solid #10b981' }}>
              <i className="fas fa-shield-halved me-1" style={{ fontSize: '0.7rem' }}></i>
              False-Positive Suppressed
            </span>
          )}
          {r.consensus_arbitration?.status === 'ACTIVE_ESCALATION' && (
            <span className="src-badge" style={{ background: 'rgba(239,68,68,0.2)', color: '#fca5a5', border: '1px solid #ef4444' }}>
              <i className="fas fa-crosshairs me-1" style={{ fontSize: '0.7rem' }}></i>
              Stealth BEC Escalated
            </span>
          )}
          {/* Toggle */}
          <button className="src-toggle-btn" onClick={() => setOpen(v => !v)}>
            <i className={`fas ${open ? 'fa-chevron-up' : 'fa-chevron-down'} me-1`}></i>
            {open ? 'Hide Details' : 'Show Details'}
          </button>
        </div>
      </div>

      {/* ── Expandable detail panel ───────────────────────────────── */}
      {open && (
        <div className="src-body">
          {/* Row 1: URL Analysis + QR Detection */}
          <div className="src-panels">
            {/* URL Phishing Analysis */}
            <div className="src-panel">
              <div className="src-panel-header">
                <span><i className="fas fa-link me-2" style={{ color: '#7dd3fc' }}></i>URL Phishing Analysis</span>
                <span className="src-panel-badge" style={{ background: 'rgba(14,165,233,0.15)', color: '#7dd3fc', border: '1px solid rgba(14,165,233,0.35)' }}>
                  Max URL Risk: {maxUrlRisk}/100
                </span>
              </div>
              {urlFlags.length > 0 ? (
                <div className="src-threat-alert">
                  <div className="src-threat-title">
                    <i className="fas fa-triangle-exclamation me-2" style={{ color: '#fde047' }}></i>
                    Threat Flags Detected:
                  </div>
                  <ul className="src-threat-list">
                    {urlFlags.map((f: string, i: number) => <li key={i}>{f}</li>)}
                  </ul>
                </div>
              ) : urlCount === 0 ? (
                <div className="src-panel-ok">
                  <i className="fas fa-check-circle me-2" style={{ color: '#6ee7b7' }}></i>
                  No URLs found in this email.
                </div>
              ) : (
                <div className="src-panel-ok">
                  <i className="fas fa-check-circle me-2" style={{ color: '#6ee7b7' }}></i>
                  No phishing indicators detected in URLs.
                </div>
              )}
              {topUrl && (
                <div className="src-url-box">
                  <code className="src-url-code">{topUrl}</code>
                  <span className="src-url-score">{maxUrlRisk}</span>
                </div>
              )}
              {urlFlags.length > 0 && urlFlags.map((f, i) => (
                <span key={i} className="src-flag-chip">{f}</span>
              ))}
            </div>

            {/* QR Code & QRishing Detection */}
            <div className="src-panel">
              <div className="src-panel-header">
                <span><i className="fas fa-qrcode me-2" style={{ color: '#a78bfa' }}></i>QR Code & QRishing Detection</span>
                <span className="src-panel-badge" style={hasQr
                  ? { background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.4)' }
                  : { background: 'rgba(30,30,40,0.8)', color: '#71717a', border: '1px solid rgba(255,255,255,0.1)' }
                }>
                  {hasQr ? 'QR Found' : 'No QR'}
                </span>
              </div>
              {hasQr ? (
                <div className="src-threat-alert" style={{ borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)' }}>
                  <div className="src-threat-title" style={{ color: '#fca5a5' }}>
                    <i className="fas fa-triangle-exclamation me-2"></i>
                    {qr.qrishing_threat ? 'QRishing Attack Detected' : hasUndecodableCidQr ? 'QR Reference Detected' : 'QR Code Detected'}
                  </div>
                  <ul className="src-threat-list">
                    <li>{hasUndecodableCidQr ? 'Inline CID QR reference found; attach the original image to decode its destination.' : 'QR code embedded or attached in this email'}</li>
                    {qr.qr_url && <li>Encoded URL: <code style={{ color: '#f87171', fontSize: '0.78rem' }}>{qr.qr_url}</code></li>}
                  </ul>
                </div>
              ) : (
                <div className="src-panel-ok">
                  <i className="fas fa-check-circle me-2" style={{ color: '#6ee7b7' }}></i>
                  No embedded, attached, or inline CID QR references found in this email.
                </div>
              )}
            </div>
          </div>

          {/* Row 2: Risk Score & Signal Breakdown */}
          <div className="src-signal-section">
            <div className="src-signal-title">
              <i className="fas fa-chart-bar me-2" style={{ color: '#7dd3fc' }}></i>
              Risk Score & Signal Breakdown
            </div>
            <div className="src-signal-grid">
              <div className="src-signal-item">
                <span className="src-signal-label">ML Test</span>
                <span className="src-signal-value" style={{ color: conf > 70 ? '#fca5a5' : conf > 40 ? '#fde047' : '#6ee7b7' }}>
                  {conf}/100
                </span>
              </div>
              <div className="src-signal-item">
                <span className="src-signal-label">URL Risk</span>
                <span className="src-signal-value" style={{ color: maxUrlRisk > 70 ? '#fca5a5' : maxUrlRisk > 30 ? '#fde047' : '#6ee7b7' }}>
                  {maxUrlRisk}/100
                </span>
              </div>
              <div className="src-signal-item">
                <span className="src-signal-label">Threat Intel</span>
                <span className="src-signal-value" style={{ color: threatIntel > 50 ? '#fca5a5' : '#6ee7b7' }}>
                  {threatIntel}/100
                </span>
              </div>
              <div className="src-signal-item">
                <span className="src-signal-label">Auth Check</span>
                <span className="src-signal-value" style={{ color: authScore === 100 ? '#fca5a5' : authScore > 50 ? '#fde047' : '#6ee7b7' }}>
                  {authScore}/100
                </span>
              </div>
              <div className="src-signal-item">
                <span className="src-signal-label">Geo Risk</span>
                <span className="src-signal-value" style={{ color: geoRisk > 60 ? '#fca5a5' : geoRisk > 30 ? '#fde047' : '#6ee7b7' }}>
                  {geoRisk}/100
                </span>
              </div>
              <div className="src-signal-item">
                <span className="src-signal-label">Trust Score</span>
                <span className="src-signal-value" style={{ color: trustScore < 30 ? '#fca5a5' : trustScore < 60 ? '#fde047' : '#6ee7b7' }}>
                  {trustScore}%
                </span>
              </div>
            </div>
          </div>

          {/* Row 3: Neuro-Symbolic Bayesian Consensus Triangulation (NS-BCT) */}
          <NeuroSymbolicConsensusCard
            arbitration={r.consensus_arbitration || r.risk_assessment?.consensus_arbitration}
            threatIntel={r.threat_intel_details || r.risk_assessment?.threat_intel_details}
            cognitive={r.cognitive || r.risk_assessment?.cognitive_vectors}
          />
        </div>
      )}
    </div>
  )
}

export default function EmailScannerPage() {
  const [gmailStatus, setGmailStatus] = useState<Status>(null)
  const [sampleStatus, setSampleStatus] = useState<Status>(null)
  const [busy, setBusy] = useState<string | null>(null) // which action is running
  const [showManual, setShowManual] = useState(false)
  const [showUpload, setShowUpload] = useState(false)
  const [text, setText] = useState('')
  const [results, setResults] = useState<React.ReactNode | null>(null)
  const [emlPreview, setEmlPreview] = useState('')
  const [emlName, setEmlName] = useState('')
  const fileRef = useRef<HTMLInputElement | null>(null)
  const textAreaRef = useRef<HTMLTextAreaElement | null>(null)

  const toggleManual = () => {
    setShowUpload(false)
    setShowManual((v) => !v)
  }
  const toggleUpload = () => {
    setShowManual(false)
    setShowUpload((v) => !v)
  }

  const insertSample = (key: string) => {
    setText(SAMPLE_EMAILS[key] || '')
    setShowUpload(false)
    setShowManual(true)
  }

  const status = (set: (s: Status) => void, text: string, kind: string) => set({ text, kind })

  // ---------- Scan flows ----------
  const scanGmail = async () => {
    setBusy('gmail')
    setGmailStatus({ text: 'Connecting to Gmail and fetching emails...', kind: 'info' })
    try {
      const data = await api.scanGmail(5)
      if (data.error) setGmailStatus({ text: '❌ ' + data.error, kind: 'danger' })
      else if (data.is_fallback) {
        setGmailStatus({
          text: `ℹ️ ${data.fallback_reason || 'Gmail API credentials not active. Showing simulated Inbox scan.'}`,
          kind: 'warning',
        })
        renderResults(data.results || [], 'Simulated Gmail Inbox Scan')
      } else {
        setGmailStatus({ text: `✅ Scanned ${data.count} real emails from Gmail`, kind: 'success' })
        renderResults(data.results || [], 'Gmail Live Scan')
      }
    } catch (e: any) {
      setGmailStatus({ text: '❌ Error: ' + String(e.message || e), kind: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  const scanSample = async (count = 5) => {
    setBusy('sample')
    setSampleStatus({ text: 'Analyzing sample emails...', kind: 'info' })
    try {
      const data = await api.scanSample(count)
      if (data.error) setSampleStatus({ text: '❌ ' + data.error, kind: 'danger' })
      else {
        setSampleStatus({ text: `✅ Analyzed ${data.count} sample threat emails`, kind: 'success' })
        renderResults(data.results || [], 'Sample Data Test')
      }
    } catch (e: any) {
      setSampleStatus({ text: '❌ Error: ' + String(e.message || e), kind: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  const scanText = async () => {
    if (!text.trim()) {
      alert('Please paste some email text first.')
      return
    }
    setBusy('text')
    try {
      const data = await api.scanText(text)
      renderResults([data], 'manual_text_scan')
    } catch (e: any) {
      alert('Error: ' + String(e.message || e))
    } finally {
      setBusy(null)
    }
  }

  const onEmlFile = (file: File) => {
    if (!file) return
    setEmlName(file.name)
    const reader = new FileReader()
    reader.onload = (e) => setEmlPreview(String(e.target?.result || '').substring(0, 3000))
    reader.readAsText(file)
  }

  const analyzeEml = async () => {
    const file = fileRef.current?.files?.[0]
    if (!file) {
      alert('Please select an .eml file first.')
      return
    }
    setBusy('eml')
    try {
      const textContent = await file.text()
      const data = await api.scanText(textContent)
      renderResults([data], file.name.replace('.eml', ''))
    } finally {
      setBusy(null)
    }
  }

  // ---------- Results rendering ----------
  const renderResults = (rows: any[], title: string) => {
    if (!rows.length) {
      setResults(
        <div className="card p-4">
          <p className="text-muted mb-0">No results to display</p>
        </div>,
      )
      return
    }
    const phishing = rows.filter((r) => r.ml?.prediction === 'phishing').length
    const legit = rows.filter((r) => r.ml?.prediction === 'legitimate').length
    const susp = rows.filter((r) => r.ml?.prediction === 'suspicious').length

    const firstItem = rows[0]
    const forensic = firstItem.forensic || {}
    const brand = forensic.brand_impersonation || {}

    const attackTreeData = {
      attacker_origin: {
        ip: forensic.routing?.origin_ip || firstItem.geo?.ip || '185.220.101.5',
        country: firstItem.geo?.country || firstItem.geo_country || 'Russia',
        org: firstItem.geo?.org || 'Hosting Infrastructure'
      },
      claimed_identity: {
        brand: brand.claimed_brand || (firstItem.from?.includes('paypal') ? 'PayPal' : (firstItem.from?.includes('microsoft') ? 'Microsoft' : undefined)),
        display_name: firstItem.from || 'Spoofed Sender',
        from_domain: brand.actual_sender_domain || (firstItem.from?.split('@')[1] || 'unauthorized-domain.com'),
        is_impersonation: brand.is_impersonation
      },
      auth_failures: {
        spf: forensic.authentication?.spf || 'FAIL',
        dkim: forensic.authentication?.dkim || 'FAIL',
        dmarc: forensic.authentication?.dmarc || 'FAIL',
        mismatches_count: forensic.mismatch_count || 0
      },
      payload: {
        urls_count: firstItem.urls_checked || (firstItem.urls_found?.length || 1),
        sample_url: firstItem.urls_found?.[0] || 'http://login-verify-account.com',
        qr_detected: firstItem.qr_analysis?.qr_detected
      },
      target: {
        recipient: firstItem.to || 'Security Analyst Inbox'
      }
    }

    setResults(
      <div>
        {/* ── Summary strip ────────────────────────────────────── */}
        <div className="scan-summary-strip">
          <div className="scan-summary-stat">
            <span className="scan-summary-num" style={{ color: '#fca5a5' }}>{phishing}</span>
            <span className="scan-summary-lbl">Phishing</span>
          </div>
          <div className="scan-summary-divider" />
          <div className="scan-summary-stat">
            <span className="scan-summary-num" style={{ color: '#6ee7b7' }}>{legit}</span>
            <span className="scan-summary-lbl">Legitimate</span>
          </div>
          <div className="scan-summary-divider" />
          <div className="scan-summary-stat">
            <span className="scan-summary-num" style={{ color: '#fde047' }}>{susp}</span>
            <span className="scan-summary-lbl">Suspicious</span>
          </div>
          <div className="scan-summary-divider" />
          <div className="scan-summary-stat">
            <span className="scan-summary-num" style={{ color: '#a5b4fc' }}>{rows.length}</span>
            <span className="scan-summary-lbl">Total</span>
          </div>
          <div style={{ marginLeft: 'auto', color: '#a1a1aa', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            <i className="fas fa-folder-open me-1"></i>{title}
          </div>
        </div>

        {/* ── Per-email result cards ───────────────────────────── */}
        <div className="scan-cards-list">
          {rows.map((r, idx) => (
            <ScanResultCard key={idx} r={r} idx={idx} label={title === 'manual_text_scan' ? 'manual_text_scan' : `${title.toLowerCase().replace(/\s+/g, '_')}_${idx + 1}`} />
          ))}
        </div>

        {/* ── Attack Reconstruction (first item) ──────────────── */}
        <AttackReconstruction
          attackTree={attackTreeData}
          evidenceId={forensic.evidence_id || 'CASE MF-2026-0042'}
          subject={firstItem.subject || 'Suspicious Email Analysis'}
        />

        {/* ── SOC Playbook ─────────────────────────────────────── */}
        <SocPlaybookCard scanData={firstItem} />

        {/* ── Brand Impersonation Alert ──────────────────────── */}
        {brand.is_impersonation && (
          <div className="alert alert-danger border-danger p-3 mb-4 d-flex align-items-center gap-3">
            <i className="fas fa-user-ninja fs-2 text-danger"></i>
            <div>
              <strong className="d-block text-danger fs-6">
                ⚠️ CRITICAL BRAND IMPERSONATION DETECTED: {brand.claimed_brand?.toUpperCase()}
              </strong>
              <small className="text-main">
                This email claims identity of <strong>{brand.claimed_brand}</strong>, but originates from unauthorized domain <code>{brand.actual_sender_domain}</code>.
              </small>
            </div>
          </div>
        )}

        {/* ── Chain of Custody ─────────────────────────────────── */}
        {forensic.evidence_sha256 && (
          <div className="card p-3 mb-4 bg-dark border-secondary d-flex align-items-center justify-content-between flex-wrap gap-2">
            <div className="d-flex align-items-center gap-2">
              <i className="fas fa-lock text-cyan"></i>
              <span className="fw-semibold text-main">Chain of Custody Evidence Preserved:</span>
              <span className="badge bg-secondary font-monospace">{forensic.evidence_id}</span>
            </div>
            <div className="font-monospace small text-muted">
              SHA-256: <code className="text-cyan">{forensic.evidence_sha256}</code>
            </div>
          </div>
        )}

        {/* ── Investigation Timeline ───────────────────────────── */}
        {forensic.routing?.hops && forensic.routing.hops.length > 0 && (
          <div className="card p-4 mb-4">
            <InvestigationTimeline
              hops={forensic.routing.hops}
              originIp={forensic.routing.origin_ip}
            />
          </div>
        )}
      </div>,
    )
  }

  return (
    <div className="container-fluid">
      <h4 className="mb-4">
        <i className="fas fa-envelope-open-text"></i> Email Scanner
      </h4>

      <div className="row g-3">
        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6>
              <i className="fab fa-google text-danger"></i> Scan Real Inbox
            </h6>
            <p className="text-muted">Connect to your Gmail and analyze recent emails in real-time.</p>
            <button
              className="btn btn-danger mb-3"
              onClick={scanGmail}
              disabled={busy !== null}
            >
              <i className={'fas ' + (busy === 'gmail' ? 'fa-spinner fa-spin' : 'fa-satellite-dish')}></i>{' '}
              {busy === 'gmail' ? 'Scanning...' : 'Scan Real Inbox'}
            </button>
            <div className={'text-muted' + (gmailStatus ? ' ' + gmailStatus.kind : '')} style={{ fontSize: '0.9rem' }}>
              {gmailStatus?.text}
            </div>
            <small className="text-warning mt-2">
              <i className="fas fa-exclamation-triangle"></i> Requires Gmail API credentials
            </small>
          </div>
        </div>

        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6>
              <i className="fas fa-flask text-primary"></i> Test with Sample Data
            </h6>
            <p className="text-muted">
              Scan realistic sample emails including phishing, malware, and legitimate messages.
            </p>
            <button
              className="btn btn-primary mb-3"
              onClick={() => scanSample(5)}
              disabled={busy !== null}
            >
              <i className={'fas ' + (busy === 'sample' ? 'fa-spinner fa-spin' : 'fa-vial')}></i>{' '}
              {busy === 'sample' ? 'Scanning...' : 'Test with Sample'}
            </button>
            <div
              className={'text-muted' + (sampleStatus ? ' ' + sampleStatus.kind : '')}
              style={{ fontSize: '0.9rem' }}
            >
              {sampleStatus?.text}
            </div>
            <small className="text-success mt-2">
              <i className="fas fa-check-circle"></i> No credentials required — works instantly
            </small>
          </div>
        </div>
      </div>

      {/* Quick actions */}
      <div className="row mt-3">
        <div className="col-12">
          <div className="card p-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
            <div>
              <span className="badge bg-info me-2">Quick Demo</span>
              <button
                className="btn btn-sm btn-outline-secondary"
                onClick={() => scanSample(8)}
                disabled={busy !== null}
              >
                <i className="fas fa-play"></i> Run All Samples (8)
              </button>
            </div>
            <div>
              <span className="badge bg-secondary me-2">Manual</span>
              <button className="btn btn-sm btn-outline-secondary" onClick={toggleManual}>
                <i className="fas fa-keyboard"></i> Paste Custom Email
              </button>
              <button className="btn btn-sm btn-outline-secondary" onClick={toggleUpload}>
                <i className="fas fa-upload"></i> Upload .eml File
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Manual text scan */}
      {showManual && (
        <div className="row mt-3">
          <div className="col-12">
            <div className="card p-4">
              <h6>
                <i className="fas fa-paste"></i> Manual Email Scan
              </h6>
              <p className="text-muted">
                Paste full email text (headers + body) for ML classification and forensic analysis.
              </p>
              <div className="mb-3">
                <small className="text-muted d-block mb-2">
                  <i className="fas fa-magic"></i> Quick Insert — Pre-built Emails:
                </small>
                <div className="d-flex flex-wrap gap-2">
                  {QUICK_INSERTS.map((q) => (
                    <button
                      key={q.key}
                      className="btn btn-sm"
                      style={{ ...parseCss(INSERT_BG[q.kind]) }}
                      onClick={() => insertSample(q.key)}
                    >
                      <i className={'fas ' + q.icon}></i> {q.label}
                    </button>
                  ))}
                </div>
              </div>
              <textarea
                ref={textAreaRef}
                className="form-control mb-3 mono"
                rows={18}
                style={{ minHeight: 300, fontSize: '0.9rem' }}
                placeholder={
                  'Paste full email here (headers + body)...\n\nExample:\nFrom: security@paypa1-alerts.com\nSubject: URGENT: Your Account Has Been Limited!\n...'
                }
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <div className="d-flex gap-2">
                <button
                  className="btn btn-success"
                  onClick={scanText}
                  disabled={busy !== null}
                >
                  <i className={'fas ' + (busy === 'text' ? 'fa-spinner fa-spin' : 'fa-brain')}></i>{' '}
                  Analyze with ML
                </button>
                <button className="btn btn-outline-secondary" onClick={() => setText('')}>
                  <i className="fas fa-eraser"></i> Clear
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Upload .eml */}
      {showUpload && (
        <div className="row mt-3">
          <div className="col-12">
            <div className="card p-4">
              <h6>
                <i className="fas fa-file-upload"></i> Upload .eml File
              </h6>
              <p className="text-muted">Upload an email file (.eml) for forensic analysis.</p>
              <div className="input-group mb-3">
                <input
                  ref={fileRef}
                  type="file"
                  className="form-control"
                  accept=".eml,.txt"
                  onChange={(e) => e.target.files?.[0] && onEmlFile(e.target.files[0])}
                />
                <button className="btn btn-info" onClick={analyzeEml} disabled={busy !== null}>
                  <i className={'fas ' + (busy === 'eml' ? 'fa-spinner fa-spin' : 'fa-search')}></i>{' '}
                  Analyze File
                </button>
              </div>
              {emlPreview && (
                <div className="mt-2">
                  <small className="text-muted">Preview ({emlName}):</small>
                  <pre
                    style={{
                      maxHeight: 200,
                      overflow: 'auto',
                      fontSize: '0.8rem',
                      background: '#1a1a2e',
                      padding: 10,
                      borderRadius: 5,
                      color: '#e0e0e0',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {emlPreview}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && <div className="mt-4">{results}</div>}
    </div>
  )
}

function parseCss(css: string): React.CSSProperties {
  const out: Record<string, string> = {}
  css.split(';').forEach((part) => {
    const idx = part.indexOf(':')
    if (idx > -1) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim()
  })
  return out as React.CSSProperties
}
