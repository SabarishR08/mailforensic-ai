import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { riskClass, riskColor } from '../lib/format'
import ForensicRouteMap from '../components/ForensicRouteMap'
import NeuroSymbolicConsensusCard from '../components/NeuroSymbolicConsensusCard'

type Phase = 'upload' | 'loading' | 'error' | 'results'

interface PresetEml {
  id: string
  name: string
  label: string
  subtitle: string
  badge: string
  badgeColor: string
  icon: string
  content: string
}

const PRESET_DEMO_EMLS: PresetEml[] = [
  {
    id: 'legit_bank',
    name: '01_legit_bank_statement.eml',
    label: 'Bank of America Statement',
    subtitle: 'SPF+DKIM+DMARC 100% PASS · 0% AbuseIPDB · 10,000+ Day Domain',
    badge: '🛡️ Anti-False-Positive Shield',
    badgeColor: '#10b981',
    icon: 'fa-building-columns',
    content: `From: statements@bankofamerica.com
To: victim-analyst@defense-corp.com
Subject: Monthly Account Statement - August 2026
Date: Sun, 24 Aug 2026 23:00:00 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit
Authentication-Results: mx.google.com;
\tspf=pass (google.com: domain of statements@bankofamerica.com designates 171.161.202.155 as permitted sender) smtp.mailfrom=statements@bankofamerica.com;
\tdkim=pass header.i=@bankofamerica.com header.s=boa2026 header.b=vX7k2j;
\tdmarc=pass (p=REJECT sp=REJECT dis=none) header.from=bankofamerica.com
Received: from mail-gateway.bankofamerica.com (171.161.202.155)
\tby mx.google.com with ESMTPS id boa-corp-991823
\tfor <victim-analyst@defense-corp.com>; Sun, 24 Aug 2026 23:00:01 -0500 (CDT)
Return-Path: <statements@bankofamerica.com>
Message-ID: <st-20260824-stmt-88219@smtpprod.bankofamerica.com>

Dear Bank of America Customer,

Your electronic monthly account statement for August 2026 is now available.

Account Summary:
- Account Ending In: ...4819
- Statement Period: Jul 24, 2026 - Aug 23, 2026
- Available Balance: $14,829.40

To view your complete itemized statement, please sign in securely to your account through the official mobile application or by visiting:
https://www.bankofamerica.com

Security Reminder: Bank of America will never ask you to verify your full card PIN or online banking password via email or phone call.

Thank you for choosing Bank of America.

Customer Service Team
Bank of America, N.A. Member FDIC.`,
  },
  {
    id: 'bec_ceo',
    name: '02_stealth_bec_ceo_wire_fraud.eml',
    label: 'CEO Wire Transfer (BEC)',
    subtitle: 'Zero URLs · Zero Attachments · Unauthenticated Wire Fraud',
    badge: '🚨 Anti-False-Negative Hunter',
    badgeColor: '#ef4444',
    icon: 'fa-user-tie',
    content: `From: "Robert Vance, Chief Executive Officer" <ceo@exec-holding-corp.com>
To: finance-controller@victim-corp.com
Subject: URGENT: Confidential Wire Transfer - Vendor Settlement before 4 PM
Date: Mon, 25 Aug 2026 14:15:22 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit
Authentication-Results: mx.google.com;
\tspf=neutral (google.com: 185.220.101.5 is neither permitted nor denied by domain of exec-holding-corp.com);
\tdkim=none;
\tdmarc=fail (p=none) header.from=exec-holding-corp.com
Received: from vps-mailer-out.net (185.220.101.5)
\tby mx.google.com with ESMTP id corp-wire-evasion-0012
\tfor <finance-controller@victim-corp.com>; Mon, 25 Aug 2026 14:15:23 +0000
Message-ID: <wire-req-20260825-9941@vps-mailer-out.net>
Reply-To: ceo-executive-office@consultant-desk.com

Hi Sarah,

Are you at your desk right now? 

I am currently in an all-day confidential executive board session and unable to take phone calls. We have reached an agreement on the overseas asset acquisition, but per the closing agreement terms, our initial earnest settlement must be wired prior to 4:00 PM EST today.

Please process an immediate federal wire transfer for $48,750.00 to our external transaction escrow partner:

Bank: JPMorgan Chase Bank, N.A.
Beneficiary Name: Apex Commercial Settlements LLC
Routing Transit: 021000021
Account Number: 49201948201
Reference: ACQ-SETTLE-SEC77

Please prioritize this immediately and reply with the PDF wire confirmation receipt as soon as the transfer reference is issued. Do not discuss this with the broader department until the official press announcement tomorrow morning.

Regards,

Robert Vance
Chief Executive Officer
Executive Management Group
Sent from my iPad`,
  },
  {
    id: 'cred_phish',
    name: '03_credential_phish_microsoft365.eml',
    label: 'Microsoft 365 Phish',
    subtitle: 'Typosquatted Domain · Suspicious Login URL · SPF/DKIM Fail',
    badge: '⚠️ Brand Impersonation',
    badgeColor: '#f59e0b',
    icon: 'fa-windows',
    content: `From: "Microsoft 365 Security Center" <no-reply@micros0ft-account-support.com>
To: user@victim-corp.com
Subject: ACTION REQUIRED: Your Microsoft 365 Password Expires in 2 Hours
Date: Mon, 25 Aug 2026 10:45:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.google.com;
\tspf=fail (google.com: domain of no-reply@micros0ft-account-support.com does not designate 45.77.65.211 as permitted sender);
\tdkim=fail;
\tdmarc=fail (p=reject) header.from=micros0ft-account-support.com
Received: from mail-phish-sender.ru (45.77.65.211)
\tby mx.google.com with ESMTPS id ms-phish-audit-220
\tfor <user@victim-corp.com>; Mon, 25 Aug 2026 10:45:01 +0000
Message-ID: <m365-alert-8392104@micros0ft-account-support.com>

<!DOCTYPE html>
<html>
<head><title>Microsoft Account Alert</title></head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
  <div style="background-color: #ffffff; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e0e0e0;">
    <h2 style="color: #0078d4; margin-top: 0;">Microsoft 365 Security Alert</h2>
    <p>Dear Valued User,</p>
    <p>Your organizational password for <strong>user@victim-corp.com</strong> is scheduled to expire today in <strong>2 hours</strong>. Due to recent security compliance updates, failure to update your credentials immediately will result in your email and cloud services being suspended.</p>
    <div style="margin: 24px 0; text-align: center;">
      <a href="http://194.26.29.11/ms-login/auth?user=victim-corp.com" style="background-color: #0078d4; color: #ffffff; padding: 12px 24px; text-decoration: none; font-weight: bold; border-radius: 4px; display: inline-block;">
        Keep Current Password & Verify Now
      </a>
    </div>
    <p style="font-size: 12px; color: #666;">If you do not update your password within 120 minutes, all active sessions will be terminated and your mailbox locked.</p>
    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
    <p style="font-size: 11px; color: #999;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
  </div>
</body>
</html>`,
  },
  {
    id: 'tor_relay',
    name: '04_multihop_tor_exit_relay.eml',
    label: 'Multi-Hop Tor Relay',
    subtitle: '3 Relay Hops · Origin Tor Node 185.220.101.5 Mapped',
    badge: '🌐 Tor Node & Hop Divergence',
    badgeColor: '#a855f7',
    icon: 'fa-route',
    content: `From: "Internal IT Helpdesk" <support@internal-corp.net>
To: target-user@victim-corp.com
Subject: [MANDATORY] Urgent Network Certificate Migration Required
Date: Mon, 25 Aug 2026 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.victim-corp.com;
\tspf=softfail (domain of internal-corp.net does not designate 185.220.101.5 as permitted sender);
\tdkim=fail;
\tdmarc=fail (p=none)
Received: from gateway.internal-corp.net (gateway.internal-corp.net [10.0.0.1])
\tby mail.victim-corp.com (Postfix) with ESMTPS id 4X98b2
\tfor <target-user@victim-corp.com>; Mon, 25 Aug 2026 12:01:14 +0000
Received: from relay2.vps-colo.eu (relay2.vps-colo.eu [91.219.236.88])
\tby gateway.internal-corp.net with ESMTP id relay-alpha-441
\tfor <target-user@victim-corp.com>; Mon, 25 Aug 2026 12:00:45 +0000
Received: from tor-exit-node.anonymizer.org (tor-exit-node.anonymizer.org [185.220.101.5])
\tby relay2.vps-colo.eu with ESMTP id tor-hop-inbound
\tfor <target-user@victim-corp.com>; Mon, 25 Aug 2026 12:00:02 +0000
Message-ID: <cert-update-alert-991283@gateway.internal-corp.net>

All Staff Members,

Due to a root SSL certificate expiration on our corporate VPN infrastructure, all employees are instructed to install the new VPN client certificate update immediately.

Download and install your personal certificate package from the network repository:
http://185.220.101.5/vpn-certs/Corp_Root_CA_2026.exe

Failure to install the security patch within 4 hours will prevent your workstation from authenticating against the company active directory domain.

IT Systems Administration
Internal Infrastructure Team`,
  },
  {
    id: 'payroll_nrd',
    name: '05_urgent_payroll_direct_deposit.eml',
    label: 'HR Payroll Redirect',
    subtitle: 'Newly Registered Domain (<30d) · Employee Wire Coercion',
    badge: '📅 NRD & Financial Coercion',
    badgeColor: '#f97316',
    icon: 'fa-money-bill-transfer',
    content: `From: "Human Resources Department" <payroll-update@workday-benefits-auth.com>
To: employee@victim-corp.com
Subject: [URGENT ACTION] Direct Deposit Re-Verification Required for End-of-Month Payroll
Date: Mon, 25 Aug 2026 08:30:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.google.com;
\tspf=neutral (domain of workday-benefits-auth.com designates 194.26.29.11 as sender);
\tdkim=fail;
\tdmarc=fail (p=none)
Received: from mail-dispatch.workday-benefits-auth.com (194.26.29.11)
\tby mx.google.com with ESMTPS id payroll-auth-chk-991
\tfor <employee@victim-corp.com>; Mon, 25 Aug 2026 08:30:01 +0000
Message-ID: <payroll-notice-839120@workday-benefits-auth.com>

Dear Employee,

During our quarterly banking ledger audit, our payroll processing vendor flagged an invalid routing number mismatch on your direct deposit account profile.

To prevent your upcoming salary disbursement from being returned or rejected by the federal clearing house, you must confirm your current banking routing and account credentials before 5:00 PM today.

Access the self-service employee payroll portal here:
http://194.26.29.11/hr/payroll/direct-deposit-verify

Failure to update your information before today's processing deadline will result in your salary check being withheld until the subsequent pay cycle.

Warm regards,

Payroll & Benefits Operations
Corporate Human Resources`,
  },
]

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

  const loadPreset = (preset: PresetEml) => {
    const file = new File([preset.content], preset.name, { type: 'message/rfc822' })
    analyzeFile(file)
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
      <div className="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
          <h4 className="fw-bold mb-1">
            <i className="fas fa-microscope text-info me-2"></i> Raw .EML Forensic Inspection
          </h4>
          <p className="text-muted mb-0" style={{ fontSize: '0.88rem' }}>
            Upload or select RFC 5322 email messages to deconstruct headers, check cryptographic signatures, and arbitrate threats with NS-BCT.
          </p>
        </div>
        {phase === 'results' && (
          <div className="d-flex gap-2">
            <button className="btn btn-outline-secondary btn-sm" onClick={resetPage}>
              <i className="fas fa-rotate-left me-1"></i> Inspect Another
            </button>
            {report?.scan_id && (
              <a
                href={api.forensicPdfUrl(report.scan_id)}
                target="_blank"
                rel="noreferrer"
                className="btn btn-primary btn-sm"
              >
                <i className="fas fa-file-pdf me-1"></i> Download PDF
              </a>
            )}
          </div>
        )}
      </div>

      {phase === 'upload' && (
        <>
          {/* 1-Click Forensic Demo Presets */}
          <div
            className="card p-3 mb-4"
            style={{
              background: 'rgba(18, 20, 28, 0.85)',
              border: '1px solid rgba(85,230,212,0.25)',
              borderRadius: '10px',
            }}
          >
            <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
              <div>
                <span className="fw-bold text-light" style={{ fontSize: '0.95rem' }}>
                  <i className="fas fa-flask text-cyan me-2"></i>
                  Instant Demo Scenarios (1-Click Evaluation)
                </span>
                <p className="text-muted mb-0 small">
                  Click any verified test vector to trigger full header deconstruction, cryptographic verification, and NS-BCT arbitration.
                </p>
              </div>
              <span
                className="badge font-monospace px-2 py-1"
                style={{
                  background: 'rgba(85,230,212,0.1)',
                  color: 'var(--cyan, #55e6d4)',
                  border: '1px solid rgba(85,230,212,0.3)',
                  fontSize: '0.72rem',
                }}
              >
                SIH 2026 JURY BENCHMARK
              </span>
            </div>

            <div className="row g-2">
              {PRESET_DEMO_EMLS.map((preset) => (
                <div key={preset.id} className="col-md-6 col-xl">
                  <button
                    className="btn text-start w-100 p-2 h-100 d-flex flex-column justify-content-between"
                    style={{
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: `1px solid ${preset.badgeColor}40`,
                      borderRadius: '8px',
                      transition: 'all 0.2s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.borderColor = preset.badgeColor)}
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.borderColor = `${preset.badgeColor}40`)
                    }
                    onClick={() => loadPreset(preset)}
                  >
                    <div>
                      <div className="d-flex align-items-center justify-content-between mb-1">
                        <span className="fw-semibold text-light" style={{ fontSize: '0.82rem' }}>
                          <i
                            className={`fas ${preset.icon} me-1`}
                            style={{ color: preset.badgeColor }}
                          ></i>
                          {preset.label}
                        </span>
                      </div>
                      <div
                        className="text-muted mb-2"
                        style={{ fontSize: '0.7rem', lineHeight: '1.3' }}
                      >
                        {preset.subtitle}
                      </div>
                    </div>
                    <span
                      className="badge align-self-start font-monospace"
                      style={{
                        fontSize: '0.65rem',
                        background: `${preset.badgeColor}20`,
                        color: preset.badgeColor,
                        border: `1px solid ${preset.badgeColor}60`,
                      }}
                    >
                      {preset.badge}
                    </span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Standard Drag & Drop Upload Zone */}
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
                Standard RFC 822/2822 email format supported · Located in <code>demo_eml_samples/</code>
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
        </>
      )}

      {phase === 'loading' && (
        <div className="card p-5 text-center">
          <div
            className="spinner-border text-info mb-3 mx-auto"
            style={{ width: '2.5rem', height: '2.5rem' }}
            role="status"
          ></div>
          <div className="fw-semibold">Deconstructing {fileName}…</div>
          <p className="text-muted mt-2 mb-0" style={{ fontSize: '0.85rem' }}>
            Evaluating SPF/DKIM/DMARC headers, relay hop latencies, and Bayesian consensus arbitration.
          </p>
        </div>
      )}

      {phase === 'error' && (
        <div className="card p-4">
          <div className="text-center py-4">
            <i
              className="fas fa-triangle-exclamation text-danger mb-3"
              style={{ fontSize: '2.5rem' }}
            ></i>
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
          <div
            className="card p-4 h-100"
            style={{ borderTop: `3px solid ${riskColor(riskLevel)}` }}
          >
            <div
              className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2"
              style={{ borderColor: 'var(--border)' }}
            >
              <h6
                className="fw-bold mb-0 text-uppercase"
                style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
              >
                <i className="fas fa-shield-halved text-info me-2"></i> Overall Risk Assessment
              </h6>
              <span className={`badge-risk ${riskClass(riskLevel)}`}>
                {risk.risk_level || 'Unknown'}
              </span>
            </div>
            <div className="text-center my-3">
              <div
                style={{ fontSize: '3.6rem', fontWeight: 800, lineHeight: 1 }}
                className={riskClass(riskLevel)}
              >
                {risk.risk_score ?? 0}
              </div>
              <div className="text-muted mt-2 font-monospace" style={{ fontSize: '0.8rem' }}>
                Score out of 100
              </div>
            </div>
          </div>
        </div>

        {/* ML Inference Card */}
        <div className="col-md-6">
          <div
            className="card p-4 h-100"
            style={{
              borderTop: `3px solid ${
                mlPred === 'phishing'
                  ? '#EF4444'
                  : mlPred === 'legitimate'
                  ? '#10B981'
                  : '#F59E0B'
              }`,
            }}
          >
            <div
              className="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2"
              style={{ borderColor: 'var(--border)' }}
            >
              <h6
                className="fw-bold mb-0 text-uppercase"
                style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
              >
                <i className="fas fa-brain text-info me-2"></i> ML Classifier Model
              </h6>
              <span
                className="badge"
                style={{
                  background: 'var(--bg-panel)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                }}
              >
                {ml.model_loaded ? 'DistilBERT / Ensemble Active' : 'Heuristic Mode'}
              </span>
            </div>
            <div className="text-center my-2">
              <span
                className={`badge-risk ${
                  mlPred === 'phishing'
                    ? 'risk-critical'
                    : mlPred === 'suspicious'
                    ? 'risk-medium'
                    : 'risk-safe'
                }`}
                style={{ fontSize: '1.2rem', padding: '8px 24px', fontWeight: 800 }}
              >
                {String(mlPred).toUpperCase()}
              </span>
              <div
                className="mt-3 font-monospace"
                style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}
              >
                Confidence: <b>{mlConf.toFixed(1)}%</b>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Row: Neuro-Symbolic Bayesian Consensus Triangulation (NS-BCT) */}
      <div className="mb-3">
        <NeuroSymbolicConsensusCard
          arbitration={
            report.consensus_arbitration || report.risk_assessment?.consensus_arbitration
          }
          threatIntel={
            report.threat_intel_details || report.risk_assessment?.threat_intel_details
          }
          cognitive={report.cognitive || report.risk_assessment?.cognitive_vectors}
        />
      </div>

      {/* Auth & Metadata Cards */}
      <div className="row g-3 mb-3">
        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6
              className="fw-bold text-uppercase mb-3"
              style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
            >
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
            <h6
              className="fw-bold text-uppercase mb-3"
              style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
            >
              <i className="fas fa-envelope text-info me-2"></i> Message Envelope Metadata
            </h6>
            <table className="table table-sm mb-0">
              <tbody>
                <tr>
                  <td className="text-muted ps-0" style={{ width: '110px' }}>
                    Subject
                  </td>
                  <td className="fw-medium text-truncate" style={{ maxWidth: '240px' }}>
                    {report.subject || '—'}
                  </td>
                </tr>
                <tr>
                  <td className="text-muted ps-0">From</td>
                  <td
                    className="mono text-truncate"
                    style={{ maxWidth: '240px', fontSize: '0.8rem' }}
                  >
                    {report.from || '—'}
                  </td>
                </tr>
                <tr>
                  <td className="text-muted ps-0">Message-ID</td>
                  <td
                    className="mono text-truncate"
                    style={{ maxWidth: '240px', fontSize: '0.78rem' }}
                  >
                    {report.email_id || '—'}
                  </td>
                </tr>
                <tr>
                  <td className="text-muted ps-0">Body Length</td>
                  <td className="font-monospace">
                    {(report.body_length || 0).toLocaleString()} characters
                  </td>
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
            <h6
              className="fw-bold text-uppercase mb-3"
              style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
            >
              <i className="fas fa-globe text-info me-2"></i> Origin Geolocation & Cyber Intelligence
            </h6>
            {geo.ip && geo.source !== 'unknown' ? (
              <table className="table table-sm mb-0">
                <tbody>
                  <tr>
                    <td className="text-muted ps-0">Origin IP</td>
                    <td className="mono text-info">{geo.ip}</td>
                  </tr>
                  <tr>
                    <td className="text-muted ps-0">Location</td>
                    <td>
                      {geo.city || '—'}, {geo.country || '—'} ({geo.country_code || 'XX'})
                    </td>
                  </tr>
                  <tr>
                    <td className="text-muted ps-0">ISP / ASN</td>
                    <td>
                      {geo.org || '—'} {geo.asn ? `(${geo.asn})` : ''}
                    </td>
                  </tr>
                  <tr>
                    <td className="text-muted ps-0">Anonymizer Status</td>
                    <td>
                      {anon.is_tor ? (
                        <span className="badge bg-danger text-white">
                          <i className="fas fa-shield-virus me-1"></i> Tor Exit Node Detected
                        </span>
                      ) : anon.is_vpn_proxy ? (
                        <span className="badge bg-warning text-dark">
                          <i className="fas fa-user-secret me-1"></i> VPN / Proxy Detected
                        </span>
                      ) : anon.is_bulletproof ? (
                        <span className="badge bg-danger text-white">
                          <i className="fas fa-server me-1"></i> Bulletproof / High-Abuse Host
                        </span>
                      ) : geo.is_hosting ? (
                        <span className="badge bg-secondary text-white">Cloud / VPS Datacenter</span>
                      ) : (
                        <span className="badge bg-success text-white">
                          <i className="fas fa-check-circle me-1"></i> Direct Residential ISP
                        </span>
                      )}
                    </td>
                  </tr>
                  <tr>
                    <td className="text-muted ps-0">Clock Alignment</td>
                    <td>
                      {temporal.has_anomaly ? (
                        <span className="text-warning fw-bold" style={{ fontSize: '0.8rem' }}>
                          <i className="fas fa-clock me-1"></i> Timezone Drift:{' '}
                          {temporal.drift_hours}h discrepancy
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
              <p className="text-muted mb-0" style={{ fontSize: '0.85rem' }}>
                No geolocation data extracted from headers.
              </p>
            )}
          </div>
        </div>

        <div className="col-md-6">
          <div className="card p-4 h-100">
            <h6
              className="fw-bold text-uppercase mb-3"
              style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
            >
              <i className="fas fa-route text-warning me-2"></i> Relay Routing Chain
            </h6>
            <div>
              {(routing.hops || []).map((hop: any) => (
                <div
                  key={hop.hop_number}
                  className="d-flex align-items-center gap-2 mb-2 p-2 rounded"
                  style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)' }}
                >
                  <span
                    className="badge"
                    style={{
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border)',
                      color: 'var(--text-muted)',
                      fontFamily: 'JetBrains Mono',
                    }}
                  >
                    #{hop.hop_number}
                  </span>
                  <div className="flex-grow-1 text-truncate" style={{ fontSize: '0.82rem' }}>
                    <span className="mono text-info">{hop.ip || 'Unknown IP'}</span>
                    <span className="text-muted ms-2">({hop.by_host || 'Direct'})</span>
                  </div>
                  {hop.suspicious ? (
                    <span className="badge-risk risk-critical" style={{ fontSize: '0.7rem' }}>
                      Anomaly
                    </span>
                  ) : (
                    <span className="text-success" style={{ fontSize: '0.78rem' }}>
                      ✓ Clean
                    </span>
                  )}
                </div>
              ))}
              {(routing.hops || []).length === 0 && (
                <p className="text-muted mb-0" style={{ fontSize: '0.85rem' }}>
                  No relay Received: headers identified.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Cross-Border Payload Infrastructure Correlation */}
      {geoCorr.correlated && (
        <div className="card p-4 mb-3" style={{ borderLeft: '4px solid #e74c3c' }}>
          <div className="d-flex justify-content-between align-items-center mb-2">
            <h6
              className="fw-bold text-uppercase mb-0"
              style={{ fontSize: '0.8rem', letterSpacing: '0.8px', color: '#e74c3c' }}
            >
              <i className="fas fa-satellite-dish me-2"></i> Cross-Border Infrastructure Divergence Matrix
            </h6>
            <span className="badge bg-danger text-white">
              {Math.round(geoCorr.max_distance_km || 0).toLocaleString()} km Physical Divergence
            </span>
          </div>
          <p className="text-muted mb-3" style={{ fontSize: '0.84rem' }}>
            Attacker relayed email via <strong>{geoCorr.sender_origin?.country || 'Unknown'}</strong>, but malicious landing payload is hosted on remote infrastructure.
          </p>
          <div className="table-responsive">
            <table className="table table-sm mb-0">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>IP Address</th>
                  <th>Hosting Org / ASN</th>
                  <th>Location</th>
                  <th>Physical Distance</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><span className="badge bg-secondary">Origin Relay</span></td>
                  <td className="mono text-info">{geoCorr.sender_origin?.ip}</td>
                  <td>{geoCorr.sender_origin?.org}</td>
                  <td>{geoCorr.sender_origin?.country}</td>
                  <td>—</td>
                </tr>
                {(geoCorr.divergent_payloads || []).map((p: any, idx: number) => (
                  <tr key={idx}>
                    <td><span className="badge bg-danger">Landing Payload</span></td>
                    <td className="mono text-danger">{p.ip}</td>
                    <td>{p.org || 'Unknown'}</td>
                    <td>{p.country || 'Unknown'}</td>
                    <td className="text-danger fw-bold font-monospace">
                      {Math.round(p.distance_km || 0).toLocaleString()} km
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Intelligence Attributions Breakdown */}
      <div className="card p-4 mb-3">
        <h6
          className="fw-bold text-uppercase mb-3"
          style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
        >
          <i className="fas fa-chart-pie text-info me-2"></i> Signal Weight Contribution Breakdown
        </h6>
        <div className="row g-2">
          {BREAKDOWN_ORDER.map((key) => {
            const val = breakdown[key] ?? 0
            const pct = Math.min(100, Math.round(val))
            return (
              <div key={key} className="col-md-4 col-sm-6">
                <div
                  className="p-3 rounded h-100"
                  style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)' }}
                >
                  <div className="d-flex justify-content-between mb-1" style={{ fontSize: '0.8rem' }}>
                    <span className="text-muted">{breakdownLabels[key] || key}</span>
                    <span className="mono fw-bold">{val}/100</span>
                  </div>
                  <div
                    className="progress"
                    style={{ height: '6px', background: 'rgba(255,255,255,0.06)' }}
                  >
                    <div
                      className="progress-bar"
                      role="progressbar"
                      style={{
                        width: `${pct}%`,
                        background:
                          pct > 70 ? '#EF4444' : pct > 40 ? '#F59E0B' : '#10B981',
                      }}
                    />
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Malicious Landing URLs & QR payload */}
      {report.urls_found && report.urls_found.length > 0 && (
        <div className="card p-4 mb-3">
          <h6
            className="fw-bold text-uppercase mb-3"
            style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
          >
            <i className="fas fa-link text-info me-2"></i> Extracted URLs & Endpoint Reputation ({report.urls_found.length})
          </h6>
          <div className="table-responsive">
            <table className="table table-sm mb-0">
              <thead>
                <tr>
                  <th>Scanned URL</th>
                  <th>Risk Score</th>
                  <th>Threat Level</th>
                </tr>
              </thead>
              <tbody>
                {report.urls_found.map((url: string, idx: number) => {
                  const urlInfo = urlResults[url] || {}
                  const score = urlInfo.risk_score ?? urlInfo.threat_score ?? 0
                  const level = urlInfo.risk_level || (score > 60 ? 'Critical' : score > 30 ? 'Suspicious' : 'Clean')
                  return (
                    <tr key={idx}>
                      <td className="mono" style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                        {url}
                      </td>
                      <td className="mono">{score}/100</td>
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
        <h6
          className="fw-bold text-uppercase mb-2"
          style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
        >
          <i className="fas fa-file-lines text-info me-2"></i> Parsed Message Body
        </h6>
        <div
          className="mono p-3 rounded"
          style={{
            maxHeight: '200px',
            overflowY: 'auto',
            background: 'var(--bg-input)',
            border: '1px solid var(--border)',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
            lineHeight: 1.5,
            whiteSpace: 'pre-wrap',
          }}
        >
          {report.body_preview || '(Empty message body)'}
        </div>
      </div>

      {/* Bottom Action Footer */}
      <div className="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
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
