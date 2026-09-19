// Thin typed wrapper over the Flask JSON APIs. The endpoint surface
// mirrors backend/routes/*.py exactly — the SPA must never depend on
// something the Python backend doesn't expose.

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe' | 'Unknown'
export type Prediction = 'phishing' | 'legitimate' | 'suspicious' | 'unknown'

async function j<T = any>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const res = await fetch(input, init)
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body && body.error) message = body.error
    } catch {
      /* not json */
    }
    throw new Error(message)
  }
  return res.json()
}

const post = (url: string, body: unknown) =>
  j(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

export const api = {
  // --- General ---
  health: () => j<{ status: string }>('/api/health'),
  stats: () => j<{ total_scans: number; phishing_detected: number; total_threats: number }>('/api/stats'),
  geoThreats: () => j<{ points: any[]; count: number }>('/api/geo/threats'),

  // --- Dashboard / recent scans (threat-intel/recent is the JSON scans list) ---
  recentScans: (limit = 20) => j(`/api/threat-intel/recent?limit=${limit}`),

  // --- Threat intel ---
  summary: () => j('/api/threat-intel/summary'),
  trends: (days: number) => j(`/api/threat-intel/trends?days=${days}`),
  distribution: () => j('/api/threat-intel/distribution'),
  topSources: () => j('/api/threat-intel/top-sources'),
  authTrends: (days: number) => j(`/api/threat-intel/auth-trends?days=${days}`),
  threatIntelRecent: (limit = 25) => j(`/api/threat-intel/recent?limit=${limit}`),

  // --- Threat map ---
  mapPoints: (days: number, riskLevel = '') => j(`/api/threat-map/points?days=${days}&risk_level=${riskLevel}`),
  mapStats: (days: number) => j(`/api/threat-map/stats?days=${days}`),
  mapRecent: (limit = 10) => j(`/api/threat-map/recent?limit=${limit}`),
  geoLookup: (target: string) => post('/api/geo/lookup', { target }),

  // --- Email scanning ---
  scanGmail: (limit: number) => post('/email/api/scan/gmail', { limit }),
  scanSample: (limit: number) => post('/email/api/scan/sample', { limit }),
  scanText: (text: string) =>
    post('/email/api/scan/text', { text }),

  // --- Forensic .eml pipeline (multipart upload) ---
  analyzeEml: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return j('/forensic/api/analyze-eml', { method: 'POST', body: form })
  },
  forensicReport: (scanId: number | string) => j(`/forensic/api/report/${scanId}`),
  forensicPdfUrl: (scanId: number | string) => `/forensic/api/report/pdf/${scanId}`,
}

export type ScanRow = {
  id: number
  timestamp: string | null
  email_id: string
  ml_prediction: Prediction
  ml_confidence: number
  risk_score: number
  risk_level: RiskLevel
  forensic_trust_score: number
  geo_country: string
  origin_ip: string
  // enrichment added by /api/threat-intel/recent
  from?: string
  subject?: string
  geo_city?: string
  auth_all_pass?: boolean
}
