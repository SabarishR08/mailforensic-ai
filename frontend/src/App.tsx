import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'

const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const EmailScannerPage = lazy(() => import('./pages/EmailScannerPage'))
const BatchScannerPage = lazy(() => import('./pages/BatchScannerPage'))
const CampaignsPage = lazy(() => import('./pages/CampaignsPage'))
const DemoPage = lazy(() => import('./pages/DemoPage'))
const ForensicEmlPage = lazy(() => import('./pages/ForensicEmlPage'))
const ForensicReportPage = lazy(() => import('./pages/ForensicReportPage'))
const ThreatMapPage = lazy(() => import('./pages/ThreatMapPage'))
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage'))

function PageLoader() {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '55vh',
        gap: '14px',
        color: 'var(--cyan, #55e6d4)',
        fontFamily: 'var(--font-mono, monospace)',
        fontSize: '0.82rem',
        letterSpacing: '0.08em',
      }}
    >
      <div
        style={{
          width: '32px',
          height: '32px',
          border: '2.5px solid rgba(85,230,212,0.15)',
          borderTopColor: 'var(--cyan, #55e6d4)',
          borderRadius: '50%',
          animation: 'spin 0.65s linear infinite',
        }}
      />
      <span>LOADING SUBSYSTEM...</span>
    </div>
  )
}

// Routes mirror the original Jinja URLs 1:1 so nothing breaks and the
// backend keeps serving the same /api + /email/api + /forensic/api surface.
export default function App() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/email/scan" element={<EmailScannerPage />} />
          <Route path="/email/batch" element={<BatchScannerPage />} />
          <Route path="/dashboard/campaigns" element={<CampaignsPage />} />
          <Route path="/email/demo" element={<DemoPage />} />
          <Route path="/forensic/scan" element={<ForensicEmlPage />} />
          <Route path="/forensic/report/:scanId" element={<ForensicReportPage />} />
          <Route path="/threat-map" element={<ThreatMapPage />} />
          <Route path="/dashboard/threat-intel" element={<ThreatIntelPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </Suspense>
  )
}
