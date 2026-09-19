import { useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'

interface NavItem {
  to: string
  icon: string
  label: string
  badge?: string
  badgeColor?: string
}

const NAV_OPERATIONS: NavItem[] = [
  { to: '/dashboard', icon: 'fa-chart-line', label: 'Dashboard' },
  { to: '/email/scan', icon: 'fa-envelope-open-text', label: 'Email Scanner' },
  { to: '/forensic/scan', icon: 'fa-microscope', label: 'Forensic .EML' },
  { to: '/email/demo', icon: 'fa-satellite-dish', label: 'Live Stream Demo', badge: 'LIVE', badgeColor: '#ef4444' },
  { to: '/email/batch', icon: 'fa-layer-group', label: 'Batch & Playbooks' },
]

const NAV_INTELLIGENCE: NavItem[] = [
  { to: '/threat-map', icon: 'fa-globe', label: 'Threat Map', badge: '60 FPS', badgeColor: '#10b981' },
  { to: '/dashboard/campaigns', icon: 'fa-sitemap', label: 'Threat Campaigns' },
  { to: '/dashboard/threat-intel', icon: 'fa-chart-area', label: 'Threat Intel' },
]

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const { pathname } = useLocation()
  const flush = pathname === '/threat-map'

  return (
    <div>
      {/* Sidebar Navigation */}
      <div className={`sidebar ${sidebarOpen ? '' : 'collapsed'}`}>
        <div className="brand d-flex justify-content-between align-items-center px-3 pb-3 border-bottom border-secondary">
          <Link to="/dashboard" className="d-flex align-items-center gap-2 overflow-hidden brand-text text-decoration-none">
            <i className="fas fa-shield-halved text-info fs-5"></i>
            <div className="d-flex flex-column">
              <span className="fw-bold text-light lh-1" style={{ fontSize: '0.95rem' }}>
                MailForensic AI
              </span>
              <small className="text-muted font-monospace mt-1 badge-sih" style={{ fontSize: '0.62rem', letterSpacing: '0.05em' }}>
                SIH 2026 · PS-106
              </small>
            </div>
          </Link>
          <button
            className="sidebar-toggle-btn px-2 py-1 text-light border-secondary flex-shrink-0"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            title={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            style={{ fontSize: '0.85rem' }}
          >
            <i className="fas fa-bars"></i>
          </button>
        </div>

        {/* Section 1: Operations & Forensics */}
        <div className="sidebar-section-label nav-text mt-3">DETECTION & FORENSICS</div>
        <nav className="nav flex-column mt-1">
          {NAV_OPERATIONS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/dashboard'}
              title={!sidebarOpen ? item.label : undefined}
              className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}
            >
              <i className={'fas ' + item.icon}></i>
              <span className="nav-text ms-2 flex-grow-1">{item.label}</span>
              {item.badge && sidebarOpen && (
                <span
                  className="badge font-monospace ms-auto"
                  style={{
                    fontSize: '0.62rem',
                    background: `${item.badgeColor}20`,
                    color: item.badgeColor,
                    border: `1px solid ${item.badgeColor}60`,
                    padding: '2px 6px',
                  }}
                >
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Section 2: Intelligence & Operations */}
        <div className="sidebar-section-label nav-text mt-3">THREAT INTELLIGENCE</div>
        <nav className="nav flex-column mt-1">
          {NAV_INTELLIGENCE.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              title={!sidebarOpen ? item.label : undefined}
              className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}
            >
              <i className={'fas ' + item.icon}></i>
              <span className="nav-text ms-2 flex-grow-1">{item.label}</span>
              {item.badge && sidebarOpen && (
                <span
                  className="badge font-monospace ms-auto"
                  style={{
                    fontSize: '0.62rem',
                    background: `${item.badgeColor}20`,
                    color: item.badgeColor,
                    border: `1px solid ${item.badgeColor}60`,
                    padding: '2px 6px',
                  }}
                >
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>
      </div>

      <main className={`${flush ? 'main-content--flush' : 'main-content'} ${sidebarOpen ? '' : 'collapsed'}`}>
        {!flush && (
          <div className="top-header d-flex justify-content-between align-items-center">
            <div className="d-flex align-items-center gap-3">
              <span className="system-status font-monospace">
                <span className="status-pulse"></span>
                <i className="fas fa-satellite-dish"></i> NS-BCT ARBITRATION ONLINE
              </span>
            </div>

            {/* Quick Demo Navigation Shortcuts */}
            <div className="d-flex align-items-center gap-2">
              <Link
                to="/email/scan"
                className={`btn btn-sm ${pathname === '/email/scan' ? 'btn-primary' : 'btn-outline-secondary'}`}
                style={{ fontSize: '0.75rem' }}
              >
                <i className="fas fa-envelope-open-text me-1"></i> Scanner
              </Link>
              <Link
                to="/forensic/scan"
                className={`btn btn-sm ${pathname === '/forensic/scan' ? 'btn-primary' : 'btn-outline-secondary'}`}
                style={{ fontSize: '0.75rem' }}
              >
                <i className="fas fa-microscope me-1"></i> .EML Forensics
              </Link>
              <Link
                to="/threat-map"
                className={`btn btn-sm ${pathname === '/threat-map' ? 'btn-primary' : 'btn-outline-secondary'}`}
                style={{ fontSize: '0.75rem' }}
              >
                <i className="fas fa-globe me-1"></i> Threat Map
              </Link>
              <span className="header-vault font-monospace d-none d-md-inline ms-2">
                <i className="fas fa-lock"></i> Evidence Vault Active
              </span>
            </div>
          </div>
        )}
        <Outlet />
      </main>
    </div>
  )
}
