import React, { useState, useEffect, Suspense } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar.jsx';
import TopBar from './TopBar.jsx';
import Footer from './Footer.jsx';
import CommandPalette from '../CommandPalette.jsx';
import useCommandPalette from '../../hooks/useCommandPalette.js';
import { useBackendStatus } from '../../context/BackendStatusContext.jsx';
import { WifiOff, RefreshCw } from 'lucide-react';

function PageLoader() {
  const [slow, setSlow] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setSlow(true), 3500);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div style={{ padding: 48, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, maxWidth: 460, textAlign: 'center' }}>
        <div
          style={{
            width: 40,
            height: 40,
            border: '3px solid rgba(0,194,255,0.2)',
            borderTop: '3px solid #00c2ff',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
          }}
        />
        <p style={{ color: '#94a3b8', fontSize: 14 }}>
          Loading SOC workspace...
        </p>

        {slow && (
          <div
            style={{
              fontSize: 12,
              color: '#f59e0b',
              background: 'rgba(245,158,11,0.1)',
              border: '1px solid rgba(245,158,11,0.25)',
              borderRadius: 8,
              padding: '10px 14px',
              lineHeight: 1.5,
            }}
          >
            <div>Workspace asset loading is taking longer than usual.</div>
            <button
              onClick={() => window.location.reload()}
              style={{
                marginTop: 8,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '4px 10px',
                borderRadius: 6,
                background: 'rgba(255,255,255,0.06)',
                border: '1px solid rgba(255,255,255,0.15)',
                color: '#fff',
                cursor: 'pointer',
                fontSize: 11,
              }}
            >
              <RefreshCw size={12} /> Reload Workspace
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function AppShell() {
  const [expanded, setExpanded] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('phishguard_theme') || 'dark');

  const { status, statusMessage, retryConnection } = useBackendStatus();

  useCommandPalette(() => setCmdOpen(true));

  useEffect(() => {
    localStorage.setItem('phishguard_theme', theme);
    if (theme === 'light') {
      document.documentElement.classList.add('light-mode');
    } else {
      document.documentElement.classList.remove('light-mode');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((t) => (t === 'light' ? 'dark' : 'light'));
  };

  const isBackendOffline = status === 'UNAVAILABLE' || status === 'TIMEOUT' || status === 'ERROR';

  const location = useLocation();

  // Close mobile drawer on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)', color: 'var(--text-primary)', width: '100%', overflowX: 'hidden' }}>
      <Sidebar
        expanded={expanded}
        onToggle={() => setExpanded((e) => !e)}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      <div className={`app-main ${expanded ? 'sidebar-expanded' : 'sidebar-collapsed'}`}>
        <TopBar
          onMobileMenuOpen={() => setMobileOpen(true)}
          onCommandPalette={() => setCmdOpen(true)}
          theme={theme}
          onToggleTheme={toggleTheme}
        />

        {/* Non-blocking degraded mode alert when backend is unreachable */}
        {isBackendOffline && (
          <div className="backend-offline-banner">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, minWidth: 0, flex: 1 }}>
              <WifiOff size={18} color="#ef4444" style={{ flexShrink: 0, marginTop: 2 }} />
              <span style={{ fontSize: 13, lineHeight: 1.5, wordBreak: 'break-word' }}>
                <strong style={{ color: '#ef4444' }}>BACKEND UNAVAILABLE:</strong> {statusMessage} Operating in offline degraded mode with heuristic fallbacks.
              </span>
            </div>
            <div className="backend-offline-actions">
              <button
                onClick={retryConnection}
                className="touch-btn"
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  padding: '8px 14px',
                  borderRadius: 6,
                  background: 'rgba(255, 255, 255, 0.08)',
                  border: '1px solid rgba(255, 255, 255, 0.15)',
                  color: '#fff',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  minHeight: 38,
                }}
              >
                <RefreshCw size={12} /> Retry Connection
              </button>
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '4px 8px',
                  borderRadius: 4,
                  background: 'rgba(239,68,68,0.2)',
                  border: '1px solid rgba(239,68,68,0.4)',
                  color: '#f87171',
                  whiteSpace: 'nowrap',
                }}
              >
                OFFLINE MODE
              </span>
            </div>
          </div>
        )}

        <main className="app-content">
          <Suspense fallback={<PageLoader />}>
            <Outlet />
          </Suspense>
        </main>

        <Footer />
      </div>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  );
}
