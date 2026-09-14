import React, { useState, useEffect, Suspense } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar.jsx';
import TopBar from './TopBar.jsx';
import CommandPalette from '../CommandPalette.jsx';
import useCommandPalette from '../../hooks/useCommandPalette.js';
import { IS_BACKEND_CONFIGURED, IS_PRODUCTION } from '../../lib/constants.js';
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
          {slow ? 'Loading SOC workspace...' : 'Loading SOC workspace...'}
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

  const mainStyle = {
    marginLeft: expanded ? 240 : 64,
    minHeight: '100vh',
    background: 'var(--bg-primary)',
    transition: 'margin-left 0.25s ease, background-color 0.25s ease',
  };

  if (typeof window !== 'undefined' && window.innerWidth < 768) {
    mainStyle.marginLeft = 0;
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}>
      <Sidebar
        expanded={expanded}
        onToggle={() => setExpanded((e) => !e)}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      <div style={mainStyle}>
        <TopBar
          onMobileMenuOpen={() => setMobileOpen(true)}
          onCommandPalette={() => setCmdOpen(true)}
          theme={theme}
          onToggleTheme={toggleTheme}
        />

        {/* Informative banner when running on Vercel without a configured backend */}
        {!IS_BACKEND_CONFIGURED && IS_PRODUCTION && (
          <div
            style={{
              margin: '16px 24px 0',
              padding: '12px 16px',
              borderRadius: 10,
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#fca5a5',
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 12,
              flexWrap: 'wrap',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <WifiOff size={18} color="#ef4444" style={{ flexShrink: 0 }} />
              <span>
                <strong>Backend unavailable:</strong> Vercel frontend is running in production without a public FastAPI backend URL.
                Add <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px', borderRadius: 4, fontFamily: 'monospace' }}>VITE_API_URL</code> in Vercel Project Settings to connect threat intelligence and live scans.
              </span>
            </div>
            <span
              style={{
                fontSize: 11,
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 6,
                background: 'rgba(239,68,68,0.2)',
                border: '1px solid rgba(239,68,68,0.4)',
                color: '#f87171',
                whiteSpace: 'nowrap',
              }}
            >
              DEGRADED UI MODE
            </span>
          </div>
        )}

        <main style={{ padding: '24px', minHeight: 'calc(100vh - 60px)' }}>
          <Suspense fallback={<PageLoader />}>
            <Outlet />
          </Suspense>
        </main>
      </div>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  );
}
