import React, { useState, useEffect, Suspense } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar.jsx';
import TopBar from './TopBar.jsx';
import CommandPalette from '../CommandPalette.jsx';
import useCommandPalette from '../../hooks/useCommandPalette.js';

function PageLoader() {
  return (
    <div style={{ padding: 48, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
        <div style={{ width: 40, height: 40, border: '3px solid rgba(0,194,255,0.2)', borderTop: '3px solid #00c2ff', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
        <p style={{ color: '#64748b', fontSize: 14 }}>Loading SOC workspace...</p>
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
    setTheme(t => t === 'light' ? 'dark' : 'light');
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
        onToggle={() => setExpanded(e => !e)}
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
