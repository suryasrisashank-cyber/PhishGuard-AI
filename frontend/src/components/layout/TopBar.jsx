import React from 'react';
import { Search, Bell, Menu, Shield, Command, Sun, Moon, Wifi, WifiOff, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useBackendStatus } from '../../context/BackendStatusContext.jsx';

export default function TopBar({ onMobileMenuOpen, onCommandPalette, theme, onToggleTheme }) {
  const navigate = useNavigate();
  const { status, latency, retryConnection } = useBackendStatus();

  return (
    <header className="glass-card" style={{
      position: 'sticky', top: 0, zIndex: 20,
      borderBottom: '1px solid rgba(255,255,255,0.06)',
      borderTop: 'none', borderLeft: 'none', borderRight: 'none',
      borderRadius: 0,
      padding: '0 24px',
      height: 60,
      display: 'flex',
      alignItems: 'center',
      gap: 12,
    }}>
      {/* Mobile menu toggle */}
      <button
        className="btn-ghost md:hidden"
        onClick={onMobileMenuOpen}
        aria-label="Open navigation menu"
        style={{ padding: 8 }}
      >
        <Menu size={18} />
      </button>

      {/* Global search launcher */}
      <button
        onClick={onCommandPalette}
        style={{
          flex: 1, maxWidth: 440,
          display: 'flex', alignItems: 'center', gap: 10,
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: 10,
          padding: '8px 14px',
          color: '#64748b',
          cursor: 'text',
          fontSize: 13,
          transition: 'border-color 0.2s',
        }}
        aria-label="Open global search (Ctrl+K)"
      >
        <Search size={14} style={{ flexShrink: 0 }} />
        <span style={{ flex: 1, textAlign: 'left' }}>Global Search: URLs, Domains, IPs, IOCs...</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 4, padding: '2px 6px', fontSize: 11 }}>
          <Command size={10} />
          <span>K</span>
        </div>
      </button>

      <div style={{ flex: 1 }} />

      {/* Backend Health Status Badge */}
      <div style={{ display: 'flex', alignItems: 'center' }}>
        {status === 'CONNECTED' ? (
          <div
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 11, fontWeight: 600, color: '#10b981',
              background: 'rgba(16,185,129,0.08)',
              border: '1px solid rgba(16,185,129,0.2)',
              padding: '4px 10px', borderRadius: 8,
              fontFamily: 'var(--font-mono)',
            }}
            title={latency ? `API Online (${latency}ms)` : 'API Online'}
          >
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }} />
            <span className="hidden sm:inline">API ONLINE</span>
            {latency && <span style={{ opacity: 0.7, fontSize: 10 }}>{latency}ms</span>}
          </div>
        ) : status === 'CONNECTING' ? (
          <div
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 11, fontWeight: 600, color: '#00c2ff',
              background: 'rgba(0,194,255,0.08)',
              border: '1px solid rgba(0,194,255,0.2)',
              padding: '4px 10px', borderRadius: 8,
              fontFamily: 'var(--font-mono)',
            }}
          >
            <RefreshCw size={11} className="animate-spin text-cyan-400" />
            <span className="hidden sm:inline">CONNECTING...</span>
          </div>
        ) : (
          <button
            onClick={retryConnection}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 11, fontWeight: 600, color: '#f87171',
              background: 'rgba(239,68,68,0.08)',
              border: '1px solid rgba(239,68,68,0.2)',
              padding: '4px 10px', borderRadius: 8,
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
            }}
            title="Backend unavailable. Click to retry connection."
          >
            <WifiOff size={11} />
            <span className="hidden sm:inline">API OFFLINE</span>
            <span style={{ fontSize: 10, textDecoration: 'underline' }}>Retry</span>
          </button>
        )}
      </div>

      {/* Theme Toggle (Dark / Light) */}
      <button
        className="btn-ghost"
        onClick={onToggleTheme}
        aria-label="Toggle dark/light mode"
        style={{ padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
        title={theme === 'light' ? 'Switch to Dark SOC Mode' : 'Switch to Light SOC Mode'}
      >
        {theme === 'light' ? <Moon size={15} color="#00c2ff" /> : <Sun size={15} color="#f59e0b" />}
        <span className="hidden sm:inline" style={{ fontSize: 11 }}>{theme === 'light' ? 'Dark' : 'Light'}</span>
      </button>

      {/* Notifications */}
      <button className="btn-ghost" style={{ padding: 8, position: 'relative' }} aria-label="Notifications">
        <Bell size={16} />
        <div style={{ position: 'absolute', top: 6, right: 6, width: 6, height: 6, borderRadius: '50%', background: '#00c2ff' }} />
      </button>

      {/* User avatar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '6px 10px',
        background: 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 10,
        cursor: 'pointer',
      }} onClick={() => navigate('/settings')} role="button" aria-label="Open settings">
        <div style={{
          width: 28, height: 28,
          borderRadius: 8,
          background: 'linear-gradient(135deg,#00c2ff,#2563eb)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 12, fontWeight: 700, color: '#fff',
        }}>A</div>
        <span style={{ fontSize: 13, fontWeight: 500 }}>SOC Lead</span>
      </div>
    </header>
  );
}
