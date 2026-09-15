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
      borderBottom: '1px solid var(--border-subtle)',
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

      {/* Global search launcher — Strictly Horizontal Layout */}
      <button
        onClick={onCommandPalette}
        className="search-launcher"
        style={{
          flex: '1 1 auto',
          maxWidth: 460,
          minWidth: 140,
          height: 38,
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 10,
          padding: '0 12px',
          color: 'var(--text-dim)',
          cursor: 'pointer',
          fontSize: 13,
          transition: 'border-color 0.2s, box-shadow 0.2s',
          overflow: 'hidden',
          whiteSpace: 'nowrap',
          boxSizing: 'border-box',
        }}
        aria-label="Open global search (Ctrl + K)"
        title="Search anything... (Ctrl + K)"
      >
        <div style={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          gap: 8,
          minWidth: 0,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          flex: 1,
        }}>
          <Search size={14} style={{ flexShrink: 0, color: 'var(--accent-cyan)' }} />
          <span style={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            color: 'var(--text-dim)',
            fontSize: 13,
            textAlign: 'left',
          }}>
            <span className="hidden sm:inline">Search anything...</span>
            <span className="inline sm:hidden">Search...</span>
          </span>
        </div>

        <div style={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          gap: 3,
          flexShrink: 0,
          background: 'var(--bg-card-hover)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 5,
          padding: '2px 6px',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-dim)',
          lineHeight: 1,
        }}>
          <span className="hidden sm:inline">Ctrl</span>
          <span className="inline sm:hidden">^</span>
          <span style={{ opacity: 0.6 }}>+</span>
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
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
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
