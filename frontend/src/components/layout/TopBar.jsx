import React from 'react';
import { Search, Bell, Menu, Shield, Sun, Moon, Wifi, WifiOff, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useBackendStatus } from '../../context/BackendStatusContext.jsx';

export default function TopBar({ onMobileMenuOpen, onCommandPalette, theme, onToggleTheme }) {
  const navigate = useNavigate();
  const { status, latency, retryConnection } = useBackendStatus();

  return (
    <header className="topbar-container glass-card">
      {/* DESKTOP ROW (Hidden on mobile, visible on >= 768px) */}
      <div className="topbar-desktop-row">
        {/* Global search launcher */}
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
              Search anything...
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
            <span>Ctrl</span>
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
              <span>API ONLINE</span>
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
              <span>CONNECTING...</span>
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
              <span>API OFFLINE</span>
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
          <span style={{ fontSize: 11 }}>{theme === 'light' ? 'Dark' : 'Light'}</span>
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
      </div>

      {/* MOBILE ROW (Visible on < 768px, hidden on desktop) */}
      <div className="topbar-mobile-row">
        {/* Mobile Header: Hamburger + Brand + Compact Status + Actions */}
        <div className="topbar-mobile-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              className="btn-ghost touch-btn"
              onClick={onMobileMenuOpen}
              aria-label="Open navigation drawer"
              style={{ padding: '8px 10px', minWidth: 40, minHeight: 40, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              <Menu size={20} color="var(--accent-cyan)" />
            </button>

            <div
              style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
              onClick={() => navigate('/')}
            >
              <div style={{ width: 26, height: 26, borderRadius: 6, background: 'linear-gradient(135deg,#00c2ff,#2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Shield size={14} color="#fff" />
              </div>
              <span style={{ fontSize: 15, fontWeight: 800, color: '#f1f5f9', letterSpacing: '-0.01em' }}>
                PhishGuard
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {/* Compact Status Indicator */}
            {status === 'CONNECTED' ? (
              <div
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  fontSize: 10, fontWeight: 700, color: '#10b981',
                  background: 'rgba(16,185,129,0.1)',
                  border: '1px solid rgba(16,185,129,0.25)',
                  padding: '4px 8px', borderRadius: 6,
                  fontFamily: 'var(--font-mono)',
                }}
                title="API Online"
              >
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }} />
                <span>ONLINE</span>
              </div>
            ) : status === 'CONNECTING' ? (
              <div
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  fontSize: 10, fontWeight: 700, color: '#00c2ff',
                  background: 'rgba(0,194,255,0.1)',
                  border: '1px solid rgba(0,194,255,0.25)',
                  padding: '4px 8px', borderRadius: 6,
                  fontFamily: 'var(--font-mono)',
                }}
              >
                <RefreshCw size={9} className="animate-spin text-cyan-400" />
                <span>WAKING</span>
              </div>
            ) : (
              <button
                onClick={retryConnection}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  fontSize: 10, fontWeight: 700, color: '#f87171',
                  background: 'rgba(239,68,68,0.1)',
                  border: '1px solid rgba(239,68,68,0.25)',
                  padding: '4px 8px', borderRadius: 6,
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                }}
              >
                <WifiOff size={10} />
                <span>RETRY</span>
              </button>
            )}

            {/* Mobile Theme Toggle */}
            <button
              className="btn-ghost touch-btn"
              onClick={onToggleTheme}
              aria-label="Toggle theme"
              style={{ padding: '8px', minWidth: 36, minHeight: 36, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              {theme === 'light' ? <Moon size={16} color="#00c2ff" /> : <Sun size={16} color="#f59e0b" />}
            </button>

            {/* Mobile Settings Icon */}
            <button
              className="btn-ghost touch-btn"
              onClick={() => navigate('/settings')}
              aria-label="Settings"
              style={{ padding: '8px', minWidth: 36, minHeight: 36, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              <div style={{
                width: 22, height: 22,
                borderRadius: 6,
                background: 'linear-gradient(135deg,#00c2ff,#2563eb)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 10, fontWeight: 700, color: '#fff',
              }}>A</div>
            </button>
          </div>
        </div>

        {/* Mobile Search Row: Full-width, Horizontal, Touch-friendly (min 44px) */}
        <button
          onClick={onCommandPalette}
          className="search-launcher topbar-mobile-search"
          style={{
            width: '100%',
            height: 44,
            minHeight: 44,
            display: 'flex',
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 10,
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 10,
            padding: '0 14px',
            color: 'var(--text-dim)',
            cursor: 'pointer',
            fontSize: 13,
            boxSizing: 'border-box',
          }}
          aria-label="Open search launcher"
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <Search size={16} style={{ color: 'var(--accent-cyan)', flexShrink: 0 }} />
            <span style={{ color: 'var(--text-dim)', fontSize: 13, textAlign: 'left', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              Search commands, cases, URLs...
            </span>
          </div>
          <span style={{
            fontSize: 10,
            fontFamily: 'var(--font-mono)',
            padding: '3px 7px',
            borderRadius: 4,
            background: 'var(--bg-card-hover)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text-muted)',
            flexShrink: 0,
          }}>
            Ctrl+K
          </span>
        </button>
      </div>
    </header>
  );
}

