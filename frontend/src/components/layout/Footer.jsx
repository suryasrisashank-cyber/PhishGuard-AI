import React from 'react';
import { Shield } from 'lucide-react';

export default function Footer() {
  return (
    <footer
      className="site-footer"
      style={{
        borderTop: '1px solid var(--border-subtle)',
        background: 'var(--bg-surface)',
        padding: '16px 24px',
        marginTop: 'auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
        fontSize: 12,
        color: 'var(--text-dim)',
        fontFamily: 'var(--font-sans)',
        transition: 'background-color 0.25s ease, border-color 0.25s ease',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Shield size={14} style={{ color: 'var(--accent-cyan)' }} />
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
          PhishGuard AI 3.0
        </span>
        <span style={{ opacity: 0.4 }}>—</span>
        <span className="hidden sm:inline">Real-World SOC Platform</span>
      </div>

      <div
        className="footer-rights"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          flexWrap: 'wrap',
          color: 'var(--text-muted)',
        }}
      >
        <span>
          Developed by <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>@CYBERGUARD</span>
        </span>
        <span style={{ opacity: 0.5 }}>•</span>
        <span>All rights reserved 2026</span>
      </div>
    </footer>
  );
}
