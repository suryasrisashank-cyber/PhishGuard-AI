import React from 'react';
import { VERDICT_CONFIG } from '../../lib/constants.js';

export default function ThreatBadge({ verdict, size = 'md' }) {
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.Unknown;
  const pad = size === 'sm' ? '3px 8px' : size === 'lg' ? '6px 14px' : '4px 10px';
  const fs = size === 'sm' ? 10 : size === 'lg' ? 13 : 11;

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 4,
      padding: pad,
      borderRadius: 999,
      background: cfg.bg,
      border: `1px solid ${cfg.border}`,
      color: cfg.color,
      fontSize: fs,
      fontWeight: 700,
      letterSpacing: '0.06em',
      whiteSpace: 'nowrap',
      fontFamily: 'var(--font-sans)',
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.color, flexShrink: 0 }} />
      {cfg.label}
    </span>
  );
}
