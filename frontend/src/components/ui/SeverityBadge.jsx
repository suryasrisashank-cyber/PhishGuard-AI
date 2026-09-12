import React from 'react';
import { SEVERITY_CONFIG } from '../../lib/constants.js';

export default function SeverityBadge({ severity, size = 'md' }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.INFORMATIONAL;
  const pad = size === 'sm' ? '2px 7px' : '3px 9px';
  const fs = size === 'sm' ? 10 : 11;

  return (
    <span style={{
      display: 'inline-block',
      padding: pad,
      borderRadius: 6,
      background: cfg.bg,
      color: cfg.color,
      fontSize: fs,
      fontWeight: 700,
      letterSpacing: '0.06em',
      whiteSpace: 'nowrap',
    }}>
      {cfg.label}
    </span>
  );
}
