import React from 'react';
import { STATUS_CONFIG } from '../../lib/constants.js';

export default function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.NEW;
  return (
    <span style={{
      display: 'inline-block',
      padding: '3px 9px',
      borderRadius: 6,
      background: cfg.bg,
      color: cfg.color,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.05em',
      whiteSpace: 'nowrap',
    }}>
      {cfg.label}
    </span>
  );
}
