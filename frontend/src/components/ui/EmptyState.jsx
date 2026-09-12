import React from 'react';
import { Shield } from 'lucide-react';

export default function EmptyState({ icon: Icon = Shield, title = 'No data yet', message = 'Run your first scan to see results here.' }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 32px', gap: 16, textAlign: 'center' }}>
      <div style={{ width: 64, height: 64, borderRadius: 16, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Icon size={28} color="#475569" />
      </div>
      <div>
        <p style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#e2e8f0' }}>{title}</p>
        <p style={{ margin: '6px 0 0', fontSize: 13, color: '#64748b', maxWidth: 320 }}>{message}</p>
      </div>
    </div>
  );
}
