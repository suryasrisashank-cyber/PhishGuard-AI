import React from 'react';
import GlassCard from './GlassCard.jsx';

export default function StatCard({ title, value, icon: Icon, color = '#00c2ff', subtitle }) {
  return (
    <GlassCard hover style={{ padding: '20px 24px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <p style={{ margin: 0, fontSize: 12, color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>{title}</p>
          <p style={{ margin: '8px 0 4px', fontSize: 28, fontWeight: 800, color: '#f1f5f9' }}>{value ?? '—'}</p>
          {subtitle && <p style={{ margin: 0, fontSize: 12, color: '#475569' }}>{subtitle}</p>}
        </div>
        {Icon && (
          <div style={{ padding: 12, borderRadius: 10, background: `${color}15`, border: `1px solid ${color}25` }}>
            <Icon size={20} color={color} />
          </div>
        )}
      </div>
    </GlassCard>
  );
}
