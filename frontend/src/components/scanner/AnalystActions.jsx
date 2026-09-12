import React from 'react';
import { ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function AnalystActions({ actions = [] }) {
  const navigate = useNavigate();

  if (!actions || actions.length === 0) {
    return <p style={{ color: '#64748b', fontSize: 13 }}>No analyst actions generated.</p>;
  }

  const getActionNav = (action) => {
    if (action.toLowerCase().includes('website analysis') || action.toLowerCase().includes('website analyzer')) return '/scanner/website';
    if (action.toLowerCase().includes('threat intel')) return '/threat-intel';
    if (action.toLowerCase().includes('url scanner')) return '/scanner/url';
    if (action.toLowerCase().includes('scan history')) return '/history';
    if (action.toLowerCase().includes('report')) return '/reports';
    return null;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {actions.map((action, i) => {
        const nav = getActionNav(action);
        return (
          <div
            key={i}
            style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 14px',
              borderRadius: 10,
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.06)',
              cursor: nav ? 'pointer' : 'default',
              transition: 'border-color 0.15s',
            }}
            onClick={() => nav && navigate(nav)}
          >
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#00c2ff', flexShrink: 0 }} />
            <span style={{ flex: 1, fontSize: 13, color: '#cbd5e1' }}>{action}</span>
            {nav && <ArrowRight size={14} color="#64748b" />}
          </div>
        );
      })}
    </div>
  );
}
