import React from 'react';
import { Clock } from 'lucide-react';

export default function InvestigationTimeline({ events = [] }) {
  if (!events || events.length === 0) {
    return <p style={{ color: '#64748b', fontSize: 13 }}>No timeline data available.</p>;
  }

  return (
    <div style={{ position: 'relative', paddingLeft: 24 }}>
      <div style={{ position: 'absolute', left: 7, top: 0, bottom: 0, width: 2, background: 'rgba(0,194,255,0.15)', borderRadius: 1 }} />
      {events.map((ev, i) => (
        <div key={i} style={{ position: 'relative', marginBottom: i < events.length - 1 ? 20 : 0, paddingLeft: 20 }}>
          <div style={{
            position: 'absolute', left: -7, top: 2,
            width: 12, height: 12, borderRadius: '50%',
            background: i === events.length - 1 ? '#00c2ff' : '#1e3a5f',
            border: `2px solid ${i === events.length - 1 ? '#00c2ff' : 'rgba(0,194,255,0.3)'}`,
          }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
            <Clock size={10} color="#64748b" />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#64748b' }}>{ev.timestamp}</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: i === events.length - 1 ? '#00c2ff' : '#94a3b8' }}>{ev.event}</span>
          </div>
          <p style={{ margin: 0, fontSize: 12, color: '#64748b', lineHeight: 1.5 }}>{ev.detail}</p>
        </div>
      ))}
    </div>
  );
}
