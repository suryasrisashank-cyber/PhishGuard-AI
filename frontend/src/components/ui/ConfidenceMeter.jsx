import React, { useEffect, useState } from 'react';

export default function ConfidenceMeter({ value = null }) {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    if (value !== null) {
      const timer = setTimeout(() => setAnimated(value), 400);
      return () => clearTimeout(timer);
    }
  }, [value]);

  if (value === null) {
    return (
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          <span style={{ fontSize: 11, color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Confidence</span>
          <span style={{ fontSize: 11, color: '#475569' }}>Not available</span>
        </div>
        <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)' }} />
        <p style={{ fontSize: 11, color: '#475569', marginTop: 6 }}>
          Insufficient evidence to calculate a reliable confidence score.
        </p>
      </div>
    );
  }

  const color = animated >= 75 ? '#10b981' : animated >= 50 ? '#f59e0b' : '#ef4444';

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 11, color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Confidence</span>
        <span style={{ fontSize: 13, fontWeight: 700, color }}>{animated.toFixed(1)}%</span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
        <div style={{
          height: '100%',
          width: `${animated}%`,
          borderRadius: 3,
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          transition: 'width 1s ease',
        }} />
      </div>
      <p style={{ fontSize: 11, color: '#475569', marginTop: 6 }}>
        How strongly available evidence supports this verdict.
        {animated < 60 && ' Low confidence — additional investigation recommended.'}
      </p>
    </div>
  );
}
