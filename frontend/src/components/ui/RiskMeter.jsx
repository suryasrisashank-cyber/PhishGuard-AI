import React, { useEffect, useState } from 'react';

export default function RiskMeter({ value = 0, size = 140, label = 'Risk Score' }) {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setAnimated(value), 200);
    return () => clearTimeout(timer);
  }, [value]);

  const stroke = 10;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, animated));
  const offset = circumference - (pct / 100) * circumference;

  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f59e0b' : '#10b981';
  const glow = pct >= 70 ? '0 0 20px rgba(239,68,68,0.3)' : pct >= 40 ? '0 0 20px rgba(245,158,11,0.25)' : '0 0 20px rgba(16,185,129,0.25)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <svg width={size} height={size} style={{ filter: `drop-shadow(${glow})` }}>
        <defs>
          <linearGradient id={`rg${value}`} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#00c2ff" />
            <stop offset="100%" stopColor={color} />
          </linearGradient>
        </defs>
        <g transform={`translate(${size / 2},${size / 2})`}>
          <circle r={radius} stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} fill="transparent" />
          <circle
            r={radius}
            stroke={`url(#rg${value})`}
            strokeWidth={stroke}
            fill="transparent"
            strokeDasharray={`${circumference} ${circumference}`}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform="rotate(-90)"
            style={{ transition: 'stroke-dashoffset 1s ease' }}
          />
          <text x="0" y="2" textAnchor="middle" fontSize={size > 120 ? 22 : 16} fill={color} fontWeight="800" fontFamily="Inter,sans-serif">
            {Math.round(pct)}
          </text>
          <text x="0" y={size > 120 ? 18 : 14} textAnchor="middle" fontSize="9" fill="#64748b" fontWeight="600" letterSpacing="1">
            /100
          </text>
        </g>
      </svg>
      <span style={{ fontSize: 11, color: '#64748b', fontWeight: 600, letterSpacing: '0.07em', textTransform: 'uppercase' }}>{label}</span>
    </div>
  );
}
