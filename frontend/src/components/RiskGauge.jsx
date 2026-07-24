import React from 'react';

export default function RiskGauge({ value=0, size=140 }){
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, value));
  const offset = circumference - (pct/100) * circumference;

  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f59e0b' : '#00ffa3';

  return (
    <div style={{width:size,height:size,display:'flex',alignItems:'center',justifyContent:'center'}}>
      <svg width={size} height={size}>
        <defs>
          <linearGradient id="g1" x1="0%" x2="100%">
            <stop offset="0%" stopColor="#00c2ff" />
            <stop offset="100%" stopColor="#00ffa3" />
          </linearGradient>
        </defs>
        <g transform={`translate(${size/2},${size/2})`}>
          <circle r={radius} stroke="#061028" strokeWidth={stroke} fill="transparent" />
          <circle r={radius} stroke="url(#g1)" strokeWidth={stroke} fill="transparent" strokeDasharray={`${circumference} ${circumference}`} strokeDashoffset={offset} strokeLinecap="round" transform={`rotate(-90)`} />
          <text x="0" y="6" textAnchor="middle" fontSize="20" fill={color} fontWeight="700">{Math.round(pct)}</text>
        </g>
      </svg>
    </div>
  )
}
