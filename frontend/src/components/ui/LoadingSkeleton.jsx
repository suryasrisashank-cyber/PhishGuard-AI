import React from 'react';

export function SkeletonLine({ width = '100%', height = 16 }) {
  return (
    <div style={{
      width, height,
      borderRadius: 6,
      background: 'linear-gradient(90deg, rgba(255,255,255,0.04) 25%, rgba(255,255,255,0.08) 50%, rgba(255,255,255,0.04) 75%)',
      backgroundSize: '200% 100%',
      animation: 'shimmer 1.6s linear infinite',
    }} />
  );
}

export function SkeletonCard({ lines = 3 }) {
  return (
    <div className="glass-card" style={{ padding: 20, borderRadius: 14 }}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} style={{ marginBottom: i < lines - 1 ? 12 : 0 }}>
          <SkeletonLine width={i === 0 ? '60%' : i % 2 === 0 ? '80%' : '100%'} />
        </div>
      ))}
    </div>
  );
}

export default function LoadingSkeleton({ cards = 4 }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 16 }}>
      {Array.from({ length: cards }).map((_, i) => <SkeletonCard key={i} />)}
    </div>
  );
}
