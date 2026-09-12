import React, { useEffect, useRef, useMemo } from 'react';

/**
 * CSS/SVG animated threat activity visualization.
 * NOT backed by real geographic data — labeled clearly as "Threat Activity Visualization".
 * Uses no WebGL/Three.js — pure SVG + CSS animation for performance.
 */
const NODE_COUNT = 18;

function seededRandom(seed) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) & 0xffffffff;
    return ((s >>> 0) / 0xffffffff);
  };
}

export default function ThreatNetwork({ stats }) {
  const rand = useMemo(() => seededRandom(42), []);

  const nodes = useMemo(() => Array.from({ length: NODE_COUNT }, (_, i) => ({
    id: i,
    x: 50 + rand() * 500,
    y: 40 + rand() * 180,
    r: 3 + rand() * 5,
    threat: rand() > 0.65,
    delay: rand() * 2,
    duration: 2 + rand() * 3,
  })), []);

  const edges = useMemo(() => {
    const result = [];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120 && result.length < 24) {
          result.push({ from: i, to: j, threat: nodes[i].threat || nodes[j].threat });
        }
      }
    }
    return result;
  }, [nodes]);

  return (
    <div style={{ position: 'relative', width: '100%', height: 260, overflow: 'hidden', borderRadius: 12 }}>
      {/* Background grid */}
      <svg width="100%" height="100%" style={{ position: 'absolute', inset: 0, opacity: 0.15 }}>
        <defs>
          <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
            <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(0,194,255,0.3)" strokeWidth="0.5" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>

      {/* Network */}
      <svg width="600" height="260" viewBox="0 0 600 260" style={{ position: 'absolute', left: '50%', transform: 'translateX(-50%)' }}>
        {edges.map((e, i) => (
          <line
            key={i}
            x1={nodes[e.from].x} y1={nodes[e.from].y}
            x2={nodes[e.to].x} y2={nodes[e.to].y}
            stroke={e.threat ? 'rgba(239,68,68,0.25)' : 'rgba(0,194,255,0.1)'}
            strokeWidth={e.threat ? 1.5 : 0.8}
          />
        ))}
        {nodes.map(n => (
          <g key={n.id}>
            {n.threat && (
              <circle cx={n.x} cy={n.y} r={n.r + 4} fill="rgba(239,68,68,0.1)">
                <animate attributeName="r" values={`${n.r + 2};${n.r + 8};${n.r + 2}`} dur={`${n.duration}s`} begin={`${n.delay}s`} repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.6;0;0.6" dur={`${n.duration}s`} begin={`${n.delay}s`} repeatCount="indefinite" />
              </circle>
            )}
            <circle
              cx={n.x} cy={n.y} r={n.r}
              fill={n.threat ? '#ef4444' : '#00c2ff'}
              opacity={n.threat ? 0.9 : 0.6}
            >
              <animate attributeName="opacity" values={`${n.threat ? 0.9 : 0.6};${n.threat ? 0.6 : 0.3};${n.threat ? 0.9 : 0.6}`} dur={`${n.duration}s`} begin={`${n.delay}s`} repeatCount="indefinite" />
            </circle>
          </g>
        ))}
      </svg>

      {/* Label */}
      <div style={{ position: 'absolute', bottom: 10, right: 14 }}>
        <span style={{ fontSize: 10, color: '#334155', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          Threat Activity Visualization — Demo Data
        </span>
      </div>

      {/* Live indicator */}
      <div style={{ position: 'absolute', top: 14, right: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }}>
          <div style={{ width: '100%', height: '100%', borderRadius: '50%', background: '#10b981', animation: 'pulse 2s ease infinite' }} />
        </div>
        <span style={{ fontSize: 10, color: '#64748b', fontWeight: 600 }}>MONITORING</span>
      </div>
    </div>
  );
}
