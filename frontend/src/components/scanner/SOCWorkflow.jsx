import React from 'react';
import { SOC_WORKFLOW_STAGES } from '../../lib/constants.js';

/**
 * Visual indicator of which SOC workflow stage the investigation is at.
 * verdict: 'Safe' | 'Suspicious' | 'Malicious' | null (scanning)
 */
export default function SOCWorkflow({ stage = 'detect', verdict = null, scanning = false }) {
  const stageIndex = SOC_WORKFLOW_STAGES.findIndex(s => s.id === stage);
  const activeIdx = scanning ? 0 : verdict ? 4 : stageIndex;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, flexWrap: 'nowrap', overflowX: 'auto', padding: '16px 0' }}>
      {SOC_WORKFLOW_STAGES.map((s, idx) => {
        const done = idx < activeIdx;
        const active = idx === activeIdx;
        const color = active ? '#00c2ff' : done ? '#10b981' : '#334155';
        return (
          <React.Fragment key={s.id}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, minWidth: 72 }}>
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: active ? 'rgba(0,194,255,0.15)' : done ? 'rgba(16,185,129,0.1)' : 'rgba(255,255,255,0.04)',
                border: `2px solid ${color}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 16,
                animation: active && scanning ? 'pulse 1.5s ease infinite' : 'none',
              }}>
                {s.icon}
              </div>
              <span style={{ fontSize: 10, fontWeight: 600, color, textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
                {s.label}
              </span>
            </div>
            {idx < SOC_WORKFLOW_STAGES.length - 1 && (
              <div style={{ flex: 1, height: 2, minWidth: 16, background: done ? '#10b981' : 'rgba(255,255,255,0.06)', marginBottom: 22 }} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
