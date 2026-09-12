import React, { useState, useEffect } from 'react';
import { CheckCircle, Circle, Loader } from 'lucide-react';

const URL_STAGES = [
  { name: 'Input Validation', desc: 'Validating scheme, syntax & length' },
  { name: 'URL Normalization', desc: 'Decoding hex & parsing authority parameters' },
  { name: 'Domain Analysis', desc: 'Inspecting TLD, brand mappings & homoglyphs' },
  { name: 'DNS Analysis', desc: 'Evaluating passive host mapping & resolver queries' },
  { name: 'Security Analysis', desc: 'Checking entropy & non-standard port binds' },
  { name: 'Content Analysis', desc: 'Scanning path keywords & credential cues' },
  { name: 'Indicator Extraction', desc: 'Synthesizing structured IOC artifacts' },
  { name: 'Risk Calculation', desc: 'Aggregating rule impacts and metric weights' },
  { name: 'Severity Classification', desc: 'Applying deterministic severity matrix' },
  { name: 'Final Verdict', desc: 'Generating SOC investigation report' },
];

export default function ScanProgress({ scanning, scanType = 'url' }) {
  const [currentStage, setCurrentStage] = useState(0);

  useEffect(() => {
    if (!scanning) { setCurrentStage(0); return; }
    setCurrentStage(0);
    const interval = setInterval(() => {
      setCurrentStage(s => {
        if (s >= URL_STAGES.length - 1) { clearInterval(interval); return s; }
        return s + 1;
      });
    }, 280);
    return () => clearInterval(interval);
  }, [scanning]);

  if (!scanning) return null;

  return (
    <div className="glass-card fade-in" style={{ padding: 24, borderRadius: 14, marginTop: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
        <Loader size={16} color="#00c2ff" style={{ animation: 'spin 1s linear infinite' }} />
        <span style={{ fontSize: 14, fontWeight: 700, color: '#00c2ff' }}>
          Deterministic Analysis Pipeline Active ({currentStage + 1} / {URL_STAGES.length})
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
        {URL_STAGES.map((stage, idx) => {
          const done = idx < currentStage;
          const active = idx === currentStage;
          return (
            <div
              key={stage.name}
              style={{
                display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 12px',
                borderRadius: 8,
                background: active ? 'rgba(0,194,255,0.08)' : done ? 'rgba(16,185,129,0.04)' : 'rgba(255,255,255,0.01)',
                border: `1px solid ${active ? 'rgba(0,194,255,0.3)' : done ? 'rgba(16,185,129,0.2)' : 'rgba(255,255,255,0.04)'}`,
              }}
            >
              <div style={{ marginTop: 2 }}>
                {done
                  ? <CheckCircle size={15} color="#10b981" />
                  : active
                  ? <Loader size={15} color="#00c2ff" style={{ animation: 'spin 1s linear infinite' }} />
                  : <Circle size={15} color="#334155" />
                }
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: done ? '#10b981' : active ? '#f1f5f9' : '#64748b' }}>
                  {stage.name}
                </div>
                <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>
                  {stage.desc}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
