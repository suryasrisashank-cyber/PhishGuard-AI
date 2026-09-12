import React from 'react';
import { ExternalLink } from 'lucide-react';

export default function MitreMapping({ techniques = [] }) {
  if (!techniques || techniques.length === 0) {
    return (
      <div style={{ padding: '16px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <p style={{ margin: 0, fontSize: 13, color: '#475569' }}>
          No MITRE ATT&CK technique mappings — insufficient evidence to justify a technique assignment for this target.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {techniques.map((t, i) => (
        <div key={i} style={{ padding: 16, borderRadius: 10, background: 'rgba(124,58,237,0.08)', border: '1px solid rgba(124,58,237,0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: '#7c3aed', background: 'rgba(124,58,237,0.15)', padding: '3px 8px', borderRadius: 6 }}>
              {t.technique_id}
            </span>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>{t.technique_name}</span>
            <a
              href={`https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}`}
              target="_blank"
              rel="noopener noreferrer"
              style={{ marginLeft: 'auto', color: '#7c3aed', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, textDecoration: 'none' }}
            >
              ATT&CK <ExternalLink size={11} />
            </a>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <span style={{ fontSize: 11, color: '#94a3b8', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 4 }}>
              Tactic: {t.tactic}
            </span>
          </div>
          <p style={{ margin: '0 0 6px', fontSize: 12, color: '#94a3b8' }}><strong style={{ color: '#cbd5e1' }}>Reason:</strong> {t.reason}</p>
          <p style={{ margin: 0, fontSize: 12, color: '#94a3b8' }}><strong style={{ color: '#cbd5e1' }}>Evidence:</strong> {t.evidence}</p>
        </div>
      ))}
      <p style={{ margin: '4px 0 0', fontSize: 11, color: '#475569', fontStyle: 'italic' }}>
        ATT&CK mappings are only assigned when specific evidence patterns directly support the technique. These are not inferred speculatively.
      </p>
    </div>
  );
}
