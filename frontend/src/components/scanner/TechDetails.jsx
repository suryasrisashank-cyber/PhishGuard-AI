import React from 'react';

export default function TechDetails({ scan }) {
  const items = [
    { label: 'Detection Engine', value: scan.detection_engine_version || '2.0.0' },
    { label: 'Analysis Type', value: 'Heuristic rule-based detection' },
    { label: 'Scan Type', value: scan.scan_type?.toUpperCase() || 'N/A' },
    { label: 'Processing Time', value: scan.processing_time_ms ? `${scan.processing_time_ms.toFixed(1)} ms` : 'N/A' },
    { label: 'Indicators Checked', value: scan.indicators ? `${scan.indicators.length} checks` : 'N/A' },
    { label: 'External APIs', value: 'None (heuristic only)' },
    { label: 'ML Inference', value: 'Not used in this scan' },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
      {items.map(({ label, value }) => (
        <div key={label} style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <p style={{ margin: '0 0 4px', fontSize: 10, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</p>
          <p style={{ margin: 0, fontSize: 13, color: '#cbd5e1', fontFamily: label.includes('Engine') || label.includes('Type') ? 'var(--font-mono)' : 'inherit' }}>{value}</p>
        </div>
      ))}
    </div>
  );
}
