import React, { useState, useEffect } from 'react';
import { Sparkles, Shield, Info, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';
import { aiApi } from '../../services/api.js';

export default function AIExplanationCard({ scan }) {
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchExplanation = async () => {
    if (!scan) return;
    setLoading(true);
    setError(null);
    try {
      const res = await aiApi.explain({
        verdict: scan.verdict,
        risk_score: scan.risk_score,
        confidence_score: scan.confidence_score,
        severity: scan.severity,
        target: scan.target,
        indicators: scan.indicators || [],
        mitre_techniques: scan.mitre_techniques || [],
      });
      setExplanation(res.data);
    } catch (err) {
      setError(err.message || 'AI explanation unavailable');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExplanation();
  }, [scan?.id, scan?.target]);

  if (!scan) return null;

  return (
    <div style={{
      background: 'linear-gradient(135deg, rgba(124,58,237,0.08) 0%, rgba(0,194,255,0.05) 100%)',
      border: '1px solid rgba(124,58,237,0.25)',
      borderRadius: 12,
      padding: '20px 24px',
      marginBottom: 20,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Sparkles size={16} color="#7c3aed" />
          <span style={{ fontSize: 12, fontWeight: 700, color: '#a78bfa', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            AI Security Explanation Layer
          </span>
          <span style={{ fontSize: 10, color: '#64748b', background: 'rgba(255,255,255,0.04)', padding: '2px 6px', borderRadius: 4 }}>
            Deterministic Source of Truth
          </span>
        </div>
        <button
          onClick={fetchExplanation}
          disabled={loading}
          style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}
        >
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 0', color: '#94a3b8', fontSize: 13 }}>
          <div style={{ width: 16, height: 16, border: '2px solid rgba(124,58,237,0.3)', borderTop: '2px solid #7c3aed', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
          Synthesizing structured scanner evidence into plain-English briefing...
        </div>
      ) : error ? (
        <p style={{ margin: 0, fontSize: 12, color: '#ef4444' }}>{error}</p>
      ) : explanation ? (
        <div>
          <h4 style={{ margin: '0 0 8px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>
            {explanation.headline}
          </h4>
          <p style={{ margin: '0 0 14px', fontSize: 13, color: '#cbd5e1', lineHeight: 1.7 }}>
            {explanation.explanation}
          </p>

          {/* Key Drivers */}
          <div style={{ marginBottom: 12 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Key Threat Drivers:</span>
            <ul style={{ margin: '6px 0 0', paddingLeft: 18, color: '#94a3b8', fontSize: 12, lineHeight: 1.6 }}>
              {explanation.key_drivers?.map((driver, i) => <li key={i}>{driver}</li>)}
            </ul>
          </div>

          {/* Analyst Context */}
          <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 8, padding: '10px 14px', marginBottom: 10 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#00c2ff', textTransform: 'uppercase' }}>SOC Analyst Guidance: </span>
            <span style={{ fontSize: 12, color: '#cbd5e1' }}>{explanation.analyst_context}</span>
          </div>

          <div style={{ fontSize: 10, color: '#64748b', fontStyle: 'italic' }}>
            {explanation.disclaimer}
          </div>
        </div>
      ) : null}
    </div>
  );
}
