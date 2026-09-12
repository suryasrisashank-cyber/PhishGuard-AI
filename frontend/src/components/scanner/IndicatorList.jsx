import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Copy, CheckCircle, XCircle } from 'lucide-react';
import SeverityBadge from '../ui/SeverityBadge.jsx';
import { IOC_TYPE_ICONS } from '../../lib/constants.js';
import toast from 'react-hot-toast';

function IndicatorRow({ indicator }) {
  const [expanded, setExpanded] = useState(false);
  const icon = IOC_TYPE_ICONS[indicator.ioc_type] || '⚠️';

  const copyValue = () => {
    navigator.clipboard.writeText(indicator.ioc_value);
    toast.success('IOC value copied');
  };

  return (
    <div style={{
      border: `1px solid ${indicator.passed ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.06)'}`,
      borderRadius: 10,
      marginBottom: 8,
      overflow: 'hidden',
    }}>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', cursor: 'pointer', background: expanded ? 'rgba(255,255,255,0.03)' : 'transparent' }}
        onClick={() => setExpanded(e => !e)}
        role="button"
        aria-expanded={expanded}
      >
        {indicator.passed
          ? <CheckCircle size={14} color="#10b981" style={{ flexShrink: 0 }} />
          : <XCircle size={14} color="#ef4444" style={{ flexShrink: 0 }} />
        }
        <span style={{ fontSize: 11, color: '#64748b', flexShrink: 0 }}>{icon} {indicator.ioc_type}</span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: indicator.passed ? '#94a3b8' : '#f1f5f9' }}>{indicator.name}</span>
        {!indicator.passed && <SeverityBadge severity={indicator.severity} size="sm" />}
        {expanded ? <ChevronUp size={14} color="#64748b" /> : <ChevronDown size={14} color="#64748b" />}
      </div>

      {expanded && (
        <div style={{ padding: '12px 14px 14px', borderTop: '1px solid rgba(255,255,255,0.04)', background: 'rgba(0,0,0,0.1)' }}>
          {indicator.ioc_value && indicator.ioc_value !== 'N/A' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#94a3b8', background: 'rgba(255,255,255,0.05)', padding: '3px 8px', borderRadius: 6, maxWidth: '80%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {indicator.ioc_value}
              </span>
              <button onClick={copyValue} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', padding: 4 }} aria-label="Copy IOC value">
                <Copy size={12} />
              </button>
            </div>
          )}
          <p style={{ margin: 0, fontSize: 12, color: '#94a3b8', lineHeight: 1.6 }}>{indicator.explanation}</p>
          {!indicator.passed && indicator.score_impact > 0 && (
            <p style={{ margin: '8px 0 0', fontSize: 11, color: '#64748b' }}>
              Risk contribution: <span style={{ color: '#f97316', fontWeight: 600 }}>+{indicator.score_impact}</span> points
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export default function IndicatorList({ indicators = [], showPassed = false }) {
  if (!indicators || indicators.length === 0) {
    return <p style={{ color: '#64748b', fontSize: 13 }}>No indicators available.</p>;
  }

  const failed = indicators.filter(i => !i.passed);
  const passed = indicators.filter(i => i.passed);

  return (
    <div>
      {failed.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <p style={{ margin: '0 0 10px', fontSize: 11, color: '#ef4444', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            Suspicious Indicators ({failed.length})
          </p>
          {failed.map((ind, i) => <IndicatorRow key={i} indicator={ind} />)}
        </div>
      )}
      {showPassed && passed.length > 0 && (
        <div>
          <p style={{ margin: '0 0 10px', fontSize: 11, color: '#10b981', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            Passed Checks ({passed.length})
          </p>
          {passed.map((ind, i) => <IndicatorRow key={i} indicator={ind} />)}
        </div>
      )}
    </div>
  );
}
