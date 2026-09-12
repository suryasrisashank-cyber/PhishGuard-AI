import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronUp, Copy, CheckCircle, XCircle, Filter, ShieldAlert } from 'lucide-react';
import SeverityBadge from '../ui/SeverityBadge.jsx';
import { IOC_TYPE_ICONS, EVIDENCE_CATEGORIES } from '../../lib/constants.js';
import toast from 'react-hot-toast';

function EvidenceRow({ item }) {
  const [expanded, setExpanded] = useState(false);
  const icon = IOC_TYPE_ICONS[item.ioc_type] || '🔍';

  const copyEvidence = () => {
    const text = item.technical_evidence || item.ioc_value || item.explanation;
    navigator.clipboard.writeText(text);
    toast.success('Technical evidence copied');
  };

  return (
    <div style={{
      border: `1px solid ${item.passed ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.08)'}`,
      borderRadius: 10,
      marginBottom: 8,
      overflow: 'hidden',
      background: expanded ? 'rgba(255,255,255,0.02)' : 'transparent',
    }}>
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px',
          cursor: 'pointer', transition: 'background 0.15s',
        }}
        onClick={() => setExpanded(e => !e)}
        role="button"
        aria-expanded={expanded}
      >
        {item.passed
          ? <CheckCircle size={15} color="#10b981" style={{ flexShrink: 0 }} />
          : <XCircle size={15} color="#ef4444" style={{ flexShrink: 0 }} />
        }
        <span style={{ fontSize: 10, color: '#64748b', background: 'rgba(255,255,255,0.04)', padding: '2px 6px', borderRadius: 4, fontFamily: 'var(--font-mono)' }}>
          {item.category || 'URL'}
        </span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: item.passed ? '#94a3b8' : '#f1f5f9' }}>
          {item.name}
        </span>
        {!item.passed && <SeverityBadge severity={item.severity} size="sm" />}
        {expanded ? <ChevronUp size={14} color="#64748b" /> : <ChevronDown size={14} color="#64748b" />}
      </div>

      {expanded && (
        <div style={{ padding: '14px 16px 16px', borderTop: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.18)' }}>
          {/* Technical Evidence Box */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Technical Evidence</span>
              <button onClick={copyEvidence} style={{ background: 'none', border: 'none', color: '#00c2ff', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Copy size={11} /> Copy Evidence
              </button>
            </div>
            <div style={{
              background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: 6, padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 12,
              color: '#cbd5e1', wordBreak: 'break-all',
            }}>
              {item.technical_evidence || item.ioc_value || 'No raw payload observed'}
            </div>
          </div>

          {/* Explanation */}
          <p style={{ margin: '0 0 8px', fontSize: 12, color: '#94a3b8', lineHeight: 1.6 }}>
            <strong style={{ color: '#e2e8f0' }}>SOC Explanation:</strong> {item.explanation}
          </p>

          {!item.passed && item.score_impact > 0 && (
            <div style={{ fontSize: 11, color: '#64748b' }}>
              Risk Impact: <span style={{ color: '#f97316', fontWeight: 700 }}>+{item.score_impact} pts</span> (Rule Weight: {item.weight || item.score_impact})
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function EvidencePanel({ indicators = [] }) {
  const [activeCategory, setActiveCategory] = useState('ALL');
  const [filterMode, setFilterMode] = useState('failed'); // 'failed' | 'all' | 'passed'

  const filtered = useMemo(() => {
    return indicators.filter(ind => {
      // Category filter
      if (activeCategory !== 'ALL' && (ind.category || 'URL') !== activeCategory) {
        return false;
      }
      // Pass/Fail filter
      if (filterMode === 'failed') return !ind.passed;
      if (filterMode === 'passed') return ind.passed;
      return true;
    });
  }, [indicators, activeCategory, filterMode]);

  const failedCount = indicators.filter(i => !i.passed).length;
  const passedCount = indicators.filter(i => i.passed).length;

  return (
    <div>
      {/* Category Tabs */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 14 }}>
        {EVIDENCE_CATEGORIES.map(cat => {
          const count = cat === 'ALL'
            ? indicators.length
            : indicators.filter(i => (i.category || 'URL') === cat).length;
          if (cat !== 'ALL' && count === 0) return null;

          return (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className="btn-ghost"
              style={{
                fontSize: 11, padding: '5px 10px',
                borderColor: activeCategory === cat ? '#00c2ff' : undefined,
                color: activeCategory === cat ? '#00c2ff' : undefined,
                background: activeCategory === cat ? 'rgba(0,194,255,0.08)' : undefined,
              }}
            >
              {cat} ({count})
            </button>
          );
        })}
      </div>

      {/* Filter Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <span style={{ fontSize: 12, color: '#64748b' }}>
          Showing {filtered.length} indicator(s)
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            className="btn-ghost"
            onClick={() => setFilterMode('failed')}
            style={{
              fontSize: 11, padding: '3px 8px',
              color: filterMode === 'failed' ? '#ef4444' : undefined,
              borderColor: filterMode === 'failed' ? '#ef4444' : undefined,
            }}
          >
            Failed ({failedCount})
          </button>
          <button
            className="btn-ghost"
            onClick={() => setFilterMode('all')}
            style={{
              fontSize: 11, padding: '3px 8px',
              color: filterMode === 'all' ? '#00c2ff' : undefined,
              borderColor: filterMode === 'all' ? '#00c2ff' : undefined,
            }}
          >
            All Checks ({indicators.length})
          </button>
          <button
            className="btn-ghost"
            onClick={() => setFilterMode('passed')}
            style={{
              fontSize: 11, padding: '3px 8px',
              color: filterMode === 'passed' ? '#10b981' : undefined,
              borderColor: filterMode === 'passed' ? '#10b981' : undefined,
            }}
          >
            Passed ({passedCount})
          </button>
        </div>
      </div>

      {/* Items list */}
      {filtered.length === 0 ? (
        <div style={{ padding: 24, textAlign: 'center', color: '#64748b', fontSize: 13 }}>
          No indicators found for the selected category.
        </div>
      ) : (
        filtered.map((item, idx) => <EvidenceRow key={idx} item={item} />)
      )}
    </div>
  );
}
