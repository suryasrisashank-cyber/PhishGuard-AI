import React, { useState, useMemo } from 'react';
import { Copy, Search, Filter, Download, ExternalLink } from 'lucide-react';
import { IOC_TYPE_ICONS } from '../../lib/constants.js';
import SeverityBadge from '../ui/SeverityBadge.jsx';
import toast from 'react-hot-toast';

export default function IOCManagementTable({ indicators = [], target = '' }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');

  // Extract raw IOCs produced by analysis
  const iocs = useMemo(() => {
    const list = [];
    indicators.forEach((ind, i) => {
      if (ind.ioc_value && ind.ioc_value !== 'N/A' && ind.ioc_value !== 'Within expected parameters') {
        list.push({
          id: i + 1,
          type: ind.ioc_type || 'URL',
          value: ind.ioc_value,
          severity: ind.severity || 'INFORMATIONAL',
          source: ind.name,
          status: ind.passed ? 'BENIGN' : 'SUSPICIOUS',
        });
      }
    });
    return list;
  }, [indicators]);

  const filtered = useMemo(() => {
    return iocs.filter(ioc => {
      if (typeFilter !== 'ALL' && ioc.type !== typeFilter) return false;
      if (searchTerm && !ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) && !ioc.source.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
  }, [iocs, typeFilter, searchTerm]);

  const copyVal = (val) => {
    navigator.clipboard.writeText(val);
    toast.success('IOC value copied');
  };

  const exportIOCs = () => {
    const jsonStr = JSON.stringify(iocs, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iocs_${target.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    a.click();
    toast.success('IOC list exported');
  };

  if (iocs.length === 0) {
    return <p style={{ color: '#64748b', fontSize: 13 }}>No Indicators of Compromise extracted for this target.</p>;
  }

  return (
    <div>
      {/* Controls Bar */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <input
            type="text"
            className="cyber-input"
            placeholder="Search IOC value or detection source..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            style={{ paddingLeft: 36, paddingBottom: 6, paddingTop: 6, fontSize: 12 }}
          />
          <Search size={14} color="#64748b" style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }} />
        </div>

        <select
          className="cyber-input"
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          style={{ width: 140, padding: '6px 10px', fontSize: 12 }}
        >
          <option value="ALL">All Types ({iocs.length})</option>
          {['DOMAIN', 'URL', 'IP', 'HASH', 'EMAIL', 'FILE'].map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        <button className="btn-ghost" onClick={exportIOCs} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '6px 12px' }}>
          <Download size={13} /> Export IOCs
        </button>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Artifact Value</th>
              <th>Detection Source</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(ioc => (
              <tr key={ioc.id}>
                <td>
                  <span style={{ fontSize: 11, color: '#94a3b8' }}>
                    {IOC_TYPE_ICONS[ioc.type] || '🔍'} {ioc.type}
                  </span>
                </td>
                <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 12, color: '#cbd5e1' }}>
                  {ioc.value}
                </td>
                <td style={{ fontSize: 12, color: '#94a3b8' }}>{ioc.source}</td>
                <td><SeverityBadge severity={ioc.severity} size="sm" /></td>
                <td>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                    color: ioc.status === 'SUSPICIOUS' ? '#ef4444' : '#10b981',
                    background: ioc.status === 'SUSPICIOUS' ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)',
                  }}>
                    {ioc.status}
                  </span>
                </td>
                <td>
                  <button onClick={() => copyVal(ioc.value)} className="btn-ghost" style={{ padding: '3px 8px', fontSize: 11 }}>
                    <Copy size={11} /> Copy
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
