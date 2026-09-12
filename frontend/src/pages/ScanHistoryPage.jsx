import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import StatusBadge from '../components/ui/StatusBadge.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { scansApi } from '../services/api.js';
import { Search, Download, Filter, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await scansApi.list({ verdict: verdictFilter, search });
      setScans(res.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch scan records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, [verdictFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadScans();
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(scans, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard_scans_${Date.now()}.json`;
    a.click();
    toast.success('Scans exported to JSON');
  };

  return (
    <div>
      <PageHeader
        title="Historical Scan Archive"
        subtitle="Complete database audit trail of all inspected URLs, files & communications"
        actions={
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn-ghost" onClick={exportJSON} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <Download size={14} /> Export JSON
            </button>
            <button className="btn-ghost" onClick={loadScans} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        }
      />

      {/* Filter Bar */}
      <GlassCard style={{ padding: '16px 20px', marginBottom: 20 }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
            <input
              type="text"
              className="cyber-input"
              placeholder="Search by target or domain..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: 38, paddingBottom: 8, paddingTop: 8 }}
            />
            <Search size={15} color="#64748b" style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }} />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Filter size={14} color="#64748b" />
            <select
              className="cyber-input"
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              style={{ width: 140, padding: '8px 12px', fontSize: 13 }}
            >
              <option value="">All Verdicts</option>
              <option value="Safe">Safe</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Malicious">Malicious</option>
            </select>
          </div>

          <button type="submit" className="btn-primary" style={{ padding: '8px 16px', fontSize: 13 }}>
            Filter
          </button>
        </form>
      </GlassCard>

      {/* Scans Table */}
      <GlassCard style={{ padding: 20 }}>
        {loading ? (
          <LoadingSkeleton cards={3} />
        ) : error ? (
          <ErrorState message={error} onRetry={loadScans} />
        ) : scans.length === 0 ? (
          <p style={{ textAlign: 'center', color: '#64748b', padding: '36px 0', fontSize: 13 }}>
            No scans match the current filter parameters.
          </p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Risk Score</th>
                  <th>Verdict</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Date</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', color: '#64748b' }}>#{scan.id}</td>
                    <td style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>
                      {scan.target}
                    </td>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>
                        {scan.scan_type}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: scan.risk_score >= 70 ? '#ef4444' : scan.risk_score >= 40 ? '#f59e0b' : '#10b981',
                      }}>
                        {scan.risk_score?.toFixed(0)}/100
                      </span>
                    </td>
                    <td><ThreatBadge verdict={scan.verdict} size="sm" /></td>
                    <td><SeverityBadge severity={scan.severity} size="sm" /></td>
                    <td><StatusBadge status={scan.investigation_status} /></td>
                    <td style={{ fontSize: 11, color: '#64748b', whiteSpace: 'nowrap' }}>
                      {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td>
                      <button
                        className="btn-ghost"
                        onClick={() => navigate(`/investigation/${scan.id}`)}
                        style={{ padding: '4px 10px', fontSize: 11 }}
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
