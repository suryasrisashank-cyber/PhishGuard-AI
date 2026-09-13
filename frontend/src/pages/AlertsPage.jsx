import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { alertsApi, investigationsApi } from '../services/api.js';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { ShieldAlert, AlertTriangle, ArrowRight, Filter, RefreshCw } from 'lucide-react';

export default function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [counts, setCounts] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('');

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await alertsApi.list({ severity: severityFilter || undefined });
      setAlerts(res.data.alerts || []);
      setCounts(res.data.counts || { critical: 0, high: 0, medium: 0, low: 0 });
    } catch (err) {
      setError(err.message || 'Failed to fetch SOC alert queue.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [severityFilter]);

  const handleInvestigate = async (alert) => {
    try {
      const res = await investigationsApi.createFromScan(alert.scan_id, `Escalated Alert: ${alert.target}`);
      navigate(`/investigations/${res.data.case_id || res.data.id}`);
    } catch (err) {
      alert(`Could not create investigation case: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOC Alert Triage Queue"
        subtitle="Active high-priority security events requiring analyst review, evidence correlation, and formal containment."
        action={
          <button
            onClick={fetchAlerts}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/20 transition text-sm font-medium"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh Queue
          </button>
        }
      />

      {/* Triage Stats Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div
          onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? '' : 'CRITICAL')}
          className={`p-4 rounded-xl border cursor-pointer transition ${
            severityFilter === 'CRITICAL' ? 'bg-red-500/20 border-red-500' : 'bg-red-500/5 border-red-500/20 hover:bg-red-500/10'
          }`}
        >
          <span className="text-[11px] font-mono text-red-400 uppercase tracking-wider">CRITICAL ALERTS</span>
          <p className="text-2xl font-bold text-red-400 mt-1">{counts.critical}</p>
        </div>

        <div
          onClick={() => setSeverityFilter(severityFilter === 'HIGH' ? '' : 'HIGH')}
          className={`p-4 rounded-xl border cursor-pointer transition ${
            severityFilter === 'HIGH' ? 'bg-amber-500/20 border-amber-500' : 'bg-amber-500/5 border-amber-500/20 hover:bg-amber-500/10'
          }`}
        >
          <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider">HIGH ALERTS</span>
          <p className="text-2xl font-bold text-amber-400 mt-1">{counts.high}</p>
        </div>

        <div
          onClick={() => setSeverityFilter(severityFilter === 'MEDIUM' ? '' : 'MEDIUM')}
          className={`p-4 rounded-xl border cursor-pointer transition ${
            severityFilter === 'MEDIUM' ? 'bg-yellow-500/20 border-yellow-500' : 'bg-yellow-500/5 border-yellow-500/20 hover:bg-yellow-500/10'
          }`}
        >
          <span className="text-[11px] font-mono text-yellow-400 uppercase tracking-wider">MEDIUM ALERTS</span>
          <p className="text-2xl font-bold text-yellow-400 mt-1">{counts.medium}</p>
        </div>

        <div
          onClick={() => setSeverityFilter(severityFilter === 'LOW' ? '' : 'LOW')}
          className={`p-4 rounded-xl border cursor-pointer transition ${
            severityFilter === 'LOW' ? 'bg-blue-500/20 border-blue-500' : 'bg-blue-500/5 border-blue-500/20 hover:bg-blue-500/10'
          }`}
        >
          <span className="text-[11px] font-mono text-blue-400 uppercase tracking-wider">LOW / INFORMATIONAL</span>
          <p className="text-2xl font-bold text-blue-400 mt-1">{counts.low}</p>
        </div>
      </div>

      {loading && <LoadingSkeleton count={4} />}
      {error && <ErrorState message={error} onRetry={fetchAlerts} />}

      {!loading && !error && (
        <div className="space-y-3">
          {alerts.length > 0 ? (
            alerts.map((al) => (
              <GlassCard key={al.alert_id} className="p-4 flex flex-wrap items-center justify-between gap-4">
                <div className="space-y-1 max-w-xl">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-cyber-blue font-semibold">{al.alert_id}</span>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-white/10 text-slate-300">
                      {al.source_type}
                    </span>
                    <SeverityBadge severity={al.severity} />
                  </div>
                  <h4 className="text-sm font-semibold text-white truncate">{al.target}</h4>
                  <p className="text-xs text-slate-400">{al.summary}</p>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right text-xs font-mono">
                    <span className="text-slate-400 block text-[10px]">RISK SCORE</span>
                    <span className="font-bold text-cyber-blue">{al.risk_score} / 100</span>
                  </div>
                  <button
                    onClick={() => handleInvestigate(al)}
                    className="btn-primary px-3.5 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5"
                  >
                    Investigate
                    <ArrowRight size={13} />
                  </button>
                </div>
              </GlassCard>
            ))
          ) : (
            <GlassCard className="p-10 text-center text-slate-500 italic">
              No unresolved alerts currently in the queue.
            </GlassCard>
          )}
        </div>
      )}
    </div>
  );
}
