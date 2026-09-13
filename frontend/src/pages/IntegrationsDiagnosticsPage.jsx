import React, { useState, useEffect } from 'react';
import { systemApi } from '../services/api.js';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { Shield, RefreshCw, CheckCircle2, AlertTriangle, XCircle, Info, Radio } from 'lucide-react';

const STATUS_CONFIG = {
  'CONNECTED': { color: '#10b981', bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.3)', icon: CheckCircle2 },
  'AVAILABLE': { color: '#38bdf8', bg: 'rgba(56,189,248,0.12)', border: 'rgba(56,189,248,0.3)', icon: Radio },
  'NOT CONFIGURED': { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)', icon: AlertTriangle },
  'UNAVAILABLE': { color: '#94a3b8', bg: 'rgba(148,163,184,0.12)', border: 'rgba(148,163,184,0.3)', icon: Info },
  'ERROR': { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)', icon: XCircle },
};

export default function IntegrationsDiagnosticsPage() {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDiagnostics = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await systemApi.getIntegrations();
      setIntegrations(res.data.integrations || []);
    } catch (err) {
      setError(err.message || 'Failed to load system integrations diagnostics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDiagnostics();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Integrations Diagnostics"
        subtitle="Live runtime operational status for all 11 SIEM, Threat Intel, and Forensic inspection tools."
        action={
          <button
            onClick={fetchDiagnostics}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/20 transition text-sm font-medium"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh Diagnostics
          </button>
        }
      />

      {loading && <LoadingSkeleton count={6} />}
      {error && <ErrorState message={error} onRetry={fetchDiagnostics} />}

      {!loading && !error && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {integrations.map((tool) => {
            const statusStyle = STATUS_CONFIG[tool.status] || STATUS_CONFIG['UNAVAILABLE'];
            const StatusIcon = statusStyle.icon;

            return (
              <GlassCard key={tool.name} className="p-5 flex flex-col justify-between">
                <div>
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div>
                      <span className="text-[11px] font-mono tracking-wider text-slate-400 uppercase">{tool.category}</span>
                      <h3 className="text-base font-semibold text-white mt-0.5">{tool.name}</h3>
                    </div>
                    <div
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium"
                      style={{ background: statusStyle.bg, color: statusStyle.color, border: `1px solid ${statusStyle.border}` }}
                    >
                      <StatusIcon size={12} />
                      {tool.status}
                    </div>
                  </div>
                  <p className="text-sm text-slate-300 mt-3 leading-relaxed">{tool.details}</p>
                </div>

                <div className="mt-5 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span>Configured: {tool.configured ? 'YES' : 'NO'}</span>
                  <span>Probe Tested: {tool.tested ? 'YES' : 'SKIPPED'}</span>
                </div>
              </GlassCard>
            );
          })}
        </div>
      )}
    </div>
  );
}
