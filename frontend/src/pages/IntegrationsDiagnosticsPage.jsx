import React, { useState, useEffect } from 'react';
import { systemApi } from '../services/api.js';
import GlassCard from '../components/ui/GlassCard.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import {
  RefreshCw,
  Zap,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Radio,
  Server,
  KeyRound,
  ShieldAlert,
  Play,
} from 'lucide-react';

const STATUS_THEME = {
  'CONNECTED': {
    color: '#10b981',
    bg: 'rgba(16, 185, 129, 0.12)',
    border: 'rgba(16, 185, 129, 0.35)',
    dot: 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]',
    text: 'text-emerald-400',
  },
  'AVAILABLE': {
    color: '#38bdf8',
    bg: 'rgba(56, 189, 248, 0.12)',
    border: 'rgba(56, 189, 248, 0.35)',
    dot: 'bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.8)]',
    text: 'text-sky-400',
  },
  'MANUAL': {
    color: '#818cf8',
    bg: 'rgba(129, 140, 248, 0.12)',
    border: 'rgba(129, 140, 248, 0.35)',
    dot: 'bg-indigo-400 shadow-[0_0_8px_rgba(129,140,248,0.8)]',
    text: 'text-indigo-400',
  },
  'NOT VERIFIED': {
    color: '#eab308',
    bg: 'rgba(234, 179, 8, 0.12)',
    border: 'rgba(234, 179, 8, 0.35)',
    dot: 'bg-yellow-400 shadow-[0_0_8px_rgba(234,179,8,0.8)]',
    text: 'text-yellow-400',
  },
  'NOT CONFIGURED': {
    color: '#f59e0b',
    bg: 'rgba(245, 158, 11, 0.12)',
    border: 'rgba(245, 158, 11, 0.35)',
    dot: 'bg-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.8)]',
    text: 'text-amber-400',
  },
  'INVALID CREDENTIALS': {
    color: '#f43f5e',
    bg: 'rgba(244, 63, 94, 0.12)',
    border: 'rgba(244, 63, 94, 0.35)',
    dot: 'bg-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.8)]',
    text: 'text-rose-400',
  },
  'RATE LIMITED': {
    color: '#a855f7',
    bg: 'rgba(168, 85, 247, 0.12)',
    border: 'rgba(168, 85, 247, 0.35)',
    dot: 'bg-purple-400 shadow-[0_0_8px_rgba(168,85,247,0.8)]',
    text: 'text-purple-400',
  },
  'QUOTA EXCEEDED': {
    color: '#c084fc',
    bg: 'rgba(192, 132, 252, 0.12)',
    border: 'rgba(192, 132, 252, 0.35)',
    dot: 'bg-purple-300 shadow-[0_0_8px_rgba(192,132,252,0.8)]',
    text: 'text-purple-300',
  },
  'TLS ERROR': {
    color: '#ec4899',
    bg: 'rgba(236, 72, 153, 0.12)',
    border: 'rgba(236, 72, 153, 0.35)',
    dot: 'bg-pink-400 shadow-[0_0_8px_rgba(236,72,153,0.8)]',
    text: 'text-pink-400',
  },
  'TIMEOUT': {
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.12)',
    border: 'rgba(249, 115, 22, 0.35)',
    dot: 'bg-orange-400 shadow-[0_0_8px_rgba(249,115,22,0.8)]',
    text: 'text-orange-400',
  },
  'PROVIDER ERROR': {
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.12)',
    border: 'rgba(239, 68, 68, 0.35)',
    dot: 'bg-red-400 shadow-[0_0_8px_rgba(239,68,68,0.8)]',
    text: 'text-red-400',
  },
  'UNAVAILABLE': {
    color: '#94a3b8',
    bg: 'rgba(148, 163, 184, 0.10)',
    border: 'rgba(148, 163, 184, 0.25)',
    dot: 'bg-slate-400',
    text: 'text-slate-400',
  },
};

export default function IntegrationsDiagnosticsPage() {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [testingAll, setTestingAll] = useState(false);
  const [testingIndividual, setTestingIndividual] = useState({});
  const [error, setError] = useState(null);
  const [lastTestedAt, setLastTestedAt] = useState(null);

  // Initial load: fetches current state without spamming probes
  const fetchDiagnostics = async (runProbe = false) => {
    if (runProbe) {
      setTestingAll(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      let res;
      if (runProbe) {
        res = await systemApi.testAllIntegrations();
      } else {
        res = await systemApi.getIntegrations(false);
      }
      setIntegrations(res.data.integrations || []);
      setLastTestedAt(new Date().toLocaleTimeString());
    } catch (err) {
      setError(err.message || 'Failed to communicate with diagnostics backend API.');
    } finally {
      setLoading(false);
      setTestingAll(false);
    }
  };

  // Test an individual provider on demand
  const handleTestProvider = async (providerId) => {
    if (!providerId) return;
    setTestingIndividual((prev) => ({ ...prev, [providerId]: true }));
    setError(null);

    try {
      const res = await systemApi.testProvider(providerId);
      const updated = res.data.provider;
      if (updated) {
        setIntegrations((prev) =>
          prev.map((item) => (item.id === updated.id ? updated : item))
        );
      }
    } catch (err) {
      setError(`Probe failed for provider ${providerId}: ${err.message}`);
    } finally {
      setTestingIndividual((prev) => ({ ...prev, [providerId]: false }));
    }
  };

  useEffect(() => {
    // Initial fetch of current integration status
    fetchDiagnostics(false);
  }, []);

  // Separate critical vs secondary integrations
  const criticalList = integrations.filter((i) => i.critical);
  const secondaryList = integrations.filter((i) => !i.critical);

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-12 font-sans">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[11px] font-mono font-bold tracking-widest text-cyber-blue uppercase bg-cyber-blue/10 border border-cyber-blue/20 px-2.5 py-0.5 rounded">
              PHISHGUARD AI
            </span>
            {lastTestedAt && (
              <span className="text-[11px] font-mono text-slate-400">
                Last Tested: <span className="text-slate-200">{lastTestedAt}</span>
              </span>
            )}
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3 font-mono">
            SYSTEM DIAGNOSTICS
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Real-time operational verification of security integrations and SOC telemetry tools. No simulated data.
          </p>
        </div>

        <div>
          <button
            onClick={() => fetchDiagnostics(true)}
            disabled={testingAll || loading}
            className="flex items-center gap-2.5 px-5 py-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/20 hover:border-emerald-500/60 transition-all text-sm font-mono font-bold shadow-[0_0_15px_rgba(16,185,129,0.15)] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            <RefreshCw size={16} className={testingAll ? 'animate-spin text-emerald-400' : ''} />
            {testingAll ? 'Testing All Integrations...' : '[ Test All Integrations ]'}
          </button>
        </div>
      </div>

      {loading && <LoadingSkeleton count={4} />}
      {error && <ErrorState message={error} onRetry={() => fetchDiagnostics(false)} />}

      {!loading && (
        <div className="space-y-10">
          {/* CRITICAL INTEGRATIONS */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap size={18} className="text-cyber-blue" />
                <h2 className="text-sm font-mono font-bold tracking-wider text-slate-200 uppercase">
                  CRITICAL INTEGRATIONS
                </h2>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Primary Threat Intel & SIEM pipeline
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {criticalList.map((tool) => {
                const theme = STATUS_THEME[tool.status] || STATUS_THEME['UNAVAILABLE'];
                const isSplunk = tool.id === 'splunk';
                const isTesting = testingIndividual[tool.id] || testingAll;

                return (
                  <GlassCard
                    key={tool.id}
                    className="p-6 relative overflow-hidden flex flex-col justify-between border-white/10 hover:border-cyber-blue/30 transition-all duration-300"
                  >
                    <div>
                      {/* Card Header: Title & Action Button */}
                      <div className="flex items-start justify-between gap-3 mb-3">
                        <div>
                          <h3 className="text-xl font-bold text-white font-mono">{tool.name}</h3>
                          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                            {tool.category}
                          </span>
                        </div>
                        <button
                          onClick={() => handleTestProvider(tool.id)}
                          disabled={isTesting}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white/5 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 hover:border-cyber-blue/60 transition-all text-xs font-mono font-semibold cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                          title={`Execute real-time probe for ${tool.name}`}
                        >
                          <Play size={12} className={isTesting ? 'animate-spin' : ''} />
                          {isTesting ? 'Testing...' : '[ Test ]'}
                        </button>
                      </div>

                      {/* Status Badge */}
                      <div
                        className="inline-flex items-center gap-2 px-3 py-1 rounded-md text-xs font-mono font-bold mb-4"
                        style={{ background: theme.bg, color: theme.color, border: `1px solid ${theme.border}` }}
                      >
                        <span className={`w-2 h-2 rounded-full ${theme.dot}`} />
                        <span>● {tool.status}</span>
                      </div>

                      {/* Operational Telemetry Grid */}
                      <div className="space-y-2 font-mono text-xs text-slate-300 bg-black/25 p-3.5 rounded-lg border border-white/5">
                        <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                          <span className="text-slate-400">Configured:</span>
                          <span className={tool.configured ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                            {tool.configured ? 'YES' : 'NO'}
                          </span>
                        </div>

                        <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                          <span className="text-slate-400">Probe Tested:</span>
                          <span className={tool.tested ? 'text-emerald-400 font-bold' : 'text-yellow-400'}>
                            {tool.tested ? 'YES' : 'NO'}
                          </span>
                        </div>

                        {isSplunk ? (
                          <>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">TCP:</span>
                              <span className={tool.tcp === 'PASS' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                                {tool.tcp || 'NOT TESTED'}
                              </span>
                            </div>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">HEC Health:</span>
                              <span className={tool.hec_health === 'PASS' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                                {tool.hec_health || 'NOT TESTED'}
                              </span>
                            </div>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">Authentication:</span>
                              <span className={tool.authentication === 'PASS' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                                {tool.authentication || 'NOT TESTED'}
                              </span>
                            </div>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">Test Event:</span>
                              <span className={tool.test_event === 'ACCEPTED' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                                {tool.test_event || 'NOT TESTED'}
                              </span>
                            </div>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">ACK Status:</span>
                              <span className="text-slate-300 text-[11px] truncate max-w-[150px]">
                                {tool.ack_status || 'NOT TESTED'}
                              </span>
                            </div>
                          </>
                        ) : (
                          <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                            <span className="text-slate-400">Real Probe:</span>
                            <span className={tool.real_probe === 'PASS' ? 'text-emerald-400 font-bold' : 'text-yellow-400 font-bold'}>
                              {tool.real_probe || 'NOT TESTED'}
                            </span>
                          </div>
                        )}

                        <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                          <span className="text-slate-400">Latency:</span>
                          <span className="text-cyber-blue font-bold">
                            {tool.latency_ms !== null && tool.latency_ms !== undefined ? `${tool.latency_ms} ms` : '-'}
                          </span>
                        </div>

                        <div className="flex justify-between items-center py-0.5">
                          <span className="text-slate-400">Last Checked:</span>
                          <span className="text-slate-400 text-[11px]">
                            {tool.last_checked ? new Date(tool.last_checked).toLocaleTimeString() : 'Never'}
                          </span>
                        </div>
                      </div>

                      {/* Safe Error Box */}
                      {tool.error_message && (
                        <div className="mt-3 p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
                          <span className="font-bold">Error:</span> {tool.error_message}
                        </div>
                      )}
                    </div>

                    {/* Operational Details */}
                    <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-slate-400 font-sans leading-relaxed">
                      {tool.details}
                    </div>
                  </GlassCard>
                );
              })}
            </div>
          </section>

          {/* SECONDARY INTEGRATIONS */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck size={18} className="text-slate-400" />
                <h2 className="text-sm font-mono font-bold tracking-wider text-slate-300 uppercase">
                  SECONDARY INTEGRATIONS
                </h2>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Network, DNS, File & Forensics
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {secondaryList.map((tool) => {
                const theme = STATUS_THEME[tool.status] || STATUS_THEME['UNAVAILABLE'];
                const isTesting = testingIndividual[tool.id] || testingAll;

                return (
                  <GlassCard
                    key={tool.id}
                    className="p-5 flex flex-col justify-between border-white/5 hover:border-white/20 transition-all"
                  >
                    <div>
                      {/* Header with Title and Test Button */}
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div>
                          <h3 className="text-base font-bold text-white font-mono">{tool.name}</h3>
                          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                            {tool.category}
                          </span>
                        </div>
                        <button
                          onClick={() => handleTestProvider(tool.id)}
                          disabled={isTesting}
                          className="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 text-xs font-mono transition cursor-pointer disabled:opacity-50"
                          title={`Test ${tool.name}`}
                        >
                          <Play size={10} className={isTesting ? 'animate-spin' : ''} />
                          {isTesting ? '...' : '[ Test ]'}
                        </button>
                      </div>

                      {/* Status Badge */}
                      <div
                        className="inline-flex items-center gap-2 px-2.5 py-1 rounded text-xs font-mono font-bold mb-3"
                        style={{ background: theme.bg, color: theme.color, border: `1px solid ${theme.border}` }}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${theme.dot}`} />
                        <span>● {tool.status}</span>
                      </div>

                      {/* Key Indicators */}
                      <div className="space-y-1.5 font-mono text-[11px] text-slate-400 bg-black/20 p-2.5 rounded border border-white/5">
                        <div className="flex justify-between items-center">
                          <span>Configured:</span>
                          <span className={tool.configured ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                            {tool.configured ? 'YES' : 'NO'}
                          </span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span>Probe Tested:</span>
                          <span className={tool.tested ? 'text-emerald-400' : 'text-slate-500'}>
                            {tool.tested ? 'YES' : 'NO'}
                          </span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span>Latency:</span>
                          <span className="text-slate-300 font-bold">
                            {tool.latency_ms !== null && tool.latency_ms !== undefined ? `${tool.latency_ms} ms` : '-'}
                          </span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span>Last Checked:</span>
                          <span className="text-slate-400 text-[10px]">
                            {tool.last_checked ? new Date(tool.last_checked).toLocaleTimeString() : 'Never'}
                          </span>
                        </div>
                      </div>

                      {/* Safe Error Box */}
                      {tool.error_message && (
                        <div className="mt-2.5 p-2 rounded bg-rose-500/10 border border-rose-500/25 text-rose-400 text-[11px] font-mono">
                          <span className="font-bold">Error:</span> {tool.error_message}
                        </div>
                      )}
                    </div>

                    <div className="mt-3.5 pt-2.5 border-t border-white/5 text-[11px] font-sans text-slate-400">
                      {tool.details}
                    </div>
                  </GlassCard>
                );
              })}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
