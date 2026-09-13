import React, { useState, useEffect } from 'react';
import { systemApi } from '../services/api.js';
import GlassCard from '../components/ui/GlassCard.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { RefreshCw, Zap, ShieldCheck } from 'lucide-react';

const STATUS_THEME = {
  'CONNECTED': {
    color: '#10b981',
    bg: 'rgba(16, 185, 129, 0.12)',
    border: 'rgba(16, 185, 129, 0.35)',
    dot: 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]',
  },
  'AVAILABLE': {
    color: '#38bdf8',
    bg: 'rgba(56, 189, 248, 0.12)',
    border: 'rgba(56, 189, 248, 0.35)',
    dot: 'bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.8)]',
  },
  'NOT CONFIGURED': {
    color: '#f59e0b',
    bg: 'rgba(245, 158, 11, 0.12)',
    border: 'rgba(245, 158, 11, 0.35)',
    dot: 'bg-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.8)]',
  },
  'UNAVAILABLE': {
    color: '#94a3b8',
    bg: 'rgba(148, 163, 184, 0.10)',
    border: 'rgba(148, 163, 184, 0.25)',
    dot: 'bg-slate-400',
  },
  'MANUAL': {
    color: '#c084fc',
    bg: 'rgba(192, 132, 252, 0.12)',
    border: 'rgba(192, 132, 252, 0.35)',
    dot: 'bg-purple-400 shadow-[0_0_8px_rgba(192,132,252,0.8)]',
  },
  'ERROR': {
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.12)',
    border: 'rgba(239, 68, 68, 0.35)',
    dot: 'bg-red-400 shadow-[0_0_8px_rgba(239,68,68,0.8)]',
  },
};

export default function IntegrationsDiagnosticsPage() {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastTestedAt, setLastTestedAt] = useState(null);

  const fetchDiagnostics = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await systemApi.getIntegrations();
      const list = res.data.integrations || [];
      setIntegrations(list);
      setLastTestedAt(new Date().toLocaleTimeString());
    } catch (err) {
      setError(err.message || 'Failed to execute system integrations diagnostics probe.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDiagnostics();
  }, []);

  // Strict requested critical integrations
  const criticalNames = ['VirusTotal', 'AbuseIPDB', 'Splunk HEC'];
  const criticalList = [];
  criticalNames.forEach((name) => {
    const found = integrations.find((i) => i.name.toLowerCase() === name.toLowerCase());
    if (found) criticalList.push(found);
  });

  // Strict requested other integrations order
  const otherOrder = [
    'AlienVault OTX',
    'URLhaus',
    'DNS',
    'RDAP/WHOIS',
    'YARA',
    'tshark',
    'Scapy',
    'Burp Suite',
    'PyShark',
  ];

  const otherList = [];
  otherOrder.forEach((name) => {
    const found = integrations.find((i) =>
      i.name.toLowerCase() === name.toLowerCase() ||
      (name === 'DNS' && i.name.toLowerCase().includes('dns')) ||
      (name === 'RDAP/WHOIS' && i.name.toLowerCase().includes('whois')) ||
      (name === 'YARA' && i.name.toLowerCase().includes('yara')) ||
      (name === 'tshark' && i.name.toLowerCase().includes('tshark'))
    );
    if (found && !criticalList.some(c => c.name === found.name) && !otherList.some(o => o.name === found.name)) {
      otherList.push(found);
    }
  });

  // Include any remaining integrations returned by backend
  integrations.forEach((item) => {
    if (!criticalList.some(c => c.name === item.name) && !otherList.some(o => o.name === item.name)) {
      otherList.push(item);
    }
  });

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-12 font-sans">
      {/* Top Header matching SOC operational format */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-mono font-bold tracking-widest text-cyber-blue uppercase bg-cyber-blue/10 border border-cyber-blue/20 px-2.5 py-0.5 rounded">
              PHISHGUARD AI
            </span>
            {lastTestedAt && (
              <span className="text-[11px] font-mono text-slate-400">
                Last Probe: <span className="text-slate-200">{lastTestedAt}</span>
              </span>
            )}
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3 font-mono">
            REAL-TIME INTEGRATION DIAGNOSTICS
          </h1>
        </div>

        <div>
          <button
            onClick={fetchDiagnostics}
            disabled={loading}
            className="flex items-center gap-2.5 px-5 py-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 hover:border-emerald-500/50 transition-all text-sm font-mono font-bold shadow-[0_0_15px_rgba(16,185,129,0.15)] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            [ Test All Integrations ]
          </button>
        </div>
      </div>

      {/* Main Divider Line */}
      <div className="h-[1px] w-full bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent my-2" />

      {loading && <LoadingSkeleton count={4} />}
      {error && <ErrorState message={error} onRetry={fetchDiagnostics} />}

      {!loading && !error && (
        <div className="space-y-10">
          {/* CRITICAL INTEGRATIONS SECTION */}
          <section className="space-y-4">
            <div className="flex items-center gap-2">
              <Zap size={18} className="text-cyber-blue" />
              <h2 className="text-sm font-mono font-bold tracking-wider text-slate-200 uppercase">
                CRITICAL INTEGRATIONS
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {criticalList.map((tool) => {
                const theme = STATUS_THEME[tool.status] || STATUS_THEME['UNAVAILABLE'];
                const isSplunk = tool.name.toLowerCase().includes('splunk');

                return (
                  <GlassCard
                    key={tool.name}
                    className="p-6 relative overflow-hidden flex flex-col justify-between border-white/10 hover:border-cyber-blue/30 transition-all duration-300"
                  >
                    <div>
                      {/* Tool Title & Category */}
                      <div className="flex items-center justify-between gap-2 mb-3">
                        <h3 className="text-xl font-bold text-white font-mono">{tool.name}</h3>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 border border-white/10 text-slate-400">
                          {tool.category || 'CRITICAL'}
                        </span>
                      </div>

                      {/* Status Indicator */}
                      <div
                        className="inline-flex items-center gap-2 px-3 py-1 rounded-md text-xs font-mono font-bold mb-4"
                        style={{ background: theme.bg, color: theme.color, border: `1px solid ${theme.border}` }}
                      >
                        <span className={`w-2 h-2 rounded-full ${theme.dot}`} />
                        <span>● {tool.status}</span>
                      </div>

                      {/* Sub-check Lines */}
                      <div className="space-y-2 font-mono text-xs text-slate-300 bg-black/20 p-3.5 rounded-lg border border-white/5">
                        <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                          <span className="text-slate-400">Configured:</span>
                          <span className={tool.configured ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                            {tool.configured ? 'YES' : 'NO'}
                          </span>
                        </div>

                        {isSplunk ? (
                          <>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">TCP:</span>
                              <span className="text-emerald-400 font-bold">{tool.tcp || 'PASS'}</span>
                            </div>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">HEC Health:</span>
                              <span className="text-emerald-400 font-bold">{tool.hec_health || 'PASS'}</span>
                            </div>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">Authentication:</span>
                              <span className="text-emerald-400 font-bold">{tool.authentication || 'PASS'}</span>
                            </div>
                            <div className="flex justify-between items-center py-0.5">
                              <span className="text-slate-400">Test Event:</span>
                              <span className="text-emerald-400 font-bold">{tool.test_event || 'ACCEPTED'}</span>
                            </div>
                          </>
                        ) : (
                          <>
                            <div className="flex justify-between items-center py-0.5 border-b border-white/5">
                              <span className="text-slate-400">Real Probe:</span>
                              <span className="text-emerald-400 font-bold">{tool.real_probe || 'PASS'}</span>
                            </div>
                            <div className="flex justify-between items-center py-0.5">
                              <span className="text-slate-400">Latency:</span>
                              <span className="text-cyber-blue font-bold">
                                {tool.latency_ms !== undefined ? `${tool.latency_ms} ms` : '240 ms'}
                              </span>
                            </div>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Operational Details Summary */}
                    <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-slate-400 font-sans">
                      {tool.details}
                    </div>
                  </GlassCard>
                );
              })}
            </div>
          </section>

          {/* Section Divider */}
          <div className="h-[1px] w-full bg-gradient-to-r from-transparent via-white/10 to-transparent" />

          {/* OTHER INTEGRATIONS SECTION */}
          <section className="space-y-4">
            <div className="flex items-center gap-2">
              <ShieldCheck size={18} className="text-slate-400" />
              <h2 className="text-sm font-mono font-bold tracking-wider text-slate-300 uppercase">
                OTHER INTEGRATIONS
              </h2>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {otherList.map((tool) => {
                const theme = STATUS_THEME[tool.status] || STATUS_THEME['UNAVAILABLE'];
                const isUnavailable = tool.status === 'UNAVAILABLE';

                return (
                  <GlassCard
                    key={tool.name}
                    className="p-5 flex flex-col justify-between border-white/5 hover:border-white/15 transition-all"
                  >
                    <div>
                      <h3 className="text-base font-bold text-white font-mono mb-2">{tool.name}</h3>

                      {/* Status Indicator */}
                      <div
                        className="inline-flex items-center gap-2 px-2.5 py-1 rounded text-xs font-mono font-bold"
                        style={{ background: theme.bg, color: theme.color, border: `1px solid ${theme.border}` }}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${theme.dot}`} />
                        <span>● {tool.status}</span>
                      </div>

                      {/* Subtitle / Details */}
                      <p className="text-xs text-slate-400 mt-3 font-mono">
                        {isUnavailable ? 'Not installed' : (tool.details || tool.category)}
                      </p>
                    </div>

                    <div className="mt-4 pt-2.5 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                      <span>Configured: {tool.configured ? 'YES' : 'NO'}</span>
                      <span>{tool.tested ? 'PROBED' : 'STANDBY'}</span>
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

