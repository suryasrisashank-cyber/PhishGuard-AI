import React, { useState, useEffect } from 'react';
import { splunkApi } from '../services/api.js';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import { Send, CheckCircle2, AlertTriangle, Copy, Check, Terminal, ExternalLink, RefreshCw } from 'lucide-react';

export default function SplunkPage() {
  const [status, setStatus] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);
  const [splData, setSplData] = useState(null);
  const [copiedSpl, setCopiedSpl] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchSplunkInfo = async () => {
    setLoading(true);
    try {
      const [statusRes, splRes] = await Promise.all([
        splunkApi.getStatus(),
        splunkApi.getSplExamples(),
      ]);
      setStatus(statusRes.data);
      setSplData(splRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSplunkInfo();
  }, []);

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await splunkApi.testConnection();
      setTestResult(res.data);
    } catch (err) {
      setTestResult({ status: 'ERROR', message: err.message });
    } finally {
      setTesting(false);
    }
  };

  const handleCopy = (spl, idx) => {
    navigator.clipboard.writeText(spl);
    setCopiedSpl(idx);
    setTimeout(() => setCopiedSpl(null), 2000);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Splunk Enterprise / Cloud SIEM Integration"
        subtitle="Centralized telemetry forwarding using Splunk HTTP Event Collector (HEC). Normalized security events, alert forwarding, and verified SPL queries."
      />

      {loading ? (
        <LoadingSkeleton count={3} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Status & Test Card */}
          <GlassCard className="p-6 lg:col-span-1 space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Terminal size={16} className="text-cyber-blue" />
              HEC Connection Status
            </h3>

            <div className="p-3 rounded-lg bg-black/30 border border-white/5 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Configuration:</span>
                <span className={status?.configured ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                  {status?.status || 'UNKNOWN'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target Index:</span>
                <span className="text-cyber-blue">{status?.index || 'phishguard'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Default Sourcetype:</span>
                <span className="text-slate-300">{status?.default_sourcetype || 'phishguard:scan'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">TLS Verification:</span>
                <span className="text-slate-300">{status?.verify_tls ? 'Strict' : 'Disabled'}</span>
              </div>
            </div>

            <button
              onClick={handleTestConnection}
              disabled={testing}
              className="w-full btn-primary py-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-2"
            >
              <RefreshCw size={14} className={testing ? 'animate-spin' : ''} />
              {testing ? 'Testing Connection...' : 'Test Splunk HEC Connection'}
            </button>

            {testResult && (
              <div className={`p-3 rounded-lg text-xs font-mono border ${
                testResult.status === 'CONNECTED' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
                testResult.status === 'NOT CONFIGURED' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                'bg-red-500/10 border-red-500/30 text-red-400'
              }`}>
                <p className="font-bold">STATUS: {testResult.status}</p>
                <p className="mt-1 text-[11px] opacity-90">{testResult.message}</p>
              </div>
            )}
          </GlassCard>

          {/* SPL Queries Library */}
          <GlassCard className="p-6 lg:col-span-2 space-y-4">
            <h3 className="text-sm font-semibold text-white">Verified Splunk SPL Search Queries</h3>
            <p className="text-xs text-slate-400">
              Directly query normalized PhishGuard security events indexed inside Splunk Enterprise / Cloud.
            </p>

            <div className="space-y-3">
              {splData?.searches?.map((s, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-black/30 border border-white/5 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-white">{s.title}</span>
                    <button
                      onClick={() => handleCopy(s.spl, idx)}
                      className="flex items-center gap-1 text-[11px] font-mono text-cyber-blue hover:text-white transition px-2 py-0.5 rounded bg-white/5"
                    >
                      {copiedSpl === idx ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      {copiedSpl === idx ? 'Copied' : 'Copy SPL'}
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-400">{s.description}</p>
                  <pre className="p-2 rounded bg-slate-950 font-mono text-xs text-emerald-400 overflow-x-auto select-all">
                    {s.spl}
                  </pre>
                </div>
              ))}
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
}
