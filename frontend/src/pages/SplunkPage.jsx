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
      const [statusRes, splRes] = await Promise.allSettled([
        splunkApi.getStatus(),
        splunkApi.getSplExamples(),
      ]);
      if (statusRes.status === 'fulfilled') {
        setStatus(statusRes.value.data);
      } else {
        setStatus({
          status: 'UNAVAILABLE',
          configured: false,
          endpoint: 'Backend Unreachable',
          message: 'Unable to retrieve Splunk status from backend.',
        });
      }
      if (splRes.status === 'fulfilled') {
        setSplData(splRes.value.data);
      } else {
        setSplData({
          searches: [
            {
              title: 'Phishing Threat Verdicts',
              spl: 'index=phishguard sourcetype="phishguard:scan" verdict=Malicious | table _time target risk_score sender_ip',
              description: 'Retrieve confirmed phishing detections from recent scans.',
            },
            {
              title: 'High Risk IOC Correlation',
              spl: 'index=phishguard sourcetype="phishguard:scan" risk_score>=75 | stats count by target, verdict',
              description: 'Count targets exceeding high severity risk threshold.',
            },
          ],
        });
      }
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
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Status:</span>
                <span className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                  status?.status === 'CONNECTED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                  status?.status === 'LOCAL ONLY' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' :
                  status?.status === 'NOT CONFIGURED' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  'bg-red-500/20 text-red-400 border border-red-500/30'
                }`}>
                  {status?.status || 'UNKNOWN'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Endpoint:</span>
                <span className="text-slate-200">{status?.endpoint || 'Not configured'}</span>
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
                <span className="text-slate-400">Environment:</span>
                <span className="text-slate-300">{status?.environment === 'cloud' ? 'Cloud Deployment' : 'Local Lab'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">TLS Verification:</span>
                <span className="text-slate-300">{status?.verify_tls ? 'Strict' : 'Disabled'}</span>
              </div>
            </div>

            {status?.message && (
              <p className="text-[11px] text-slate-400 leading-relaxed">
                {status.message}
              </p>
            )}

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
                testResult.status === 'LOCAL ONLY' ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400' :
                testResult.status === 'NOT CONFIGURED' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                'bg-red-500/10 border-red-500/30 text-red-400'
              }`}>
                <p className="font-bold">RESULT: {testResult.status}</p>
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
