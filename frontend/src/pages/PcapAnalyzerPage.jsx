import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { scansApi, investigationsApi, splunkApi } from '../services/api.js';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import RiskMeter from '../components/ui/RiskMeter.jsx';
import { Network, Upload, ArrowRight, Send, AlertTriangle, Activity, Globe, Shield } from 'lucide-react';

export default function PcapAnalyzerPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [splunkStatus, setSplunkStatus] = useState(null);
  const [caseCreating, setCaseCreating] = useState(false);

  // Restore PCAP scan on browser refresh
  useEffect(() => {
    const scanId = searchParams.get('id');
    if (scanId) {
      setLoading(true);
      scansApi.get(scanId)
        .then((res) => {
          setResult(res.data);
        })
        .catch((err) => {
          setError(`Could not restore PCAP scan #${scanId}: ${err.message}`);
        })
        .finally(() => setLoading(false));
    }
  }, [searchParams]);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
      setResult(null);
    }
  };

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    setError(null);
    try {
      const res = await scansApi.scanPcap(file);
      setResult(res.data);
      if (res.data?.id) {
        setSearchParams({ id: String(res.data.id) }, { replace: true });
      }
    } catch (err) {
      setError(err.message || 'PCAP analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCase = async () => {
    if (!result?.id) return;
    setCaseCreating(true);
    try {
      const res = await investigationsApi.createFromScan(result.id, `Network Investigation: ${result.pcap_file || 'Capture sample'}`);
      navigate(`/investigations/${res.data.case_id || res.data.id}`);
    } catch (err) {
      setError(`Failed to create case: ${err.message}`);
    } finally {
      setCaseCreating(false);
    }
  };

  const handleForwardSplunk = async () => {
    if (!result) return;
    try {
      const res = await splunkApi.sendEvent(result, 'pcap_analysis', 'phishguard:pcap');
      setSplunkStatus(res.data.message || 'Packet telemetry sent to Splunk.');
    } catch (err) {
      setSplunkStatus(`Splunk dispatch error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Offline PCAP Network Analyzer"
        subtitle="Defensive offline packet capture analysis using Scapy & tshark. Extracts IP conversations, DNS queries, HTTP hostnames, and suspicious ports."
      />

      <GlassCard className="p-6">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="border-2 border-dashed border-white/10 hover:border-cyber-blue/40 rounded-xl p-8 text-center transition cursor-pointer relative bg-slate-900/30">
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileChange}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <div className="flex flex-col items-center justify-center gap-2">
              <Network size={32} className="text-cyber-blue mb-1" />
              <p className="text-sm font-medium text-white">
                {file ? file.name : 'Select or drop .pcap / .pcapng network capture file'}
              </p>
              <p className="text-xs text-slate-400">
                Offline analysis only (Max 25MB) • Does not generate or sniff active traffic
              </p>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={!file || loading}
              className="btn-primary flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-50"
            >
              <Activity size={16} />
              {loading ? 'Parsing Network Packets...' : 'Analyze PCAP Offline'}
            </button>
          </div>
        </form>
      </GlassCard>

      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <GlassCard className="p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <ThreatBadge verdict={result.verdict} />
              <SeverityBadge severity={result.severity} />
              <span className="text-xs font-mono text-slate-400">Total Packets: {result.total_packets || 0}</span>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={handleForwardSplunk}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 hover:bg-white/10 text-slate-200 border border-white/10 flex items-center gap-1.5 transition"
              >
                <Send size={12} />
                Send to Splunk
              </button>
              <button
                onClick={handleCreateCase}
                disabled={caseCreating}
                className="btn-primary px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5"
              >
                Create Investigation Case
                <ArrowRight size={12} />
              </button>
            </div>
          </GlassCard>

          {splunkStatus && (
            <div className="p-3 rounded-lg bg-cyber-blue/10 border border-cyber-blue/20 text-cyber-blue text-xs font-mono">
              Splunk HEC: {splunkStatus}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <GlassCard className="p-5">
              <span className="text-xs text-slate-400 font-mono block mb-1">NETWORK PROTOCOLS</span>
              <div className="space-y-1 mt-2 text-xs">
                {Object.entries(result.total_protocols || {}).map(([proto, count]) => (
                  <div key={proto} className="flex justify-between py-1 border-b border-white/5">
                    <span className="font-mono text-cyber-blue">{proto}</span>
                    <span className="text-slate-300">{count} pkts</span>
                  </div>
                ))}
              </div>
            </GlassCard>

            <GlassCard className="p-5">
              <span className="text-xs text-slate-400 font-mono block mb-1">CONVERSATION ENDPOINTS</span>
              <div className="mt-3 space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Unique Source IPs:</span>
                  <span className="font-semibold text-white">{result.unique_source_ips || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Unique Destination IPs:</span>
                  <span className="font-semibold text-white">{result.unique_destination_ips || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Analysis Duration:</span>
                  <span className="font-mono text-cyber-blue">{result.processing_time_ms}ms</span>
                </div>
              </div>
            </GlassCard>

            <GlassCard className="p-5">
              <RiskMeter score={result.risk_score} />
            </GlassCard>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <GlassCard className="p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Globe size={16} className="text-cyber-blue" />
                DNS Lookups Extracted ({result.dns_queries?.length || 0})
              </h3>
              <div className="max-h-48 overflow-y-auto space-y-1 text-xs font-mono text-slate-300">
                {result.dns_queries?.length > 0 ? (
                  result.dns_queries.map((q, idx) => (
                    <div key={idx} className="p-1.5 rounded bg-black/20 hover:bg-white/5 select-all">
                      {q}
                    </div>
                  ))
                ) : (
                  <p className="text-slate-500 italic">No DNS queries recorded in capture.</p>
                )}
              </div>
            </GlassCard>

            <GlassCard className="p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Activity size={16} className="text-cyber-blue" />
                HTTP Host Headers Identified ({result.http_hosts?.length || 0})
              </h3>
              <div className="max-h-48 overflow-y-auto space-y-1 text-xs font-mono text-slate-300">
                {result.http_hosts?.length > 0 ? (
                  result.http_hosts.map((h, idx) => (
                    <div key={idx} className="p-1.5 rounded bg-black/20 hover:bg-white/5 select-all">
                      {h}
                    </div>
                  ))
                ) : (
                  <p className="text-slate-500 italic">No cleartext HTTP host headers observed.</p>
                )}
              </div>
            </GlassCard>
          </div>
        </div>
      )}
    </div>
  );
}
