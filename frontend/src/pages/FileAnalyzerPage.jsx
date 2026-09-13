import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scansApi, investigationsApi, splunkApi } from '../services/api.js';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import RiskMeter from '../components/ui/RiskMeter.jsx';
import ConfidenceMeter from '../components/ui/ConfidenceMeter.jsx';
import { Upload, FileCode, CheckCircle, AlertTriangle, Shield, ExternalLink, Send, ArrowRight } from 'lucide-react';

export default function FileAnalyzerPage() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [splunkStatus, setSplunkStatus] = useState(null);
  const [caseCreating, setCaseCreating] = useState(false);

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
      const res = await scansApi.scanFile(file);
      setResult(res.data);
    } catch (err) {
      setError(err.message || 'File analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCase = async () => {
    if (!result?.id) return;
    setCaseCreating(true);
    try {
      const res = await investigationsApi.createFromScan(result.id, `Investigation: ${result.file_name || 'File sample'}`);
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
      const res = await splunkApi.sendEvent(result, 'file_analysis', 'phishguard:file');
      setSplunkStatus(res.data.message || 'Event sent to Splunk.');
    } catch (err) {
      setSplunkStatus(`Splunk dispatch error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Safe Static File Analyzer"
        subtitle="Defensive binary and script inspection. Extracts cryptographic hashes, strings, embedded IOCs, and checks YARA signatures without execution."
      />

      <GlassCard className="p-6">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="border-2 border-dashed border-white/10 hover:border-cyber-blue/40 rounded-xl p-8 text-center transition cursor-pointer relative bg-slate-900/30">
            <input
              type="file"
              onChange={handleFileChange}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <div className="flex flex-col items-center justify-center gap-2">
              <Upload size={32} className="text-cyber-blue mb-1" />
              <p className="text-sm font-medium text-white">
                {file ? file.name : 'Drag & drop suspicious sample or click to browse'}
              </p>
              <p className="text-xs text-slate-400">
                Safe static analysis only (Max 15MB) • File is NEVER executed
              </p>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={!file || loading}
              className="btn-primary flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-50"
            >
              <FileCode size={16} />
              {loading ? 'Inspecting Binary...' : 'Analyze File Statically'}
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
          {/* Quick Actions Bar */}
          <GlassCard className="p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <ThreatBadge verdict={result.verdict} />
              <SeverityBadge severity={result.severity} />
              <span className="text-xs font-mono text-slate-400">Duration: {result.processing_time_ms}ms</span>
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

          {/* Scores Overview */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <GlassCard className="p-5">
              <RiskMeter score={result.risk_score} />
            </GlassCard>
            <GlassCard className="p-5">
              <ConfidenceMeter score={result.confidence_score} />
            </GlassCard>
          </div>

          {/* Cryptographic Hashes & Metadata */}
          <GlassCard className="p-5">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <FileCode size={16} className="text-cyber-blue" />
              Cryptographic Identifiers & Metadata
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-black/30 border border-white/5">
                <span className="text-slate-400 block text-[10px] uppercase">SHA-256</span>
                <span className="text-cyber-blue select-all break-all">{result.sha256 || 'N/A'}</span>
              </div>
              <div className="p-2.5 rounded bg-black/30 border border-white/5">
                <span className="text-slate-400 block text-[10px] uppercase">MD5</span>
                <span className="text-slate-300 select-all break-all">{result.md5 || 'N/A'}</span>
              </div>
              <div className="p-2.5 rounded bg-black/30 border border-white/5">
                <span className="text-slate-400 block text-[10px] uppercase">SHA-1</span>
                <span className="text-slate-300 select-all break-all">{result.sha1 || 'N/A'}</span>
              </div>
              <div className="p-2.5 rounded bg-black/30 border border-white/5">
                <span className="text-slate-400 block text-[10px] uppercase">MIME / Size</span>
                <span className="text-slate-300">{result.mime_type || 'Unknown'} • {result.file_size_bytes} bytes</span>
              </div>
            </div>
          </GlassCard>

          {/* YARA & Threat Intelligence Status */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <GlassCard className="p-5">
              <h3 className="text-sm font-semibold text-white mb-2">YARA Signature Engine</h3>
              <p className="text-xs text-slate-300 mb-2">Status: <span className="font-mono text-cyber-blue uppercase">{result.yara?.status || 'Not Configured'}</span></p>
              <p className="text-xs text-slate-400">{result.yara?.message || 'No rules matched.'}</p>
            </GlassCard>

            <GlassCard className="p-5">
              <h3 className="text-sm font-semibold text-white mb-2">VirusTotal File Reputation</h3>
              <p className="text-xs text-slate-300 mb-2">Verdict: <span className="font-mono uppercase text-cyber-blue">{result.threat_intelligence?.virustotal?.provider_verdict || 'NOT CONFIGURED'}</span></p>
              <p className="text-xs text-slate-400">{result.threat_intelligence?.virustotal?.normalized_interpretation || 'VirusTotal API key not configured.'}</p>
            </GlassCard>
          </div>

          {/* Forensic Indicators */}
          <GlassCard className="p-5">
            <h3 className="text-sm font-semibold text-white mb-3">Heuristic Findings & Evidence</h3>
            <div className="space-y-2">
              {result.indicators?.map((ind, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-black/30 border border-white/5 flex items-start justify-between gap-3 text-xs">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{ind.name}</span>
                      <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-white/10 text-slate-300">{ind.category}</span>
                    </div>
                    <p className="text-slate-400 mt-1">{ind.explanation}</p>
                    <p className="text-[11px] font-mono text-slate-400 mt-1">Evidence: {ind.technical_evidence}</p>
                  </div>
                  <SeverityBadge severity={ind.severity} />
                </div>
              ))}
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
}
