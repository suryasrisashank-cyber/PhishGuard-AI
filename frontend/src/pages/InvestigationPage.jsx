import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import RiskMeter from '../components/ui/RiskMeter.jsx';
import ConfidenceMeter from '../components/ui/ConfidenceMeter.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import StatusBadge from '../components/ui/StatusBadge.jsx';
import EvidencePanel from '../components/scanner/EvidencePanel.jsx';
import IOCManagementTable from '../components/scanner/IOCManagementTable.jsx';
import MitreMapping from '../components/scanner/MitreMapping.jsx';
import AnalystActions from '../components/scanner/AnalystActions.jsx';
import AnalystNotes from '../components/scanner/AnalystNotes.jsx';
import InvestigationTimeline from '../components/scanner/InvestigationTimeline.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { scansApi, investigationsApi, splunkApi } from '../services/api.js';
import { Shield, ArrowLeft, Send, Plus, CheckCircle, AlertTriangle, ExternalLink, Activity, X } from 'lucide-react';
import toast from 'react-hot-toast';

export default function InvestigationPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [splunkSending, setSplunkSending] = useState(false);
  const [splunkMsg, setSplunkMsg] = useState(null);

  // Burp modal state
  const [burpModalOpen, setBurpModalOpen] = useState(false);
  const [burpForm, setBurpForm] = useState({
    issue_name: 'Cleartext Submission of Password',
    severity: 'High',
    confidence: 'Certain',
    host: '',
    path: '/',
    detail: 'Form submits sensitive credentials over unencrypted communication channel.',
    remediation: 'Ensure all authentication forms submit strictly via HTTPS with HSTS.',
  });

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Try investigation case first
      try {
        const caseRes = await investigationsApi.get(id);
        setScan({
          ...caseRes.data,
          scan_type: caseRes.data.scan_type || 'Investigation Case',
          target: caseRes.data.title,
          indicators: caseRes.data.evidence || [],
        });
        return;
      } catch (caseErr) {
        // Fallback to scan ID
      }

      const res = await scansApi.get(id);
      setScan(res.data);
    } catch (err) {
      setError(err.message || `Failed to fetch case #${id}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [id]);

  const handleStatusTransition = async (newStatus) => {
    setStatusUpdating(true);
    try {
      if (scan.case_id) {
        await investigationsApi.update(scan.case_id, { status: newStatus });
      } else {
        await scansApi.updateStatus(id, newStatus);
      }
      setScan(prev => ({ ...prev, investigation_status: newStatus, status: newStatus }));
      toast.success(`Workflow status: ${newStatus}`);
    } catch (err) {
      toast.error(err.message || 'Failed to update status');
    } finally {
      setStatusUpdating(false);
    }
  };

  const handleForwardSplunk = async () => {
    setSplunkSending(true);
    setSplunkMsg(null);
    try {
      let res;
      if (scan.case_id) {
        res = await investigationsApi.forwardToSplunk(scan.case_id);
      } else {
        res = await splunkApi.sendEvent(scan, 'investigation_event', 'phishguard:investigation');
      }
      setSplunkMsg(res.data.message || 'Dispatched to Splunk HEC');
      toast.success('Dispatched to Splunk SIEM');
    } catch (err) {
      setSplunkMsg(`Error: ${err.message}`);
      toast.error('Splunk dispatch failed');
    } finally {
      setSplunkSending(false);
    }
  };

  const handleAttachBurp = async (e) => {
    e.preventDefault();
    try {
      const caseIdToUse = scan.case_id || id;
      await investigationsApi.attachBurpFinding(caseIdToUse, {
        ...burpForm,
        host: burpForm.host || scan.target || 'target-host',
      });
      toast.success('Burp Suite finding attached');
      setBurpModalOpen(false);
      loadData();
    } catch (err) {
      toast.error(`Failed to attach: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition"
          >
            <ArrowLeft size={18} />
          </button>
          <div>
            <span className="text-[11px] font-mono text-cyber-blue uppercase tracking-wider">
              {scan?.case_id ? `CASE ${scan.case_id}` : `SCAN #${id}`}
            </span>
            <h1 className="text-xl font-bold text-white mt-0.5">{scan?.target || 'Case Investigation'}</h1>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setBurpModalOpen(true)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20 transition flex items-center gap-1.5"
          >
            <Plus size={13} />
            Attach Burp Finding
          </button>
          <button
            onClick={handleForwardSplunk}
            disabled={splunkSending}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/20 transition flex items-center gap-1.5"
          >
            <Send size={13} />
            {splunkSending ? 'Forwarding...' : 'Dispatch to Splunk'}
          </button>
        </div>
      </div>

      {splunkMsg && (
        <div className="p-3 rounded-lg bg-cyber-blue/10 border border-cyber-blue/20 text-cyber-blue text-xs font-mono">
          Splunk HEC: {splunkMsg}
        </div>
      )}

      {loading && <LoadingSkeleton count={4} />}
      {error && <ErrorState message={error} onRetry={loadData} />}

      {scan && !loading && (
        <div className="space-y-6">
          {/* Status Workflow Progression Ribbon */}
          <GlassCard className="p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">WORKFLOW:</span>
              <StatusBadge status={scan.status || scan.investigation_status || 'NEW'} />
            </div>

            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              {['NEW', 'TRIAGED', 'INVESTIGATING', 'CONFIRMED_THREAT', 'CONTAINMENT', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
                <button
                  key={st}
                  onClick={() => handleStatusTransition(st)}
                  disabled={statusUpdating}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition ${
                    (scan.status || scan.investigation_status) === st
                      ? 'bg-cyber-blue text-black font-bold'
                      : 'bg-white/5 hover:bg-white/10 text-slate-300'
                  }`}
                >
                  {st.replace('_', ' ')}
                </button>
              ))}
            </div>
          </GlassCard>

          {/* Three Column Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Column 1: Case Details & Notes */}
            <div className="space-y-6">
              <GlassCard className="p-5 space-y-3">
                <h3 className="text-sm font-bold text-white border-b border-white/5 pb-2">Case Metadata</h3>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Modality:</span>
                    <span className="font-mono text-cyber-blue uppercase">{scan.scan_type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Severity:</span>
                    <SeverityBadge severity={scan.severity} />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Verdict:</span>
                    <ThreatBadge verdict={scan.verdict} />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Analyst:</span>
                    <span className="text-slate-200">{scan.analyst || 'SOC Analyst Tier 1'}</span>
                  </div>
                </div>
              </GlassCard>

              <GlassCard className="p-5">
                <h3 className="text-sm font-bold text-white mb-3">Analyst Case Notes</h3>
                <AnalystNotes scanId={scan.id} initialNotes={scan.analyst_notes} />
              </GlassCard>

              {/* Burp Suite Findings (External Validation) */}
              {scan.burp_findings?.length > 0 && (
                <GlassCard className="p-5 space-y-3">
                  <h3 className="text-sm font-bold text-amber-400 flex items-center gap-1.5">
                    <Shield size={16} />
                    External Burp Suite Findings ({scan.burp_findings.length})
                  </h3>
                  <div className="space-y-2 text-xs">
                    {scan.burp_findings.map((bf, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-black/30 border border-amber-500/20 space-y-1">
                        <div className="flex justify-between font-semibold text-white">
                          <span>{bf.issue_name}</span>
                          <span className="text-amber-400 font-mono text-[10px]">{bf.severity}</span>
                        </div>
                        <p className="text-slate-400 text-[11px]">{bf.detail}</p>
                        <p className="text-[10px] font-mono text-slate-500">Target: {bf.host}{bf.path}</p>
                      </div>
                    ))}
                  </div>
                </GlassCard>
              )}
            </div>

            {/* Column 2: Evidence & Extracted IOCs */}
            <div className="space-y-6">
              <GlassCard className="p-5">
                <h3 className="text-sm font-bold text-white mb-3">Forensic Evidence</h3>
                <EvidencePanel indicators={scan.indicators || []} />
              </GlassCard>

              <GlassCard className="p-5">
                <h3 className="text-sm font-bold text-white mb-3">Extracted Indicators of Compromise</h3>
                <IOCManagementTable indicators={scan.indicators || []} target={scan.target} />
              </GlassCard>
            </div>

            {/* Column 3: Scores, MITRE & Timeline */}
            <div className="space-y-6">
              <GlassCard className="p-5 flex flex-col items-center justify-center space-y-3">
                <RiskMeter value={scan.risk_score || 0} size={140} />
                <ConfidenceMeter value={scan.confidence_score} />
              </GlassCard>

              <GlassCard className="p-5">
                <h3 className="text-sm font-bold text-white mb-3">MITRE ATT&CK Alignment</h3>
                <MitreMapping techniques={scan.mitre_techniques} />
              </GlassCard>

              <GlassCard className="p-5">
                <h3 className="text-sm font-bold text-white mb-3">Investigation Timeline</h3>
                <InvestigationTimeline events={scan.timeline} />
              </GlassCard>
            </div>
          </div>
        </div>
      )}

      {/* Attach Burp Suite Finding Modal */}
      {burpModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-white/10 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Shield size={18} className="text-amber-400" />
                Attach External Burp Suite Finding
              </h3>
              <button onClick={() => setBurpModalOpen(false)} className="text-slate-400 hover:text-white">
                <X size={18} />
              </button>
            </div>

            <p className="text-xs text-slate-400">
              PhishGuard documents Burp Suite as an external authorized testing tool. Attach genuine manual assessment evidence to this case file.
            </p>

            <form onSubmit={handleAttachBurp} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Issue Name / Vulnerability</label>
                <input
                  type="text"
                  value={burpForm.issue_name}
                  onChange={(e) => setBurpForm({ ...burpForm, issue_name: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-white/10 rounded px-3 py-2 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Severity</label>
                  <select
                    value={burpForm.severity}
                    onChange={(e) => setBurpForm({ ...burpForm, severity: e.target.value })}
                    className="w-full bg-slate-950 border border-white/10 rounded px-3 py-2 text-white"
                  >
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Information">Information</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Confidence</label>
                  <select
                    value={burpForm.confidence}
                    onChange={(e) => setBurpForm({ ...burpForm, confidence: e.target.value })}
                    className="w-full bg-slate-950 border border-white/10 rounded px-3 py-2 text-white"
                  >
                    <option value="Certain">Certain</option>
                    <option value="Firm">Firm</option>
                    <option value="Tentative">Tentative</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Host</label>
                  <input
                    type="text"
                    value={burpForm.host}
                    placeholder="e.g. target.com"
                    onChange={(e) => setBurpForm({ ...burpForm, host: e.target.value })}
                    className="w-full bg-slate-950 border border-white/10 rounded px-3 py-2 text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Path</label>
                  <input
                    type="text"
                    value={burpForm.path}
                    onChange={(e) => setBurpForm({ ...burpForm, path: e.target.value })}
                    className="w-full bg-slate-950 border border-white/10 rounded px-3 py-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Observation Detail</label>
                <textarea
                  value={burpForm.detail}
                  rows={3}
                  onChange={(e) => setBurpForm({ ...burpForm, detail: e.target.value })}
                  className="w-full bg-slate-950 border border-white/10 rounded px-3 py-2 text-white"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setBurpModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-white/5 hover:bg-white/10 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary px-4 py-1.5 rounded text-xs font-semibold"
                >
                  Attach to Investigation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
