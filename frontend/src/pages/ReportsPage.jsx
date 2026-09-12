import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import StatusBadge from '../components/ui/StatusBadge.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { reportsApi, dashboardApi } from '../services/api.js';
import { FileText, Copy, Download, CheckCircle, Shield, AlertTriangle, Printer } from 'lucide-react';
import toast from 'react-hot-toast';

export default function ReportsPage() {
  const [searchParams] = useSearchParams();
  const scanIdParam = searchParams.get('scanId');
  const navigate = useNavigate();

  const [scanId, setScanId] = useState(scanIdParam || '');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [recentScans, setRecentScans] = useState([]);

  useEffect(() => {
    dashboardApi.getRecent(15).then(res => setRecentScans(res.data)).catch(() => {});
    if (scanIdParam) {
      loadReport(scanIdParam);
    }
  }, [scanIdParam]);

  const loadReport = async (idToFetch = scanId) => {
    if (!idToFetch) {
      toast.error('Select a scan ID to generate report');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await reportsApi.get(idToFetch);
      setReport(res.data);
    } catch (err) {
      setError(err.message || 'Report generation failed');
    } finally {
      setLoading(false);
    }
  };

  const copyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    toast.success('Report JSON copied to clipboard');
  };

  const downloadJSON = () => {
    const jsonStr = JSON.stringify(report, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard_report_${report.scan_id}.json`;
    a.click();
    toast.success('Report downloaded as JSON');
  };

  return (
    <div>
      <PageHeader
        title="Executive Security Reports"
        subtitle="Automated incident documentation, IOC summaries & remediation protocols"
      />

      {/* Select Scan Bar */}
      <GlassCard style={{ padding: 20, marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <select
              className="cyber-input"
              value={scanId}
              onChange={(e) => {
                setScanId(e.target.value);
                if (e.target.value) loadReport(e.target.value);
              }}
            >
              <option value="">Select an audited case to generate report...</option>
              {recentScans.map(s => (
                <option key={s.id} value={s.id}>
                  Case #{s.id} — [{s.verdict}] {s.target.slice(0, 50)}
                </option>
              ))}
            </select>
          </div>
          <button className="btn-primary" onClick={() => loadReport()} disabled={loading || !scanId}>
            {loading ? 'Compiling Dossier...' : 'Generate Report'}
          </button>
        </div>
      </GlassCard>

      {loading ? (
        <LoadingSkeleton cards={3} />
      ) : error ? (
        <ErrorState message={error} onRetry={() => loadReport()} />
      ) : report ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Executive Header Card */}
          <GlassCard style={{ padding: 28 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
              <div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#00c2ff', fontWeight: 700, letterSpacing: '0.08em' }}>
                  PHISHGUARD AI • SECURITY INCIDENT REPORT
                </span>
                <h2 style={{ margin: '6px 0 10px', fontSize: 20, fontWeight: 800, color: '#f1f5f9' }}>
                  {report.target}
                </h2>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                  <ThreatBadge verdict={report.verdict} />
                  <SeverityBadge severity={report.severity} />
                  <StatusBadge status={report.investigation_status} />
                  <span style={{ fontSize: 12, color: '#64748b' }}>
                    Engine: {report.detection_engine_version}
                  </span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button className="btn-ghost" onClick={copyJSON} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                  <Copy size={13} /> Copy JSON
                </button>
                <button className="btn-ghost" onClick={downloadJSON} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                  <Download size={13} /> Download JSON
                </button>
                <button
                  className="btn-ghost"
                  onClick={() => toast('PDF Export — Coming Soon (JSON export available)', { icon: 'ℹ️' })}
                  title="PDF generation pipeline"
                  style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, opacity: 0.85 }}
                >
                  <Download size={13} /> PDF Export — Coming Soon
                </button>
              </div>
            </div>

            <hr style={{ borderColor: 'rgba(255,255,255,0.06)', margin: '20px 0' }} />

            {/* Metrics Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
              <div style={{ padding: 12, borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Risk Score</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: report.risk_score >= 70 ? '#ef4444' : report.risk_score >= 40 ? '#f59e0b' : '#10b981' }}>
                  {report.risk_score?.toFixed(0)} / 100
                </div>
              </div>
              <div style={{ padding: 12, borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Evidence Confidence</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: '#00c2ff' }}>
                  {report.confidence_score ? `${report.confidence_score}%` : 'N/A'}
                </div>
              </div>
              <div style={{ padding: 12, borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Audit ID</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: '#cbd5e1', fontFamily: 'var(--font-mono)' }}>
                  #{report.scan_id}
                </div>
              </div>
              <div style={{ padding: 12, borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Generated Timestamp</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginTop: 4 }}>
                  {report.generated_at ? new Date(report.generated_at).toLocaleTimeString() : 'N/A'}
                </div>
              </div>
            </div>

            {/* Executive Summary */}
            <h4 style={{ margin: '0 0 8px', fontSize: 12, textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.06em' }}>
              Executive Summary
            </h4>
            <p style={{ margin: 0, fontSize: 14, color: '#cbd5e1', lineHeight: 1.7 }}>
              {report.executive_summary}
            </p>
          </GlassCard>

          {/* Technical Findings & Actions */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <GlassCard style={{ padding: 20 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, textTransform: 'uppercase', color: '#64748b' }}>
                Recommended Response Protocols
              </h4>
              {report.recommendations?.map((rec, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', marginBottom: 10 }}>
                  <CheckCircle size={15} color="#10b981" style={{ flexShrink: 0, marginTop: 2 }} />
                  <span style={{ fontSize: 13, color: '#94a3b8' }}>{rec}</span>
                </div>
              ))}
            </GlassCard>

            <GlassCard style={{ padding: 20 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, textTransform: 'uppercase', color: '#64748b' }}>
                MITRE ATT&CK Matrix Alignment
              </h4>
              {report.mitre_attack_mapping?.length > 0 ? (
                report.mitre_attack_mapping.map((m, i) => (
                  <div key={i} style={{ marginBottom: 12, paddingBottom: 8, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#7c3aed', background: 'rgba(124,58,237,0.1)', padding: '2px 6px', borderRadius: 4 }}>
                        {m.technique_id}
                      </span>
                      <strong style={{ fontSize: 13, color: '#f1f5f9' }}>{m.technique_name}</strong>
                    </div>
                    <p style={{ margin: '4px 0 0', fontSize: 12, color: '#94a3b8' }}>{m.reason}</p>
                  </div>
                ))
              ) : (
                <p style={{ fontSize: 13, color: '#64748b', margin: 0 }}>No MITRE techniques mapped for this target.</p>
              )}
            </GlassCard>
          </div>

          <div style={{ fontSize: 11, color: '#475569', fontStyle: 'italic', textAlign: 'center' }}>
            {report.disclaimer}
          </div>
        </div>
      ) : null}
    </div>
  );
}
