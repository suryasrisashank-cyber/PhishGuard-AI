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
import AIExplanationCard from '../components/scanner/AIExplanationCard.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { scansApi } from '../services/api.js';
import { Shield, ArrowLeft, FileText, CheckCircle, AlertOctagon, UserCheck, Play, Check } from 'lucide-react';
import toast from 'react-hot-toast';

export default function InvestigationPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusUpdating, setStatusUpdating] = useState(false);

  const loadScan = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await scansApi.get(id);
      setScan(res.data);
    } catch (err) {
      setError(err.message || `Failed to fetch case #${id}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScan();
  }, [id]);

  const handleStatusTransition = async (newStatus) => {
    setStatusUpdating(true);
    try {
      await scansApi.updateStatus(id, newStatus);
      setScan(prev => ({ ...prev, investigation_status: newStatus }));
      toast.success(`Workflow status: ${newStatus}`);
    } catch (err) {
      toast.error(err.message || 'Failed to update status');
    } finally {
      setStatusUpdating(false);
    }
  };

  return (
    <div>
      <PageHeader
        title={`SOC Investigation Dossier #${id}`}
        subtitle={`Active forensics case record for target: ${scan?.target || 'loading...'}`}
        actions={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button className="btn-ghost" onClick={() => navigate('/history')} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <ArrowLeft size={14} /> Scan Archive
            </button>
            <button className="btn-ghost" onClick={() => navigate(`/reports?scanId=${id}`)} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <FileText size={14} /> Export Report
            </button>
          </div>
        }
      />

      {loading ? (
        <LoadingSkeleton cards={4} />
      ) : error ? (
        <ErrorState message={error} onRetry={loadScan} />
      ) : scan ? (
        <div>
          {/* Workflow Status Action Bar */}
          <GlassCard style={{ padding: '16px 20px', marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
              <div>
                <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Triage State: </span>
                <StatusBadge status={scan.investigation_status} />
              </div>

              {/* Status Action Workflow Buttons */}
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button
                  className="btn-ghost"
                  onClick={() => handleStatusTransition('INVESTIGATING')}
                  disabled={statusUpdating || scan.investigation_status === 'INVESTIGATING'}
                  style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 5 }}
                >
                  <Play size={12} /> Start Investigation
                </button>
                <button
                  className="btn-ghost"
                  onClick={() => handleStatusTransition('CONFIRMED_THREAT')}
                  disabled={statusUpdating || scan.investigation_status === 'CONFIRMED_THREAT'}
                  style={{ fontSize: 12, color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)', display: 'flex', alignItems: 'center', gap: 5 }}
                >
                  <AlertOctagon size={12} /> Confirm Threat
                </button>
                <button
                  className="btn-ghost"
                  onClick={() => handleStatusTransition('RESPONDING')}
                  disabled={statusUpdating || scan.investigation_status === 'RESPONDING'}
                  style={{ fontSize: 12, color: '#f97316', borderColor: 'rgba(249,115,22,0.3)', display: 'flex', alignItems: 'center', gap: 5 }}
                >
                  <Shield size={12} /> Start Response
                </button>
                <button
                  className="btn-ghost"
                  onClick={() => handleStatusTransition('FALSE_POSITIVE')}
                  disabled={statusUpdating || scan.investigation_status === 'FALSE_POSITIVE'}
                  style={{ fontSize: 12, color: '#10b981', borderColor: 'rgba(16,185,129,0.3)', display: 'flex', alignItems: 'center', gap: 5 }}
                >
                  <UserCheck size={12} /> Mark False Positive
                </button>
                <button
                  className="btn-primary"
                  onClick={() => handleStatusTransition('RESOLVED')}
                  disabled={statusUpdating || scan.investigation_status === 'RESOLVED'}
                  style={{ fontSize: 12, padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 5 }}
                >
                  <Check size={12} /> Resolve Case
                </button>
              </div>
            </div>
          </GlassCard>

          {/* AI Security Explanation */}
          <AIExplanationCard scan={scan} />

          {/* 3-Column SOC Dossier Layout */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr 1.1fr', gap: 20, alignItems: 'start' }}>
            
            {/* LEFT COLUMN: Case Information & ATT&CK */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* Case Information */}
              <GlassCard style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>Case Metadata</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12 }}>
                  <div>
                    <span style={{ color: '#64748b' }}>Target Artifact:</span>
                    <div style={{ fontFamily: 'var(--font-mono)', color: '#f1f5f9', wordBreak: 'break-all', marginTop: 3 }}>
                      {scan.target}
                    </div>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Scan Modality:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: '#00c2ff', textTransform: 'uppercase' }}>{scan.scan_type}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Engine Version:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>{scan.detection_engine_version || '2.1.0'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Ingestion Time:</span>
                    <span style={{ color: '#94a3b8' }}>{scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Processing Latency:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>{scan.processing_time_ms ? `${scan.processing_time_ms} ms` : 'N/A'}</span>
                  </div>
                </div>
              </GlassCard>

              {/* MITRE ATT&CK */}
              <GlassCard style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>MITRE ATT&CK Alignment</h3>
                <MitreMapping techniques={scan.mitre_techniques} />
              </GlassCard>

              {/* Analyst Notes Editor */}
              <GlassCard style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>Case Notes</h3>
                <AnalystNotes scanId={scan.id} initialNotes={scan.analyst_notes} />
              </GlassCard>
            </div>

            {/* CENTER COLUMN: Evidence Breakdown & IOCs */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <GlassCard style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Forensic Evidence</h3>
                <EvidencePanel indicators={scan.indicators || []} />
              </GlassCard>

              <GlassCard style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Extracted IOCs</h3>
                <IOCManagementTable indicators={scan.indicators || []} target={scan.target} />
              </GlassCard>
            </div>

            {/* RIGHT COLUMN: Risk Summary, Recommended Response, Activity Timeline */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* Risk Summary */}
              <GlassCard style={{ padding: 20, textAlign: 'center' }}>
                <div style={{ marginBottom: 12 }}>
                  <RiskMeter value={scan.risk_score || 0} size={140} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginBottom: 14 }}>
                  <ThreatBadge verdict={scan.verdict} size="lg" />
                  <SeverityBadge severity={scan.severity} />
                </div>
                <ConfidenceMeter value={scan.confidence_score} />
              </GlassCard>

              {/* Recommended Response */}
              <GlassCard style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>Recommended Response</h3>
                <AnalystActions actions={scan.analyst_actions} />
              </GlassCard>

              {/* Activity Timeline */}
              <GlassCard style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>Investigation Timeline</h3>
                <InvestigationTimeline events={scan.timeline} />
              </GlassCard>
            </div>

          </div>
        </div>
      ) : null}
    </div>
  );
}
