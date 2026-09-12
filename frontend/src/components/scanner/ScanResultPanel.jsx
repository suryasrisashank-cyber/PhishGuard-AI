import React, { useState } from 'react';
import { motion } from 'framer-motion';
import RiskMeter from '../ui/RiskMeter.jsx';
import ConfidenceMeter from '../ui/ConfidenceMeter.jsx';
import ThreatBadge from '../ui/ThreatBadge.jsx';
import SeverityBadge from '../ui/SeverityBadge.jsx';
import StatusBadge from '../ui/StatusBadge.jsx';
import EvidencePanel from './EvidencePanel.jsx';
import AIExplanationCard from './AIExplanationCard.jsx';
import IOCManagementTable from './IOCManagementTable.jsx';
import MitreMapping from './MitreMapping.jsx';
import InvestigationTimeline from './InvestigationTimeline.jsx';
import AnalystActions from './AnalystActions.jsx';
import AnalystNotes from './AnalystNotes.jsx';
import TechDetails from './TechDetails.jsx';
import SOCWorkflow from './SOCWorkflow.jsx';
import GlassCard from '../ui/GlassCard.jsx';
import { FileText, ExternalLink, ShieldAlert, Sparkles, CheckCircle2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

const TABS = [
  { id: 'evidence', label: 'Evidence Breakdown' },
  { id: 'iocs', label: 'IOC Management' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
  { id: 'actions', label: 'Recommended Response' },
  { id: 'timeline', label: 'Investigation Timeline' },
  { id: 'technical', label: 'Technical Details' },
  { id: 'notes', label: 'Analyst Notes' },
];

export default function ScanResultPanel({ scan }) {
  const [tab, setTab] = useState('evidence');
  const navigate = useNavigate();

  if (!scan) return null;

  const copyReport = () => {
    navigator.clipboard.writeText(JSON.stringify(scan, null, 2));
    toast.success('Investigation JSON copied to clipboard');
  };

  const failedCount = (scan.indicators || []).filter(i => !i.passed).length;

  return (
    <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>
      {/* SOC Workflow Stage Tracker */}
      <GlassCard style={{ padding: '16px 24px', marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
          <p style={{ margin: 0, fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            SOC Investigation Workflow
          </p>
          <span style={{ fontSize: 11, color: '#00c2ff', fontWeight: 600 }}>
            Stage: RESPOND & REPORT
          </span>
        </div>
        <SOCWorkflow stage="respond" verdict={scan.verdict} />
      </GlassCard>

      {/* AI Explanation Layer (Prominent synthesis of technical facts) */}
      <AIExplanationCard scan={scan} />

      {/* Large Premium Risk Result Hero Card */}
      <GlassCard style={{ padding: 24, marginBottom: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', gap: 28, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Risk Gauge */}
          <div style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
            <RiskMeter value={scan.risk_score || 0} size={150} />
            <div style={{ width: 1, height: 90, background: 'rgba(255,255,255,0.08)' }} />
          </div>

          {/* Verdict and Classification Details */}
          <div>
            <div style={{ fontSize: 11, color: '#64748b', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 6 }}>
              SECURITY VERDICT
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10, flexWrap: 'wrap' }}>
              <span style={{
                fontSize: 26, fontWeight: 900, letterSpacing: '0.02em',
                color: scan.verdict === 'Malicious' ? '#ef4444' : scan.verdict === 'Suspicious' ? '#f59e0b' : '#10b981',
              }}>
                {scan.verdict?.toUpperCase()}
              </span>
              <SeverityBadge severity={scan.severity} />
              <StatusBadge status={scan.investigation_status} />
            </div>
            <p style={{ margin: '0 0 10px', fontSize: 13, color: '#94a3b8', lineHeight: 1.6, maxWidth: 640 }}>
              {scan.summary}
            </p>
            <div style={{ fontSize: 12, color: '#64748b' }}>
              Identified <strong style={{ color: failedCount > 0 ? '#ef4444' : '#10b981' }}>{failedCount}</strong> anomalous pattern(s) across {(scan.indicators || []).length} heuristic checks.
            </div>
          </div>

          {/* Confidence and Quick Actions */}
          <div style={{ minWidth: 220, borderLeft: '1px solid rgba(255,255,255,0.06)', paddingLeft: 24 }}>
            <div style={{ marginBottom: 16 }}>
              <ConfidenceMeter value={scan.confidence_score} />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <button className="btn-primary" onClick={() => navigate(`/investigation/${scan.id}`)} style={{ fontSize: 12, padding: '8px 12px' }}>
                Open SOC Dossier
              </button>
              <button className="btn-ghost" onClick={copyReport} style={{ fontSize: 12, padding: '7px 12px' }}>
                Copy Case JSON
              </button>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Tabbed Detail Sections */}
      <GlassCard>
        {/* Tab Header Bar */}
        <div style={{ display: 'flex', gap: 2, padding: '12px 16px 0', borderBottom: '1px solid rgba(255,255,255,0.06)', flexWrap: 'wrap' }}>
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                padding: '10px 14px',
                fontSize: 13, fontWeight: tab === t.id ? 700 : 500,
                color: tab === t.id ? '#00c2ff' : '#64748b',
                borderBottom: tab === t.id ? '2px solid #00c2ff' : '2px solid transparent',
                marginBottom: -1,
                transition: 'all 0.15s',
              }}
            >
              {t.label}
              {t.id === 'evidence' && failedCount > 0 && (
                <span style={{ marginLeft: 6, fontSize: 10, background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '1px 6px', borderRadius: 10 }}>
                  {failedCount}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Body */}
        <div style={{ padding: 24 }}>
          {tab === 'evidence' && <EvidencePanel indicators={scan.indicators || []} />}
          {tab === 'iocs' && <IOCManagementTable indicators={scan.indicators || []} target={scan.target} />}
          {tab === 'mitre' && <MitreMapping techniques={scan.mitre_techniques} />}
          {tab === 'actions' && <AnalystActions actions={scan.analyst_actions} />}
          {tab === 'timeline' && <InvestigationTimeline events={scan.timeline} />}
          {tab === 'technical' && <TechDetails scan={scan} />}
          {tab === 'notes' && <AnalystNotes scanId={scan.id} initialNotes={scan.analyst_notes} />}
        </div>
      </GlassCard>
    </motion.div>
  );
}
