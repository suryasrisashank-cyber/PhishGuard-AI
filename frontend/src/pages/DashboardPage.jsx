import React, { useEffect, useState, lazy, Suspense } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, AlertTriangle, CheckCircle, Flame, Activity, ArrowRight, RefreshCw, Link2, Globe, Mail, Image, AlertOctagon } from 'lucide-react';
import PageHeader from '../components/ui/PageHeader.jsx';
import StatCard from '../components/ui/StatCard.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import StatusBadge from '../components/ui/StatusBadge.jsx';
import VerdictPie from '../components/charts/VerdictPie.jsx';
import ThreatTrendLine from '../components/charts/ThreatTrendLine.jsx';
import SeverityBar from '../components/charts/SeverityBar.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { dashboardApi } from '../services/api.js';
import { DEMO_MODE } from '../lib/constants.js';

// Lazy-load 3D Globe to optimize initial bundle performance
const GlobalThreatGlobe3D = lazy(() => import('../components/network/GlobalThreatGlobe3D.jsx'));

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, recentRes] = await Promise.all([
        dashboardApi.getStats(),
        dashboardApi.getRecent(10),
      ]);
      setStats(statsRes.data);
      setRecent(recentRes.data);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard telemetry');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const pieData = stats ? [
    { name: 'Safe', value: stats.safe || 0 },
    { name: 'Suspicious', value: stats.suspicious || 0 },
    { name: 'Malicious', value: stats.malicious || 0 },
  ] : [];

  const criticalScans = recent.filter(s => s.severity === 'CRITICAL' || s.risk_score >= 80);

  return (
    <div>
      <PageHeader
        title="Security Operations Center"
        subtitle="Tier-1 Threat Intelligence, Heuristic Forensics & Automated Case Triage"
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
            <RefreshCw size={14} /> Refresh Telemetry
          </button>
        }
      />

      {DEMO_MODE && (
        <div style={{
          padding: '10px 16px', borderRadius: 10, background: 'rgba(245,158,11,0.1)',
          border: '1px solid rgba(245,158,11,0.3)', color: '#f59e0b', fontSize: 12,
          fontWeight: 600, marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <AlertTriangle size={15} />
          <span>DEMO DATA ACTIVE — Synthetic baseline telemetry displayed for SOC interview & demo simulations.</span>
        </div>
      )}

      {loading ? (
        <LoadingSkeleton cards={5} />
      ) : error ? (
        <ErrorState message={error} onRetry={loadData} />
      ) : (
        <>
          {/* Quick Launch Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
            {[
              { label: 'URL Scanner', icon: Link2, path: '/scanner/url', color: '#00c2ff' },
              { label: 'Website Analyzer', icon: Globe, path: '/scanner/website', color: '#2563eb' },
              { label: 'Email Forensics', icon: Mail, path: '/scanner/email', color: '#7c3aed' },
              { label: 'Image Inspector', icon: Image, path: '/scanner/screenshot', color: '#10b981' },
            ].map(({ label, icon: Icon, path, color }) => (
              <GlassCard
                key={path}
                hover
                onClick={() => navigate(path)}
                style={{ padding: '14px 16px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12 }}
              >
                <div style={{ padding: 8, borderRadius: 8, background: `${color}15`, border: `1px solid ${color}30` }}>
                  <Icon size={18} color={color} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>{label}</div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>Start inspection</div>
                </div>
                <ArrowRight size={14} color="#64748b" />
              </GlassCard>
            ))}
          </div>

          {/* TOP SECTION: Prioritized SOC KPIs */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
            <StatCard title="Threat Level" value={stats?.threat_rate > 35 ? 'ELEVATED' : 'GUARDED'} color={stats?.threat_rate > 35 ? '#ef4444' : '#10b981'} subtitle="Calculated posture" />
            <StatCard title="Total Audited" value={stats?.total_scans} icon={Activity} color="#00c2ff" subtitle="Total inspected targets" />
            <StatCard title="Critical Alerts" value={stats?.critical || 0} icon={AlertOctagon} color="#dc2626" subtitle="Score >= 80 or Critical" />
            <StatCard title="Phishing Targets" value={stats?.malicious || 0} icon={Shield} color="#ef4444" subtitle="Confirmed malicious" />
            <StatCard title="Threat Ratio" value={`${stats?.threat_rate || 0}%`} icon={Flame} color="#f97316" subtitle="Anomalous targets" />
          </div>

          {/* MIDDLE SECTION: 3D Globe + Trend + Verdict Distribution */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 20 }}>
            <GlassCard style={{ padding: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>Global Threat Activity</h3>
                  <p style={{ margin: '2px 0 0', fontSize: 11, color: '#64748b' }}>Interactive WebGL threat activity visualization</p>
                </div>
              </div>
              <Suspense fallback={<div style={{ height: 280, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b' }}>Loading 3D globe...</div>}>
                <GlobalThreatGlobe3D stats={stats} />
              </Suspense>
            </GlassCard>

            <GlassCard style={{ padding: 20, display: 'flex', flexDirection: 'column' }}>
              <h3 style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>Verdict Distribution</h3>
              <p style={{ margin: '0 0 12px', fontSize: 11, color: '#64748b' }}>Classification of audited targets</p>
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <VerdictPie data={pieData} />
              </div>
            </GlassCard>
          </div>

          {/* Trend & Severity Matrix */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 16, marginBottom: 20 }}>
            <GlassCard style={{ padding: 20 }}>
              <h3 style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>7-Day Threat Trend</h3>
              <p style={{ margin: '0 0 16px', fontSize: 11, color: '#64748b' }}>Total target volume versus identified attacks</p>
              <ThreatTrendLine data={stats?.threat_trend} />
            </GlassCard>

            <GlassCard style={{ padding: 20 }}>
              <h3 style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>Severity Matrix</h3>
              <p style={{ margin: '0 0 16px', fontSize: 11, color: '#64748b' }}>Targets by calculated severity tier</p>
              <SeverityBar data={stats?.severity_distribution} />
            </GlassCard>
          </div>

          {/* BOTTOM SECTION: Recent Investigations & Critical Alerts */}
          <GlassCard style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Active SOC Case Dossiers</h3>
                <p style={{ margin: '2px 0 0', fontSize: 12, color: '#64748b' }}>Recent targets processed through the investigation pipeline</p>
              </div>
              <button className="btn-ghost" onClick={() => navigate('/history')} style={{ fontSize: 12 }}>
                Open Scan Archive
              </button>
            </div>

            {recent.length === 0 ? (
              <p style={{ textAlign: 'center', color: '#64748b', padding: '32px 0', fontSize: 13 }}>No scans recorded yet. Use the URL or Email Scanner to begin.</p>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Case</th>
                      <th>Target Artifact</th>
                      <th>Modality</th>
                      <th>Risk Score</th>
                      <th>Verdict</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map((scan) => (
                      <tr key={scan.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', color: '#64748b' }}>#{scan.id}</td>
                        <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>
                          {scan.target}
                        </td>
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>
                            {scan.scan_type}
                          </span>
                        </td>
                        <td>
                          <span style={{
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            color: scan.risk_score >= 70 ? '#ef4444' : scan.risk_score >= 40 ? '#f59e0b' : '#10b981',
                          }}>
                            {scan.risk_score?.toFixed(0)}/100
                          </span>
                        </td>
                        <td><ThreatBadge verdict={scan.verdict} size="sm" /></td>
                        <td><SeverityBadge severity={scan.severity} size="sm" /></td>
                        <td><StatusBadge status={scan.investigation_status} /></td>
                        <td>
                          <button
                            className="btn-ghost"
                            onClick={() => navigate(`/investigation/${scan.id}`)}
                            style={{ padding: '4px 10px', fontSize: 11 }}
                          >
                            Investigate
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </GlassCard>
        </>
      )}
    </div>
  );
}
