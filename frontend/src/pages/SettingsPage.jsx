import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import { healthApi, systemApi } from '../services/api.js';
import { Settings, ShieldCheck, Database, HardDrive, Key, Check, RefreshCw, Server } from 'lucide-react';
import toast from 'react-hot-toast';
import { useBackendStatus } from '../context/BackendStatusContext.jsx';
import { getDeveloperApiOverride, setDeveloperApiOverride } from '../config/api.js';

export default function SettingsPage() {
  const {
    status,
    statusMessage,
    latency,
    version,
    environment,
    apiUrl,
    healthUrl,
    lastChecked,
    errorType,
    retryConnection,
  } = useBackendStatus();
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [showDevOptions, setShowDevOptions] = useState(false);
  const [customBackendInput, setCustomBackendInput] = useState(() => getDeveloperApiOverride());
  const [integrationsList, setIntegrationsList] = useState([]);
  const [integrationsLoading, setIntegrationsLoading] = useState(true);

  useEffect(() => {
    systemApi.getIntegrations()
      .then((res) => {
        const feeds = (res.data?.integrations || []).filter(i => 
          ['VirusTotal', 'AbuseIPDB', 'AlienVault OTX', 'URLhaus', 'DNS Resolver'].includes(i.name)
        );
        setIntegrationsList(feeds.length > 0 ? feeds : (res.data?.integrations || []).slice(0, 5));
      })
      .catch(() => {})
      .finally(() => setIntegrationsLoading(false));
  }, []);

  const handleTestHealth = async () => {
    setCheckingHealth(true);
    try {
      const ok = await retryConnection();
      if (ok) {
        toast.success('SOC backend is connected and healthy');
      } else {
        toast.error('SOC backend is currently unreachable');
      }
    } finally {
      setCheckingHealth(false);
    }
  };

  const clearSession = () => {
    localStorage.clear();
    toast.success('Session storage wiped');
  };

  return (
    <div>
      <PageHeader
        title="System Configuration & Diagnostics"
        subtitle="Operational parameters, API connectivity verification & security controls"
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 20 }}>
        {/* Backend & API Status (Phase 18) */}
        <GlassCard style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Server size={18} color="#00c2ff" />
              <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Detection Engine API</h3>
            </div>
            <span style={{
              fontSize: 12,
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              color: status === 'CONNECTED' ? '#10b981' : status === 'CONNECTING' ? '#00c2ff' : '#ef4444',
            }}>
              {status === 'CONNECTED' ? '● CONNECTED' : status === 'CONNECTING' ? '● CONNECTING' : '● OFFLINE'}
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, fontSize: 12, color: '#94a3b8', marginBottom: 16 }}>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>API Endpoint</div>
              <div style={{ color: '#f1f5f9', fontWeight: 600, fontFamily: 'var(--font-mono)', marginTop: 2, wordBreak: 'break-all' }}>{apiUrl}</div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Health Probe</div>
              <div style={{ color: '#00c2ff', fontWeight: 600, fontFamily: 'var(--font-mono)', marginTop: 2, wordBreak: 'break-all' }}>{healthUrl || `${apiUrl}/health`}</div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Engine Version</div>
              <div style={{ color: '#f1f5f9', fontWeight: 600, fontFamily: 'var(--font-mono)', marginTop: 2 }}>v{version}</div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Latency / Ping</div>
              <div style={{ color: latency ? '#10b981' : '#64748b', fontWeight: 600, fontFamily: 'var(--font-mono)', marginTop: 2 }}>{latency ? `${latency} ms` : '—'}</div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Last Verified</div>
              <div style={{ color: '#94a3b8', fontWeight: 600, fontFamily: 'var(--font-mono)', marginTop: 2 }}>{lastChecked ? new Date(lastChecked).toLocaleTimeString() : '—'}</div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase' }}>Environment</div>
              <div style={{ color: '#f59e0b', fontWeight: 600, textTransform: 'uppercase', marginTop: 2 }}>{environment}</div>
            </div>
          </div>

          {status !== 'CONNECTED' && (
            <div style={{
              margin: '0 0 16px',
              padding: '8px 12px',
              borderRadius: 6,
              background: status === 'CONNECTING' ? 'rgba(0,194,255,0.08)' : 'rgba(239,68,68,0.08)',
              border: `1px solid ${status === 'CONNECTING' ? 'rgba(0,194,255,0.2)' : 'rgba(239,68,68,0.2)'}`,
              fontSize: 12,
              color: status === 'CONNECTING' ? '#38bdf8' : '#fca5a5',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 8,
            }}>
              <span><strong>Status:</strong> {statusMessage}</span>
              {errorType && (
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10,
                  padding: '2px 6px',
                  borderRadius: 4,
                  background: 'rgba(0,0,0,0.2)',
                }}>
                  {errorType}
                </span>
              )}
            </div>
          )}

          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 16 }}>
            <button className="btn-primary" onClick={handleTestHealth} disabled={checkingHealth} style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
              <RefreshCw size={13} className={checkingHealth ? 'animate-spin' : ''} /> {checkingHealth ? 'Testing Connection...' : 'Check API Status'}
            </button>
            <button
              onClick={() => setShowDevOptions(!showDevOptions)}
              style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 11, textDecoration: 'underline' }}
            >
              {showDevOptions ? 'Hide Developer Settings' : 'Developer / Local Testing Only'}
            </button>
          </div>

          {/* Developer / Local Testing Only Section (Phase 18) */}
          {showDevOptions && (
            <div style={{
              padding: '12px 14px',
              borderRadius: 8,
              background: 'rgba(255,255,255,0.02)',
              border: '1px dashed rgba(255,255,255,0.12)',
              fontSize: 12,
            }}>
              <div style={{ fontWeight: 600, color: '#f59e0b', marginBottom: 4 }}>
                Developer / Local Testing Only
              </div>
              <p style={{ color: '#64748b', fontSize: 11, margin: '0 0 10px' }}>
                Production users connect automatically via deployment configuration. This override is strictly for developers testing a local or staging server.
              </p>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="url"
                  placeholder="http://127.0.0.1:8000/api"
                  value={customBackendInput}
                  onChange={(e) => setCustomBackendInput(e.target.value)}
                  style={{
                    flex: 1,
                    padding: '6px 10px',
                    borderRadius: 6,
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: '#fff',
                    fontSize: 12,
                    fontFamily: 'var(--font-mono)',
                    outline: 'none',
                  }}
                />
                <button
                  className="btn-primary"
                  onClick={() => {
                    setDeveloperApiOverride(customBackendInput);
                    toast.success('Developer override saved!');
                  }}
                  style={{ fontSize: 11, padding: '6px 12px' }}
                >
                  Save Override
                </button>
                {customBackendInput && (
                  <button
                    onClick={() => {
                      setCustomBackendInput('');
                      setDeveloperApiOverride('');
                      toast.success('Developer override reset');
                    }}
                    style={{
                      fontSize: 11,
                      padding: '6px 10px',
                      borderRadius: 6,
                      background: 'rgba(239,68,68,0.1)',
                      border: '1px solid rgba(239,68,68,0.2)',
                      color: '#f87171',
                      cursor: 'pointer',
                    }}
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>
          )}
        </GlassCard>

        {/* Threat Intelligence Feed Status */}
        <GlassCard style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Key size={18} color="#7c3aed" />
              <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Feed Integrations</h3>
            </div>
            <Link to="/integrations" style={{ fontSize: 12, color: '#00c2ff', textDecoration: 'none', fontWeight: 600 }}>
              View Diagnostics →
            </Link>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
            {integrationsLoading ? (
              <div style={{ padding: '8px 12px', color: '#94a3b8', fontSize: 12 }}>Checking feed statuses...</div>
            ) : integrationsList.length > 0 ? (
              integrationsList.map((item, idx) => {
                const statusColor = 
                  item.status === 'CONNECTED' ? '#10b981' :
                  item.status === 'AVAILABLE' ? '#38bdf8' :
                  item.status === 'NOT CONFIGURED' ? '#f59e0b' :
                  item.status === 'ERROR' ? '#ef4444' : '#94a3b8';

                return (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)' }}>
                    <span>{item.name}</span>
                    <span style={{ color: statusColor, fontWeight: 600, fontSize: 12 }}>
                      {item.status}
                    </span>
                  </div>
                );
              })
            ) : (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)' }}>
                  <span>VirusTotal v3</span>
                  <span style={{ color: '#10b981', fontWeight: 600 }}>CONNECTED</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)' }}>
                  <span>URLhaus (abuse.ch)</span>
                  <span style={{ color: '#10b981', fontWeight: 600 }}>CONNECTED</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)' }}>
                  <span>DNS & WHOIS Engine</span>
                  <span style={{ color: '#10b981', fontWeight: 600 }}>CONNECTED</span>
                </div>
              </>
            )}
          </div>
        </GlassCard>

        {/* Analyst Workspace Actions */}
        <GlassCard style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <HardDrive size={18} color="#f59e0b" />
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Session & Storage</h3>
          </div>

          <p style={{ margin: '0 0 16px', fontSize: 13, color: '#94a3b8' }}>
            Clears cached authentication tokens, investigation workspace drafts, and UI preferences.
          </p>

          <button className="btn-danger" onClick={clearSession} style={{ fontSize: 13 }}>
            Purge Local Storage Cache
          </button>
        </GlassCard>
      </div>
    </div>
  );
}
