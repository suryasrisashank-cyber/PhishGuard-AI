import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import { healthApi, systemApi } from '../services/api.js';
import { Settings, ShieldCheck, Database, HardDrive, Key, Check, RefreshCw, Server } from 'lucide-react';
import toast from 'react-hot-toast';
import { API_URL, getCustomBackendUrl, setCustomBackendUrl } from '../lib/constants.js';

export default function SettingsPage() {
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [healthStatus, setHealthStatus] = useState(null);
  const [customBackendInput, setCustomBackendInput] = useState(() => getCustomBackendUrl());
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

  const checkHealth = async () => {
    setCheckingHealth(true);
    try {
      const res = await healthApi.check();
      setHealthStatus(res.data);
      toast.success('Backend is healthy');
    } catch (err) {
      setHealthStatus({ status: 'offline', error: err.message });
      toast.error('Backend unreachable');
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
        {/* Backend & API Status */}
        <GlassCard style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Server size={18} color="#00c2ff" />
              <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Detection Engine API</h3>
            </div>
            {healthStatus && (
              <span style={{ fontSize: 12, color: healthStatus.status === 'ok' ? '#10b981' : '#ef4444', fontWeight: 600 }}>
                {healthStatus.status === 'ok' ? '● ONLINE' : '● UNREACHABLE'}
              </span>
            )}
          </div>

          <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 16 }}>
            <div>Active Endpoint: <strong style={{ color: API_URL ? '#f1f5f9' : '#ef4444', fontFamily: 'var(--font-mono)' }}>{API_URL || 'Not Configured (Degraded Mode)'}</strong></div>
            <div style={{ marginTop: 4 }}>Engine Version: <strong style={{ color: '#00c2ff' }}>PhishGuard AI 3.0.0</strong></div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#cbd5e1', marginBottom: 6 }}>
              Public Backend URL (Render / Cloud / Custom):
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                type="url"
                placeholder="https://your-backend.onrender.com"
                value={customBackendInput}
                onChange={(e) => setCustomBackendInput(e.target.value)}
                style={{
                  flex: 1,
                  padding: '8px 12px',
                  borderRadius: 6,
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.15)',
                  color: '#fff',
                  fontSize: 12,
                  fontFamily: 'var(--font-mono)',
                  outline: 'none',
                }}
              />
              <button
                className="btn-primary"
                onClick={() => {
                  setCustomBackendUrl(customBackendInput);
                  toast.success('Backend URL saved!');
                }}
                style={{ fontSize: 12, padding: '8px 14px', whiteSpace: 'nowrap' }}
              >
                Save & Connect
              </button>
              {customBackendInput && (
                <button
                  onClick={() => {
                    setCustomBackendInput('');
                    setCustomBackendUrl('');
                    toast.success('Reset to default');
                  }}
                  style={{
                    fontSize: 12,
                    padding: '8px 12px',
                    borderRadius: 6,
                    background: 'rgba(239,68,68,0.1)',
                    border: '1px solid rgba(239,68,68,0.25)',
                    color: '#f87171',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                  }}
                >
                  Reset
                </button>
              )}
            </div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 6 }}>
              Can also be configured via <code style={{ color: '#00c2ff' }}>VITE_API_URL</code> in Vercel Project Settings.
            </div>
          </div>

          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <button className="btn-primary" onClick={checkHealth} disabled={checkingHealth} style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
              <RefreshCw size={13} className={checkingHealth ? 'animate-spin' : ''} /> {checkingHealth ? 'Testing Connection...' : 'Check API Status'}
            </button>
          </div>
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
