import React, { useState } from 'react';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import { healthApi } from '../services/api.js';
import { Settings, ShieldCheck, Database, HardDrive, Key, Check, RefreshCw, Server } from 'lucide-react';
import toast from 'react-hot-toast';
import { API_URL } from '../lib/constants.js';

export default function SettingsPage() {
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [healthStatus, setHealthStatus] = useState(null);

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
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Server size={18} color="#00c2ff" />
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Detection Engine API</h3>
          </div>

          <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 16 }}>
            <div>Active Endpoint: <strong style={{ color: '#f1f5f9', fontFamily: 'var(--font-mono)' }}>{API_URL}</strong></div>
            <div style={{ marginTop: 4 }}>Engine Version: <strong style={{ color: '#00c2ff' }}>PhishGuard AI 2.0.0</strong></div>
          </div>

          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <button className="btn-primary" onClick={checkHealth} disabled={checkingHealth} style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
              <RefreshCw size={13} /> {checkingHealth ? 'Testing...' : 'Check API Status'}
            </button>
            {healthStatus && (
              <span style={{ fontSize: 12, color: healthStatus.status === 'ok' ? '#10b981' : '#ef4444', fontWeight: 600 }}>
                {healthStatus.status === 'ok' ? 'HEALTHY' : 'UNREACHABLE'}
              </span>
            )}
          </div>
        </GlassCard>

        {/* Threat Intelligence Feed Status */}
        <GlassCard style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Key size={18} color="#7c3aed" />
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>Feed Integrations</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)' }}>
              <span>DNS / WHOIS Native Scanner</span>
              <span style={{ color: '#10b981', fontWeight: 600 }}>ACTIVE</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)' }}>
              <span>VirusTotal API v3</span>
              <span style={{ color: '#f59e0b', fontWeight: 600 }}>NOT CONFIGURED</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)' }}>
              <span>AbuseIPDB Threat Stream</span>
              <span style={{ color: '#f59e0b', fontWeight: 600 }}>NOT CONFIGURED</span>
            </div>
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
