import React, { useState } from 'react';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import { threatsApi } from '../services/api.js';
import { Shield, Search, Globe, Server, AlertCircle } from 'lucide-react';
import toast from 'react-hot-toast';

export default function ThreatIntelPage() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const handleLookup = async (e) => {
    if (e) e.preventDefault();
    const trimmed = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!trimmed) {
      toast.error('Enter a domain or host to look up');
      return;
    }
    setLoading(true);
    setError(null);
    setData(null);

    try {
      const res = await threatsApi.lookup(trimmed);
      setData(res.data);
      toast.success(`Lookup completed for ${trimmed}`);
    } catch (err) {
      setError(err.message || 'Threat intelligence lookup failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Threat Intelligence Enrichment"
        subtitle="Passive DNS discovery, MX routing, authoritative WHOIS lookup & threat feed status"
      />

      <GlassCard style={{ padding: 24, marginBottom: 24 }}>
        <form onSubmit={handleLookup}>
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ position: 'relative', flex: 1 }}>
              <input
                type="text"
                className="cyber-input"
                placeholder="Domain or Hostname (e.g. suspicious-bank-alert.xyz)"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={loading}
                style={{ paddingLeft: 42 }}
              />
              <Search size={18} color="#64748b" style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)' }} />
            </div>
            <button type="submit" className="btn-primary" disabled={loading || !domain.trim()}>
              {loading ? 'Querying...' : 'Enrich Domain'}
            </button>
          </div>
        </form>
      </GlassCard>

      {error && (
        <div style={{
          padding: 16, borderRadius: 10, background: 'rgba(239,68,68,0.1)',
          border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444', marginBottom: 20,
          display: 'flex', alignItems: 'center', gap: 10, fontSize: 13,
        }}>
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* DNS Records */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            <GlassCard style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <Server size={18} color="#00c2ff" />
                <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>A Records (IP Addresses)</h3>
              </div>
              {data.ips && data.ips.length > 0 ? (
                <ul style={{ margin: 0, paddingLeft: 18, color: '#94a3b8', fontSize: 13, fontFamily: 'var(--font-mono)' }}>
                  {data.ips.map((ip, i) => <li key={i} style={{ marginBottom: 4 }}>{ip}</li>)}
                </ul>
              ) : (
                <p style={{ margin: 0, fontSize: 13, color: '#64748b' }}>No A records found</p>
              )}
            </GlassCard>

            <GlassCard style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <Globe size={18} color="#7c3aed" />
                <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: '#f1f5f9' }}>MX Mail Exchanges</h3>
              </div>
              {data.mx_records && data.mx_records.length > 0 ? (
                <ul style={{ margin: 0, paddingLeft: 18, color: '#94a3b8', fontSize: 13, fontFamily: 'var(--font-mono)' }}>
                  {data.mx_records.map((mx, i) => <li key={i} style={{ marginBottom: 4 }}>{mx}</li>)}
                </ul>
              ) : (
                <p style={{ margin: 0, fontSize: 13, color: '#64748b' }}>No MX records located</p>
              )}
            </GlassCard>
          </div>

          {/* WHOIS Data */}
          <GlassCard style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 16px', fontSize: 15, fontWeight: 700, color: '#f1f5f9' }}>WHOIS Registration Data</h3>
            {data.whois && !data.whois.error ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
                {[
                  { label: 'Registrar', val: data.whois.registrar },
                  { label: 'Created On', val: data.whois.creation_date },
                  { label: 'Expires On', val: data.whois.expiration_date },
                  { label: 'Country', val: data.whois.country },
                  { label: 'Organization', val: data.whois.org },
                ].map(({ label, val }) => (
                  <div key={label} style={{ padding: 12, borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', marginBottom: 4 }}>{label}</div>
                    <div style={{ fontSize: 13, color: '#f1f5f9', wordBreak: 'break-all' }}>{String(val || 'N/A')}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: '#64748b', fontSize: 13, margin: 0 }}>WHOIS data not available or request blocked.</p>
            )}
          </GlassCard>

          {/* External Threat Feeds Status */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <GlassCard style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Shield size={16} color="#64748b" />
                <h4 style={{ margin: 0, fontSize: 14, color: '#f1f5f9' }}>VirusTotal Threat Engine</h4>
              </div>
              {data.virustotal?.status === 'configured' ? (
                <div style={{ fontSize: 13, color: '#94a3b8' }}>
                  Malicious: {data.virustotal.malicious} | Suspicious: {data.virustotal.suspicious} | Harmless: {data.virustotal.harmless}
                </div>
              ) : (
                <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.5 }}>
                  <span style={{ color: '#f59e0b', fontWeight: 600 }}>VirusTotal — Not configured</span>
                  <br />Set VIRUS_TOTAL_API_KEY in backend .env to enable multi-engine antivirus reputation scans.
                </div>
              )}
            </GlassCard>

            <GlassCard style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Shield size={16} color="#64748b" />
                <h4 style={{ margin: 0, fontSize: 14, color: '#f1f5f9' }}>AbuseIPDB Threat Feed</h4>
              </div>
              <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.5 }}>
                <span style={{ color: '#f59e0b', fontWeight: 600 }}>AbuseIPDB — Not configured</span>
                <br />Configure ABUSEIPDB_API_KEY to verify IP attack history and malicious reporting ratios.
              </div>
            </GlassCard>
          </div>
        </div>
      )}
    </div>
  );
}
