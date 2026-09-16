import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ScanProgress from '../components/scanner/ScanProgress.jsx';
import ScanResultPanel from '../components/scanner/ScanResultPanel.jsx';
import { scansApi } from '../services/api.js';
import { Globe, AlertCircle, Shield, FileCode, FormInput, ExternalLink } from 'lucide-react';
import toast from 'react-hot-toast';

export default function WebsiteAnalyzerPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // Restore scan on browser refresh or when ?id= is in the URL
  useEffect(() => {
    const scanId = searchParams.get('id');
    if (scanId) {
      setScanning(true);
      scansApi.get(scanId)
        .then((res) => {
          setResult(res.data);
          if (res.data?.target) setUrl(res.data.target);
        })
        .catch((err) => {
          setError(`Could not restore scan #${scanId}: ${err.message}`);
        })
        .finally(() => setScanning(false));
    }
  }, [searchParams]);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      toast.error('Please enter a website URL to analyze');
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const response = await scansApi.scanWebsite(trimmed);
      setResult(response.data);
      if (response.data?.id) {
        setSearchParams({ id: String(response.data.id) }, { replace: true });
      }
      toast.success(`Website analyzed: ${response.data.verdict}`);
    } catch (err) {
      setError(err.message || 'Website analysis failed');
      toast.error(err.message || 'Analysis failed');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ width: '100%', maxWidth: '100%', overflowX: 'hidden' }}>
      <PageHeader
        title="Website Content Analyzer"
        subtitle="Live DOM parsing for credential inputs, external form action targets, hidden iframes & obfuscated JS"
      />

      <GlassCard style={{ padding: '20px 24px', marginBottom: 24, width: '100%', boxSizing: 'border-box' }}>
        <form onSubmit={handleScan}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: '1 1 240px', minWidth: 0, width: '100%' }}>
              <input
                type="text"
                className="cyber-input"
                placeholder="Enter website URL to fetch and parse (e.g. https://account-verification-portal.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={scanning}
                style={{ paddingLeft: 42, width: '100%', minHeight: 44, boxSizing: 'border-box' }}
              />
              <Globe size={18} color="#64748b" style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)' }} />
            </div>
            <button
              type="submit"
              className="btn-primary"
              disabled={scanning || !url.trim()}
              style={{ minHeight: 44, padding: '0 22px', fontSize: 13, flexShrink: 0, minWidth: 140 }}
            >
              {scanning ? 'Analyzing DOM...' : 'Analyze Website'}
            </button>
          </div>
        </form>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginTop: 16 }}>
          {[
            { icon: FormInput, title: 'Form Action Targets', desc: 'Flags external or cross-domain action handlers' },
            { icon: Shield, title: 'Credential Inputs', desc: 'Detects password and credit card input tags' },
            { icon: FileCode, title: 'Hidden iframes & JS', desc: 'Identifies eval(), unescape() and 0px frames' },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} style={{ padding: '10px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', display: 'flex', gap: 10, alignItems: 'center' }}>
              <Icon size={16} color="#00c2ff" />
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#f1f5f9' }}>{title}</div>
                <div style={{ fontSize: 10, color: '#64748b' }}>{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </GlassCard>

      <ScanProgress scanning={scanning} scanType="website" />

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

      {result && <ScanResultPanel scan={result} />}
    </div>
  );
}
