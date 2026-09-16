import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ScanProgress from '../components/scanner/ScanProgress.jsx';
import ScanResultPanel from '../components/scanner/ScanResultPanel.jsx';
import { scansApi } from '../services/api.js';
import { Link2, Sparkles, AlertCircle } from 'lucide-react';
import toast from 'react-hot-toast';

export default function UrlScannerPage() {
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

  const handleScan = async (targetUrl = url) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      toast.error('Please enter a target URL to scan');
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const response = await scansApi.scanUrl(trimmed);
      setResult(response.data);
      if (response.data?.id) {
        setSearchParams({ id: String(response.data.id) }, { replace: true });
      }
      toast.success(`Analysis completed: ${response.data.verdict}`);
    } catch (err) {
      setError(err.message || 'Scan failed');
      toast.error(err.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const loadSample = (sampleUrl) => {
    setUrl(sampleUrl);
    handleScan(sampleUrl);
  };

  return (
    <div style={{ width: '100%', maxWidth: '100%', overflowX: 'hidden' }}>
      <PageHeader
        title="URL Threat Scanner"
        subtitle="Heuristic deep-inspection for phishing patterns, typosquatting, IDN homoglyphs & redirect chains"
      />

      {/* Input Box */}
      <GlassCard style={{ padding: '20px 24px', marginBottom: 24, width: '100%', boxSizing: 'border-box' }}>
        <form onSubmit={(e) => { e.preventDefault(); handleScan(); }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: '1 1 240px', minWidth: 0, width: '100%' }}>
              <input
                type="text"
                className="cyber-input"
                placeholder="Enter URL to inspect (e.g. https://login-verification-service.com/account/update)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={scanning}
                style={{ paddingLeft: 42, width: '100%', minHeight: 44, boxSizing: 'border-box' }}
              />
              <Link2 size={18} color="#64748b" style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)' }} />
            </div>
            <button
              type="submit"
              className="btn-primary"
              disabled={scanning || !url.trim()}
              style={{ minHeight: 44, padding: '0 22px', fontSize: 13, flexShrink: 0, minWidth: 120 }}
            >
              {scanning ? 'Scanning...' : 'Analyze URL'}
            </button>
          </div>
        </form>

        {/* Quick Test Samples */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: '#64748b' }}>Quick Test Presets:</span>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => loadSample('https://google.com')}
            style={{ fontSize: 11, padding: '4px 8px' }}
          >
            Safe: google.com
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => loadSample('http://paypal-verification.security-update.xyz/login?ref=account')}
            style={{ fontSize: 11, padding: '4px 8px', color: '#f59e0b' }}
          >
            Suspicious: paypal-verification.xyz
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => loadSample('http://192.168.1.1:8080/secure-banking/login/verify?user=admin')}
            style={{ fontSize: 11, padding: '4px 8px', color: '#ef4444' }}
          >
            Malicious IP: 192.168.1.1:8080
          </button>
        </div>
      </GlassCard>

      {/* Progress */}
      <ScanProgress scanning={scanning} scanType="url" />

      {/* Error */}
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

      {/* Result Panel */}
      {result && <ScanResultPanel scan={result} />}
    </div>
  );
}
