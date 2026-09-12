import React, { useState } from 'react';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ScanProgress from '../components/scanner/ScanProgress.jsx';
import ScanResultPanel from '../components/scanner/ScanResultPanel.jsx';
import { scansApi } from '../services/api.js';
import { Mail, UploadCloud, FileText, AlertCircle, Shield, FileCheck, Key } from 'lucide-react';
import toast from 'react-hot-toast';

export default function EmailAnalyzerPage() {
  const [tab, setTab] = useState('text'); // 'text' | 'file'
  const [content, setContent] = useState('');
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScanText = async () => {
    if (!content.trim()) {
      toast.error('Please paste email headers and body content');
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const response = await scansApi.scanEmail(content.trim());
      setResult(response.data);
      toast.success(`Email analysis completed: ${response.data.verdict}`);
    } catch (err) {
      setError(err.message || 'Email scan failed');
      toast.error(err.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleScanFile = async () => {
    if (!file) {
      toast.error('Please choose a .eml or .txt file');
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const response = await scansApi.scanEmailFile(file);
      setResult(response.data);
      toast.success(`Email file analyzed: ${response.data.verdict}`);
    } catch (err) {
      setError(err.message || 'File upload failed');
      toast.error(err.message || 'Analysis failed');
    } finally {
      setScanning(false);
    }
  };

  const loadSampleEmail = () => {
    setContent(
`From: "Account Security Support" <security-alert@paypal-account-update.xyz>
Reply-To: security-escalation@hacker-infrastructure.net
To: target-analyst@enterprise-domain.com
Subject: URGENT: Your PayPal Account Has Been Temporarily Suspended
Date: Wed, 12 Sep 2026 09:14:22 +0000
Authentication-Results: spf=fail (sender IP 198.51.100.44) smtp.mailfrom=paypal-account-update.xyz; dkim=none; dmarc=fail

Dear Valued Customer,

We detected unusual sign-in activity on your account from an unrecognized device in Moscow, Russia.
For your safety, access to your funds has been locked immediately.

You must confirm your identity and verify your credentials within 24 hours to prevent permanent closure:
http://paypal-verification-portal.xyz/login/challenge?token=8943201

Failure to act now will lead to indefinite account suspension.

Sincerely,
Security Operations Department`
    );
  };

  return (
    <div>
      <PageHeader
        title="Email Threat Analyzer"
        subtitle="Social engineering & spoofing detector: inspects urgency keywords, sender mismatch & authentication headers"
      />

      <GlassCard style={{ padding: 24, marginBottom: 24 }}>
        {/* Sub-tabs */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className={tab === 'text' ? 'btn-primary' : 'btn-ghost'}
              onClick={() => setTab('text')}
              style={{ fontSize: 13 }}
            >
              <FileText size={14} style={{ display: 'inline', marginRight: 6 }} /> Forensic Message Viewer
            </button>
            <button
              className={tab === 'file' ? 'btn-primary' : 'btn-ghost'}
              onClick={() => setTab('file')}
              style={{ fontSize: 13 }}
            >
              <UploadCloud size={14} style={{ display: 'inline', marginRight: 6 }} /> Upload Raw .EML
            </button>
          </div>

          <button
            className="btn-ghost"
            onClick={loadSampleEmail}
            style={{ fontSize: 11, color: '#f59e0b', borderColor: 'rgba(245,158,11,0.3)' }}
          >
            Load Sample Phishing EML
          </button>
        </div>

        {tab === 'text' ? (
          <div>
            <textarea
              className="cyber-input"
              rows={9}
              placeholder="Paste raw email message with RFC-822 headers (From:, Reply-To:, Subject:, Authentication-Results:, Body...)"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              disabled={scanning}
              style={{ fontFamily: 'var(--font-mono)', fontSize: 12, marginBottom: 14 }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn-primary" onClick={handleScanText} disabled={scanning || !content.trim()}>
                {scanning ? 'Analyzing Email...' : 'Run Forensic Inspection'}
              </button>
            </div>
          </div>
        ) : (
          <div>
            <div style={{
              border: '2px dashed rgba(255,255,255,0.1)',
              borderRadius: 12,
              padding: 32,
              textAlign: 'center',
              marginBottom: 16,
              background: 'rgba(255,255,255,0.01)',
            }}>
              <Mail size={32} color="#64748b" style={{ margin: '0 auto 12px' }} />
              <p style={{ margin: '0 0 6px', fontSize: 14, fontWeight: 600 }}>Select .EML or .TXT file</p>
              <p style={{ margin: '0 0 16px', fontSize: 12, color: '#64748b' }}>Supports exported Outlook, Gmail, or Thunderbird messages</p>
              <input
                type="file"
                accept=".eml,.txt"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                style={{ color: '#94a3b8', fontSize: 13 }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn-primary" onClick={handleScanFile} disabled={scanning || !file}>
                {scanning ? 'Uploading & Analyzing...' : 'Upload & Run Forensics'}
              </button>
            </div>
          </div>
        )}
      </GlassCard>

      <ScanProgress scanning={scanning} scanType="email" />

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
