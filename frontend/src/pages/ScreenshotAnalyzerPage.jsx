import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import IndicatorList from '../components/scanner/IndicatorList.jsx';
import AnalystActions from '../components/scanner/AnalystActions.jsx';
import TechDetails from '../components/scanner/TechDetails.jsx';
import { screenshotsApi, scansApi } from '../services/api.js';
import { Image, Upload, AlertCircle, Info } from 'lucide-react';
import toast from 'react-hot-toast';

export default function ScreenshotAnalyzerPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // Restore screenshot scan on browser refresh
  useEffect(() => {
    const scanId = searchParams.get('id');
    if (scanId) {
      setScanning(true);
      scansApi.get(scanId)
        .then((res) => {
          setResult(res.data);
        })
        .catch((err) => {
          setError(`Could not restore screenshot #${scanId}: ${err.message}`);
        })
        .finally(() => setScanning(false));
    }
  }, [searchParams]);

  const handleFileChange = (e) => {
    const selected = e.target.files?.[0];
    if (selected) {
      setFile(selected);
      setPreview(URL.createObjectURL(selected));
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      toast.error('Please upload an image screenshot');
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const response = await screenshotsApi.upload(file);
      setResult(response.data);
      if (response.data?.id) {
        setSearchParams({ id: String(response.data.id) }, { replace: true });
      }
      toast.success('Heuristic image analysis complete');
    } catch (err) {
      setError(err.message || 'Screenshot analysis failed');
      toast.error(err.message || 'Analysis failed');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Screenshot Analyzer"
        subtitle="Heuristic image metadata analysis & forensic property extraction"
      />

      {/* Mandatory honesty label */}
      <div style={{
        padding: '12px 16px',
        borderRadius: 10,
        background: 'rgba(0,194,255,0.08)',
        border: '1px solid rgba(0,194,255,0.2)',
        color: '#00c2ff',
        fontSize: 12,
        marginBottom: 20,
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10,
        lineHeight: 1.5,
      }}>
        <Info size={18} style={{ flexShrink: 0, marginTop: 1 }} />
        <div>
          <strong>Heuristic Image Analysis:</strong> This tool extracts image dimensions, format metadata, and pixel brightness statistics. It does <em>not</em> execute OCR or AI visual object classification. For live webpage inspection, please use the Website Analyzer.
        </div>
      </div>

      <GlassCard style={{ padding: 24, marginBottom: 24 }}>
        <div style={{ display: 'grid', gridTemplateColumns: preview ? '1fr 1fr' : '1fr', gap: 24, alignItems: 'center' }}>
          <div style={{
            border: '2px dashed rgba(255,255,255,0.1)',
            borderRadius: 12,
            padding: 32,
            textAlign: 'center',
            background: 'rgba(255,255,255,0.01)',
          }}>
            <Image size={36} color="#64748b" style={{ margin: '0 auto 12px' }} />
            <p style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 600 }}>Upload Website Screenshot</p>
            <p style={{ margin: '0 0 16px', fontSize: 12, color: '#64748b' }}>Supports PNG, JPG, JPEG, WEBP</p>
            <input type="file" accept="image/*" onChange={handleFileChange} style={{ fontSize: 12, color: '#94a3b8' }} />
          </div>

          {preview && (
            <div style={{ textAlign: 'center' }}>
              <div style={{ maxHeight: 220, overflow: 'hidden', borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', marginBottom: 12 }}>
                <img src={preview} alt="Upload preview" style={{ maxWidth: '100%', height: 'auto', display: 'block' }} />
              </div>
              <button className="btn-primary" onClick={handleAnalyze} disabled={scanning} style={{ width: '100%' }}>
                {scanning ? 'Processing Image...' : 'Run Heuristic Image Analysis'}
              </button>
            </div>
          )}
        </div>
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

      {result && (
        <GlassCard style={{ padding: 24 }}>
          <h3 style={{ margin: '0 0 8px', fontSize: 16, fontWeight: 700, color: '#f1f5f9' }}>{result.analysis_type}</h3>
          <p style={{ margin: '0 0 16px', fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>{result.summary}</p>

          <div style={{ marginBottom: 20 }}>
            <h4 style={{ fontSize: 12, color: '#64748b', textTransform: 'uppercase', marginBottom: 10 }}>Forensic Indicators</h4>
            <IndicatorList indicators={result.indicators} showPassed={true} />
          </div>

          <div style={{ marginBottom: 20 }}>
            <h4 style={{ fontSize: 12, color: '#64748b', textTransform: 'uppercase', marginBottom: 10 }}>Recommended Actions</h4>
            <AnalystActions actions={result.analyst_actions} />
          </div>

          <TechDetails scan={result} />
        </GlassCard>
      )}
    </div>
  );
}
