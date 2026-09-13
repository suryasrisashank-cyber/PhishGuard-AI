import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import { threatsApi } from '../services/api.js';
import { Shield, Search, Globe, Server, AlertCircle, Activity, ExternalLink, Clock } from 'lucide-react';
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
    <div className="space-y-6">
      <PageHeader
        title="Multi-Provider Threat Intelligence"
        subtitle="Live reputation, DNS mapping, WHOIS/RDAP lifecycle, and malware feed correlation across VirusTotal, AlienVault OTX, URLhaus, and AbuseIPDB."
        action={
          <Link
            to="/system/integrations"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/20 transition text-sm font-medium"
          >
            <Activity size={14} />
            Integration Diagnostics
          </Link>
        }
      />

      <GlassCard className="p-6">
        <form onSubmit={handleLookup}>
          <div className="flex gap-3">
            <div className="relative flex-1">
              <input
                type="text"
                className="w-full bg-slate-950 border border-white/10 rounded-lg px-4 py-2.5 pl-10 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyber-blue/50"
                placeholder="Domain, IP, or Hostname (e.g. suspicious-update.xyz)"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={loading}
              />
              <Search size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            </div>
            <button
              type="submit"
              className="btn-primary px-5 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-50"
              disabled={loading || !domain.trim()}
            >
              {loading ? 'Querying Feeds...' : 'Enrich Indicator'}
            </button>
          </div>
        </form>
      </GlassCard>

      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {data && (
        <div className="space-y-6">
          {/* Consensus Overview Card */}
          <GlassCard className="p-5 flex flex-wrap items-center justify-between gap-4">
            <div>
              <span className="text-[11px] font-mono text-slate-400 uppercase">INDICATOR</span>
              <h2 className="text-lg font-bold text-white font-mono mt-0.5">{data.indicator}</h2>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right text-xs font-mono">
                <span className="text-slate-400 block text-[10px]">CONSENSUS</span>
                <span className="font-bold text-white">{data.consensus_verdict}</span>
              </div>
              <ThreatBadge verdict={data.consensus_verdict === 'MALICIOUS' ? 'Malicious' : (data.consensus_verdict === 'SUSPICIOUS' ? 'Suspicious' : 'Safe')} />
            </div>
          </GlassCard>

          {/* Provider Telemetry Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {data.sources?.map((source, idx) => (
              <GlassCard key={idx} className="p-5 flex flex-col justify-between space-y-3">
                <div>
                  <div className="flex items-start justify-between gap-2 border-b border-white/5 pb-2">
                    <span className="text-sm font-semibold text-white">{source.provider}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                      source.provider_verdict === 'MALICIOUS' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                      source.provider_verdict === 'SUSPICIOUS' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
                      source.provider_verdict === 'BENIGN' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                      source.provider_verdict === 'NOT CONFIGURED' ? 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/30' :
                      'bg-slate-500/10 text-slate-400 border border-slate-500/30'
                    }`}>
                      {source.provider_verdict}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                    {source.normalized_interpretation}
                  </p>

                  {source.raw_reputation && (
                    <div className="mt-3 p-2 rounded bg-black/30 border border-white/5 text-[11px] font-mono text-slate-400 space-y-0.5">
                      {Object.entries(source.raw_reputation).map(([k, v]) => (
                        <div key={k} className="flex justify-between">
                          <span className="text-slate-500">{k}:</span>
                          <span className="text-slate-200 truncate max-w-[200px]">{JSON.stringify(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                  <span className="flex items-center gap-1">
                    <Clock size={10} />
                    {source.retrieval_timestamp ? new Date(source.retrieval_timestamp).toLocaleTimeString() : 'N/A'}
                  </span>
                  <span>Confidence: {source.confidence ? `${source.confidence}%` : 'N/A'}</span>
                </div>
              </GlassCard>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
