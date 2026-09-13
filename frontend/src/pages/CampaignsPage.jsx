import React, { useState, useEffect } from 'react';
import { campaignsApi } from '../services/api.js';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import ThreatBadge from '../components/ui/ThreatBadge.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { Target, Shield, Layers, RefreshCw } from 'lucide-react';

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchCampaigns = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await campaignsApi.list();
      setCampaigns(res.data.campaigns || []);
    } catch (err) {
      setError(err.message || 'Failed to load threat campaign clusters.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCampaigns();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Campaigns & Infrastructure Correlation"
        subtitle="Correlated attack infrastructure grouped by targeted brand, registration clusters, and observed multi-stage payloads."
        action={
          <button
            onClick={fetchCampaigns}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/20 transition text-sm font-medium"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh Campaigns
          </button>
        }
      />

      {loading && <LoadingSkeleton count={3} />}
      {error && <ErrorState message={error} onRetry={fetchCampaigns} />}

      {!loading && !error && (
        <div className="space-y-4">
          {campaigns.length > 0 ? (
            campaigns.map((camp) => (
              <GlassCard key={camp.campaign_id} className="p-6 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 pb-3">
                  <div>
                    <span className="text-[11px] font-mono text-cyber-blue">{camp.campaign_id}</span>
                    <h3 className="text-base font-semibold text-white">{camp.name}</h3>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-slate-400">
                      Average Risk: <strong className="text-white">{camp.average_risk}/100</strong>
                    </span>
                    <ThreatBadge verdict={camp.verdict} />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div>
                    <h4 className="font-mono text-slate-400 uppercase text-[11px] mb-2 flex items-center gap-1.5">
                      <Target size={14} className="text-cyber-blue" />
                      Associated Targets & Indicators ({camp.target_count})
                    </h4>
                    <div className="space-y-1.5 max-h-36 overflow-y-auto">
                      {camp.targets?.map((t, idx) => (
                        <div key={idx} className="p-1.5 rounded bg-black/20 font-mono text-slate-300 break-all select-all">
                          {t}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-mono text-slate-400 uppercase text-[11px] mb-2 flex items-center gap-1.5">
                      <Layers size={14} className="text-cyber-blue" />
                      Attack Modalities Observed
                    </h4>
                    <div className="flex flex-wrap gap-2 mb-3">
                      {camp.modalities?.map((m) => (
                        <span key={m} className="px-2.5 py-1 rounded-full bg-white/10 font-mono uppercase text-[11px] text-cyber-blue">
                          {m}
                        </span>
                      ))}
                    </div>

                    <div className="p-3 rounded-lg bg-black/20 text-slate-400 space-y-1">
                      <p>Severities Breakdown:</p>
                      <div className="flex gap-3 font-mono text-[11px]">
                        {Object.entries(camp.severity_breakdown || {}).map(([sev, cnt]) => (
                          <span key={sev} className="text-slate-200">{sev}: {cnt}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </GlassCard>
            ))
          ) : (
            <GlassCard className="p-10 text-center text-slate-500 italic">
              No active multi-indicator threat campaigns correlated yet.
            </GlassCard>
          )}
        </div>
      )}
    </div>
  );
}
