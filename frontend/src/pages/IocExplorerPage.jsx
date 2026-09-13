import React, { useState, useEffect } from 'react';
import { iocsApi } from '../services/api.js';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import SeverityBadge from '../components/ui/SeverityBadge.jsx';
import LoadingSkeleton from '../components/ui/LoadingSkeleton.jsx';
import ErrorState from '../components/ui/ErrorState.jsx';
import { Search, Download, Filter, Database, Link2, ExternalLink, RefreshCw, X, Plus } from 'lucide-react';

export default function IocExplorerPage() {
  const [iocs, setIocs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedCorrelation, setSelectedCorrelation] = useState(null);
  const [corrLoading, setCorrLoading] = useState(false);

  const fetchIocs = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await iocsApi.list({
        search: search || undefined,
        ioc_type: typeFilter || undefined,
        severity: severityFilter || undefined,
        limit: 50,
      });
      setIocs(res.data.iocs || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to load IOC repository.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIocs();
  }, [typeFilter, severityFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchIocs();
  };

  const handleCorrelate = async (value) => {
    setCorrLoading(true);
    try {
      const res = await iocsApi.correlate(value);
      setSelectedCorrelation(res.data);
    } catch (err) {
      alert(`Correlation error: ${err.message}`);
    } finally {
      setCorrLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="IOC Management & Threat Explorer"
        subtitle="Cataloged Indicators of Compromise (URLs, Domains, IPs, Hashes) with cross-scan correlation and SIEM export."
        action={
          <div className="flex items-center gap-2">
            <a
              href={iocsApi.getExportUrl()}
              download="phishguard_iocs.csv"
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/20 transition text-sm font-medium"
            >
              <Download size={14} />
              Export CSV
            </a>
          </div>
        }
      />

      {/* Filters Bar */}
      <GlassCard className="p-4">
        <form onSubmit={handleSearchSubmit} className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-1 min-w-[240px]">
            <Search size={16} className="text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IOC value, hash, or IP..."
              className="bg-transparent border-none text-sm text-white placeholder-slate-500 focus:outline-none w-full"
            />
          </div>

          <div className="flex items-center gap-3">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-900 border border-white/10 rounded-lg px-2.5 py-1.5 text-xs text-slate-300"
            >
              <option value="">All IOC Types</option>
              <option value="URL">URL</option>
              <option value="DOMAIN">DOMAIN</option>
              <option value="IPV4">IPv4</option>
              <option value="SHA256">SHA256</option>
              <option value="MD5">MD5</option>
              <option value="EMAIL">EMAIL</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-900 border border-white/10 rounded-lg px-2.5 py-1.5 text-xs text-slate-300"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFORMATIONAL">INFORMATIONAL</option>
            </select>

            <button
              type="submit"
              className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-xs text-white font-medium"
            >
              Search
            </button>
          </div>
        </form>
      </GlassCard>

      {loading && <LoadingSkeleton count={5} />}
      {error && <ErrorState message={error} onRetry={fetchIocs} />}

      {!loading && !error && (
        <div className="overflow-x-auto rounded-xl border border-white/5 bg-slate-900/30">
          <table className="w-full text-left text-xs">
            <thead className="bg-black/40 text-slate-400 font-mono uppercase text-[11px] border-b border-white/5">
              <tr>
                <th className="py-3 px-4">Indicator Value</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Reputation</th>
                <th className="py-3 px-4">Hits</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {iocs.length > 0 ? (
                iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-white/5 transition font-mono">
                    <td className="py-3 px-4 text-slate-200 font-semibold select-all break-all max-w-xs">
                      {ioc.value}
                    </td>
                    <td className="py-3 px-4 text-cyber-blue">{ioc.ioc_type}</td>
                    <td className="py-3 px-4"><SeverityBadge severity={ioc.severity} /></td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        ioc.reputation === 'MALICIOUS' ? 'bg-red-500/10 text-red-400' :
                        ioc.reputation === 'SUSPICIOUS' ? 'bg-amber-500/10 text-amber-400' :
                        'bg-emerald-500/10 text-emerald-400'
                      }`}>
                        {ioc.reputation}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{ioc.scan_count}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] font-sans">{ioc.source}</td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => handleCorrelate(ioc.value)}
                        className="px-2.5 py-1 rounded bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue text-xs font-medium"
                      >
                        Correlate
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 italic">
                    No Indicators of Compromise matching search criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Correlation Drawer Modal */}
      {selectedCorrelation && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-white/10 rounded-xl max-w-2xl w-full p-6 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Link2 size={18} className="text-cyber-blue" />
                Cross-Entity Correlation: {selectedCorrelation.ioc?.value}
              </h3>
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="p-1 rounded text-slate-400 hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono p-3 rounded bg-black/30 border border-white/5">
              <div>Type: <span className="text-cyber-blue">{selectedCorrelation.ioc?.ioc_type}</span></div>
              <div>Reputation: <span className="text-amber-400">{selectedCorrelation.ioc?.reputation}</span></div>
              <div>Correlated Scans: <span className="text-white font-bold">{selectedCorrelation.correlation?.total_correlated_scans}</span></div>
              <div>Correlated Cases: <span className="text-white font-bold">{selectedCorrelation.correlation?.total_correlated_cases}</span></div>
            </div>

            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 mb-2">Associated Detection Telemetry</h4>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {selectedCorrelation.correlation?.scans?.map((s) => (
                  <div key={s.id} className="p-2.5 rounded bg-black/20 text-xs flex justify-between items-center border border-white/5">
                    <div>
                      <span className="font-mono text-cyber-blue uppercase text-[10px] mr-2">[{s.scan_type}]</span>
                      <span className="text-slate-200">{s.target}</span>
                    </div>
                    <SeverityBadge severity={s.severity} />
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 mb-2">Associated SOC Cases</h4>
              <div className="space-y-2 max-h-36 overflow-y-auto">
                {selectedCorrelation.correlation?.cases?.length > 0 ? (
                  selectedCorrelation.correlation.cases.map((c) => (
                    <div key={c.id} className="p-2.5 rounded bg-black/20 text-xs flex justify-between items-center border border-white/5">
                      <div>
                        <span className="font-mono text-cyber-blue text-xs mr-2">{c.case_id}</span>
                        <span className="text-slate-200">{c.title}</span>
                      </div>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-white/10">{c.status}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 italic">No formal investigation cases linked yet.</p>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="btn-primary px-4 py-2 rounded-lg text-xs"
              >
                Close Correlation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
