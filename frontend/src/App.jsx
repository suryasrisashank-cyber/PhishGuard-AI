import { useEffect, useState } from 'react';
import axios from 'axios';
import Header from './components/Header';
import StatsCard from './components/StatsCard';
import RiskGauge from './components/RiskGauge';
import { VerdictPie, ScansBar } from './components/Charts';
import ScansTable from './components/ScansTable';
import LoadingSpinner from './components/LoadingSpinner';

const API_URL = 'https://phishguard-ai-6ngm.onrender.com/api';

function ensureScheme(target){
  if(!target) return '';
  if(/^https?:\/\//i.test(target)) return target;
  return 'https://' + target;
}

function App(){
  const [stats, setStats] = useState({ total_scans: 0, safe: 0, suspicious: 0, malicious: 0 });
  const [scans, setScans] = useState([]);
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('url');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const fetchStats = async ()=>{
    try{
      const r = await axios.get(`${API_URL}/dashboard/stats`);
      setStats(r.data);
    }catch(e){ console.error(e) }
  }
  const fetchScans = async ()=>{
    try{ const r = await axios.get(`${API_URL}/scans`); setScans(r.data); }catch(e){ console.error(e) }
  }

  useEffect(()=>{ fetchStats(); fetchScans(); },[]);

  const runScan = async ()=>{
    setMessage('');
    const final = ensureScheme(target.trim());
    if(!final){ setMessage('Please enter a URL or domain.'); return }
    setLoading(true);
    try{
      const payload = { scan_type: scanType, target: final };
      const r = await axios.post(`${API_URL}/scans/${scanType}`, payload, { timeout: 20000 });
      setMessage('Scan completed');
      await fetchStats();
      await fetchScans();
    }catch(err){
      console.error(err);
      setMessage('Scan failed — check the target and try again.');
    }finally{ setLoading(false) }
  }

  const pieData = [
    { name: 'Safe', value: stats.safe || 0 },
    { name: 'Suspicious', value: stats.suspicious || 0 },
    { name: 'Malicious', value: stats.malicious || 0 },
  ];

  const barData = [
    { name:'Safe', value: stats.safe || 0 },
    { name:'Suspicious', value: stats.suspicious || 0 },
    { name:'Malicious', value: stats.malicious || 0 },
  ];

  const riskScore = scans.length ? Math.round((stats.malicious*80 + stats.suspicious*40) / Math.max(1, stats.total_scans)) : 5;

  return (
    <div className="min-h-screen" style={{background:'linear-gradient(180deg,#020617 0%, #030826 100%)',padding:'24px'}}>
      <div className="container">
        <Header onRefresh={()=>{ fetchStats(); fetchScans(); }} />

        <div className="grid lg:grid-cols-4 gap-4 mb-6">
          <StatsCard title="Total Scans" value={stats.total_scans} icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none"><path d="M12 2v4" stroke="#00c2ff" strokeWidth="1.6" strokeLinecap="round"/></svg>} />
          <StatsCard title="Safe URLs" value={stats.safe} icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="#00ffa3" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/></svg>} />
          <StatsCard title="Suspicious URLs" value={stats.suspicious} icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none"><path d="M12 8v4" stroke="#f59e0b" strokeWidth="1.6" strokeLinecap="round"/><path d="M12 16h.01" stroke="#f59e0b" strokeWidth="1.6" strokeLinecap="round"/></svg>} />
          <StatsCard title="Malicious URLs" value={stats.malicious} icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none"><path d="M12 9v4" stroke="#ef4444" strokeWidth="1.6" strokeLinecap="round"/><path d="M12 17h.01" stroke="#ef4444" strokeWidth="1.6" strokeLinecap="round"/></svg>} />
        </div>

        <div className="grid lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-2 glass-card p-6 rounded-lg">
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
              <h3 className="text-lg font-semibold">Quick Scan</h3>
              <div className="text-sm text-gray-400">Secure scanning</div>
            </div>
            <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
              <select className="btn-ghost" value={scanType} onChange={e=>setScanType(e.target.value)}>
                <option value="url">URL</option>
                <option value="website">Website</option>
              </select>
              <input className="flex-1 rounded-lg bg-transparent" placeholder="Enter URL or domain" value={target} onChange={e=>setTarget(e.target.value)} style={{padding:'10px 12px',border:'1px solid rgba(255,255,255,0.04)',borderRadius:8}} />
              <button className="btn-primary" onClick={runScan} disabled={loading}>{loading ? <span style={{display:'inline-flex',alignItems:'center',gap:8}}><LoadingSpinner size={18}/>Scanning</span> : 'Run Scan'}</button>
            </div>
            {message && <div className="mt-4 text-sm text-slate-300">{message}</div>}
          </div>

          <div className="glass-card p-6 rounded-lg">
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
              <h3 className="text-lg font-semibold">Risk Score</h3>
              <div className="text-sm text-gray-400">0 - 100</div>
            </div>
            <div style={{display:'flex',justifyContent:'center',alignItems:'center'}}>
              <RiskGauge value={riskScore} />
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 glass-card p-4 rounded-lg">
            <h4 className="text-sm text-gray-400 mb-2">Verdict Distribution</h4>
            <VerdictPie data={pieData} />
            <div className="mt-4"><ScansBar data={barData} /></div>
          </div>

          <div className="lg:col-span-2">
            <h4 className="text-lg font-semibold mb-3">Recent Scans</h4>
            <ScansTable scans={scans} />
          </div>
        </div>
      </div>
    </div>
  )
}

export default App;
