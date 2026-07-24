import React, { useMemo, useState } from 'react';

function Badge({ verdict }){
  if(verdict === 'Malicious') return <span className="badge-malicious">Malicious</span>
  if(verdict === 'Suspicious') return <span className="badge-suspicious">Suspicious</span>
  return <span className="badge-safe">Safe</span>
}

export default function ScansTable({ scans }){
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState('all');
  const [sortKey, setSortKey] = useState('id');
  const [page, setPage] = useState(1);
  const per = 8;

  const filtered = useMemo(()=>{
    let arr = scans || [];
    if(q) arr = arr.filter(s => (s.target||'').toLowerCase().includes(q.toLowerCase()));
    if(filter !== 'all') arr = arr.filter(s => s.verdict === filter);
    arr = [...arr].sort((a,b)=> b.id - a.id);
    return arr;
  },[scans,q,filter,sortKey]);

  const pages = Math.max(1, Math.ceil(filtered.length / per));
  const pageRows = filtered.slice((page-1)*per, page*per);

  return (
    <div className="glass-card p-4 rounded-lg">
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',gap:12,marginBottom:12}}>
        <div style={{display:'flex',gap:8}}>
          <input placeholder="Search target" className="btn-ghost" value={q} onChange={e=>{setQ(e.target.value); setPage(1)}} />
          <select value={filter} onChange={e=>{setFilter(e.target.value); setPage(1)}} className="btn-ghost">
            <option value="all">All</option>
            <option value="Safe">Safe</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Malicious">Malicious</option>
          </select>
        </div>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          <div className="text-sm text-gray-400">Rows per page: {per}</div>
        </div>
      </div>

      <div className="table-scroll">
        <table className="table min-w-full">
          <thead>
            <tr>
              <th>Type</th>
              <th>Target</th>
              <th>Verdict</th>
              <th>Risk</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.map(s=> (
              <tr key={s.id} className="border-t border-slate-800">
                <td className="py-3">{s.scan_type}</td>
                <td className="py-3">{s.target}</td>
                <td className="py-3"><Badge verdict={s.verdict} /></td>
                <td className="py-3">{s.risk_score}</td>
                <td className="py-3">{s.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginTop:12}}>
        <div className="text-sm text-gray-400">Showing {pageRows.length} of {filtered.length}</div>
        <div style={{display:'flex',gap:8}}>
          <button className="btn-ghost" onClick={()=>setPage(p=>Math.max(1,p-1))}>Prev</button>
          <div className="text-sm">{page}/{pages}</div>
          <button className="btn-ghost" onClick={()=>setPage(p=>Math.min(pages,p+1))}>Next</button>
        </div>
      </div>
    </div>
  )
}
