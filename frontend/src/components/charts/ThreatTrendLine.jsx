import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

export default function ThreatTrendLine({ data = [] }) {
  if (!data || data.length === 0) {
    return <div style={{ textAlign: 'center', padding: 32, color: '#475569', fontSize: 13 }}>No trend data available</div>;
  }

  return (
    <ResponsiveContainer width="100%" height={160}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="tScans" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00c2ff" stopOpacity={0.3} />
            <stop offset="100%" stopColor="#00c2ff" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="tThreats" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
        <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background: '#0a1628', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }}
          itemStyle={{ color: '#f1f5f9' }}
        />
        <Area type="monotone" dataKey="scans" stroke="#00c2ff" strokeWidth={2} fill="url(#tScans)" name="Total Scans" />
        <Area type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} fill="url(#tThreats)" name="Threats" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
