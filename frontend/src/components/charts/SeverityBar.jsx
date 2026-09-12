import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { SEVERITY_CONFIG } from '../../lib/constants.js';

export default function SeverityBar({ data }) {
  if (!data) return null;
  const chartData = Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => ({
    name: cfg.label,
    value: data[sev] || 0,
    color: cfg.color,
  })).filter(d => d.value > 0);

  if (chartData.length === 0) return <div style={{ textAlign: 'center', padding: 24, color: '#475569', fontSize: 13 }}>No severity data</div>;

  return (
    <ResponsiveContainer width="100%" height={120}>
      <BarChart data={chartData} barCategoryGap="30%">
        <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background: '#0a1628', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }}
          itemStyle={{ color: '#f1f5f9' }}
        />
        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
          {chartData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
