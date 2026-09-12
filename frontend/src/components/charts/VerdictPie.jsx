import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = { Safe: '#10b981', Suspicious: '#f59e0b', Malicious: '#ef4444' };

export default function VerdictPie({ data }) {
  const hasData = data && data.some(d => d.value > 0);
  if (!hasData) return <div style={{ textAlign: 'center', padding: 32, color: '#475569', fontSize: 13 }}>No scan data yet</div>;

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={data.filter(d => d.value > 0)}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          outerRadius={70}
          innerRadius={40}
          paddingAngle={4}
        >
          {data.filter(d => d.value > 0).map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || '#6b7280'} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: '#0a1628', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }}
          itemStyle={{ color: '#f1f5f9' }}
        />
        <Legend formatter={(v) => <span style={{ fontSize: 12, color: '#94a3b8' }}>{v}</span>} />
      </PieChart>
    </ResponsiveContainer>
  );
}
