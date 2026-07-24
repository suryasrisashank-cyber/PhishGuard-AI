import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

export function VerdictPie({ data }){
  const COLORS = ['#00ffa3','#f59e0b','#ef4444'];
  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie dataKey="value" data={data} outerRadius={70} label>
          {data.map((entry, idx) => <Cell key={idx} fill={COLORS[idx % COLORS.length]} />)}
        </Pie>
        <Tooltip />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function ScansBar({ data }){
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data}>
        <XAxis dataKey="name" stroke="#98a0b3" />
        <YAxis stroke="#98a0b3" />
        <Tooltip />
        <Bar dataKey="value" fill="#00c2ff" />
      </BarChart>
    </ResponsiveContainer>
  )
}
