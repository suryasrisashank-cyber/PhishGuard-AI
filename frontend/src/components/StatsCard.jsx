import React from 'react';

export default function StatsCard({ title, value, icon, className }){
  return (
    <div className={`glass-card p-4 rounded-lg fade-in ${className || ''}`}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
        <div>
          <div className="text-sm text-gray-400">{title}</div>
          <div className="text-2xl font-bold mt-2">{value}</div>
        </div>
        <div style={{fontSize:28,opacity:0.9}}>{icon}</div>
      </div>
    </div>
  )
}
