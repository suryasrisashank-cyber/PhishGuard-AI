import React from 'react';
import Logo from '../assets/logo.svg';

export default function Header({ onRefresh }){
  return (
    <header className="glass-card rounded-lg p-4 header-row mb-6">
      <div style={{display:'flex',alignItems:'center',gap:12}}>
        <img src={Logo} alt="PhishGuard" style={{width:48,height:48}} />
        <div>
          <div className="neon-text text-lg font-bold">PhishGuard AI Pro</div>
          <div className="text-sm text-gray-400">Cybersecurity dashboard</div>
        </div>
      </div>

      <nav style={{display:'flex',gap:8,alignItems:'center'}}>
        <button className="btn-ghost" onClick={onRefresh}>Refresh</button>
        <div className="p-2 glass-card rounded-lg" style={{display:'flex',alignItems:'center',gap:8}}>
          <div style={{width:36,height:36,background:'#061028',borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center'}}>U</div>
          <div className="text-sm">Admin</div>
        </div>
      </nav>
    </header>
  )
}
