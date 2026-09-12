import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Link2, Globe, Mail, Image, Shield, Clock, FileText, Settings, X, FolderOpen, ArrowRight } from 'lucide-react';
import { scansApi } from '../services/api.js';

const STATIC_COMMANDS = [
  { label: 'Scan URL', icon: Link2, path: '/scanner/url', category: 'Scanners' },
  { label: 'Scan Website', icon: Globe, path: '/scanner/website', category: 'Scanners' },
  { label: 'Analyze Email', icon: Mail, path: '/scanner/email', category: 'Scanners' },
  { label: 'Analyze Screenshot', icon: Image, path: '/scanner/screenshot', category: 'Scanners' },
  { label: 'Open Threat Intelligence', icon: Shield, path: '/threat-intel', category: 'Enrichment' },
  { label: 'View Scan History Archive', icon: Clock, path: '/history', category: 'Cases' },
  { label: 'Open Security Reports', icon: FileText, path: '/reports', category: 'Reports' },
  { label: 'System Configuration', icon: Settings, path: '/settings', category: 'Admin' },
];

export default function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const [recentScans, setRecentScans] = useState([]);
  const navigate = useNavigate();
  const inputRef = useRef(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
      scansApi.list({ limit: 6 }).then(res => setRecentScans(res.data)).catch(() => {});
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const filteredCommands = STATIC_COMMANDS.filter(c => c.label.toLowerCase().includes(query.toLowerCase()));
  const matchingScans = recentScans.filter(s => s.target.toLowerCase().includes(query.toLowerCase()) || String(s.id).includes(query));

  const combined = [
    ...filteredCommands.map(c => ({ ...c, kind: 'cmd' })),
    ...matchingScans.map(s => ({
      label: `Case #${s.id}: ${s.target.slice(0, 45)}`,
      icon: FolderOpen,
      path: `/investigation/${s.id}`,
      category: `Case Archive (${s.verdict})`,
      kind: 'scan',
    })),
  ];

  const go = (path) => {
    navigate(path);
    onClose();
  };

  const handleKey = (e) => {
    if (e.key === 'Escape') onClose();
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIdx(i => Math.min(i + 1, combined.length - 1));
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIdx(i => Math.max(i - 1, 0));
    }
    if (e.key === 'Enter' && combined[activeIdx]) {
      go(combined[activeIdx].path);
    }
  };

  if (!open) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: '15vh', background: 'rgba(2,6,23,0.85)', backdropFilter: 'blur(8px)' }} onClick={onClose}>
      <div className="glass-card fade-in" style={{ width: '100%', maxWidth: 580, borderRadius: 16, overflow: 'hidden', boxShadow: '0 24px 64px rgba(0,0,0,0.7)' }} onClick={e => e.stopPropagation()}>
        {/* Search Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 18px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <Search size={16} color="#00c2ff" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setActiveIdx(0); }}
            onKeyDown={handleKey}
            placeholder="Search commands, cases, URLs, IOCs (e.g. 'paypal', 'Case #1')..."
            style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: '#f1f5f9', fontSize: 14, fontFamily: 'var(--font-sans)' }}
          />
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', padding: 4 }}>
            <X size={14} />
          </button>
        </div>

        {/* Results List */}
        <div style={{ maxHeight: 380, overflowY: 'auto', padding: '8px' }}>
          {combined.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: '#475569', fontSize: 13 }}>
              No commands or cases match '{query}'.
            </div>
          ) : combined.map((item, i) => {
            const Icon = item.icon;
            const isSelected = i === activeIdx;
            return (
              <button
                key={item.path + i}
                onClick={() => go(item.path)}
                onMouseEnter={() => setActiveIdx(i)}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 12,
                  padding: '10px 12px', borderRadius: 10, border: 'none',
                  background: isSelected ? 'rgba(0,194,255,0.1)' : 'transparent',
                  cursor: 'pointer', textAlign: 'left', transition: 'background 0.1s',
                }}
              >
                <div style={{ width: 30, height: 30, borderRadius: 8, background: 'rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Icon size={15} color={isSelected ? '#00c2ff' : '#64748b'} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 500, color: isSelected ? '#f1f5f9' : '#cbd5e1' }}>{item.label}</div>
                  <div style={{ fontSize: 10, color: '#64748b' }}>{item.category}</div>
                </div>
                {isSelected && <ArrowRight size={13} color="#00c2ff" />}
              </button>
            );
          })}
        </div>

        {/* Keyboard Shortcuts Footer */}
        <div style={{ padding: '10px 18px', borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', gap: 16 }}>
          {[['↑↓', 'Navigate'], ['↵', 'Select'], ['Esc', 'Dismiss']].map(([key, label]) => (
            <span key={key} style={{ fontSize: 11, color: '#475569', display: 'flex', alignItems: 'center', gap: 4 }}>
              <kbd style={{ background: 'rgba(255,255,255,0.06)', borderRadius: 4, padding: '1px 5px', fontFamily: 'var(--font-mono)' }}>{key}</kbd> {label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
