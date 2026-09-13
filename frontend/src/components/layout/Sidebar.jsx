import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Link2,
  Globe,
  Mail,
  FileCode,
  Network,
  Image,
  Shield,
  Activity,
  Database,
  Layers,
  ShieldAlert,
  Terminal,
  Grid,
  FileText,
  Clock,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

const navSections = [
  {
    title: 'OVERVIEW',
    items: [
      { path: '/', icon: LayoutDashboard, label: 'SOC Dashboard' },
    ],
  },
  {
    title: 'DETECTION ENGINES',
    items: [
      { path: '/scanner/url', icon: Link2, label: 'URL Scanner' },
      { path: '/scanner/website', icon: Globe, label: 'Website Forensics' },
      { path: '/scanner/email', icon: Mail, label: 'Email Analyzer' },
      { path: '/scanner/file', icon: FileCode, label: 'File Static Analysis' },
      { path: '/scanner/pcap', icon: Network, label: 'PCAP Network Analysis' },
      { path: '/scanner/screenshot', icon: Image, label: 'Screenshot Analyzer' },
    ],
  },
  {
    title: 'THREAT INTELLIGENCE',
    items: [
      { path: '/threat-intel', icon: Shield, label: 'Threat Intel Feeds' },
      { path: '/system/integrations', icon: Activity, label: 'Integration Diagnostics' },
      { path: '/iocs', icon: Database, label: 'IOC Explorer' },
      { path: '/campaigns', icon: Layers, label: 'Threat Campaigns' },
    ],
  },
  {
    title: 'SOC OPERATIONS',
    items: [
      { path: '/alerts', icon: ShieldAlert, label: 'Alert Triage Queue' },
      { path: '/mitre', icon: Grid, label: 'MITRE ATT&CK Matrix' },
      { path: '/splunk', icon: Terminal, label: 'Splunk SIEM' },
    ],
  },
  {
    title: 'GOVERNANCE',
    items: [
      { path: '/reports', icon: FileText, label: 'Forensic Reports' },
      { path: '/history', icon: Clock, label: 'Scan History' },
      { path: '/settings', icon: Settings, label: 'Platform Settings' },
    ],
  },
];

export default function Sidebar({ expanded, onToggle, mobileOpen, onMobileClose }) {
  const location = useLocation();

  const sidebarClass = [
    'sidebar glass-card',
    expanded ? 'sidebar-expanded' : 'sidebar-collapsed',
    mobileOpen ? 'mobile-open' : '',
  ].join(' ');

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm md:hidden"
          onClick={onMobileClose}
          aria-label="Close menu"
        />
      )}

      <aside className={sidebarClass} style={{ borderRight: '1px solid rgba(255,255,255,0.06)' }}>
        {/* Header */}
        <div style={{ padding: '20px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 10, minHeight: 72 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg,#00c2ff,#2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Shield size={18} color="#fff" />
          </div>
          {(expanded || mobileOpen) && (
            <div style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#00c2ff', lineHeight: 1.2 }}>PhishGuard AI</div>
              <div style={{ fontSize: 10, color: '#64748b', fontWeight: 500 }}>3.0 — Real-World SOC</div>
            </div>
          )}
        </div>

        {/* Navigation Sections */}
        <nav style={{ flex: 1, padding: '12px 8px', overflowY: 'auto' }}>
          {navSections.map((section) => (
            <div key={section.title} style={{ marginBottom: 14 }}>
              {(expanded || mobileOpen) && (
                <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: '#64748b', padding: '4px 10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {section.title}
                </div>
              )}
              {section.items.map(({ path, icon: Icon, label }) => {
                const active = path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);
                return (
                  <NavLink
                    key={path}
                    to={path}
                    onClick={onMobileClose}
                    title={!expanded ? label : undefined}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '8px 10px',
                      borderRadius: 8,
                      marginBottom: 2,
                      textDecoration: 'none',
                      background: active ? 'rgba(0,194,255,0.1)' : 'transparent',
                      border: active ? '1px solid rgba(0,194,255,0.2)' : '1px solid transparent',
                      color: active ? '#00c2ff' : '#94a3b8',
                      transition: 'all 0.15s ease',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                    }}
                  >
                    <Icon size={16} style={{ flexShrink: 0 }} />
                    {(expanded || mobileOpen) && (
                      <span style={{ fontSize: 12, fontWeight: 500 }}>{label}</span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div style={{ padding: '12px 8px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 10px', marginBottom: 4 }} title={!expanded ? 'SOC Defensive Mode' : undefined}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', flexShrink: 0 }} />
            {(expanded || mobileOpen) && <span style={{ fontSize: 11, color: '#64748b', fontFamily: 'var(--font-mono)' }}>SOC Defensive Mode</span>}
          </div>

          <button
            className="btn-ghost"
            onClick={onToggle}
            style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: expanded ? 'flex-end' : 'center', gap: 6, padding: '7px 10px', fontSize: 12 }}
            aria-label={expanded ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {expanded ? <><ChevronLeft size={14} /><span>Collapse</span></> : <ChevronRight size={14} />}
          </button>
        </div>
      </aside>
    </>
  );
}
