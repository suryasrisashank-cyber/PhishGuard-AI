import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Link2, Globe, Mail, Image, Shield,
  Clock, FileText, Settings, ChevronLeft, ChevronRight,
  Activity, Menu, X
} from 'lucide-react';

const navItems = [
  { path: '/',                icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/scanner/url',     icon: Link2,           label: 'URL Scanner' },
  { path: '/scanner/website', icon: Globe,           label: 'Website Analyzer' },
  { path: '/scanner/email',   icon: Mail,            label: 'Email Analyzer' },
  { path: '/scanner/screenshot', icon: Image,        label: 'Screenshot Analyzer' },
  { path: '/threat-intel',    icon: Shield,          label: 'Threat Intelligence' },
  { path: '/history',         icon: Clock,           label: 'Scan History' },
  { path: '/reports',         icon: FileText,        label: 'Reports' },
  { path: '/settings',        icon: Settings,        label: 'Settings' },
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
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm md:hidden"
          onClick={onMobileClose}
          aria-label="Close menu"
        />
      )}

      <aside className={sidebarClass} style={{ borderRight: '1px solid rgba(255,255,255,0.06)' }}>
        {/* Logo area */}
        <div style={{ padding: '20px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 10, minHeight: 72 }}>
          {/* Logo icon */}
          <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg,#00c2ff,#2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Shield size={18} color="#fff" />
          </div>
          {(expanded || mobileOpen) && (
            <div style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#00c2ff', lineHeight: 1.2 }}>PhishGuard AI</div>
              <div style={{ fontSize: 10, color: '#64748b', fontWeight: 500 }}>2.0 — SOC Platform</div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '12px 8px', overflowY: 'auto' }}>
          {navItems.map(({ path, icon: Icon, label }) => {
            const active = path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);
            return (
              <NavLink
                key={path}
                to={path}
                onClick={onMobileClose}
                title={!expanded ? label : undefined}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '9px 10px',
                  borderRadius: 8,
                  marginBottom: 2,
                  textDecoration: 'none',
                  background: active ? 'rgba(0,194,255,0.1)' : 'transparent',
                  border: active ? '1px solid rgba(0,194,255,0.2)' : '1px solid transparent',
                  color: active ? '#00c2ff' : '#94a3b8',
                  transition: 'all 0.15s ease',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                })}
              >
                <Icon size={18} style={{ flexShrink: 0 }} />
                {(expanded || mobileOpen) && (
                  <span style={{ fontSize: 13, fontWeight: 500 }}>{label}</span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Bottom */}
        <div style={{ padding: '12px 8px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          {/* System Status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', marginBottom: 4 }} title={!expanded ? 'System Online' : undefined}>
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }} />
            </div>
            {(expanded || mobileOpen) && <span style={{ fontSize: 12, color: '#64748b' }}>System Online</span>}
          </div>

          {/* Collapse toggle (desktop only) */}
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
