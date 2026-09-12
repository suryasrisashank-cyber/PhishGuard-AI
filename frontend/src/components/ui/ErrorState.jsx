import React from 'react';
import { AlertCircle, RefreshCw, Server, AlertTriangle } from 'lucide-react';
import { API_URL } from '../../lib/constants.js';

export default function ErrorState({ message, onRetry }) {
  const isApiError = !message || message.includes('API') || message.includes('connect') || message.includes('unavailable') || message.includes('Network');

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '36px 20px',
      gap: 20,
      maxWidth: 540,
      margin: '0 auto',
      textAlign: 'left',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%' }}>
        <div style={{
          width: 44,
          height: 44,
          borderRadius: 12,
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}>
          <AlertCircle size={24} color="#ef4444" />
        </div>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
            Unable to connect to PhishGuard API
          </h3>
          <p style={{ margin: '3px 0 0', fontSize: 13, color: '#94a3b8' }}>
            {message || 'The application cannot reach the threat detection backend.'}
          </p>
        </div>
      </div>

      <div style={{
        width: '100%',
        padding: 16,
        borderRadius: 10,
        background: 'rgba(15, 23, 42, 0.75)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        boxSizing: 'border-box',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: 10 }}>
          <span style={{ fontSize: 12, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
            Connection Status
          </span>
          <span style={{
            fontSize: 11,
            fontWeight: 700,
            padding: '2px 8px',
            borderRadius: 6,
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            color: '#ef4444',
            letterSpacing: '0.04em',
          }}>
            OFFLINE
          </span>
        </div>

        <div>
          <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, marginBottom: 4 }}>
            API Endpoint:
          </div>
          <code style={{
            display: 'block',
            padding: '8px 10px',
            borderRadius: 6,
            background: 'rgba(0, 0, 0, 0.35)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            color: '#00c2ff',
            fontSize: 12,
            fontFamily: 'var(--font-mono, monospace)',
            wordBreak: 'break-all',
          }}>
            {API_URL}
          </code>
        </div>

        <div>
          <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, marginBottom: 6 }}>
            Possible Causes:
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: '#cbd5e1', lineHeight: 1.6 }}>
            <li>Backend is not running</li>
            <li>Backend tunnel is offline</li>
            <li>CORS configuration</li>
            <li>HTTPS/mixed-content issue</li>
            <li>Incorrect API URL</li>
          </ul>
        </div>
      </div>

      {onRetry && (
        <button
          className="btn-primary"
          onClick={onRetry}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            fontSize: 13,
            padding: '10px 18px',
            borderRadius: 8,
          }}
        >
          <RefreshCw size={14} /> Retry Connection
        </button>
      )}
    </div>
  );
}

