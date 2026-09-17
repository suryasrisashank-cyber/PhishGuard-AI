import React from 'react';
import { createRoot } from 'react-dom/client';
import { Toaster } from 'react-hot-toast';
import App from './App.jsx';
import './styles/globals.css';

// Deactivate the initialization watchdog timer once application script executes
if (typeof window !== 'undefined' && window.__PG_INIT_TIMER__) {
  clearTimeout(window.__PG_INIT_TIMER__);
  window.__PG_INIT_TIMER__ = null;
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
    <Toaster
      position="top-right"
      toastOptions={{
        duration: 4000,
        style: {
          background: '#0a1628',
          color: '#f1f5f9',
          border: '1px solid rgba(0,194,255,0.2)',
          borderRadius: '10px',
          fontSize: '13px',
        },
        success: { iconTheme: { primary: '#10b981', secondary: '#0a1628' } },
        error: { iconTheme: { primary: '#ef4444', secondary: '#0a1628' } },
      }}
    />
  </React.StrictMode>
);
