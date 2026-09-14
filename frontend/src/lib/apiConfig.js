/**
 * PhishGuard AI — Centralized API & Runtime Configuration
 * Strictly resolves API endpoints for Local Development vs Vercel Production.
 * Supports:
 * 1. Runtime custom URL stored in localStorage (allows instant connection from UI)
 * 2. Build-time environment variable VITE_API_URL
 * 3. Local development fallback (127.0.0.1:8000)
 */

const isBrowser = typeof window !== 'undefined';
const hostname = isBrowser ? window.location.hostname : '';

export const IS_LOCAL_HOST =
  hostname === 'localhost' ||
  hostname === '127.0.0.1' ||
  hostname === '0.0.0.0' ||
  hostname.startsWith('192.168.') ||
  hostname.startsWith('10.');

export const IS_PRODUCTION =
  import.meta.env.PROD || (!IS_LOCAL_HOST && Boolean(hostname));

export function getCustomBackendUrl() {
  if (isBrowser) {
    try {
      return (localStorage.getItem('PHISHGUARD_BACKEND_URL') || '').trim();
    } catch {
      return '';
    }
  }
  return '';
}

export function setCustomBackendUrl(url) {
  if (isBrowser) {
    try {
      if (url && url.trim()) {
        localStorage.setItem('PHISHGUARD_BACKEND_URL', url.trim());
      } else {
        localStorage.removeItem('PHISHGUARD_BACKEND_URL');
      }
      window.location.reload();
    } catch (e) {
      console.error('Failed to save backend URL:', e);
    }
  }
}

function resolveApiUrl() {
  const customUrl = getCustomBackendUrl();
  const rawApiUrl = customUrl || (import.meta.env.VITE_API_URL || '').trim();

  if (rawApiUrl) {
    let clean = rawApiUrl.replace(/\/+$/, '');
    if (!clean.endsWith('/api')) {
      clean = `${clean}/api`;
    }
    return clean;
  }

  if (IS_PRODUCTION) {
    // In production on Vercel: NEVER fallback to localhost!
    // Returning empty string signals degraded/unconfigured backend state
    return '';
  }

  // In local development on localhost/127.0.0.1: default to local FastAPI
  return 'http://127.0.0.1:8000/api';
}

export const API_URL = resolveApiUrl();
export const IS_BACKEND_CONFIGURED = Boolean(API_URL);
export const IS_BACKEND_HTTPS = API_URL.startsWith('https://');

export function getHealthUrl() {
  if (!API_URL) return '';
  return `${API_URL}/health`;
}
