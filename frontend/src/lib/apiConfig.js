/**
 * PhishGuard AI — Centralized API & Runtime Configuration
 * Strictly resolves API endpoints for Local Development vs Vercel Production.
 * Never defaults to localhost or 127.0.0.1 in production.
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

// Read configured VITE_API_URL
const rawApiUrl = (import.meta.env.VITE_API_URL || '').trim();

function resolveApiUrl() {
  if (rawApiUrl) {
    let clean = rawApiUrl.replace(/\/+$/, '');
    // If user passed root URL without /api, append /api
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
