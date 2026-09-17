/**
 * PhishGuard AI 3.0 — Authoritative Centralized API Configuration
 *
 * Single source of truth for API base URL resolution across all frontend services.
 * Production: Automatically uses VITE_API_URL (or relative /api for same-origin/rewrites).
 * Development: Defaults to http://127.0.0.1:8000/api.
 *
 * Normal users never need to configure a backend URL.
 * Optional developer override is strictly confined to local debugging.
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

function normalizeApiUrl(url) {
  if (!url) return '';
  let clean = url.trim().replace(/\/+$/, '');
  if (!clean.endsWith('/api')) {
    clean = `${clean}/api`;
  }
  return clean;
}

/**
 * Returns optional developer override from localStorage.
 * Strictly used for developer debugging on the Settings page.
 */
export function getDeveloperApiOverride() {
  if (!isBrowser) return '';
  try {
    return (localStorage.getItem('PHISHGUARD_DEV_API_OVERRIDE') || '').trim();
  } catch {
    return '';
  }
}

/**
 * Sets or clears developer override (Settings page developer section only).
 */
export function setDeveloperApiOverride(url) {
  if (!isBrowser) return;
  try {
    if (url && url.trim()) {
      localStorage.setItem('PHISHGUARD_DEV_API_OVERRIDE', url.trim());
    } else {
      localStorage.removeItem('PHISHGUARD_DEV_API_OVERRIDE');
    }
    window.location.reload();
  } catch (e) {
    console.error('Failed to set developer API override:', e);
  }
}

/**
 * Authoritative API Base URL Resolution:
 * 1. Developer override (if explicitly configured in dev settings)
 * 2. VITE_API_URL environment variable (from Vercel build / environment)
 * 3. Production fallback: '/api' (relative HTTPS)
 * 4. Localhost development fallback: 'http://127.0.0.1:8000/api'
 */
export function resolveApiBaseUrl() {
  const devOverride = getDeveloperApiOverride();
  if (devOverride) {
    return normalizeApiUrl(devOverride);
  }

  const envUrl = (
    import.meta.env.VITE_API_URL ||
    import.meta.env.API_URL ||
    import.meta.env.BACKEND_URL ||
    (typeof __API_URL__ !== 'undefined' ? __API_URL__ : '') ||
    ''
  ).trim();
  if (envUrl) {
    return normalizeApiUrl(envUrl);
  }

  if (IS_PRODUCTION) {
    // When running on Vercel, use relative '/api' to route via Vercel edge proxy rewrites
    if (isBrowser && window.location.hostname.includes('vercel.app')) {
      return '/api';
    }
    // Direct cloud connection fallback to live FastAPI backend on Render
    return 'https://phishguard-backend-880i.onrender.com/api';
  }

  // Local development on localhost/127.0.0.1
  return 'http://127.0.0.1:8000/api';
}

export const API_BASE_URL = resolveApiBaseUrl();
export const API_URL = API_BASE_URL; // alias
export const IS_BACKEND_CONFIGURED = Boolean(API_BASE_URL);
export const IS_BACKEND_HTTPS =
  API_BASE_URL.startsWith('https://') ||
  (IS_PRODUCTION && !API_BASE_URL.startsWith('http://'));

export function getHealthUrl() {
  if (!API_BASE_URL || API_BASE_URL === '/api') {
    return '/api/health';
  }
  return `${API_BASE_URL}/health`;
}
