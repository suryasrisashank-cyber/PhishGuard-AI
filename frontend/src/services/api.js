/**
 * PhishGuard AI 3.0 — Axios API Client
 * Centralized communication layer for all SOC analysis, telemetry, and SIEM endpoints.
 */
import axios from 'axios';
import { API_BASE_URL, getHealthUrl } from '../config/api.js';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor — attach token if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('phishguard_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor — Phase 17 Centralized API Error Handling Layer
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // 1. Timeout handling
    if (error.code === 'ECONNABORTED' || (error.message && error.message.toLowerCase().includes('timeout'))) {
      return Promise.reject(new Error('The backend did not respond within the expected time.'));
    }

    // 2. Network / Connection Refused / DNS Error
    if (!error.response) {
      if (error.code === 'ERR_NETWORK' || (error.message && error.message.includes('Network Error'))) {
        return Promise.reject(new Error('The SOC backend could not be reached.'));
      }
      return Promise.reject(new Error('The SOC backend is currently unavailable.'));
    }

    const { status, data } = error.response;

    // 3. HTTP Status code mappings
    switch (status) {
      case 401:
        localStorage.removeItem('phishguard_token');
        return Promise.reject(new Error('Authentication is required.'));
      case 403:
        return Promise.reject(new Error('Access denied.'));
      case 429:
        return Promise.reject(new Error('Request limit reached. Please try again later.'));
      case 500:
        return Promise.reject(new Error('SOC backend encountered an internal error.'));
      case 502:
      case 503:
      case 504:
        return Promise.reject(new Error('SOC backend is temporarily unavailable.'));
      default:
        const detailMsg = data?.detail || data?.message;
        if (detailMsg && typeof detailMsg === 'string') {
          return Promise.reject(new Error(detailMsg));
        }
        return Promise.reject(new Error('Unable to connect to SOC backend.'));
    }
  }
);

// ============================================================
// API Services
// ============================================================

export const systemApi = {
  getIntegrations: (probe = false) => api.get(`/system/integrations${probe ? '?probe=true' : ''}`),
  testAllIntegrations: () => api.post('/system/integrations/test-all'),
  testProvider: (providerId) => api.post(`/system/integrations/${encodeURIComponent(providerId)}/test`),
};

export const dashboardApi = {
  getStats: () => api.get('/dashboard/stats'),
  getRecent: (limit = 10) => api.get(`/dashboard/recent?limit=${limit}`),
};

export const scansApi = {
  scanUrl: (target) => api.post('/scans/url', { scan_type: 'url', target }),
  scanWebsite: (target) => api.post('/scans/website', { scan_type: 'website', target }),
  scanEmail: (content) => api.post('/scans/email', { content }),
  scanEmailFile: (file) => {
    const form = new FormData();
    form.append('file', file);
    return api.post('/scans/email/file', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  scanFile: (file) => {
    const form = new FormData();
    form.append('file', file);
    return api.post('/scans/file', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  scanPcap: (file) => {
    const form = new FormData();
    form.append('file', file);
    return api.post('/scans/pcap', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  list: (params = {}) => api.get('/scans', { params }),
  get: (id) => api.get(`/scans/${id}`),
  updateStatus: (id, status) => api.patch(`/scans/${id}/status`, { investigation_status: status }),
  updateNotes: (id, notes) => api.patch(`/scans/${id}/notes`, { analyst_notes: notes }),
};

export const splunkApi = {
  getStatus: () => api.get('/splunk/status'),
  testConnection: () => api.post('/splunk/test'),
  sendEvent: (data, eventType = 'manual_event', sourcetype = null) =>
    api.post('/splunk/send', { data, event_type: eventType, sourcetype }),
  getSplExamples: () => api.get('/splunk/spl-examples'),
};

export const iocsApi = {
  list: (params = {}) => api.get('/iocs', { params }),
  get: (id) => api.get(`/iocs/${id}`),
  correlate: (value) => api.get(`/iocs/correlate/${encodeURIComponent(value)}`),
  create: (data) => api.post('/iocs', data),
  getExportUrl: () => `${API_URL}/iocs/export/csv`,
};

export const investigationsApi = {
  list: (params = {}) => api.get('/investigations', { params }),
  get: (id) => api.get(`/investigations/${id}`),
  createFromScan: (scanId, title = null) => api.post('/investigations/from-scan', { scan_id: scanId, title }),
  update: (id, data) => api.patch(`/investigations/${id}`, data),
  attachBurpFinding: (id, finding) => api.post(`/investigations/${id}/burp-finding`, finding),
  forwardToSplunk: (id) => api.post(`/investigations/${id}/splunk`),
};

export const alertsApi = {
  list: (params = {}) => api.get('/alerts', { params }),
};

export const campaignsApi = {
  list: () => api.get('/campaigns'),
};

export const screenshotsApi = {
  upload: (file) => {
    const form = new FormData();
    form.append('file', file);
    return api.post('/screenshots/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
};

export const threatsApi = {
  getProvidersStatus: () => api.get('/threats/providers/status'),
  lookup: (domain) => api.get(`/threats/lookup?domain=${encodeURIComponent(domain)}`),
  enrich: (type, value) => api.get(`/threats/enrich/${encodeURIComponent(type)}/${encodeURIComponent(value)}`),
};

export const reportsApi = {
  get: (scanId) => api.get(`/reports/${scanId}`),
};

export const aiApi = {
  explain: (payload) => api.post('/ai/explain', payload),
};

export const authApi = {
  login: (username, password) => api.post('/auth/login', { username, password }),
  register: (username, email, password, role = 'user') =>
    api.post('/auth/register', { username, email, password, role }),
};

export const healthApi = {
  check: () => {
    const url = getHealthUrl();
    if (!url) {
      return Promise.reject(new Error('Backend unavailable. VITE_API_URL is not configured.'));
    }
    return axios.get(url, { timeout: 5000 });
  },
};


export default api;

