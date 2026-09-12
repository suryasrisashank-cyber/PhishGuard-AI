/**
 * PhishGuard AI 2.0 — Axios API Client
 * All backend communication goes through this module.
 * Never hardcode API keys here — use environment variables.
 */
import axios from 'axios';
import { API_URL } from '../lib/constants.js';

const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor — attach auth token if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('phishguard_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor — normalize errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.code === 'ECONNABORTED') {
      return Promise.reject(new Error('Request timed out. The backend may be slow or unavailable.'));
    }
    if (!error.response) {
      return Promise.reject(new Error('Unable to connect to PhishGuard API. Ensure the backend is running and tunnel is active.'));
    }
    if (error.response.status === 401) {
      localStorage.removeItem('phishguard_token');
      return Promise.reject(new Error('Session expired. Please log in again.'));
    }
    const message = error.response.data?.detail || error.response.data?.message || `API error ${error.response.status}`;
    return Promise.reject(new Error(message));
  }
);

// ============================================================
// API Methods
// ============================================================

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
  list: (params = {}) => api.get('/scans', { params }),
  get: (id) => api.get(`/scans/${id}`),
  updateStatus: (id, status) => api.patch(`/scans/${id}/status`, { investigation_status: status }),
  updateNotes: (id, notes) => api.patch(`/scans/${id}/notes`, { analyst_notes: notes }),
};

export const screenshotsApi = {
  upload: (file) => {
    const form = new FormData();
    form.append('file', file);
    return api.post('/screenshots/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
};

export const threatsApi = {
  lookup: (domain) => api.get(`/threats/lookup?domain=${encodeURIComponent(domain)}`),
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
  check: () => axios.get(API_URL.startsWith('http') ? `${API_URL.replace(/\/api\/?$/, '')}/health` : '/health', { timeout: 5000 }),
};

export default api;
