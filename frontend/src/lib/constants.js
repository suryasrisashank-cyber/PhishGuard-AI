/**
 * PhishGuard AI 2.0 — Shared constants and configuration
 */

import {
  API_URL,
  IS_BACKEND_CONFIGURED,
  IS_PRODUCTION,
  IS_BACKEND_HTTPS,
  getHealthUrl,
} from './apiConfig.js';

export { API_URL, IS_BACKEND_CONFIGURED, IS_PRODUCTION, IS_BACKEND_HTTPS, getHealthUrl };
export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true';

export const VERDICT_CONFIG = {
  Safe:       { color: '#10b981', bg: 'rgba(16,185,129,0.1)',  border: 'rgba(16,185,129,0.25)',  label: 'SAFE' },
  Suspicious: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)',  border: 'rgba(245,158,11,0.25)',  label: 'SUSPICIOUS' },
  Malicious:  { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.25)',   label: 'MALICIOUS' },
  Unknown:    { color: '#6b7280', bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.25)', label: 'UNKNOWN' },
};

export const SEVERITY_CONFIG = {
  INFORMATIONAL: { color: '#6366f1', bg: 'rgba(99,102,241,0.1)',  label: 'INFO' },
  LOW:           { color: '#22d3ee', bg: 'rgba(34,211,238,0.1)',  label: 'LOW' },
  MEDIUM:        { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)',  label: 'MEDIUM' },
  HIGH:          { color: '#f97316', bg: 'rgba(249,115,22,0.1)',  label: 'HIGH' },
  CRITICAL:      { color: '#dc2626', bg: 'rgba(220,38,38,0.1)',   label: 'CRITICAL' },
};

export const STATUS_CONFIG = {
  NEW:               { color: '#6b7280', bg: 'rgba(107,114,128,0.1)', label: 'NEW' },
  INVESTIGATING:     { color: '#2563eb', bg: 'rgba(37,99,235,0.1)',   label: 'INVESTIGATING' },
  CONFIRMED_THREAT:  { color: '#dc2626', bg: 'rgba(220,38,38,0.1)',   label: 'CONFIRMED THREAT' },
  RESPONDING:        { color: '#f97316', bg: 'rgba(249,115,22,0.1)',  label: 'RESPONDING' },
  FALSE_POSITIVE:    { color: '#10b981', bg: 'rgba(16,185,129,0.1)',  label: 'FALSE POSITIVE' },
  RESOLVED:          { color: '#0d9488', bg: 'rgba(13,148,136,0.1)',  label: 'RESOLVED' },
};

export const EVIDENCE_CATEGORIES = [
  'ALL',
  'DOMAIN',
  'NETWORK',
  'URL',
  'CONTENT',
  'EMAIL',
  'AUTHENTICATION',
  'THREAT INTELLIGENCE',
];

export const IOC_TYPE_ICONS = {
  URL: '🔗',
  DOMAIN: '🌐',
  IP: '📡',
  EMAIL: '📧',
  HOSTNAME: '🖥️',
  HASH: '#',
  FILE: '📄',
};

export const SCAN_TYPES = ['url', 'website', 'email', 'screenshot'];

export const SOC_WORKFLOW_STAGES = [
  { id: 'detect',      label: 'Detect',      icon: '🔍' },
  { id: 'investigate', label: 'Investigate',  icon: '🔎' },
  { id: 'enrich',      label: 'Enrich',       icon: '📊' },
  { id: 'classify',    label: 'Classify',     icon: '🏷️' },
  { id: 'respond',     label: 'Respond',      icon: '⚡' },
  { id: 'report',      label: 'Report',       icon: '📋' },
];
