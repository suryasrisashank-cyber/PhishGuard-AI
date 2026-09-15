/**
 * PhishGuard AI — Legacy apiConfig.js wrapper
 * Re-exports from authoritative centralized config: frontend/src/config/api.js
 */

export {
  API_BASE_URL,
  API_URL,
  IS_BACKEND_CONFIGURED,
  IS_BACKEND_HTTPS,
  IS_LOCAL_HOST,
  IS_PRODUCTION,
  getDeveloperApiOverride,
  setDeveloperApiOverride,
  getDeveloperApiOverride as getCustomBackendUrl,
  setDeveloperApiOverride as setCustomBackendUrl,
  getHealthUrl,
  resolveApiBaseUrl,
} from '../config/api.js';
