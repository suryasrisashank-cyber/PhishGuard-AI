import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { API_BASE_URL, getHealthUrl, IS_PRODUCTION } from '../config/api.js';

const BackendStatusContext = createContext({
  status: 'CONNECTING', // 'CONNECTING' | 'CONNECTED' | 'UNAVAILABLE' | 'TIMEOUT' | 'ERROR'
  statusMessage: 'Connecting to SOC backend...',
  isHealthy: false,
  latency: null,
  version: '3.0.0',
  environment: IS_PRODUCTION ? 'production' : 'development',
  apiUrl: API_BASE_URL,
  retryConnection: () => {},
});

export function BackendStatusProvider({ children }) {
  const [status, setStatus] = useState('CONNECTING');
  const [statusMessage, setStatusMessage] = useState('Connecting to SOC backend...');
  const [isHealthy, setIsHealthy] = useState(false);
  const [latency, setLatency] = useState(null);
  const [version, setVersion] = useState('3.0.0');
  const [environment, setEnvironment] = useState(IS_PRODUCTION ? 'production' : 'development');

  const checkTimerRef = useRef(null);

  const checkHealth = useCallback(async (isManualRetry = false) => {
    if (isManualRetry) {
      setStatus('CONNECTING');
      setStatusMessage('Checking SOC backend availability...');
    }

    const healthUrl = getHealthUrl();
    const startTime = performance.now();

    try {
      // 5-second initial probe timeout for responsiveness
      const response = await axios.get(healthUrl, {
        timeout: 5000,
        headers: { Accept: 'application/json' },
      });

      const elapsed = Math.round(performance.now() - startTime);

      if (response.status === 200 && response.data?.status === 'healthy') {
        setStatus('CONNECTED');
        setStatusMessage('SOC backend online');
        setIsHealthy(true);
        setLatency(elapsed);
        if (response.data.version) setVersion(response.data.version);
        if (response.data.environment) setEnvironment(response.data.environment);
        return true;
      } else {
        setStatus('UNAVAILABLE');
        setStatusMessage('The SOC backend is currently unavailable.');
        setIsHealthy(false);
        setLatency(null);
        return false;
      }
    } catch (err) {
      setIsHealthy(false);
      setLatency(null);

      if (err.code === 'ECONNABORTED' || (err.message && err.message.toLowerCase().includes('timeout'))) {
        setStatus('TIMEOUT');
        setStatusMessage('The backend did not respond within the expected time.');
      } else if (!err.response) {
        setStatus('UNAVAILABLE');
        setStatusMessage('The SOC backend is currently unavailable.');
      } else if (err.response.status === 401) {
        setStatus('CONNECTED'); // Backend is reachable, just needs auth
        setStatusMessage('Authentication is required.');
        setIsHealthy(true);
      } else if (err.response.status >= 500) {
        setStatus('ERROR');
        setStatusMessage('SOC backend encountered an internal error.');
      } else {
        setStatus('UNAVAILABLE');
        setStatusMessage('Unable to connect to SOC backend.');
      }
      return false;
    }
  }, []);

  useEffect(() => {
    // Initial probe on app startup
    checkHealth();

    // Auto-retry every 30 seconds if unhealthy, or poll every 60s if healthy
    const interval = setInterval(() => {
      checkHealth();
    }, 30000);

    return () => clearInterval(interval);
  }, [checkHealth]);

  const value = {
    status,
    statusMessage,
    isHealthy,
    latency,
    version,
    environment,
    apiUrl: API_BASE_URL,
    retryConnection: () => checkHealth(true),
  };

  return (
    <BackendStatusContext.Provider value={value}>
      {children}
    </BackendStatusContext.Provider>
  );
}

export function useBackendStatus() {
  return useContext(BackendStatusContext);
}
