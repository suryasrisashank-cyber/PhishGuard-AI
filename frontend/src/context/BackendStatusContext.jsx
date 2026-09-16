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
  healthUrl: getHealthUrl(),
  lastChecked: null,
  errorType: null,
  retryConnection: () => {},
});

export function BackendStatusProvider({ children }) {
  const [status, setStatus] = useState('CONNECTING');
  const [statusMessage, setStatusMessage] = useState('Connecting to SOC backend...');
  const [isHealthy, setIsHealthy] = useState(false);
  const [latency, setLatency] = useState(null);
  const [version, setVersion] = useState('3.0.0');
  const [environment, setEnvironment] = useState(IS_PRODUCTION ? 'production' : 'development');
  const [lastChecked, setLastChecked] = useState(null);
  const [errorType, setErrorType] = useState(null);

  const consecutiveFailuresRef = useRef(0);
  const fastRetryTimerRef = useRef(null);
  const intervalTimerRef = useRef(null);
  const isCheckingRef = useRef(false);

  const checkHealth = useCallback(async (isManualRetry = false) => {
    // Avoid overlapping concurrent probes
    if (isCheckingRef.current) return false;
    isCheckingRef.current = true;

    if (isManualRetry) {
      consecutiveFailuresRef.current = 0;
      setStatus('CONNECTING');
      setStatusMessage('Checking SOC backend availability...');
    }

    const healthUrl = getHealthUrl();
    const startTime = performance.now();

    try {
      // 15-second probe timeout to comfortably accommodate Render free-tier cold starts
      const response = await axios.get(healthUrl, {
        timeout: 15000,
        headers: { Accept: 'application/json' },
      });

      const elapsed = Math.round(performance.now() - startTime);

      if (response.status === 200 && response.data?.status === 'healthy') {
        consecutiveFailuresRef.current = 0;
        setStatus('CONNECTED');
        setStatusMessage('SOC backend online');
        setIsHealthy(true);
        setLatency(elapsed);
        setLastChecked(new Date().toISOString());
        setErrorType(null);
        if (response.data.version) setVersion(response.data.version);
        if (response.data.environment) setEnvironment(response.data.environment);
        isCheckingRef.current = false;
        return true;
      } else {
        consecutiveFailuresRef.current += 1;
        setStatus('UNAVAILABLE');
        setStatusMessage('The SOC backend is currently unavailable.');
        setIsHealthy(false);
        setLatency(null);
        setLastChecked(new Date().toISOString());
        setErrorType('UNHEALTHY_PAYLOAD');
        isCheckingRef.current = false;
        return false;
      }
    } catch (err) {
      const nowIso = new Date().toISOString();
      setIsHealthy(false);
      setLatency(null);
      setLastChecked(nowIso);

      const isTimeout =
        err.code === 'ECONNABORTED' ||
        (err.message && err.message.toLowerCase().includes('timeout'));

      if (isTimeout) {
        consecutiveFailuresRef.current += 1;
        // If first attempt timed out, Render is likely spinning up from cold storage.
        // Fast-retry in 3 seconds before declaring permanent timeout.
        if (consecutiveFailuresRef.current === 1) {
          setStatus('CONNECTING');
          setStatusMessage('Waking up SOC backend (Render cold start in progress, retrying...)');
          setErrorType('COLD_START');
          isCheckingRef.current = false;

          if (fastRetryTimerRef.current) clearTimeout(fastRetryTimerRef.current);
          fastRetryTimerRef.current = setTimeout(() => {
            checkHealth(false);
          }, 3000);

          return false;
        } else {
          setStatus('TIMEOUT');
          setStatusMessage('The backend did not respond within the expected time.');
          setErrorType('TIMEOUT');
        }
      } else if (!err.response) {
        consecutiveFailuresRef.current += 1;
        setStatus('UNAVAILABLE');
        setStatusMessage('The SOC backend is currently unavailable.');
        setErrorType(err.code === 'ERR_NETWORK' ? 'NETWORK' : 'UNAVAILABLE');
      } else if (err.response.status === 401) {
        consecutiveFailuresRef.current = 0;
        setStatus('CONNECTED'); // Backend is reachable and answering
        setStatusMessage('Authentication is required.');
        setIsHealthy(true);
        setErrorType(null);
        isCheckingRef.current = false;
        return true;
      } else if (err.response.status >= 500) {
        consecutiveFailuresRef.current += 1;
        setStatus('ERROR');
        setStatusMessage('SOC backend encountered an internal error.');
        setErrorType(`HTTP_${err.response.status}`);
      } else {
        consecutiveFailuresRef.current += 1;
        setStatus('UNAVAILABLE');
        setStatusMessage('Unable to connect to SOC backend.');
        setErrorType(`HTTP_${err.response.status}`);
      }

      isCheckingRef.current = false;
      return false;
    }
  }, []);

  useEffect(() => {
    // Initial health probe on app load
    checkHealth();

    // Auto-poll: check every 15s if offline/degraded (to quickly recover when awake), or every 45s if connected
    intervalTimerRef.current = setInterval(() => {
      checkHealth();
    }, isHealthy ? 45000 : 15000);

    return () => {
      if (intervalTimerRef.current) clearInterval(intervalTimerRef.current);
      if (fastRetryTimerRef.current) clearTimeout(fastRetryTimerRef.current);
    };
  }, [checkHealth, isHealthy]);

  const value = {
    status,
    statusMessage,
    isHealthy,
    latency,
    version,
    environment,
    apiUrl: API_BASE_URL,
    healthUrl: getHealthUrl(),
    lastChecked,
    errorType,
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

