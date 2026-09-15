import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const resolvedApiUrl = env.VITE_API_URL || env.API_URL || env.BACKEND_URL || '';

  return {
    plugins: [react()],
    envPrefix: ['VITE_', 'API_', 'BACKEND_'],
    define: {
      __API_URL__: JSON.stringify(resolvedApiUrl),
    },
    server: {
      host: '0.0.0.0',
      port: 3000,
      allowedHosts: true,
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
        },
        '/health': {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
        },
      },
    },
    preview: {
      host: '0.0.0.0',
      port: 3000,
      allowedHosts: true,
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
        },
        '/health': {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
        },
      },
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ['react', 'react-dom', 'react-router-dom'],
            charts: ['recharts'],
            motion: ['framer-motion'],
            three: ['three'],
          },
        },
      },
      chunkSizeWarningLimit: 600,
    },
  };
});
