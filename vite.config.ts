import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Security note: API keys should NEVER be exposed to client-side bundles
// per codeguard-1-hardcoded-credentials. If external API access is needed,
// route through the backend server to keep credentials server-side only.

export default defineConfig(() => {
  return {
    server: {
      port: 3000,
      // Security: Bind to localhost only (per codeguard-0-api-web-services)
      // Use '0.0.0.0' only if you need LAN access during development
      host: 'localhost',
      proxy: {
        '/api': 'http://127.0.0.1:17920'
      }
    },
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      }
    }
  };
});
