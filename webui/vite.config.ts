import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Production build outputs to dist/, which rust-embed embeds into optical-center.
// Dev mode (npm run dev) serves on :5173 with /api proxied to a local center.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:30092',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
