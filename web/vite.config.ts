import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies API calls to a locally running beacon-server.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/snooze': 'http://127.0.0.1:8080',
    },
  },
  build: { outDir: 'dist', sourcemap: false },
})
