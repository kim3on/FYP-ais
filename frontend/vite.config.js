import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // All /api/* requests forwarded to FastAPI
      '/api': {
        target: 'http://127.0.0.1:8001',
        changeOrigin: true,
      },
      // WebSocket proxy for live capture
      '/ws': {
        target: 'ws://127.0.0.1:8001',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: '../app/static_react', // FastAPI will serve from here
    emptyOutDir: true,
  },
})
