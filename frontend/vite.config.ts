import { defineConfig } from 'vite'

import react from '@vitejs/plugin-react'

// Backend Flask app runs on port 5000 (see backend/app.py).
// During `npm run dev` every /api, /email, /forensic request and the
// Socket.IO upgrade are proxied to it, so the SPA talks to the exact same
// endpoints it will use in production (where Flask serves the built dist/).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:5000', changeOrigin: true },
      '/email': { target: 'http://localhost:5000', changeOrigin: true },
      '/forensic': { target: 'http://localhost:5000', changeOrigin: true },
      '/socket.io': { target: 'http://localhost:5000', ws: true, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-leaflet': ['leaflet'],
          'vendor-chart': ['chart.js'],
        },
      },
    },
  },
})
