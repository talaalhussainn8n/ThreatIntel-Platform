import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Im Entwicklungsmodus werden /api-Aufrufe an die ASP.NET-Core-API weitergeleitet.
export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      '/api': process.env.API_URL ?? 'http://localhost:5000'
    }
  }
})
