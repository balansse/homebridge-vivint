import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// homebridge-config-ui-x serves this UI from a sub-path inside an iframe,
// so every asset URL must be relative.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    outDir: 'build',
    emptyOutDir: true,
    sourcemap: false,
  },
})
