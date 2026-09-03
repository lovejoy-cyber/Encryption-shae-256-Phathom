import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'
import { VitePWA } from 'vite-plugin-pwa'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.svg'],
      manifest: {
        name: 'PhantomVault',
        short_name: 'PhantomVault',
        description: 'Local-first encryption, steganography and ephemeral messaging.',
        theme_color: '#0a0f14',
        background_color: '#0a0f14',
        display: 'standalone',
        icons: [
          { src: 'pwa-192.svg', sizes: '192x192', type: 'image/svg+xml' },
          { src: 'pwa-512.svg', sizes: '512x512', type: 'image/svg+xml' },
        ],
      },
    }),
  ],
  test: {
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    globals: true,
    // PBKDF2 runs at 600k iterations by design (see src/lib/crypto.ts) — real
    // crypto tests that call it dozens of times need real time, not a weaker KDF.
    testTimeout: 30000,
  },
})
