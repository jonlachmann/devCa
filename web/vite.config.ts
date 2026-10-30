import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// `npm run dev` proxies the API to a running `devca serve`.
// The Origin header is dropped because DevCA only accepts its own origin.
export default defineConfig({
  plugins: [svelte()],
  build: { outDir: 'dist/ui', emptyOutDir: true, assetsInlineLimit: 0 },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7171',
        changeOrigin: true,
        configure: (proxy) => proxy.on('proxyReq', (req) => req.removeHeader('origin')),
      },
    },
  },
})
