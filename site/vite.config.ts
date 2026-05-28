import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vercel serves this at the domain root ("/"); GitHub Pages serves a project
// site under "/<repo>/". The Pages deploy workflow sets GITHUB_PAGES=true so the
// same source builds correctly for both. Vite rewrites the import.meta.url WASM
// asset path relative to `base`, so the demo loads under either prefix.
const base = process.env.GITHUB_PAGES === 'true' ? '/signet/' : '/';

export default defineConfig({
  base,
  plugins: [react()],
  // The wasm-pack `--target web` glue loads its .wasm via `new URL(..., import.meta.url)`,
  // which Vite handles natively. Keep the binary as an emitted asset (never inlined).
  build: {
    assetsInlineLimit: 0,
    target: 'es2022',
  },
});
