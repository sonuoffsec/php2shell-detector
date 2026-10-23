import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Mode "e2e" adds a throwaway manifest key (so tests can compute the extension ID), a test name and
// loopback-only host_permissions. extension/static/manifest.json is never modified.
function e2eManifest(): Plugin {
  return {
    name: 'e2e-manifest',
    apply: 'build',
    closeBundle() {
      const out = resolve(__dirname, 'dist-e2e/manifest.json');
      const manifest = JSON.parse(readFileSync(out, 'utf8')) as Record<string, unknown>;
      manifest.name = 'PHP2Shell Detector (E2E TEST BUILD)';
      manifest.host_permissions = ['http://127.0.0.1/*', 'https://127.0.0.1/*', 'http://localhost/*', 'https://localhost/*'];
      // Throwaway key so the test can compute the extension ID (no background worker to read it from).
      const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      manifest.key = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
      writeFileSync(out, JSON.stringify(manifest, null, 2));
    },
  };
}

export default defineConfig(({ mode }) => ({
  base: './',
  publicDir: 'extension/static',
  plugins: [react(), ...(mode === 'e2e' ? [e2eManifest()] : [])],
  build: {
    outDir: mode === 'e2e' ? 'dist-e2e' : 'dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'chrome120',
    rollupOptions: { input: { popup: resolve(__dirname, 'popup.html') } },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/unit/**/*.test.{ts,tsx}', 'tests/integration/**/*.test.{ts,tsx}'],
    setupFiles: ['tests/helpers/setup.ts'],
  },
}));
