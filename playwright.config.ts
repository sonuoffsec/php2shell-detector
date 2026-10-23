import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  workers: 1, // one persistent Chrome profile at a time
  reporter: [['list']],
  use: { trace: 'retain-on-failure' },
});
