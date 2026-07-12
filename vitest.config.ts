import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Unit tests live in src/. The e2e/ folder holds Playwright specs, which
    // must not be collected by vitest (they import @playwright/test).
    include: ['src/**/*.{test,spec}.ts'],
    environment: 'node',
  },
});
