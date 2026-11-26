import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000,
    hookTimeout: 30000,
    // Run all test files sequentially (singleThread) to avoid SQLite singleton conflicts
    singleThread: true,
    sequence: { concurrent: false },
  },
});
