import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['./test/setup.ts'],
    globals: true,
    testTimeout: 20000,
    // Integration tests share one Postgres/Redis instance and use advisory
    // locks / row locks for correctness — run serially to avoid cross-test
    // interference rather than adding per-test DB isolation infrastructure.
    fileParallelism: false,
  },
});
