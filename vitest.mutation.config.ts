import { defineConfig } from "vitest/config";

// Mutation runs keep the written order: Stryker maps each planted bug to the tests that reach it.
export default defineConfig({ test: { include: ["src/**/*.test.ts"], sequence: { shuffle: false } } });
