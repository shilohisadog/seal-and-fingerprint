import { defineConfig } from "vitest/config";

// Tests run in a shuffled order, so no test can quietly depend on another's leftovers. TEST_SEED=random for a new order.
const seed = process.env.TEST_SEED === "random" ? Date.now() % 1e9 : Number(process.env.TEST_SEED ?? 20261118);

export default defineConfig({ test: { include: ["src/**/*.test.ts"], sequence: { shuffle: { files: true, tests: true }, seed } } });
