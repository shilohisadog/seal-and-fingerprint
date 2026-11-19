import { describe, expect, it } from "vitest";
import { CryptoError, type CryptoErrorCode } from "./errors.ts";

describe("Errors", () => {
  it("have a fixed, distinct, plain message per code, and say what they are", () => {
    const codes: CryptoErrorCode[] = ["bad-context", "bad-format", "bad-input", "refused", "lock-failed", "mac-failed"];
    const messages = codes.map((c) => new CryptoError(c).message);
    for (const m of messages) expect(m.length).toBeGreaterThan(20);
    expect(new Set(messages).size).toBe(codes.length);
    expect(new CryptoError("refused").message).toMatch(/^Could not open/);
    const e = new CryptoError("refused", "AccessDeniedException");
    expect([e.name, e.code, e.serviceError, e instanceof Error]).toEqual(["CryptoError", "refused", "AccessDeniedException", true]);
    expect(new CryptoError("bad-format").serviceError).toBeUndefined();
  });
});
