// One error type for everything this library refuses. Its message is fixed per code: it never carries a value, a key
// or a context, so it can be logged safely.

export type CryptoErrorCode = "bad-context" | "bad-format" | "bad-input" | "refused" | "lock-failed" | "mac-failed";

const MESSAGES: Readonly<Record<CryptoErrorCode, string>> = {
  "bad-context": "The context is not valid: 1 to 8 names (letters, digits, - and _), each with a value of 1 to 256 printable characters",
  "bad-format": "Not a sealed value this library can read",
  "bad-input": "The input is not valid for this operation",
  refused: "Could not open: wrong context, wrong key, tampered with, or not allowed",
  "lock-failed": "The key service did not lock the key",
  "mac-failed": "The key service did not compute the fingerprint",
};

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;
  /** The key service's error name (for example AccessDeniedException), when it refused. Never its message. */
  readonly serviceError: string | undefined;

  constructor(code: CryptoErrorCode, serviceError?: string) {
    super(MESSAGES[code]);
    this.name = "CryptoError";
    this.code = code;
    this.serviceError = serviceError;
  }
}

/** The name of whatever was thrown, and nothing else from it. */
export function errorName(e: unknown): string {
  return e instanceof Error ? e.name : "unknown";
}
