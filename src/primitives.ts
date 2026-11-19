// The building blocks, from Node's own crypto: AES-256-GCM and HMAC-SHA256. Checked against published test vectors
// (primitives.test.ts) so a mistake in how they're called can't hide.
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

export const KEY_BYTES = 32;
export const IV_BYTES = 12;
export const TAG_BYTES = 16;

/** AES-256-GCM. Returns the ciphertext followed by the 16-byte tag. */
export function aesGcmEncrypt(key: Uint8Array, iv: Uint8Array, plain: Uint8Array, aad: Uint8Array): Uint8Array {
  const c = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
  c.setAAD(aad);
  return new Uint8Array(Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]));
}

/** Throws if the key, IV, checked data (AAD) or any byte differs from what was sealed. */
export function aesGcmDecrypt(key: Uint8Array, iv: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Uint8Array {
  const tagAt = sealed.length - TAG_BYTES;
  if (tagAt < 0) throw new Error("too short");
  const d = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
  d.setAAD(aad);
  d.setAuthTag(sealed.subarray(tagAt));
  return new Uint8Array(Buffer.concat([d.update(sealed.subarray(0, tagAt)), d.final()]));
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", key).update(data).digest());
}

export function random(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

/** base64url without padding. */
export function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/**
 * Strict base64url: only the canonical spelling of some bytes is accepted, else null. Node's decoder skips characters
 * it doesn't know, so the bytes are encoded again and must give back exactly the text.
 */
export function fromB64(s: string): Uint8Array | null {
  const b = Buffer.from(s, "base64url");
  return s.length > 0 && b.toString("base64url") === s ? new Uint8Array(b) : null;
}
