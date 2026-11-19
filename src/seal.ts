// Sealing: envelope encryption bound to a context.
// A fresh 256-bit key encrypts the value locally (AES-256-GCM, the context as checked data). The key service then
// locks that key under the same context, and the locked key is stored beside the value:
//   seal1.<locked key>.<iv>.<ciphertext and tag>       (each part base64url, no padding)
// Opening needs the same context at both steps: the key service refuses to unlock under any other, and the local
// decryption refuses too, so neither silently relies on the other.
import { type Context, checkedData } from "./context.ts";
import { CryptoError, errorName } from "./errors.ts";
import { aesGcmDecrypt, aesGcmEncrypt, fromB64, IV_BYTES, KEY_BYTES, random, TAG_BYTES, toB64 } from "./primitives.ts";

/** Something that locks and unlocks a 32-byte key under a context: a KMS key (kms.ts), or memoryLock for tests. */
export interface KeyLock {
  lock(key: Uint8Array, context: Context): Promise<Uint8Array>;
  unlock(locked: Uint8Array, context: Context): Promise<Uint8Array>;
}

/** A sealed value. Only seal() makes one, so code that stores personal data can insist on it. */
export type Sealed = string & { readonly __brand: "Sealed" };

export interface SealOptions {
  /** Tests only: where the random key and IV come from. */
  readonly random?: (n: number) => Uint8Array;
}

export const FORMAT = "seal1";
/** A KMS-locked 32-byte key is under 300 bytes; anything far larger isn't one. */
export const MAX_LOCKED = 4096;

export async function seal(value: string | Uint8Array, context: Context, lock: KeyLock, options: SealOptions = {}): Promise<Sealed> {
  const aad = checkedData(FORMAT, context);
  if (typeof value !== "string" && !(value instanceof Uint8Array)) throw new CryptoError("bad-input");
  const plain = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const draw = options.random ?? random;
  const key = Uint8Array.from(draw(KEY_BYTES));
  const iv = draw(IV_BYTES);
  try {
    let locked: unknown;
    try {
      locked = await lock.lock(key, context);
    } catch (e) {
      throw new CryptoError("lock-failed", errorName(e));
    }
    if (!(locked instanceof Uint8Array) || locked.length === 0 || locked.length > MAX_LOCKED) throw new CryptoError("lock-failed");
    return [FORMAT, toB64(locked), toB64(iv), toB64(aesGcmEncrypt(key, iv, plain, aad))].join(".") as Sealed;
  } finally {
    key.fill(0);
  }
}

function parse(sealed: string): { locked: Uint8Array; iv: Uint8Array; body: Uint8Array } {
  if (typeof sealed !== "string") throw new CryptoError("bad-format");
  const parts = sealed.split(".");
  if (parts.length !== 4 || parts[0] !== FORMAT) throw new CryptoError("bad-format");
  const [locked, iv, body] = parts.slice(1).map(fromB64);
  if (!locked || !iv || !body || locked.length > MAX_LOCKED || iv.length !== IV_BYTES || body.length < TAG_BYTES) throw new CryptoError("bad-format");
  return { locked, iv, body };
}

/** Opens a sealed value, given the context it was sealed with. Throws CryptoError (bad-format or refused). */
export async function open(sealed: string, context: Context, lock: KeyLock): Promise<Uint8Array> {
  const aad = checkedData(FORMAT, context);
  const { locked, iv, body } = parse(sealed);
  let key: unknown;
  try {
    key = await lock.unlock(locked, context);
  } catch (e) {
    throw new CryptoError("refused", errorName(e));
  }
  if (!(key instanceof Uint8Array)) throw new CryptoError("refused");
  try {
    return aesGcmDecrypt(key, iv, body, aad); // a key of the wrong size is refused here too

  } catch {
    throw new CryptoError("refused");
  } finally {
    key.fill(0);
  }
}

/** open(), for a value sealed from text. Throws bad-format if the bytes aren't UTF-8. */
export async function openText(sealed: string, context: Context, lock: KeyLock): Promise<string> {
  const bytes = await open(sealed, context, lock);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CryptoError("bad-format");
  }
}
