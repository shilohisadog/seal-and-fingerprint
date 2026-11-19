// Two KeyLocks: a KMS key (what runs in AWS), and a key held in memory (for tests and local use; it behaves like KMS:
// the context must match exactly, or unlocking fails).
import { type Context, checkedData } from "./context.ts";
import { CryptoError } from "./errors.ts";
import type { KeyLock } from "./seal.ts";
import { aesGcmDecrypt, aesGcmEncrypt, IV_BYTES, KEY_BYTES, random } from "./primitives.ts";

/**
 * The two calls we use from AWS KMS. The AWS SDK's `KMS` class (`new KMS({})` from @aws-sdk/client-kms) fits as is,
 * so this library needs no dependency on it.
 */
export interface KmsLike {
  encrypt(input: { KeyId: string; Plaintext: Uint8Array; EncryptionContext: Record<string, string> }): Promise<{ CiphertextBlob?: Uint8Array | undefined }>;
  decrypt(input: { KeyId: string; CiphertextBlob: Uint8Array; EncryptionContext: Record<string, string> }): Promise<{ Plaintext?: Uint8Array | undefined }>;
}

/**
 * Locks with a KMS key. Only `kms:Encrypt` is needed to seal (so an encrypt-only role can seal but never open),
 * and `kms:Decrypt` to open. The context goes to KMS as the encryption context, which key policies can test.
 */
export function kmsLock(kms: KmsLike, keyId: string): KeyLock {
  if (typeof keyId !== "string" || keyId.length === 0) throw new CryptoError("bad-input");
  return {
    async lock(key, context) {
      const r = await kms.encrypt({ KeyId: keyId, Plaintext: key, EncryptionContext: { ...context } });
      if (!r.CiphertextBlob) throw new CryptoError("lock-failed");
      return r.CiphertextBlob;
    },
    async unlock(locked, context) {
      // KeyId pins the key: a value locked under another key is refused even if this role could use that one.
      const r = await kms.decrypt({ KeyId: keyId, CiphertextBlob: locked, EncryptionContext: { ...context } });
      if (!r.Plaintext) throw new CryptoError("refused");
      return r.Plaintext;
    },
  };
}

/** A key held in memory (32 bytes). For tests and local use only: in AWS, use kmsLock. */
export function memoryLock(master: Uint8Array): KeyLock {
  if (!(master instanceof Uint8Array) || master.length !== KEY_BYTES) throw new CryptoError("bad-input");
  const k = Uint8Array.from(master);
  const aad = (context: Context) => checkedData("lock1", context);
  return {
    lock(key, context) {
      const iv = random(IV_BYTES);
      return Promise.resolve(new Uint8Array(Buffer.concat([iv, aesGcmEncrypt(k, iv, key, aad(context))])));
    },
    unlock(locked, context) {
      try {
        return Promise.resolve(aesGcmDecrypt(k, locked.subarray(0, IV_BYTES), locked.subarray(IV_BYTES), aad(context)));
      } catch {
        return Promise.reject(new CryptoError("refused"));
      }
    },
  };
}
