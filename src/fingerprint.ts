// Keyed fingerprints: HMAC-SHA256 of a person's phone number or email, under a key that belongs to one owner (for
// example, one business). The same person fingerprints the same within an owner, differently between owners, and a
// fingerprint can't be reversed by trying every phone number without the key.
//   fp1:<kind>:<HMAC-SHA256(key, "fp1" 0x00 kind 0x00 standard form), base64url>
// In AWS the key is a KMS HMAC key (kmsMac): the HMAC is computed inside KMS and the key never leaves it, so no memory
// dump, log or compromised dependency can carry the key away for an offline search.
import { CryptoError, errorName } from "./errors.ts";
import { type Country, COUNTRIES, normalizeEmail, normalizePhone } from "./normalize.ts";
import { hmacSha256, toB64 } from "./primitives.ts";
import type { Sealed } from "./seal.ts";

/** A fingerprint. Only a Fingerprinter makes one. */
export type Fingerprint = string & { readonly __brand: "Fingerprint" };

/** What may be stored for a person's details: sealed, or a fingerprint. Never the plain value. */
export type PersonalField = Sealed | Fingerprint;

export type Kind = "phone" | "email";

/** Computes HMAC-SHA256 under a key it holds: a KMS HMAC key (kmsMac), or a key in memory (memoryMac, for tests). */
export interface Mac {
  mac(message: Uint8Array): Promise<Uint8Array>;
}

/** The one call used from AWS KMS. The AWS SDK's `KMS` class fits as is. */
export interface KmsMacLike {
  generateMac(input: { KeyId: string; Message: Uint8Array; MacAlgorithm: "HMAC_SHA_256" }): Promise<{ Mac?: Uint8Array | undefined }>;
}

export const MAC_BYTES = 32;

const checked = (m: unknown): Uint8Array => {
  if (!(m instanceof Uint8Array) || m.length !== MAC_BYTES) throw new CryptoError("mac-failed");
  return m;
};

/** HMAC-SHA256 inside KMS, with an HMAC_256 key. Needs `kms:GenerateMac` on that key, and nothing else. */
export function kmsMac(kms: KmsMacLike, keyId: string): Mac {
  if (typeof keyId !== "string" || keyId.length === 0) throw new CryptoError("bad-input");
  return {
    async mac(message) {
      let r: { Mac?: Uint8Array | undefined };
      try {
        r = await kms.generateMac({ KeyId: keyId, Message: message, MacAlgorithm: "HMAC_SHA_256" });
      } catch (e) {
        throw new CryptoError("mac-failed", errorName(e));
      }
      return checked(r.Mac);
    },
  };
}

/** A 32-byte key held in memory. For tests and local use only: in AWS, use kmsMac so the key never leaves KMS. */
export function memoryMac(key: Uint8Array): Mac {
  if (!(key instanceof Uint8Array) || key.length !== MAC_BYTES) throw new CryptoError("bad-input");
  const k = Uint8Array.from(key); // the caller may wipe theirs
  return { mac: (message) => Promise.resolve(hmacSha256(k, message)) };
}

export interface Fingerprinter {
  /** null: the number can't be read with certainty (show it as not checked; never guess). */
  phone(raw: string): Promise<Fingerprint | null>;
  email(raw: string): Promise<Fingerprint | null>;
}

export function fingerprinter(mac: Mac, country: Country): Fingerprinter {
  if (typeof (mac as Partial<Mac> | null | undefined)?.mac !== "function" || !COUNTRIES.includes(country)) throw new CryptoError("bad-input");
  // The kind is part of what's hashed, so a phone and an email can never share a fingerprint.
  const make = async (kind: Kind, standard: string | null) =>
    standard === null ? null : (`fp1:${kind}:${toB64(checked(await mac.mac(new TextEncoder().encode(`fp1\u0000${kind}\u0000${standard}`))))}` as Fingerprint);
  return {
    phone: (raw) => make("phone", normalizePhone(raw, country)),
    email: (raw) => make("email", normalizeEmail(raw)),
  };
}
