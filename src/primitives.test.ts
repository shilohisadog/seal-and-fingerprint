// The building blocks against published test vectors, so a mistake in how Node's crypto is called can't hide.
// AES-GCM: McGrew and Viega's GCM spec, test cases 13 and 14 (AES-256). HMAC: RFC 4231 test case 2. One more AES-GCM
// vector with checked data (AAD) was computed with Python's `cryptography` package (a separate implementation).
import { describe, expect, it } from "vitest";
import { aesGcmDecrypt, aesGcmEncrypt, fromB64, hmacSha256, random, toB64 } from "./primitives.ts";

const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const enc = (s: string) => new TextEncoder().encode(s);
const zeros = (n: number) => new Uint8Array(n);

describe("AES-256-GCM", () => {
  it("matches GCM spec test case 13 (nothing to encrypt: the tag alone)", () => {
    expect(toHex(aesGcmEncrypt(zeros(32), zeros(12), zeros(0), zeros(0)))).toBe("530f8afbc74536b9a963b4f1c4cb738b");
  });

  it("matches GCM spec test case 14 (one block of zeros)", () => {
    expect(toHex(aesGcmEncrypt(zeros(32), zeros(12), zeros(16), zeros(0)))).toBe("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
  });

  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  const iv = Uint8Array.from({ length: 12 }, (_, i) => i);
  const aad = enc('seal1\n[["shop","k7q2m9"]]');
  const sealed = hex("156ba07eb784e24be134fae9d8871f405a73c744e6172ca1f041926a31d81e");

  it("matches a second implementation with checked data, and opens it", () => {
    expect(toHex(aesGcmEncrypt(key, iv, enc("Rivera Plumbing"), aad))).toBe(toHex(sealed));
    expect(new TextDecoder().decode(aesGcmDecrypt(key, iv, sealed, aad))).toBe("Rivera Plumbing");
  });

  it("refuses different checked data, a different IV or key, a changed byte, or too few bytes", () => {
    expect(() => aesGcmDecrypt(key, iv, sealed, enc('seal1\n[["shop","x"]]'))).toThrow();
    expect(() => aesGcmDecrypt(key, zeros(12), sealed, aad)).toThrow();
    expect(() => aesGcmDecrypt(zeros(32), iv, sealed, aad)).toThrow();
    for (let i = 0; i < sealed.length; i++) {
      const bad = Uint8Array.from(sealed);
      bad[i] = (bad[i] ?? 0) ^ 1;
      expect(() => aesGcmDecrypt(key, iv, bad, aad)).toThrow();
    }
    expect(() => aesGcmDecrypt(key, iv, sealed.subarray(0, 15), aad)).toThrow("too short");
  });
});

describe("HMAC-SHA256", () => {
  it("matches RFC 4231 test case 2", () => {
    expect(toHex(hmacSha256(enc("Jefe"), enc("what do ya want for nothing?")))).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  });
});

describe("base64url and randomness", () => {
  it("round-trips, and accepts only the one canonical spelling", () => {
    expect(toB64(hex("fbff00"))).toBe("-_8A");
    expect(fromB64("-_8A")).toEqual(hex("fbff00"));
    expect(fromB64("AA")).toEqual(hex("00"));
    expect(fromB64("AB")).toBeNull(); // the same byte, spelled with stray low bits
    expect(fromB64("-_8A=")).toBeNull();
    expect(fromB64("+/8A")).toBeNull(); // plain base64, not base64url
    expect(fromB64("")).toBeNull();
  });

  it("draws the bytes asked for, differently each time", () => {
    expect(random(32)).toHaveLength(32);
    expect(toHex(random(16))).not.toBe(toHex(random(16)));
  });
});
