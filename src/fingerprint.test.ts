// Keyed fingerprints: same person, same owner, same fingerprint; another owner, another fingerprint; useless without
// the owner's key. In AWS the key is a KMS HMAC key that never leaves KMS (kmsMac); memoryMac is the same HMAC with the
// key in memory, for tests, and the two must agree byte for byte.
import { fc, test } from "@fast-check/vitest";
import { describe, expect, it } from "vitest";
import { CryptoError } from "./errors.ts";
import { type Fingerprint, fingerprinter, kmsMac, type KmsMacLike, MAC_BYTES, memoryMac, type PersonalField } from "./fingerprint.ts";
import { hmacSha256, toB64 } from "./primitives.ts";

const keyA = new Uint8Array(32).fill(1);
const keyB = new Uint8Array(32).fill(2);
const shopA = fingerprinter(memoryMac(keyA), "US");
const shopB = fingerprinter(memoryMac(keyB), "US");

/** A stand-in for KMS GenerateMac: real HMAC-SHA256 under a key only it holds, recording each call. */
function fakeKms(key: Uint8Array) {
  const calls: { KeyId: string; MacAlgorithm: string }[] = [];
  const kms: KmsMacLike = {
    generateMac: ({ KeyId, Message, MacAlgorithm }) => {
      calls.push({ KeyId, MacAlgorithm });
      return Promise.resolve({ Mac: hmacSha256(key, Message) });
    },
  };
  return { kms, calls };
}

function badInput(f: () => unknown) {
  const e: unknown = (() => { try { f(); return "no error"; } catch (x) { return x; } })();
  expect(e).toBeInstanceOf(CryptoError);
  expect((e as CryptoError).code).toBe("bad-input");
}

describe("Customer fingerprints", () => {
  it("are the same for one phone however it's written, within one owner", async () => {
    const f = await shopA.phone("(512) 555-0100");
    expect(f).toMatch(/^fp1:phone:[A-Za-z0-9_-]{43}$/);
    for (const raw of ["512.555.0100", "+1 512 555 0100", "15125550100"]) expect(await shopA.phone(raw)).toBe(f);
  });

  it("differ between owners for the same phone or email (a customer of two can't be linked)", async () => {
    expect(await shopA.phone("(512) 555-0100")).not.toBe(await shopB.phone("(512) 555-0100"));
    expect(await shopA.email("ana@x.com")).not.toBe(await shopB.email("ana@x.com"));
  });

  it("are exactly HMAC-SHA256 of the kind and the standard form, under the owner's key", async () => {
    const expected = toB64(hmacSha256(keyA, new TextEncoder().encode("fp1\u0000phone\u0000+15125550100")));
    expect(await shopA.phone("512-555-0100")).toBe(`fp1:phone:${expected}`);
  });

  it("keep kinds apart: a phone and an email never share one", async () => {
    expect(await shopA.email("ana@x.com")).toMatch(/^fp1:email:/);
    expect((await shopA.email("ana@x.com"))?.split(":")[2]).not.toBe((await shopA.phone("+15125550100"))?.split(":")[2]);
  });

  it("aren't made from what can't be read: null, shown as not checked, and the key is never asked", async () => {
    const { kms, calls } = fakeKms(keyA);
    const fp = fingerprinter(kmsMac(kms, "k"), "US");
    expect(await fp.phone("555-0100")).toBeNull();
    expect(await fp.email("not an email")).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("read numbers without a country code in the owner's own country", async () => {
    const mx = fingerprinter(memoryMac(keyA), "MX");
    expect(await mx.phone("55 1234 5678")).toBe(await shopA.phone("+52 55 1234 5678"));
    expect(await mx.phone("512 555 0100")).not.toBe(await shopA.phone("512 555 0100"));
  });

  it("don't change when the caller wipes its copy of a memory key", async () => {
    const s = new Uint8Array(32).fill(9);
    const f = fingerprinter(memoryMac(s), "US");
    const before = await f.phone("5125550100");
    s.fill(0);
    expect(await f.phone("5125550100")).toBe(before);
  });

  it("need a MAC and a country we read", () => {
    badInput(() => fingerprinter(memoryMac(keyA), "GB" as "US"));
    badInput(() => fingerprinter({} as never, "US"));
    badInput(() => fingerprinter(null as never, "US"));
  });

  test.prop([fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ minLength: 32, maxLength: 32 })])(
    "two different keys never give the same fingerprint for the test number", async (k1, k2) => {
      fc.pre(Buffer.compare(k1, k2) !== 0);
      expect(await fingerprinter(memoryMac(k1), "US").phone("5125550100")).not.toBe(await fingerprinter(memoryMac(k2), "US").phone("5125550100"));
    });

  it("only sealed values and fingerprints count as personal fields: plain text is refused by the type checker", async () => {
    const stored: PersonalField[] = [];
    const keep = (f: PersonalField) => stored.push(f);
    keep((await shopA.phone("5125550100")) as Fingerprint);
    // @ts-expect-error -- a plain phone number is not a personal field that may be stored
    keep("512-555-0100");
    expect(stored).toHaveLength(2);
  });
});

describe("The key, inside KMS (kmsMac)", () => {
  it("gives exactly what the same key in memory gives: one fingerprint, wherever it's computed", async () => {
    const { kms } = fakeKms(keyA);
    const inKms = fingerprinter(kmsMac(kms, "arn:aws:kms:us-east-2:111122223333:alias/fingerprint"), "US");
    expect(await inKms.phone("(512) 555-0100")).toBe(await shopA.phone("(512) 555-0100"));
    expect(await inKms.email("Ana@X.com")).toBe(await shopA.email("ana@x.com"));
  });

  it("asks KMS for HMAC-SHA256 with the named key, one call per value", async () => {
    const { kms, calls } = fakeKms(keyA);
    const fp = fingerprinter(kmsMac(kms, "arn:k"), "US");
    await fp.phone("5125550100");
    await fp.email("ana@x.com");
    expect(calls).toEqual([{ KeyId: "arn:k", MacAlgorithm: "HMAC_SHA_256" }, { KeyId: "arn:k", MacAlgorithm: "HMAC_SHA_256" }]);
  });

  it("fails rather than guess when KMS refuses, keeping only the error's name", async () => {
    const denied = new Error("User: arn:aws:sts::1:assumed-role/x is not authorized");
    denied.name = "AccessDeniedException";
    const kms: KmsMacLike = { generateMac: () => Promise.reject(denied) };
    const e = await fingerprinter(kmsMac(kms, "k"), "US").phone("5125550100").catch((x: unknown) => x);
    expect(e).toMatchObject({ code: "mac-failed", serviceError: "AccessDeniedException" });
    expect((e as Error).message).not.toMatch(/arn|authorized/);
  });

  it("refuses an answer that isn't a 32-byte MAC (empty, short, long, not bytes)", async () => {
    for (const Mac of [undefined, new Uint8Array(0), new Uint8Array(MAC_BYTES - 1), new Uint8Array(MAC_BYTES + 1), "x" as unknown as Uint8Array]) {
      const kms: KmsMacLike = { generateMac: () => Promise.resolve({ Mac }) };
      await expect(fingerprinter(kmsMac(kms, "k"), "US").phone("5125550100")).rejects.toMatchObject({ code: "mac-failed" });
    }
  });

  it("needs a key name", () => {
    const { kms } = fakeKms(keyA);
    for (const bad of ["", undefined, 7]) badInput(() => kmsMac(kms, bad as unknown as string));
  });
});

describe("The key, in memory (memoryMac, tests and local use)", () => {
  it("needs exactly 32 bytes", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), "secret" as unknown as Uint8Array]) badInput(() => memoryMac(bad));
  });

  it("is plain HMAC-SHA256 (RFC 4231 test case 2's key is too short for us, so checked against the primitive)", async () => {
    const msg = new TextEncoder().encode("what do ya want for nothing?");
    expect(await memoryMac(keyB).mac(msg)).toEqual(hmacSha256(keyB, msg));
  });
});
