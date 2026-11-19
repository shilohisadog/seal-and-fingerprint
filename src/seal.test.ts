// Sealing: round trips for any value and context, bound to its context, tamper-evident, and never leaking a value,
// key or context through an error.
import { fc, test } from "@fast-check/vitest";
import { describe, expect, it } from "vitest";
import { canonical, type Context } from "./context.ts";
import { CryptoError } from "./errors.ts";
import { type KmsLike, kmsLock, memoryLock } from "./locks.ts";
import { FORMAT, type KeyLock, MAX_LOCKED, open, openText, seal } from "./seal.ts";

const lock = memoryLock(new Uint8Array(32).fill(7));
const ctx: Context = { shop: "k7q2m9", purpose: "token", tool: "crm", tokenClass: "readwrite" };

/** Fails unless f rejects with a CryptoError of that code. */
async function refuses(f: () => Promise<unknown>, code: string) {
  const e: unknown = await f().then(() => "no error", (x: unknown) => x);
  expect(e).toBeInstanceOf(CryptoError);
  expect((e as CryptoError).code).toBe(code);
  return e as CryptoError;
}

/** A lock that ignores the context entirely: shows the local check refuses a wrong context on its own. */
const careless: KeyLock = { lock: (k) => Promise.resolve(Uint8Array.from(k)), unlock: (l) => Promise.resolve(Uint8Array.from(l)) };

const anyName = fc.stringMatching(/^[A-Za-z][A-Za-z0-9_-]{0,15}$/);
// eslint-disable-next-line no-control-regex -- control characters are what a context refuses
const anyValue = fc.string({ minLength: 1, maxLength: 40 }).filter((v) => !/[\u0000-\u001f\u007f]/.test(v));
const anyContext = fc.dictionary(anyName, anyValue, { minKeys: 1, maxKeys: 8 });

describe("Sealing round trips", () => {
  it("seals and opens an empty value (the body is the 16-byte tag alone), and refuses a body shorter than the tag", async () => {
    const empty = await seal(new Uint8Array(0), ctx, lock);
    expect(await open(empty, ctx, lock)).toEqual(new Uint8Array(0));
    expect(await openText(await seal("", ctx, lock), ctx, lock)).toBe("");
    const parts = empty.split(".");
    const short = [...parts.slice(0, 3), Buffer.from(parts[3] ?? "", "base64url").subarray(1).toString("base64url")].join(".");
    await expect(open(short, ctx, lock)).rejects.toMatchObject({ code: "bad-format" });
  });

  test.prop([fc.uint8Array({ maxLength: 2000 }), anyContext])("any bytes, any context: open gives back exactly what was sealed", async (value, context) => {
    expect(await open(await seal(value, context, lock), context, lock)).toEqual(value);
  });

  test.prop([fc.string({ unit: "grapheme" }), anyContext])("any text, any context", async (value, context) => {
    expect(await openText(await seal(value, context, lock), context, lock)).toBe(value);
  });

  it("names the format, and never contains the value", async () => {
    const s = await seal("refresh-token-AB12", ctx, lock);
    expect(s.split(".")).toHaveLength(4);
    expect(s.startsWith(`${FORMAT}.`)).toBe(true);
    expect(s).not.toContain("refresh-token");
    expect(s).not.toContain(Buffer.from("refresh-token-AB12").toString("base64url"));
  });

  it("seals the same value differently every time (a fresh key and IV each time)", async () => {
    expect(await seal("x", ctx, lock)).not.toBe(await seal("x", ctx, lock));
  });

  it("keeps its format: a fixed key and IV give exactly this, as computed by a second implementation (Python's cryptography; a lock that returns the key as is)", async () => {
    let n = 0;
    const counting = (len: number) => Uint8Array.from({ length: len }, () => n++ % 256);
    const s = await seal("Rivera Plumbing", { shop: "k7q2m9" }, careless, { random: counting });
    expect(s).toBe("seal1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.ICEiIyQlJicoKSor.gFPQFR75Ol52CS-sqHaTyu8jXJC_dyyQpzu4Rke9sg");
  });
});

describe("A sealed value opens only in its own place", () => {
  const variants: [string, Context][] = [
    ["another shop", { ...ctx, shop: "z9z9z9" }],
    ["another purpose", { ...ctx, purpose: "field" }],
    ["another tool", { ...ctx, tool: "quickbooks" }],
    ["another token class", { ...ctx, tokenClass: "readonly" }],
    ["a name missing", { shop: "k7q2m9", purpose: "token", tool: "crm" }],
    ["a name added", { ...ctx, record: "r1" }],
  ];

  for (const [what, wrong] of variants) {
    it(`refuses ${what}, both at the key service and in the local check`, async () => {
      await refuses(async () => open(await seal("t", ctx, lock), wrong, lock), "refused");
      await refuses(async () => open(await seal("t", ctx, careless), wrong, careless), "refused");
    });
  }

  it("opens with the same context written in any order", async () => {
    const s = await seal("t", ctx, lock);
    expect(await openText(s, { tokenClass: "readwrite", tool: "crm", purpose: "token", shop: "k7q2m9" }, lock)).toBe("t");
  });

  it("refuses another key", async () => {
    await refuses(async () => open(await seal("t", ctx, lock), ctx, memoryLock(new Uint8Array(32).fill(8))), "refused");
  });
});

describe("Tampering is caught", () => {
  it("refuses the value with any one character changed, or its parts swapped or cut", async () => {
    const s = await seal("refresh-token-AB12", ctx, lock);
    for (let i = 0; i < s.length; i++) {
      const c = s[i] === "A" ? "B" : "A";
      const bad = s.slice(0, i) + c + s.slice(i + 1);
      const e: unknown = await open(bad, ctx, lock).then(() => "opened", (x: unknown) => x);
      expect(e, `character ${String(i)}`).toBeInstanceOf(CryptoError);
    }
    const [f, l, iv, body] = s.split(".");
    for (const bad of [`${f}.${l}.${body}.${iv}`, `${f}.${l}.${iv}`, `${f}.${l}.${iv}.${body}.x`, `seal2.${l}.${iv}.${body}`, `${f}.${l}.${iv}.${String(body).slice(0, 10)}`, "", "plain text"]) {
      await refuses(() => open(bad, ctx, lock), "bad-format");
    }
  });

  it("refuses a value sealed under another value's locked key (a mixed-up record)", async () => {
    const [, l1] = (await seal("one", ctx, lock)).split(".");
    const [f, , iv, body] = (await seal("two", ctx, lock)).split(".");
    await refuses(() => open(`${String(f)}.${String(l1)}.${String(iv)}.${String(body)}`, ctx, lock), "refused");
  });

  it("refuses a locked key far too large to be one", async () => {
    const big = Buffer.alloc(MAX_LOCKED + 1).toString("base64url");
    const [f, , iv, body] = (await seal("x", ctx, lock)).split(".");
    await refuses(() => open(`${String(f)}.${big}.${String(iv)}.${String(body)}`, ctx, lock), "bad-format");
  });

  it("refuses a value that isn't text, or whose parts aren't base64url, or whose IV or tag is the wrong size", async () => {
    await refuses(() => open(42 as unknown as string, ctx, lock), "bad-format");
    const [f, l, iv, body] = (await seal("x", ctx, lock)).split(".");
    const parts = [String(l), String(iv), String(body)];
    for (let i = 0; i < 3; i++) {
      const bad = [...parts];
      bad[i] = "@@@@";
      await refuses(() => open([f, ...bad].join("."), ctx, lock), "bad-format");
    }
    await refuses(() => open([f, l, "AAAAAAAAAAAAAAAA", body].join("."), ctx, lock), "refused"); // 12 bytes: the right size, the wrong IV
    await refuses(() => open([f, l, "AAAAAAAA", body].join("."), ctx, lock), "bad-format"); // 6 bytes
    await refuses(() => open([f, l, iv, "AAAAAAAAAAAAAAAAAAAA"].join("."), ctx, lock), "bad-format"); // 15 bytes: no room for a tag
  });

  it("accepts a locked key of exactly the largest size, both ways", async () => {
    const padded: KeyLock = {
      lock: (k) => { const out = new Uint8Array(MAX_LOCKED); out.set(k); return Promise.resolve(out); },
      unlock: (l) => Promise.resolve(Uint8Array.from(l.subarray(0, 32))),
    };
    expect(await openText(await seal("x", ctx, padded), ctx, padded)).toBe("x");
  });

  it("refuses text that isn't UTF-8", async () => {
    await refuses(async () => openText(await seal(new Uint8Array([0xff, 0xfe]), ctx, lock), ctx, lock), "bad-format");
  });
});

describe("The context", () => {
  it("is checked before anything is sealed or opened", async () => {
    const bad: Context[] = [{}, { shop: 5 } as unknown as Context, { "1shop": "x" }, { shop: "" }, { shop: "a\nb" }, { shop: "x".repeat(257) }, Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`n${String(i)}`, "v"]))];
    let calls = 0;
    const counted: KeyLock = { lock: (k) => { calls++; return Promise.resolve(k); }, unlock: (l) => { calls++; return Promise.resolve(l); } };
    for (const c of bad) {
      await refuses(() => seal("x", c, counted), "bad-context");
      await refuses(() => open("seal1.AA.AA.AA", c, counted), "bad-context");
    }
    expect(calls).toBe(0);
  });

  it("accepts the limits exactly: 8 names, 256-character values, 64-character names", () => {
    expect(() => canonical(Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`n${String(i)}`, "v".repeat(256)])))).not.toThrow();
    expect(() => canonical({ [`a${"b".repeat(63)}`]: "v" })).not.toThrow();
    expect(() => canonical({ [`a${"b".repeat(64)}`]: "v" })).toThrow(CryptoError);
  });

  it("has one spelling whatever the order it's written in", () => {
    expect(canonical({ b: "2", a: "1", c: "3" })).toBe('[["a","1"],["b","2"],["c","3"]]');
    // A name that starts another sorts first, whatever the values.
    expect(canonical({ ab: "a", a: "z", "a-b": "1", aB: "2" })).toBe('[["a","z"],["a-b","1"],["aB","2"],["ab","a"]]');
  });
});

describe("Errors never leak", () => {
  it("carries a fixed message and the key service's error name, never its message, the value or the context", async () => {
    const kms: KmsLike = {
      encrypt: () => Promise.reject(Object.assign(new Error("User arn:aws:iam::1:role/x may not use key k7q2m9 for refresh-token-AB12"), { name: "AccessDeniedException" })),
      decrypt: () => Promise.reject(Object.assign(new Error("context shop=k7q2m9 refresh-token-AB12"), { name: "InvalidCiphertextException" })),
    };
    const e1 = await refuses(() => seal("refresh-token-AB12", ctx, kmsLock(kms, "alias/data")), "lock-failed");
    expect(e1.serviceError).toBe("AccessDeniedException");
    const e2 = await refuses(async () => open(await seal("refresh-token-AB12", ctx, lock), ctx, kmsLock(kms, "alias/data")), "refused");
    expect(e2.serviceError).toBe("InvalidCiphertextException");
    for (const e of [e1, e2]) {
      const shown = `${e.message} ${e.stack ?? ""} ${JSON.stringify(e)}`;
      for (const secret of ["refresh-token", "k7q2m9", "crm", "arn:aws", "readwrite"]) expect(shown).not.toContain(secret);
    }
  });

  it("names a thrown non-error as unknown", async () => {
    // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- what some code throws
    const odd: KeyLock = { lock: () => Promise.reject("refresh-token"), unlock: () => Promise.reject("refresh-token") };
    expect((await refuses(() => seal("x", ctx, odd), "lock-failed")).serviceError).toBe("unknown");
  });
});

describe("A key service that misbehaves is refused", () => {
  it("refuses an empty, missing or oversized locked key when sealing", async () => {
    for (const out of [new Uint8Array(0), new Uint8Array(MAX_LOCKED + 1), "not bytes"]) {
      const bad = { lock: () => Promise.resolve(out), unlock: () => Promise.resolve(new Uint8Array(32)) } as unknown as KeyLock;
      await refuses(() => seal("x", ctx, bad), "lock-failed");
    }
    await refuses(() => seal("x", ctx, kmsLock({ encrypt: () => Promise.resolve({}), decrypt: () => Promise.resolve({}) }, "k")), "lock-failed");
  });

  it("refuses an unlocked key of the wrong size or type, or none", async () => {
    const s = await seal("x", ctx, careless);
    for (const out of [new Uint8Array(31), new Uint8Array(33), "key"]) {
      const bad = { lock: (k: Uint8Array, c: Context) => careless.lock(k, c), unlock: () => Promise.resolve(out) } as unknown as KeyLock;
      await refuses(() => open(s, ctx, bad), "refused");
    }
    await refuses(() => open(s, ctx, kmsLock({ encrypt: () => Promise.resolve({}), decrypt: () => Promise.resolve({}) }, "k")), "refused");
  });

  it("refuses a value that is neither text nor bytes", async () => {
    await refuses(() => seal(42 as unknown as string, ctx, lock), "bad-input");
  });

  it("wipes the working key after sealing and after opening", async () => {
    const seen: Uint8Array[] = [];
    const spy: KeyLock = { lock: (k) => { seen.push(k); return careless.lock(k, ctx); }, unlock: async (l) => { const k = await careless.unlock(l, ctx); seen.push(k); return k; } };
    await open(await seal("x", ctx, spy), ctx, spy);
    expect(seen).toHaveLength(2);
    for (const k of seen) expect(k.every((b) => b === 0)).toBe(true);
  });
});

describe("The KMS lock", () => {
  it("sends the key, the key ID and the context to KMS, and pins the key ID when unlocking", async () => {
    const calls: unknown[] = [];
    const kms: KmsLike = {
      encrypt: (i) => { calls.push(["encrypt", i.KeyId, i.EncryptionContext, i.Plaintext.length]); return Promise.resolve({ CiphertextBlob: Uint8Array.from(i.Plaintext) }); },
      decrypt: (i) => { calls.push(["decrypt", i.KeyId, i.EncryptionContext]); return Promise.resolve({ Plaintext: Uint8Array.from(i.CiphertextBlob) }); },
    };
    const k = kmsLock(kms, "arn:aws:kms:us-east-2:1:alias/data");
    expect(await openText(await seal("t", ctx, k), ctx, k)).toBe("t");
    expect(calls).toEqual([
      ["encrypt", "arn:aws:kms:us-east-2:1:alias/data", ctx, 32],
      ["decrypt", "arn:aws:kms:us-east-2:1:alias/data", ctx],
    ]);
  });

  it("needs a key ID", () => {
    const empty: KmsLike = { encrypt: () => Promise.resolve({}), decrypt: () => Promise.resolve({}) };
    for (const id of ["", undefined]) expect(() => kmsLock(empty, id as string)).toThrow(expect.objectContaining({ code: "bad-input" }));
  });

  it("refuses a KMS answer with nothing in it, each way", async () => {
    const k = kmsLock({ encrypt: () => Promise.resolve({}), decrypt: () => Promise.resolve({}) }, "k");
    await expect(k.lock(new Uint8Array(32), ctx)).rejects.toMatchObject({ code: "lock-failed" });
    await expect(k.unlock(new Uint8Array(32), ctx)).rejects.toMatchObject({ code: "refused" });
  });

  it("the memory lock needs a 32-byte key, and refuses a locked key that's too short", async () => {
    for (const bad of [new Uint8Array(16), "key" as unknown as Uint8Array]) expect(() => memoryLock(bad)).toThrow(expect.objectContaining({ code: "bad-input" }));
    await expect(lock.unlock(new Uint8Array(10), ctx)).rejects.toMatchObject({ code: "refused" });
  });
});
