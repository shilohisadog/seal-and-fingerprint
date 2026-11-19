# seal-and-fingerprint

A small library for keeping personal data and credentials safe. It has two jobs:

- **Sealing**: envelope encryption, bound to the place the value belongs.
- **Keyed fingerprints**: lets people's phone numbers and emails be matched without being stored.

It uses only Node's built-in `crypto` and has no dependencies. It works with AWS KMS (the AWS SDK's `KMS` client fits as is) or, for tests, with keys held in memory.

## Sealing

```ts
import { kmsLock, open, seal } from "./src/index.ts";
import { KMS } from "@aws-sdk/client-kms";

const lock = kmsLock(new KMS({}), "arn:aws:kms:…:alias/data");
const context = { owner: "k7q2m9", purpose: "token", tool: "crm", tokenClass: "readwrite", record: "r1" };
const sealed = await seal(token, context, lock); // "seal1.…"
const token2 = await open(sealed, context, lock); // the same bytes; any other context is refused
```

**How it works:**
1. A fresh 256-bit key encrypts the value locally with AES-256-GCM. The **context** is the checked data (AAD).
2. The key service locks that key under the **same context**, using KMS `Encrypt`.
3. The result is stored as one string: `seal1.<locked key>.<iv>.<ciphertext and tag>`, each part in base64url without padding.

**Opening** needs the same context at both steps:
- the key service won't unlock the key under any other context;
- the local decryption refuses as well.

Each check is tested on its own, so neither silently relies on the other. A value copied to another record, purpose or account won't open.

**Why `Encrypt`, not `GenerateDataKey`:** a role that may only encrypt can still seal. It can never open what it sealed, so a service can lock a credential for someone else without being able to read it back.

**The context:**
- 1 to 8 names (letters, digits, `-` and `_`), each with a value of 1 to 256 printable characters;
- written in any order (it's sorted before use);
- sent to KMS as the encryption context, so key policies can test it. For example, "only this role may open values whose `tokenClass` is `readwrite`".

**Errors:** everything refused is a `CryptoError` with a `code`: `bad-context`, `bad-format`, `bad-input`, `refused`, `lock-failed` or `mac-failed`.
- Its message is fixed per code. It never contains the value, a key or the context, so it is safe to log.
- When the key service refused, `serviceError` holds that error's name (for example `AccessDeniedException`), never its message.

## Keyed fingerprints

```ts
import { fingerprinter, kmsMac } from "./src/index.ts";
import { KMS } from "@aws-sdk/client-kms";

const fp = fingerprinter(kmsMac(new KMS({}), "arn:aws:kms:…:alias/fingerprint"), "US"); // an HMAC_256 KMS key
await fp.phone("(512) 555-0100") === await fp.phone("+1 512.555.0100"); // true: "fp1:phone:…"
await fp.phone("555-0100"); // null: can't be read with certainty, so never guessed (and KMS is never asked)
```

**How it works:**
- A fingerprint is HMAC-SHA256 under a 256-bit key: `fp1:<kind>:<base64url>`.
- The input is `fp1`, the kind, then the value in its standard form, separated by zero bytes. A phone number and an email can therefore never share a fingerprint.
- In AWS, the HMAC is **computed inside KMS** (`GenerateMac`, an `HMAC_256` key). The key never leaves KMS: not into memory, logs or a crash dump. Roles that fingerprint need `kms:GenerateMac` on that key and nothing else.

**What gets fingerprinted, and what the key is for:**
- It's always a **person's** phone number or email that gets fingerprinted: for example, a business's customers.
- The **key** belongs to whoever holds the records: for example, the business. It isn't made from anyone's details.
- Each business has its own key, so a customer of two businesses can't be linked between them.

**Why the key stays inside KMS:** phone numbers are guessable. There are about ten billion in North America, so:
- a plain hash of a phone number can be reversed in minutes by trying every number;
- a keyed hash can't be, without the key. But anyone who once copies the key can reverse every fingerprint, past and future, offline;
- with the key inside KMS there's nothing to copy. Someone who takes over a role allowed to fingerprint can only ask KMS, one number per request. Checking a particular number is easy that way. Trying all ten billion is not practical: at KMS's default quota of 10,000 requests a second (shared with everything else the account does with KMS in that region) it takes about 12 days, costs about $30,000 in requests, and leaves ten billion `GenerateMac` entries in CloudTrail. An alarm on the request count catches it on day one.

**Cost:** one KMS request per value fingerprinted (values that can't be read are never sent). Fingerprint new or changed values only, and keep the result.

**For tests and local use**, `memoryMac(key)` computes the same HMAC with a 32-byte key in memory. Given the same key, both give the same fingerprint (tested).

**Standard forms:**
- **Phones:**
  - North America (+1) and Mexico (+52), read in the owner's country when written without a country code;
  - the old Mexican forms (`01`, `044`, `045`, `+52 1`) are recognised;
  - other countries are accepted only with their `+` and kept as written;
  - letters, extensions or anything uncertain give `null`.
- **Emails:**
  - Unicode-normalised, trimmed and lower-cased, with the domain in its ASCII form;
  - nothing provider-specific: dots and `+tags` are kept, because Gmail's rules are wrong for most other providers;
  - anything that isn't a single plain address gives `null`.

## Limits, said plainly

What this library doesn't do, and why. These are the first questions we'd ask of anyone else's.

- **The context is not secret.** KMS logs the encryption context in plain text (CloudTrail). Put names and IDs in it, never personal data.
- **Anyone who may encrypt can forge.** A role allowed `kms:Encrypt` on the key can seal any value for any context it's allowed. Sealing proves "made by someone allowed to lock", not "made by a particular service". Key policies should narrow which contexts each role may lock (for example, a lock-only role only for `purpose=token`).
- **No freshness.** An older value sealed for the same context still opens. If replacing a value must make the old one useless, put a version in the context, or check it where the value is stored.
- **Length shows.** The ciphertext is as long as the value plus 16 bytes. Pad before sealing if length matters.
- **AES-GCM doesn't commit to its key.** One ciphertext can be built to open under two chosen keys. It doesn't apply here: each value has exactly one locked key, and KMS unlocks that locked key to only one key, under only its own context.
- **Random IVs are fine because keys aren't reused.** Every value gets a fresh key, so each key encrypts exactly once.
- **Wiping memory is best effort.** Keys are overwritten after use, but JavaScript and the AWS SDK may keep copies we can't reach. Treat any process that opened a value as having seen it.
- **Fingerprints show equality, by design.** Two records with the same phone number have the same fingerprint, within one owner. That's what makes matching possible; it also means a number on many records is visible as such (without the number).
- **KMS sees each value it fingerprints.** The standard form (for example `+15125550100`) is sent to KMS over TLS. CloudTrail's `GenerateMac` entry records the key and algorithm, not the message (AWS's documented example), so the value isn't kept in the audit log. If KMS itself is outside what you trust, this design isn't for you.
- **Whoever may fingerprint can test a guess.** A role with `kms:GenerateMac` can ask "is this number among the records?" one number at a time. Keep that permission to the roles that need it, and watch the request count.
- **The fingerprint key can't be rotated in place.** KMS doesn't rotate HMAC keys, and a new key would change every fingerprint. Rotating means a new key and fingerprinting everything again from the source records.
- **Lower-casing the local part is a choice.** The email standard lets `Ana@x.com` and `ana@x.com` be different mailboxes; in practice providers treat them as one, and we follow practice.

## Types

`seal()` returns a `Sealed` and a fingerprinter returns a `Fingerprint`. `PersonalField = Sealed | Fingerprint`. Code that stores personal data can require a `PersonalField`, and the type checker then refuses plain text.

## Tests

- **Encryption and HMAC:** checked against published vectors (the GCM spec's test cases 13 and 14, and RFC 4231 test case 2).
- **The sealed format:** pinned to a vector computed by a second implementation (Python's `cryptography`).
- **Property tests:** round trips for any value and context, and formatting never changing a phone's fingerprint.
- **Tampering:** a sealed value with any one character changed is refused.
- **Mutation testing:** the tests are themselves checked by planting bugs in the library; at least 90% must be caught.

## Running the tests

Node 24 or later.

```sh
npm ci
npm test                    # shuffled order, fixed seed
TEST_SEED=random npm test   # a new order each time
npm run typecheck
npm run mutation            # plants bugs in src/ and checks the tests catch at least 90%
```

## License

Apache-2.0.
