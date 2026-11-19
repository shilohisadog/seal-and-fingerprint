// The context names where a sealed value belongs (for example shop, purpose, record). It's sent to the key service
// and also checked by the local encryption, so a value copied anywhere else won't open.
import { CryptoError } from "./errors.ts";

export type Context = Readonly<Record<string, string>>;

const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
// eslint-disable-next-line no-control-regex -- control characters are exactly what's refused
const CONTROL = /[\u0000-\u001f\u007f]/;
export const MAX_ENTRIES = 8;
export const MAX_VALUE = 256;

/** Checks the context and returns its one canonical spelling (names sorted). Throws bad-context. */
export function canonical(context: Context): string {
  const entries = Object.entries(context);
  if (entries.length === 0 || entries.length > MAX_ENTRIES) throw new CryptoError("bad-context");
  for (const [name, value] of entries) {
    if (!NAME.test(name) || typeof value !== "string" || value.length === 0 || value.length > MAX_VALUE || CONTROL.test(value)) {
      throw new CryptoError("bad-context");
    }
  }
  // Sorted by name: each entry sorts as "name,value", and a comma sorts before every character a name may contain.
  return JSON.stringify(entries.sort());
}

/** The checked data (AAD) for a purpose: a label, then the canonical context. */
export function checkedData(label: string, context: Context): Uint8Array {
  return new TextEncoder().encode(`${label}\n${canonical(context)}`);
}
