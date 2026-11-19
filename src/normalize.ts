// One standard form per phone number or email, so two tools that write the same one differently produce the same
// fingerprint. A value that can't be read with certainty gives null: never a guess.
import { domainToASCII } from "node:url";

/** The countries whose numbers are read without a +country code: North America (+1) and Mexico (+52). */
export type Country = "US" | "CA" | "MX";
export const COUNTRIES: readonly Country[] = ["US", "CA", "MX"];

// Digits with the usual separators, and an optional + in front. Anything else (letters, "ext", "#") is unreadable.
const PHONE_CHARS = /^\+?[\d\s\-.()/]+$/;
const NANP = /^[2-9]\d{2}[2-9]\d{6}$/; // area code and exchange never start with 0 or 1
const MEXICO = /^[2-9]\d{9}$/; // ten digits since 2019; area codes start with 2-9

const nanp = (n: string) => (NANP.test(n) ? `+1${n}` : null);
const mexico = (n: string) => (MEXICO.test(n) ? `+52${n}` : null);

/** The first prefix that, dropped, leaves a valid number. Each check above demands exactly ten digits. */
const firstReading = (digits: string, prefixes: readonly string[], read: (n: string) => string | null) =>
  prefixes.map((p) => (digits.startsWith(p) ? read(digits.slice(p.length)) : null)).find((r) => r !== null) ?? null;

// Ways a number is written at home, each with what to drop. North America: nothing, or the leading 1. Mexico:
// nothing; the old long-distance 01 and mobile 044/045 (gone since 2019); the country code without its +, with or
// without the old mobile 1 (+52 1 …). Mexican numbers never start with 0 or 1, so no two readings can both succeed.
const AT_HOME: Readonly<Record<Country, readonly string[]>> = { US: ["", "1"], CA: ["", "1"], MX: ["", "01", "044", "045", "52", "521"] };

/** digits: everything after the + (or after an international dialing prefix). */
function international(digits: string): string | null {
  if (digits.startsWith("1")) return nanp(digits.slice(1));
  if (digits.startsWith("52")) return firstReading(digits, ["52", "521"], mexico); // +52 1 …: the pre-2019 mobile form
  // Other countries: kept as written (E.164 allows up to 15 digits; 8 is the shortest we accept).
  return digits.length >= 8 && digits.length <= 15 && !digits.startsWith("0") ? `+${digits}` : null;
}

/** A phone number in international form (+15125550100), or null if it can't be read with certainty. */
export function normalizePhone(raw: string, country: Country): string | null {
  if (typeof raw !== "string" || !COUNTRIES.includes(country)) return null;
  const s = raw.normalize("NFKC").trim(); // NFKC turns full-width digits into ordinary ones
  if (!PHONE_CHARS.test(s)) return null;
  const digits = s.replace(/\D/g, "");
  if (s.startsWith("+")) return international(digits);
  // Dialling abroad without the +: 011 from North America, 00 from Mexico.
  const abroad = country === "MX" ? "00" : "011";
  if (digits.startsWith(abroad)) return international(digits.slice(abroad.length));
  return firstReading(digits, AT_HOME[country], country === "MX" ? mexico : nanp);
}

/**
 * An email in one standard form: Unicode-normalised, trimmed, lower-cased, the domain in its ASCII spelling.
 * Nothing provider-specific: Gmail ignores dots and +tags, most providers don't, so applying
 * Gmail's rules everywhere would merge different people. null if it isn't a single plain address.
 */
export function normalizeEmail(raw: string): string | null {
  if (typeof raw !== "string") return null;
  const s = raw.normalize("NFC").trim().toLowerCase();
  // Hidden characters (controls, zero-width, direction marks) would make one address look like two.
  if (s.length > 254 || /[\s<>"(),;:[\]\\]|[\p{Cc}\p{Cf}]/u.test(s)) return null;
  const at = s.indexOf("@"); // a second @ lands in the domain, which refuses it
  if (at < 1) return null;
  const local = s.slice(0, at);
  const domain = domainToASCII(s.slice(at + 1));
  if (local.length > 64 || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) return null;
  return `${local}@${domain}`;
}
