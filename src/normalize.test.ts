// One standard form per phone or email. 555-01xx numbers are reserved for fiction.
import { fc, test } from "@fast-check/vitest";
import { describe, expect, it } from "vitest";
import { type Country, normalizeEmail, normalizePhone } from "./normalize.ts";

describe("Phone numbers: North America", () => {
  const same = ["(512) 555-0100", "512-555-0100", "512.555.0100", "512 555 0100", "5125550100", "1 512 555 0100", "1-512-555-0100", "+1 512 555 0100", "+1 (512) 555-0100", "+15125550100", "011 1 512 555 0100", " ５１２-５５５-０１００ ", "512/555-0100"];
  for (const raw of same) {
    it(`reads "${raw}" as +15125550100`, () => {
      expect(normalizePhone(raw, "US")).toBe("+15125550100");
    });
  }

  it("reads Canada the same way (one numbering plan)", () => {
    expect(normalizePhone("(416) 555-0100", "CA")).toBe("+14165550100");
    expect(normalizePhone("1 (416) 555-0100", "CA")).toBe("+14165550100");
  });

  it("reads a Mexican number written with its country code", () => {
    expect(normalizePhone("+52 55 1234 5678", "US")).toBe("+525512345678");
    expect(normalizePhone("011 52 55 1234 5678", "US")).toBe("+525512345678");
  });

  it("keeps another country's number as written when it has its +: 8 to 15 digits", () => {
    expect(normalizePhone("+44 20 7946 0000", "US")).toBe("+442079460000");
    expect(normalizePhone(" +44 20 7946 0000", "US")).toBe("+442079460000");
    expect(normalizePhone("+44 123456", "US")).toBe("+44123456");
    expect(normalizePhone("+44 12345", "US")).toBeNull();
    expect(normalizePhone("+44 1234567890123", "US")).toBe("+441234567890123");
    expect(normalizePhone("+44 12345678901234", "US")).toBeNull();
  });

  const unreadable = ["", "   ", "555-0100", "(512) 555-010", "512 555 01000", "2 512 555 0100", "(112) 555-0100", "(512) 155-0100", "(012) 555-0100", "512-555-0100 ext 12", "512-555-0100 x12", "1-800-FLOWERS", "+1 512 555 010", "+1 112 555 0100", "+44 1234", "+0 1234 5678 90", "+1234567890123456", "512+555+0100", "5125550100#", "tel:5125550100", "+52 55 1234 567", "+52 1 55 1234 567", "+52 05 1234 5678"];
  for (const raw of unreadable) {
    it(`can't read "${raw}" with certainty, so gives nothing (never a guess)`, () => {
      expect(normalizePhone(raw, "US")).toBeNull();
    });
  }

  it("refuses a country it doesn't read, or something that isn't text", () => {
    expect(normalizePhone("5125550100", "GB" as Country)).toBeNull();
    expect(normalizePhone(5125550100 as unknown as string, "US")).toBeNull();
  });
});

describe("Phone numbers: Mexico", () => {
  const same = ["55 1234 5678", "5512345678", "(55) 1234-5678", "+52 55 1234 5678", "+52 1 55 1234 5678", "+5215512345678", "52 55 1234 5678", "521 55 1234 5678", "01 55 1234 5678", "044 55 1234 5678", "045 55 1234 5678", "00 52 55 1234 5678"];
  for (const raw of same) {
    it(`reads "${raw}" as +525512345678 (old and new ways of writing it)`, () => {
      expect(normalizePhone(raw, "MX")).toBe("+525512345678");
    });
  }

  it("reads a US number written with its country code", () => {
    expect(normalizePhone("+1 512 555 0100", "MX")).toBe("+15125550100");
    expect(normalizePhone("00 1 512 555 0100", "MX")).toBe("+15125550100");
  });

  for (const raw of ["15 1234 5678", "55 1234 567", "046 55 1234 5678", "02 55 1234 5678", "53 55 1234 5678", "522 55 1234 5678", "1 512 555 0100", "011 1 512 555 0100"]) {
    it(`can't read "${raw}" with certainty in Mexico`, () => {
      expect(normalizePhone(raw, "MX")).toBeNull();
    });
  }
});

describe("Phone numbers: properties", () => {
  const areaOrExchange = fc.integer({ min: 200, max: 999 }).map(String);
  const line = fc.integer({ min: 0, max: 9999 }).map((n) => String(n).padStart(4, "0"));
  const sep = fc.constantFrom("", " ", "-", ".", " - ");

  test.prop([areaOrExchange, areaOrExchange, line, sep, sep, fc.constantFrom("", "1 ", "+1 ", "+1-", "1-")])(
    "formatting never changes the result", (area, exchange, last, s1, s2, lead) => {
      const plain = normalizePhone(`${area}${exchange}${last}`, "US");
      expect(plain).toBe(`+1${area}${exchange}${last}`);
      expect(normalizePhone(`${lead}(${area})${s1}${exchange}${s2}${last}`, "US")).toBe(plain);
    });

  test.prop([fc.string()])("anything at all gives a number in international form, or nothing", (raw) => {
    for (const c of ["US", "MX"] as const) {
      const r = normalizePhone(raw, c);
      if (r !== null) expect(r).toMatch(/^\+[1-9]\d{7,14}$/);
    }
  });
});

describe("Emails: exact address, ignoring case and spaces", () => {
  for (const raw of ["J.Doe@Gmail.com", " j.doe@gmail.com ", "J.DOE@GMAIL.COM", "j.doe@gmail.com"]) {
    it(`reads "${raw}" as j.doe@gmail.com`, () => {
      expect(normalizeEmail(raw)).toBe("j.doe@gmail.com");
    });
  }

  it("keeps dots and +tags: jdoe and j.doe+jobs are different addresses", () => {
    expect(normalizeEmail("jdoe@gmail.com")).toBe("jdoe@gmail.com");
    expect(normalizeEmail("j.doe+jobs@gmail.com")).toBe("j.doe+jobs@gmail.com");
  });

  it("spells an international domain one way, however it was written", () => {
    expect(normalizeEmail("ana@MÜNCHEN.de")).toBe("ana@xn--mnchen-3ya.de");
    expect(normalizeEmail("ana@xn--mnchen-3ya.de")).toBe("ana@xn--mnchen-3ya.de");
  });

  it("treats a letter written as one character or as letter plus accent as the same", () => {
    expect(normalizeEmail("josé@x.mx")).toBe(normalizeEmail("josé@x.mx"));
  });

  const unreadable = ["", "plain", "@x.com", "a@", "a@x", "a@@x.com", "a@b@x.com", "a b@x.com", "Ana <a@x.com>", "a@x.com, b@x.com", "a@x..com", "a@.x.com", "a@x.com.", "a@x_y.com", `${"a".repeat(65)}@x.com`, `a@${"x".repeat(250)}.com`, "mailto:a@x.com", "a@[1.2.3.4]"];
  for (const raw of unreadable) {
    it(`can't read "${raw}" as one plain address, so gives nothing`, () => {
      expect(normalizeEmail(raw)).toBeNull();
    });
  }

  it("accepts a one-letter name, a domain with several dots, and the longest address (254)", () => {
    expect(normalizeEmail("a@x.com")).toBe("a@x.com");
    expect(normalizeEmail("ana@mail.rivera.com.mx")).toBe("ana@mail.rivera.com.mx");
    const domain = `${"b".repeat(60)}.${"b".repeat(60)}.${"b".repeat(60)}.comxyz`; // 189
    expect(normalizeEmail(`${"a".repeat(64)}@${domain}`)).toHaveLength(254);
    expect(normalizeEmail(`${"a".repeat(64)}@${domain}z`)).toBeNull();
  });

  it("accepts the longest local part (64)", () => {
    expect(normalizeEmail(`${"a".repeat(64)}@x.com`)).toBe(`${"a".repeat(64)}@x.com`);
  });

  it("refuses hidden characters (controls, zero-width, direction marks): they'd split one address into two", () => {
    for (const hidden of ["\u0000", "\u0007", "\u007f", "\u200b", "\u200d", "\u202e", "\ufeff"]) {
      expect(normalizeEmail(`a${hidden}na@x.com`)).toBeNull();
    }
  });

  it("refuses something that isn't text", () => {
    expect(normalizeEmail(null as unknown as string)).toBeNull();
  });

  test.prop([fc.emailAddress()])("any address reads the same however its case is written", (e) => {
    const r = normalizeEmail(e);
    if (r !== null) {
      expect(normalizeEmail(e.toUpperCase())).toBe(r);
      expect(normalizeEmail(`  ${e}\t`)).toBe(r);
    }
  });
});
