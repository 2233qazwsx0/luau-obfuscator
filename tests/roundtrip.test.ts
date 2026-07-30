// tests/roundtrip.test.ts — Cipher roundtrip: encrypt → decrypt should match.
import { describe, it, expect } from "vitest";
import { encryptString, decryptString, buildCipher } from "../src/transforms/strings.js";

describe("cipher", () => {
  it("encrypts and decrypts round-trip", () => {
    const cipher = buildCipher(123);
    const key = Buffer.from(cipher.masterKeyHex, "hex");
    const samples = ["hello", "world", "luau", "🔥 emoji 🔥", "longer string with spaces"];
    for (const s of samples) {
      const enc = encryptString(s, Array.from(key));
      const dec = decryptString(enc, Array.from(key));
      expect(dec).toBe(s);
    }
  });

  it("produces different cipher keys for different seeds", () => {
    const a = buildCipher(1);
    const b = buildCipher(2);
    expect(a.masterKeyHex).not.toBe(b.masterKeyHex);
  });

  it("produces the same cipher key for the same seed", () => {
    expect(buildCipher(42).masterKeyHex).toBe(buildCipher(42).masterKeyHex);
  });
});