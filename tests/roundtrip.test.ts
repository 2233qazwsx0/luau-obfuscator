// tests/roundtrip.test.ts — Cipher roundtrip: encrypt → decrypt should match.
import { describe, it, expect } from "vitest";
import { encryptString, decryptString, deriveStringKey, STRING_KEY_BYTES } from "../src/transforms/strings.js";

describe("cipher", () => {
  it("encrypts and decrypts round-trip with per-string keys", () => {
    const samples = ["hello", "world", "luau", "🔥 emoji 🔥", "longer string with spaces"];
    for (let strId = 0; strId < samples.length; strId++) {
      const key = deriveStringKey(123, strId);
      expect(key.length).toBe(STRING_KEY_BYTES);
      const enc = encryptString(samples[strId]!, key);
      const dec = decryptString(enc, key);
      expect(dec).toBe(samples[strId]);
    }
  });

  it("produces different keys for different string ids", () => {
    const a = deriveStringKey(42, 0);
    const b = deriveStringKey(42, 1);
    expect(a).not.toEqual(b);
  });

  it("produces different keys for different seeds", () => {
    const a = deriveStringKey(1, 0);
    const b = deriveStringKey(2, 0);
    expect(a).not.toEqual(b);
  });

  it("is deterministic for the same seed + strId", () => {
    expect(deriveStringKey(42, 7)).toEqual(deriveStringKey(42, 7));
  });

  it("different keys produce different ciphertext for the same plaintext", () => {
    const k1 = deriveStringKey(1, 0);
    const k2 = deriveStringKey(2, 0);
    const s = "same plaintext";
    expect(encryptString(s, k1)).not.toBe(encryptString(s, k2));
  });

  it("rejects keys of wrong length", () => {
    expect(() => encryptString("x", [1, 2, 3, 4])).toThrow();
    expect(() => decryptString("00", [1, 2, 3, 4])).toThrow();
  });

  it("rolling factor makes cipher bytes vary even for repeated plaintext bytes", () => {
    // Same byte repeated: with rolling factor, cipher bytes should NOT all be equal.
    const key = deriveStringKey(99, 0);
    const enc = encryptString("AAAAAAAAAAAAAAAA", key);
    const bytes = Buffer.from(enc, "hex");
    const allSame = bytes.every((b) => b === bytes[0]);
    expect(allSame).toBe(false);
  });

  it("emitted Lua IIFE formula matches TS encryptString", () => {
    // Mirror the exact Lua IIFE emitted by emitter.ts to verify the inlined
    // decryptor produces the original plaintext. Without luau available, this
    // is the only way to catch formula mismatches (precedence, indexing).
    function luaIIFE(hex: string, K: number[]): string {
      // local R=_B(K[1],K[6])
      let R = (K[0] ^ K[5]) >>> 0;
      let O = "";
      // for i=1,#H,2 do local j=(i+1)/2-1
      for (let i = 1; i <= hex.length; i += 2) {
        const j = (i + 1) / 2 - 1; // 0-based byte index
        // tonumber(H:sub(i,i+1),16)
        const byte = parseInt(hex.substring(i - 1, i + 1), 16);
        // _B(_B(byte, (K[(j%6)+1]+j)%256), R%256) % 256
        const k = K[(j % 6)]!; // Lua K[(j%6)+1] → 0-based K[j%6]
        const dec = ((byte ^ ((k + j) & 0xff)) ^ (R & 0xff)) & 0xff;
        O += String.fromCharCode(dec);
        // R=(R*1664525+1013904223)%4294967296
        R = (Math.imul(R, 1664525) + 1013904223) >>> 0;
      }
      return O;
    }
    const samples = ["hello", "world 🌍", "mixed CASE 123", "x".repeat(50)];
    for (let id = 0; id < samples.length; id++) {
      const key = deriveStringKey(2024, id);
      const blob = encryptString(samples[id]!, key);
      // The Lua side decodes bytes; compare against the UTF-8 byte sequence.
      const expected = Buffer.from(samples[id]!, "utf8").toString("binary");
      expect(luaIIFE(blob, key)).toBe(expected);
    }
  });
});
