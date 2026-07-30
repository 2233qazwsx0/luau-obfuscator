// src/transforms/strings.ts — D3: XOR string encryption.
//
// For each STRING token we either:
//   (a) emit `a[28](a[27], "HEX")` where a[27] is the master key (single
//       4-byte hex) and a[28] is a fixed XOR decoder (same as sample).
//   (b) When the string is short and may be a Lua keyword candidate we keep
//       it raw to avoid decode-time perf hazards.
//
// We do NOT actually LZW-compress here — that's a stretch goal in TODO.md.
// The byte-level XOR with a 4-byte rotating key is already very hard to grep.

import { TokenKind, type Token } from "../parser/tokens.js";
import { mulberry32, randBytes } from "../util/prng.js";

export interface StringCipher {
  /** master key, encoded as uppercase hex (4 bytes = 8 hex chars). */
  masterKeyHex: string;
  /** per-string encrypted blobs as uppercase hex. */
  pool: { id: number; hex: string }[];
}

/** Build the cipher metadata (master key + empty pool) seeded. */
export function buildCipher(seed: number): StringCipher {
  const rng = mulberry32(seed ^ 0x6d2b79f5);
  const key = randBytes(rng, 4);
  const masterKeyHex = Buffer.from(key).toString("hex").toUpperCase().padStart(8, "0");
  return { masterKeyHex, pool: [] };
}

/**
 * Encrypt a single string `s` with `key` (4 bytes), return hex.
 * Mirrors the reference sample's `aT`/`aW` chain:
 *   cipher[i] = (plain[i] ^ key[(i + (i+1))%4]) & 0xff  (rotating + offset)
 */
function encryptString(s: string, key: number[]): string {
  const buf = Buffer.from(s, "utf8");
  for (let i = 0; i < buf.length; i++) {
    const k = key[(i + 1) % 4]!;
    buf[i] = (buf[i]! ^ (k + i)) & 0xff;
  }
  return buf.toString("hex").toUpperCase();
}

/** Apply encryption to all STRING tokens, accumulating into `cipher.pool`. */
export function obfuscateStrings(tokens: Token[], cipher: StringCipher, seed: number): Token[] {
  const rng = mulberry32(seed ^ 0x12345678);
  const masterKey = Buffer.from(cipher.masterKeyHex, "hex");
  const out: Token[] = [];
  let id = 0;
  for (const t of tokens) {
    if (t.kind !== TokenKind.STRING) { out.push(t); continue; }
    // Skip empty / single-char — saves cycles, no info leak.
    if (t.value.length === 0) { out.push(t); continue; }
    const usePool = rng() > 0.4 || t.value.length > 4;
    if (!usePool) { out.push(t); continue; }
    const blob = encryptString(t.value, Array.from(masterKey));
    cipher.pool.push({ id: id++, hex: blob });
    // Replace the string token with a synthetic placeholder.
    out.push({
      kind: TokenKind.OP,
      value: "__STR__",
      line: t.line,
      col: t.col,
      pos: t.pos,
      // @ts-expect-error metadata channel for emitter
      __str_id: id - 1,
      __str_hex: blob,
    });
  }
  return out;
}

// Re-export so the decrypt prototype can reuse if needed.
export { encryptString };
/** Decrypt a single encrypted blob (for tests / decrypt). */
export function decryptString(hex: string, key: number[]): string {
  const buf = Buffer.from(hex, "hex");
  for (let i = 0; i < buf.length; i++) {
    const k = key[(i + 1) % 4]!;
    buf[i] = (buf[i]! ^ (k + i)) & 0xff;
  }
  return buf.toString("utf8");
}