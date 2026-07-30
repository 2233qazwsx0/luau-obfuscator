import { type Token } from "../parser/tokens.js";
export interface StringCipher {
    /** master key, encoded as uppercase hex (4 bytes = 8 hex chars). */
    masterKeyHex: string;
    /** per-string encrypted blobs as uppercase hex. */
    pool: {
        id: number;
        hex: string;
    }[];
}
/** Build the cipher metadata (master key + empty pool) seeded. */
export declare function buildCipher(seed: number): StringCipher;
/**
 * Encrypt a single string `s` with `key` (4 bytes), return hex.
 * Mirrors the reference sample's `aT`/`aW` chain:
 *   cipher[i] = (plain[i] ^ key[(i + (i+1))%4]) & 0xff  (rotating + offset)
 */
declare function encryptString(s: string, key: number[]): string;
/** Apply encryption to all STRING tokens, accumulating into `cipher.pool`. */
export declare function obfuscateStrings(tokens: Token[], cipher: StringCipher, seed: number): Token[];
export { encryptString };
/** Decrypt a single encrypted blob (for tests / decrypt). */
export declare function decryptString(hex: string, key: number[]): string;
