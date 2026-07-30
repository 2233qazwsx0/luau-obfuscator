// src/util/prng.ts — Mulberry32 PRNG (32-bit seed) + key chain helpers.
// Deterministic, offline. Used by identifier / number / string transforms.
export function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
/** Integer in [0, max). */
export function randInt(rng, max) {
    return Math.floor(rng() * max);
}
/** Generate a single uint8 in [0, 256). */
export function randByte(rng) {
    return Math.floor(rng() * 256);
}
/**
 * Produces an array of `n` random bytes deterministically from the given rng.
 */
export function randBytes(rng, n) {
    const out = new Array(n);
    for (let i = 0; i < n; i++)
        out[i] = randByte(rng);
    return out;
}
/**
 * xor a buffer (in place) against an iterable of bytes; key cycles if shorter.
 */
export function xorInPlace(buf, key) {
    for (let i = 0; i < buf.length; i++) {
        buf[i] = (buf[i] ^ key[i % key.length]) & 0xff;
    }
}
/**
 * Same as xorInPlace but also re-encodes as hex string.
 */
export function xorToHex(input, key) {
    const buf = Buffer.from(input, "utf8");
    xorInPlace(buf, key);
    return buf.toString("hex").toUpperCase();
}
/**
 * Inverse of xorToHex — input is a hex string.
 */
export function xorFromHex(hex, key) {
    const buf = Buffer.from(hex, "hex");
    xorInPlace(buf, key);
    return buf.toString("utf8");
}
//# sourceMappingURL=prng.js.map