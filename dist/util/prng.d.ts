export declare function mulberry32(seed: number): () => number;
/** Integer in [0, max). */
export declare function randInt(rng: () => number, max: number): number;
/** Generate a single uint8 in [0, 256). */
export declare function randByte(rng: () => number): number;
/**
 * Produces an array of `n` random bytes deterministically from the given rng.
 */
export declare function randBytes(rng: () => number, n: number): number[];
/**
 * xor a buffer (in place) against an iterable of bytes; key cycles if shorter.
 */
export declare function xorInPlace(buf: Buffer | Uint8Array, key: number[]): void;
/**
 * Same as xorInPlace but also re-encodes as hex string.
 */
export declare function xorToHex(input: string, key: number[]): string;
/**
 * Inverse of xorToHex — input is a hex string.
 */
export declare function xorFromHex(hex: string, key: number[]): string;
