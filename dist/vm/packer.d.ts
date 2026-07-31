/**
 * LZW-compress a string into the reference's base-36 format.
 *
 * The reference's N(O) decoder:
 *   - Dictionary starts at 256 (codes 0-255 = single chars)
 *   - W() reads a variable-length base-36 number:
 *     - Read 1 char as base-36 → get length X
 *     - Read X chars as base-36 → get the dictionary code
 *   - First code is the initial "previous" entry
 *   - For each subsequent code Z:
 *     - If Z < dictionary size: output = dict[Z]
 *     - Else: output = prev + first_char(prev)
 *     - Add prev + first_char(output) to dictionary
 *     - prev = output
 *   - Concatenate all outputs
 *
 * The encoder must produce output that this decoder can read.
 */
export declare function lzwCompress(input: string): string;
/**
 * LZW-decompress a string in the reference's base-36 format.
 * This is the inverse of lzwCompress and mirrors the reference's N(O) decoder.
 */
export declare function lzwDecompress(compressed: string): string;
/**
 * XOR/stream-cipher encrypt a binary string.
 * This mirrors the reference's aT() in reverse (encrypt = add, decrypt = subtract).
 *
 * @param data The binary string to encrypt
 * @param key The position-dependent key parameter (a number)
 * @returns The encrypted string (same length, each byte modified)
 */
export declare function streamEncrypt(data: string, key: number): string;
/**
 * XOR/stream-cipher decrypt a binary string.
 * Mirrors the reference's aT() function exactly.
 *
 * @param data The encrypted binary string
 * @param key The position-dependent key parameter
 * @returns The decrypted string
 */
export declare function streamDecrypt(data: string, key: number): string;
/**
 * Convert a binary string to uppercase hex string (for embedding in Lua).
 * Each byte → 2 hex chars, concatenated without separators.
 */
export declare function bytesToHex(data: string): string;
/**
 * Convert a hex string back to binary string.
 * This mirrors the reference's aW() function.
 */
export declare function hexToBytes(hex: string): string;
/**
 * XOR a single byte with a key byte. Mirrors a0() in the reference.
 */
export declare function xorByte(byte: number, key: number): number;
/**
 * Pack a serialized function blob: LZW compress + stream encrypt + hex encode.
 *
 * @param serializedFunc The binary string from serializeFunction()
 * @param key The position-dependent cipher key
 * @param useLZW Whether to apply LZW compression (can be disabled for debugging)
 * @returns Hex string ready for embedding in the Lua runtime
 */
export declare function packBytecode(serializedFunc: string, key: number, useLZW?: boolean): string;
/**
 * Pack with an additional 512-bit XOR outer layer (v0.9 keyfuse).
 * Pipeline: serialize → LZW → streamEncrypt(8位) → xor512(512位) → hex.
 * 运行时逆向：hex → hex_to_bytes → xor_bytes_512 → stream_decrypt → lzw_decode。
 *
 * @param serializedFunc The binary string from serializeFunction()
 * @param key           8 位 stream cipher key
 * @param keyBytes      512 位（64 字节）XOR 密钥
 * @param useLZW        是否 LZW 压缩
 */
export declare function packBytecodeKeyfused(serializedFunc: string, key: number, keyBytes: number[], useLZW?: boolean): string;
/**
 * Unpack a hex string back to the original serialized function blob.
 *
 * @param hex The hex string from packBytecode()
 * @param key The position-dependent cipher key
 * @param useLZW Whether LZW compression was applied
 * @returns The binary string (serialized function)
 */
export declare function unpackBytecode(hex: string, key: number, useLZW?: boolean): string;
/**
 * Unpack with the 512-bit XOR outer layer (inverse of packBytecodeKeyfused).
 */
export declare function unpackBytecodeKeyfused(hex: string, key: number, keyBytes: number[], useLZW?: boolean): string;
