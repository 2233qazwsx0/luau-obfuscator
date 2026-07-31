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
 * Pack a serialized function blob: stream encrypt + hex encode.
 *
 * v0.8 性能修复：移除 LZW 压缩层（bi 层去重）。LZW 在运行时需要重建 256 项字典
 * + 逐 code 字符串拼接，是 Roblox 脚本超时的主要瓶颈。仅保留 stream cipher
 * (XOR 变换) 后整个解密链开销可忽略。
 *
 * `useLZW` 参数保留只是为了向后兼容（测试 / 旧调用方），实际被忽略——始终不压缩。
 *
 * @param serializedFunc The binary string from serializeFunction()
 * @param key The position-dependent cipher key
 * @param useLZW (deprecated v0.8) 不再压缩，参数被忽略
 * @returns Hex string ready for embedding in the Lua runtime
 */
export declare function packBytecode(serializedFunc: string, key: number, useLZW?: boolean): string;
/**
 * Pack to the xor512 stage (stream + xor512), WITHOUT hex encoding.
 * v0.10 rt_deps：pipeline 用此函数获取中间二进制串，从中算出 hexLen → rtToken，
 * 再用 packRtMixHex() 追加 rt_mix 层。xor512 / rt_mix 均保长，hexLen 不依赖 KEY。
 *
 * v0.8：移除 LZW 步骤（与 packBytecode 一致）。`useLZW` 参数仅为向后兼容，被忽略。
 *
 * @returns xor512 后的二进制串（尚未 hex 编码）
 */
export declare function packToXor512Stage(serializedFunc: string, key: number, keyBytes: number[], useLZW?: boolean): string;
/**
 * 在 xor512 二进制串上追加 rt_mix 层 + hex 编码（v0.10 Feature 4）。
 * v0.8：移除 LZW 步骤后，运行时逆向：hex → hex_to_bytes → rt_mix_decrypt → xor_bytes_512 → stream_decrypt。
 */
export declare function packRtMixHex(xorData: string, rtToken: number): string;
/**
 * Pack with an additional 512-bit XOR outer layer (v0.9 keyfuse).
 * v0.8 性能修复：移除 LZW 步骤。
 * Pipeline: serialize → streamEncrypt(8位) → xor512(512位) → hex.
 * 运行时逆向：hex → hex_to_bytes → xor_bytes_512 → stream_decrypt。
 *
 * @param serializedFunc The binary string from serializeFunction()
 * @param key           8 位 stream cipher key
 * @param keyBytes      512 位（64 字节）XOR 密钥
 * @param useLZW        (deprecated v0.8) 不再压缩，参数被忽略
 */
export declare function packBytecodeKeyfused(serializedFunc: string, key: number, keyBytes: number[], useLZW?: boolean): string;
/**
 * Unpack a hex string back to the original serialized function blob.
 *
 * v0.8：`useLZW` 参数仅为向后兼容，被忽略（不再 LZW 解压）。
 *
 * @param hex The hex string from packBytecode()
 * @param key The position-dependent cipher key
 * @param useLZW (deprecated v0.8) 不再解压，参数被忽略
 * @returns The binary string (serialized function)
 */
export declare function unpackBytecode(hex: string, key: number, useLZW?: boolean): string;
/**
 * Unpack with the 512-bit XOR outer layer (inverse of packBytecodeKeyfused).
 *
 * v0.8：`useLZW` 参数仅为向后兼容，被忽略。
 */
export declare function unpackBytecodeKeyfused(hex: string, key: number, keyBytes: number[], useLZW?: boolean): string;
