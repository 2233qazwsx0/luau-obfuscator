// src/vm/packer.ts — LZW compression + position-dependent XOR encryption.
//
// Faithfully mirrors the reference sample's:
//   - N(O): LZW decoder (dictionary starts at 256, output is a string)
//   - aT(U, aU): XOR stream cipher with position-dependent key
//   - aW(aX): hex string splitter → byte array → char concat
//   - a0(a1, b): bit32.xor helper (key = 156 in the reference)
//
// The packing pipeline is:
//   serializeFunction() → binary string → LZW compress → XOR encrypt → hex string
//
// At runtime, the Luau interpreter reverses this:
//   hex string → XOR decrypt → LZW decompress → bytecode string → b3() decoder
import { rtMixEncrypt } from "./rtdeps.js";
// ---- LZW Compression ----
// Mirrors the reference's N(O) decoder in reverse.
// The reference's LZW uses base-36 encoding for dictionary indices,
// with a variable-length scheme. We implement a compatible encoder.
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
export function lzwCompress(input) {
    if (input.length === 0)
        return "";
    // Build dictionary: codes 0-255 are single characters
    const dict = new Map();
    for (let i = 0; i < 256; i++) {
        dict.set(String.fromCharCode(i), i);
    }
    let nextCode = 256;
    // Compress: produce a sequence of dictionary codes
    const codes = [];
    let prev = "";
    for (let i = 0; i < input.length; i++) {
        const ch = input[i];
        const combined = prev + ch;
        if (dict.has(combined)) {
            prev = combined;
        }
        else {
            codes.push(dict.get(prev));
            dict.set(combined, nextCode++);
            prev = ch;
        }
    }
    if (prev.length > 0)
        codes.push(dict.get(prev));
    // Encode codes into base-36 variable-length format matching W():
    //   For each code: write length as 1 base-36 digit, then the code as that many base-36 digits
    let result = "";
    for (const code of codes) {
        // Convert code to base-36 string
        const codeStr = code.toString(36);
        // Length = number of base-36 digits needed
        const len = codeStr.length;
        // Write length as a single base-36 digit (max 35 for single digit)
        // For codes needing > 35 digits, this won't happen in practice (codes < 2^52)
        result += len.toString(36);
        // Write the code digits
        result += codeStr;
    }
    return result;
}
/**
 * LZW-decompress a string in the reference's base-36 format.
 * This is the inverse of lzwCompress and mirrors the reference's N(O) decoder.
 */
export function lzwDecompress(compressed) {
    if (compressed.length === 0)
        return "";
    // Dictionary starts at 256
    const dict = new Array(256);
    for (let i = 0; i < 256; i++)
        dict[i] = String.fromCharCode(i);
    let pos = 1; // skip the initial code reading position
    // Read codes using the W() function logic:
    //   Read 1 base-36 char → length X
    //   Read X base-36 chars → code
    function readCode() {
        const lenChar = compressed[pos - 1];
        const len = parseInt(lenChar, 36);
        pos++;
        const codeStr = compressed.substring(pos - 1, pos - 1 + len);
        pos += len;
        return parseInt(codeStr, 36);
    }
    // First code is the initial entry
    const firstCode = readCode();
    let prev = String.fromCharCode(firstCode);
    let result = prev;
    let nextCode = 256;
    while (pos <= compressed.length) {
        const code = readCode();
        let entry;
        if (code < nextCode) {
            entry = dict[code];
        }
        else if (code === nextCode) {
            entry = prev + prev[0];
        }
        else {
            throw new Error(`LZW decompress: invalid code ${code} at dict size ${nextCode}`);
        }
        result += entry;
        dict[nextCode] = prev + entry[0];
        nextCode++;
        prev = entry;
    }
    return result;
}
// ---- XOR Stream Cipher (position-dependent) ----
// Mirrors the reference's aT(U, aU) function:
//   for V = 1 to #aU:
//     P = byte(aU, V) - (U + V) % 256
//     if P < 0: P += 256
//     output = output .. char(P)
//
// Where U is the cipher key parameter and aU is the hex-decoded key bytes.
//
// The reference uses a8-style bit operations, but the core is:
//   decrypted[i] = encrypted[i] ^ key_byte XOR (key_param + i) % 256
//
// Actually, looking more carefully at aT():
//   P = I(aU, V, V) - (U + V) % 256
//   if P < 0 then P = P + 256
// This is SUBTRACTION, not XOR. The reverse (encryption) is ADDITION.
//   encrypt[i] = plain[i] + (key + i + 1) % 256  (1-indexed)
//   decrypt[i] = cipher[i] - (key + i + 1) % 256
/**
 * XOR/stream-cipher encrypt a binary string.
 * This mirrors the reference's aT() in reverse (encrypt = add, decrypt = subtract).
 *
 * @param data The binary string to encrypt
 * @param key The position-dependent key parameter (a number)
 * @returns The encrypted string (same length, each byte modified)
 */
export function streamEncrypt(data, key) {
    const bytes = Buffer.from(data, "binary");
    const out = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        // 1-indexed in the reference: V = i + 1
        const v = i + 1;
        const p = (bytes[i] + ((key + v) % 256)) & 0xFF;
        out[i] = p;
    }
    return out.toString("binary");
}
/**
 * XOR/stream-cipher decrypt a binary string.
 * Mirrors the reference's aT() function exactly.
 *
 * @param data The encrypted binary string
 * @param key The position-dependent key parameter
 * @returns The decrypted string
 */
export function streamDecrypt(data, key) {
    const bytes = Buffer.from(data, "binary");
    const out = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        const v = i + 1;
        let p = bytes[i] - ((key + v) % 256);
        if (p < 0)
            p += 256;
        out[i] = p;
    }
    return out.toString("binary");
}
// ---- Hex string helpers ----
// The reference uses aW(aX) to split a hex string into bytes:
//   return L(aX, '..', function(aY) return G(M(aY, 16) % 256) end)
// Which is: split by '..', parse each chunk as hex, convert to char.
/**
 * Convert a binary string to uppercase hex string (for embedding in Lua).
 * Each byte → 2 hex chars, concatenated without separators.
 */
export function bytesToHex(data) {
    return Buffer.from(data, "binary").toString("hex").toUpperCase();
}
/**
 * Convert a hex string back to binary string.
 * This mirrors the reference's aW() function.
 */
export function hexToBytes(hex) {
    return Buffer.from(hex, "hex").toString("binary");
}
// ---- Bit32 XOR helper (for bytecode reading) ----
// The reference uses a0(a1, b) which is a simple bit-xor.
// In the bytecode reader, every byte is XOR'd with key (156 in reference).
/**
 * XOR a single byte with a key byte. Mirrors a0() in the reference.
 */
export function xorByte(byte, key) {
    let result = 0;
    let a = byte;
    let b = key;
    let bit = 1;
    while (a > 0 || b > 0) {
        if ((a % 2) !== (b % 2))
            result += bit;
        a = Math.floor(a / 2);
        b = Math.floor(b / 2);
        bit *= 2;
    }
    return result;
}
// ---- Full packing pipeline ----
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
export function packBytecode(serializedFunc, key, useLZW = false) {
    void useLZW; // v0.8: LZW 移除，参数仅为向后兼容
    let data = serializedFunc;
    // v0.8: LZW 压缩步骤移除（运行时解压是性能瓶颈）。
    // Step 1: Stream encrypt (position-dependent XOR)
    data = streamEncrypt(data, key);
    // Step 2: Hex encode for embedding
    return bytesToHex(data);
}
/**
 * Pack to the xor512 stage (stream + xor512), WITHOUT hex encoding.
 * v0.10 rt_deps：pipeline 用此函数获取中间二进制串，从中算出 hexLen → rtToken，
 * 再用 packRtMixHex() 追加 rt_mix 层。xor512 / rt_mix 均保长，hexLen 不依赖 KEY。
 *
 * v0.8：移除 LZW 步骤（与 packBytecode 一致）。`useLZW` 参数仅为向后兼容，被忽略。
 *
 * @returns xor512 后的二进制串（尚未 hex 编码）
 */
export function packToXor512Stage(serializedFunc, key, keyBytes, useLZW = false) {
    void useLZW; // v0.8: LZW 移除
    let data = serializedFunc;
    data = streamEncrypt(data, key);
    data = xor512Outer(data, keyBytes);
    return data;
}
/**
 * 在 xor512 二进制串上追加 rt_mix 层 + hex 编码（v0.10 Feature 4）。
 * v0.8：移除 LZW 步骤后，运行时逆向：hex → hex_to_bytes → rt_mix_decrypt → xor_bytes_512 → stream_decrypt。
 */
export function packRtMixHex(xorData, rtToken) {
    const rtData = rtMixEncrypt(xorData, rtToken);
    return bytesToHex(rtData);
}
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
export function packBytecodeKeyfused(serializedFunc, key, keyBytes, useLZW = false) {
    void useLZW; // v0.8: LZW 移除
    let data = serializedFunc;
    data = streamEncrypt(data, key);
    // v0.9: 512 位 XOR 外层（在 hex 编码前作用于二进制串）。
    data = xor512Outer(data, keyBytes);
    return bytesToHex(data);
}
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
export function unpackBytecode(hex, key, useLZW = false) {
    void useLZW; // v0.8: LZW 移除
    // Step 1: Hex decode
    let data = hexToBytes(hex);
    // Step 2: Stream decrypt
    data = streamDecrypt(data, key);
    // v0.8: LZW decompress 步骤移除。
    return data;
}
/**
 * Unpack with the 512-bit XOR outer layer (inverse of packBytecodeKeyfused).
 *
 * v0.8：`useLZW` 参数仅为向后兼容，被忽略。
 */
export function unpackBytecodeKeyfused(hex, key, keyBytes, useLZW = false) {
    void useLZW; // v0.8: LZW 移除
    let data = hexToBytes(hex);
    data = xor512Outer(data, keyBytes); // XOR 对称，同函数解密
    data = streamDecrypt(data, key);
    return data;
}
/**
 * 512 位循环 XOR（v0.9 keyfuse 外层）。与运行时 xor_bytes_512 对齐：
 * data 逐字节 XOR keyBytes[i % 64]。XOR 对称，加密解密同函数。
 * 内联于此以避免 packer ↔ keyfuse 循环依赖。
 */
function xor512Outer(data, keyBytes) {
    const bytes = Buffer.from(data, "binary");
    const out = Buffer.alloc(bytes.length);
    const klen = keyBytes.length;
    for (let i = 0; i < bytes.length; i++) {
        out[i] = (bytes[i] ^ keyBytes[i % klen]) & 0xff;
    }
    return out.toString("binary");
}
//# sourceMappingURL=packer.js.map