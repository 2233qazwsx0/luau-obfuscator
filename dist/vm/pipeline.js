// src/vm/pipeline.ts — VM bytecode compilation pipeline entry.
//
// Takes a parsed AST and a PRNG seed, compiles to FuncPrototype,
// serializes to binary, packs with stream-cipher (+ optional keyfuse XOR +
// rt_mix), returns a hex string suitable for embedding in a Luau runtime
// template.
//
// v0.8 性能修复：移除 LZW 压缩层（bi 层去重）。pipeline 不再调用 lzwCompress，
// packer.packBytecode / packBytecodeKeyfused 内部仅做 stream cipher (+ xor512)。
import { compileAST } from "./compiler.js";
import { serializeFunction } from "./encoder.js";
import { packBytecode, packBytecodeKeyfused, streamEncrypt, bytesToHex } from "./packer.js";
import { buildRuntime } from "./runtime-template.js";
import { DEFAULT_RUNTIME_PROTECT } from "./memory.js";
import { deriveKeyfuseKey, xor512, computeKeyfuseKhSize } from "./keyfuse.js";
import { deriveRtToken, rtTokenToNibbles, rtMixEncrypt } from "./rtdeps.js";
/**
 * Derive the stream cipher key from the seed.
 * The runtime template needs this to decrypt the bytecode.
 */
export function deriveCipherKey(seed) {
    return ((seed ^ 0xDEADBEEF) >>> 0) % 256;
}
/**
 * Compile an AST to packed bytecode.
 *
 * @param ast  - The parsed AST (Block node) from parser.parse()
 * @param seed - PRNG seed for deterministic compilation + encryption
 * @param insnCrypt - v0.11 F6 指令层加密模式（"f6" 默认 / "f4" legacy / "off"）
 * @param compactArith - v0.12 Feature #3: 紧凑算术/比较（合并 ALU/CMP）
 * @returns Packed hex string + cipher key, ready for embedding
 */
export function compileVM(ast, seed, insnCrypt = "f6", compactArith = false) {
    const cipherKey = deriveCipherKey(seed);
    const compilerOpts = { insnCrypt, compactArith };
    const proto = compileAST(ast, seed, compilerOpts);
    const serialized = serializeFunction(proto);
    // v0.8: LZW 移除，packBytecode 内部仅做 stream encrypt + hex。
    const hex = packBytecode(serialized, cipherKey);
    return { hex, cipherKey };
}
/**
 * Compile an AST to packed bytecode AND wrap it in the Luau runtime template.
 * The returned string is a complete, executable Luau script.
 *
 * v0.9 keyfuse：opts.keyfuse 开启时，在 stream cipher 外层加 512 位 XOR 层，
 * 并把密钥拆成 128 个 nibble 碎片深度融合到运行时代码中。
 *
 * v0.10 rt_deps：opts.rtDeps 开启时（需 keyfuse），解密链追加 rt_mix 层
 * （position-dependent ADD，token 依赖 #HEX_BLOB / #_kh），且 keyfuse KEY 的
 * nibbles 126/127 改由 runtime token 派生。废弃纯静态状态机拼密钥。
 *
 * @param ast  - The parsed AST (Block node)
 * @param seed - PRNG seed
 * @param opts - 运行时保护选项（内存清理 / 反 dump / 碎片化 / keyfuse / rt_deps，默认全开）
 * @returns Final Luau source that decodes and executes the bytecode
 */
export function compileVMWithRuntime(ast, seed, opts = DEFAULT_RUNTIME_PROTECT, insnCrypt = "f6", compactArith = false) {
    const cipherKey = deriveCipherKey(seed);
    const compilerOpts = { insnCrypt, compactArith };
    const proto = compileAST(ast, seed, compilerOpts);
    const serialized = serializeFunction(proto);
    const keyfuseOn = opts.keyfuse !== false;
    const rtDepsOn = keyfuseOn && opts.rtDeps !== false;
    if (!keyfuseOn) {
        // 无 keyfuse：v0.8 仅 stream + hex（LZW 已移除）。
        const hex = packBytecode(serialized, cipherKey);
        return buildRuntime(hex, cipherKey, opts, seed, null);
    }
    // keyfuse 开启：派生 512 位密钥。
    const kfKey = deriveKeyfuseKey(seed);
    if (!rtDepsOn) {
        // keyfuse 但无 rt_deps：stream + xor512 + hex（v0.8 移除 LZW 后）。
        const hex = packBytecodeKeyfused(serialized, cipherKey, kfKey.keyBytes);
        return buildRuntime(hex, cipherKey, opts, seed, kfKey.keyHex);
    }
    // v0.10 rt_deps：解密链追加 rt_mix 层 + KEY nibbles 126/127 运行时派生。
    // v0.8 步骤分解（LZW 已移除，避免循环依赖：hexLen 不依赖 KEY 内容）：
    //   1. stream → streamData（不依赖 keyBytes）
    //   2. hexLen = streamData.length * 2（xor512 / rt_mix 均保长）
    //   3. rtToken = deriveRtToken(hexLen, khSize)
    //   4. 覆盖 keyBytes[63] = rtToken 派生的 2 nibble
    //   5. xor512(streamData, keyBytes) → xorData
    //   6. rtMixEncrypt(xorData, rtToken) → rtData
    //   7. hex = bytesToHex(rtData)
    const streamData = streamEncrypt(serialized, cipherKey);
    const hexLen = streamData.length * 2;
    const rtToken = deriveRtToken(hexLen, computeKeyfuseKhSize());
    const [n126, n127] = rtTokenToNibbles(rtToken);
    kfKey.keyBytes[63] = n126 * 16 + n127;
    // 重建 keyHex（nibbles 126/127 已被 rtToken 覆盖）。
    kfKey.keyHex = kfKey.keyBytes
        .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
        .join("");
    const xorData = xor512(streamData, kfKey.keyBytes);
    const rtData = rtMixEncrypt(xorData, rtToken);
    const hex = bytesToHex(rtData);
    // buildRuntime 内部用 hex.length + khSize 重算同一 rtToken，传给 genKeyfuseAssembly。
    return buildRuntime(hex, cipherKey, opts, seed, kfKey.keyHex);
}
//# sourceMappingURL=pipeline.js.map