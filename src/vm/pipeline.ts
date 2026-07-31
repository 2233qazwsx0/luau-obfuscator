// src/vm/pipeline.ts — VM bytecode compilation pipeline entry.
//
// Takes a parsed AST and a PRNG seed, compiles to FuncPrototype,
// serializes to binary, packs with LZW+XOR, returns a hex string
// suitable for embedding in a Luau runtime template.

import { compileAST, type CompilerOptions, type InsncryptMode } from "./compiler.js";
import { serializeFunction } from "./encoder.js";
import { packBytecode, packBytecodeKeyfused, lzwCompress, streamEncrypt, bytesToHex } from "./packer.js";
import { buildRuntime } from "./runtime-template.js";
import { DEFAULT_RUNTIME_PROTECT, type RuntimeProtectOptions } from "./memory.js";
import { deriveKeyfuseKey, xor512, computeKeyfuseKhSize } from "./keyfuse.js";
import { deriveRtToken, rtTokenToNibbles, rtMixEncrypt } from "./rtdeps.js";
import type { Node } from "../parser/parser.js";

export interface VmResult {
  /** Hex-encoded packed bytecode string */
  hex: string;
  /** Stream cipher key (0-255) used for packing — needed by the runtime */
  cipherKey: number;
}

/**
 * Derive the stream cipher key from the seed.
 * The runtime template needs this to decrypt the bytecode.
 */
export function deriveCipherKey(seed: number): number {
  return ((seed ^ 0xDEADBEEF) >>> 0) % 256;
}

/**
 * Compile an AST to packed bytecode.
 *
 * @param ast  - The parsed AST (Block node) from parser.parse()
 * @param seed - PRNG seed for deterministic compilation + encryption
 * @param insnCrypt - v0.11 F6 指令层加密模式（"f6" 默认 / "f4" legacy / "off"）
 * @returns Packed hex string + cipher key, ready for embedding
 */
export function compileVM(
  ast: Node,
  seed: number,
  insnCrypt: InsncryptMode = "f6",
): VmResult {
  const cipherKey = deriveCipherKey(seed);
  const compilerOpts: CompilerOptions = { insnCrypt };
  const proto = compileAST(ast, seed, compilerOpts);
  const serialized = serializeFunction(proto);
  const hex = packBytecode(serialized, cipherKey, true);
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
export function compileVMWithRuntime(
  ast: Node,
  seed: number,
  opts: RuntimeProtectOptions = DEFAULT_RUNTIME_PROTECT,
  insnCrypt: InsncryptMode = "f6",
): string {
  const cipherKey = deriveCipherKey(seed);
  const compilerOpts: CompilerOptions = { insnCrypt };
  const proto = compileAST(ast, seed, compilerOpts);
  const serialized = serializeFunction(proto);
  const keyfuseOn = opts.keyfuse !== false;
  const rtDepsOn = keyfuseOn && opts.rtDeps !== false;

  if (!keyfuseOn) {
    // 无 keyfuse：原始 LZW + stream + hex。
    const hex = packBytecode(serialized, cipherKey, true);
    return buildRuntime(hex, cipherKey, opts, seed, null);
  }

  // keyfuse 开启：派生 512 位密钥。
  const kfKey = deriveKeyfuseKey(seed);

  if (!rtDepsOn) {
    // keyfuse 但无 rt_deps：LZW + stream + xor512 + hex（v0.9 行为）。
    const hex = packBytecodeKeyfused(serialized, cipherKey, kfKey.keyBytes, true);
    return buildRuntime(hex, cipherKey, opts, seed, kfKey.keyHex);
  }

  // v0.10 rt_deps：解密链追加 rt_mix 层 + KEY nibbles 126/127 运行时派生。
  // 步骤分解（避免循环依赖：hexLen 不依赖 KEY 内容）：
  //   1. LZW + stream → streamData（不依赖 keyBytes）
  //   2. hexLen = streamData.length * 2（xor512 / rt_mix 均保长）
  //   3. rtToken = deriveRtToken(hexLen, khSize)
  //   4. 覆盖 keyBytes[63] = rtToken 派生的 2 nibble
  //   5. xor512(streamData, keyBytes) → xorData
  //   6. rtMixEncrypt(xorData, rtToken) → rtData
  //   7. hex = bytesToHex(rtData)
  const lzwData = lzwCompress(serialized);
  const streamData = streamEncrypt(lzwData, cipherKey);
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
