import { type RuntimeProtectOptions } from "./memory.js";
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
export declare function deriveCipherKey(seed: number): number;
/**
 * Compile an AST to packed bytecode.
 *
 * @param ast - The parsed AST (Block node) from parser.parse()
 * @param seed - PRNG seed for deterministic compilation + encryption
 * @returns Packed hex string + cipher key, ready for embedding
 */
export declare function compileVM(ast: Node, seed: number): VmResult;
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
export declare function compileVMWithRuntime(ast: Node, seed: number, opts?: RuntimeProtectOptions): string;
