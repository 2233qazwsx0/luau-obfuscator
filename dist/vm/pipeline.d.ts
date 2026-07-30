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
 * @param ast  - The parsed AST (Block node)
 * @param seed - PRNG seed
 * @param opts - 运行时保护选项（内存清理 / 反 dump / 碎片化，默认全开）
 * @returns Final Luau source that decodes and executes the bytecode
 */
export declare function compileVMWithRuntime(ast: Node, seed: number, opts?: RuntimeProtectOptions): string;
