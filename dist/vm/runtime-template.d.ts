import { type RuntimeProtectOptions } from "./memory.js";
/**
 * Build the final executable Luau script by injecting the packed bytecode
 * hex blob and cipher key into the runtime template.
 *
 * @param hex       Packed hex bytecode (from compileVM().hex)
 * @param cipherKey Stream cipher key (0-255)
 * @param opts      运行时保护选项（默认全开）
 * @returns Final Luau source that, when executed, decodes and runs the bytecode
 */
export declare function buildRuntime(hex: string, cipherKey: number, opts?: RuntimeProtectOptions): string;
