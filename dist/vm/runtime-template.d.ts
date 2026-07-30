import { type RuntimeProtectOptions } from "./memory.js";
/**
 * Build the final executable Luau script by injecting the packed bytecode
 * hex blob and cipher key into the runtime template.
 *
 * @param hex       Packed hex bytecode (from compileVM().hex)
 * @param cipherKey Stream cipher key (0-255)
 * @param opts      运行时保护选项（默认全开）
 * @param vmSeed    v0.8 多 VM：派生 opcode 映射表的种子（与编译器同源）。
 *                  运行时用它重建 3 套 op→sem 反查表。
 * @returns Final Luau source that, when executed, decodes and runs the bytecode
 */
export declare function buildRuntime(hex: string, cipherKey: number, opts?: RuntimeProtectOptions, vmSeed?: number): string;
