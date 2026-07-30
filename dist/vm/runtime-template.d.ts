import { type MemWipeOptions } from "./memory.js";
/**
 * Build the final executable Luau script by injecting the packed bytecode
 * hex blob and cipher key into the runtime template.
 *
 * @param hex       Packed hex bytecode (from compileVM().hex)
 * @param cipherKey Stream cipher key (0-255)
 * @param opts      Memory-protection options (default: both enabled)
 * @returns Final Luau source that, when executed, decodes and runs the bytecode
 */
export declare function buildRuntime(hex: string, cipherKey: number, opts?: MemWipeOptions): string;
