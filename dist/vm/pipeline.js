// src/vm/pipeline.ts — VM bytecode compilation pipeline entry.
//
// Takes a parsed AST and a PRNG seed, compiles to FuncPrototype,
// serializes to binary, packs with LZW+XOR, returns a hex string
// suitable for embedding in a Luau runtime template.
import { compileAST } from "./compiler.js";
import { serializeFunction } from "./encoder.js";
import { packBytecode } from "./packer.js";
import { buildRuntime } from "./runtime-template.js";
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
 * @param ast - The parsed AST (Block node) from parser.parse()
 * @param seed - PRNG seed for deterministic compilation + encryption
 * @returns Packed hex string + cipher key, ready for embedding
 */
export function compileVM(ast, seed) {
    const cipherKey = deriveCipherKey(seed);
    const proto = compileAST(ast, seed);
    const serialized = serializeFunction(proto);
    const hex = packBytecode(serialized, cipherKey, true);
    return { hex, cipherKey };
}
/**
 * Compile an AST to packed bytecode AND wrap it in the Luau runtime template.
 * The returned string is a complete, executable Luau script.
 *
 * @param ast - The parsed AST (Block node)
 * @param seed - PRNG seed
 * @returns Final Luau source that decodes and executes the bytecode
 */
export function compileVMWithRuntime(ast, seed) {
    const { hex, cipherKey } = compileVM(ast, seed);
    return buildRuntime(hex, cipherKey);
}
//# sourceMappingURL=pipeline.js.map