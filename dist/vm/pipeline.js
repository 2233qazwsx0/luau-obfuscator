// src/vm/pipeline.ts — VM bytecode compilation pipeline entry.
//
// Takes a parsed AST and a PRNG seed, compiles to FuncPrototype,
// serializes to binary, packs with LZW+XOR, returns a hex string
// suitable for embedding in a Luau runtime template.
import { compileAST } from "./compiler.js";
import { serializeFunction } from "./encoder.js";
import { packBytecode, packBytecodeKeyfused } from "./packer.js";
import { buildRuntime } from "./runtime-template.js";
import { DEFAULT_RUNTIME_PROTECT } from "./memory.js";
import { deriveKeyfuseKey } from "./keyfuse.js";
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
 * v0.9 keyfuse：opts.keyfuse 开启时，在 stream cipher 外层加 512 位 XOR 层，
 * 并把密钥拆成 128 个 nibble 碎片深度融合到运行时代码中。
 *
 * @param ast  - The parsed AST (Block node)
 * @param seed - PRNG seed
 * @param opts - 运行时保护选项（内存清理 / 反 dump / 碎片化 / keyfuse，默认全开）
 * @returns Final Luau source that decodes and executes the bytecode
 */
export function compileVMWithRuntime(ast, seed, opts = DEFAULT_RUNTIME_PROTECT) {
    const cipherKey = deriveCipherKey(seed);
    const proto = compileAST(ast, seed);
    const serialized = serializeFunction(proto);
    const keyfuseOn = opts.keyfuse !== false;
    // v0.9 keyfuse：512 位 XOR 外层 + 碎片宿主装配。
    const kfKey = keyfuseOn ? deriveKeyfuseKey(seed) : null;
    const hex = keyfuseOn
        ? packBytecodeKeyfused(serialized, cipherKey, kfKey.keyBytes, true)
        : packBytecode(serialized, cipherKey, true);
    // 把 keyHex 透传给运行时模板（用于碎片装配 + XOR 解密）。
    return buildRuntime(hex, cipherKey, opts, seed, keyfuseOn ? kfKey.keyHex : null);
}
//# sourceMappingURL=pipeline.js.map