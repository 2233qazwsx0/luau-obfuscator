// src/vm/pipeline.ts — VM bytecode compilation pipeline entry.
//
// Takes a parsed AST and a PRNG seed, compiles to FuncPrototype,
// serializes to binary, packs with LZW+XOR, returns a hex string
// suitable for embedding in a Luau runtime template.

import { compileAST } from "./compiler.js";
import { serializeFunction } from "./encoder.js";
import { packBytecode } from "./packer.js";
import { buildRuntime } from "./runtime-template.js";
import { DEFAULT_MEMWIPE, type MemWipeOptions } from "./memory.js";
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
 * @param ast - The parsed AST (Block node) from parser.parse()
 * @param seed - PRNG seed for deterministic compilation + encryption
 * @returns Packed hex string + cipher key, ready for embedding
 */
export function compileVM(ast: Node, seed: number): VmResult {
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
 * @param ast  - The parsed AST (Block node)
 * @param seed - PRNG seed
 * @param mem  - 内存清理 / 反 dump 选项（默认全开）
 * @returns Final Luau source that decodes and executes the bytecode
 */
export function compileVMWithRuntime(
  ast: Node,
  seed: number,
  mem: MemWipeOptions = DEFAULT_MEMWIPE,
): string {
  const { hex, cipherKey } = compileVM(ast, seed);
  return buildRuntime(hex, cipherKey, mem);
}
