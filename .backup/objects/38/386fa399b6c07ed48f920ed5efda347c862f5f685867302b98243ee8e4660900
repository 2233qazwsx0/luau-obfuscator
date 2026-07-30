// src/vm/pipeline.ts — VM bytecode compilation pipeline entry.
//
// Takes a parsed AST and a PRNG seed, compiles to FuncPrototype,
// serializes to binary, packs with LZW+XOR, returns a hex string
// suitable for embedding in a Luau runtime template.

import { compileAST } from "./compiler.js";
import { serializeFunction } from "./encoder.js";
import { packBytecode } from "./packer.js";
import type { Node } from "../parser/parser.js";

export interface VmResult {
  /** Hex-encoded packed bytecode string */
  hex: string;
}

/**
 * Compile an AST to packed bytecode.
 *
 * @param ast - The parsed AST (Block node) from parser.parse()
 * @param seed - PRNG seed for deterministic compilation + encryption
 * @returns Packed hex string ready for embedding
 */
export function compileVM(ast: Node, seed: number): VmResult {
  // Derive a separate key for the stream cipher from the seed
  const cipherKey = ((seed ^ 0xDEADBEEF) >>> 0) % 256;

  const proto = compileAST(ast, seed);
  const serialized = serializeFunction(proto);
  const hex = packBytecode(serialized, cipherKey, true);

  return { hex };
}
