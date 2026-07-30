// src/vm/runtime-template.ts — Wrap packed bytecode in a Luau runtime template.
//
// Reads runtime/vm-runtime.template.lua, substitutes the __HEX_BLOB__ and
// __CIPHER_KEY__ placeholders, and returns the final executable Luau script.
//
// v0.4: plain substitution (no self-obfuscation yet). The runtime template
// runs as-is; the bytecode blob is already LZW+XOR protected.

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const TEMPLATE_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../runtime/vm-runtime.template.lua",
);

/**
 * Build the final executable Luau script by injecting the packed bytecode
 * hex blob and cipher key into the runtime template.
 *
 * @param hex - Packed hex bytecode (from compileVM().hex)
 * @param cipherKey - Stream cipher key (0-255)
 * @returns Final Luau source that, when executed, decodes and runs the bytecode
 */
export function buildRuntime(hex: string, cipherKey: number): string {
  const template = readFileSync(TEMPLATE_PATH, "utf8");
  // Replace placeholders. The hex string is pure [0-9A-F], safe in a Lua
  // double-quoted string literal. The cipher key is a small integer.
  return template
    .replace('"__HEX_BLOB__"', JSON.stringify(hex))
    .replace(/__CIPHER_KEY__/g, String(cipherKey));
}
