// src/vm/constants.ts — Constant pool manager for the VM compiler.
//
// Manages the constants table (bk in the reference) which holds:
//   type 0: string  (via aF() in the bytecode reader)
//   type 1: boolean (via aq() ~= 0 in the bytecode reader)
//   type 2: number  (via au() — IEEE 754 double in the bytecode reader)
//
// The compiler adds constants as it walks the AST; the encoder writes
// them into the bytecode blob. The runtime reads them in order.

import { type ConstEntry } from "./opcodes.js";

export class ConstantPool {
  private entries: ConstEntry[] = [];
  private indexMap: Map<string, number> = new Map();

  /** Returns the index of a constant in the pool, adding it if new. */
  add(entry: ConstEntry): number {
    const key = constKey(entry);
    const existing = this.indexMap.get(key);
    if (existing !== undefined) return existing;
    const idx = this.entries.length;
    this.entries.push(entry);
    this.indexMap.set(key, idx);
    return idx;
  }

  /** Add a string constant, return its index. */
  addString(value: string): number {
    return this.add({ type: "string", value });
  }

  /** Add a boolean constant, return its index. */
  addBool(value: boolean): number {
    return this.add({ type: "bool", value });
  }

  /** Add a number constant, return its index. */
  addNumber(value: number): number {
    return this.add({ type: "number", value });
  }

  /** Get all entries in order. */
  getAll(): ConstEntry[] {
    return this.entries;
  }

  /** Number of constants. */
  size(): number {
    return this.entries.length;
  }

  /** Get the type tag for the bytecode reader (0=string, 1=bool, 2=number). */
  static typeTag(entry: ConstEntry): number {
    switch (entry.type) {
      case "string": return 0;
      case "bool": return 1;
      case "number": return 2;
    }
  }
}

/** Build a unique key for deduplication. */
function constKey(entry: ConstEntry): string {
  return `${entry.type}:${entry.type === "bool" ? entry.value : entry.type === "number" ? entry.value : entry.value}`;
}