import { type Instruction, type FuncPrototype } from "./opcodes.js";
/** Extract bits [start, start+width-1] from a 32-bit integer (1-indexed, like reference). */
export declare function extractBits(value: number, start: number, width: number): number;
/**
 * Encode a single Instruction into (b8, b9) pair.
 * Returns [b8, b9] as two 32-bit unsigned integers.
 */
export declare function encodeInstruction(insn: Instruction): [number, number];
/**
 * Serialize a FuncPrototype to a binary string.
 * Returns a string where each char is a byte (0-255).
 * This string is then LZW-compressed and XOR-encrypted.
 */
export declare function serializeFunction(func: FuncPrototype): string;
/**
 * Deserialize a function from a binary string.
 * Returns the FuncPrototype and the number of bytes consumed.
 */
export declare function deserializeFunction(data: string, offset?: number): [FuncPrototype, number];
/**
 * Decode a (b8, b9) pair back into an Instruction.
 * This is the inverse of encodeInstruction.
 */
export declare function decodeInstruction(b8: number, b9: number): Instruction;
