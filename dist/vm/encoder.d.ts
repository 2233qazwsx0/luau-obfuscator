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
 *
 * Compatibility: the old (pre v0.6) format lacks blind descriptors and
 * instruction-XOR seed.  We detect the v0.6 format by checking if the
 * uint32 immediately after constants has a plausible value:
 *   - old format: at that position we have paramCount (uint8, 0..254) + vararg (uint8, 0/1)
 *     → first 32 bits read as u32 will be ≤ 0x000100FE (≈ 65790) and will equal numConsts
 *   - v0.6 format: after constants we write exactly numConsts as uint32.
 * So we check: the uint32-after-constants equals numConsts AND numConsts >= 1 → v0.6 format.
 * Edge case: numConsts=0 → v0.6 always writes 0 u32 followed by numBlind=0 → same shape as old.
 *            For numConsts=0, we peek further and use a heuristic.
 */
export declare function deserializeFunction(data: string, offset?: number): [FuncPrototype, number];
/**
 * Decode a (b8, b9) pair back into an Instruction.
 * This is the inverse of encodeInstruction.
 */
export declare function decodeInstruction(b8: number, b9: number): Instruction;
