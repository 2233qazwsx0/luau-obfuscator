// src/vm/encoder.ts — Bytecode encoder for the register-based VM.
//
// Encodes Instruction[] into the (b8, b9) dual-32-bit integer format
// used by the reference sample's b3() decoder. Also serializes entire
// FuncPrototype trees into a binary string for LZW+XOR packing.
//
// Encoding scheme (from b3() in the reference):
//
// For each instruction, we produce two 32-bit values: b8 and b9.
//   ba = bits 1-2 of b8   → mode (0-3)
//   bb = bits 1-11 of b9  → opcode number
//
//   mode 0: A = bits 3-11 of b8, C = bits 12-20 of b8, D = bits 21-29 of b8
//           (B comes from b9 bits 12+)
//   mode 1: A = bits 3-11 of b8, B/C = bits 12-33 of b9 (unsigned)
//   mode 2: A = bits 3-11 of b8, B/C = bits 12-32 of b9 - 1048575 (signed)
//   mode 3: A = bits 3-11 of b8, B/C = bits 12-32 of b9 - 1048575, D = bits 21-29 of b8
//
// At decode time, the runtime reconstructs the instruction array as:
//   {opcode, A, C_or_B, nil, D_or_B} where the exact field assignment
//   depends on the mode.
//
// The serialized function format (binary string) is:
//   [numInstructions: uint32]
//   for each instruction: [b8: uint32 LE][b9: uint32 LE]
//   [numConstants: uint32]
//   for each constant: [typeTag: uint8][data...]
//     type 0 (string): [len: uint8][bytes...]
//     type 1 (bool): [val: uint8]
//     type 2 (number): [8 bytes IEEE 754 LE]
//   [paramCount: uint8]
//   [isVararg: uint8]
//   [numSubFunctions: uint32]
//   for each sub-function: [recursive serialization]
//   [numUpvalues: uint8]
//   for each upvalue: [fromStack: uint8][index: uint8]
//
// All multi-byte integers are written little-endian to match the reference's aj().
// ---- Bit extraction helpers (mirror reference's a8 function) ----
/** Extract bits [start, start+width-1] from a 32-bit integer (1-indexed, like reference). */
export function extractBits(value, start, width) {
    const shifted = Math.floor(value / Math.pow(2, start - 1));
    const mask = Math.pow(2, width) - 1;
    return shifted & mask;
}
/** Set bits [start, start+width-1] in a 32-bit integer (1-indexed). */
function setBits(target, start, width, value) {
    const mask = (Math.pow(2, width) - 1) * Math.pow(2, start - 1);
    const cleared = target & ~mask;
    return cleared | (value * Math.pow(2, start - 1));
}
// ---- Instruction encoding to (b8, b9) ----
/**
 * Encode a single Instruction into (b8, b9) pair.
 * Returns [b8, b9] as two 32-bit unsigned integers.
 */
export function encodeInstruction(insn) {
    const mode = insn.mode;
    let b8 = 0;
    let b9 = 0;
    // Mode is in bits 1-2 of b8
    b8 = setBits(b8, 1, 2, mode);
    // A is in bits 3-11 of b8 (9 bits, 0-255 for register indices)
    b8 = setBits(b8, 3, 9, insn.A & 0x1FF);
    // Opcode is in bits 1-11 of b9 (11 bits, 0-2047)
    b9 = setBits(b9, 1, 11, insn.op & 0x7FF);
    switch (mode) {
        case 0:
            // C = bits 12-20 of b8 (9 bits), D = bits 21-29 of b8 (9 bits)
            // B = bits 12+ of b9 (unused in mode 0 for basic ops)
            b8 = setBits(b8, 12, 9, insn.C & 0x1FF);
            b8 = setBits(b8, 21, 9, insn.D & 0x1FF);
            // B goes into b9 bits 12-20
            b9 = setBits(b9, 12, 9, insn.B & 0x1FF);
            break;
        case 1: {
            // C = bits 12-33 of b9 (22 bits, unsigned)
            const cVal = insn.C & 0x3FFFFF;
            b9 = setBits(b9, 12, 22, cVal);
            // B can share the same field or use b8 bits 12-20
            b8 = setBits(b8, 12, 9, insn.B & 0x1FF);
            break;
        }
        case 2: {
            // C = bits 12-32 of b9, minus 1048575 (signed 21-bit)
            // Encoding: store C + 1048575 as 21-bit unsigned
            const cEncoded = (insn.C + 1048575) & 0x1FFFFF;
            b9 = setBits(b9, 12, 21, cEncoded);
            b8 = setBits(b8, 12, 9, insn.B & 0x1FF);
            break;
        }
        case 3: {
            // C = bits 12-32 of b9, minus 1048575 (signed 21-bit)
            const cEncoded = (insn.C + 1048575) & 0x1FFFFF;
            b9 = setBits(b9, 12, 21, cEncoded);
            // D = bits 21-29 of b8 (9 bits)
            b8 = setBits(b8, 21, 9, insn.D & 0x1FF);
            b8 = setBits(b8, 12, 9, insn.B & 0x1FF);
            break;
        }
    }
    return [b8 >>> 0, b9 >>> 0];
}
// ---- Binary string serialization (byte buffer) ----
/**
 * Write a little-endian uint32 to the byte buffer.
 */
function writeU32(buf, value) {
    buf.push(value & 0xFF);
    buf.push((value >> 8) & 0xFF);
    buf.push((value >> 16) & 0xFF);
    buf.push((value >> 24) & 0xFF);
}
/**
 * Write a single byte to the buffer.
 */
function writeU8(buf, value) {
    buf.push(value & 0xFF);
}
/**
 * Write an IEEE 754 double (8 bytes, little-endian) to the buffer.
 */
function writeF64(buf, value) {
    const tmpBuf = Buffer.alloc(8);
    tmpBuf.writeDoubleLE(value, 0);
    for (let i = 0; i < 8; i++)
        buf.push(tmpBuf[i]);
}
/**
 * Write a string as length-prefixed bytes.
 */
function writeString(buf, value) {
    const encoded = Buffer.from(value, "utf8");
    // Length as a single byte (max 255 for short strings)
    // For longer strings, we use a varint-like scheme: if length > 255,
    // write 0xFF then the actual length as uint32
    if (encoded.length <= 0xFF) {
        writeU8(buf, encoded.length);
    }
    else {
        writeU8(buf, 0xFF);
        writeU32(buf, encoded.length);
    }
    for (let i = 0; i < encoded.length; i++)
        buf.push(encoded[i]);
}
/**
 * Serialize a constant entry to the bytecode buffer.
 */
function writeConstant(buf, entry) {
    switch (entry.type) {
        case "string":
            writeU8(buf, 0);
            writeString(buf, entry.value);
            break;
        case "bool":
            writeU8(buf, 1);
            writeU8(buf, entry.value ? 1 : 0);
            break;
        case "number":
            writeU8(buf, 2);
            writeF64(buf, entry.value);
            break;
    }
}
/**
 * Serialize a FuncPrototype to a binary string.
 * Returns a string where each char is a byte (0-255).
 * This string is then LZW-compressed and XOR-encrypted.
 */
export function serializeFunction(func) {
    const buf = [];
    // Instructions
    writeU32(buf, func.instructions.length);
    for (const insn of func.instructions) {
        const [b8, b9] = encodeInstruction(insn);
        writeU32(buf, b8);
        writeU32(buf, b9);
    }
    // Constants
    writeU32(buf, func.constants.length);
    for (const c of func.constants) {
        writeConstant(buf, c);
    }
    // Param count
    writeU8(buf, func.paramCount);
    // Vararg flag
    writeU8(buf, func.isVararg ? 1 : 0);
    // Sub-functions
    writeU32(buf, func.subFunctions.length);
    for (const sub of func.subFunctions) {
        const subStr = serializeFunction(sub);
        // Write sub-function as length-prefixed binary
        const subBytes = Buffer.from(subStr, "binary");
        writeU32(buf, subBytes.length);
        for (let i = 0; i < subBytes.length; i++)
            buf.push(subBytes[i]);
    }
    // Upvalues
    writeU8(buf, func.upvalues.length);
    for (const uv of func.upvalues) {
        writeU8(buf, uv.fromStack ? 1 : 0);
        writeU8(buf, uv.index);
    }
    // v0.8 多 VM：函数默认 VM 编号（0/1/2）。undefined → 0（向后兼容）。
    writeU8(buf, (func.vmId ?? 0) & 0xFF);
    // Convert byte array to binary string
    return Buffer.from(buf).toString("binary");
}
// ---- Deserialization (for tests / decrypt) ----
/**
 * Read a little-endian uint32 from byte array at offset.
 * Returns [value, newOffset].
 */
function readU32(bytes, offset) {
    const val = (bytes[offset] | (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
    return [val, offset + 4];
}
/**
 * Read a single byte.
 * Returns [value, newOffset].
 */
function readU8(bytes, offset) {
    return [bytes[offset], offset + 1];
}
/**
 * Read an IEEE 754 double.
 * Returns [value, newOffset].
 */
function readF64(bytes, offset) {
    const tmpBuf = Buffer.alloc(8);
    for (let i = 0; i < 8; i++)
        tmpBuf[i] = bytes[offset + i];
    return [tmpBuf.readDoubleLE(0), offset + 8];
}
/**
 * Read a length-prefixed string.
 * Returns [value, newOffset].
 */
function readString(bytes, offset) {
    let len;
    [len, offset] = readU8(bytes, offset);
    if (len === 0xFF) {
        [len, offset] = readU32(bytes, offset);
    }
    const strBuf = Buffer.alloc(len);
    for (let i = 0; i < len; i++)
        strBuf[i] = bytes[offset + i];
    return [strBuf.toString("utf8"), offset + len];
}
/**
 * Deserialize a function from a binary string.
 * Returns the FuncPrototype and the number of bytes consumed.
 */
export function deserializeFunction(data, offset = 0) {
    const bytes = Array.from(Buffer.from(data, "binary"), b => b);
    let pos = offset;
    // Instructions
    let numInsns;
    [numInsns, pos] = readU32(bytes, pos);
    const instructions = [];
    for (let i = 0; i < numInsns; i++) {
        let b8, b9;
        [b8, pos] = readU32(bytes, pos);
        [b9, pos] = readU32(bytes, pos);
        instructions.push(decodeInstruction(b8, b9));
    }
    // Constants
    let numConsts;
    [numConsts, pos] = readU32(bytes, pos);
    const constants = [];
    for (let i = 0; i < numConsts; i++) {
        let typeTag;
        [typeTag, pos] = readU8(bytes, pos);
        if (typeTag === 0) {
            let s;
            [s, pos] = readString(bytes, pos);
            constants.push({ type: "string", value: s });
        }
        else if (typeTag === 1) {
            let b;
            [b, pos] = readU8(bytes, pos);
            constants.push({ type: "bool", value: b !== 0 });
        }
        else {
            let d;
            [d, pos] = readF64(bytes, pos);
            constants.push({ type: "number", value: d });
        }
    }
    // Param count
    let paramCount;
    [paramCount, pos] = readU8(bytes, pos);
    // Vararg flag
    let varargFlag;
    [varargFlag, pos] = readU8(bytes, pos);
    // Sub-functions
    let numSubs;
    [numSubs, pos] = readU32(bytes, pos);
    const subFunctions = [];
    for (let i = 0; i < numSubs; i++) {
        let subLen;
        [subLen, pos] = readU32(bytes, pos);
        const subBytes = bytes.slice(pos, pos + subLen);
        const subStr = Buffer.from(subBytes).toString("binary");
        const [subFunc] = deserializeFunction(subStr, 0);
        subFunctions.push(subFunc);
        pos += subLen;
    }
    // Upvalues
    let numUpvals;
    [numUpvals, pos] = readU8(bytes, pos);
    const upvalues = [];
    for (let i = 0; i < numUpvals; i++) {
        let fromStack, idx;
        [fromStack, pos] = readU8(bytes, pos);
        [idx, pos] = readU8(bytes, pos);
        upvalues.push({ fromStack: fromStack !== 0, index: idx });
    }
    // v0.8 多 VM：函数默认 VM 编号。
    let vmId;
    [vmId, pos] = readU8(bytes, pos);
    return [{
            instructions,
            constants,
            subFunctions,
            paramCount,
            isVararg: varargFlag !== 0,
            upvalues,
            vmId,
        }, pos - offset];
}
// ---- Instruction decoding (for tests / decrypt) ----
/**
 * Decode a (b8, b9) pair back into an Instruction.
 * This is the inverse of encodeInstruction.
 */
export function decodeInstruction(b8, b9) {
    const mode = extractBits(b8, 1, 2);
    const op = extractBits(b9, 1, 11);
    const A = extractBits(b8, 3, 9);
    let B = 0;
    let C = 0;
    let D = 0;
    switch (mode) {
        case 0:
            B = extractBits(b9, 12, 9);
            C = extractBits(b8, 12, 9);
            D = extractBits(b8, 21, 9);
            break;
        case 1:
            B = extractBits(b8, 12, 9);
            C = extractBits(b9, 12, 22);
            break;
        case 2:
            B = extractBits(b8, 12, 9);
            C = extractBits(b9, 12, 21) - 1048575;
            break;
        case 3:
            B = extractBits(b8, 12, 9);
            C = extractBits(b9, 12, 21) - 1048575;
            D = extractBits(b8, 21, 9);
            break;
    }
    return { op, A, B, C, D, mode };
}
//# sourceMappingURL=encoder.js.map