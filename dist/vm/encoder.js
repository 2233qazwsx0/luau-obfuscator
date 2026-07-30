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
//     (b8/b9 are XOR-encrypted if insnSeed is set; see F4 below)
//   [numConstants: uint32]
//   for each constant: [typeTag: uint8][data...]
//     type 0 (string): [len: uint8][bytes...]
//       NOTE: strings with blindDesc[str_xor] are stored XOR'd
//     type 1 (bool): [val: uint8]
//     type 2 (number): [8 bytes IEEE 754 LE]
//       NOTE: numbers with blindDesc[num_split] are stored as value + k2 (i.e. k1)
//   [numBlindEntries: uint32]   -- v0.6 F3 (always = numConstants, can be 0 for compat)
//   for each blind entry: [tag: uint8][params...]
//     0 = none
//     1 = num_split: [k2: 8 bytes IEEE 754 LE]
//     2 = str_xor: [keyLen: uint8][keyBytes[0..keyLen-1]: uint8]
//   [paramCount: uint8]
//   [isVararg: uint8]
//   [numSubFunctions: uint32]
//   for each sub-function: [recursive serialization]
//   [numUpvalues: uint8]
//   for each upvalue: [fromStack: uint8][index: uint8]
//   [vmId: uint8]
//   [hasInsnSeed: uint8]       -- v0.6 F4 (0/1)
//   if hasInsnSeed: [insnSeed: uint32 LE]
//
// All multi-byte integers are written little-endian to match the reference's aj().
import { mulberry32 } from "../util/prng.js";
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
 * If `blind` is provided and applies to this entry, the stored value
 * is blinded (F3): numbers become (value + k2) = k1, strings become XOR bytes.
 */
function writeConstant(buf, entry, blind) {
    switch (entry.type) {
        case "string":
            writeU8(buf, 0);
            if (blind && blind.kind === "str_xor") {
                // Write XOR-encoded bytes with same length
                const key = blind.key;
                const klen = key.length;
                const s = entry.value;
                const buf2 = [];
                for (let i = 0; i < s.length; i++) {
                    const code = s.charCodeAt(i) & 0xFF;
                    buf2.push((code ^ (key[i % klen] & 0xFF)) & 0xFF);
                }
                writeU8(buf, s.length & 0xFF);
                for (const b of buf2)
                    buf.push(b);
            }
            else {
                writeString(buf, entry.value);
            }
            break;
        case "bool":
            writeU8(buf, 1);
            writeU8(buf, entry.value ? 1 : 0);
            break;
        case "number":
            writeU8(buf, 2);
            if (blind && blind.kind === "num_split") {
                writeF64(buf, entry.value + blind.k2); // stored = k1
            }
            else {
                writeF64(buf, entry.value);
            }
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
    // ---- F4 pre-compute instruction XOR keystream ----
    const numInsn = func.instructions.length;
    let insnKeys = null;
    if (func.insnSeed !== undefined) {
        const rng = mulberry32(func.insnSeed >>> 0);
        insnKeys = new Array(numInsn * 2);
        for (let i = 0; i < numInsn * 2; i++)
            insnKeys[i] = Math.floor(rng() * 0x100000000) >>> 0;
    }
    // Instructions
    writeU32(buf, numInsn);
    for (let i = 0; i < numInsn; i++) {
        const insn = func.instructions[i];
        let [b8, b9] = encodeInstruction(insn);
        if (insnKeys) {
            b8 = ((b8 >>> 0) ^ insnKeys[i * 2]) >>> 0;
            b9 = ((b9 >>> 0) ^ insnKeys[i * 2 + 1]) >>> 0;
        }
        writeU32(buf, b8);
        writeU32(buf, b9);
    }
    // Constants
    const numConst = func.constants.length;
    writeU32(buf, numConst);
    const descs = func.blindDescs;
    for (let i = 0; i < numConst; i++) {
        const c = func.constants[i];
        const desc = descs ? (descs[i] ?? null) : null;
        writeConstant(buf, c, desc);
    }
    // F3: blind descriptors (parallel array, always written for compat)
    writeU32(buf, numConst);
    for (let i = 0; i < numConst; i++) {
        const desc = descs ? (descs[i] ?? null) : null;
        if (!desc) {
            writeU8(buf, 0);
        }
        else if (desc.kind === "num_split") {
            writeU8(buf, 1);
            writeF64(buf, desc.k2);
        }
        else {
            // str_xor
            writeU8(buf, 2);
            const klen = desc.key.length & 0xFF;
            writeU8(buf, klen);
            for (let k = 0; k < klen; k++)
                writeU8(buf, desc.key[k] & 0xFF);
        }
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
    // v0.8 多 VM：函数默认 VM 编号（0/1/2 真VM，3/4 假VM，向后兼容 undefined=0）。
    writeU8(buf, (func.vmId ?? 0) & 0xFF);
    // v0.6 F4: instruction XOR seed presence
    const hasSeed = func.insnSeed !== undefined;
    writeU8(buf, hasSeed ? 1 : 0);
    if (hasSeed)
        writeU32(buf, (func.insnSeed >>> 0));
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
export function deserializeFunction(data, offset = 0) {
    const bytes = Array.from(Buffer.from(data, "binary"), b => b);
    let pos = offset;
    // Instructions
    let numInsns;
    [numInsns, pos] = readU32(bytes, pos);
    // We might need to re-read instructions after insnSeed is known; for
    // now keep them encoded+plaintext in a parallel buffer, we'll re-XOR at the end.
    const encB8 = new Array(numInsns);
    const encB9 = new Array(numInsns);
    const instructions = [];
    for (let i = 0; i < numInsns; i++) {
        let b8, b9;
        [b8, pos] = readU32(bytes, pos);
        [b9, pos] = readU32(bytes, pos);
        encB8[i] = b8;
        encB9[i] = b9;
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
    // Detect v0.6 format
    const peekU32 = (p) => ((bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16) | (bytes[p + 3] << 24)) >>> 0);
    let isV06 = false;
    if (pos + 4 <= bytes.length) {
        const nxt = peekU32(pos);
        if (nxt === numConsts && numConsts >= 1)
            isV06 = true;
        if (numConsts === 0) {
            // Heuristic: v0.6 writes 0x00000000 then later has (hasInsnSeed byte).
            // Old format here writes (paramCount u8)(vararg u8)(numSubs u32)... very rarely
            // would paramCount=0+vararg=0+numSubsLow=0 look exactly like 0 u32 twice.
            // Safer: try to parse v0.6, if the remaining shape matches at end we use it.
            if (peekU32(pos) === 0) {
                // Tentatively mark v0.6; if later structure misaligns on end we might be wrong,
                // but for our compiler output (always v0.6 new) this is correct.
                isV06 = true;
            }
        }
    }
    let blindDescs = undefined;
    if (isV06) {
        // numBlindEntries
        let nBlind;
        [nBlind, pos] = readU32(bytes, pos);
        const arr = new Array(nBlind);
        for (let i = 0; i < nBlind; i++) {
            let tag;
            [tag, pos] = readU8(bytes, pos);
            if (tag === 0) {
                arr[i] = null;
            }
            else if (tag === 1) {
                let k2;
                [k2, pos] = readF64(bytes, pos);
                arr[i] = { kind: "num_split", k2 };
            }
            else if (tag === 2) {
                let klen;
                [klen, pos] = readU8(bytes, pos);
                const kArr = new Array(klen);
                for (let k = 0; k < klen; k++) {
                    let kb;
                    [kb, pos] = readU8(bytes, pos);
                    kArr[k] = kb;
                }
                arr[i] = { kind: "str_xor", key: kArr };
            }
            else {
                arr[i] = null;
            }
        }
        blindDescs = arr;
        // Now un-blind constants in memory so tests & compiler see plaintext
        // (this mirrors the runtime blind cache first-hit).
        for (let i = 0; i < constants.length; i++) {
            const bd = blindDescs[i];
            if (!bd)
                continue;
            const c = constants[i];
            if (bd.kind === "num_split" && c.type === "number") {
                c.value = c.value - bd.k2;
            }
            else if (bd.kind === "str_xor" && c.type === "string") {
                const key = bd.key;
                const klen = key.length;
                if (klen === 0)
                    continue;
                const raw = c.value;
                let out = "";
                for (let ch = 0; ch < raw.length; ch++) {
                    const code = raw.charCodeAt(ch) & 0xFF;
                    out += String.fromCharCode((code ^ (key[ch % klen] & 0xFF)) & 0xFF);
                }
                c.value = out;
            }
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
    // v0.6 F4: instruction XOR seed
    let insnSeed = undefined;
    if (isV06 && pos + 1 <= bytes.length) {
        let hasSeed;
        [hasSeed, pos] = readU8(bytes, pos);
        if (hasSeed !== 0) {
            let sd;
            [sd, pos] = readU32(bytes, pos);
            insnSeed = sd;
        }
    }
    // If F4 seed present, re-decode instructions with XOR keys applied.
    if (insnSeed !== undefined) {
        const rng = mulberry32(insnSeed >>> 0);
        for (let i = 0; i < numInsns; i++) {
            const k8 = Math.floor(rng() * 0x100000000) >>> 0;
            const k9 = Math.floor(rng() * 0x100000000) >>> 0;
            const b8 = ((encB8[i] >>> 0) ^ k8) >>> 0;
            const b9 = ((encB9[i] >>> 0) ^ k9) >>> 0;
            instructions[i] = decodeInstruction(b8, b9);
        }
    }
    return [{
            instructions,
            constants,
            subFunctions,
            paramCount,
            isVararg: varargFlag !== 0,
            upvalues,
            vmId,
            blindDescs,
            insnSeed,
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