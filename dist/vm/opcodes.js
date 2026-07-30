// src/vm/opcodes.ts — 70-op register-based VM opcode definitions.
//
// Faithfully mirrors the reference sample's "猫猫脚本 114514" VM:
//   - 70 opcode numbers (0-69), with many duplicate semantics for anti-analysis
//   - 5-10 fused compound ops that execute multi-instruction sequences
//   - Instruction format: [op, A, B, C, D] (5-element Lua array)
//   - Encoding: two 32-bit integers (b8, b9), bit-extracted via a8()
//
// Encoding scheme (from b3() in reference):
//   b8 = instruction word 1 (11 bits: mode+A+C2, 9 bits: optional D)
//   b9 = instruction word 2 (11 bits: opcode, up to 33 bits: operand)
//   ba = a8(b8, 1, 2)  → mode (0-3): decides where C/D fields come from
//   bb = a8(b9, 1, 11) → opcode number (0-2047, we use 0-69)
//
//   mode 0: C=a8(b8,12,20)  D=a8(b8,21,29)   (both from b8)
//   mode 1: C=a8(b9,12,33)  (from b9, D unused)
//   mode 2: C=a8(b9,12,32)-1048575  (signed from b9, D unused)
//   mode 3: C=a8(b9,12,32)-1048575  D=a8(b8,21,29)  (signed C from b9, D from b8)
//
// Operand conventions:
//   A (bc[2]): destination register or source register 1
//   B (bc[3]): source register 2 or constant index or jump offset
//   C (bc[5] in ref): source register/constant index or jump offset
//   D: extra operand for fused ops
// ---- Semantic opcode groups ----
// The 70 numbers map to ~35 unique semantics. We define both the semantic
// enum and the full 70-number alias table for the runtime dispatch.
export var Op;
(function (Op) {
    // --- Arithmetic (reg-const) ---
    Op["ADD_RC"] = "ADD_RC";
    // --- Arithmetic (reg-reg) ---
    Op["ADD_RR"] = "ADD_RR";
    Op["SUB_RR"] = "SUB_RR";
    Op["MOD_RR"] = "MOD_RR";
    Op["MOD_RC"] = "MOD_RC";
    Op["MUL_RR"] = "MUL_RR";
    Op["DIV_RR"] = "DIV_RR";
    // --- Data movement ---
    Op["MOVE"] = "MOVE";
    Op["LOADK"] = "LOADK";
    Op["LOADBOOL"] = "LOADBOOL";
    Op["LEN"] = "LEN";
    Op["CONCAT"] = "CONCAT";
    // --- Table access ---
    Op["GETFIELD_K"] = "GETFIELD_K";
    Op["GETFIELD_K2"] = "GETFIELD_K2";
    Op["SETTABLE"] = "SETTABLE";
    // --- Upvalues / Globals ---
    Op["GETUPVAL"] = "GETUPVAL";
    Op["SETGLOBAL"] = "SETGLOBAL";
    // --- Closures ---
    Op["CLOSURE"] = "CLOSURE";
    Op["CLOSURE_SIMPLE"] = "CLOSURE_SIMPLE";
    // --- Calls ---
    Op["CALL_RET_N"] = "CALL_RET_N";
    Op["CALL_VA"] = "CALL_VA";
    Op["CALL_1RET"] = "CALL_1RET";
    Op["CALL_TAILCALL"] = "CALL_TAILCALL";
    // --- Returns ---
    Op["RETURN0"] = "RETURN0";
    Op["RETURN_N"] = "RETURN_N";
    Op["RETURN_VA"] = "RETURN_VA";
    // --- Control flow ---
    Op["JUMP"] = "JUMP";
    Op["TEST_EQ_K"] = "TEST_EQ_K";
    Op["TEST_LT_RR"] = "TEST_LT_RR";
    Op["TEST_LE_RR"] = "TEST_LE_RR";
    Op["TEST_GT"] = "TEST_GT";
    Op["TEST_FALSE"] = "TEST_FALSE";
    Op["TEST_NIL"] = "TEST_NIL";
    // --- Loops ---
    Op["FORPREP"] = "FORPREP";
    Op["FORLOOP"] = "FORLOOP";
    // --- Direct comparison (register-set) — v0.4 ---
    // These set R[A] = (R[B] op R[C]) directly, avoiding the SUB_RR+TEST
    // hack that breaks for non-numeric operands (e.g. string equality).
    Op["EQ_RR"] = "EQ_RR";
    Op["NEQ_RR"] = "NEQ_RR";
    Op["LT_RR_SET"] = "LT_RR_SET";
    Op["LE_RR_SET"] = "LE_RR_SET";
    Op["GT_RR_SET"] = "GT_RR_SET";
    Op["GE_RR_SET"] = "GE_RR_SET";
    // --- Power operator — v0.4 ---
    Op["POW_RR"] = "POW_RR";
    // --- Table get with register index — v0.4 ---
    Op["GETTABLE_RR"] = "GETTABLE_RR";
    // --- Table set with register index — v0.4 ---
    Op["SETTABLE_RR"] = "SETTABLE_RR";
    // --- Real upvalue access — v0.4 (closures capturing parent locals) ---
    Op["GETUPVAL_REAL"] = "GETUPVAL_REAL";
    Op["SETUPVAL_REAL"] = "SETUPVAL_REAL";
    // --- Fused compound ops ---
    // These execute multi-instruction sequences in a single dispatch case.
    // They are the hardest to analyze but provide the most compression.
    Op["FUSED_CALL_LOADK_LEN_SUB"] = "FUSED_CALL_LOADK_LEN_SUB";
    Op["FUSED_TAILCALL_VA"] = "FUSED_TAILCALL_VA";
    Op["FUSED_CALL_5RET"] = "FUSED_CALL_5RET";
    Op["FUSED_TAILCALL_RET"] = "FUSED_TAILCALL_RET";
    Op["FUSED_GETFIELD_CALL_CONCAT"] = "FUSED_GETFIELD_CALL_CONCAT";
    Op["FUSED_CALL_VA_RET"] = "FUSED_CALL_VA_RET";
})(Op || (Op = {}));
// ---- Full 70-number alias table ----
// Maps each of the 70 dispatch numbers (0-69) to a semantic Op.
// Duplicate entries are intentional — the reference sample has the same
// semantics under different dispatch numbers to resist analysis.
// The compiler randomly picks among aliases when emitting instructions.
export const OP_ALIASES = {
    0: Op.ADD_RC,
    1: Op.FUSED_TAILCALL_VA, // fused: call multi + tailcall + return
    2: Op.CLOSURE,
    3: Op.GETFIELD_K,
    4: Op.FUSED_CALL_LOADK_LEN_SUB, // fused
    5: Op.FUSED_TAILCALL_VA, // fused (variant 2)
    6: Op.MOVE,
    7: Op.JUMP,
    8: Op.GETUPVAL,
    9: Op.FUSED_CALL_5RET, // fused
    10: Op.TEST_NIL,
    11: Op.FUSED_TAILCALL_RET, // fused
    12: Op.LOADBOOL,
    13: Op.CALL_TAILCALL,
    14: Op.CALL_RET_N,
    15: Op.MOD_RR,
    16: Op.FUSED_CALL_VA_RET, // fused
    17: Op.CALL_TAILCALL, // same as 13 (tailcall from bp)
    18: Op.ADD_RC, // same as 0
    19: Op.FUSED_GETFIELD_CALL_CONCAT, // fused
    20: Op.GETUPVAL, // same as 8 (but via bh[B] directly)
    21: Op.FORLOOP,
    22: Op.CLOSURE, // same as 2
    23: Op.GETUPVAL, // same as 8
    24: Op.MOD_RR, // same as 15
    25: Op.GETFIELD_K2,
    26: Op.CONCAT,
    27: Op.ADD_RR,
    28: Op.CLOSURE_SIMPLE,
    29: Op.CALL_1RET,
    30: Op.MOVE, // same as 6
    31: Op.MOD_RC,
    32: Op.FORPREP,
    33: Op.LEN,
    34: Op.TEST_EQ_K,
    35: Op.FUSED_CALL_VA_RET, // fused (variant 2)
    36: Op.RETURN_VA,
    37: Op.CLOSURE_SIMPLE, // same as 28
    38: Op.LOADK,
    39: Op.FUSED_CALL_VA_RET, // fused (variant 3)
    40: Op.SUB_RR,
    41: Op.FORPREP, // same as 32 (numeric for with step)
    42: Op.TEST_EQ_K, // same as 34
    43: Op.LOADBOOL, // same as 12
    44: Op.RETURN_N,
    45: Op.RETURN_N, // same as 44
    46: Op.MOD_RC, // same as 31
    47: Op.GETFIELD_K, // same as 3
    48: Op.CALL_1RET, // same as 29
    49: Op.SUB_RR, // same as 40
    50: Op.FUSED_CALL_VA_RET, // fused (variant 4)
    51: Op.RETURN_VA, // same as 36
    52: Op.LEN, // same as 33
    53: Op.SETGLOBAL,
    54: Op.CONCAT, // same as 26
    55: Op.RETURN0,
    56: Op.LOADK, // same as 38
    57: Op.JUMP, // same as 7
    58: Op.ADD_RR, // same as 27
    59: Op.MUL_RR, // new: multiplication
    60: Op.SETGLOBAL, // same as 53
    61: Op.TEST_NIL, // same as 10
    62: Op.TEST_FALSE,
    63: Op.FUSED_GETFIELD_CALL_CONCAT, // fused (variant 2)
    64: Op.GETUPVAL, // same as 20/8
    65: Op.FORLOOP, // same as 21
    66: Op.DIV_RR, // new: division
    67: Op.GETFIELD_K2, // same as 25
    68: Op.RETURN0, // same as 55
    69: Op.SETTABLE, // new: table field store
    70: Op.TEST_LT_RR, // new: reg < reg
    71: Op.TEST_LE_RR, // new: reg <= reg
    // ---- v0.4 additions: direct comparison (register-set) + pow + gettable_rr ----
    72: Op.EQ_RR, // R[A] = (R[B] == R[C])
    73: Op.NEQ_RR, // R[A] = (R[B] ~= R[C])
    74: Op.LT_RR_SET, // R[A] = (R[B] <  R[C])
    75: Op.LE_RR_SET, // R[A] = (R[B] <= R[C])
    76: Op.GT_RR_SET, // R[A] = (R[B] >  R[C])
    77: Op.GE_RR_SET, // R[A] = (R[B] >= R[C])
    78: Op.POW_RR, // R[A] = R[B] ^ R[C]
    79: Op.GETTABLE_RR, // R[A] = R[B][R[C]]
    80: Op.EQ_RR, // alias for EQ_RR
    81: Op.SETTABLE_RR, // R[A][R[B]] = R[C]
    // ---- v0.4: real upvalue access (closures capturing parent locals) ----
    82: Op.GETUPVAL_REAL, // R[A] = upvals[B]  (true upvalue by index)
    83: Op.SETUPVAL_REAL, // upvals[B] = R[A]
};
// Reverse map: Op → list of alias numbers
export function getAliases(op) {
    const result = [];
    for (const [num, sem] of Object.entries(OP_ALIASES)) {
        if (sem === op)
            result.push(Number(num));
    }
    return result;
}
// ---- Helper: pick a random alias for a given semantic Op ----
export function pickAlias(rng, op) {
    const aliases = getAliases(op);
    if (aliases.length === 0) {
        throw new Error(`No alias found for Op.${op}`);
    }
    return aliases[Math.floor(rng() * aliases.length)];
}
//# sourceMappingURL=opcodes.js.map