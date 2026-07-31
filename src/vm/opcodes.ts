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

import { mulberry32 } from "../util/prng.js";

// ---- Semantic opcode groups ----
// The 70 numbers map to ~35 unique semantics. We define both the semantic
// enum and the full 70-number alias table for the runtime dispatch.

export enum Op {
  // --- Arithmetic (reg-const) ---
  ADD_RC = "ADD_RC",        // R[A] = R[B] + K[C]
  // --- Arithmetic (reg-reg) ---
  ADD_RR = "ADD_RR",        // R[A] = R[B] + R[C]
  SUB_RR = "SUB_RR",        // R[A] = R[B] - R[C]
  MOD_RR = "MOD_RR",        // R[A] = R[B] % R[C]
  MOD_RC = "MOD_RC",        // R[A] = R[B] % K[C]
  MUL_RR = "MUL_RR",        // R[A] = R[B] * R[C]
  DIV_RR = "DIV_RR",        // R[A] = R[B] / R[C]
  // --- Data movement ---
  MOVE = "MOVE",            // R[A] = R[B]
  LOADK = "LOADK",          // R[A] = K[B]
  LOADBOOL = "LOADBOOL",    // R[A] = (C ~= 0)
  LEN = "LEN",              // R[A] = #R[B]
  CONCAT = "CONCAT",        // R[A] = R[B] .. R[B+1] .. ... .. R[D]
    // --- Table access ---
    GETFIELD_K = "GETFIELD_K",// R[A+1] = R[B]; R[A] = R[B][K[C]]  (also SELF-like)
    GETFIELD_K2 = "GETFIELD_K2", // R[A] = R[B][K[C]]  (simple field access)
    SETTABLE = "SETTABLE",    // R[A][K[B]] = R[C]  (table field store)
    // --- Upvalues / Globals ---
  GETUPVAL = "GETUPVAL",    // R[A] = Upvalues[B]
  SETGLOBAL = "SETGLOBAL",  // G[K[B]] = R[A]
  // --- Closures ---
  CLOSURE = "CLOSURE",      // R[A] = new closure from prototype[B] with upvalue captures
  CLOSURE_SIMPLE = "CLOSURE_SIMPLE", // R[A] = createClosure(prototype[B], nil, env)
  // --- Calls ---
  CALL_RET_N = "CALL_RET_N",     // call R[A](R[A+1]..R[A+C-1]), return N results to R[A..]
  CALL_VA = "CALL_VA",     // call R[A](R[A+1]..bp), variable results from aO
  CALL_1RET = "CALL_1RET",   // call R[A](R[A+1]..R[A+C-1]), return 1 result (tailcall-like)
  CALL_TAILCALL = "CALL_TAILCALL", // tailcall R[A](R[A+1]..bp)
  // --- Returns ---
  RETURN0 = "RETURN0",      // return (no values)
  RETURN_N = "RETURN_N",    // return R[A], R[A+1], ..., R[A+C-2]
  RETURN_VA = "RETURN_VA",  // return R[A], R[A+1], ..., R[bp] (variable)
    // --- Control flow ---
    JUMP = "JUMP",            // pc = pc + C
    TEST_EQ_K = "TEST_EQ_K",  // if R[A] == K[C] then pc++ else pc += C
    TEST_LT_RR = "TEST_LT_RR", // if R[A] < R[B] then pc++ else pc += C
    TEST_LE_RR = "TEST_LE_RR", // if R[A] <= R[B] then pc++ else pc += C
    TEST_GT = "TEST_GT",      // if R[A] > R[C] then pc++ else pc += C  (reg compare)
  TEST_FALSE = "TEST_FALSE", // if not R[A] then pc++ else pc += C
  TEST_NIL = "TEST_NIL",    // if not R[B] then pc++ else R[A]=R[B]; pc += next[3]+1
  // --- Loops ---
  FORPREP = "FORPREP",      // R[A] = R[A] - R[A+2]; pc += C  (numeric for prep)
  FORLOOP = "FORLOOP",      // R[A] = R[A] - R[A+2]; if cond then pc += C; R[A+3] = R[A]
  // --- Direct comparison (register-set) — v0.4 ---
  // These set R[A] = (R[B] op R[C]) directly, avoiding the SUB_RR+TEST
  // hack that breaks for non-numeric operands (e.g. string equality).
  EQ_RR = "EQ_RR",          // R[A] = (R[B] == R[C])
  NEQ_RR = "NEQ_RR",        // R[A] = (R[B] ~= R[C])
  LT_RR_SET = "LT_RR_SET",  // R[A] = (R[B] <  R[C])
  LE_RR_SET = "LE_RR_SET",  // R[A] = (R[B] <= R[C])
  GT_RR_SET = "GT_RR_SET",  // R[A] = (R[B] >  R[C])
  GE_RR_SET = "GE_RR_SET",  // R[A] = (R[B] >= R[C])
  // --- Power operator — v0.4 ---
  POW_RR = "POW_RR",        // R[A] = R[B] ^ R[C]
  // --- Table get with register index — v0.4 ---
  GETTABLE_RR = "GETTABLE_RR", // R[A] = R[B][R[C]]
  // --- Table set with register index — v0.4 ---
  SETTABLE_RR = "SETTABLE_RR", // R[A][R[B]] = R[C]
  // --- Real upvalue access — v0.4 (closures capturing parent locals) ---
  GETUPVAL_REAL = "GETUPVAL_REAL", // R[A] = upvals[B]
  SETUPVAL_REAL = "SETUPVAL_REAL", // upvals[B] = R[A]
  // --- Fused compound ops ---
  // These execute multi-instruction sequences in a single dispatch case.
  // They are the hardest to analyze but provide the most compression.
  FUSED_CALL_LOADK_LEN_SUB = "FUSED_CALL_LOADK_LEN_SUB", // op 4: call+noret+len+loadk+...+sub+jump
  FUSED_TAILCALL_VA = "FUSED_TAILCALL_VA", // op 5: load global+call+tailcall+return values+return
  FUSED_CALL_5RET = "FUSED_CALL_5RET", // op 9: call+add+mod+getfield+call+cmp
  FUSED_TAILCALL_RET = "FUSED_TAILCALL_RET", // op 11: call+tailcall+return
  FUSED_GETFIELD_CALL_CONCAT = "FUSED_GETFIELD_CALL_CONCAT", // op 19/63: getupval+getfield+call+concat+...
  FUSED_CALL_VA_RET = "FUSED_CALL_VA_RET", // op 16: call with vararg count from aO
}

// ---- Full 70-number alias table ----
// Maps each of the 70 dispatch numbers (0-69) to a semantic Op.
// Duplicate entries are intentional — the reference sample has the same
// semantics under different dispatch numbers to resist analysis.
// The compiler randomly picks among aliases when emitting instructions.

export const OP_ALIASES: Record<number, Op> = {
  0:  Op.ADD_RC,
  1:  Op.FUSED_TAILCALL_VA,        // fused: call multi + tailcall + return
  2:  Op.CLOSURE,
  3:  Op.GETFIELD_K,
  4:  Op.FUSED_CALL_LOADK_LEN_SUB, // fused
  5:  Op.FUSED_TAILCALL_VA,        // fused (variant 2)
  6:  Op.MOVE,
  7:  Op.JUMP,
  8:  Op.GETUPVAL,
  9:  Op.FUSED_CALL_5RET,          // fused
  10: Op.TEST_NIL,
  11: Op.FUSED_TAILCALL_RET,       // fused
  12: Op.LOADBOOL,
  13: Op.CALL_TAILCALL,
  14: Op.CALL_RET_N,
  15: Op.MOD_RR,
  16: Op.FUSED_CALL_VA_RET,        // fused
  17: Op.CALL_TAILCALL,            // same as 13 (tailcall from bp)
  18: Op.ADD_RC,                   // same as 0
  19: Op.FUSED_GETFIELD_CALL_CONCAT, // fused
  20: Op.GETUPVAL,                 // same as 8 (but via bh[B] directly)
  21: Op.FORLOOP,
  22: Op.CLOSURE,                  // same as 2
  23: Op.GETUPVAL,                 // same as 8
  24: Op.MOD_RR,                   // same as 15
  25: Op.GETFIELD_K2,
  26: Op.CONCAT,
  27: Op.ADD_RR,
  28: Op.CLOSURE_SIMPLE,
  29: Op.CALL_1RET,
  30: Op.MOVE,                     // same as 6
  31: Op.MOD_RC,
  32: Op.FORPREP,
  33: Op.LEN,
  34: Op.TEST_EQ_K,
  35: Op.FUSED_CALL_VA_RET,        // fused (variant 2)
  36: Op.RETURN_VA,
  37: Op.CLOSURE_SIMPLE,           // same as 28
  38: Op.LOADK,
  39: Op.FUSED_CALL_VA_RET,        // fused (variant 3)
  40: Op.SUB_RR,
  41: Op.FORPREP,                  // same as 32 (numeric for with step)
  42: Op.TEST_EQ_K,                // same as 34
  43: Op.LOADBOOL,                 // same as 12
  44: Op.RETURN_N,
  45: Op.RETURN_N,                 // same as 44
  46: Op.MOD_RC,                   // same as 31
  47: Op.GETFIELD_K,               // same as 3
  48: Op.CALL_1RET,                // same as 29
  49: Op.SUB_RR,                   // same as 40
  50: Op.FUSED_CALL_VA_RET,        // fused (variant 4)
  51: Op.RETURN_VA,                // same as 36
  52: Op.LEN,                      // same as 33
  53: Op.SETGLOBAL,
  54: Op.CONCAT,                   // same as 26
  55: Op.RETURN0,
  56: Op.LOADK,                    // same as 38
  57: Op.JUMP,                     // same as 7
  58: Op.ADD_RR,                   // same as 27
   59: Op.MUL_RR,                  // new: multiplication
   60: Op.SETGLOBAL,                // same as 53
   61: Op.TEST_NIL,                 // same as 10
   62: Op.TEST_FALSE,
   63: Op.FUSED_GETFIELD_CALL_CONCAT, // fused (variant 2)
   64: Op.GETUPVAL,                 // same as 20/8
   65: Op.FORLOOP,                  // same as 21
   66: Op.DIV_RR,                   // new: division
   67: Op.GETFIELD_K2,              // same as 25
   68: Op.RETURN0,                  // same as 55
   69: Op.SETTABLE,                 // new: table field store
   70: Op.TEST_LT_RR,               // new: reg < reg
  71: Op.TEST_LE_RR,               // new: reg <= reg
  // ---- v0.4 additions: direct comparison (register-set) + pow + gettable_rr ----
  72: Op.EQ_RR,                    // R[A] = (R[B] == R[C])
  73: Op.NEQ_RR,                   // R[A] = (R[B] ~= R[C])
  74: Op.LT_RR_SET,                // R[A] = (R[B] <  R[C])
  75: Op.LE_RR_SET,                // R[A] = (R[B] <= R[C])
  76: Op.GT_RR_SET,                // R[A] = (R[B] >  R[C])
  77: Op.GE_RR_SET,                // R[A] = (R[B] >= R[C])
  78: Op.POW_RR,                   // R[A] = R[B] ^ R[C]
  79: Op.GETTABLE_RR,              // R[A] = R[B][R[C]]
  80: Op.EQ_RR,                    // alias for EQ_RR
  81: Op.SETTABLE_RR,              // R[A][R[B]] = R[C]
  // ---- v0.4: real upvalue access (closures capturing parent locals) ----
  82: Op.GETUPVAL_REAL,           // R[A] = upvals[B]  (true upvalue by index)
  83: Op.SETUPVAL_REAL,           // upvals[B] = R[A]
  };

// Reverse map: Op → list of alias numbers
export function getAliases(op: Op): number[] {
  const result: number[] = [];
  for (const [num, sem] of Object.entries(OP_ALIASES)) {
    if (sem === op) result.push(Number(num));
  }
  return result;
}

// ---- Instruction encoding modes ----
// Matches the b3() decoder in the reference:
//   mode 0: C from bits 12-20 of b8, D from bits 21-29 of b8
//   mode 1: C from bits 12-33 of b9 (unsigned, up to 22 bits)
//   mode 2: C from bits 12-32 of b9, minus 1048575 (signed, 21-bit range)
//   mode 3: C from bits 12-32 of b9 minus 1048575, D from bits 21-29 of b8

export type EncodeMode = 0 | 1 | 2 | 3;

// ---- Instruction representation ----
// This is the in-memory representation used by the compiler.
// Each instruction is a 5-element array: [opcode_num, A, B, C, D]
// where opcode_num is one of the 70 dispatch numbers.
export type Instruction = {
  op: number;      // dispatch number (0-69)
  A: number;       // operand A (register index, typically 0-255)
  B: number;       // operand B (register or constant index)
  C: number;       // operand C (register, constant index, or jump offset)
  D: number;       // operand D (used by fused ops, 0 if unused)
  mode: EncodeMode; // encoding mode
};

// ---- Function prototype ----
// Mirrors the reference's b7 structure:
//   b7 = { instructions[], constants[], sub_functions[], param_count, upvalues[] }
// (b4=instructions, be=constants, b5=sub_functions, b7[4]=param_count, b6=upvalues)

export interface FuncPrototype {
  instructions: Instruction[];
  constants: ConstEntry[];
  subFunctions: FuncPrototype[];
  paramCount: number;
  isVararg: boolean;
  // Upvalue descriptors: each entry is { fromStack: boolean, index: number }
  // fromStack=true → capture from parent's register stack (bs)
  // fromStack=false → capture from parent's upvalues (bh)
  upvalues: { fromStack: boolean; index: number }[];
  // v0.8 多 VM：本函数默认使用的 VM 编号 (0/1/2)。
  // undefined 视为 0（向后兼容 v0.4 序列化格式）。
  vmId?: number;
  // ---- v0.6 new fields ----
  // v0.6 F3: constant blinding. Parallel array to constants. Entry i != null means
  // constant[i] is stored blinded and must be un-blinded at first LOADK.
  blindDescs?: (BlindDesc | null)[];
  // v0.6 F4 / v0.11 F6: per-proto PRNG seed for instruction-field encryption.
  // undefined = not encrypted (backward compat with unencoded protos used in tests).
  insnSeed?: number;
  // v0.11 F6: 指令层加密模式。
  //   0 / undefined = F4 (legacy stream cipher: 单 mulberry32(insnSeed) 流 XOR)
  //   1             = F6 (per-IP keystream + per-IP ROL + CBC chaining + IV)
  // 新编译默认 F6；F4 路径保留用于反序列化旧 proto / 调试。
  insnCryptMode?: number;
  // v0.11 F6: CBC 链式加密的初始向量。insnCryptMode == 1 时必填。
  // enc_i = ROL((plain_i ^ key_i) ^ enc_{i-1}, rot_i)，enc_{-1} = (ivB8, ivB9)。
  // 篡改任一字节会破坏本条 + 下一条的解密（tamper propagation）。
  insnIv?: { b8: number; b9: number };
}

// ---- v0.6 F3: constant blinding descriptors ----
// Numbers use subtraction split (safe for doubles, no bit fiddling).
// Strings use chunked single-byte-key XOR (the same key pattern repeats).

export type BlindDesc =
  | { kind: "num_split"; k2: number }      // value = stored_k1 - k2  (stored_k1 = value + k2)
  | { kind: "str_xor"; key: number[] };  // bytes[i] XOR key[i % len]

// ---- v0.8: 多 VM 交替执行 ----
// 运行时内置 3 套 opcode 映射。同一语义 Op 在不同 VM 中对应不同的
// dispatch 号。编译器为每个函数随机分配 vmId，并在函数内部随机插入
// SWITCH_VM 指令切换上下文。攻击者必须同时逆向 3 套映射表。
//
// 保留 op 号（不参与上述 70 号表，由运行时单独 dispatch）：
//   200 = SWITCH_VM (C = 目标 vmId)
//   201 = DEAD_VM   (诱饵：跳转到垃圾区，永不执行)

export const OP_SWITCH_VM = 200;
export const OP_DEAD_VM = 201;

/** v0.8 多 VM：内置 VM 数量。VM0-2 复用标准 OP_ALIASES / 派生置换（真VM）。
 *  v0.6 F5：VM3-4 是假 VM（有完整 dispatch 表，但是惰性 junk 写入高寄存器区）。*/
export const VM_COUNT = 5;
/** 真 VM 编号：VM0/1/2（3 套真实执行环境，与 v0.8 兼容）。*/
export const REAL_VM_IDS = [0, 1, 2];
/** 假 VM 编号：VM3/4（v0.6 F5）。有完整 dispatch 结构，但只在 OPAQUE_FALSE 分支
 *  中短暂进入并写入高寄存器（regs[200..255]），不影响真实执行。*/
export const FAKE_VM_IDS = [3, 4];
/** 死 VM 编号：DEAD_VM 指令 / 死区 SWITCH_VM 跳转到这些编号制造混淆。
 *  这些 ID > VM_COUNT，运行时 current_vm 到这里会触发 no-map 错误（永不执行）。*/
export const DEAD_VM_IDS = [5, 6, 7];

/** 构建指定 VM 的 op→sem 反查表。
 *  VM0 用 OP_ALIASES 本身；VM1/VM2 用 seed 派生的置换。
 *  返回 Map<number, Op>：vmInternalOp → 语义 Op。 */
export function buildVmOpMap(seed: number, vmId: number): Map<number, Op> {
  // OP_ALIASES 的条目数（键 0..N-1）。运行时与编译器必须用同一个 N。
  const aliasKeys = Object.keys(OP_ALIASES).map(Number).sort((a, b) => a - b);
  const n = aliasKeys.length;
  if (vmId === 0) {
    // VM0 直接复用标准表
    const m = new Map<number, Op>();
    for (const num of aliasKeys) m.set(num, OP_ALIASES[num]!);
    return m;
  }
  // VM1/VM2：以 seed+vmId 为种子打乱 0..N-1 的顺序，重新分配语义。
  // 同一个语义在 VM1/VM2 下对应不同的 op 号。
  const rng = mulberry32(((seed ^ 0x5AA00000) >>> 0) + vmId * 0x9E3779B1);
  const order = Array.from({ length: n }, (_, i) => i);
  // Fisher-Yates 洗牌
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = order[i]!;
    order[i] = order[j]!;
    order[j] = tmp;
  }
  // 把 OP_ALIASES 的语义（按 op 号升序）按洗牌后的 op 号顺序重新分配。
  // entries[i] 的语义 → 在本 VM 下编号为 order[i]。
  const entries = Object.entries(OP_ALIASES).sort((a, b) => Number(a[0]) - Number(b[0]));
  const m = new Map<number, Op>();
  for (let i = 0; i < entries.length; i++) {
    m.set(order[i]!, entries[i]![1] as Op);
  }
  return m;
}

/** 构建 sem→op 的正向表（编译器用：给定语义，返回该 VM 下的 op 号）。
 *  对于有多别名的语义，随机选一个。 */
export function buildSemToOpMap(seed: number, vmId: number, rng: () => number): Map<Op, number> {
  const opMap = buildVmOpMap(seed, vmId);
  // 收集每个语义的所有 op 号
  const semToOps = new Map<Op, number[]>();
  for (const [num, sem] of opMap) {
    if (!semToOps.has(sem)) semToOps.set(sem, []);
    semToOps.get(sem)!.push(num);
  }
  const result = new Map<Op, number>();
  for (const [sem, ops] of semToOps) {
    result.set(sem, ops[Math.floor(rng() * ops.length)]!);
  }
  return result;
}

export type ConstEntry =
  | { type: "string"; value: string }
  | { type: "bool"; value: boolean }
  | { type: "number"; value: number };

// ---- Helper: pick a random alias for a given semantic Op ----
export function pickAlias(rng: () => number, op: Op): number {
  const aliases = getAliases(op);
  if (aliases.length === 0) {
    throw new Error(`No alias found for Op.${op}`);
  }
  return aliases[Math.floor(rng() * aliases.length)]!;
}
