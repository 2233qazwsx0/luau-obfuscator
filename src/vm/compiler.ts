// src/vm/compiler.ts — AST → bytecode compiler.
//
// Walks the parser's AST and generates a FuncPrototype tree.
// Each function (including the main chunk) becomes a FuncPrototype with
// its own instructions, constants, sub-functions, and upvalue descriptors.
//
// Register allocation:
//   - Each function has a flat register array R[0..255].
//   - Parameters occupy R[0..paramCount-1].
//   - Local variables are allocated sequentially after parameters.
//   - Temporary values use registers above the current local high-water mark.
//
// Jump handling:
//   - Two-pass: first emit instructions with placeholder offsets,
//     then patch jump targets in a final pass.
//
// The compiler uses pickAlias() to randomly select among the 70 opcode
// aliases, making each compilation produce different bytecode even for
// the same input + same seed (seed determines alias selection).

import type { Node } from "../parser/parser.js";
import {
  Op, buildSemToOpMap,
  OP_SWITCH_VM, OP_DEAD_VM, VM_COUNT, REAL_VM_IDS, DEAD_VM_IDS,
  type FuncPrototype, type ConstEntry, type EncodeMode,
  type BlindDesc,
} from "./opcodes.js";
import { ConstantPool } from "./constants.js";
import { mulberry32 } from "../util/prng.js";
import {
  INSN_CRYPT_F4,
  INSN_CRYPT_F6,
  genInsnIv,
} from "./insncrypt.js";

/** v0.11 F6 指令层加密模式选项（编译器入口）。 */
export type InsncryptMode = "f6" | "f4" | "off";

/** v0.11 F6: 编译器选项。pipeline.ts 透传。 */
export interface CompilerOptions {
  /**
   * 指令层加密模式。
   * - "f6" (默认): per-IP keystream + per-IP ROL + CBC chaining + IV
   * - "f4"        : v0.6 legacy 单 mulberry32(insnSeed) 流 XOR
   * - "off"       : 不加密（insnSeed 不设，明文写指令，仅用于调试）
   */
  insnCrypt?: InsncryptMode;
}

// ---- Compiler state ----

interface Scope {
  // Variable name → register index
  locals: Map<string, number>;
  // Next available register (above all locals)
  nextReg: number;
  // Upvalue references needed by this scope
  upvalueRefs: Map<string, number>; // name → index into upvalues[]
  upvalues: { fromStack: boolean; index: number }[];
  // Parent scope (for upvalue resolution)
  parent: Scope | null;
}

interface CompilerFunc {
  scope: Scope;
  proto: FuncPrototype;
  pool: ConstantPool;
  // Jump patches: list of instruction indices that need offset patching
  jumpPatches: { insnIdx: number; target: number }[];
  // Sub-functions collected during compilation
  subFuncs: FuncPrototype[];
  // Label positions for goto/label support
  labels: Map<string, number>;
  pendingGotos: { label: string; insnIdx: number }[];
  // Loop break/continue stack: each loop pushes its start/end instruction indices
  // v0.8: loopStartVm = 循环头所在的 VM。回边 JUMP / FORLOOP、break、continue
  // 在跳转前必须 sync 到此 VM，否则跳入按旧 VM 编码的指令会被新 VM 误解。
  loopStack: { loopStart: number; loopStartVm: number; breakPatches: number[] }[];
  // v0.8 多 VM：本函数默认 VM（决定 proto.vmId，运行时从此 VM 开始解释）。
  vmId: number;
  // 当前正在使用的 VM（随 SWITCH_VM 改变）。emitOp 据此选择 op 号。
  currentVm: number;
  // 距上次 VM 切换已发射的语义指令数；达到 nextSwitchAt 时插入 SWITCH_VM/诱饵。
  insnsSinceSwitch: number;
  // 下次切换点（5-30 条语义指令之间，随机）。
  nextSwitchAt: number;
}

// ---- Main compiler entry point ----

export function compileAST(
  ast: Node,
  seed: number,
  opts: CompilerOptions = {},
): FuncPrototype {
  const rng = mulberry32((seed ^ 0xC0FFEE) >>> 0);
  const compiler = new Compiler(rng, seed, opts);
  return compiler.compileChunk(ast);
}

// ---- Compiler class ----

class Compiler {
  private rng: () => number;
  private seed: number;
  // v0.8 多 VM：sem→op 正向表，按 vmId 索引。每个 VM 下同一语义对应不同 op 号。
  // buildSemToOpMap 对多别名的语义随机选一个；这里固定下来贯穿整次编译，
  // 保证同一函数内同一语义始终用同一 op 号。映射由 seed 派生，运行时用同
  // 一个 seed 重建反查表 vm_maps，从而正确解释字节码。
  // v0.6 F5：索引 0..REAL_VM_IDS.length-1 是真 VM；3..4 是假 VM（复用 1/2 的同结构表）。
  private readonly semToOpMaps: Map<Op, number>[];
  // v0.6 F4：全局递增 proto 计数器，用作 insnSeed 派生源。
  private protoCounter: number;
  // v0.6 F3 阈值
  private readonly BLIND_STR_MIN = 8;
  private readonly BLIND_NUM_MIN = 8;
  // v0.11 F6: 指令层加密模式（"f6" / "f4" / "off"）。
  private readonly insnCrypt: InsncryptMode;

  constructor(rng: () => number, seed: number, opts: CompilerOptions = {}) {
    this.rng = rng;
    this.seed = seed >>> 0;
    this.semToOpMaps = [];
    this.protoCounter = 0;
    this.insnCrypt = opts.insnCrypt ?? "f6";
    for (let vm = 0; vm < VM_COUNT; vm++) {
      this.semToOpMaps.push(buildSemToOpMap(seed, vm, rng));
    }
  }

  compileChunk(ast: Node): FuncPrototype {
    const func: CompilerFunc = this.newFunc(null, 0, true);
    this.compileBlock(func, ast);
    // Add implicit return
    this.emitOp(func, Op.RETURN0, 0, 0, 0, 0, 0);
    this.patchJumps(func);
    this.resolveGotos(func);
    return this.finalize(func);
  }

  // ---- Function management ----

  private newFunc(parent: CompilerFunc | null, paramCount: number, isVararg: boolean): CompilerFunc {
    const pool = new ConstantPool();
    const scope: Scope = {
      locals: new Map(),
      nextReg: paramCount,
      upvalueRefs: new Map(),
      upvalues: [],
      parent: parent ? parent.scope : null,
    };
    // v0.8：每个函数随机分配一个默认 VM。运行时 vm_execute 以 proto.vmId 起步，
    // 之后由字节码内的 SWITCH_VM 在 VM 之间切换。
    // v0.6 F5：只在 REAL_VM_IDS (0/1/2) 中分配。假 VM (3/4) 仅用于诱饵分支。
    const vmId = REAL_VM_IDS[Math.floor(this.rng() * REAL_VM_IDS.length)]!;
    const proto: FuncPrototype = {
      instructions: [],
      constants: [],
      subFunctions: [],
      paramCount,
      isVararg,
      upvalues: [],
      vmId,
    };
    return {
      scope,
      proto,
      pool,
      jumpPatches: [],
      subFuncs: [],
      labels: new Map(),
      pendingGotos: [],
      loopStack: [],
      vmId,
      currentVm: vmId,
      insnsSinceSwitch: 0,
      nextSwitchAt: 5 + Math.floor(this.rng() * 26), // 5..30
    };
  }

  // ---- Register management ----

  private allocReg(func: CompilerFunc, name?: string): number {
    const reg = func.scope.nextReg;
    func.scope.nextReg++;
    if (name) func.scope.locals.set(name, reg);
    return reg;
  }

  private freeReg(func: CompilerFunc, reg: number): void {
    // Only reclaim if it's the topmost temp register
    if (reg === func.scope.nextReg - 1) {
      func.scope.nextReg = reg;
    }
  }

  private getLocal(func: CompilerFunc, name: string): number | null {
    // v0.8 修复：只查当前函数作用域，不向上递归。
    // 寄存器 VM 每个函数有独立寄存器文件，父层 local 必须经 upvalue 访问
    // （resolveUpvalue → GETUPVAL_REAL / SETUPVAL_REAL）。之前这里向上递归，
    // 导致 `count = count + 1`（count 是父层 local）被误判为本函数 local，
    // 写入当前函数 R[count_reg] 而非父层 upvalue，counter 永远返回 0。
    const reg = func.scope.locals.get(name);
    return reg !== undefined ? reg : null;
  }

  // ---- Upvalue resolution ----
  // A variable referenced inside a function that is a local of an enclosing
  // scope becomes an upvalue of the current function. We record an upvalue
  // descriptor (fromStack + index) so the runtime can capture it at CLOSURE.

  /**
   * Resolve `name` as an upvalue of `func`. Returns the upvalue index (into
   * func.scope.upvalues), or null if `name` is a local of the CURRENT scope
   * (not an upvalue) or not found anywhere (→ global).
   */
  private resolveUpvalue(func: CompilerFunc, name: string): number | null {
    if (func.scope.locals.has(name)) return null; // current-scope local
    return this.findUpvalue(func, name, func.scope.parent);
  }

  private findUpvalue(func: CompilerFunc, name: string, scope: Scope | null): number | null {
    if (!scope) return null;
    if (scope.locals.has(name)) {
      // Found in this enclosing scope → capture from its register stack.
      return this.addUpvalueRef(func, true, scope.locals.get(name)!);
    }
    // Not here → recurse up; if found, it's an upvalue of our parent, so we
    // re-export it (fromStack=false, index=parent's upvalue index).
    const parentUpvalIdx = this.findUpvalue(func, name, scope.parent);
    if (parentUpvalIdx !== null) {
      return this.addUpvalueRef(func, false, parentUpvalIdx);
    }
    return null;
  }

  private addUpvalueRef(func: CompilerFunc, fromStack: boolean, index: number): number {
    for (let i = 0; i < func.scope.upvalues.length; i++) {
      const uv = func.scope.upvalues[i]!;
      if (uv.fromStack === fromStack && uv.index === index) return i;
    }
    func.scope.upvalues.push({ fromStack, index });
    return func.scope.upvalues.length - 1;
  }

  // ---- Constant pool ----

  private addConst(func: CompilerFunc, entry: ConstEntry): number {
    return func.pool.add(entry);
  }

  // ---- Instruction emission ----

  private emit(
    func: CompilerFunc,
    op: number,
    A: number,
    B: number,
    C: number,
    D: number,
    mode: EncodeMode = 0,
  ): number {
    const idx = func.proto.instructions.length;
    func.proto.instructions.push({ op, A, B, C, D, mode });
    return idx;
  }

  /** Emit an instruction for a semantic Op.
   *  v0.8: 不再用全局 pickAlias（VM0 标准表），而是按 func.currentVm 查
   *  semToOpMaps，得到当前 VM 下该语义对应的 op 号。同一语义在不同 VM
   *  下编号不同 → 攻击者必须为每个 VM 各逆向一套映射。
   *
   *  在每 5-30 条语义指令之间随机插入 SWITCH_VM（切到另一个 VM）或死 VM
   *  诱饵。SWITCH_VM 对控制流透明（只换 dispatch 表），因此插在任何基本块
   *  边界都不影响跳转偏移：所有偏移在发射时按 live instructions.length 计算，
   *  SWITCH_VM 作为普通指令参与计数。 */
  private emitOp(
    func: CompilerFunc,
    sem: Op,
    A: number,
    B: number,
    C: number,
    D: number,
    mode: EncodeMode = 0,
  ): number {
    // v0.8: 周期性 VM 切换 / 死 VM 诱饵。仅对语义发射触发，SWITCH_VM/DEAD_VM
    // 走 raw emit 不进这里，避免递归。
    if (++func.insnsSinceSwitch >= func.nextSwitchAt) {
      if (this.rng() < 0.25) {
        // 死 VM 诱饵：不可达的 SWITCH_VM deadVm，currentVm 不变。
        this.emitDeadVmDecoy(func);
      } else {
        // 切到另一个 VM（与当前不同）。
        let target = func.currentVm;
        while (target === func.currentVm) {
          target = Math.floor(this.rng() * VM_COUNT);
        }
        this.emitSwitchVm(func, target);
      }
      func.insnsSinceSwitch = 0;
      func.nextSwitchAt = 5 + Math.floor(this.rng() * 26); // 5..30
    }
    const opNum = this.semToOpMaps[func.currentVm]!.get(sem);
    if (opNum === undefined) {
      throw new Error(`emitOp: no op mapping for Op.${sem} in VM${func.currentVm}`);
    }
    return this.emit(func, opNum, A, B, C, D, mode);
  }

  /** v0.8: 发射 SWITCH_VM 指令。op 号 200 是保留号（不参与各 VM 的 op 映射），
   *  运行时遇到 200 时把 current_vm 切到 C。随后 emitOp 用新 VM 的映射表。
   *  该指令对控制流透明（不跳转），因此可以安全插在任何基本块边界。 */
  private emitSwitchVm(func: CompilerFunc, targetVm: number): number {
    func.currentVm = targetVm % VM_COUNT;
    return this.emit(func, OP_SWITCH_VM, 0, 0, func.currentVm, 0, 0);
  }

  /** v0.8: 在 JUMP 源处恢复 VM 到 targetVm。
   *  SWITCH_VM 会改变运行时 current_vm 全局状态。如果循环体内插了 SWITCH_VM，
   *  回边 JUMP 会带着错误的 VM 落到循环头，导致循环头指令（按旧 VM 编码）被
   *  新 VM 误解 → 反编译失败或运行时崩溃。
   *  本方法在发射 JUMP 前确保 currentVm == targetVm，否则补一条 SWITCH_VM。 */
  private syncVmBeforeJump(func: CompilerFunc, targetVm: number): void {
    if (func.currentVm !== targetVm) {
      this.emitSwitchVm(func, targetVm);
    }
  }

  /** v0.8: 发射死 VM 诱饵区。
   *  生成结构：JUMP → DEAD_VM(deadVm) → DEAD_VM(deadVm) → (真实代码继续)
   *  JUMP 的 C = deadCount + 1，跳过整个死区使其中 SWITCH_VM/deadVm 永不执行。
   *  静态分析看到 DEAD_VM 切到 deadVm（>= VM_COUNT，寄存器全是垃圾），但
   *  无法轻易判定该区不可达。本方法用 raw emit，不走 emitOp 的切换计数器，
   *  保证 JUMP 与其落点之间不被插入 SWITCH_VM。 */
  private emitDeadVmDecoy(func: CompilerFunc): void {
    const deadCount = 2;
    const jumpOp = this.semToOpMaps[func.currentVm]!.get(Op.JUMP)!;
    // JUMP C = deadCount + 1（落点 = jump + deadCount + 1，跳过 deadCount 条）。
    this.emit(func, jumpOp, 0, 0, deadCount + 1, 0, 2);
    const deadVm = DEAD_VM_IDS[Math.floor(this.rng() * DEAD_VM_IDS.length)]!;
    for (let i = 0; i < deadCount; i++) {
      this.emit(func, OP_DEAD_VM, 0, 0, deadVm, 0, 0);
    }
  }

  // ---- Jump patching ----

  private emitJump(func: CompilerFunc, sem: Op, A: number, C: number): number {
    // v0.8: JUMP 类指令走 raw emit，不走 emitOp 的计数器。
    // 否则计数器可能在 syncVmBeforeJump 之后、JUMP 之前插入 SWITCH_VM，
    // 破坏 JUMP 源/目标的 VM 一致性。
    const opNum = this.semToOpMaps[func.currentVm]!.get(sem);
    if (opNum === undefined) {
      throw new Error(`emitJump: no op mapping for Op.${sem} in VM${func.currentVm}`);
    }
    return this.emit(func, opNum, A, 0, C, 0, 2);
  }

  private patchJumps(func: CompilerFunc): void {
    for (const { insnIdx, target } of func.jumpPatches) {
      const insn = func.proto.instructions[insnIdx];
      if (insn) {
        insn.C = target - insnIdx;
      }
    }
  }

  private resolveGotos(func: CompilerFunc): void {
    for (const { label, insnIdx } of func.pendingGotos) {
      const target = func.labels.get(label);
      if (target === undefined) {
        throw new Error(`goto to undefined label '${label}'`);
      }
      const insn = func.proto.instructions[insnIdx];
      if (insn) {
        insn.C = target - insnIdx;
      }
    }
  }

  // ---- Finalize a function prototype ----

  private finalize(func: CompilerFunc): FuncPrototype {
    func.proto.constants = func.pool.getAll();
    func.proto.subFunctions = func.subFuncs;
    func.proto.upvalues = func.scope.upvalues;

    // v0.6 F4 / v0.11 F6: 每个 proto 独立的指令加密 seed。
    // insnCrypt 决定模式：f6 (默认) → mode=1 + IV；f4 → mode=0；off → 不设 seed。
    if (this.insnCrypt !== "off") {
      this.protoCounter = (this.protoCounter + 1) >>> 0;
      func.proto.insnSeed = (this.seed ^ (this.protoCounter * 0x9E3779B1)) >>> 0;
      if (this.insnCrypt === "f6") {
        func.proto.insnCryptMode = INSN_CRYPT_F6;
        // IV 由 PRNG 派生，确保确定性。复用 seed + protoCounter 墒源。
        const ivRng = mulberry32(
          (this.seed ^ (this.protoCounter * 0x85EBCA6B)) >>> 0,
        );
        func.proto.insnIv = genInsnIv(ivRng);
      } else {
        // F4 legacy：不写 mode 字节也能向后兼容（反序列化默认 mode=0=F4），
        // 但显式写 0 让 v0.11+ 反序列化端无需 end-of-buffer 探测。
        func.proto.insnCryptMode = INSN_CRYPT_F4;
      }
    }

    // v0.6 F3: 对敏感常量加盲
    const nConst = func.proto.constants.length;
    if (nConst > 0) {
      const descs: (BlindDesc | null)[] = new Array(nConst);
      const localRng = mulberry32(
        (this.seed ^ (this.protoCounter * 0x6D2B79F5)) >>> 0,
      );
      for (let i = 0; i < nConst; i++) {
        const entry = func.proto.constants[i]!;
        let desc: BlindDesc | null = null;
        if (entry.type === "string" && entry.value.length >= this.BLIND_STR_MIN) {
          // str_xor: 4..8 字节密钥
          const klen = 4 + Math.floor(localRng() * 5);
          const key: number[] = new Array(klen);
          for (let k = 0; k < klen; k++) key[k] = Math.floor(localRng() * 256);
          desc = { kind: "str_xor", key };
        } else if (entry.type === "number" && Math.abs(entry.value) >= this.BLIND_NUM_MIN) {
          // num_split: 随机 k2，使 stored = value + k2
          const sign = localRng() < 0.5 ? -1 : 1;
          const magnitude = 1e-6 + localRng() * 1e4;
          let k2 = sign * magnitude;
          // 防止 stored (value + k2) 出现 NaN/Infinity
          const stored = entry.value + k2;
          if (!Number.isFinite(stored)) k2 = -k2;
          desc = { kind: "num_split", k2 };
        }
        descs[i] = desc;
      }
      func.proto.blindDescs = descs;
    }

    return func.proto;
  }

  // ---- Block compilation ----

  private compileBlock(func: CompilerFunc, node: Node): void {
    if (node.t !== "Block") return;
    for (const stmt of node.body) {
      this.compileStmt(func, stmt);
    }
  }

  // ---- Statement compilation ----

  private compileStmt(func: CompilerFunc, stmt: Node): void {
    switch (stmt.t) {
      case "Local":
        this.compileLocal(func, stmt);
        break;
      case "Assign":
        this.compileAssign(func, stmt);
        break;
      case "If":
        this.compileIf(func, stmt);
        break;
      case "While":
        this.compileWhile(func, stmt);
        break;
      case "Repeat":
        this.compileRepeat(func, stmt);
        break;
      case "For":
        this.compileFor(func, stmt);
        break;
      case "ForIn":
        this.compileForIn(func, stmt);
        break;
      case "Function": {
        if ("name" in stmt && stmt.name) {
          this.compileFunctionDecl(func, stmt);
        }
        break;
      }
      case "Return":
        this.compileReturn(func, stmt);
        break;
      case "Call":
        this.compileCallStmt(func, stmt);
        break;
      case "Method":
        this.compileMethodStmt(func, stmt);
        break;
      case "Do":
        this.compileBlock(func, stmt.block);
        break;
      case "Break": {
        // v0.8: break 跳到循环出口（位于回边 JUMP 之后，VM = loopStartVm）。
        // 先 sync 到 loopStartVm 再发射 JUMP，保证落地 VM 一致。
        if (func.loopStack.length > 0) {
          const top = func.loopStack[func.loopStack.length - 1]!;
          this.syncVmBeforeJump(func, top.loopStartVm);
        }
        // Emit JUMP — target will be patched by the enclosing loop
        const breakIdx = this.emitJump(func, Op.JUMP, 0, 0);
        if (func.loopStack.length > 0) {
          const top = func.loopStack[func.loopStack.length - 1]!;
          top.breakPatches.push(breakIdx);
        }
        break;
      }
      case "Continue": {
        // v0.8: continue 跳回循环头（loopStart），VM = loopStartVm。
        if (func.loopStack.length > 0) {
          const top = func.loopStack[func.loopStack.length - 1]!;
          this.syncVmBeforeJump(func, top.loopStartVm);
          // Emit JUMP back to loop start — target patched by enclosing loop
          const contIdx = this.emitJump(func, Op.JUMP, 0, 0);
          func.proto.instructions[contIdx]!.C = top.loopStart - contIdx;
        }
        break;
      }
      case "Goto": {
        this.emitJump(func, Op.JUMP, 0, 0);
        func.pendingGotos.push({ label: stmt.label, insnIdx: func.proto.instructions.length - 1 });
        break;
      }
      case "Label": {
        func.labels.set(stmt.name, func.proto.instructions.length);
        break;
      }
      case "TypeDecl":
        // Type declarations are transparent — no bytecode emitted
        break;
      case "Empty":
        break;
      default:
        // Unhandled statement types — no bytecode emitted
        break;
    }
  }

  // ---- Local declaration ----

  private compileLocal(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "Local") return;
    const numNames = stmt.names.length;
    // Allocate registers for all locals
    const regs: number[] = [];
    for (let i = 0; i < numNames; i++) {
      regs.push(this.allocReg(func, stmt.names[i]));
    }
    // Compile values
    if (stmt.values && stmt.values.length > 0) {
      for (let i = 0; i < stmt.values.length; i++) {
        if (i < numNames) {
          this.compileExpr(func, stmt.values[i]!, regs[i]!);
        } else {
          const tempReg = this.allocReg(func);
          this.compileExpr(func, stmt.values[i]!, tempReg);
          this.freeReg(func, tempReg);
        }
      }
    }
  }

  // ---- Assignment ----

  private compileAssign(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "Assign") return;
    for (let i = 0; i < stmt.targets.length; i++) {
      const target = stmt.targets[i]!;
      const value = stmt.values[i] ?? { t: "Nil" } as Node;

      if (target.t === "Ident") {
        const reg = this.getLocal(func, target.name);
        if (reg !== null) {
          // Local assignment
          this.compileExpr(func, value, reg);
        } else {
          // v0.8 修复：闭合捕获的 upvalue 写回（SETUPVAL_REAL）。
          // 之前只判 local / global，导致 `count = count + 1`（count 是父层
          // local 被闭包捕获）落到 SETGLOBAL 分支，把结果写到 env 表里，
          // upvalue 真值永远不变 → counter 返回 0,0,0。
          const upvalIdx = this.resolveUpvalue(func, target.name);
          if (upvalIdx !== null) {
            const tempReg = this.allocReg(func);
            this.compileExpr(func, value, tempReg);
            this.emitOp(func, Op.SETUPVAL_REAL, tempReg, upvalIdx, 0, 0, 0);
            this.freeReg(func, tempReg);
          } else {
            // Global assignment: SETGLOBAL
            const constIdx = this.addConst(func, { type: "string", value: target.name });
            const tempReg = this.allocReg(func);
            this.compileExpr(func, value, tempReg);
            this.emitOp(func, Op.SETGLOBAL, tempReg, constIdx, 0, 0, 0);
            this.freeReg(func, tempReg);
          }
        }
      } else if (target.t === "Index") {
        // Table field assignment: R[target][key] = R[value]
        const tblReg = this.allocReg(func);
        const valReg = this.allocReg(func);
        this.compileExpr(func, target.obj, tblReg);
        this.compileExpr(func, value, valReg);
        if (target.index.t === "String") {
          // String key → SETTABLE (B = constant index)
          const constIdx = this.addConst(func, { type: "string", value: target.index.value });
          this.emitOp(func, Op.SETTABLE, tblReg, constIdx, valReg, 0, 0);
        } else {
          // Dynamic register key → SETTABLE_RR (B = key register)
          const idxReg = this.allocReg(func);
          this.compileExpr(func, target.index, idxReg);
          this.emitOp(func, Op.SETTABLE_RR, tblReg, idxReg, valReg, 0, 0);
          this.freeReg(func, idxReg);
        }
        this.freeReg(func, valReg);
        this.freeReg(func, tblReg);
      }
    }
  }

  // ---- If statement ----

  private compileIf(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "If") return;
    const jumpTargets: number[] = [];
    // v0.8: 记录 if 入口 VM。所有分支的 TEST_FALSE 和 end-JUMP 都以此 VM
    // 为基准，确保所有路径在 if 结束后汇聚到同一 VM。否则 then-branch 里的
    // SWITCH_VM 会让 end-JUMP 带着错误的 VM 落到 if 之后的代码。
    const preIfVm = func.currentVm;

    for (let i = 0; i < stmt.branches.length; i++) {
      const branch = stmt.branches[i]!;
      // v0.8: 每个分支头部 sync 到 preIfVm。
      // 上一分支的 end-JUMP 之前已 syncVmBeforeJump(preIfVm)，但 emitOp 计数器
      // 可能在 end-JUMP 后插入 SWITCH_VM。这里强制恢复。
      this.syncVmBeforeJump(func, preIfVm);
      const condReg = this.allocReg(func);
      this.compileExpr(func, branch.cond, condReg);

      // v0.8: 条件表达式编译过程中 emitOp 计数器可能插入 SWITCH_VM，改变
      // currentVm。TEST_FALSE 的跳转目标（下一分支头部）在 preIfVm 中，所以
      // TEST_FALSE 本身也必须在 preIfVm 中。此处 re-sync 保证一致。
      this.syncVmBeforeJump(func, preIfVm);
      // TEST_FALSE: if not cond then jump to next branch/end
      const testIdx = this.emitJump(func, Op.TEST_FALSE, condReg, 0);
      this.freeReg(func, condReg);

      // Compile the then-block
      this.compileBlock(func, branch.block);

      // v0.8: end-JUMP 之前 sync 到 preIfVm，确保落到 if 之后时 VM 正确。
      this.syncVmBeforeJump(func, preIfVm);
      // JUMP to end (skip else/elseif blocks)
      const endJumpIdx = this.emitJump(func, Op.JUMP, 0, 0);
      jumpTargets.push(endJumpIdx);

      // Patch test to jump here (to next branch)
      func.proto.instructions[testIdx]!.C = func.proto.instructions.length - testIdx;
    }

    // Else block
    if (stmt.else) {
      // v0.8: else 分支入口由最后一条 TEST_FALSE 跳入，VM = preIfVm。
      this.syncVmBeforeJump(func, preIfVm);
      this.compileBlock(func, stmt.else);
    }

    // v0.8: 所有路径汇聚点。end-JUMP 带 preIfVm 落地；else/无 else 直落到此。
    // 直落路径的 VM 可能被 else 体内的 SWITCH_VM 改过，需 sync 回 preIfVm。
    this.syncVmBeforeJump(func, preIfVm);

    // Patch all end-jumps to here
    const endPos = func.proto.instructions.length;
    for (const idx of jumpTargets) {
      func.proto.instructions[idx]!.C = endPos - idx;
    }
  }

  // ---- While loop ----

  private compileWhile(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "While") return;
    const loopStart = func.proto.instructions.length;
    const loopStartVm = func.currentVm;
    func.loopStack.push({ loopStart, loopStartVm, breakPatches: [] });

    const condReg = this.allocReg(func);
    this.compileExpr(func, stmt.cond, condReg);

    // v0.8: 条件编译中 emitOp 可能插入 SWITCH_VM。exit TEST_FALSE 的目标
    // （循环出口）在 loopStartVm 中，TEST_FALSE 也必须如此。
    this.syncVmBeforeJump(func, loopStartVm);
    // TEST_FALSE: if not cond then jump past loop
    const exitTestIdx = this.emitJump(func, Op.TEST_FALSE, condReg, 0);
    this.freeReg(func, condReg);

    // Loop body
    this.compileBlock(func, stmt.block);

    // v0.8: 回边 JUMP 前先 sync 到 loopStartVm。循环体内的 SWITCH_VM 可能
    // 改变了 currentVm，回边带着新 VM 落到按旧 VM 编码的循环头会导致解释错乱。
    this.syncVmBeforeJump(func, loopStartVm);
    // JUMP back to loop start
    this.emitJump(func, Op.JUMP, 0, loopStart - func.proto.instructions.length);

    // Patch exit test + all breaks
    const top = func.loopStack.pop()!;
    const exitPos = func.proto.instructions.length;
    func.proto.instructions[exitTestIdx]!.C = exitPos - exitTestIdx;
    for (const breakIdx of top.breakPatches) {
      func.proto.instructions[breakIdx]!.C = exitPos - breakIdx;
    }
  }

  // ---- Repeat-until ----

  private compileRepeat(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "Repeat") return;
    const loopStart = func.proto.instructions.length;
    const loopStartVm = func.currentVm;
    func.loopStack.push({ loopStart, loopStartVm, breakPatches: [] });

    // Loop body
    this.compileBlock(func, stmt.block);

    // v0.8: 回边 TEST_FALSE 前先 sync 到 loopStartVm。
    this.syncVmBeforeJump(func, loopStartVm);

    // Evaluate condition
    const condReg = this.allocReg(func);
    this.compileExpr(func, stmt.cond, condReg);

    // v0.8: 条件编译中 emitOp 可能插入 SWITCH_VM。回边 TEST_FALSE 跳回
    // loopStart（在 loopStartVm 中），TEST_FALSE 也必须如此。
    this.syncVmBeforeJump(func, loopStartVm);
    // TEST_FALSE: if not cond then jump back to loop start
    // Jump convention: C = target - idx (same as JUMP/TEST).
    this.emitJump(func, Op.TEST_FALSE, condReg, loopStart - func.proto.instructions.length);
    this.freeReg(func, condReg);

    // Patch all breaks
    const top = func.loopStack.pop()!;
    const exitPos = func.proto.instructions.length;
    for (const breakIdx of top.breakPatches) {
      func.proto.instructions[breakIdx]!.C = exitPos - breakIdx;
    }
  }

  // ---- Numeric for ----

  private compileFor(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "For") return;
    // R[A] = start, R[A+1] = stop, R[A+2] = step
    const baseReg = this.allocReg(func, stmt.varName);
    const stopReg = this.allocReg(func);
    const stepReg = this.allocReg(func);
    const counterReg = this.allocReg(func, stmt.varName); // loop variable (visible in body)

    this.compileExpr(func, stmt.start, baseReg);
    this.compileExpr(func, stmt.stop, stopReg);
    if (stmt.step) {
      this.compileExpr(func, stmt.step, stepReg);
    } else {
      // Default step = 1
      const oneIdx = this.addConst(func, { type: "number", value: 1 });
      this.emitOp(func, Op.LOADK, stepReg, oneIdx, 0, 0, 0);
    }

    // FORPREP: R[baseReg] -= R[stepReg]; then jump FORWARD to FORLOOP.
    // This skips the body on the first pass so the counter is incremented
    // (and the loop var R[A+3] set) before the body ever runs — matches
    // standard Lua VM numeric-for semantics.
    // Use mode=2 (signed C) so negative offsets encode correctly.
    const prepIdx = this.emitOp(func, Op.FORPREP, baseReg, 0, 0, 0, 2);
    const loopBodyStart = func.proto.instructions.length;
    // v0.8: 记录循环头 VM。FORPREP 的前向跳转落到 FORLOOP，二者必须同 VM；
    // FORLOOP 的回边跳到 loopBodyStart，也必须同 VM。loopBodyStartVm 在循环体
    // 第一条指令之前记录，作为回边 sync 的基准。
    const loopBodyStartVm = func.currentVm;
    func.loopStack.push({ loopStart: loopBodyStart, loopStartVm: loopBodyStartVm, breakPatches: [] });

    // Set counter = current value (redundant w/ FORLOOP's R[A+3]=R[A], but
    // keeps a clear register-init point for the body).
    this.emitOp(func, Op.MOVE, counterReg, baseReg, 0, 0, 0);

    // Loop body
    this.compileBlock(func, stmt.block);

    // v0.8: FORLOOP 是回边，跳回 loopBodyStart。循环体内的 SWITCH_VM 可能改变
    // currentVm，必须先 sync 到 loopBodyStartVm。用 emitJump（raw）发射，避免
    // emitOp 计数器在 sync 与 FORLOOP 之间插入 SWITCH_VM 破坏一致性。
    this.syncVmBeforeJump(func, loopBodyStartVm);
    // FORLOOP: R[baseReg] += R[stepReg]; if within bounds, R[A+3]=R[A] and
    // jump back to body start (loopBodyStart). Jump convention: C = target - idx.
    const forloopIdx = this.emitJump(
      func, Op.FORLOOP, baseReg,
      loopBodyStart - func.proto.instructions.length,
    );

    // Patch FORPREP to jump forward to FORLOOP (skip body on first pass).
    func.proto.instructions[prepIdx]!.C = forloopIdx - prepIdx;

    // Patch all breaks
    const top = func.loopStack.pop()!;
    const exitPos = func.proto.instructions.length;
    for (const breakIdx of top.breakPatches) {
      func.proto.instructions[breakIdx]!.C = exitPos - breakIdx;
    }

    // Free for-loop registers
    this.freeReg(func, counterReg);
    this.freeReg(func, stepReg);
    this.freeReg(func, stopReg);
    this.freeReg(func, baseReg);
  }

  // ---- Generic for (for ... in) ----

  private compileForIn(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "ForIn") return;
    // Register layout:
    //   R[A]   = iterReg  (iterator function, preserved across iterations)
    //   R[A+1] = stateReg (state, preserved)
    //   R[A+2] = ctrlReg  (control, updated each iteration to first loop var)
    //   R[A+3] = callBase / varRegs[0]  (callee + first loop var)
    //   R[A+4] = varRegs[1] / call arg1 (state)
    //   R[A+5] = varRegs[2] / call arg2 (control)  [or temp if numVars < 3]
    //
    // CALL_RET_N puts results starting at the callee register, so the
    // iterator call must use callBase (= varRegs[0]) as A. Before each
    // call, we MOVE iter/state/ctrl into the call positions.
    const iterReg = this.allocReg(func);
    const stateReg = this.allocReg(func);
    const ctrlReg = this.allocReg(func);

    // Compile iterator expressions (e.g., pairs(t), ipairs(t)).
    // For a single call like `pairs(t)`, we need a multi-result call (3
    // results) to fill iterReg, stateReg, ctrlReg simultaneously.
    if (stmt.iter.length === 1 && stmt.iter[0]!.t === "Call") {
      const callExpr = stmt.iter[0]!;
      // Compile callee into iterReg, args right after it (stateReg, ctrlReg)
      this.compileExpr(func, callExpr.callee, iterReg);
      for (let i = 0; i < callExpr.args.length; i++) {
        const reg = iterReg + 1 + i;
        func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
        this.compileExpr(func, callExpr.args[i]!, reg);
      }
      // CALL_RET_N with 3 results → fills iterReg, stateReg, ctrlReg
      this.emitOp(func, Op.CALL_RET_N, iterReg, callExpr.args.length, 3, 0, 0);
      func.scope.nextReg = ctrlReg + 1;
    } else if (stmt.iter.length === 1) {
      this.compileExpr(func, stmt.iter[0]!, iterReg);
    } else if (stmt.iter.length >= 2) {
      this.compileExpr(func, stmt.iter[0]!, iterReg);
      this.compileExpr(func, stmt.iter[1]!, stateReg);
      if (stmt.iter.length >= 3) {
        this.compileExpr(func, stmt.iter[2]!, ctrlReg);
      }
    }

    // Allocate loop variable registers starting at callBase = ctrlReg + 1.
    // The call needs callee at callBase and 2 args at callBase+1, callBase+2.
    // Vars overlap with call area; allocate extra temps if numVars < 3.
    const numVars = stmt.names.length;
    const callBase = this.allocReg(func); // varRegs[0] / call callee
    const varRegs: number[] = [callBase];
    for (let i = 1; i < numVars; i++) {
      varRegs.push(this.allocReg(func, stmt.names[i]));
    }
    // Ensure call args (state, control) have registers at callBase+1, callBase+2
    const callArgsNeeded = 2;
    const existingCallArea = Math.max(numVars, 1); // callBase already allocated
    for (let i = existingCallArea; i < callArgsNeeded + 1; i++) {
      this.allocReg(func); // temp registers for call args beyond varRegs
    }
    // Register the first loop var name if it wasn't registered (callBase was
    // allocated without a name above to avoid cluttering the Local map before
    // the full layout is known — fix it now).
    func.scope.locals.set(stmt.names[0]!, callBase);

    const loopStart = func.proto.instructions.length;
    // v0.8: 记录循环头 VM。回边 JUMP 跳回 loopStart，必须 sync 到此 VM。
    const loopStartVm = func.currentVm;
    func.loopStack.push({ loopStart, loopStartVm, breakPatches: [] });

    // Each iteration: MOVE iterator/state/ctrl into call positions, then call.
    this.emitOp(func, Op.MOVE, callBase, iterReg, 0, 0, 0);     // callee
    this.emitOp(func, Op.MOVE, callBase + 1, stateReg, 0, 0, 0); // state arg
    this.emitOp(func, Op.MOVE, callBase + 2, ctrlReg, 0, 0, 0);  // control arg
    // CALL_RET_N(callBase, 2, numVars) → results in callBase..callBase+numVars-1
    this.emitOp(func, Op.CALL_RET_N, callBase, 2, numVars, 0, 0);

    // v0.8: 上述 emitOp 序列可能触发计数器插入 SWITCH_VM，改变 currentVm。
    // exit TEST_FALSE 的目标（循环出口）在 loopStartVm 中，需 re-sync。
    this.syncVmBeforeJump(func, loopStartVm);
    // Test first variable: if nil/false, exit loop. Save the index so we can
    // patch the jump target to the loop exit below (emitJump leaves C=0).
    const exitTestIdx = this.emitJump(func, Op.TEST_FALSE, callBase, 0);

    // Update control variable for next iteration: ctrl = first loop var
    this.emitOp(func, Op.MOVE, ctrlReg, callBase, 0, 0, 0);

    // Loop body
    this.compileBlock(func, stmt.block);

    // v0.8: 回边 JUMP 前先 sync 到 loopStartVm。循环体内的 SWITCH_VM 可能
    // 改变了 currentVm，回边带着新 VM 落到按旧 VM 编码的循环头会导致解释错乱。
    this.syncVmBeforeJump(func, loopStartVm);
    // JUMP back to the MOVE + call sequence
    this.emitJump(func, Op.JUMP, 0, loopStart - func.proto.instructions.length);

    // Patch exit test + all breaks to jump here (past the loop)
    const top = func.loopStack.pop()!;
    const exitPos = func.proto.instructions.length;
    func.proto.instructions[exitTestIdx]!.C = exitPos - exitTestIdx;
    for (const breakIdx of top.breakPatches) {
      func.proto.instructions[breakIdx]!.C = exitPos - breakIdx;
    }

    // Free registers (call area + iter state)
    const totalCallArea = Math.max(numVars, 3); // callee + 2 args
    func.scope.nextReg = callBase;
    this.freeReg(func, ctrlReg);
    this.freeReg(func, stateReg);
    this.freeReg(func, iterReg);
    void totalCallArea;
  }

  // ---- Function declaration ----

  private compileFunctionDecl(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "Function" || !("name" in stmt) || !stmt.name) return;
    const params = stmt.params.filter(p => p !== "...");

    // For `local function name(...)`, pre-declare the local BEFORE compiling
    // the body so recursive self-references resolve to an upvalue (captured
    // from this register) rather than a global. Standard Lua semantics.
    let preDeclaredReg: number | null = null;
    if (stmt.isLocal && stmt.name.parts.length === 1 && !stmt.name.method) {
      preDeclaredReg = this.allocReg(func, stmt.name.parts[0]!);
    }

    const subFunc = this.newFunc(func, params.length, stmt.params.includes("..."));
    for (let i = 0; i < params.length; i++) {
      subFunc.scope.locals.set(params[i]!, i);
    }
    this.compileBlock(subFunc, stmt.body);
    this.emitOp(subFunc, Op.RETURN0, 0, 0, 0, 0, 0);
    this.patchJumps(subFunc);
    this.resolveGotos(subFunc);
    const proto = this.finalize(subFunc);
    func.subFuncs.push(proto);

    const subIdx = func.subFuncs.length - 1;

    // Assign to local or global
    if (stmt.name.parts.length === 1 && !stmt.name.method) {
      const name = stmt.name.parts[0]!;
      if (preDeclaredReg !== null) {
        // `local function name(...)` — bind closure into the pre-declared local.
        this.emitOp(func, Op.CLOSURE_SIMPLE, preDeclaredReg, subIdx, 0, 0, 0);
      } else {
        const localReg = this.getLocal(func, name);
        if (localReg !== null) {
          // Pre-existing local: reassign the closure into it.
          this.emitOp(func, Op.CLOSURE_SIMPLE, localReg, subIdx, 0, 0, 0);
        } else {
          // Global function: create closure and store in global
          const tempReg = this.allocReg(func);
          this.emitOp(func, Op.CLOSURE_SIMPLE, tempReg, subIdx, 0, 0, 0);
          const constIdx = this.addConst(func, { type: "string", value: name });
          this.emitOp(func, Op.SETGLOBAL, tempReg, constIdx, 0, 0, 0);
          this.freeReg(func, tempReg);
        }
      }
    }
    // TODO: handle dotted names (obj.method = function ...)
  }

  // ---- Return ----

  private compileReturn(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "Return") return;
    if (stmt.values.length === 0) {
      this.emitOp(func, Op.RETURN0, 0, 0, 0, 0, 0);
    } else {
      // Compile all return values into consecutive registers
      const baseReg = this.allocReg(func);
      this.compileExpr(func, stmt.values[0]!, baseReg);
      for (let i = 1; i < stmt.values.length; i++) {
        const reg = baseReg + i;
        func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
        this.compileExpr(func, stmt.values[i]!, reg);
      }
      this.emitOp(func, Op.RETURN_N, baseReg, 0, stmt.values.length + 1, 0, 0);
    }
  }

  // ---- Call statement ----

  private compileCallStmt(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "Call") return;
    // v0.8 修复：CALL_RET_N 要求 callee + args 占用连续寄存器 R[A..A+B]。
    // 之前用 argBase = allocReg()，若 callee 表达式编译时分配过临时寄存器，
    // argBase 会落在 calleeReg 之上的某个空位而非 calleeReg+1，导致运行时
    // 从 R[A+1] 取不到参数（fib 递归 n 为 nil → compare nil < number）。
    const calleeReg = this.allocReg(func);
    this.compileExpr(func, stmt.callee, calleeReg);
    const argBase = calleeReg + 1;
    func.scope.nextReg = Math.max(func.scope.nextReg, argBase + stmt.args.length);
    for (let i = 0; i < stmt.args.length; i++) {
      this.compileExpr(func, stmt.args[i]!, argBase + i);
    }
    // CALL_RET_N with 0 results (statement context)
    this.emitOp(func, Op.CALL_RET_N, calleeReg, stmt.args.length, 0, 0, 0);
    // Reclaim the entire callee+args block
    func.scope.nextReg = calleeReg;
  }

  private compileMethodStmt(func: CompilerFunc, stmt: Node): void {
    if (stmt.t !== "Method") return;
    // obj:method(args) → obj.method(obj, args)
    const objReg = this.allocReg(func);
    this.compileExpr(func, stmt.callee, objReg);
    // obj+1 = method string, obj = function
    const methodConstIdx = this.addConst(func, { type: "string", value: stmt.name });
    // GETFIELD_K: R[objReg+1] = R[objReg]; R[objReg] = R[objReg][K[method]]
    this.emitOp(func, Op.GETFIELD_K, objReg, objReg, methodConstIdx, 0, 0);
    // Args: first arg is self (objReg+1 was set by GETFIELD_K)
    const argBase = objReg + 2;
    func.scope.nextReg = Math.max(func.scope.nextReg, argBase + stmt.args.length);
    for (let i = 0; i < stmt.args.length; i++) {
      this.compileExpr(func, stmt.args[i]!, argBase + i);
    }
    // CALL_RET_N: call R[objReg](R[objReg+1], R[argBase..])
    this.emitOp(func, Op.CALL_RET_N, objReg, stmt.args.length + 1, 0, 0, 0);
    this.freeReg(func, objReg);
  }

  // ---- Expression compilation ----
  // Compiles an expression and places the result in R[destReg].

  private compileExpr(func: CompilerFunc, expr: Node, destReg: number): void {
    switch (expr.t) {
      case "Nil": {
        // Emit LOADBOOL false as a stand-in for nil
        this.emitOp(func, Op.LOADBOOL, destReg, 0, 0, 0, 0);
        break;
      }
      case "Bool": {
        this.emitOp(func, Op.LOADBOOL, destReg, 0, expr.value ? 1 : 0, 0, 0);
        break;
      }
      case "Number": {
        const idx = this.addConst(func, { type: "number", value: Number(expr.value) });
        this.emitOp(func, Op.LOADK, destReg, idx, 0, 0, 0);
        break;
      }
      case "String": {
        const idx = this.addConst(func, { type: "string", value: expr.value });
        this.emitOp(func, Op.LOADK, destReg, idx, 0, 0, 0);
        break;
      }
      case "Ident": {
        // Current-scope local → MOVE
        const localReg = func.scope.locals.get(expr.name);
        if (localReg !== undefined) {
          this.emitOp(func, Op.MOVE, destReg, localReg, 0, 0, 0);
        } else {
          // Enclosing-scope local → upvalue capture
          const upvalIdx = this.resolveUpvalue(func, expr.name);
          if (upvalIdx !== null) {
            this.emitOp(func, Op.GETUPVAL_REAL, destReg, upvalIdx, 0, 0, 0);
          } else {
            // Global access via the env table (GETUPVAL with name constant)
            const constIdx = this.addConst(func, { type: "string", value: expr.name });
            this.emitOp(func, Op.GETUPVAL, destReg, constIdx, 0, 0, 0);
          }
        }
        break;
      }
      case "Binop": {
        this.compileBinop(func, expr, destReg);
        break;
      }
      case "Unop": {
        this.compileUnop(func, expr, destReg);
        break;
      }
      case "Concat": {
        // Compile all parts into consecutive registers, then CONCAT
        const baseReg = this.allocReg(func);
        this.compileExpr(func, expr.parts[0]!, baseReg);
        for (let i = 1; i < expr.parts.length; i++) {
          const reg = baseReg + i;
          func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
          this.compileExpr(func, expr.parts[i]!, reg);
        }
        this.emitOp(func, Op.CONCAT, destReg, baseReg, expr.parts.length, baseReg + expr.parts.length - 1, 0);
        this.freeReg(func, baseReg);
        break;
      }
      case "Call": {
        this.compileCallExpr(func, expr, destReg);
        break;
      }
      case "Method": {
        this.compileMethodExpr(func, expr, destReg);
        break;
      }
      case "Index": {
        const objReg = this.allocReg(func);
        this.compileExpr(func, expr.obj, objReg);
        if (expr.index.t === "String") {
          // Constant string key → GETFIELD_K2
          const constIdx = this.addConst(func, { type: "string", value: expr.index.value });
          this.emitOp(func, Op.GETFIELD_K2, destReg, objReg, constIdx, 0, 0);
        } else if (expr.index.t === "Number") {
          // Numeric index — store as constant and use GETTABLE_RR via a register
          const idxReg = this.allocReg(func);
          this.compileExpr(func, expr.index, idxReg);
          this.emitOp(func, Op.GETTABLE_RR, destReg, objReg, idxReg, 0, 0);
          this.freeReg(func, idxReg);
        } else {
          // Dynamic register index → GETTABLE_RR
          const idxReg = this.allocReg(func);
          this.compileExpr(func, expr.index, idxReg);
          this.emitOp(func, Op.GETTABLE_RR, destReg, objReg, idxReg, 0, 0);
          this.freeReg(func, idxReg);
        }
        this.freeReg(func, objReg);
        break;
      }
      case "Function": {
        this.compileFunctionExpr(func, expr, destReg);
        break;
      }
      case "Table": {
        this.compileTable(func, expr, destReg);
        break;
      }
      case "IfExpr": {
        // if cond then a else b → compile as conditional + move
        const condReg = this.allocReg(func);
        this.compileExpr(func, expr.cond, condReg);
        const testIdx = this.emitJump(func, Op.TEST_FALSE, condReg, 0);
        this.freeReg(func, condReg);

        // Then branch
        this.compileExpr(func, expr.then, destReg);
        const endJumpIdx = this.emitJump(func, Op.JUMP, 0, 0);

        // Else branch
        func.proto.instructions[testIdx]!.C = func.proto.instructions.length - testIdx;
        this.compileExpr(func, expr.else, destReg);

        // Patch end jump
        const endPos = func.proto.instructions.length;
        func.proto.instructions[endJumpIdx]!.C = endPos - endJumpIdx;
        break;
      }
      case "Vararg": {
        // Load vararg into destReg — use a VARARG-like op
        // For now, emit as a placeholder
        this.emitOp(func, Op.MOVE, destReg, 0, 0, 0, 0); // TODO: proper VARARG op
        break;
      }
      case "Interp": {
        // Interp strings are already lowered to Concat by the parser
        // Handle as concat chain
        const baseReg = this.allocReg(func);
        for (let i = 0; i < expr.parts.length; i++) {
          const reg = baseReg + i;
          func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
          this.compileExpr(func, expr.parts[i]!, reg);
        }
        this.emitOp(func, Op.CONCAT, destReg, baseReg, expr.parts.length, baseReg + expr.parts.length - 1, 0);
        this.freeReg(func, baseReg);
        break;
      }
      default:
        // Unhandled expression type — emit nil placeholder
        this.emitOp(func, Op.LOADBOOL, destReg, 0, 0, 0, 0);
        break;
    }
  }

  // ---- Binary operations ----

  private compileBinop(func: CompilerFunc, expr: Node, destReg: number): void {
    if (expr.t !== "Binop") return;
    // Concat needs its operands in CONSECUTIVE registers (R[base], R[base+1])
    // because CONCAT reads a range R[B]..R[D]. Handle before the general
    // lhsReg/rhsReg alloc so we control register layout.
    if (expr.op === "..") {
      const baseReg = this.allocReg(func);
      this.compileExpr(func, expr.lhs, baseReg);
      const rhsSlot = baseReg + 1;
      func.scope.nextReg = Math.max(func.scope.nextReg, rhsSlot + 1);
      this.compileExpr(func, expr.rhs, rhsSlot);
      this.emitOp(func, Op.CONCAT, destReg, baseReg, 2, rhsSlot, 0);
      this.freeReg(func, baseReg);
      return;
    }
    const lhsReg = this.allocReg(func);
    const rhsReg = this.allocReg(func);
    this.compileExpr(func, expr.lhs, lhsReg);
    this.compileExpr(func, expr.rhs, rhsReg);

    switch (expr.op) {
      case "+":
        this.emitOp(func, Op.ADD_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      case "-":
        this.emitOp(func, Op.SUB_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      case "*":
        this.emitOp(func, Op.MUL_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      case "/":
      case "//":
        this.emitOp(func, Op.DIV_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      case "%":
        this.emitOp(func, Op.MOD_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      case "^":
        // v0.4: proper power operator
        this.emitOp(func, Op.POW_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      case "==": {
        // v0.4: direct equality (works for any type, not just numbers)
        this.emitOp(func, Op.EQ_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      }
      case "~=": {
        this.emitOp(func, Op.NEQ_RR, destReg, lhsReg, rhsReg, 0, 0);
        break;
      }
      case "<": {
        // A < B
        this.emitOp(func, Op.LT_RR_SET, destReg, lhsReg, rhsReg, 0, 0);
        break;
      }
      case ">": {
        // A > B
        this.emitOp(func, Op.GT_RR_SET, destReg, lhsReg, rhsReg, 0, 0);
        break;
      }
      case "<=": {
        // A <= B
        this.emitOp(func, Op.LE_RR_SET, destReg, lhsReg, rhsReg, 0, 0);
        break;
      }
      case ">=": {
        // A >= B
        this.emitOp(func, Op.GE_RR_SET, destReg, lhsReg, rhsReg, 0, 0);
        break;
      }
      case "and":
        // A and B: if A is falsy, result = A, else result = B
        this.emitOp(func, Op.MOVE, destReg, lhsReg, 0, 0, 0);
        const andTestIdx = this.emitJump(func, Op.TEST_FALSE, destReg, 0);
        this.emitOp(func, Op.MOVE, destReg, rhsReg, 0, 0, 0);
        func.proto.instructions[andTestIdx]!.C = func.proto.instructions.length - andTestIdx;
        break;
      case "or":
        // A or B: if A is truthy, result = A, else result = B
        this.emitOp(func, Op.MOVE, destReg, lhsReg, 0, 0, 0);
        const orTestIdx = this.emitJump(func, Op.TEST_FALSE, destReg, 0);
        func.proto.instructions[orTestIdx]!.C = func.proto.instructions.length - orTestIdx;
        this.emitOp(func, Op.MOVE, destReg, rhsReg, 0, 0, 0);
        break;
      default:
        // Unknown operator — nil placeholder
        this.emitOp(func, Op.LOADBOOL, destReg, 0, 0, 0, 0);
        break;
    }

    this.freeReg(func, rhsReg);
    this.freeReg(func, lhsReg);
  }

  // ---- Unary operations ----

  private compileUnop(func: CompilerFunc, expr: Node, destReg: number): void {
    if (expr.t !== "Unop") return;
    const argReg = this.allocReg(func);
    this.compileExpr(func, expr.arg, argReg);

    switch (expr.op) {
      case "-":
        // Negation: 0 - arg
        const zeroIdx = this.addConst(func, { type: "number", value: 0 });
        this.emitOp(func, Op.LOADK, destReg, zeroIdx, 0, 0, 0);
        this.emitOp(func, Op.SUB_RR, destReg, destReg, argReg, 0, 0);
        break;
      case "not":
        this.emitOp(func, Op.LOADBOOL, destReg, 0, 0, 0, 0);
        // if arg is truthy, set false; else set true
        const notTestIdx = this.emitJump(func, Op.TEST_FALSE, argReg, 0);
        func.proto.instructions[notTestIdx]!.C = func.proto.instructions.length - notTestIdx;
        this.emitOp(func, Op.LOADBOOL, destReg, 0, 1, 0, 0);
        break;
      case "#":
        this.emitOp(func, Op.LEN, destReg, argReg, 0, 0, 0);
        break;
      default:
        this.emitOp(func, Op.LOADBOOL, destReg, 0, 0, 0, 0);
        break;
    }

    this.freeReg(func, argReg);
  }

  // ---- Call expression ----

  private compileCallExpr(func: CompilerFunc, expr: Node, destReg: number): void {
    if (expr.t !== "Call") return;
    // v0.8 修复：CALL_RET_N 要求 callee + args 占用连续寄存器 R[A..A+B]。
    // 总是在栈顶分配 callee，确保 args 可紧跟其后；结果写回 destReg。
    // 之前复用 destReg 作 calleeReg 时，若 destReg 上方还有已分配寄存器
    // （如 binop 的 rhsReg），argBase=allocReg() 会跳过它们，导致运行时
    // 从 R[A+1] 取不到参数。
    const calleeReg = this.allocReg(func);
    this.compileExpr(func, expr.callee, calleeReg);
    const argBase = calleeReg + 1;
    func.scope.nextReg = Math.max(func.scope.nextReg, argBase + expr.args.length);
    for (let i = 0; i < expr.args.length; i++) {
      this.compileExpr(func, expr.args[i]!, argBase + i);
    }
    // CALL_RET_N with 1 result to calleeReg
    this.emitOp(func, Op.CALL_RET_N, calleeReg, expr.args.length, 1, 0, 0);
    // Move result to destReg if needed
    if (calleeReg !== destReg) {
      this.emitOp(func, Op.MOVE, destReg, calleeReg, 0, 0, 0);
    }
    // Reclaim the entire callee+args block
    func.scope.nextReg = calleeReg;
  }

  // ---- Method expression ----

  private compileMethodExpr(func: CompilerFunc, expr: Node, destReg: number): void {
    if (expr.t !== "Method") return;
    const objReg = this.allocReg(func);
    this.compileExpr(func, expr.callee, objReg);
    const methodConstIdx = this.addConst(func, { type: "string", value: expr.name });
    // GETFIELD_K: R[objReg+1] = R[objReg]; R[objReg] = R[objReg][K[method]]
    this.emitOp(func, Op.GETFIELD_K, objReg, objReg, methodConstIdx, 0, 0);
    // Args: first arg is self (at objReg+1), then regular args
    const argBase = objReg + 2;
    func.scope.nextReg = Math.max(func.scope.nextReg, argBase + expr.args.length);
    for (let i = 0; i < expr.args.length; i++) {
      this.compileExpr(func, expr.args[i]!, argBase + i);
    }
    // CALL_RET_N: call R[objReg](R[objReg+1], R[argBase..])
    this.emitOp(func, Op.CALL_RET_N, objReg, expr.args.length + 1, 1, 0, 0);
    // Move result to destReg
    this.emitOp(func, Op.MOVE, destReg, objReg, 0, 0, 0);
    this.freeReg(func, objReg);
  }

  // ---- Function expression (anonymous) ----

  private compileFunctionExpr(func: CompilerFunc, expr: Node, destReg: number): void {
    if (expr.t !== "Function") return;
    const params = expr.params.filter(p => p !== "...");
    const subFunc = this.newFunc(func, params.length, "vararg" in expr ? expr.vararg : expr.params.includes("..."));
    for (let i = 0; i < params.length; i++) {
      subFunc.scope.locals.set(params[i]!, i);
    }
    this.compileBlock(subFunc, expr.body);
    this.emitOp(subFunc, Op.RETURN0, 0, 0, 0, 0, 0);
    this.patchJumps(subFunc);
    this.resolveGotos(subFunc);
    const proto = this.finalize(subFunc);
    func.subFuncs.push(proto);
    const subIdx = func.subFuncs.length - 1;
    this.emitOp(func, Op.CLOSURE_SIMPLE, destReg, subIdx, 0, 0, 0);
  }

  // ---- Table constructor ----
  private compileTable(func: CompilerFunc, expr: Node, destReg: number): void {
    if (expr.t !== "Table") return;
    // Emit a NEWTABLE-like op: we reuse LOADBOOL with C=2 as a sentinel meaning
    // "R[A] = {}" (empty table). The runtime treats LOADBOOL C=2 specially.
    this.emitOp(func, Op.LOADBOOL, destReg, 0, 2, 0, 0);

    let arrayIdx = 1; // Lua tables are 1-indexed
    for (const f of expr.fields) {
      if (f.key) {
        // R[destReg][K[key]] = R[value]
        if (f.key.t === "String") {
          const keyIdx = this.addConst(func, { type: "string", value: f.key.value });
          const valReg = this.allocReg(func);
          this.compileExpr(func, f.value, valReg);
          this.emitOp(func, Op.SETTABLE, destReg, keyIdx, valReg, 0, 0);
          this.freeReg(func, valReg);
        } else {
          const keyReg = this.allocReg(func);
          const valReg = this.allocReg(func);
          this.compileExpr(func, f.key, keyReg);
          this.compileExpr(func, f.value, valReg);
          this.emitOp(func, Op.SETTABLE, destReg, keyReg, valReg, 0, 0);
          this.freeReg(func, valReg);
          this.freeReg(func, keyReg);
        }
      } else {
        // Array-like entry: store at sequential integer keys (1, 2, 3, ...)
        const valReg = this.allocReg(func);
        this.compileExpr(func, f.value, valReg);
        const keyIdx = this.addConst(func, { type: "number", value: arrayIdx });
        this.emitOp(func, Op.SETTABLE, destReg, keyIdx, valReg, 0, 0);
        this.freeReg(func, valReg);
        arrayIdx++;
      }
    }
  }
}