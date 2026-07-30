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
import { Op, pickAlias, } from "./opcodes.js";
import { ConstantPool } from "./constants.js";
import { mulberry32 } from "../util/prng.js";
// ---- Main compiler entry point ----
export function compileAST(ast, seed) {
    const rng = mulberry32((seed ^ 0xC0FFEE) >>> 0);
    const compiler = new Compiler(rng);
    return compiler.compileChunk(ast);
}
// ---- Compiler class ----
class Compiler {
    rng;
    constructor(rng) {
        this.rng = rng;
    }
    compileChunk(ast) {
        const func = this.newFunc(null, 0, true);
        this.compileBlock(func, ast);
        // Add implicit return
        this.emitOp(func, Op.RETURN0, 0, 0, 0, 0, 0);
        this.patchJumps(func);
        this.resolveGotos(func);
        return this.finalize(func);
    }
    // ---- Function management ----
    newFunc(parent, paramCount, isVararg) {
        const pool = new ConstantPool();
        const scope = {
            locals: new Map(),
            nextReg: paramCount,
            upvalueRefs: new Map(),
            upvalues: [],
            parent: parent ? parent.scope : null,
        };
        const proto = {
            instructions: [],
            constants: [],
            subFunctions: [],
            paramCount,
            isVararg,
            upvalues: [],
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
        };
    }
    // ---- Register management ----
    allocReg(func, name) {
        const reg = func.scope.nextReg;
        func.scope.nextReg++;
        if (name)
            func.scope.locals.set(name, reg);
        return reg;
    }
    freeReg(func, reg) {
        // Only reclaim if it's the topmost temp register
        if (reg === func.scope.nextReg - 1) {
            func.scope.nextReg = reg;
        }
    }
    getLocal(func, name) {
        let scope = func.scope;
        while (scope) {
            const reg = scope.locals.get(name);
            if (reg !== undefined)
                return reg;
            scope = scope.parent;
        }
        return null;
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
    resolveUpvalue(func, name) {
        if (func.scope.locals.has(name))
            return null; // current-scope local
        return this.findUpvalue(func, name, func.scope.parent);
    }
    findUpvalue(func, name, scope) {
        if (!scope)
            return null;
        if (scope.locals.has(name)) {
            // Found in this enclosing scope → capture from its register stack.
            return this.addUpvalueRef(func, true, scope.locals.get(name));
        }
        // Not here → recurse up; if found, it's an upvalue of our parent, so we
        // re-export it (fromStack=false, index=parent's upvalue index).
        const parentUpvalIdx = this.findUpvalue(func, name, scope.parent);
        if (parentUpvalIdx !== null) {
            return this.addUpvalueRef(func, false, parentUpvalIdx);
        }
        return null;
    }
    addUpvalueRef(func, fromStack, index) {
        for (let i = 0; i < func.scope.upvalues.length; i++) {
            const uv = func.scope.upvalues[i];
            if (uv.fromStack === fromStack && uv.index === index)
                return i;
        }
        func.scope.upvalues.push({ fromStack, index });
        return func.scope.upvalues.length - 1;
    }
    // ---- Constant pool ----
    addConst(func, entry) {
        return func.pool.add(entry);
    }
    // ---- Instruction emission ----
    emit(func, op, A, B, C, D, mode = 0) {
        const idx = func.proto.instructions.length;
        func.proto.instructions.push({ op, A, B, C, D, mode });
        return idx;
    }
    /** Emit an instruction for a semantic Op, picking a random alias. */
    emitOp(func, sem, A, B, C, D, mode = 0) {
        const alias = pickAlias(this.rng, sem);
        return this.emit(func, alias, A, B, C, D, mode);
    }
    // ---- Jump patching ----
    emitJump(func, sem, A, C) {
        const idx = this.emitOp(func, sem, A, 0, C, 0, 2);
        return idx;
    }
    patchJumps(func) {
        for (const { insnIdx, target } of func.jumpPatches) {
            const insn = func.proto.instructions[insnIdx];
            if (insn) {
                insn.C = target - insnIdx;
            }
        }
    }
    resolveGotos(func) {
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
    finalize(func) {
        func.proto.constants = func.pool.getAll();
        func.proto.subFunctions = func.subFuncs;
        func.proto.upvalues = func.scope.upvalues;
        return func.proto;
    }
    // ---- Block compilation ----
    compileBlock(func, node) {
        if (node.t !== "Block")
            return;
        for (const stmt of node.body) {
            this.compileStmt(func, stmt);
        }
    }
    // ---- Statement compilation ----
    compileStmt(func, stmt) {
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
                // Emit JUMP — target will be patched by the enclosing loop
                const breakIdx = this.emitJump(func, Op.JUMP, 0, 0);
                if (func.loopStack.length > 0) {
                    const top = func.loopStack[func.loopStack.length - 1];
                    top.breakPatches.push(breakIdx);
                }
                break;
            }
            case "Continue": {
                // Emit JUMP back to loop start — target patched by enclosing loop
                const contIdx = this.emitJump(func, Op.JUMP, 0, 0);
                if (func.loopStack.length > 0) {
                    const top = func.loopStack[func.loopStack.length - 1];
                    func.proto.instructions[contIdx].C = top.loopStart - contIdx;
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
    compileLocal(func, stmt) {
        if (stmt.t !== "Local")
            return;
        const numNames = stmt.names.length;
        // Allocate registers for all locals
        const regs = [];
        for (let i = 0; i < numNames; i++) {
            regs.push(this.allocReg(func, stmt.names[i]));
        }
        // Compile values
        if (stmt.values && stmt.values.length > 0) {
            for (let i = 0; i < stmt.values.length; i++) {
                if (i < numNames) {
                    this.compileExpr(func, stmt.values[i], regs[i]);
                }
                else {
                    const tempReg = this.allocReg(func);
                    this.compileExpr(func, stmt.values[i], tempReg);
                    this.freeReg(func, tempReg);
                }
            }
        }
    }
    // ---- Assignment ----
    compileAssign(func, stmt) {
        if (stmt.t !== "Assign")
            return;
        for (let i = 0; i < stmt.targets.length; i++) {
            const target = stmt.targets[i];
            const value = stmt.values[i] ?? { t: "Nil" };
            if (target.t === "Ident") {
                const reg = this.getLocal(func, target.name);
                if (reg !== null) {
                    // Local assignment
                    this.compileExpr(func, value, reg);
                }
                else {
                    // Global assignment: SETGLOBAL
                    const constIdx = this.addConst(func, { type: "string", value: target.name });
                    const tempReg = this.allocReg(func);
                    this.compileExpr(func, value, tempReg);
                    this.emitOp(func, Op.SETGLOBAL, tempReg, constIdx, 0, 0, 0);
                    this.freeReg(func, tempReg);
                }
            }
            else if (target.t === "Index") {
                // Table field assignment: R[target][key] = R[value]
                const tblReg = this.allocReg(func);
                const valReg = this.allocReg(func);
                this.compileExpr(func, target.obj, tblReg);
                this.compileExpr(func, value, valReg);
                if (target.index.t === "String") {
                    // String key → SETTABLE (B = constant index)
                    const constIdx = this.addConst(func, { type: "string", value: target.index.value });
                    this.emitOp(func, Op.SETTABLE, tblReg, constIdx, valReg, 0, 0);
                }
                else {
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
    compileIf(func, stmt) {
        if (stmt.t !== "If")
            return;
        const jumpTargets = [];
        for (let i = 0; i < stmt.branches.length; i++) {
            const branch = stmt.branches[i];
            const condReg = this.allocReg(func);
            this.compileExpr(func, branch.cond, condReg);
            // TEST_FALSE: if not cond then jump to next branch/end
            const testIdx = this.emitJump(func, Op.TEST_FALSE, condReg, 0);
            this.freeReg(func, condReg);
            // Compile the then-block
            this.compileBlock(func, branch.block);
            // JUMP to end (skip else/elseif blocks)
            const endJumpIdx = this.emitJump(func, Op.JUMP, 0, 0);
            jumpTargets.push(endJumpIdx);
            // Patch test to jump here (to next branch)
            func.proto.instructions[testIdx].C = func.proto.instructions.length - testIdx;
        }
        // Else block
        if (stmt.else) {
            this.compileBlock(func, stmt.else);
        }
        // Patch all end-jumps to here
        const endPos = func.proto.instructions.length;
        for (const idx of jumpTargets) {
            func.proto.instructions[idx].C = endPos - idx;
        }
    }
    // ---- While loop ----
    compileWhile(func, stmt) {
        if (stmt.t !== "While")
            return;
        const loopStart = func.proto.instructions.length;
        func.loopStack.push({ loopStart, breakPatches: [] });
        const condReg = this.allocReg(func);
        this.compileExpr(func, stmt.cond, condReg);
        // TEST_FALSE: if not cond then jump past loop
        const exitTestIdx = this.emitJump(func, Op.TEST_FALSE, condReg, 0);
        this.freeReg(func, condReg);
        // Loop body
        this.compileBlock(func, stmt.block);
        // JUMP back to loop start
        this.emitJump(func, Op.JUMP, 0, loopStart - func.proto.instructions.length);
        // Patch exit test + all breaks
        const top = func.loopStack.pop();
        const exitPos = func.proto.instructions.length;
        func.proto.instructions[exitTestIdx].C = exitPos - exitTestIdx;
        for (const breakIdx of top.breakPatches) {
            func.proto.instructions[breakIdx].C = exitPos - breakIdx;
        }
    }
    // ---- Repeat-until ----
    compileRepeat(func, stmt) {
        if (stmt.t !== "Repeat")
            return;
        const loopStart = func.proto.instructions.length;
        func.loopStack.push({ loopStart, breakPatches: [] });
        // Loop body
        this.compileBlock(func, stmt.block);
        // Evaluate condition
        const condReg = this.allocReg(func);
        this.compileExpr(func, stmt.cond, condReg);
        // TEST_FALSE: if not cond then jump back to loop start
        // Jump convention: C = target - idx (same as JUMP/TEST).
        this.emitJump(func, Op.TEST_FALSE, condReg, loopStart - func.proto.instructions.length);
        this.freeReg(func, condReg);
        // Patch all breaks
        const top = func.loopStack.pop();
        const exitPos = func.proto.instructions.length;
        for (const breakIdx of top.breakPatches) {
            func.proto.instructions[breakIdx].C = exitPos - breakIdx;
        }
    }
    // ---- Numeric for ----
    compileFor(func, stmt) {
        if (stmt.t !== "For")
            return;
        // R[A] = start, R[A+1] = stop, R[A+2] = step
        const baseReg = this.allocReg(func, stmt.varName);
        const stopReg = this.allocReg(func);
        const stepReg = this.allocReg(func);
        const counterReg = this.allocReg(func, stmt.varName); // loop variable (visible in body)
        this.compileExpr(func, stmt.start, baseReg);
        this.compileExpr(func, stmt.stop, stopReg);
        if (stmt.step) {
            this.compileExpr(func, stmt.step, stepReg);
        }
        else {
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
        func.loopStack.push({ loopStart: loopBodyStart, breakPatches: [] });
        // Set counter = current value (redundant w/ FORLOOP's R[A+3]=R[A], but
        // keeps a clear register-init point for the body).
        this.emitOp(func, Op.MOVE, counterReg, baseReg, 0, 0, 0);
        // Loop body
        this.compileBlock(func, stmt.block);
        // FORLOOP: R[baseReg] += R[stepReg]; if within bounds, R[A+3]=R[A] and
        // jump back to body start (loopBodyStart). Jump convention: C = target - idx.
        const forloopIdx = this.emitOp(func, Op.FORLOOP, baseReg, 0, loopBodyStart - func.proto.instructions.length, 0, 2);
        // Patch FORPREP to jump forward to FORLOOP (skip body on first pass).
        func.proto.instructions[prepIdx].C = forloopIdx - prepIdx;
        // Patch all breaks
        const top = func.loopStack.pop();
        const exitPos = func.proto.instructions.length;
        for (const breakIdx of top.breakPatches) {
            func.proto.instructions[breakIdx].C = exitPos - breakIdx;
        }
        // Free for-loop registers
        this.freeReg(func, counterReg);
        this.freeReg(func, stepReg);
        this.freeReg(func, stopReg);
        this.freeReg(func, baseReg);
    }
    // ---- Generic for (for ... in) ----
    compileForIn(func, stmt) {
        if (stmt.t !== "ForIn")
            return;
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
        if (stmt.iter.length === 1 && stmt.iter[0].t === "Call") {
            const callExpr = stmt.iter[0];
            // Compile callee into iterReg, args right after it (stateReg, ctrlReg)
            this.compileExpr(func, callExpr.callee, iterReg);
            for (let i = 0; i < callExpr.args.length; i++) {
                const reg = iterReg + 1 + i;
                func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
                this.compileExpr(func, callExpr.args[i], reg);
            }
            // CALL_RET_N with 3 results → fills iterReg, stateReg, ctrlReg
            this.emitOp(func, Op.CALL_RET_N, iterReg, callExpr.args.length, 3, 0, 0);
            func.scope.nextReg = ctrlReg + 1;
        }
        else if (stmt.iter.length === 1) {
            this.compileExpr(func, stmt.iter[0], iterReg);
        }
        else if (stmt.iter.length >= 2) {
            this.compileExpr(func, stmt.iter[0], iterReg);
            this.compileExpr(func, stmt.iter[1], stateReg);
            if (stmt.iter.length >= 3) {
                this.compileExpr(func, stmt.iter[2], ctrlReg);
            }
        }
        // Allocate loop variable registers starting at callBase = ctrlReg + 1.
        // The call needs callee at callBase and 2 args at callBase+1, callBase+2.
        // Vars overlap with call area; allocate extra temps if numVars < 3.
        const numVars = stmt.names.length;
        const callBase = this.allocReg(func); // varRegs[0] / call callee
        const varRegs = [callBase];
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
        func.scope.locals.set(stmt.names[0], callBase);
        const loopStart = func.proto.instructions.length;
        func.loopStack.push({ loopStart, breakPatches: [] });
        // Each iteration: MOVE iterator/state/ctrl into call positions, then call.
        this.emitOp(func, Op.MOVE, callBase, iterReg, 0, 0, 0); // callee
        this.emitOp(func, Op.MOVE, callBase + 1, stateReg, 0, 0, 0); // state arg
        this.emitOp(func, Op.MOVE, callBase + 2, ctrlReg, 0, 0, 0); // control arg
        // CALL_RET_N(callBase, 2, numVars) → results in callBase..callBase+numVars-1
        this.emitOp(func, Op.CALL_RET_N, callBase, 2, numVars, 0, 0);
        // Test first variable: if nil/false, exit loop. Save the index so we can
        // patch the jump target to the loop exit below (emitJump leaves C=0).
        const exitTestIdx = this.emitJump(func, Op.TEST_FALSE, callBase, 0);
        // Update control variable for next iteration: ctrl = first loop var
        this.emitOp(func, Op.MOVE, ctrlReg, callBase, 0, 0, 0);
        // Loop body
        this.compileBlock(func, stmt.block);
        // JUMP back to the MOVE + call sequence
        this.emitJump(func, Op.JUMP, 0, loopStart - func.proto.instructions.length);
        // Patch exit test + all breaks to jump here (past the loop)
        const top = func.loopStack.pop();
        const exitPos = func.proto.instructions.length;
        func.proto.instructions[exitTestIdx].C = exitPos - exitTestIdx;
        for (const breakIdx of top.breakPatches) {
            func.proto.instructions[breakIdx].C = exitPos - breakIdx;
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
    compileFunctionDecl(func, stmt) {
        if (stmt.t !== "Function" || !("name" in stmt) || !stmt.name)
            return;
        const params = stmt.params.filter(p => p !== "...");
        // For `local function name(...)`, pre-declare the local BEFORE compiling
        // the body so recursive self-references resolve to an upvalue (captured
        // from this register) rather than a global. Standard Lua semantics.
        let preDeclaredReg = null;
        if (stmt.isLocal && stmt.name.parts.length === 1 && !stmt.name.method) {
            preDeclaredReg = this.allocReg(func, stmt.name.parts[0]);
        }
        const subFunc = this.newFunc(func, params.length, stmt.params.includes("..."));
        for (let i = 0; i < params.length; i++) {
            subFunc.scope.locals.set(params[i], i);
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
            const name = stmt.name.parts[0];
            if (preDeclaredReg !== null) {
                // `local function name(...)` — bind closure into the pre-declared local.
                this.emitOp(func, Op.CLOSURE_SIMPLE, preDeclaredReg, subIdx, 0, 0, 0);
            }
            else {
                const localReg = this.getLocal(func, name);
                if (localReg !== null) {
                    // Pre-existing local: reassign the closure into it.
                    this.emitOp(func, Op.CLOSURE_SIMPLE, localReg, subIdx, 0, 0, 0);
                }
                else {
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
    compileReturn(func, stmt) {
        if (stmt.t !== "Return")
            return;
        if (stmt.values.length === 0) {
            this.emitOp(func, Op.RETURN0, 0, 0, 0, 0, 0);
        }
        else {
            // Compile all return values into consecutive registers
            const baseReg = this.allocReg(func);
            this.compileExpr(func, stmt.values[0], baseReg);
            for (let i = 1; i < stmt.values.length; i++) {
                const reg = baseReg + i;
                func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
                this.compileExpr(func, stmt.values[i], reg);
            }
            this.emitOp(func, Op.RETURN_N, baseReg, 0, stmt.values.length + 1, 0, 0);
        }
    }
    // ---- Call statement ----
    compileCallStmt(func, stmt) {
        if (stmt.t !== "Call")
            return;
        const calleeReg = this.allocReg(func);
        this.compileExpr(func, stmt.callee, calleeReg);
        // Compile args into consecutive registers
        const argBase = this.allocReg(func);
        for (let i = 0; i < stmt.args.length; i++) {
            const reg = argBase + i;
            func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
            this.compileExpr(func, stmt.args[i], reg);
        }
        // CALL_RET_N with 0 results (statement context)
        this.emitOp(func, Op.CALL_RET_N, calleeReg, stmt.args.length, 0, 0, 0);
        this.freeReg(func, argBase);
        this.freeReg(func, calleeReg);
    }
    compileMethodStmt(func, stmt) {
        if (stmt.t !== "Method")
            return;
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
            this.compileExpr(func, stmt.args[i], argBase + i);
        }
        // CALL_RET_N: call R[objReg](R[objReg+1], R[argBase..])
        this.emitOp(func, Op.CALL_RET_N, objReg, stmt.args.length + 1, 0, 0, 0);
        this.freeReg(func, objReg);
    }
    // ---- Expression compilation ----
    // Compiles an expression and places the result in R[destReg].
    compileExpr(func, expr, destReg) {
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
                }
                else {
                    // Enclosing-scope local → upvalue capture
                    const upvalIdx = this.resolveUpvalue(func, expr.name);
                    if (upvalIdx !== null) {
                        this.emitOp(func, Op.GETUPVAL_REAL, destReg, upvalIdx, 0, 0, 0);
                    }
                    else {
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
                this.compileExpr(func, expr.parts[0], baseReg);
                for (let i = 1; i < expr.parts.length; i++) {
                    const reg = baseReg + i;
                    func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
                    this.compileExpr(func, expr.parts[i], reg);
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
                }
                else if (expr.index.t === "Number") {
                    // Numeric index — store as constant and use GETTABLE_RR via a register
                    const idxReg = this.allocReg(func);
                    this.compileExpr(func, expr.index, idxReg);
                    this.emitOp(func, Op.GETTABLE_RR, destReg, objReg, idxReg, 0, 0);
                    this.freeReg(func, idxReg);
                }
                else {
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
                func.proto.instructions[testIdx].C = func.proto.instructions.length - testIdx;
                this.compileExpr(func, expr.else, destReg);
                // Patch end jump
                const endPos = func.proto.instructions.length;
                func.proto.instructions[endJumpIdx].C = endPos - endJumpIdx;
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
                    this.compileExpr(func, expr.parts[i], reg);
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
    compileBinop(func, expr, destReg) {
        if (expr.t !== "Binop")
            return;
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
                func.proto.instructions[andTestIdx].C = func.proto.instructions.length - andTestIdx;
                break;
            case "or":
                // A or B: if A is truthy, result = A, else result = B
                this.emitOp(func, Op.MOVE, destReg, lhsReg, 0, 0, 0);
                const orTestIdx = this.emitJump(func, Op.TEST_FALSE, destReg, 0);
                func.proto.instructions[orTestIdx].C = func.proto.instructions.length - orTestIdx;
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
    compileUnop(func, expr, destReg) {
        if (expr.t !== "Unop")
            return;
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
                func.proto.instructions[notTestIdx].C = func.proto.instructions.length - notTestIdx;
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
    compileCallExpr(func, expr, destReg) {
        if (expr.t !== "Call")
            return;
        const calleeReg = (destReg !== func.scope.nextReg - 1) ? destReg : this.allocReg(func);
        this.compileExpr(func, expr.callee, calleeReg);
        const argBase = this.allocReg(func);
        for (let i = 0; i < expr.args.length; i++) {
            const reg = argBase + i;
            func.scope.nextReg = Math.max(func.scope.nextReg, reg + 1);
            this.compileExpr(func, expr.args[i], reg);
        }
        // CALL_RET_N with 1 result to destReg
        this.emitOp(func, Op.CALL_RET_N, calleeReg, expr.args.length, 1, 0, 0);
        // If calleeReg was separate from destReg, move result
        if (calleeReg !== destReg) {
            this.emitOp(func, Op.MOVE, destReg, calleeReg, 0, 0, 0);
            this.freeReg(func, calleeReg);
        }
        this.freeReg(func, argBase);
    }
    // ---- Method expression ----
    compileMethodExpr(func, expr, destReg) {
        if (expr.t !== "Method")
            return;
        const objReg = this.allocReg(func);
        this.compileExpr(func, expr.callee, objReg);
        const methodConstIdx = this.addConst(func, { type: "string", value: expr.name });
        // GETFIELD_K: R[objReg+1] = R[objReg]; R[objReg] = R[objReg][K[method]]
        this.emitOp(func, Op.GETFIELD_K, objReg, objReg, methodConstIdx, 0, 0);
        // Args: first arg is self (at objReg+1), then regular args
        const argBase = objReg + 2;
        func.scope.nextReg = Math.max(func.scope.nextReg, argBase + expr.args.length);
        for (let i = 0; i < expr.args.length; i++) {
            this.compileExpr(func, expr.args[i], argBase + i);
        }
        // CALL_RET_N: call R[objReg](R[objReg+1], R[argBase..])
        this.emitOp(func, Op.CALL_RET_N, objReg, expr.args.length + 1, 1, 0, 0);
        // Move result to destReg
        this.emitOp(func, Op.MOVE, destReg, objReg, 0, 0, 0);
        this.freeReg(func, objReg);
    }
    // ---- Function expression (anonymous) ----
    compileFunctionExpr(func, expr, destReg) {
        if (expr.t !== "Function")
            return;
        const params = expr.params.filter(p => p !== "...");
        const subFunc = this.newFunc(func, params.length, "vararg" in expr ? expr.vararg : expr.params.includes("..."));
        for (let i = 0; i < params.length; i++) {
            subFunc.scope.locals.set(params[i], i);
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
    compileTable(func, expr, destReg) {
        if (expr.t !== "Table")
            return;
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
                }
                else {
                    const keyReg = this.allocReg(func);
                    const valReg = this.allocReg(func);
                    this.compileExpr(func, f.key, keyReg);
                    this.compileExpr(func, f.value, valReg);
                    this.emitOp(func, Op.SETTABLE, destReg, keyReg, valReg, 0, 0);
                    this.freeReg(func, valReg);
                    this.freeReg(func, keyReg);
                }
            }
            else {
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
//# sourceMappingURL=compiler.js.map