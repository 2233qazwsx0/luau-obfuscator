// src/ir/flatten.ts - Control-flow flattening (D4): AST -> AST rewrite.
//
// Takes a top-level Block AST, builds basic-block IR via buildIR, shuffles
// state IDs deterministically from seed, and produces a new AST containing:
//
//   local __b = <initial state ID>
//   while true do
//     if __b == <state0> then <block0 stmts>; __b = <next state> end
//     if __b == <state1> then <block1 stmts>; __b = <next state> end
//     ...
//     if __b == -1 then break end
//   end
//
// All new AST nodes use the existing Node types from parser.ts. D2/D3 walks
// run after this pass and will naturally cover all new nodes.
//
// v0.6: Recursive flattening — `flattenRecursive` extends D4 to every Function
// body, building nested dispatch state machines. Each scope uses a unique
// dispatch var name to avoid cross-scope hoisting collisions.
import { buildIR, shuffleArray } from "./ir.js";
import { mulberry32 } from "../util/prng.js";
// Exit state is always -1 (matches TODO.md convention).
const EXIT_STATE = -1;
// Base dispatch variable prefix. Identifiers starting with __ are skipped by D1.
const DISPATCH_PREFIX = "__b";
// Legacy single name (top-level only flattening).
const DISPATCH_VAR = DISPATCH_PREFIX;
// Min non-exit blocks for top-level / non-function blocks.
const MIN_BLOCKS_TOPLEVEL = 2;
// v0.11: 嵌套函数平坦化阈值 + 每作用域 seed 步进。duplicate-return bug 已在
// buildIR 修复（Return 只作 terminator），递归分支正式启用。
const MIN_BLOCKS_FUNC = 3;
const SEED_STEP = 0x9E3779B1;
// v0.11: 状态转移不透明谓词概率。50% 的转移升级为
// `__b = (OPAQUE_TRUE and T) or EXIT_STATE`，其余保持 `__b = T`。
// 攻击者不能假设所有转移都是直赋值，必须逐 case 化简谓词。
const OPAQUE_TRANSITION_PROB = 0.5;
// v0.11: 假路径 case 数量范围。state ID 永不命中任何真实转移目标，
// body 是垃圾 local + __b = -1（万一命中也安全退出）。
const FAKE_CASE_MIN = 2;
const FAKE_CASE_MAX = 4;
/**
 * Main entry (v0.5 behavior): flatten only the top-level Block of `ast` into
 * a dispatch state machine. If the block has <= 1 basic block, returns the
 * original AST unchanged.
 */
export function flattenAST(ast, seed) {
    return flattenBlock(ast, seed, DISPATCH_VAR, MIN_BLOCKS_TOPLEVEL);
}
/**
 * v0.6 entry: recursively flatten every Function body Block in addition to the
 * top-level Block. Innermost functions are flattened first (post-order). Each
 * flattened scope gets a unique dispatch var name (__b, __b1, __b2, ...) to
 * avoid outer-scope collectLocalNames hoisting inner dispatch locals.
 *
 * Top-level threshold: >= 2 non-exit blocks. Function threshold: >= 3 non-exit
 * blocks (skips tiny helpers).
 */
export function flattenRecursive(ast, seed) {
    let scopeCounter = 0;
    // Walk AST bottom-up: transform children, then current node.
    const visit = (n) => {
        // First recurse into children
        walkChildrenInPlace(n, visit);
        // v0.11: 嵌套函数平坦化正式启用。duplicate-return bug 已在 buildIR 修复
        // （Return 只作 terminator，不再进 currentStmts），dispatch 结构不再异常。
        // 每个函数体（>= MIN_BLOCKS_FUNC 个非 exit 块）都被转成独立 dispatch 状态机，
        // 与顶层共用 OPAQUE 转移 + 假路径 case 机制。内层先 flatten（post-order）。
        if (n.t === "Function") {
            scopeCounter++;
            const dispatchVar = `${DISPATCH_PREFIX}${scopeCounter}`;
            const funcSeed = (seed ^ (scopeCounter * SEED_STEP)) >>> 0;
            n.body = flattenBlock(n.body, funcSeed, dispatchVar, MIN_BLOCKS_FUNC);
            return n;
        }
        return n;
    };
    // Flatten nested functions first.
    const processed = visit(ast);
    // Finally flatten top-level (if it's a Block). Use scopeCounter + 1 for
    // unique dispatch var (avoid name clash with any function scope).
    scopeCounter++;
    const topDispatchVar = scopeCounter === 0 ? DISPATCH_PREFIX : `${DISPATCH_PREFIX}${scopeCounter}`;
    const topSeed = (seed ^ 0xDEADBEEF) >>> 0;
    return flattenBlock(processed, topSeed, topDispatchVar, MIN_BLOCKS_TOPLEVEL);
}
// ---------- Core flatten implementation (parameterized) ----------
/**
 * Internal: flatten a single Block node into dispatch state machine.
 * @param ast Must be a Block node (otherwise returned unchanged).
 * @param seed  PRNG seed for this scope.
 * @param dispatchVar Name of the dispatch state variable (e.g. "__b", "__b2").
 * @param minNonExit Flatten only when non-exit block count >= minNonExit.
 */
function flattenBlock(ast, seed, dispatchVar, minNonExit) {
    if (ast.t !== "Block") {
        return ast;
    }
    const blocks = buildIR(ast);
    // Don't flatten unless there are enough non-exit blocks.
    const nonExitCount = blocks.filter((b) => b.terminator.type !== "exit").length;
    if (nonExitCount < minNonExit) {
        return ast;
    }
    const rng = mulberry32(seed);
    const exitBlock = blocks.find((b) => b.terminator.type === "exit");
    const nonExitBlocks = blocks.filter((b) => b.terminator.type !== "exit");
    const shuffledIds = shuffleArray(nonExitBlocks.map((_, i) => i * 7 + 100), rng);
    const stateIdMap = new Map();
    let shuffleIdx = 0;
    for (const b of nonExitBlocks) {
        stateIdMap.set(b.id, shuffledIds[shuffleIdx]);
        shuffleIdx++;
    }
    if (exitBlock) {
        stateIdMap.set(exitBlock.id, EXIT_STATE);
    }
    const initialState = stateIdMap.get(0) ?? 0;
    const hoistedNames = [];
    const hoistedNameSet = new Set();
    for (const block of blocks) {
        if (block.terminator.type === "exit")
            continue;
        for (const stmt of block.stmts) {
            collectLocalNames(stmt, hoistedNames, hoistedNameSet);
        }
    }
    const dispatchCases = [];
    for (const block of blocks) {
        if (block.terminator.type === "exit") {
            continue;
        }
        const stateId = stateIdMap.get(block.id) ?? 0;
        const transformedStmts = block.stmts.map((s) => localToAssign(s));
        const ifBody = buildIfBody({ ...block, stmts: transformedStmts }, stateIdMap, dispatchVar, rng);
        dispatchCases.push(makeIf(makeBinop("==", makeIdent(dispatchVar), makeNumber(String(stateId))), ifBody));
    }
    // v0.11: 假路径 case。state ID 永不在任何真实转移目标中，body 是垃圾 local
    // + __b = -1（万一命中也安全退出）。结构与真实 case 完全一致，攻击者必须逆向
    // dispatch 才能区分真假。数量 2-4 个，随机。
    const realStateIds = new Set(stateIdMap.values());
    const fakeCount = FAKE_CASE_MIN + Math.floor(rng() * (FAKE_CASE_MAX - FAKE_CASE_MIN + 1));
    for (let i = 0; i < fakeCount; i++) {
        let fakeState;
        do {
            fakeState = (Math.floor(rng() * 0x7fffffff) | 1) >>> 0; // 正奇数，避免 -1
        } while (realStateIds.has(fakeState));
        realStateIds.add(fakeState); // 避免假 case 之间重复
        const fakeBody = makeFakeCaseBody(rng, dispatchVar);
        dispatchCases.push(makeIf(makeBinop("==", makeIdent(dispatchVar), makeNumber(String(fakeState))), fakeBody));
    }
    dispatchCases.push(makeIf(makeBinop("==", makeIdent(dispatchVar), makeNumber(String(EXIT_STATE))), makeBlock([makeBreak()])));
    const resultBody = [
        makeLocal(dispatchVar, makeNumber(String(initialState))),
    ];
    if (hoistedNames.length > 0) {
        resultBody.push(makeLocalMulti(hoistedNames));
    }
    resultBody.push(makeWhile(makeBool(true), makeBlock(dispatchCases)));
    return makeBlock(resultBody);
}
/**
 * Collect all local variable names from a statement (recursing into
 * nested blocks for if/while/for/function bodies). Skips __d prefix
 * (dead code) and __b prefix (flatten dispatch vars) since those are
 * self-contained / scoped to their own flatten pass.
 */
function collectLocalNames(stmt, names, seen) {
    if (stmt.t === "Local") {
        for (const nm of stmt.names) {
            if (!nm.startsWith("__d") &&
                !nm.startsWith(DISPATCH_PREFIX) &&
                !seen.has(nm)) {
                seen.add(nm);
                names.push(nm);
            }
        }
    }
    // Recurse into nested control-flow bodies to find inner locals
    switch (stmt.t) {
        case "If":
            for (const b of stmt.branches)
                collectBlockNames(b.block, names, seen);
            if (stmt.else)
                collectBlockNames(stmt.else, names, seen);
            break;
        case "While":
        case "Repeat":
            collectBlockNames(stmt.block, names, seen);
            if (stmt.t === "Repeat")
                collectLocalNames(stmt.cond, names, seen);
            break;
        case "For":
            if (!stmt.varName.startsWith("__d") &&
                !stmt.varName.startsWith(DISPATCH_PREFIX) &&
                !seen.has(stmt.varName)) {
                seen.add(stmt.varName);
                names.push(stmt.varName);
            }
            collectBlockNames(stmt.block, names, seen);
            break;
        case "ForIn":
            for (const nm of stmt.names) {
                if (!nm.startsWith("__d") &&
                    !nm.startsWith(DISPATCH_PREFIX) &&
                    !seen.has(nm)) {
                    seen.add(nm);
                    names.push(nm);
                }
            }
            collectBlockNames(stmt.block, names, seen);
            break;
        case "Function":
            collectBlockNames(stmt.body, names, seen);
            break;
        case "Do":
            collectBlockNames(stmt.block, names, seen);
            break;
    }
}
/** Collect local names from all statements in a Block. */
function collectBlockNames(block, names, seen) {
    if (block.t === "Block") {
        for (const s of block.body)
            collectLocalNames(s, names, seen);
    }
}
/**
 * Transform `local x = expr` → `x = expr` at the top level of a statement.
 * Recurses into nested block structures (if/while/for/function bodies)
 * to transform inner locals too — but inner locals that are scoped
 * entirely within one dispatch case can stay as `local` (they don't
 * need hoisting). We only transform the OUTERMOST local in each stmt.
 *
 * For function declarations `function name(...) ... end`, we leave them
 * as-is since they declare a global/function, not a local.
 */
function localToAssign(stmt) {
    // Skip dead-code locals (__d prefix) and dispatch vars (__b prefix) — keep
    // their `local` declaration inside the dispatch case so they remain properly
    // scoped (dispatch vars are declared above the while loop, not here, so we
    // just need to avoid accidentally stripping predeclarations of dead ones).
    if (stmt.t === "Local") {
        const skip = stmt.names.some((nm) => nm.startsWith("__d") || nm.startsWith(DISPATCH_PREFIX));
        if (skip)
            return stmt;
    }
    if (stmt.t === "Local" && stmt.values && stmt.values.length > 0) {
        // local x = expr  →  x = expr
        return {
            t: "Assign",
            targets: stmt.names.map((nm) => makeIdent(nm)),
            values: stmt.values,
            line: stmt.line,
        };
    }
    if (stmt.t === "Local" && (!stmt.values || stmt.values.length === 0)) {
        // `local x` with no value — drop it (already pre-declared)
        return { t: "Empty", line: stmt.line };
    }
    return stmt;
}
/** Create a `local a, b, c` declaration with no initial values. */
function makeLocalMulti(names) {
    return {
        t: "Local",
        names: [...names],
        types: names.map(() => null),
        values: null,
        line: 0,
    };
}
/**
 * Build the body (Block) for one dispatch case: `if __b == S then <body> end`.
 * The body contains the block's statements followed by the state transition.
 *
 * v0.11: 状态转移以 OPAQUE_TRANSITION_PROB 概率升级为不透明谓词形式
 * `__b = (OPAQUE_TRUE and T) or EXIT_STATE`。OPAQUE_TRUE 用 dispatchVar 自身
 * 构造恒等式（5 种形式随机），不引入新变量。攻击者必须化简谓词才能确定转移目标。
 */
function buildIfBody(block, stateIdMap, dispatchVar, rng) {
    const stmts = [...block.stmts];
    switch (block.terminator.type) {
        case "jump": {
            const targetState = stateIdMap.get(block.terminator.target) ?? EXIT_STATE;
            stmts.push(makeStateAssign(dispatchVar, targetState, rng));
            break;
        }
        case "branch": {
            const trueState = stateIdMap.get(block.terminator.trueTarget) ?? EXIT_STATE;
            const falseState = stateIdMap.get(block.terminator.falseTarget) ?? EXIT_STATE;
            const trueAssign = makeStateAssign(dispatchVar, trueState, rng);
            const falseAssign = makeStateAssign(dispatchVar, falseState, rng);
            stmts.push(makeIf(block.terminator.cond, makeBlock([trueAssign]), makeBlock([falseAssign])));
            break;
        }
        case "loop": {
            const exitState = stateIdMap.get(block.terminator.exitTarget) ?? EXIT_STATE;
            stmts.push(makeStateAssign(dispatchVar, exitState, rng));
            break;
        }
        case "return": {
            stmts.push(makeReturn(block.terminator.values));
            break;
        }
        case "exit": {
            stmts.push(makeStateAssign(dispatchVar, EXIT_STATE, rng));
            break;
        }
    }
    return makeBlock(stmts);
}
/**
 * 生成状态转移赋值 `__b = <expr>`。
 * 以 OPAQUE_TRANSITION_PROB 概率升级为 `__b = (OPAQUE_TRUE and T) or EXIT_STATE`。
 * OPAQUE_TRUE 恒为真 → 表达式结果恒为 T。EXIT_STATE 作为 fallback 保证万一
 * 谓词误判也安全退出（不会无限循环）。
 */
function makeStateAssign(dispatchVar, targetState, rng) {
    if (rng() >= OPAQUE_TRANSITION_PROB) {
        return makeAssign(dispatchVar, makeNumber(String(targetState)));
    }
    const opaqueTrue = makeOpaqueTrue(makeIdent(dispatchVar), rng);
    return makeAssign(dispatchVar, makeBinop("or", makeBinop("and", opaqueTrue, makeNumber(String(targetState))), makeNumber(String(EXIT_STATE))));
}
/**
 * 5 种 OPAQUE_TRUE 形式，全用 dispatchVar 自身构造恒等式，不引入新变量。
 * 形式多样化迫使攻击者不能单一模式匹配，必须逐 case 化简。
 *   0: v == v                  恒真
 *   1: (v - v) == 0            恒真
 *   2: (v * 0) == 0            恒真
 *   3: (v - v) < 1             恒真
 *   4: v ~= (v + 1)            恒真（v 不等于 v+1）
 */
function makeOpaqueTrue(v, rng) {
    const form = Math.floor(rng() * 5);
    switch (form) {
        case 0:
            return makeBinop("==", v, v);
        case 1:
            return makeBinop("==", makeBinop("-", v, v), makeNumber("0"));
        case 2:
            return makeBinop("==", makeBinop("*", v, makeNumber("0")), makeNumber("0"));
        case 3:
            return makeBinop("<", makeBinop("-", v, v), makeNumber("1"));
        case 4:
            return makeBinop("~=", v, makeBinop("+", v, makeNumber("1")));
        default:
            return makeBinop("==", v, v);
    }
}
/**
 * 生成假路径 case body：1-2 个垃圾 local + __b = -1（安全退出）。
 * 垃圾 local 用 __d 前缀（D1/D5 跳过），值是随机数。结构与真实 case 相似，
 * 攻击者需逆向 dispatch 才能识别。
 */
function makeFakeCaseBody(rng, dispatchVar) {
    const stmtCount = 1 + Math.floor(rng() * 2); // 1-2 个垃圾 local
    const stmts = [];
    for (let i = 0; i < stmtCount; i++) {
        const idx = Math.floor(rng() * 100000);
        const val = Math.floor(rng() * 1000000);
        stmts.push({
            t: "Local",
            names: [`__d${idx}`],
            types: [null],
            values: [makeNumber(String(val))],
            line: 0,
        });
    }
    stmts.push(makeAssign(dispatchVar, makeNumber(String(EXIT_STATE))));
    return makeBlock(stmts);
}
// ---- AST node constructors ----
function makeBlock(body) {
    return { t: "Block", body, line: 0 };
}
function makeLocal(name, value) {
    return { t: "Local", names: [name], types: [null], values: [value], line: 0 };
}
function makeAssign(target, value) {
    return {
        t: "Assign",
        targets: [makeIdent(target)],
        values: [value],
        line: 0,
    };
}
function makeIf(cond, thenBlock, elseBlock) {
    const branches = [{ cond, block: thenBlock }];
    const node = {
        t: "If",
        branches,
        else: elseBlock,
        line: 0,
    };
    return node;
}
function makeWhile(cond, block) {
    return { t: "While", cond, block, line: 0 };
}
function makeBinop(op, lhs, rhs) {
    return { t: "Binop", op, lhs, rhs, line: 0 };
}
function makeIdent(name) {
    return { t: "Ident", name, line: 0 };
}
function makeNumber(value) {
    return { t: "Number", value, line: 0 };
}
function makeBool(value) {
    return { t: "Bool", value, line: 0 };
}
function makeBreak() {
    return { t: "Break", line: 0 };
}
function makeReturn(values) {
    return { t: "Return", values, line: 0 };
}
// ---------- AST child walker (post-order, in-place) ----------
/**
 * Walk all AST children of `n` using `fn` (which may return new nodes).
 * Mutates in place. Covers all statement/expression node types that can
 * contain nested Blocks / Functions (mirrors the walker in pipeline/obfuscate.ts).
 */
function walkChildrenInPlace(n, fn) {
    switch (n.t) {
        case "Block":
            n.body = n.body.map(fn);
            break;
        case "Local":
            if (n.values)
                n.values = n.values.map(fn);
            break;
        case "Assign":
            n.targets = n.targets.map(fn);
            n.values = n.values.map(fn);
            break;
        case "If":
            n.branches = n.branches.map((b) => ({
                cond: fn(b.cond),
                block: fn(b.block),
            }));
            if (n.else)
                n.else = fn(n.else);
            break;
        case "While":
            n.cond = fn(n.cond);
            n.block = fn(n.block);
            break;
        case "Repeat":
            n.block = fn(n.block);
            n.cond = fn(n.cond);
            break;
        case "For":
            n.start = fn(n.start);
            n.stop = fn(n.stop);
            if (n.step)
                n.step = fn(n.step);
            n.block = fn(n.block);
            break;
        case "ForIn":
            n.iter = n.iter.map(fn);
            n.block = fn(n.block);
            break;
        case "Function":
            // Walk the function body first so nested inner Functions get processed
            // bottom-up. The caller visit(n) will then flatten THIS function's body.
            n.body = fn(n.body);
            break;
        case "Return":
            if (n.values)
                n.values = n.values.map(fn);
            break;
        case "Call":
            n.callee = fn(n.callee);
            n.args = n.args.map(fn);
            break;
        case "Method":
            n.callee = fn(n.callee);
            n.args = n.args.map(fn);
            break;
        case "Do":
            n.block = fn(n.block);
            break;
        case "Index":
            n.obj = fn(n.obj);
            n.index = fn(n.index);
            break;
        case "Unop":
            n.arg = fn(n.arg);
            break;
        case "Binop":
            n.lhs = fn(n.lhs);
            n.rhs = fn(n.rhs);
            break;
        case "Concat":
            n.parts = n.parts.map(fn);
            break;
        case "Table":
            n.fields = n.fields.map((f) => ({
                key: f.key ? fn(f.key) : null,
                value: fn(f.value),
            }));
            break;
        case "IfExpr":
            n.cond = fn(n.cond);
            n.then = fn(n.then);
            n.else = fn(n.else);
            break;
        case "Interp":
            n.parts = n.parts.map(fn);
            break;
        // Goto, Label, TypeDecl, Empty, Break, Continue, Ident, Number, Bool, String
        // — no child nodes that are Blocks/Functions.
    }
}
//# sourceMappingURL=flatten.js.map