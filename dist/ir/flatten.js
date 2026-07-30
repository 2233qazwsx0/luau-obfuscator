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
import { buildIR, shuffleArray } from "./ir.js";
import { mulberry32 } from "../util/prng.js";
// Exit state is always -1 (matches TODO.md convention).
const EXIT_STATE = -1;
// Dispatch variable name. Identifiers starting with __ are skipped by D1.
const DISPATCH_VAR = "__b";
/**
 * Main entry: flatten the top-level Block of `ast` into a dispatch state machine.
 * If the block has <= 1 basic block, returns the original AST unchanged.
 */
export function flattenAST(ast, seed) {
    if (ast.t !== "Block") {
        return ast;
    }
    const blocks = buildIR(ast);
    // Don't flatten unless there are at least 2 non-exit blocks (i.e., at least
    // 2 statements or control-flow nodes to dispatch between). A single statement
    // produces 1 stmt block + 1 exit block = 2 blocks, but only 1 non-exit block,
    // so we check the non-exit count.
    const nonExitCount = blocks.filter((b) => b.terminator.type !== "exit").length;
    if (nonExitCount <= 1) {
        return ast;
    }
    const rng = mulberry32(seed ^ 0xDEADBEEF);
    // Assign shuffled state IDs to blocks.
    // blocks[i].id is the original order (0, 1, 2, ...).
    // stateIdMap[originalId] = shuffledUniqueID.
    // The exit block (last block with terminator type "exit") gets EXIT_STATE (-1).
    const exitBlock = blocks.find((b) => b.terminator.type === "exit");
    const nonExitBlocks = blocks.filter((b) => b.terminator.type !== "exit");
    const shuffledIds = shuffleArray(nonExitBlocks.map((_, i) => i * 7 + 100), rng);
    // Build the mapping: original block id -> state ID
    const stateIdMap = new Map();
    let shuffleIdx = 0;
    for (const b of nonExitBlocks) {
        stateIdMap.set(b.id, shuffledIds[shuffleIdx]);
        shuffleIdx++;
    }
    if (exitBlock) {
        stateIdMap.set(exitBlock.id, EXIT_STATE);
    }
    // The initial state is the state ID of block 0 (the first block in original order).
    const initialState = stateIdMap.get(0) ?? 0;
    // Collect all local variable names declared in non-exit blocks.
    // These need to be pre-declared before the while loop so they're
    // visible across all dispatch cases (each `if ... then ... end` is
    // a separate scope).
    const hoistedNames = [];
    const hoistedNameSet = new Set();
    for (const block of blocks) {
        if (block.terminator.type === "exit")
            continue;
        for (const stmt of block.stmts) {
            collectLocalNames(stmt, hoistedNames, hoistedNameSet);
        }
    }
    // Build dispatch body: one If node per block (non-exit blocks only).
    const dispatchCases = [];
    for (const block of blocks) {
        if (block.terminator.type === "exit") {
            // Exit blocks are handled by the final `if __b == -1 then break end`.
            continue;
        }
        const stateId = stateIdMap.get(block.id) ?? 0;
        // Transform `local x = expr` → `x = expr` (since x is pre-declared).
        const transformedStmts = block.stmts.map((s) => localToAssign(s));
        const ifBody = buildIfBody({ ...block, stmts: transformedStmts }, stateIdMap);
        dispatchCases.push(makeIf(makeBinop("==", makeIdent(DISPATCH_VAR), makeNumber(String(stateId))), ifBody));
    }
    // Final exit check
    dispatchCases.push(makeIf(makeBinop("==", makeIdent(DISPATCH_VAR), makeNumber(String(EXIT_STATE))), makeBlock([makeBreak()])));
    // Assemble:
    //   local __b = <initial>
    //   local <hoisted vars>     -- pre-declare so cross-case scope works
    //   while true do <dispatch cases> end
    const resultBody = [
        makeLocal(DISPATCH_VAR, makeNumber(String(initialState))),
    ];
    if (hoistedNames.length > 0) {
        resultBody.push(makeLocalMulti(hoistedNames));
    }
    resultBody.push(makeWhile(makeBool(true), makeBlock(dispatchCases)));
    const result = makeBlock(resultBody);
    return result;
}
/**
 * Collect all local variable names from a statement (recursing into
 * nested blocks for if/while/for/function bodies). Skips __d prefix
 * (dead code) variables since those are self-contained.
 */
function collectLocalNames(stmt, names, seen) {
    if (stmt.t === "Local") {
        for (const nm of stmt.names) {
            if (!nm.startsWith("__d") && !seen.has(nm)) {
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
            if (!stmt.varName.startsWith("__d") && !seen.has(stmt.varName)) {
                seen.add(stmt.varName);
                names.push(stmt.varName);
            }
            collectBlockNames(stmt.block, names, seen);
            break;
        case "ForIn":
            for (const nm of stmt.names) {
                if (!nm.startsWith("__d") && !seen.has(nm)) {
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
    // Skip dead-code locals (__d prefix) — keep their `local` declaration
    // inside the dispatch case so they remain properly scoped.
    if (stmt.t === "Local") {
        const isDeadCode = stmt.names.some((nm) => nm.startsWith("__d"));
        if (isDeadCode)
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
 */
function buildIfBody(block, stateIdMap) {
    const stmts = [...block.stmts];
    switch (block.terminator.type) {
        case "jump": {
            const targetState = stateIdMap.get(block.terminator.target) ?? EXIT_STATE;
            stmts.push(makeAssign(DISPATCH_VAR, makeNumber(String(targetState))));
            break;
        }
        case "branch": {
            // Not used in v0.2 (If nodes are kept as regular stmts, terminator is jump).
            // But handle it for completeness.
            const trueState = stateIdMap.get(block.terminator.trueTarget) ?? EXIT_STATE;
            const falseState = stateIdMap.get(block.terminator.falseTarget) ?? EXIT_STATE;
            stmts.push(makeIf(block.terminator.cond, makeBlock([makeAssign(DISPATCH_VAR, makeNumber(String(trueState)))]), makeBlock([makeAssign(DISPATCH_VAR, makeNumber(String(falseState)))])));
            break;
        }
        case "loop": {
            // Not used in v0.2 (While/For nodes are kept as regular stmts, terminator is jump).
            const exitState = stateIdMap.get(block.terminator.exitTarget) ?? EXIT_STATE;
            stmts.push(makeAssign(DISPATCH_VAR, makeNumber(String(exitState))));
            break;
        }
        case "return": {
            // Emit `return values` — this exits the function/program directly.
            stmts.push(makeReturn(block.terminator.values));
            break;
        }
        case "exit": {
            stmts.push(makeAssign(DISPATCH_VAR, makeNumber(String(EXIT_STATE))));
            break;
        }
    }
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
//# sourceMappingURL=flatten.js.map