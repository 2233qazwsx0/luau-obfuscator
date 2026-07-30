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

import type { Node } from "../parser/parser.js";
import { buildIR, shuffleArray, type Block } from "./ir.js";
import { mulberry32 } from "../util/prng.js";

// Exit state is always -1 (matches TODO.md convention).
const EXIT_STATE = -1;

// Base dispatch variable prefix. Identifiers starting with __ are skipped by D1.
const DISPATCH_PREFIX = "__b";
// Legacy single name (top-level only flattening).
const DISPATCH_VAR = DISPATCH_PREFIX;
// Min non-exit blocks for top-level / non-function blocks.
const MIN_BLOCKS_TOPLEVEL = 2;
// (Nested-function flatten thresholds — reserved for future use when we
//  fix the splitIntoBlocks duplicate-return bug. See comment in flattenRecursive.)
void 3;   // MIN_BLOCKS_FUNC
void 0x9E3779B1; // SEED_STEP

/**
 * Main entry (v0.5 behavior): flatten only the top-level Block of `ast` into
 * a dispatch state machine. If the block has <= 1 basic block, returns the
 * original AST unchanged.
 */
export function flattenAST(ast: Node, seed: number): Node {
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
export function flattenRecursive(ast: Node, seed: number): Node {
  let scopeCounter = 0;

  // Walk AST bottom-up: transform children, then current node.
  const visit = (n: Node): Node => {
    // First recurse into children
    walkChildrenInPlace(n, visit);

    // v0.6 NOTE: nested-function flattening is TEMPORARILY DISABLED.
    // Flattening inner function bodies that contain early returns inside
    // nested If blocks can produce duplicate case statements (see bugs on
    // vm-runtime.template.lua line ~137). Flattening the TOP LEVEL only is
    // both safe and already provides strong D4 coverage.
    //
    // Re-enable after fixing splitIntoBlocks to not duplicate tail returns.
    //
    // if (n.t === "Function") {
    //   scopeCounter++;
    //   const dispatchVar = scopeCounter === 0 ? DISPATCH_PREFIX : `${DISPATCH_PREFIX}${scopeCounter}`;
    //   const funcSeed = (seed ^ (scopeCounter * SEED_STEP)) >>> 0;
    //   n.body = flattenBlock(n.body, funcSeed, dispatchVar, MIN_BLOCKS_FUNC);
    //   return n;
    // }

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
function flattenBlock(
  ast: Node,
  seed: number,
  dispatchVar: string,
  minNonExit: number,
): Node {
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
  const shuffledIds = shuffleArray(
    nonExitBlocks.map((_, i) => i * 7 + 100),
    rng,
  );

  const stateIdMap = new Map<number, number>();
  let shuffleIdx = 0;
  for (const b of nonExitBlocks) {
    stateIdMap.set(b.id, shuffledIds[shuffleIdx] as number);
    shuffleIdx++;
  }
  if (exitBlock) {
    stateIdMap.set(exitBlock.id, EXIT_STATE);
  }

  const initialState = stateIdMap.get(0) ?? 0;

  const hoistedNames: string[] = [];
  const hoistedNameSet = new Set<string>();
  for (const block of blocks) {
    if (block.terminator.type === "exit") continue;
    for (const stmt of block.stmts) {
      collectLocalNames(stmt, hoistedNames, hoistedNameSet);
    }
  }

  const dispatchCases: Node[] = [];
  for (const block of blocks) {
    if (block.terminator.type === "exit") {
      continue;
    }
    const stateId = stateIdMap.get(block.id) ?? 0;
    const transformedStmts = block.stmts.map((s) => localToAssign(s));
    const ifBody = buildIfBody(
      { ...block, stmts: transformedStmts },
      stateIdMap,
      dispatchVar,
    );

    dispatchCases.push(
      makeIf(
        makeBinop("==", makeIdent(dispatchVar), makeNumber(String(stateId))),
        ifBody,
      ),
    );
  }

  dispatchCases.push(
    makeIf(
      makeBinop("==", makeIdent(dispatchVar), makeNumber(String(EXIT_STATE))),
      makeBlock([makeBreak()]),
    ),
  );

  const resultBody: Node[] = [
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
function collectLocalNames(stmt: Node, names: string[], seen: Set<string>): void {
  if (stmt.t === "Local") {
    for (const nm of stmt.names) {
      if (
        !nm.startsWith("__d") &&
        !nm.startsWith(DISPATCH_PREFIX) &&
        !seen.has(nm)
      ) {
        seen.add(nm);
        names.push(nm);
      }
    }
  }
  // Recurse into nested control-flow bodies to find inner locals
  switch (stmt.t) {
    case "If":
      for (const b of stmt.branches) collectBlockNames(b.block, names, seen);
      if (stmt.else) collectBlockNames(stmt.else, names, seen);
      break;
    case "While":
    case "Repeat":
      collectBlockNames(stmt.block, names, seen);
      if (stmt.t === "Repeat") collectLocalNames(stmt.cond, names, seen);
      break;
    case "For":
      if (
        !stmt.varName.startsWith("__d") &&
        !stmt.varName.startsWith(DISPATCH_PREFIX) &&
        !seen.has(stmt.varName)
      ) {
        seen.add(stmt.varName);
        names.push(stmt.varName);
      }
      collectBlockNames(stmt.block, names, seen);
      break;
    case "ForIn":
      for (const nm of stmt.names) {
        if (
          !nm.startsWith("__d") &&
          !nm.startsWith(DISPATCH_PREFIX) &&
          !seen.has(nm)
        ) {
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
function collectBlockNames(block: Node, names: string[], seen: Set<string>): void {
  if (block.t === "Block") {
    for (const s of block.body) collectLocalNames(s, names, seen);
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
function localToAssign(stmt: Node): Node {
  // Skip dead-code locals (__d prefix) and dispatch vars (__b prefix) — keep
  // their `local` declaration inside the dispatch case so they remain properly
  // scoped (dispatch vars are declared above the while loop, not here, so we
  // just need to avoid accidentally stripping predeclarations of dead ones).
  if (stmt.t === "Local") {
    const skip = stmt.names.some(
      (nm) => nm.startsWith("__d") || nm.startsWith(DISPATCH_PREFIX),
    );
    if (skip) return stmt;
  }
  if (stmt.t === "Local" && stmt.values && stmt.values.length > 0) {
    // local x = expr  →  x = expr
    return {
      t: "Assign",
      targets: stmt.names.map((nm) => makeIdent(nm)),
      values: stmt.values,
      line: stmt.line,
    } as Node;
  }
  if (stmt.t === "Local" && (!stmt.values || stmt.values.length === 0)) {
    // `local x` with no value — drop it (already pre-declared)
    return { t: "Empty", line: stmt.line } as Node;
  }
  return stmt;
}

/** Create a `local a, b, c` declaration with no initial values. */
function makeLocalMulti(names: string[]): Node {
  return {
    t: "Local",
    names: [...names],
    types: names.map(() => null),
    values: null,
    line: 0,
  } as Node;
}

/**
 * Build the body (Block) for one dispatch case: `if __b == S then <body> end`.
 * The body contains the block's statements followed by the state transition.
 */
function buildIfBody(
  block: Block,
  stateIdMap: Map<number, number>,
  dispatchVar: string,
): Node {
  const stmts: Node[] = [...block.stmts];

  switch (block.terminator.type) {
    case "jump": {
      const targetState = stateIdMap.get(block.terminator.target) ?? EXIT_STATE;
      stmts.push(makeAssign(dispatchVar, makeNumber(String(targetState))));
      break;
    }
    case "branch": {
      const trueState = stateIdMap.get(block.terminator.trueTarget) ?? EXIT_STATE;
      const falseState = stateIdMap.get(block.terminator.falseTarget) ?? EXIT_STATE;
      stmts.push(
        makeIf(
          block.terminator.cond,
          makeBlock([makeAssign(dispatchVar, makeNumber(String(trueState)))]),
          makeBlock([makeAssign(dispatchVar, makeNumber(String(falseState)))]),
        ),
      );
      break;
    }
    case "loop": {
      const exitState = stateIdMap.get(block.terminator.exitTarget) ?? EXIT_STATE;
      stmts.push(makeAssign(dispatchVar, makeNumber(String(exitState))));
      break;
    }
    case "return": {
      stmts.push(makeReturn(block.terminator.values));
      break;
    }
    case "exit": {
      stmts.push(makeAssign(dispatchVar, makeNumber(String(EXIT_STATE))));
      break;
    }
  }

  return makeBlock(stmts);
}

// ---- AST node constructors ----

function makeBlock(body: Node[]): Node {
  return { t: "Block", body, line: 0 } as Node;
}

function makeLocal(name: string, value: Node): Node {
  return { t: "Local", names: [name], types: [null], values: [value], line: 0 } as Node;
}

function makeAssign(target: string, value: Node): Node {
  return {
    t: "Assign",
    targets: [makeIdent(target)],
    values: [value],
    line: 0,
  } as Node;
}

function makeIf(cond: Node, thenBlock: Node, elseBlock?: Node): Node {
  const branches: { cond: Node; block: Node }[] = [{ cond, block: thenBlock }];
  const node: Node = {
    t: "If",
    branches,
    else: elseBlock,
    line: 0,
  } as Node;
  return node;
}

function makeWhile(cond: Node, block: Node): Node {
  return { t: "While", cond, block, line: 0 } as Node;
}

function makeBinop(op: string, lhs: Node, rhs: Node): Node {
  return { t: "Binop", op, lhs, rhs, line: 0 } as Node;
}

function makeIdent(name: string): Node {
  return { t: "Ident", name, line: 0 } as Node;
}

function makeNumber(value: string): Node {
  return { t: "Number", value, line: 0 } as Node;
}

function makeBool(value: boolean): Node {
  return { t: "Bool", value, line: 0 } as Node;
}

function makeBreak(): Node {
  return { t: "Break", line: 0 } as Node;
}

function makeReturn(values: Node[]): Node {
  return { t: "Return", values, line: 0 } as Node;
}

// ---------- AST child walker (post-order, in-place) ----------

/**
 * Walk all AST children of `n` using `fn` (which may return new nodes).
 * Mutates in place. Covers all statement/expression node types that can
 * contain nested Blocks / Functions (mirrors the walker in pipeline/obfuscate.ts).
 */
function walkChildrenInPlace(n: Node, fn: (child: Node) => Node): void {
  switch (n.t) {
    case "Block":
      n.body = (n.body as Node[]).map(fn);
      break;
    case "Local":
      if (n.values) n.values = (n.values as Node[]).map(fn);
      break;
    case "Assign":
      n.targets = (n.targets as Node[]).map(fn);
      n.values = (n.values as Node[]).map(fn);
      break;
    case "If":
      n.branches = (n.branches as Array<{ cond: Node; block: Node }>).map((b) => ({
        cond: fn(b.cond),
        block: fn(b.block),
      }));
      if (n.else) n.else = fn(n.else as Node);
      break;
    case "While":
      n.cond = fn(n.cond as Node);
      n.block = fn(n.block as Node);
      break;
    case "Repeat":
      n.block = fn(n.block as Node);
      n.cond = fn(n.cond as Node);
      break;
    case "For":
      n.start = fn(n.start as Node);
      n.stop = fn(n.stop as Node);
      if (n.step) n.step = fn(n.step as Node);
      n.block = fn(n.block as Node);
      break;
    case "ForIn":
      n.iter = (n.iter as Node[]).map(fn);
      n.block = fn(n.block as Node);
      break;
    case "Function":
      // Walk the function body first so nested inner Functions get processed
      // bottom-up. The caller visit(n) will then flatten THIS function's body.
      n.body = fn(n.body as Node);
      break;
    case "Return":
      if (n.values) n.values = (n.values as Node[]).map(fn);
      break;
    case "Call":
      n.callee = fn(n.callee as Node);
      n.args = (n.args as Node[]).map(fn);
      break;
    case "Method":
      n.callee = fn(n.callee as Node);
      n.args = (n.args as Node[]).map(fn);
      break;
    case "Do":
      n.block = fn(n.block as Node);
      break;
    case "Index":
      n.obj = fn(n.obj as Node);
      n.index = fn(n.index as Node);
      break;
    case "Unop":
      n.arg = fn(n.arg as Node);
      break;
    case "Binop":
      n.lhs = fn(n.lhs as Node);
      n.rhs = fn(n.rhs as Node);
      break;
    case "Concat":
      n.parts = (n.parts as Node[]).map(fn);
      break;
    case "Table":
      n.fields = (n.fields as Array<{ key: Node | null; value: Node }>).map((f) => ({
        key: f.key ? fn(f.key) : null,
        value: fn(f.value),
      }));
      break;
    case "IfExpr":
      n.cond = fn(n.cond as Node);
      n.then = fn(n.then as Node);
      n.else = fn(n.else as Node);
      break;
    case "Interp":
      n.parts = (n.parts as Node[]).map(fn);
      break;
    // Goto, Label, TypeDecl, Empty, Break, Continue, Ident, Number, Bool, String
    // — no child nodes that are Blocks/Functions.
  }
}
