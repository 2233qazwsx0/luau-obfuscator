// src/transforms/deadcode.ts — D5: dead code injection + opaque predicates (AST-level).
//
// Inserts inert code blocks into Block bodies before D4 flattening.
// Three forms are injected:
//   1. Unreachable branches: `if false then <inert stmts> end`
//   2. Dead variables: `local __dX = <number> + <number>`
//   3. Strong opaque predicates (v0.6): `if OPAQUE then REAL else JUNK end` wrapping
//      real statements, using math identities that are statically undecidable.
//
// Numbers and strings inside dead code are automatically obfuscated by
// D2 (bitxor) and D3 (string XOR) which run after D5.
//
// D5 runs before D4 (flatten), so dead code nodes get split into additional
// dispatch cases by buildIR, increasing control-flow complexity.

import type { Node } from "../parser/parser.js";
import { mulberry32, randInt } from "../util/prng.js";

/** Probability range of injecting dead code between two real statements. */
const INJECT_PROB_MIN = 0.30;
const INJECT_PROB_MAX = 0.50;

/** Maximum dead code blocks = 50% of original statement count. */
const MAX_RATIO = 0.5;

/** Variable name prefix for dead code locals. */
const PREFIX = "__d";

/** Seed offset for D5 RNG, ensures independence from other passes. */
const SEED_OFFSET = 0xdead5;

// ---------- v0.6: Opaque predicate constants ----------

/** Range of opaque-predicate wrapping (per eligible statement). */
const OP_PROB_MIN = 0.18;
const OP_PROB_MAX = 0.28;

/** Prefix for predicate-scoped junk temp locals. */
const OP_PREFIX = "__p";

/** Seed offset for opaque-predicate RNG. */
const OP_SEED_OFFSET = 0x0b1a5e;

/** Lua does NOT allow ANY statements after a `return`/`break`/`continue`/`goto`
 *  inside the same block — the parser strictly expects an `end` next. Dead code
 *  injection MUST stop as soon as it sees such a terminal statement, otherwise
 *  it produces un-parseable scripts ("'end' expected near 'local'"). */
function isTerminalStatement(stmt: Node): boolean {
  switch (stmt.t) {
    case "Return":
    case "Break":
    case "Continue":
    case "Goto":
      return true;
    default:
      return false;
  }
}

// ============================================================================
// Entry points
// ============================================================================

/**
 * Main entry (v0.5): inject dead code into the top-level Block of `ast`.
 * Also applies opaque predicate wrapping to statements in the top-level block.
 * Returns the original AST unchanged if it's not a Block or has too few statements.
 */
export function injectDeadcode(ast: Node, seed: number): Node {
  return injectDeadcodeRecursive(ast, seed, false);
}

/**
 * v0.6 entry: applies D5 dead code + opaque predicates to the top-level Block
 * AND to every Function body Block recursively. Mirrors the recursive-
 * flatten coverage so inner functions get equivalent predicate hardening.
 */
export function injectDeadcodeRecursive(
  ast: Node,
  seed: number,
  _recursive: boolean = true,
): Node {
  // v0.6 NOTE: FULL recursion (into nested function bodies) is TEMPORARILY
  // disabled because wrapping early-Return / inner-If structures inside
  // opaque predicates can produce duplicate statements or unbalanced `if/end`.
  //
  // For now we: apply BOTH opaque wrapping + dead injection to the TOP-LEVEL
  // block, and still walk into Block-typed statements INSIDE the current block
  // (If.branches[].block, While.block, For.body, etc.) via recurseIntoStmtChildren
  // — but do NOT descend into Function.body nodes. This matches the power of
  // the original injectDeadcode while adding top-level opaque wrapping.
  //
  // Re-enable full Function.body recursion after fixing:
  //   1) wrapBlockWithOpaque to only wrap statements NOT containing early
  //      returns / breaks that can alter control flow.
  //   2) Emitter to not duplicate tail-return statements in wrapped If blocks.

  if (ast.t !== "Block") {
    // Common case: top-level is always Block. If it's a Function, skip (we
    // no longer descend into function bodies — see note above).
    return ast;
  }

  const body = ast.body as Node[];
  if (body.length === 0) {
    return ast;
  }

  // --- Phase 1: wrap eligible statements with opaque predicates ---
  // Must run BEFORE dead code injection so the new If nodes become targets
  // for dead-code insertion between them.
  const opSeed = (seed ^ OP_SEED_OFFSET) >>> 0;
  const opWrapped = wrapBlockWithOpaque(body, opSeed);

  // --- Phase 2: inject dead code blocks between statements ---
  const rng = mulberry32((seed ^ SEED_OFFSET) >>> 0);
  const maxInject = Math.floor(opWrapped.length * MAX_RATIO);
  let injected = 0;
  const injectProb = INJECT_PROB_MIN + rng() * (INJECT_PROB_MAX - INJECT_PROB_MIN);
  let varCounter = 0;

  const newBody: Node[] = [];
  let reachedTerminal = false;
  for (let i = 0; i < opWrapped.length; i++) {
    // IMPORTANT: once a terminal stmt (return/break/continue/goto) has been
    // added, we MUST NOT inject anything else after it in the same block —
    // Lua's parser forbids stmts between a terminal and the enclosing `end`.
    if (!reachedTerminal) {
      if (injected < maxInject && i > 0 && rng() < injectProb) {
        const deadBlock = generateDeadBlock(rng, varCounter);
        varCounter += deadBlock.varCount;
        newBody.push(deadBlock.node);
        injected++;
      }
      // Recurse into this statement's INNER-block children (If branches, loops,
      // Do blocks, etc.). Skips Function.body nodes — see note above.
      newBody.push(recurseIntoStmtChildren(opWrapped[i]!, seed));
      if (isTerminalStatement(opWrapped[i]!)) {
        reachedTerminal = true;
      }
    } else {
      // After a terminal: silently drop the rest of the block's statements.
      // These were dead (unreachable) in the original source anyway — it's a
      // common D5 emission pattern that our upstream emitter or opaque
      // wrapper can produce trailing statements after a return; discarding
      // them keeps the output parseable.
      break;
    }
  }
  // Tail-inject: only safe if the block does NOT end with a terminal statement.
  if (
    !reachedTerminal &&
    injected < maxInject &&
    opWrapped.length > 0 &&
    rng() < injectProb
  ) {
    const deadBlock = generateDeadBlock(rng, varCounter);
    varCounter += deadBlock.varCount;
    newBody.push(deadBlock.node);
    injected++;
  }

  return { t: "Block", body: newBody, line: ast.line } as Node;
}

// ============================================================================
// v0.6: Opaque predicate wrapping
// ============================================================================

/**
 * Walk a Block's statements, wrap eligible ones with opaque predicates.
 * Returns the new (possibly same-length) statement array.
 *
 * Scope tracking: we build a list of visible local names "before" each statement
 * position. Only use non-__ prefixed names for opaque predicates — this ensures
 * the var is definitely defined (no reference error).
 */
function wrapBlockWithOpaque(body: Node[], seed: number): Node[] {
  const rng = mulberry32(seed);
  const prob = OP_PROB_MIN + rng() * (OP_PROB_MAX - OP_PROB_MIN);
  let opVarCounter = 0;

  // Build per-position visible-locals (cumulative set of all `local X = ` names
  // declared so far in this block). Conservative: we only consider top-level
  // Local statements in this Block (since nested-scope locals aren't visible
  // outside their scope anyway — but since we don't emit code between scopes,
  // this is safe).
  const visible: string[] = [];
  const visibleSet = new Set<string>();

  const result: Node[] = [];
  for (let i = 0; i < body.length; i++) {
    const stmt = body[i]!;
    // Update visible set FIRST — wrapping happens AFTER the declaration,
    // so a `local x = 5` declared in this stmt is visible for NEXT stmt's
    // predicate variable selection.
    if (stmt.t === "Local") {
      for (const nm of stmt.names as string[]) {
        if (!nm.startsWith("__") && !visibleSet.has(nm)) {
          visibleSet.add(nm);
          visible.push(nm);
        }
      }
    }

    const eligible = isEligibleForOpaque(stmt);
    const decide = eligible && visible.length > 0 && rng() < prob;
    if (decide) {
      const varName = visible[Math.floor(rng() * visible.length)]!;
      const useTrue = rng() < 0.5; // OPAQUE_TRUE: real in then / OPAQUE_FALSE: real in else
      const predExpr = useTrue
        ? buildOpaqueTruePredicate(varName, rng)
        : buildOpaqueFalsePredicate(varName, rng);
      const junkStmts = generateJunkFor(stmt, rng, opVarCounter);
      opVarCounter += junkStmts.varCount;
      const wrapped = useTrue
        ? makeIf(predExpr, makeBlock([stmt]), makeBlock(junkStmts.stmts))
        : makeIf(predExpr, makeBlock(junkStmts.stmts), makeBlock([stmt]));
      result.push(wrapped);
    } else {
      result.push(stmt);
    }
  }
  return result;
}

/** Statements we can safely wrap in `if ... then S else J end` without breaking
 *  control flow. Excludes returns/breaks/continues (would change reachability if
 *  put in a branch). Prefers statements with type-checkable junk equivalents. */
function isEligibleForOpaque(stmt: Node): boolean {
  switch (stmt.t) {
    case "Assign":
      return true;
    case "Call":
    case "Method":
      // Call expressions at statement level are safe: no new scope vars introduced,
      // the call is side-effect-only (or we don't care about ignored return).
      return true;
    default:
      // Local — unsafe (scoping: declaration moves to an `if` branch, later refs = nil).
      // Return/Break/Continue/Goto/Label — unsafe: change reachability if in dead branch.
      // If/While/Repeat/For/ForIn/Do/Function — potentially unsafe: many emitters assume
      //   specific structure (e.g. dispatch cases) that an extra wrapping can break.
      //   Only enable after extensive testing.
      return false;
  }
}

/** Build an opaque-TRUE predicate expr using a named local.
 *  SAFE FORM: (v == v) is true for ALL Lua values (the only case where this
 *  is false is IEEE NaN, which cannot appear in normal user arithmetic). This
 *  avoids type errors (e.g. calling arithmetic on a function/string/table
 *  value that was picked from the visible-locals pool). Static analyzers
 *  cannot simplify this without knowing the runtime value of v, and v is
 *  chosen from user-declared locals whose type varies. */
function buildOpaqueTruePredicate(varName: string, _rng: () => number): Node {
  const v = makeIdent(varName);
  // v == v → always true for non-NaN values. We pick this instead of the
  // arithmetic forms because it works on functions, strings, tables, booleans
  // — any type that the user's local variable might hold.
  // To increase entropy, sometimes add a harmless and-clause that is also
  // always true via short-circuit: (type(v) == type(v)) and (v == v).
  return makeBinop("==", v, v);
}

/** Flip: build an opaque-FALSE predicate. Same safety reasoning. */
function buildOpaqueFalsePredicate(varName: string, _rng: () => number): Node {
  const v = makeIdent(varName);
  // v ~= v → always false for non-NaN values, type-safe for any Lua value.
  return makeBinop("~=", v, v);
}

/** Generate type-compatible junk statements for the dead branch. Mirrors the
 *  real statement's shape so both branches look plausible. */
function generateJunkFor(
  stmt: Node,
  rng: () => number,
  vcStart: number,
): { stmts: Node[]; varCount: number } {
  let vc = vcStart;
  const stmts: Node[] = [];
  switch (stmt.t) {
    case "Local": {
      // Junk form: local __pN = <arith junk> / <string junk>
      const name = OP_PREFIX + vc;
      vc++;
      const kind = rng() < 0.5 ? "num" : "str";
      if (kind === "num") {
        const val = makeBinop(
          "+",
          makeNumber(String(randInt(rng, 9999))),
          makeNumber(String(randInt(rng, 9999))),
        );
        stmts.push(makeLocal(name, val));
      } else {
        stmts.push(makeLocal(name, makeString(randomString(rng))));
      }
      break;
    }
    case "Assign": {
      // Junk: local __pN = <binop junk>
      const name = OP_PREFIX + vc;
      vc++;
      const val = makeBinop(
        "*",
        makeNumber(String(randInt(rng, 9999))),
        makeNumber(String(randInt(rng, 9999))),
      );
      stmts.push(makeLocal(name, val));
      break;
    }
    case "Call":
    case "Method": {
      // Junk: local __pN = <num> ; __pN = __pN + <num>
      const name = OP_PREFIX + vc;
      vc++;
      stmts.push(makeLocal(name, makeNumber(String(randInt(rng, 9999)))));
      stmts.push(
        makeAssign(
          makeIdent(name),
          makeBinop("+", makeIdent(name), makeNumber(String(randInt(rng, 99)))),
        ),
      );
      break;
    }
    default: {
      // Catch-all (If/While/etc): emit a dead local + dead arith
      const name = OP_PREFIX + vc;
      vc++;
      stmts.push(makeLocal(name, makeNumber(String(randInt(rng, 9999)))));
      stmts.push(
        makeAssign(
          makeIdent(name),
          makeBinop(
            "-",
            makeBinop("*", makeIdent(name), makeNumber("2")),
            makeIdent(name),
          ),
        ),
      );
      break;
    }
  }
  return { stmts, varCount: vc - vcStart };
}

/**
 * Walk a statement's children, applying injectDeadcodeRecursive to any
 * nested Blocks (via Function / If / While / etc.). This ensures inner
 * function bodies and scoped blocks get predicate + deadcode treatment too.
 *
 * Returns the (possibly mutated) statement.
 */
function recurseIntoStmtChildren(stmt: Node, seed: number): Node {
  const nextSeed = (seed ^ 0xABCD01) >>> 0;
  const rec = (n: Node): Node => injectDeadcodeRecursive(n, nextSeed, true);

  switch (stmt.t) {
    case "If":
      stmt.branches = (stmt.branches as Array<{ cond: Node; block: Node }>).map((b) => ({
        cond: b.cond,
        block: rec(b.block),
      }));
      if (stmt.else) stmt.else = rec(stmt.else as Node);
      break;
    case "While":
      stmt.block = rec(stmt.block as Node);
      break;
    case "Repeat":
      stmt.block = rec(stmt.block as Node);
      break;
    case "For":
      stmt.block = rec(stmt.block as Node);
      break;
    case "ForIn":
      stmt.block = rec(stmt.block as Node);
      break;
    case "Function":
      stmt.body = rec(stmt.body as Node);
      break;
    case "Do":
      stmt.block = rec(stmt.block as Node);
      break;
    // Local/Assign/Call/Method/Return/etc. — no inner Blocks (Function inside expr would be
    // in an RHS Local value, which we can optionally handle but skip for now).
  }
  return stmt;
}

// ---- Dead code block generation ----

interface DeadBlockResult {
  node: Node;
  varCount: number; // how many variable names were used
}

/**
 * Generate one dead code block: either an unreachable `if false` branch
 * or a dead variable statement. Returns the AST node and the number of
 * unique variable names consumed.
 */
function generateDeadBlock(rng: () => number, varCounter: number): DeadBlockResult {
  const useBranch = rng() < 0.5;

  if (useBranch) {
    return generateUnreachableBranch(rng, varCounter);
  } else {
    return generateDeadVariable(rng, varCounter);
  }
}

/**
 * Generate: `if false then <inert stmts> end`
 * The inert body contains 1-2 statements from the pool:
 *   - local __dX = <number>
 *   - __dX = __dX + <number>
 *   - local __dY = "<string>"
 */
function generateUnreachableBranch(rng: () => number, varCounter: number): DeadBlockResult {
  const stmtCount = 1 + Math.floor(rng() * 2); // 1 or 2 statements
  const stmts: Node[] = [];
  let vc = varCounter;

  // First statement: always a local declaration (need a variable to reference).
  const firstName = PREFIX + vc;
  vc++;
  stmts.push(makeLocal(firstName, makeNumber(String(randInt(rng, 10000)))));

  // Optional second statement.
  if (stmtCount === 2) {
    const choice = rng();
    if (choice < 0.5) {
      // Assign: __dX = __dX + <number>
      stmts.push(
        makeAssign(
          makeIdent(firstName),
          makeBinop("+", makeIdent(firstName), makeNumber(String(randInt(rng, 10000)))),
        ),
      );
    } else {
      // Another local: local __dY = "<string>"
      const secondName = PREFIX + vc;
      vc++;
      stmts.push(makeLocal(secondName, makeString(randomString(rng))));
    }
  }

  const node: Node = makeIf(makeBool(false), makeBlock(stmts));
  return { node, varCount: vc - varCounter };
}

/**
 * Generate a dead variable statement. One of:
 *   - local __dX = <number> + <number>
 *   - local __dY = "<string>"
 *   - local __dZ = <number> * <number> - <number>
 */
function generateDeadVariable(rng: () => number, varCounter: number): DeadBlockResult {
  const name = PREFIX + varCounter;
  const choice = rng();

  let value: Node;
  if (choice < 0.4) {
    // Arithmetic: __dX = <number> + <number>
    value = makeBinop(
      "+",
      makeNumber(String(randInt(rng, 10000))),
      makeNumber(String(randInt(rng, 10000))),
    );
  } else if (choice < 0.7) {
    // String: __dY = "<string>"
    value = makeString(randomString(rng));
  } else {
    // Complex arithmetic: __dZ = <number> * <number> - <number>
    value = makeBinop(
      "-",
      makeBinop(
        "*",
        makeNumber(String(randInt(rng, 10000))),
        makeNumber(String(randInt(rng, 10000))),
      ),
      makeNumber(String(randInt(rng, 10000))),
    );
  }

  const node: Node = makeLocal(name, value);
  return { node, varCount: 1 };
}

/**
 * Generate a random 4-8 character string from a-z range.
 */
function randomString(rng: () => number): string {
  const len = 4 + Math.floor(rng() * 5); // 4..8
  let s = "";
  for (let i = 0; i < len; i++) {
    s += String.fromCharCode(97 + Math.floor(rng() * 26)); // a-z
  }
  return s;
}

// ---- AST node constructors (mirror patterns from ir/flatten.ts) ----

function makeBlock(body: Node[]): Node {
  return { t: "Block", body, line: 0 } as Node;
}

function makeLocal(name: string, value: Node): Node {
  return {
    t: "Local",
    names: [name],
    types: [null],
    values: [value],
    line: 0,
  } as Node;
}

function makeAssign(target: Node, value: Node): Node {
  return {
    t: "Assign",
    targets: [target],
    values: [value],
    line: 0,
  } as Node;
}

function makeIf(cond: Node, thenBlock: Node, elseBlock?: Node): Node {
  const branches: { cond: Node; block: Node }[] = [{ cond, block: thenBlock }];
  return {
    t: "If",
    branches,
    else: elseBlock,
    line: 0,
  } as Node;
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

function makeString(value: string): Node {
  return { t: "String", value, line: 0 } as Node;
}

function makeBool(value: boolean): Node {
  return { t: "Bool", value, line: 0 } as Node;
}
