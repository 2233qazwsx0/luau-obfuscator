// src/transforms/deadcode.ts — D5: dead code injection (AST-level).
//
// Inserts inert code blocks into the top-level Block body before D4 flattening.
// Two forms are injected:
//   1. Unreachable branches: `if false then <inert stmts> end`
//   2. Dead variables: `local __dX = <number> + <number>`
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

/**
 * Main entry: inject dead code into the top-level Block of `ast`.
 * Returns the original AST unchanged if it's not a Block or has too few statements.
 */
export function injectDeadcode(ast: Node, seed: number): Node {
  if (ast.t !== "Block") {
    return ast;
  }

  const body = ast.body;
  if (body.length === 0) {
    return ast;
  }

  const rng = mulberry32((seed ^ SEED_OFFSET) >>> 0);
  const maxInject = Math.floor(body.length * MAX_RATIO);
  let injected = 0;

  // Determine the actual injection probability for this run (30%-50%).
  const injectProb = INJECT_PROB_MIN + rng() * (INJECT_PROB_MAX - INJECT_PROB_MIN);

  // Build a variable name counter to ensure uniqueness.
  let varCounter = 0;

  const newBody: Node[] = [];
  for (let i = 0; i < body.length; i++) {
    // Before each real statement, decide whether to inject dead code.
    if (injected < maxInject && i > 0 && rng() < injectProb) {
      const deadBlock = generateDeadBlock(rng, varCounter);
      varCounter += deadBlock.varCount;
      newBody.push(deadBlock.node);
      injected++;
    }
    newBody.push(body[i]!);
  }

  // After the last statement, optionally inject one more.
  if (injected < maxInject && body.length > 0 && rng() < injectProb) {
    const deadBlock = generateDeadBlock(rng, varCounter);
    varCounter += deadBlock.varCount;
    newBody.push(deadBlock.node);
    injected++;
  }

  return { t: "Block", body: newBody, line: ast.line } as Node;
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
