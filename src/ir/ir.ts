// src/ir/ir.ts - Basic-block IR for control-flow flattening (D4).
//
// This is a minimal IR: we split the top-level Block body into a linear chain
// of basic blocks, each terminated by a jump / branch / loop / return / exit.
// The flatten pass (src/ir/flatten.ts) converts these blocks into a dispatch
// state machine wrapped in while true do ... if __b == S then ... end end.
//
// Block splitting rules (v0.2 non-recursive, top-level only):
//
// - Plain statements (Local, Assign, Call, Method, Do, TypeDecl, Goto, Label,
//   Empty, Function, Break, Continue) accumulate into the current block.
//
// - If / While / Repeat / For / ForIn: break the current block (flush pending
//   stmts as jump(next)), then the control-flow node goes into its own block
//   with terminator jump(next). We do NOT split the If/While body into sub-
//   blocks. The node stays as-is in stmts; the dispatch just shuffles it.
//
// - Return: goes into the current block stmts, then flush as return terminator.
//
// - End of body: if there are pending stmts, flush as exit. If the last block
//   terminator is a jump pointing past the end, add an exit block as target.

import type { Node } from "../parser/parser.js";

// ---- IR types ----

export interface Block {
  id: number;
  stmts: Node[];
  terminator: Terminator;
}

export type Terminator =
  | { type: "jump"; target: number }
  | { type: "branch"; cond: Node; trueTarget: number; falseTarget: number }
  | { type: "loop"; cond: Node; body: Node; exitTarget: number }
  | { type: "return"; values: Node[] }
  | { type: "exit" };

// ---- Helpers ----

/** Deterministic Fisher-Yates shuffle. */
export function shuffleArray<T>(arr: T[], rng: () => number): T[] {
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = out[i] as T;
    out[i] = out[j] as T;
    out[j] = tmp;
  }
  return out;
}

// ---- buildIR: AST top-level Block -> Block[] ----

export function buildIR(ast: Node): Block[] {
  if (ast.t !== "Block") {
    throw new Error("buildIR expected Block, got " + ast.t);
  }

  const blocks: Block[] = [];
  let currentStmts: Node[] = [];
  let blockId = 0;

  function flush(terminator: Terminator): void {
    blocks.push({ id: blockId++, stmts: currentStmts, terminator });
    currentStmts = [];
  }

  const body = ast.body;
  for (let i = 0; i < body.length; i++) {
    const stmt = body[i] as Node;

    switch (stmt.t) {
      case "Return":
        // v0.11: Return 不进 currentStmts。buildIfBody 的 case "return" 会
        // push makeReturn(terminator.values)，如果 Return 也在 stmts 里就会
        // 产生 duplicate return（语义上不可达，但触发 nested-flatten 时的
        // dispatch 结构异常）。Return 只作 terminator。
        flush({ type: "return", values: stmt.values });
        break;

      case "If":
      case "While":
      case "Repeat":
      case "For":
      case "ForIn":
        // Break before control-flow to create more granular blocks
        if (currentStmts.length > 0) {
          flush({ type: "jump", target: blockId + 1 });
        }
        currentStmts.push(stmt);
        flush({ type: "jump", target: blockId + 1 });
        break;

      default:
        // Each plain statement gets its own block for maximum dispatch
        // granularity. This means every statement is a separate dispatch case
        // in the flattened output, making the control flow harder to follow.
        currentStmts.push(stmt);
        flush({ type: "jump", target: blockId + 1 });
        break;
    }
  }

  // Flush remaining plain statements as a jump to the exit block
  if (currentStmts.length > 0) {
    flush({ type: "jump", target: blockId + 1 });
  }

  // Always add a dedicated exit block at the end
  if (blocks.length === 0) {
    blocks.push({ id: 0, stmts: [], terminator: { type: "exit" } });
  } else {
    const last = blocks[blocks.length - 1] as Block;
    if (last.terminator.type === "jump" && last.terminator.target >= blocks.length) {
      last.terminator = { type: "jump", target: blockId };
      blocks.push({ id: blockId++, stmts: [], terminator: { type: "exit" } });
    } else if (last.terminator.type !== "exit" && last.terminator.type !== "return") {
      last.terminator = { type: "jump", target: blockId };
      blocks.push({ id: blockId++, stmts: [], terminator: { type: "exit" } });
    }
  }

  return blocks;
}
