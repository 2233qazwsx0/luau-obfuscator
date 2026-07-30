import type { Node } from "../parser/parser.js";
/**
 * Main entry (v0.5 behavior): flatten only the top-level Block of `ast` into
 * a dispatch state machine. If the block has <= 1 basic block, returns the
 * original AST unchanged.
 */
export declare function flattenAST(ast: Node, seed: number): Node;
/**
 * v0.6 entry: recursively flatten every Function body Block in addition to the
 * top-level Block. Innermost functions are flattened first (post-order). Each
 * flattened scope gets a unique dispatch var name (__b, __b1, __b2, ...) to
 * avoid outer-scope collectLocalNames hoisting inner dispatch locals.
 *
 * Top-level threshold: >= 2 non-exit blocks. Function threshold: >= 3 non-exit
 * blocks (skips tiny helpers).
 */
export declare function flattenRecursive(ast: Node, seed: number): Node;
