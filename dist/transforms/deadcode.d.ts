import type { Node } from "../parser/parser.js";
/**
 * Main entry (v0.5): inject dead code into the top-level Block of `ast`.
 * Also applies opaque predicate wrapping to statements in the top-level block.
 * Returns the original AST unchanged if it's not a Block or has too few statements.
 */
export declare function injectDeadcode(ast: Node, seed: number): Node;
/**
 * v0.6 entry: applies D5 dead code + opaque predicates to the top-level Block
 * AND to every Function body Block recursively. Mirrors the recursive-
 * flatten coverage so inner functions get equivalent predicate hardening.
 */
export declare function injectDeadcodeRecursive(ast: Node, seed: number, _recursive?: boolean): Node;
