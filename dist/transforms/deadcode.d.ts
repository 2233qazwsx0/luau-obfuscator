import type { Node } from "../parser/parser.js";
/**
 * Main entry (v0.5): inject dead code into the top-level Block of `ast`.
 * Also applies opaque predicate wrapping to statements in the top-level block.
 * Returns the original AST unchanged if it's not a Block or has too few statements.
 *
 * v0.12 Feature #7：`ratio` 控制 D5 注入上限（占原始语句数的比例）。
 * 默认 0.2（轻量模式）。传 0.5 可恢复 v0.6 行为。
 */
export declare function injectDeadcode(ast: Node, seed: number, ratio?: number): Node;
/**
 * v0.6 entry: applies D5 dead code + opaque predicates to the top-level Block
 * AND to every Function body Block recursively. Mirrors the recursive-
 * flatten coverage so inner functions get equivalent predicate hardening.
 *
 * v0.12 Feature #7：新增 `ratio` 参数（默认 0.2），控制 D5 注入量上限。
 */
export declare function injectDeadcodeRecursive(ast: Node, seed: number, _recursive?: boolean, ratio?: number): Node;
