import type { Node } from "../parser/parser.js";
/**
 * Main entry: flatten the top-level Block of `ast` into a dispatch state machine.
 * If the block has <= 1 basic block, returns the original AST unchanged.
 */
export declare function flattenAST(ast: Node, seed: number): Node;
