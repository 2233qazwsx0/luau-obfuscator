import type { Node } from "../parser/parser.js";
/**
 * Main entry: inject dead code into the top-level Block of `ast`.
 * Returns the original AST unchanged if it's not a Block or has too few statements.
 */
export declare function injectDeadcode(ast: Node, seed: number): Node;
