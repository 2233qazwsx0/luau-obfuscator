import type { Node } from "../parser/parser.js";
import { type FuncPrototype } from "./opcodes.js";
export declare function compileAST(ast: Node, seed: number): FuncPrototype;
