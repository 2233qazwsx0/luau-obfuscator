import type { Node } from "../parser/parser.js";
export interface EmitContext {
    indent: number;
    out: string[];
}
export declare function emit(program: Node): string;
