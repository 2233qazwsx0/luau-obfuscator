import type { Node } from "../parser/parser.js";
import type { StringCipher } from "../transforms/strings.js";
export interface EmitContext {
    indent: number;
    out: string[];
    cipher: StringCipher;
}
export declare function emit(program: Node, cipher: StringCipher): string;
