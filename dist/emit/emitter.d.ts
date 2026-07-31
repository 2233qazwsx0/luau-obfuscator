import type { Node } from "../parser/parser.js";
export interface EmitContext {
    indent: number;
    out: string[];
    /** v0.12 Feature #8: 是否需要在输出顶部插入共享字符串解密器 _S。 */
    needsStringHelper: boolean;
}
export declare function emit(program: Node): string;
