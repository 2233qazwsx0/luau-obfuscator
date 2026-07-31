import type { Node } from "../parser/parser.js";
import { type FuncPrototype } from "./opcodes.js";
/** v0.11 F6 指令层加密模式选项（编译器入口）。 */
export type InsncryptMode = "f6" | "f4" | "off";
/** v0.11 F6: 编译器选项。pipeline.ts 透传。 */
export interface CompilerOptions {
    /**
     * 指令层加密模式。
     * - "f6" (默认): per-IP keystream + per-IP ROL + CBC chaining + IV
     * - "f4"        : v0.6 legacy 单 mulberry32(insnSeed) 流 XOR
     * - "off"       : 不加密（insnSeed 不设，明文写指令，仅用于调试）
     */
    insnCrypt?: InsncryptMode;
}
export declare function compileAST(ast: Node, seed: number, opts?: CompilerOptions): FuncPrototype;
