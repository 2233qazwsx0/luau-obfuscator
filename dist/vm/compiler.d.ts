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
    /** v0.12 Feature #3: 紧凑算术/比较。开启后 ADD/SUB/MUL/DIV/MOD/POW 合并为
     *  ALU 指令（D 字段编码运算类型），EQ/NEQ/LT/LE/GT/GE 合并为 CMP 指令。
     *  减少 dispatch 分支数量。默认 false（不破坏现有字节码）。 */
    compactArith?: boolean;
}
export declare function compileAST(ast: Node, seed: number, opts?: CompilerOptions): FuncPrototype;
