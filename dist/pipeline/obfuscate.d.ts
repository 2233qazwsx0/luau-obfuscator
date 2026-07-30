import { type StringCipher } from "../transforms/strings.js";
export interface ObfuscateOptions {
    seed?: number;
    /** Disable identifier renaming. */
    noRename?: boolean;
    /** Disable number bitxor. */
    noNumbers?: boolean;
    /** Disable string encryption. */
    noStrings?: boolean;
    /** Disable control-flow flattening. */
    noFlatten?: boolean;
    /** Disable dead code injection. */
    noDeadcode?: boolean;
    /** Minify output (single line, no comments). */
    minify?: boolean;
    /** Enable VM bytecode mode (AST → bytecode → LZW+XOR → hex). */
    vm?: boolean;
    /** Wrap VM bytecode in Luau runtime template → executable script (v0.4). */
    runtime?: boolean;
    /** Disable runtime memory wiping (secure_nil + GC, v0.5). */
    noMemwipe?: boolean;
    /** Disable anti-dump decoy blob (v0.5). */
    noAntidump?: boolean;
    /** Disable hex blob fragmentation (v0.7). */
    noFrag?: boolean;
    /** v0.6 F1: 递归控制流平坦化（嵌套函数/闭包也跑 D4）。默认 true。 */
    recursiveFlatten?: boolean;
    /** v0.6 F2: 递归不透明谓词包裹 + 死代码注入（每个函数作用域独立处理）。默认 true。 */
    recursiveDeadcode?: boolean;
    /** @internal 递归自调用标记，抑制重复追加签名。 */
    _internal?: boolean;
}
export interface ObfuscateResult {
    out: string;
    cipher: StringCipher;
    nameMap: Map<string, string>;
    /** VM mode: packed hex bytecode string. Present only when opts.vm is true. */
    vmHex?: string;
}
export declare function obfuscateSource(src: string, opts?: ObfuscateOptions): string;
export declare function runPipeline(src: string, opts?: ObfuscateOptions): ObfuscateResult;
