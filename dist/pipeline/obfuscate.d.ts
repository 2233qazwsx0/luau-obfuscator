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
