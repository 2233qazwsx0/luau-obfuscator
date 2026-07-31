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
    /** Disable 512-bit key deep-fusion (v0.9 keyfuse). */
    noKeyfuse?: boolean;
    /** Disable v0.10 dynamic anti-debug (timing / hook integrity / env cleanliness + periodic check). */
    noDynamicAntidump?: boolean;
    /** Disable v0.10 runtime-dependency layer (rt_mix + keyfuse runtime nibbles). Requires keyfuse. */
    noRtDeps?: boolean;
    /** v0.6 F1: 递归控制流平坦化（嵌套函数/闭包也跑 D4）。默认 true。 */
    recursiveFlatten?: boolean;
    /** v0.6 F2: 递归不透明谓词包裹 + 死代码注入（每个函数作用域独立处理）。默认 true。 */
    recursiveDeadcode?: boolean;
    /** v0.11 F6: 关闭指令层加密（F6 per-IP + ROL + CBC）。默认 false（即 F6 开启）。
     *  仅用于调试 / 反序列化旧 proto；关闭后字节码指令字段以明文写入。 */
    noInsnCrypt?: boolean;
    /** v0.12 Feature #7: D5 死代码注入上限（占原始语句数比例）。默认 0.2（轻量模式）。
     *  传 0.5 可恢复 v0.6 行为；传 0 等价于 noDeadcode。 */
    deadcodeRatio?: number;
    /** v0.12 Feature #1: 选择性虚拟化。只把 --@vm 注解（或自动识别）的关键函数
     *  编译进 VM，其余代码走 D1-D5 轻量混淆。未标记任何函数时退化为普通（非 VM）模式。 */
    selectiveVm?: boolean;
    /** v0.12 Feature #2: 自动识别关键逻辑函数（HttpGet/loadstring/卡密/白名单校验）
     *  进 VM。仅在无 --@vm 注解时生效。默认 true。传 false 关闭自动识别。 */
    vmAutoIdentify?: boolean;
    /** v0.12 Feature #3: 紧凑算术/比较。VM 编译时 ADD/SUB/MUL/DIV/MOD/POW 合并为
     *  ALU 指令，EQ/NEQ/LT/LE/GT/GE 合并为 CMP 指令。减少 dispatch 分支数量。
     *  默认 false（不破坏现有字节码）。仅 vm/runtime 模式生效。 */
    compactArith?: boolean;
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
