// src/vm/memory.ts — 内存清理与反 dump（v0.5）。
//
// 实际的 Lua 内存清理代码直接写在 runtime/vm-runtime.template.lua 里，用
// `--[[__MEMWIPE_BEGIN__]]` / `--[[__MEMWIPE_END__]]` 这类 marker 注释包裹。
// runtime-template.ts 根据 opts 决定保留还是剥离对应区段，并在需要时注入
// 假 blob。本文件只提供：选项类型 + 假 blob 生成器（需要 TS 侧 PRNG 计算）。
//
// 记住我们面向的是 luau，加密后的也是 luau。
/** 默认开启。 */
export const DEFAULT_MEMWIPE = {
    memwipe: true,
    antidump: true,
};
/**
 * 生成一段假字节码 blob（hex 字符串），用于反 dump 诱饵。
 * 长度与真实 blob 接近（±20%），内容为伪随机字节，让 dump 出来看起来像真数据。
 *
 * @param realHexLen 真实 blob 的 hex 长度（字节数 ×2）
 * @param seed       PRNG 种子，保证可复现
 */
export function genFakeBlob(realHexLen, seed) {
    // mulberry32 PRNG（与 src/util/prng.ts 一致，内联避免循环依赖）
    let s = seed >>> 0;
    const rand = () => {
        s = (s + 0x6D2B79F5) >>> 0;
        let t = s;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const len = Math.max(64, Math.floor(realHexLen * (0.8 + rand() * 0.4)));
    const hex = "0123456789ABCDEF";
    let out = "";
    for (let i = 0; i < len; i++) {
        out += hex[Math.floor(rand() * 16)];
    }
    return out;
}
//# sourceMappingURL=memory.js.map