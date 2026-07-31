// src/vm/memory.ts — 运行时保护选项 + 反 dump 假 blob 生成（v0.5/v0.7）。
//
// 本文件只提供：选项类型 + 假 blob 生成器（需要 TS 侧 PRNG 计算）。
// 实际的 Lua 内存清理代码直接写在 runtime/vm-runtime.template.lua 里，用
// marker 注释包裹，由 runtime-template.ts 根据 opts 决定保留/剥离。
//
// 记住我们面向的是 luau，加密后的也是 luau。

/** 运行时保护选项（由 pipeline 传入）。 */
export interface RuntimeProtectOptions {
  /** 启用即时寄存器清零 + boot 末尾 secure_nil/GC（v0.5）。 */
  memwipe?: boolean;
  /** 启用反 dump 假数据诱饵（v0.5）。 */
  antidump?: boolean;
  /** 启用 hex blob 碎片化（v0.7）：拆散为 N 碎片，D4 散入 dispatch case。 */
  frag?: boolean;
  /** 启用 512 位密钥深度融合（v0.9 keyfuse）：XOR 外层 + 碎片宿主 + 乱序装配。 */
  keyfuse?: boolean;
}

/** 默认全开。 */
export const DEFAULT_RUNTIME_PROTECT: RuntimeProtectOptions = {
  memwipe: true,
  antidump: true,
  frag: true,
  keyfuse: true,
};

/**
 * 生成一段假字节码 blob（hex 字符串），用于反 dump 诱饵。
 * 长度与真实 blob 接近（±20%），内容为伪随机字节，让 dump 出来看起来像真数据。
 *
 * @param realHexLen 真实 blob 的 hex 长度（字节数 ×2）
 * @param seed       PRNG 种子，保证可复现
 */
export function genFakeBlob(realHexLen: number, seed: number): string {
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
