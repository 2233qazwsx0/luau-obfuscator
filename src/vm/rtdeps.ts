// src/vm/rtdeps.ts — 运行时依赖层（v0.10 Feature 2 + 4）。
//
// 在 keyfuse 的 512 位 XOR 外层之上再插一层 position-dependent ADD/SUB，
// 其密钥流由 runtime token 派生。token 依赖运行时才能拿到的值
// （#HEX_BLOB 碎片装配后的长度 + #_kh keyfuse 宿主表大小），使得整条
// 解密链无法被纯静态模拟。
//
// 同时让 keyfuse KEY 的 2 个 nibble 由 runtime token 派生，废弃"纯静态
// 状态机拼密钥"——至少有一部分密钥片段只在运行时才能获得。
//
// 记住我们面向的是 luau，加密后的也是 luau。

/** RT_TOKEN 公式常量（TS 与 Lua 运行时必须完全对齐）。 */
const RT_MUL1 = 2654435761;
const RT_MUL2 = 16777619;
const RT_SALT = 0x5f051701;

/**
 * 从运行时值派生 32 位 token。TS 侧在打包时用已知长度计算；
 * Lua 运行时在 boot 阶段从 #HEX_BLOB / #_kh 计算，两者必须相同。
 *
 *   rt_token = (hexLen * 2654435761 + khSize * 16777619 + 0x5F051701) % 2^32
 *
 * hexLen / khSize 不依赖 KEY 内容（xor512 / rt_mix 均保长），故无循环依赖。
 */
export function deriveRtToken(hexLen: number, khSize: number): number {
  return ((hexLen * RT_MUL1 + khSize * RT_MUL2 + RT_SALT) % 4294967296) >>> 0;
}

/**
 * 从 rt_token 派生 2 个 keyfuse KEY nibble（Feature 2）。
 * nibble[126] = (token >>> 4) & 0xF
 * nibble[127] = (token >>> 8) & 0xF
 * 对应 KEY 的最后 1 字节（keyBytes[63] = nibble126*16 + nibble127）。
 */
export function rtTokenToNibbles(token: number): [number, number] {
  return [((token >>> 4) & 0xf), ((token >>> 8) & 0xf)];
}

/**
 * rt_mix 加密层（position-dependent ADD）。
 * 公式：out[i] = (data[i] + (token + (i+1)*31 + 7) % 256) % 256
 * 与 stream cipher 不同公式（i*31+7 vs i+1），不可折叠。
 */
export function rtMixEncrypt(data: string, token: number): string {
  const bytes = Buffer.from(data, "binary");
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const v = i + 1;
    const k = (token + v * 31 + 7) % 256;
    out[i] = (bytes[i]! + k) & 0xff;
  }
  return out.toString("binary");
}

/** rt_mix 解密层（加密的逆）。 */
export function rtMixDecrypt(data: string, token: number): string {
  const bytes = Buffer.from(data, "binary");
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const v = i + 1;
    const k = (token + v * 31 + 7) % 256;
    out[i] = (bytes[i]! - k + 256) & 0xff;
  }
  return out.toString("binary");
}
