// src/transforms/strings.ts — D3: per-string XOR encryption with rolling factor.
//
// v0.10 升级：废除全局共享 4 字节主密钥，每条字符串使用独立 6 字节密钥，
// 并在解密公式中加入 LCG 滚动因子，避免单一可识别模式。
//
// 加密公式（TS 端，i 为 0-based 字节序号）：
//   R_0   = key[0] ^ key[5]                         (8-bit 初值)
//   R_{n+1} = (R_n * 1664525 + 1013904223) >>> 0    (LCG, 32-bit 状态)
//   cipher[i] = (plain[i] ^ ((key[i % 6] + i) & 0xff) ^ (R & 0xff)) & 0xff
//   R = R_{i+1}
//
// Lua 端解密镜像（emitter 内联 IIFE）：
//   local R = _B(K[1], K[6])
//   for j = 0, len-1 do
//     O = O .. string.char((_B(_B(hex_byte, (K[(j%6)+1]+j)%256), R%256)) % 256)
//     R = (R * 1664525 + 1013904223) % 4294967296
//   end
//
// 每条字符串独立密钥 → 攻破一条不泄露其他；LCG 滚动 → 单字节模式不可识别。

import { mulberry32 } from "../util/prng.js";

/** 单条加密字符串的密钥长度（字节）。 */
export const STRING_KEY_BYTES = 6;

export interface StringCipher {
  /** 每条字符串的加密 blob + 独立 6 字节密钥。 */
  pool: { id: number; hex: string; key: number[] }[];
}

/** 构造空 cipher（保留 seed 参数以便调用方记录，但不再派生全局主密钥）。 */
export function buildCipher(_seed: number): StringCipher {
  return { pool: [] };
}

/** 由 seed + strId 派生 6 字节独立密钥。 */
export function deriveStringKey(seed: number, strId: number): number[] {
  const rng = mulberry32((seed ^ 0x51571425 ^ Math.imul(strId + 1, 0x9E3779B1)) >>> 0);
  const key: number[] = [];
  for (let i = 0; i < STRING_KEY_BYTES; i++) key.push(Math.floor(rng() * 256));
  return key;
}

/**
 * 用 6 字节 key + LCG 滚动因子加密单个字符串，返回 hex。
 * 与 emitter 内联的 Lua IIFE 完全对齐。
 */
export function encryptString(s: string, key: number[]): string {
  if (key.length !== STRING_KEY_BYTES) {
    throw new Error(`encryptString: key must be ${STRING_KEY_BYTES} bytes, got ${key.length}`);
  }
  const buf = Buffer.from(s, "utf8");
  let R = (key[0]! ^ key[STRING_KEY_BYTES - 1]!) >>> 0;
  for (let i = 0; i < buf.length; i++) {
    const k = key[i % STRING_KEY_BYTES]!;
    buf[i] = (buf[i]! ^ ((k + i) & 0xff) ^ (R & 0xff)) & 0xff;
    R = (Math.imul(R, 1664525) + 1013904223) >>> 0;
  }
  return buf.toString("hex").toUpperCase();
}

/** 解密单个 blob（与加密对称同形）。 */
export function decryptString(hex: string, key: number[]): string {
  if (key.length !== STRING_KEY_BYTES) {
    throw new Error(`decryptString: key must be ${STRING_KEY_BYTES} bytes, got ${key.length}`);
  }
  const buf = Buffer.from(hex, "hex");
  let R = (key[0]! ^ key[STRING_KEY_BYTES - 1]!) >>> 0;
  for (let i = 0; i < buf.length; i++) {
    const k = key[i % STRING_KEY_BYTES]!;
    buf[i] = (buf[i]! ^ ((k + i) & 0xff) ^ (R & 0xff)) & 0xff;
    R = (Math.imul(R, 1664525) + 1013904223) >>> 0;
  }
  return buf.toString("utf8");
}
