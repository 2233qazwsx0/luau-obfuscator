// src/vm/insncrypt.ts — Instruction-layer encryption (F6, v0.11).
//
// F6 升级 v0.6 F4 的单 mulberry32 流 XOR，提供三层强化：
//
//   F6.1 Per-IP keystream mixing
//     每条指令的 (k8, k9) 由独立 mulberry32 流生成：
//       perIpSeed_i = insnSeed ^ imul(i + 1, 0x9E3779B1)
//       rng_i = mulberry32(perIpSeed_i)
//     → 攻击者从一条指令恢复 keystream，无法预测其他指令的 keystream
//       （F4 是单流，泄露 16+ 字节即可还原状态机、预测后续所有指令）。
//
//   F6.2 Per-IP bit rotation
//     XOR 后对 b8/b9 各做一次 ROL，旋转量由 per-IP rng 派生：
//       rotB8_i, rotB9_i ∈ [1, 31]（强制非 0，避免退化为恒等）
//     → 即使攻击者通过差分分析拿到 keystream，比特位仍被打乱，
//       必须额外恢复每条指令的旋转量才能还原 opcode/operand 字段。
//
//   F6.3 CBC-style inter-instruction chaining + IV
//       enc_i = ROL((plain_i ^ key_i) ^ enc_{i-1}, rot_i)
//       enc_{-1} = (ivB8, ivB9)  ← 写入 proto header
//     → tamper propagation：篡改任一字节破坏本条 + 下一条的解密。
//       攻击者无法做 splice-and-replay：插入/删除任一指令都会让后续全部错位。
//
// 与 v0.6 F4 共存：proto.insnCryptMode 字段选择模式。
//   0 / undefined = F4 (legacy stream cipher)
//   1             = F6 (per-IP + ROL + CBC + IV)
// F4 路径保留用于反序列化旧 proto / 调试 / 关闭 F6 的场景。
//
// 与 Luau 运行时 (runtime/vm-runtime.template.lua) 严格对齐：
//   - rol32/ror32 用纯算术 (bshr + bor32 + b32)，与 Luau 端同源；
//   - mulberry32 与 src/util/prng.ts 完全对齐；
//   - perIpParams 的派生公式必须两端一致。

import { mulberry32 } from "../util/prng.js";

/** F6 模式常量：与 proto.insnCryptMode 字段值一一对应。 */
export const INSN_CRYPT_F4 = 0; // legacy: 单 mulberry32(insnSeed) 流 XOR
export const INSN_CRYPT_F6 = 1; // v0.11: per-IP + ROL + CBC + IV

/** 32 位循环左移（纯算术实现，与 Luau 端 bshr/bor32/b32 对齐）。 */
export function rol32(x: number, n: number): number {
  x = x >>> 0;
  n = ((n % 32) + 32) % 32;
  if (n === 0) return x;
  return (((x << n) >>> 0) | (x >>> (32 - n))) >>> 0;
}

/** 32 位循环右移。 */
export function ror32(x: number, n: number): number {
  return rol32(x, -n);
}

/**
 * 派生第 i 条指令的 (k8, k9, rotB8, rotB9)。
 *
 * 关键设计：每条指令独立 mulberry32 流 → 独立 keystream。
 * 攻击者从一条指令恢复 (k8, k9) 无法预测其他指令，因为：
 *   - mulberry32 状态由 perIpSeed 唯一决定；
 *   - perIpSeed_i 之间无序列关系（i 通过 imul 混淆后 XOR 进 seed）；
 *   - 想要恢复 perIpSeed_i，必须先有 i 的正确 keystream。
 *
 * rotB8/rotB9 强制 ∈ [1, 31]，避免 ROL 退化为恒等。
 */
function perIpParams(insnSeed: number, ip: number): {
  k8: number;
  k9: number;
  rotB8: number;
  rotB9: number;
} {
  // F6.1: imul 让 i 在 32 位空间里均匀散开，避免低 i 的 seed 之间有线性关系。
  const perIpSeed = (insnSeed ^ (Math.imul(ip + 1, 0x9E3779B1) >>> 0)) >>> 0;
  const rng = mulberry32(perIpSeed);
  const k8 = (Math.floor(rng() * 0x100000000)) >>> 0;
  const k9 = (Math.floor(rng() * 0x100000000)) >>> 0;
  // F6.2: rot ∈ [1, 31]，避免 0（恒等）。
  const rotB8 = 1 + Math.floor(rng() * 31);
  const rotB9 = 1 + Math.floor(rng() * 31);
  return { k8, k9, rotB8, rotB9 };
}

/**
 * F6 加密：把 (plainB8[], plainB9[]) 加密成 (encB8[], encB9[])。
 *
 *   enc_i = ROL((plain_i ^ key_i) ^ enc_{i-1}, rot_i)
 *   enc_{-1} = (ivB8, ivB9)
 *
 * @param plainB8 / plainB9 — encodeInstruction() 的输出（明文指令字段）
 * @param insnSeed           — proto.insnSeed
 * @param iv                 — proto.insnIv，CBC 初始向量
 */
export function f6Encrypt(
  plainB8: number[],
  plainB9: number[],
  insnSeed: number,
  iv: { b8: number; b9: number },
): { encB8: number[]; encB9: number[] } {
  const n = plainB8.length;
  const encB8 = new Array<number>(n);
  const encB9 = new Array<number>(n);
  let prevB8 = iv.b8 >>> 0;
  let prevB9 = iv.b9 >>> 0;
  for (let i = 0; i < n; i++) {
    const { k8, k9, rotB8, rotB9 } = perIpParams(insnSeed, i);
    // F6.3: 与前一条密文 XOR（CBC chaining）
    const xB8 = (((plainB8[i]! ^ k8) >>> 0) ^ prevB8) >>> 0;
    const xB9 = (((plainB9[i]! ^ k9) >>> 0) ^ prevB9) >>> 0;
    // F6.2: per-IP bit rotation
    encB8[i] = rol32(xB8, rotB8);
    encB9[i] = rol32(xB9, rotB9);
    prevB8 = encB8[i]!;
    prevB9 = encB9[i]!;
  }
  return { encB8, encB9 };
}

/**
 * F6 解密：f6Encrypt 的严格逆运算。
 *
 *   plain_i = ROR(enc_i, rot_i) ^ enc_{i-1} ^ key_i
 *   enc_{-1} = (ivB8, ivB9)
 *
 * 篡改任一 enc 字节会让本条 ROR 解码错误 + 下一条 XOR chain 错误。
 */
export function f6Decrypt(
  encB8: number[],
  encB9: number[],
  insnSeed: number,
  iv: { b8: number; b9: number },
): { plainB8: number[]; plainB9: number[] } {
  const n = encB8.length;
  const plainB8 = new Array<number>(n);
  const plainB9 = new Array<number>(n);
  let prevB8 = iv.b8 >>> 0;
  let prevB9 = iv.b9 >>> 0;
  for (let i = 0; i < n; i++) {
    const { k8, k9, rotB8, rotB9 } = perIpParams(insnSeed, i);
    // 逆 F6.2
    const xB8 = (ror32(encB8[i]!, rotB8) ^ prevB8) >>> 0;
    const xB9 = (ror32(encB9[i]!, rotB9) ^ prevB9) >>> 0;
    // 逆 F6.1
    plainB8[i] = (xB8 ^ k8) >>> 0;
    plainB9[i] = (xB9 ^ k9) >>> 0;
    // 下一条的 chain 输入是本条的密文（与加密端一致）
    prevB8 = encB8[i]! >>> 0;
    prevB9 = encB9[i]! >>> 0;
  }
  return { plainB8, plainB9 };
}

/**
 * F4 keystream：单 mulberry32(insnSeed) 流 XOR（v0.6 legacy 行为）。
 * 保留用于反序列化旧 proto / 关闭 F6 的场景。
 */
export function f4Keystream(
  insnSeed: number,
  n: number,
): { k8: number[]; k9: number[] } {
  const rng = mulberry32(insnSeed >>> 0);
  const k8 = new Array<number>(n);
  const k9 = new Array<number>(n);
  for (let i = 0; i < n; i++) {
    k8[i] = (Math.floor(rng() * 0x100000000)) >>> 0;
    k9[i] = (Math.floor(rng() * 0x100000000)) >>> 0;
  }
  return { k8, k9 };
}

/**
 * 生成随机 IV（用于 F6 CBC chaining 的初始向量）。
 * 与编译器共享同一 PRNG，确保确定性。
 */
export function genInsnIv(rng: () => number): { b8: number; b9: number } {
  return {
    b8: (Math.floor(rng() * 0x100000000)) >>> 0,
    b9: (Math.floor(rng() * 0x100000000)) >>> 0,
  };
}
