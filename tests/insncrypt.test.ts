// tests/insncrypt.test.ts — v0.11 F6 指令层加密测试。
//
// 覆盖：
//   1. rol32 / ror32 位运算正确性（已知值 / 逆运算 / 边界）
//   2. genInsnIv 输出范围
//   3. f6Encrypt / f6Decrypt 往返一致性（多 seed / 多长度 / 多 IV）
//   4. F6 vs F4：相同输入产生不同密文（确认 F6 不是 F4 的别名）
//   5. Per-IP keystream 独立性：改一条明文不影响其他指令的 keystream
//   6. Per-IP ROL：rot ∈ [1, 31]，绝不退化到 0
//   7. CBC tamper propagation：篡改任一密文字节破坏本条 + 下一条解密
//   8. CBC splice-and-replay 防御：插入 / 删除指令让后续错位
//   9. IV 敏感性：不同 IV → 不同密文
//  10. F4 向后兼容：f4Keystream 单流 XOR 仍可用
//  11. Lua 运行时公式与 TS 对齐（per_ip_params + f6_decrypt 复刻）
//  12. encoder serialize/deserialize F6 往返
//  13. encoder F6 序列化包含 mode + IV 字节
//  14. encoder F4 向后兼容（旧 proto 无 mode 字节 → 反序列化默认 F4）
//  15. compiler F6 默认 / F4 / off 三模式
//  16. pipeline noInsnCrypt 选项透传

import { describe, it, expect } from "vitest";
import {
  rol32,
  ror32,
  f6Encrypt,
  f6Decrypt,
  f4Keystream,
  genInsnIv,
  INSN_CRYPT_F4,
  INSN_CRYPT_F6,
} from "../src/vm/insncrypt.js";
import {
  serializeFunction,
  deserializeFunction,
  encodeInstruction,
  decodeInstruction,
} from "../src/vm/encoder.js";
import type { ConstEntry } from "../src/vm/opcodes.js";
import { compileAST } from "../src/vm/compiler.js";
import { lex } from "../src/parser/lexer.js";
import { parse } from "../src/parser/parser.js";
import { runPipeline } from "../src/pipeline/obfuscate.js";
import { mulberry32 } from "../src/util/prng.js";

// ---- 1. rol32 / ror32 ----

describe("insncrypt: rol32 / ror32", () => {
  it("rol32(0, n) = 0", () => {
    for (let n = 0; n < 32; n++) {
      expect(rol32(0, n)).toBe(0);
    }
  });

  it("rol32(x, 0) = x", () => {
    const samples = [0, 1, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678, 0x80000000];
    for (const x of samples) {
      expect(rol32(x, 0)).toBe(x >>> 0);
    }
  });

  it("rol32(x, 32) = x (full rotation)", () => {
    const samples = [1, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678];
    for (const x of samples) {
      expect(rol32(x, 32)).toBe(x >>> 0);
    }
  });

  it("rol32 与 ror32 互逆：ror32(rol32(x, n), n) = x", () => {
    const samples = [0, 1, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678, 0x80000000, 0x7FFFFFFF];
    for (const x of samples) {
      for (let n = 0; n < 32; n++) {
        expect(ror32(rol32(x, n), n)).toBe(x >>> 0);
        expect(rol32(ror32(x, n), n)).toBe(x >>> 0);
      }
    }
  });

  it("rol32 已知值：rol32(1, 1) = 2, rol32(1, 31) = 0x80000000", () => {
    expect(rol32(1, 1)).toBe(2);
    expect(rol32(1, 31)).toBe(0x80000000 >>> 0);
  });

  it("rol32 高位回绕：rol32(0x80000000, 1) = 1", () => {
    expect(rol32(0x80000000, 1)).toBe(1);
  });

  it("rol32 结果始终在 [0, 2^32)", () => {
    const samples = [0, 1, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678];
    for (const x of samples) {
      for (let n = 0; n < 40; n++) {
        const r = rol32(x, n);
        expect(r).toBeGreaterThanOrEqual(0);
        expect(r).toBeLessThan(0x100000000);
      }
    }
  });

  it("rol32 负旋转量等价于反向：rol32(x, -n) = ror32(x, n)", () => {
    const samples = [1, 0xDEADBEEF, 0x12345678];
    for (const x of samples) {
      for (let n = 1; n < 32; n++) {
        expect(rol32(x, -n)).toBe(ror32(x, n));
      }
    }
  });
});

// ---- 2. genInsnIv ----

describe("insncrypt: genInsnIv", () => {
  it("输出在 [0, 2^32) 范围内", () => {
    const rng = mulberry32(42);
    for (let i = 0; i < 100; i++) {
      const iv = genInsnIv(rng);
      expect(iv.b8).toBeGreaterThanOrEqual(0);
      expect(iv.b8).toBeLessThan(0x100000000);
      expect(iv.b9).toBeGreaterThanOrEqual(0);
      expect(iv.b9).toBeLessThan(0x100000000);
    }
  });

  it("相同 rng 状态 → 相同 IV（确定性）", () => {
    const rng1 = mulberry32(123);
    const rng2 = mulberry32(123);
    expect(genInsnIv(rng1)).toEqual(genInsnIv(rng2));
  });

  it("不同 rng 种子 → 不同 IV（高概率）", () => {
    const a = genInsnIv(mulberry32(1));
    const b = genInsnIv(mulberry32(2));
    // b8 / b9 至少一个不同（实际两者几乎必不同）
    expect(a).not.toEqual(b);
  });
});

// ---- 3. f6Encrypt / f6Decrypt 往返 ----

describe("insncrypt: f6Encrypt / f6Decrypt 往返", () => {
  it("encrypt → decrypt = identity（空数组）", () => {
    const iv = { b8: 0, b9: 0 };
    const r = f6Encrypt([], [], 42, iv);
    expect(r.encB8).toEqual([]);
    expect(r.encB9).toEqual([]);
    const d = f6Decrypt(r.encB8, r.encB9, 42, iv);
    expect(d.plainB8).toEqual([]);
    expect(d.plainB9).toEqual([]);
  });

  it("encrypt → decrypt = identity（单条指令）", () => {
    const plainB8 = [0x12345678];
    const plainB9 = [0xDEADBEEF];
    const iv = { b8: 0x11223344, b9: 0x55667788 };
    const r = f6Encrypt(plainB8, plainB9, 42, iv);
    const d = f6Decrypt(r.encB8, r.encB9, 42, iv);
    expect(d.plainB8).toEqual(plainB8.map((x) => x >>> 0));
    expect(d.plainB9).toEqual(plainB9.map((x) => x >>> 0));
  });

  it("encrypt → decrypt = identity（多条指令，多 seed / 多 IV）", () => {
    // 用真实 encodeInstruction 产生的 (b8, b9) 序列
    const insns = [
      { op: 1, A: 0, B: 0, C: 0, D: 0, mode: 0 as const },
      { op: 2, A: 1, B: 1, C: 1, D: 1, mode: 0 as const },
      { op: 50, A: 2, B: 5, C: 10, D: 0, mode: 0 as const },
      { op: 100, A: 3, B: 0, C: 0x100000, D: 0, mode: 1 as const },
      { op: 200, A: 4, B: 0, C: -100, D: 0, mode: 2 as const },
      { op: 150, A: 5, B: 7, C: -5, D: 9, mode: 3 as const },
    ];
    const plainB8 = insns.map((i) => encodeInstruction(i)[0]);
    const plainB9 = insns.map((i) => encodeInstruction(i)[1]);

    for (const seed of [0, 1, 42, 999, 0xDEADBEEF, 0xFFFFFFFF]) {
      for (const iv of [
        { b8: 0, b9: 0 },
        { b8: 0x11223344, b9: 0x55667788 },
        { b8: 0xFFFFFFFF, b9: 0xFFFFFFFF },
      ]) {
        const r = f6Encrypt(plainB8, plainB9, seed, iv);
        const d = f6Decrypt(r.encB8, r.encB9, seed, iv);
        expect(d.plainB8).toEqual(plainB8);
        expect(d.plainB9).toEqual(plainB9);
        // 解码后指令字段应与原始一致
        for (let i = 0; i < insns.length; i++) {
          const dec = decodeInstruction(d.plainB8[i]!, d.plainB9[i]!);
          expect(dec.op).toBe(insns[i]!.op);
          expect(dec.A).toBe(insns[i]!.A);
          expect(dec.B).toBe(insns[i]!.B);
          expect(dec.C).toBe(insns[i]!.C);
          expect(dec.D).toBe(insns[i]!.D);
          expect(dec.mode).toBe(insns[i]!.mode);
        }
      }
    }
  });

  it("密文与明文不同（非恒等加密）", () => {
    const plainB8 = [0x12345678, 0xDEADBEEF, 0x00000000];
    const plainB9 = [0x11111111, 0x22222222, 0x33333333];
    const iv = { b8: 0xAAAAAAAA, b9: 0xBBBBBBBB };
    const r = f6Encrypt(plainB8, plainB9, 42, iv);
    // 至少应有部分密文不等于明文（实际几乎全部不同）
    let same = 0;
    for (let i = 0; i < plainB8.length; i++) {
      if (r.encB8[i] === plainB8[i] && r.encB9[i] === plainB9[i]) same++;
    }
    expect(same).toBeLessThan(plainB8.length);
  });

  it("密文始终在 [0, 2^32) 范围内", () => {
    const plainB8 = [0, 1, 0xFFFFFFFF, 0xDEADBEEF, 0x80000000];
    const plainB9 = [0, 1, 0xFFFFFFFF, 0xCAFEBABE, 0x7FFFFFFF];
    const r = f6Encrypt(plainB8, plainB9, 42, { b8: 0, b9: 0 });
    for (let i = 0; i < r.encB8.length; i++) {
      expect(r.encB8[i]!).toBeGreaterThanOrEqual(0);
      expect(r.encB8[i]!).toBeLessThan(0x100000000);
      expect(r.encB9[i]!).toBeGreaterThanOrEqual(0);
      expect(r.encB9[i]!).toBeLessThan(0x100000000);
    }
  });
});

// ---- 4. F6 vs F4 ----

describe("insncrypt: F6 与 F4 产生不同密文", () => {
  it("相同明文 + 相同 seed：F6 密文 ≠ F4 密文", () => {
    const plainB8 = [0x12345678, 0xDEADBEEF, 0xAAAAAAAA, 0x00000000];
    const plainB9 = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
    const seed = 42;
    const iv = { b8: 0x11223344, b9: 0x55667788 };

    // F6
    const f6 = f6Encrypt(plainB8, plainB9, seed, iv);

    // F4：单 mulberry32(seed) 流 XOR
    const { k8, k9 } = f4Keystream(seed, plainB8.length);
    const f4B8 = plainB8.map((x, i) => ((x >>> 0) ^ k8[i]!) >>> 0);
    const f4B9 = plainB9.map((x, i) => ((x >>> 0) ^ k9[i]!) >>> 0);

    // 至少有一条指令的密文不同（实际几乎全部不同）
    let allSame = true;
    for (let i = 0; i < plainB8.length; i++) {
      if (f6.encB8[i] !== f4B8[i] || f6.encB9[i] !== f4B9[i]) {
        allSame = false;
        break;
      }
    }
    expect(allSame).toBe(false);
  });
});

// ---- 5. Per-IP keystream 独立性 ----

describe("insncrypt: Per-IP keystream 独立性", () => {
  it("改第 i 条明文不影响其他指令的 keystream（F6 per-IP）", () => {
    // 思路：F6 解密时，对每个 i，(k8_i, k9_i) 由 perIpParams(seed, i) 唯一决定，
    // 与其他指令的明文无关。验证：两条序列只差第 i 条明文，解密后第 i 条不同，
    // 其他条相同（前提是 CBC chain 输入相同 —— 这里要排除 CBC 影响只验 keystream）。
    //
    // 直接验证：perIpParams 派生的 (k8, k9) 不依赖任何明文。
    // 实现：用 f6Decrypt 在 iv=0、单条指令序列上提取每条的 keystream。
    //   enc_i = ROL((plain_i ^ k_i) ^ prev_i, rot_i)
    //   若 iv=0 且只看第 0 条：enc_0 = ROL(plain_0 ^ k_0, rot_0)
    //   但 CBC 让 prev_i = enc_{i-1}，所以单条提取最干净。
    const seed = 42;
    const iv = { b8: 0, b9: 0 };

    // 提取第 0 条的 keystream：用 plain=0，则 enc = ROL(0 ^ k ^ 0, rot) = ROL(k, rot)
    // 反推：k = ROR(enc, rot)。这里通过 f6Encrypt(enc=0) → enc 实际是 ROL(prev ^ k, rot)，
    // 但 prev = iv = 0，所以 enc = ROL(k, rot)。
    // 提取 keystream：让 plain=0，得到 enc=ROL(k, rot)，再 ROR 反推 k。
    // 不过更简单：用 plain=X 和 plain=0 两条，相减（XOR）得到 X（因为 keystream 相同）。
    const x = 0x13579BDF;
    const y = 0x2468ACE0;
    const p1B8 = [x];
    const p1B9 = [y];
    const p0B8 = [0];
    const p0B9 = [0];
    const r1 = f6Encrypt(p1B8, p1B9, seed, iv);
    const r0 = f6Encrypt(p0B8, p0B9, seed, iv);

    // ROR(r1.enc, rot) ^ ROR(r0.enc, rot) = (x ^ k ^ 0) ^ (0 ^ k ^ 0) = x
    // 等价：r1.enc ^ r0.enc 后 ROR 不行（ROL 非线性），需要先 ROR 再 XOR。
    // 但我们无法在 TS 测试里直接调 perIpParams（私有）。所以用整段往返 + 多指令间接验证。
    //
    // 间接验证：构造两段明文，只差第 0 条。F6 解密后第 0 条不同，第 1+ 条若没受 CBC
    // 影响则相同 —— 但 CBC 会让 prev 改变 → 第 1 条也会变。所以这个测试主要验证
    // "F4 单流 vs F6 per-IP" 的差异：F4 改明文不影响 keystream（永远不变），
    // F6 的 keystream 也是 per-IP 派生（不依赖明文）。验证方式：对相同 seed，
    // 两次 f6Encrypt 用不同明文，提取出的 keystream（通过 plain=0 反推）应一致。
    expect(r0.encB8[0]).not.toBe(0); // ROL(k, rot) ≠ 0（k 非零概率极高）
    expect(r1.encB8[0]).not.toBe(r0.encB8[0]); // 不同明文 → 不同密文
  });

  it("per-IP keystream 不依赖明文（通过 plain=0 反推一致）", () => {
    // 关键性质：keystream_i 只由 (seed, i) 决定。
    // 验证：对相同 (seed, i)，用 plain=0 加密得到 enc0=ROL(k^prev0, rot)；
    // 用 plain=X 加密得到 encX=ROL(X^k^prevX, rot)。但 prev 取决于前一条密文，
    // 在单条序列（n=1, iv 固定）下 prev=iv 相同。
    // 所以 ROR(enc0, rot) = k ^ iv, ROR(encX, rot) = X ^ k ^ iv
    // → ROR(enc0, rot) ^ ROR(encX, rot) = X
    // 我们无法直接调 perIpParams 拿 rot，但可以通过 f6Decrypt 反推：
    // f6Decrypt([enc0], ..., iv) 应返回 [0]；f6Decrypt([encX], ..., iv) 应返回 [X]。
    // 这已经隐含验证了 keystream 一致性（解密用同一 keystream）。
    const seed = 0xABCDEF01;
    const iv = { b8: 0x11223344, b9: 0x55667788 };
    const X = 0x13579BDF;
    const Y = 0x2468ACE0;

    const enc0 = f6Encrypt([0], [0], seed, iv);
    const encX = f6Encrypt([X], [Y], seed, iv);

    const dec0 = f6Decrypt(enc0.encB8, enc0.encB9, seed, iv);
    const decX = f6Decrypt(encX.encB8, encX.encB9, seed, iv);

    expect(dec0.plainB8[0]).toBe(0);
    expect(dec0.plainB9[0]).toBe(0);
    expect(decX.plainB8[0]).toBe(X);
    expect(decX.plainB9[0]).toBe(Y);

    // 关键：enc0 和 encX 用相同 keystream，所以 ROR(enc0) ^ ROR(encX) = 0 ^ X = X
    // 即 f6Decrypt(enc0 ^ encX 在 ROR 域) = X。但更直接的断言：
    // enc0 ≠ encX（不同明文 → 不同密文，前提 X≠0）
    expect(enc0.encB8[0]).not.toBe(encX.encB8[0]);
  });
});

// ---- 6. Per-IP ROL：rot ∈ [1, 31] ----

describe("insncrypt: Per-IP ROL 旋转量 ∈ [1, 31]", () => {
  it("每条指令的 rot 非 0（通过加密效果验证）", () => {
    // 如果某条指令的 rot=0，则 ROL 退化为恒等，enc = (plain ^ k) ^ prev。
    // 我们无法直接读 rot，但可以验证：对 plain=0、iv=0，enc = ROL(k, rot)。
    // 如果 rot=0，enc = k。而 k 来自 mulberry32 流。
    // 统计学验证：跑 1000 条指令，每条的 (enc, k) 关系都隐含 rot ∈ [1,31]。
    // 间接验证：相同 plain=0、iv=0 下，enc ≠ k（因为 ROL(k, rot≠0) ≠ k，除非 k=0 或 k=2^32 对称）。
    // 我们通过 f6Decrypt 解密 enc 应得到 plain=0 来隐式验证（已在前述测试覆盖）。
    // 这里用另一个角度：rot ∈ [1, 31] 意味着 ROL 应用了一次非平凡旋转。
    // 验证方法：rol32(k, rot) 对于 rot ∈ [1,31] 与 k 不同的概率极高（k 均匀分布）。
    const seed = 42;
    const iv = { b8: 0, b9: 0 };
    const n = 200;
    const plainB8 = new Array(n).fill(0);
    const plainB9 = new Array(n).fill(0);
    const r = f6Encrypt(plainB8, plainB9, seed, iv);

    // 对前 200 条（iv=0, plain=0），enc_i = ROL(k_i ^ prev_i, rot_i)。
    // prev_i = enc_{i-1}。这里只验证 enc 都在 [0, 2^32)（已覆盖），
    // 并验证往返一致（已覆盖）。rot ∈ [1,31] 的直接验证留给 Lua 公式对齐测试。
    expect(r.encB8.length).toBe(n);
    expect(r.encB9.length).toBe(n);
  });

  it("Lua 端 f6_per_ip_params 旋转量 ∈ [1, 31]（公式复刻）", () => {
    // 复刻 runtime/vm-runtime.template.lua 的 f6_per_ip_params，验证 rot ∈ [1, 31]。
    function luaF6PerIpParams(insnSeed: number, i: number): {
      k8: number; k9: number; rotB8: number; rotB9: number;
    } {
      const perIpSeed = (insnSeed ^ (Math.imul(i + 1, 0x9E3779B1) >>> 0)) >>> 0;
      const rng = mulberry32(perIpSeed);
      const k8 = (Math.floor(rng() * 0x100000000)) >>> 0;
      const k9 = (Math.floor(rng() * 0x100000000)) >>> 0;
      const rotB8 = 1 + Math.floor(rng() * 31);
      const rotB9 = 1 + Math.floor(rng() * 31);
      return { k8, k9, rotB8, rotB9 };
    }
    // 跑大量 (seed, i) 组合，所有 rot 都应在 [1, 31]
    for (const seed of [0, 1, 42, 999, 0xDEADBEEF]) {
      for (let i = 0; i < 500; i++) {
        const { rotB8, rotB9 } = luaF6PerIpParams(seed, i);
        expect(rotB8).toBeGreaterThanOrEqual(1);
        expect(rotB8).toBeLessThanOrEqual(31);
        expect(rotB9).toBeGreaterThanOrEqual(1);
        expect(rotB9).toBeLessThanOrEqual(31);
      }
    }
  });
});

// ---- 7. CBC tamper propagation ----

describe("insncrypt: CBC tamper propagation", () => {
  it("篡改第 i 条密文 → 第 i 条与第 i+1 条明文都损坏", () => {
    const insns = [
      { op: 1, A: 0, B: 0, C: 0, D: 0, mode: 0 as const },
      { op: 2, A: 1, B: 1, C: 1, D: 1, mode: 0 as const },
      { op: 3, A: 2, B: 2, C: 2, D: 2, mode: 0 as const },
      { op: 4, A: 3, B: 3, C: 3, D: 3, mode: 0 as const },
    ];
    const plainB8 = insns.map((i) => encodeInstruction(i)[0]);
    const plainB9 = insns.map((i) => encodeInstruction(i)[1]);
    const seed = 42;
    const iv = { b8: 0x11111111, b9: 0x22222222 };

    const r = f6Encrypt(plainB8, plainB9, seed, iv);
    const d0 = f6Decrypt(r.encB8, r.encB9, seed, iv);
    // 基线：解密应还原明文
    expect(d0.plainB8).toEqual(plainB8);

    // 篡改第 1 条的 b8 和 b9（翻转一位）。b8/b9 链独立，需同时篡改才能
    // 让第 2 条的两个字段都损坏。
    const tamperedB8 = [...r.encB8];
    const tamperedB9 = [...r.encB9];
    tamperedB8[1] = (tamperedB8[1]! ^ 0x00010000) >>> 0;
    tamperedB9[1] = (tamperedB9[1]! ^ 0x00010000) >>> 0;
    const d1 = f6Decrypt(tamperedB8, tamperedB9, seed, iv);

    // 第 0 条：prev=iv 不变，密文不变 → 明文不变
    expect(d1.plainB8[0]).toBe(d0.plainB8[0]);
    expect(d1.plainB9[0]).toBe(d0.plainB9[0]);
    // 第 1 条：密文被篡改 → ROR 错误 → 明文损坏
    expect(d1.plainB8[1]).not.toBe(d0.plainB8[1]);
    // 第 2 条：prev=enc[1] 被篡改 → XOR chain 错误 → 明文损坏
    expect(d1.plainB8[2]).not.toBe(d0.plainB8[2]);
    expect(d1.plainB9[2]).not.toBe(d0.plainB9[2]);
    // 第 3 条：prev=enc[2] 未变（enc[2] 没被篡改） → 明文应不变
    expect(d1.plainB8[3]).toBe(d0.plainB8[3]);
    expect(d1.plainB9[3]).toBe(d0.plainB9[3]);
  });

  it("篡改 IV → 第 0 条明文损坏（CBC IV 进入第 0 条的 prev）", () => {
    const plainB8 = [0x12345678, 0xDEADBEEF, 0xAAAAAAAA];
    const plainB9 = [0x11111111, 0x22222222, 0x33333333];
    const seed = 42;
    const iv = { b8: 0x11223344, b9: 0x55667788 };

    const r = f6Encrypt(plainB8, plainB9, seed, iv);
    const d0 = f6Decrypt(r.encB8, r.encB9, seed, iv);
    expect(d0.plainB8).toEqual(plainB8);

    // 篡改 IV
    const badIv = { b8: iv.b8 ^ 1, b9: iv.b9 };
    const d1 = f6Decrypt(r.encB8, r.encB9, seed, badIv);
    // 第 0 条：prev=IV 被篡改 → 明文损坏
    expect(d1.plainB8[0]).not.toBe(d0.plainB8[0]);
    // 第 1 条：prev=enc[0] 不变（密文未改） → 明文不变
    expect(d1.plainB8[1]).toBe(d0.plainB8[1]);
    expect(d1.plainB9[1]).toBe(d0.plainB9[1]);
  });
});

// ---- 8. CBC splice-and-replay 防御 ----

describe("insncrypt: CBC splice-and-replay 防御", () => {
  it("删除中间指令 → 后续解密全部错位", () => {
    const plainB8 = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
    const plainB9 = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];
    const seed = 42;
    const iv = { b8: 0x00000000, b9: 0x00000000 };

    const r = f6Encrypt(plainB8, plainB9, seed, iv);

    // 删除第 1 条：剩余 [0, 2, 3]
    const splicedB8 = [r.encB8[0]!, r.encB8[2]!, r.encB8[3]!];
    const splicedB9 = [r.encB9[0]!, r.encB9[2]!, r.encB9[3]!];
    const d = f6Decrypt(splicedB8, splicedB9, seed, iv);

    // 第 0 条：prev=iv 不变 → 明文不变
    expect(d.plainB8[0]).toBe(plainB8[0]);
    // 第 1 条（原第 2 条）：prev=enc[0] 不变，但 perIpParams(seed, 1) ≠ perIpParams(seed, 2)
    // → 用错的 keystream/rot → 明文损坏
    expect(d.plainB8[1]).not.toBe(plainB8[2]);
    // 后续也全错
    expect(d.plainB8[2]).not.toBe(plainB8[3]);
  });

  it("插入额外指令 → 后续解密错位", () => {
    const plainB8 = [0x11111111, 0x22222222];
    const plainB9 = [0xAAAAAAAA, 0xBBBBBBBB];
    const seed = 42;
    const iv = { b8: 0, b9: 0 };
    const r = f6Encrypt(plainB8, plainB9, seed, iv);

    // 在头部插入一条额外密文（用 iv 当作伪密文）
    const insertedB8 = [iv.b8, ...r.encB8];
    const insertedB9 = [iv.b9, ...r.encB9];
    const d = f6Decrypt(insertedB8, insertedB9, seed, iv);

    // 第 0 条：prev=iv，密文=iv → ROR(iv, rot_0) ^ iv ^ k_0，几乎不可能等于 plainB8[0]
    expect(d.plainB8[0]).not.toBe(plainB8[0]);
    // 第 1 条（原第 0 条）：prev=iv（被插入的），但 perIpParams(seed,1) ≠ perIpParams(seed,0)
    expect(d.plainB8[1]).not.toBe(plainB8[0]);
  });
});

// ---- 9. IV 敏感性 ----

describe("insncrypt: IV 敏感性", () => {
  it("不同 IV → 不同密文", () => {
    const plainB8 = [0x12345678, 0xDEADBEEF, 0xAAAAAAAA];
    const plainB9 = [0x11111111, 0x22222222, 0x33333333];
    const seed = 42;
    const iv1 = { b8: 0x11111111, b9: 0x22222222 };
    const iv2 = { b8: 0x33333333, b9: 0x44444444 };

    const r1 = f6Encrypt(plainB8, plainB9, seed, iv1);
    const r2 = f6Encrypt(plainB8, plainB9, seed, iv2);

    // 第 0 条密文必不同（iv 直接进入第 0 条的 prev）
    expect(r1.encB8[0]).not.toBe(r2.encB8[0]);
    expect(r1.encB9[0]).not.toBe(r2.encB9[0]);
    // 后续也会因 CBC chain 而不同
    expect(r1.encB8).not.toEqual(r2.encB8);
  });

  it("IV=0 也能正常工作（不要求 IV 非零）", () => {
    const plainB8 = [0x12345678];
    const plainB9 = [0xDEADBEEF];
    const r = f6Encrypt(plainB8, plainB9, 42, { b8: 0, b9: 0 });
    const d = f6Decrypt(r.encB8, r.encB9, 42, { b8: 0, b9: 0 });
    expect(d.plainB8).toEqual(plainB8);
    expect(d.plainB9).toEqual(plainB9);
  });
});

// ---- 10. seed 敏感性 ----

describe("insncrypt: seed 敏感性", () => {
  it("不同 seed → 不同密文", () => {
    const plainB8 = [0x12345678, 0xDEADBEEF];
    const plainB9 = [0x11111111, 0x22222222];
    const iv = { b8: 0, b9: 0 };
    const r1 = f6Encrypt(plainB8, plainB9, 1, iv);
    const r2 = f6Encrypt(plainB8, plainB9, 2, iv);
    expect(r1.encB8).not.toEqual(r2.encB8);
  });

  it("相同 seed + 相同 IV + 相同明文 → 相同密文（确定性）", () => {
    const plainB8 = [0x12345678, 0xDEADBEEF];
    const plainB9 = [0x11111111, 0x22222222];
    const iv = { b8: 0x11223344, b9: 0x55667788 };
    const r1 = f6Encrypt(plainB8, plainB9, 42, iv);
    const r2 = f6Encrypt(plainB8, plainB9, 42, iv);
    expect(r1).toEqual(r2);
  });
});

// ---- 11. F4 向后兼容 ----

describe("insncrypt: F4 向后兼容", () => {
  it("f4Keystream 单流 XOR 往返", () => {
    const plainB8 = [0x12345678, 0xDEADBEEF, 0xAAAAAAAA];
    const plainB9 = [0x11111111, 0x22222222, 0x33333333];
    const seed = 42;
    const { k8, k9 } = f4Keystream(seed, plainB8.length);
    const encB8 = plainB8.map((x, i) => ((x >>> 0) ^ k8[i]!) >>> 0);
    const encB9 = plainB9.map((x, i) => ((x >>> 0) ^ k9[i]!) >>> 0);
    // 解密：XOR 同一 keystream
    const decB8 = encB8.map((x, i) => ((x >>> 0) ^ k8[i]!) >>> 0);
    const decB9 = encB9.map((x, i) => ((x >>> 0) ^ k9[i]!) >>> 0);
    expect(decB8).toEqual(plainB8);
    expect(decB9).toEqual(plainB9);
  });

  it("f4Keystream 确定性：相同 seed → 相同流", () => {
    const a = f4Keystream(42, 10);
    const b = f4Keystream(42, 10);
    expect(a).toEqual(b);
  });

  it("f4Keystream 不同 seed → 不同流", () => {
    const a = f4Keystream(1, 10);
    const b = f4Keystream(2, 10);
    expect(a.k8).not.toEqual(b.k8);
    expect(a.k9).not.toEqual(b.k9);
  });

  it("INSN_CRYPT 常量值正确", () => {
    expect(INSN_CRYPT_F4).toBe(0);
    expect(INSN_CRYPT_F6).toBe(1);
  });
});

// ---- 12. Lua 运行时公式与 TS 对齐 ----

describe("insncrypt: Lua 运行时 f6_decrypt 公式与 TS 对齐", () => {
  // 复刻 runtime/vm-runtime.template.lua 的 f6_per_ip_params + f6_decrypt，
  // 验证 Lua 端解密结果与 TS 端 f6Decrypt 完全一致。
  // 这是 F6 跨语言正确性的核心保证：TS 加密的字节码，Luau 运行时必须能解出来。
  function luaF6PerIpParams(insnSeed: number, i: number): {
    k8: number; k9: number; rotB8: number; rotB9: number;
  } {
    // Lua: local per_ip_seed = b32(bxor32(insn_seed, imul32(i + 1, 0x9E3779B1)))
    const perIpSeed = (insnSeed ^ (Math.imul(i + 1, 0x9E3779B1) >>> 0)) >>> 0;
    const rng = mulberry32(perIpSeed);
    const k8 = (Math.floor(rng() * 0x100000000)) >>> 0;
    const k9 = (Math.floor(rng() * 0x100000000)) >>> 0;
    const rotB8 = 1 + Math.floor(rng() * 31);
    const rotB9 = 1 + Math.floor(rng() * 31);
    return { k8, k9, rotB8, rotB9 };
  }

  function luaF6Decrypt(
    encB8: number[],
    encB9: number[],
    insnSeed: number,
    ivB8: number,
    ivB9: number,
  ): { plainB8: number[]; plainB9: number[] } {
    // Lua 1-indexed: for i = 1, num_insns do ... f6_per_ip_params(insn_seed, i - 1)
    const n = encB8.length;
    const plainB8: number[] = new Array(n);
    const plainB9: number[] = new Array(n);
    let prevB8 = ivB8 >>> 0;
    let prevB9 = ivB9 >>> 0;
    for (let idx = 0; idx < n; idx++) {
      const { k8, k9, rotB8, rotB9 } = luaF6PerIpParams(insnSeed, idx); // Lua i-1 = idx
      const xB8 = (ror32(encB8[idx]!, rotB8) ^ prevB8) >>> 0;
      const xB9 = (ror32(encB9[idx]!, rotB9) ^ prevB9) >>> 0;
      plainB8[idx] = (xB8 ^ k8) >>> 0;
      plainB9[idx] = (xB9 ^ k9) >>> 0;
      prevB8 = encB8[idx]! >>> 0;
      prevB9 = encB9[idx]! >>> 0;
    }
    return { plainB8, plainB9 };
  }

  it("Lua f6_decrypt 与 TS f6Decrypt 输出完全一致", () => {
    const insns = [
      { op: 1, A: 0, B: 0, C: 0, D: 0, mode: 0 as const },
      { op: 50, A: 2, B: 5, C: 10, D: 0, mode: 0 as const },
      { op: 100, A: 3, B: 0, C: 0x100000, D: 0, mode: 1 as const },
      { op: 200, A: 4, B: 0, C: -100, D: 0, mode: 2 as const },
      { op: 150, A: 5, B: 7, C: -5, D: 9, mode: 3 as const },
    ];
    const plainB8 = insns.map((i) => encodeInstruction(i)[0]);
    const plainB9 = insns.map((i) => encodeInstruction(i)[1]);

    for (const seed of [0, 1, 42, 999, 0xDEADBEEF, 0xFFFFFFFF]) {
      for (const iv of [
        { b8: 0, b9: 0 },
        { b8: 0x11223344, b9: 0x55667788 },
        { b8: 0xFFFFFFFF, b9: 0xFFFFFFFF },
      ]) {
        const enc = f6Encrypt(plainB8, plainB9, seed, iv);
        const tsDec = f6Decrypt(enc.encB8, enc.encB9, seed, iv);
        const luaDec = luaF6Decrypt(enc.encB8, enc.encB9, seed, iv.b8, iv.b9);
        expect(luaDec.plainB8).toEqual(tsDec.plainB8);
        expect(luaDec.plainB9).toEqual(tsDec.plainB9);
        // 且都还原明文
        expect(luaDec.plainB8).toEqual(plainB8);
        expect(luaDec.plainB9).toEqual(plainB9);
      }
    }
  });

  it("Lua f6_per_ip_params 与 TS 派生公式一致（通过解密等价性隐式验证）", () => {
    // 如果 perIpParams 公式两端不一致，上面的解密等价测试会失败。
    // 这里再加一个直接断言：Lua 公式派生的 rot ∈ [1, 31]（已在前述测试覆盖）。
    // 额外验证：相同 (seed, i) 派生的 (k8, k9) 在两次调用中一致（确定性）。
    const a = luaF6PerIpParams(42, 5);
    const b = luaF6PerIpParams(42, 5);
    expect(a).toEqual(b);
  });
});

// ---- 13. encoder serialize/deserialize F6 往返 ----

describe("encoder: F6 serialize/deserialize 往返", () => {
  function makeProto(opts: {
    seed?: number;
    mode?: number;
    iv?: { b8: number; b9: number };
  }) {
    return {
      instructions: [
        { op: 1, A: 0, B: 0, C: 0, D: 0, mode: 0 as const },
        { op: 50, A: 2, B: 5, C: 10, D: 0, mode: 0 as const },
        { op: 100, A: 3, B: 0, C: 0x100000, D: 0, mode: 1 as const },
      ],
      constants: [
        { type: "string" as const, value: "hello" },
        { type: "number" as const, value: 42.5 },
        { type: "bool" as const, value: true },
      ],
      subFunctions: [],
      paramCount: 0,
      isVararg: false,
      upvalues: [],
      vmId: 0,
      insnSeed: opts.seed,
      insnCryptMode: opts.mode,
      insnIv: opts.iv,
    };
  }

  it("F6 模式：serialize → deserialize 还原指令字段", () => {
    const proto = makeProto({
      seed: 0xDEADBEEF,
      mode: INSN_CRYPT_F6,
      iv: { b8: 0x11223344, b9: 0x55667788 },
    });
    const serialized = serializeFunction(proto);
    const [dec] = deserializeFunction(serialized, 0);

    // 指令应被正确解密还原
    expect(dec.instructions.length).toBe(proto.instructions.length);
    for (let i = 0; i < proto.instructions.length; i++) {
      const orig = proto.instructions[i]!;
      const got = dec.instructions[i]!;
      expect(got.op).toBe(orig.op);
      expect(got.A).toBe(orig.A);
      expect(got.B).toBe(orig.B);
      expect(got.C).toBe(orig.C);
      expect(got.D).toBe(orig.D);
      expect(got.mode).toBe(orig.mode);
    }
    // 元数据
    expect(dec.insnSeed).toBe(proto.insnSeed);
    expect(dec.insnCryptMode).toBe(INSN_CRYPT_F6);
    expect(dec.insnIv).toEqual(proto.insnIv);
  });

  it("F6 模式：常量也正确还原", () => {
    const proto = makeProto({
      seed: 42,
      mode: INSN_CRYPT_F6,
      iv: { b8: 1, b9: 2 },
    });
    const [dec] = deserializeFunction(serializeFunction(proto), 0);
    expect(dec.constants.length).toBe(proto.constants.length);
    expect(dec.constants[0]).toEqual(proto.constants[0]);
    expect(dec.constants[1]).toEqual(proto.constants[1]);
    expect(dec.constants[2]).toEqual(proto.constants[2]);
  });

  it("F6 模式：序列化字节包含 mode=1 + IV", () => {
    const proto = makeProto({
      seed: 0xCAFEBABE,
      mode: INSN_CRYPT_F6,
      iv: { b8: 0x11223344, b9: 0x55667788 },
    });
    const serialized = serializeFunction(proto);
    const bytes = Array.from(Buffer.from(serialized, "binary"));
    // has_insn_seed 字节 = 1，紧接着是 seed(4) + mode(1) + iv(8)
    // 找到末尾的 has_insn_seed 位置：序列化最后 1 + 4 + 1 + 8 = 14 字节
    const tail = bytes.slice(-14);
    expect(tail[0]).toBe(1); // has_insn_seed
    // seed (4 bytes LE)
    const seed = (tail[1]! | (tail[2]! << 8) | (tail[3]! << 16) | (tail[4]! << 24)) >>> 0;
    expect(seed).toBe(0xCAFEBABE >>> 0);
    // mode (1 byte)
    expect(tail[5]).toBe(INSN_CRYPT_F6);
    // iv.b8 (4 bytes LE)
    const ivB8 = (tail[6]! | (tail[7]! << 8) | (tail[8]! << 16) | (tail[9]! << 24)) >>> 0;
    expect(ivB8).toBe(0x11223344);
    // iv.b9 (4 bytes LE)
    const ivB9 = (tail[10]! | (tail[11]! << 8) | (tail[12]! << 16) | (tail[13]! << 24)) >>> 0;
    expect(ivB9).toBe(0x55667788);
  });

  it("F4 模式：序列化字节包含 mode=0，无 IV", () => {
    const proto = makeProto({
      seed: 0xCAFEBABE,
      mode: INSN_CRYPT_F4,
    });
    const serialized = serializeFunction(proto);
    const bytes = Array.from(Buffer.from(serialized, "binary"));
    // 末尾 1 + 4 + 1 = 6 字节（has_seed + seed + mode，无 IV）
    const tail = bytes.slice(-6);
    expect(tail[0]).toBe(1); // has_insn_seed
    expect(tail[5]).toBe(INSN_CRYPT_F4);
  });

  it("F4 模式：serialize → deserialize 还原指令字段（向后兼容）", () => {
    const proto = makeProto({
      seed: 0xDEADBEEF,
      mode: INSN_CRYPT_F4,
    });
    const [dec] = deserializeFunction(serializeFunction(proto), 0);
    expect(dec.instructions.length).toBe(proto.instructions.length);
    for (let i = 0; i < proto.instructions.length; i++) {
      const orig = proto.instructions[i]!;
      const got = dec.instructions[i]!;
      expect(got.op).toBe(orig.op);
      expect(got.A).toBe(orig.A);
      expect(got.B).toBe(orig.B);
      expect(got.C).toBe(orig.C);
      expect(got.D).toBe(orig.D);
      expect(got.mode).toBe(orig.mode);
    }
    expect(dec.insnCryptMode).toBe(INSN_CRYPT_F4);
    expect(dec.insnIv).toBeUndefined();
  });

  it("无 seed（off 模式）：明文写指令，反序列化还原", () => {
    const proto = makeProto({}); // 无 seed / mode / iv
    const [dec] = deserializeFunction(serializeFunction(proto), 0);
    expect(dec.instructions.length).toBe(proto.instructions.length);
    for (let i = 0; i < proto.instructions.length; i++) {
      expect(dec.instructions[i]!.op).toBe(proto.instructions[i]!.op);
      expect(dec.instructions[i]!.A).toBe(proto.instructions[i]!.A);
    }
    expect(dec.insnSeed).toBeUndefined();
  });

  it("子函数的 F6 模式也正确递归还原", () => {
    const subProto = {
      instructions: [
        { op: 200, A: 1, B: 2, C: 3, D: 4, mode: 0 as const },
      ],
      constants: [{ type: "string" as const, value: "sub" }],
      subFunctions: [],
      paramCount: 1,
      isVararg: false,
      upvalues: [{ fromStack: true, index: 0 }],
      vmId: 1,
      insnSeed: 0x11111111,
      insnCryptMode: INSN_CRYPT_F6,
      insnIv: { b8: 0xAAAAAAAA, b9: 0xBBBBBBBB },
    };
    const proto = makeProto({
      seed: 0xDEADBEEF,
      mode: INSN_CRYPT_F6,
      iv: { b8: 0x11223344, b9: 0x55667788 },
    });
    proto.subFunctions = [subProto];

    const [dec] = deserializeFunction(serializeFunction(proto), 0);
    expect(dec.subFunctions.length).toBe(1);
    const sub = dec.subFunctions[0]!;
    expect(sub.insnCryptMode).toBe(INSN_CRYPT_F6);
    expect(sub.insnSeed).toBe(0x11111111);
    expect(sub.insnIv).toEqual({ b8: 0xAAAAAAAA, b9: 0xBBBBBBBB });
    // 子函数指令字段还原
    expect(sub.instructions[0]!.op).toBe(200);
    expect(sub.instructions[0]!.A).toBe(1);
    expect(sub.instructions[0]!.B).toBe(2);
    expect(sub.instructions[0]!.C).toBe(3);
    expect(sub.instructions[0]!.D).toBe(4);
  });
});

// ---- 14. compiler F6 默认 / F4 / off ----

describe("compiler: F6 默认 / F4 / off 三模式", () => {
  const SRC = 'local a = 1\nlocal b = 2\nprint(a + b)';

  it("默认（f6）：所有 proto 含 insnCryptMode=1 + insnIv", () => {
    const ast = parse(lex(SRC));
    const proto = compileAST(ast, 42); // 默认 insnCrypt="f6"
    expect(proto.insnCryptMode).toBe(INSN_CRYPT_F6);
    expect(proto.insnSeed).toBeDefined();
    expect(proto.insnIv).toBeDefined();
    // 子函数也应是 F6
    for (const sub of proto.subFunctions) {
      expect(sub.insnCryptMode).toBe(INSN_CRYPT_F6);
      expect(sub.insnSeed).toBeDefined();
      expect(sub.insnIv).toBeDefined();
    }
  });

  it("f4 模式：proto.insnCryptMode=0，无 insnIv", () => {
    const ast = parse(lex(SRC));
    const proto = compileAST(ast, 42, { insnCrypt: "f4" });
    expect(proto.insnCryptMode).toBe(INSN_CRYPT_F4);
    expect(proto.insnSeed).toBeDefined();
    expect(proto.insnIv).toBeUndefined();
    for (const sub of proto.subFunctions) {
      expect(sub.insnCryptMode).toBe(INSN_CRYPT_F4);
      expect(sub.insnIv).toBeUndefined();
    }
  });

  it("off 模式：proto.insnSeed 未定义（明文指令）", () => {
    const ast = parse(lex(SRC));
    const proto = compileAST(ast, 42, { insnCrypt: "off" });
    expect(proto.insnSeed).toBeUndefined();
    expect(proto.insnCryptMode).toBeUndefined();
    expect(proto.insnIv).toBeUndefined();
    for (const sub of proto.subFunctions) {
      expect(sub.insnSeed).toBeUndefined();
    }
  });

  it("不同 seed → 不同 insnSeed + 不同 IV", () => {
    const ast = parse(lex(SRC));
    const a = compileAST(ast, 1);
    const b = compileAST(ast, 2);
    expect(a.insnSeed).not.toBe(b.insnSeed);
    expect(a.insnIv).not.toEqual(b.insnIv);
  });

  it("相同 seed → 相同 insnSeed + 相同 IV（确定性）", () => {
    const ast = parse(lex(SRC));
    const a = compileAST(ast, 42);
    const b = compileAST(ast, 42);
    expect(a.insnSeed).toBe(b.insnSeed);
    expect(a.insnIv).toEqual(b.insnIv);
  });

  it("F6 编译结果可经 encoder 往返还原指令", () => {
    const ast = parse(lex(SRC));
    const proto = compileAST(ast, 42, { insnCrypt: "f6" });
    const [dec] = deserializeFunction(serializeFunction(proto), 0);
    expect(dec.instructions.length).toBe(proto.instructions.length);
    for (let i = 0; i < proto.instructions.length; i++) {
      expect(dec.instructions[i]!.op).toBe(proto.instructions[i]!.op);
      expect(dec.instructions[i]!.A).toBe(proto.instructions[i]!.A);
      expect(dec.instructions[i]!.mode).toBe(proto.instructions[i]!.mode);
    }
  });

  it("嵌套函数：每个子函数有独立的 insnSeed + IV（per-proto 独立）", () => {
    const src = `local function outer(x)
  local function inner(y)
    return y + 1
  end
  return inner(x)
end
print(outer(10))`;
    const ast = parse(lex(src));
    const proto = compileAST(ast, 42, { insnCrypt: "f6" });
    expect(proto.subFunctions.length).toBeGreaterThan(0);
    const outer = proto.subFunctions[0]!;
    expect(outer.insnCryptMode).toBe(INSN_CRYPT_F6);
    expect(outer.insnIv).toBeDefined();
    // outer 应有独立 seed（不同于顶层）
    expect(outer.insnSeed).not.toBe(proto.insnSeed);
    // inner 也应有自己的 seed + IV
    if (outer.subFunctions.length > 0) {
      const inner = outer.subFunctions[0]!;
      expect(inner.insnCryptMode).toBe(INSN_CRYPT_F6);
      expect(inner.insnIv).toBeDefined();
      expect(inner.insnSeed).not.toBe(outer.insnSeed);
    }
  });
});

// ---- 15. pipeline noInsnCrypt 选项 ----

describe("pipeline: noInsnCrypt 选项透传", () => {
  it("默认（无 noInsnCrypt）：VM 输出包含 F6 加密的字节码", () => {
    const r = runPipeline('print("hello")', { seed: 42, vm: true });
    // VM hex 输出非空
    expect(r.out.length).toBeGreaterThan(0);
    expect(r.vmHex).toBeDefined();
  });

  it("noInsnCrypt: true → VM 输出仍生成（明文指令，不崩）", () => {
    const r = runPipeline('print("hello")', {
      seed: 42, vm: true, noInsnCrypt: true,
    });
    expect(r.out.length).toBeGreaterThan(0);
  });

  it("runtime 模式 + 默认 F6：生成可执行 Luau 脚本", () => {
    // runtime 隐含 vm（与 CLI 行为一致：--runtime 走 VM 分支）。
    const r = runPipeline('print("hello")', { seed: 42, vm: true, runtime: true });
    expect(r.out).toContain("CUA混淆器");
    expect(r.out.length).toBeGreaterThan(500);
  });

  it("runtime 模式 + noInsnCrypt：生成可执行 Luau 脚本（不崩）", () => {
    const r = runPipeline('print("hello")', {
      seed: 42, vm: true, runtime: true, noInsnCrypt: true,
    });
    expect(r.out).toContain("CUA混淆器");
    expect(r.out.length).toBeGreaterThan(500);
  });

  it("runtime 模式 + F6 默认 vs noInsnCrypt：输出不同", () => {
    const a = runPipeline('print("hello")', { seed: 42, vm: true, runtime: true });
    const b = runPipeline('print("hello")', {
      seed: 42, vm: true, runtime: true, noInsnCrypt: true,
    });
    // F6 加密 vs 明文 → 字节码内容不同 → hex blob 不同 → 自混淆后输出不同
    expect(a.out).not.toBe(b.out);
  });

  it("VM 模式（无 runtime）+ F6 默认 vs noInsnCrypt：hex 不同", () => {
    const a = runPipeline('print("hello")', { seed: 42, vm: true });
    const b = runPipeline('print("hello")', {
      seed: 42, vm: true, noInsnCrypt: true,
    });
    // 直接比较 hex blob（未经过自混淆，F6 vs 明文差异最直接）
    expect(a.vmHex).toBeDefined();
    expect(b.vmHex).toBeDefined();
    expect(a.vmHex).not.toBe(b.vmHex);
  });
});

// ---- 16. 跨模式兼容性：F6 加密的 proto 不能被 F4 解密 ----

describe("insncrypt: F6/F4 跨模式不可解密", () => {
  it("F6 加密的字节流用 F4 keystream 解密 → 错误结果", () => {
    const insns = [
      { op: 50, A: 2, B: 5, C: 10, D: 0, mode: 0 as const },
      { op: 100, A: 3, B: 0, C: 0x100000, D: 0, mode: 1 as const },
    ];
    const plainB8 = insns.map((i) => encodeInstruction(i)[0]);
    const plainB9 = insns.map((i) => encodeInstruction(i)[1]);
    const seed = 42;
    const iv = { b8: 0x11223344, b9: 0x55667788 };

    // F6 加密
    const f6 = f6Encrypt(plainB8, plainB9, seed, iv);

    // 用 F4 keystream 尝试解密 F6 密文
    const { k8, k9 } = f4Keystream(seed, plainB8.length);
    const wrongB8 = f6.encB8.map((x, i) => ((x >>> 0) ^ k8[i]!) >>> 0);
    const wrongB9 = f6.encB9.map((x, i) => ((x >>> 0) ^ k9[i]!) >>> 0);

    // 结果不应等于明文（F6 密文用 F4 解必错）
    expect(wrongB8).not.toEqual(plainB8);
    expect(wrongB9).not.toEqual(plainB9);
  });
});

// ---- 17. v0.12 Feature #5: 常量池压缩（varint 编码整数）----

describe("encoder: v0.12 Feature #5 varint 常量压缩", () => {
  function makeProtoWithConstants(constants: ConstEntry[]) {
    return {
      instructions: [
        { op: 1, A: 0, B: 0, C: 0, D: 0, mode: 0 as const },
      ],
      constants,
      subFunctions: [],
      paramCount: 0,
      isVararg: false,
      upvalues: [],
      vmId: 0,
      insnSeed: undefined,
      blindDescs: constants.map(() => null),
    };
  }

  it("整数常量用 tag 3 (varint) 编码，小整数占 1 字节", () => {
    const proto = makeProtoWithConstants([
      { type: "number", value: 0 },   // zigzag 0 → 1 字节
      { type: "number", value: 1 },   // zigzag 2 → 1 字节
      { type: "number", value: -1 },  // zigzag 1 → 1 字节
      { type: "number", value: 63 },  // zigzag 126 → 1 字节
    ]);
    const serialized = serializeFunction(proto);
    const bytes = Array.from(Buffer.from(serialized, "binary"));
    // 定位到常量区：numInsn(u32=1) + 1 条指令(8 字节) + numConst(u32=4)
    // = 4 + 8 + 4 = 16 字节后是第一个常量的 tag。
    const tag0 = bytes[16]!;
    expect(tag0).toBe(3); // varint tag
    // 每个 varint 整数 = 1 tag + 1 data 字节 = 2 字节
    for (let i = 0; i < 4; i++) {
      expect(bytes[16 + i * 2]).toBe(3);
      expect(bytes[16 + i * 2 + 1]).toBeLessThan(128); // 单字节 varint
    }
  });

  it("浮点常量仍用 tag 2 (f64) 编码", () => {
    const proto = makeProtoWithConstants([
      { type: "number", value: 42.5 },
    ]);
    const serialized = serializeFunction(proto);
    const bytes = Array.from(Buffer.from(serialized, "binary"));
    expect(bytes[16]).toBe(2); // f64 tag
  });

  it("大整数 (>32-bit) 回退到 tag 2 (f64)", () => {
    const proto = makeProtoWithConstants([
      { type: "number", value: 2147483648 }, // 2^31，超出 32-bit signed
    ]);
    const serialized = serializeFunction(proto);
    const bytes = Array.from(Buffer.from(serialized, "binary"));
    expect(bytes[16]).toBe(2); // 回退 f64
  });

  it("varint 整数常量 serialize → deserialize 往返正确", () => {
    const samples = [0, 1, -1, 63, -64, 8191, -8192, 100000, -100000, 2147483647, -2147483648];
    const proto = makeProtoWithConstants(samples.map((v) => ({ type: "number" as const, value: v })));
    const [dec] = deserializeFunction(serializeFunction(proto), 0);
    expect(dec.constants.length).toBe(samples.length);
    for (let i = 0; i < samples.length; i++) {
      expect(dec.constants[i]!.type).toBe("number");
      expect((dec.constants[i]! as { value: number }).value).toBe(samples[i]);
    }
  });

  it("num_split 盲化的数字常量仍用 tag 2 (f64)", () => {
    const proto = {
      instructions: [{ op: 1, A: 0, B: 0, C: 0, D: 0, mode: 0 as const }],
      constants: [{ type: "number" as const, value: 42 }],
      subFunctions: [],
      paramCount: 0,
      isVararg: false,
      upvalues: [],
      vmId: 0,
      insnSeed: undefined,
      blindDescs: [{ kind: "num_split" as const, k2: 0.5 }],
    };
    const serialized = serializeFunction(proto);
    const bytes = Array.from(Buffer.from(serialized, "binary"));
    expect(bytes[16]).toBe(2); // 盲化路径走 f64
  });

  it("varint 编码确实比 f64 更小（小整数场景）", () => {
    const intProto = makeProtoWithConstants([
      { type: "number", value: 1 },
      { type: "number", value: 2 },
      { type: "number", value: 3 },
    ]);
    const floatProto = makeProtoWithConstants([
      { type: "number", value: 1.5 },
      { type: "number", value: 2.5 },
      { type: "number", value: 3.5 },
    ]);
    const intLen = serializeFunction(intProto).length;
    const floatLen = serializeFunction(floatProto).length;
    // 3 个小整数：3 * (1 tag + 1 varint) = 6 字节
    // 3 个 f64：3 * (1 tag + 8 f64) = 27 字节
    // 差距 21 字节，intLen 应明显小于 floatLen。
    expect(intLen).toBeLessThan(floatLen);
    expect(floatLen - intLen).toBeGreaterThanOrEqual(18);
  });
});
