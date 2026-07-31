// tests/keyfuse.test.ts — v0.9 keyfuse: 512 位密钥深度融合测试。
import { describe, it, expect } from "vitest";
import {
  deriveKeyfuseKey,
  xor512,
  genKeyfuseAssembly,
  KEYFUSE_KEY_HEX_LEN,
  KEYFUSE_NIBBLES,
  KEYFUSE_REAL_CASES,
  KEYFUSE_CHUNK_NIBBLES,
} from "../src/vm/keyfuse.js";
import {
  packBytecode,
  packBytecodeKeyfused,
  unpackBytecodeKeyfused,
  unpackBytecode,
} from "../src/vm/packer.js";
import { buildRuntime } from "../src/vm/runtime-template.js";
import { DEFAULT_RUNTIME_PROTECT } from "../src/vm/memory.js";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

/** 把任意字符串转成二进制串（stream cipher 期望 0..255 字节序列，非 Unicode 码点）。 */
function toBinary(s: string): string {
  return Buffer.from(s, "utf8").toString("binary");
}

/** 模拟运行时 _B(a,b) = a XOR b（与 bit32_polyfill 对齐）。 */
function _B(a: number, b: number): number {
  return (a ^ b) >>> 0;
}

/**
 * 解析 genKeyfuseAssembly 生成的 assemblyCode 并模拟 dispatch loop 执行，
 * 验证装配出的 KEY == keyHex。这是最关键的端到端正确性检查：
 * 如果 dispatch loop 逻辑、_B() 索引、state 转移有任何错误，KEY 会错。
 *
 * v0.8：每个真实 case 一次装配 16 个 nibble（8 字节），不再逐 nibble 一个 case。
 * 模拟器需从 string.format 行提取 16 个 _B(N, _kk) 索引，逐个查 _kh 拼出 nibble。
 */
function simulateAssembly(keyHex: string, seed: number): string {
  const kf = genKeyfuseAssembly(keyHex, seed);
  const code = kf.assemblyCode;

  // 解析 _kh 表。
  const khMatch = code.match(/local _kh = \{([\s\S]*?)\}/);
  expect(khMatch).not.toBeNull();
  const khValues: number[] = khMatch![1]
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => Number(s));
  // khValues 是 0-based 数组（Lua 1-based → 这里直接用，索引时 +1 对应）。

  // 解析 _kk。
  const kkMatch = code.match(/local _kk = (\d+)/);
  expect(kkMatch).not.toBeNull();
  const kk = Number(kkMatch![1]);

  // 解析初始 state。
  const initMatch = code.match(/local __kf_b = (\d+)/);
  expect(initMatch).not.toBeNull();
  let curState = Number(initMatch![1]);

  // 解析所有 case：stateId → (nibblePositions[], nextState)。
  // v0.8 case body: KEY = KEY .. string.format("%X...%X", _kh[_B(N0, _kk) + 1] % 16, ..., _kh[_B(N15, _kk) + 1] % 16)
  // 从 string.format 行提取所有 _B(N, _kk) 中的 N 值。
  const caseRe =
    /__kf_b == (\d+) then\s*\n\s*KEY = KEY \.\. string\.format\("[^"]*",\s*([^\n]+)\)\s*\n\s*__kf_b = (\d+)/g;
  const exitRe = /__kf_b == (\d+) then\s*\n\s*break/;
  const cases = new Map<number, { nibblePositions: number[]; next: number }>();
  let m: RegExpExecArray | null;
  while ((m = caseRe.exec(code)) !== null) {
    const sid = Number(m[1]);
    const exprsStr = m[2];
    const next = Number(m[3]);
    // 提取所有 _B(N, _kk) 中的 N 值（_kh 查找路径）。
    const positions: number[] = [];
    const exprRe = /_B\((\d+), _kk\)/g;
    let em: RegExpExecArray | null;
    while ((em = exprRe.exec(exprsStr)) !== null) {
      positions.push(Number(em[1]));
    }
    cases.set(sid, { nibblePositions: positions, next });
  }
  const exitMatch = code.match(exitRe);
  expect(exitMatch).not.toBeNull();
  const exitState = Number(exitMatch![1]);

  // 模拟 dispatch loop：从 curState 出发，跟踪可达 case，拼 KEY。
  // 注意：死分支 case 的 state 永不可达（无转移目标命中），故不会被执行。
  let key = "";
  let steps = 0;
  const visited = new Set<number>();
  while (curState !== exitState) {
    if (visited.has(curState)) {
      throw new Error(`simulate: state ${curState} revisited (cycle)`);
    }
    visited.add(curState);
    const c = cases.get(curState);
    if (!c) {
      throw new Error(`simulate: no case for state ${curState}`);
    }
    // 每 case 16 个 nibble 位置（v0.8 压缩：8 字节 / case）。
    for (const nibblePos of c.nibblePositions) {
      // Lua: _kh[_B(i, _kk) + 1] → 1-based → JS 索引 _B(i,kk) (0-based)。
      const slot = _B(nibblePos, kk); // 0-based 索引进 khValues
      const val = khValues[slot]!;
      const nibble = val % 16;
      key += nibble.toString(16).toUpperCase();
    }
    curState = c.next;
    if (++steps > 10000) throw new Error("simulate: too many steps");
  }
  return key;
}

describe("keyfuse: 512-bit key derivation", () => {
  it("produces a 128-hex-char key (512 bits)", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    expect(keyHex.length).toBe(KEYFUSE_KEY_HEX_LEN);
    expect(keyHex).toMatch(/^[0-9A-F]{128}$/);
  });

  it("is deterministic for the same seed", () => {
    expect(deriveKeyfuseKey(42).keyHex).toBe(deriveKeyfuseKey(42).keyHex);
  });

  it("produces different keys for different seeds", () => {
    expect(deriveKeyfuseKey(1).keyHex).not.toBe(deriveKeyfuseKey(2).keyHex);
  });

  it("keyBytes length is 64", () => {
    expect(deriveKeyfuseKey(42).keyBytes.length).toBe(64);
  });
});

describe("keyfuse: xor512 round-trip", () => {
  it("encrypt then decrypt returns the original (binary strings)", () => {
    // xor512 设计上只处理二进制串（每 char 一个字节，与 packer.xor512Outer
    // 用法对齐）。Unicode 串需先转二进制再 XOR。
    const { keyBytes } = deriveKeyfuseKey(42);
    const samples = [
      "hello",
      "",
      "a",
      "x".repeat(1000),
      toBinary("中文测试 🔥"),
    ];
    for (const s of samples) {
      const enc = xor512(s, keyBytes);
      const dec = xor512(enc, keyBytes);
      expect(dec).toBe(s);
    }
  });

  it("produces different output for different keys", () => {
    const k1 = deriveKeyfuseKey(1).keyBytes;
    const k2 = deriveKeyfuseKey(2).keyBytes;
    const data = "test data for xor";
    expect(xor512(data, k1)).not.toBe(xor512(data, k2));
  });
});

describe("keyfuse: pack/unpack with 512-bit outer layer", () => {
  it("packBytecodeKeyfused → unpackBytecodeKeyfused round-trip", () => {
    const { keyBytes } = deriveKeyfuseKey(42);
    const cipherKey = 123;
    const samples = [
      "hello world",
      "中文测试",
      JSON.stringify({ a: 1, b: [2, 3] }),
      "x".repeat(500),
    ];
    for (const s of samples) {
      const bin = toBinary(s);
      const hex = packBytecodeKeyfused(bin, cipherKey, keyBytes, true);
      const dec = unpackBytecodeKeyfused(hex, cipherKey, keyBytes, true);
      expect(dec).toBe(bin);
    }
  });

  it("differs from non-keyfused packing (outer XOR changes output)", () => {
    const { keyBytes } = deriveKeyfuseKey(42);
    const cipherKey = 123;
    const data = toBinary("same input data");
    const kfHex = packBytecodeKeyfused(data, cipherKey, keyBytes, true);
    // 直接 stream pack（无 XOR 外层）应不同。
    const plainHex = packBytecode(data, cipherKey, true);
    expect(kfHex).not.toBe(plainHex);
  });
});

describe("keyfuse: assembly dispatch loop reconstructs the key", () => {
  it("simulated runtime assembly produces keyHex (seed 42)", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const reconstructed = simulateAssembly(keyHex, 42);
    expect(reconstructed).toBe(keyHex);
  });

  it("simulated runtime assembly produces keyHex (multiple seeds)", () => {
    for (const seed of [1, 7, 42, 999, 54321, 88888]) {
      const { keyHex } = deriveKeyfuseKey(seed);
      const reconstructed = simulateAssembly(keyHex, seed);
      expect(reconstructed).toBe(keyHex);
    }
  });

  it("real-fused hosts carry the first two nibbles", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    // realFusedCode 包含 _rf1 / _rf2 定义，其 % 16 == nibbles[0]/nibbles[1]。
    const rf1Match = kf.realFusedCode.match(/local _rf1 = (\d+)/);
    const rf2Match = kf.realFusedCode.match(/local _rf2 = (\d+)/);
    expect(rf1Match).not.toBeNull();
    expect(rf2Match).not.toBeNull();
    const rf1 = Number(rf1Match![1]);
    const rf2 = Number(rf2Match![1]);
    const n0 = parseInt(keyHex[0]!, 16);
    const n1 = parseInt(keyHex[1]!, 16);
    expect(rf1 % 16).toBe(n0);
    expect(rf2 % 16).toBe(n1);
  });
});

describe("keyfuse: two obfuscations differ (verification standard)", () => {
  it("different seeds → different host values, state IDs, fragment positions", () => {
    const { keyHex: k1 } = deriveKeyfuseKey(1);
    const { keyHex: k2 } = deriveKeyfuseKey(2);
    const a = genKeyfuseAssembly(k1, 1);
    const b = genKeyfuseAssembly(k2, 2);
    // 装配代码整体不同（宿主值 + state ID + 物理 case 顺序均由 seed 决定）。
    expect(a.assemblyCode).not.toBe(b.assemblyCode);
    // 真实融合宿主值不同（因密钥不同）。
    expect(a.realFusedCode).not.toBe(b.realFusedCode);
    // _kh 表内容不同。
    expect(a.assemblyCode).not.toContain(b.assemblyCode.slice(0, 200));
  });

  it("same seed → same assembly (deterministic)", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const a = genKeyfuseAssembly(keyHex, 42);
    const b = genKeyfuseAssembly(keyHex, 42);
    expect(a.assemblyCode).toBe(b.assemblyCode);
    expect(a.realFusedCode).toBe(b.realFusedCode);
  });
});

describe("keyfuse: structure invariants", () => {
  it("emits 8 real cases + decoy cases + 1 exit (v0.8 compressed)", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    // v0.8: 真实 case 数 = KEYFUSE_REAL_CASES (8)；死分支 case 数 >= 8。
    // 总 case 数（含 string.format）= 8 真实 + numDecoyCases 死分支，落在 30-50 区间。
    const formatCount = (kf.assemblyCode.match(/KEY = KEY \.\. string\.format/g) || []).length;
    expect(formatCount).toBeGreaterThanOrEqual(KEYFUSE_REAL_CASES); // 8 真实 + 死分支
    expect(formatCount).toBeGreaterThanOrEqual(30); // v0.8 目标：30-50 case
    expect(formatCount).toBeLessThanOrEqual(50);
    // exit case 恰好 1 个。
    const exitCount = (kf.assemblyCode.match(/break/g) || []).length;
    expect(exitCount).toBe(1);
    // _B() 索引混淆存在。
    expect(kf.assemblyCode).toContain("_B(");
    // dispatch loop 存在。
    expect(kf.assemblyCode).toContain("while true do");
  });

  it("each real case assembles 16 nibbles (8 bytes) via string.format", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    // v0.8: 每 case 的 format 字符串含 16 个 %X（8 字节 / case）。
    // 提取所有 string.format 调用的 format 字符串部分。
    const fmtMatches = kf.assemblyCode.match(/string\.format\("[^"]*"/g) || [];
    expect(fmtMatches.length).toBeGreaterThanOrEqual(KEYFUSE_REAL_CASES);
    for (const fm of fmtMatches) {
      const xCount = (fm.match(/%X/g) || []).length;
      expect(xCount).toBe(KEYFUSE_CHUNK_NIBBLES); // 16
    }
  });

  it("decoy fragments use the same structure as real fragments", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    // v0.8: 所有 case（真实 + 死分支）都应匹配相同的 KEY = KEY .. string.format 模式。
    // string.format 调用整行在同一行，用 [^\n]+ 匹配表达式部分。
    const allCases = kf.assemblyCode.match(
      /__kf_b == \d+ then\s*\n\s*KEY = KEY \.\. string\.format\([^\n]+\n\s*__kf_b = \d+/g,
    );
    expect(allCases).not.toBeNull();
    expect(allCases!.length).toBeGreaterThanOrEqual(KEYFUSE_REAL_CASES);
  });

  it("cleanup nils _kh, _kk, __kf_b after assembly", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    expect(kf.assemblyCode).toContain("_kh = nil");
    expect(kf.assemblyCode).toContain("_kk = nil");
    expect(kf.assemblyCode).toContain("__kf_b = nil");
  });
});

describe("v0.8 性能修复：keyfuse 装配 + 解密链 benchmark", () => {
  // v0.8 目标：SANA HUB 500 行脚本混淆后在 Roblox 中 5 秒内完成加载执行。
  // 此 benchmark 验证关键瓶颈已消除：
  //   1. dispatch case 数 30-50（v0.7 为 300+）
  //   2. 运行时模板无 lzw_decode 函数（bi 层去重）
  //   3. keyfuse 装配生成 < 50ms（代码生成，非运行时）
  //   4. 模拟 dispatch loop 执行 < 5ms（8 case vs 128 case）
  //   5. 解密链 stream cipher 往返无 LZW

  it("dispatch case 总数在 30-50 范围（v0.7 为 300+）", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    // 真实 case (8) + 死分支 case (>=8) + exit (1) = 总 elseif/if 分支
    const caseCount = (kf.assemblyCode.match(/__kf_b == \d+ then/g) || []).length;
    expect(caseCount).toBeGreaterThanOrEqual(30);
    expect(caseCount).toBeLessThanOrEqual(50);
  });

  it("运行时模板不含 lzw_decode 函数定义/调用（bi 层去重）", () => {
    const templatePath = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../runtime/vm-runtime.template.lua",
    );
    const template = fs.readFileSync(templatePath, "utf8");
    // 注释中提到 lzw_decode 是历史说明，实际函数定义/调用不应存在。
    expect(template).not.toMatch(/function\s+lzw_decode/);
    expect(template).not.toMatch(/[^_a-zA-Z]lzw_decode\s*\(/);
    // stream_decrypt 仍保留（XOR 变换，开销可忽略）。
    expect(template).toContain("stream_decrypt");
  });

  it("生成的运行时源码不含 lzw_decode 调用", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const runtime = buildRuntime(
      "A1B2C3D4".repeat(30),
      42,
      { ...DEFAULT_RUNTIME_PROTECT, keyfuse: true, rtDeps: true },
      42,
      keyHex,
    );
    expect(runtime).not.toMatch(/function\s+lzw_decode/);
    expect(runtime).not.toMatch(/[^_a-zA-Z]lzw_decode\s*\(/);
    // 解密链：stream_decrypt → (无 LZW) → serialized
    expect(runtime).toContain("stream_decrypt");
  });

  it("keyfuse 装配生成耗时 < 50ms（多 seed 平均）", () => {
    const seeds = [1, 42, 100, 999, 54321];
    const start = performance.now();
    for (const seed of seeds) {
      const { keyHex } = deriveKeyfuseKey(seed);
      genKeyfuseAssembly(keyHex, seed);
    }
    const elapsed = performance.now() - start;
    const avgPerSeed = elapsed / seeds.length;
    expect(avgPerSeed).toBeLessThan(50);
  });

  it("模拟 dispatch loop 执行 < 5ms（8 case vs v0.7 128+ case）", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const start = performance.now();
    const result = simulateAssembly(keyHex, 42);
    const elapsed = performance.now() - start;
    expect(result).toBe(keyHex); // 正确性
    expect(elapsed).toBeLessThan(5); // 性能
  });

  it("解密链 stream cipher 往返无 LZW（pack → unpack = identity）", () => {
    const cipherKey = 200;
    const samples = [
      "hello",
      "x".repeat(500),
      toBinary("SANA HUB 测试"),
    ];
    for (const s of samples) {
      // v0.8: packBytecode 仅 stream encrypt + hex（无 LZW）。
      const hex = packBytecode(s, cipherKey);
      const dec = unpackBytecode(hex, cipherKey);
      expect(dec).toBe(s);
    }
  });
});
