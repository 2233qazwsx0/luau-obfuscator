// tests/keyfuse.test.ts — v0.9 keyfuse: 512 位密钥深度融合测试。
import { describe, it, expect } from "vitest";
import {
  deriveKeyfuseKey,
  xor512,
  genKeyfuseAssembly,
  KEYFUSE_KEY_HEX_LEN,
  KEYFUSE_NIBBLES,
} from "../src/vm/keyfuse.js";
import {
  packBytecode,
  packBytecodeKeyfused,
  unpackBytecodeKeyfused,
} from "../src/vm/packer.js";

/** 把任意字符串转成二进制串（LZW 期望 0..255 字节序列，非 Unicode 码点）。 */
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

  // 解析所有 case：stateId → (i, nextState)。真实 case 与死分支 case 结构相同。
  // 真实 case: __kf_b == SID then KEY = KEY .. fmt(_kh[_B(I, _kk) + 1] % 16) __kf_b = NEXT
  // 死分支 case 结构相同。exit case: __kf_b == SID then break
  const caseRe =
    /__kf_b == (\d+) then\s*\n\s*KEY = KEY \.\. string\.format\("%X", _kh\[_B\((\d+), _kk\) \+ 1\] % 16\)\s*\n\s*__kf_b = (\d+)/g;
  const exitRe = /__kf_b == (\d+) then\s*\n\s*break/;
  const cases = new Map<number, { i: number; next: number }>();
  let m: RegExpExecArray | null;
  while ((m = caseRe.exec(code)) !== null) {
    cases.set(Number(m[1]), { i: Number(m[2]), next: Number(m[3]) });
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
    // Lua: _kh[_B(i, _kk) + 1] → 1-based → JS 索引 _B(i,kk) (0-based)。
    const slot = _B(c.i, kk); // 0-based 索引进 khValues
    const val = khValues[slot]!;
    const nibble = val % 16;
    key += nibble.toString(16).toUpperCase();
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
    // 直接 LZW+stream pack（无 XOR 外层）应不同。
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
  it("emits exactly 128 real cases + decoy cases + 1 exit", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    // 真实 case 数 = KEYFUSE_NIBBLES (128)；死分支 case 数 >= 4（decoyCount）。
    const realCaseCount = (kf.assemblyCode.match(/KEY = KEY \.\. string\.format/g) || []).length;
    expect(realCaseCount).toBeGreaterThanOrEqual(KEYFUSE_NIBBLES); // 128 真实 + 死分支
    // exit case 恰好 1 个。
    const exitCount = (kf.assemblyCode.match(/break/g) || []).length;
    expect(exitCount).toBe(1);
    // _B() 索引混淆存在。
    expect(kf.assemblyCode).toContain("_B(");
    // dispatch loop 存在。
    expect(kf.assemblyCode).toContain("while true do");
  });

  it("decoy fragments use the same structure as real fragments", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    // 所有 case（真实 + 死分支）都应匹配相同的 KEY = KEY .. string.format 模式。
    const allCases = kf.assemblyCode.match(
      /__kf_b == \d+ then\s*\n\s*KEY = KEY \.\. string\.format\("%X", _kh\[_B\(\d+, _kk\) \+ 1\] % 16\)\s*\n\s*__kf_b = \d+/g,
    );
    expect(allCases).not.toBeNull();
    expect(allCases!.length).toBeGreaterThanOrEqual(KEYFUSE_NIBBLES);
  });

  it("cleanup nils _kh, _kk, __kf_b after assembly", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42);
    expect(kf.assemblyCode).toContain("_kh = nil");
    expect(kf.assemblyCode).toContain("_kk = nil");
    expect(kf.assemblyCode).toContain("__kf_b = nil");
  });
});
