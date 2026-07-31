// tests/rtdeps.test.ts — v0.10 rt_deps 层测试。
// 验证：rt_mix 加解密往返、rt_token 派生一致性、keyfuse 运行时 nibble、模板 marker。
import { describe, it, expect } from "vitest";
import {
  deriveRtToken,
  rtTokenToNibbles,
  rtMixEncrypt,
  rtMixDecrypt,
} from "../src/vm/rtdeps.js";
import {
  deriveKeyfuseKey,
  genKeyfuseAssembly,
  computeKeyfuseKhSize,
  KEYFUSE_NIBBLES,
} from "../src/vm/keyfuse.js";
import { buildRuntime } from "../src/vm/runtime-template.js";
import { DEFAULT_RUNTIME_PROTECT } from "../src/vm/memory.js";
import { runPipeline } from "../src/pipeline/obfuscate.js";
import { compileVMWithRuntime } from "../src/vm/pipeline.js";
import { parse } from "../src/parser/parser.js";
import { lex } from "../src/parser/lexer.js";

describe("rtdeps: rt_mix roundtrip", () => {
  it("encrypt → decrypt = identity for various data", () => {
    const samples = ["", "x", "hello world", "\x00\x01\x02\xFF", "a".repeat(500)];
    const token = 0x12345678;
    for (const s of samples) {
      const enc = rtMixEncrypt(s, token);
      const dec = rtMixDecrypt(enc, token);
      expect(dec).toBe(s);
    }
  });

  it("different tokens produce different ciphertext", () => {
    const data = "sensitive bytecode payload";
    const enc1 = rtMixEncrypt(data, 0x11111111);
    const enc2 = rtMixEncrypt(data, 0x22222222);
    expect(enc1).not.toBe(enc2);
    expect(enc1).not.toBe(data);
    expect(enc2).not.toBe(data);
  });

  it("preserves length", () => {
    const data = "a".repeat(100);
    const enc = rtMixEncrypt(data, 42);
    expect(enc.length).toBe(data.length);
  });

  it("Lua formula matches TS: (token + i*31 + 7) % 256, 1-indexed", () => {
    // 模拟 Lua rt_mix_decrypt 的逐字节逻辑，验证与 TS rtMixEncrypt 互补。
    function luaRtMixDecrypt(data: string, token: number): string {
      let out = "";
      for (let i = 1; i <= data.length; i++) {
        const k = (token + i * 31 + 7) % 256;
        const b = data.charCodeAt(i - 1);
        let p = b - k;
        if (p < 0) p += 256;
        out += String.fromCharCode(p);
      }
      return out;
    }
    const data = "test payload with various \x00\xFF bytes";
    const token = 0xDEADBEEF;
    const enc = rtMixEncrypt(data, token);
    const dec = luaRtMixDecrypt(enc, token);
    expect(dec).toBe(data);
  });
});

describe("rtdeps: rt_token derivation", () => {
  it("deterministic: same inputs → same token", () => {
    const a = deriveRtToken(240, 172);
    const b = deriveRtToken(240, 172);
    expect(a).toBe(b);
  });

  it("different hexLen → different token", () => {
    expect(deriveRtToken(100, 172)).not.toBe(deriveRtToken(200, 172));
  });

  it("different khSize → different token", () => {
    expect(deriveRtToken(240, 172)).not.toBe(deriveRtToken(240, 200));
  });

  it("matches keyfuse khSize computation", () => {
    const khSize = computeKeyfuseKhSize();
    const decoyCount = Math.max(4, Math.floor(KEYFUSE_NIBBLES * 0.35));
    expect(khSize).toBe(KEYFUSE_NIBBLES + decoyCount);
  });

  it("rtTokenToNibbles extracts bits 4-7 and 8-11", () => {
    const token = 0x00000BA0; // bits 4-7 = 0xA, bits 8-11 = 0xB
    const [n126, n127] = rtTokenToNibbles(token);
    expect(n126).toBe(0xA);
    expect(n127).toBe(0xB);
  });
});

describe("rtdeps: keyfuse with runtime nibbles", () => {
  it("rtToken=null: all 128 nibbles from _kh (v0.9 behavior)", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const kf = genKeyfuseAssembly(keyHex, 42, 0.35, null);
    // _rt_tok 不应出现
    expect(kf.assemblyCode).not.toContain("_rt_tok");
    // 128 个真实 case 都走 _kh
    const khCases = (kf.assemblyCode.match(/_kh\[_B/g) || []).length;
    expect(khCases).toBeGreaterThanOrEqual(KEYFUSE_NIBBLES);
  });

  it("rtToken set: _rt_tok present, 2 cases read from it", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const hexLen = 240;
    const khSize = computeKeyfuseKhSize();
    const rtToken = deriveRtToken(hexLen, khSize);
    const kf = genKeyfuseAssembly(keyHex, 42, 0.35, rtToken);
    // _rt_tok 定义 + 派生公式
    expect(kf.assemblyCode).toContain("_rt_tok");
    expect(kf.assemblyCode).toContain("2654435761");
    expect(kf.assemblyCode).toContain("16777619");
    // 2 个 case 从 _rt_tok 读（shift 4 和 shift 8）
    expect(kf.assemblyCode).toContain("math.floor(_rt_tok / 16) % 16");
    expect(kf.assemblyCode).toContain("math.floor(_rt_tok / 256) % 16");
    // _rt_tok 不在装配段销毁（由 vm_boot 负责）
    expect(kf.assemblyCode.trim().split("\n").pop()).not.toContain("_rt_tok = nil");
  });

  it("rtToken set: _kh still has 128+decoy slots (decoy fills nibbles 126/127)", () => {
    const { keyHex } = deriveKeyfuseKey(99);
    const rtToken = deriveRtToken(300, computeKeyfuseKhSize());
    const kf = genKeyfuseAssembly(keyHex, 99, 0.35, rtToken);
    // _kh 表项数 = 128 + decoyCount
    const khEntries = (kf.assemblyCode.match(/^\s+\d+,/gm) || []).length;
    expect(khEntries).toBe(computeKeyfuseKhSize());
  });
});

describe("rtdeps: runtime template markers", () => {
  const SAMPLE_HEX = "A1B2C3D4E5F6".repeat(20);

  function allMarkers(s: string): string[] {
    return (s.match(/__\w+_(?:BEGIN|END)__/g) || []) as string[];
  }

  it("rt_deps ON (keyfuse ON): rt_mix_decrypt + _rt_tok step present, no markers", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const out = buildRuntime(SAMPLE_HEX, 42, { ...DEFAULT_RUNTIME_PROTECT, keyfuse: true, rtDeps: true }, 42, keyHex);
    expect(allMarkers(out)).toEqual([]);
    expect(out).toContain("rt_mix_decrypt");
    expect(out).toContain("_rt_tok");
    expect(out).toContain("math.floor(_rt_tok");
    expect(out).toContain("secure_nil(_rt_tok)");
  });

  it("rt_deps OFF (keyfuse ON): rt_mix absent, keyfuse intact, no markers", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const out = buildRuntime(SAMPLE_HEX, 42, { ...DEFAULT_RUNTIME_PROTECT, keyfuse: true, rtDeps: false }, 42, keyHex);
    expect(allMarkers(out)).toEqual([]);
    expect(out).not.toContain("rt_mix_decrypt");
    expect(out).not.toContain("_rt_tok");
    expect(out).not.toContain("secure_nil(_rt_tok)");
    // keyfuse 仍然存在
    expect(out).toContain("xor_bytes_512");
    expect(out).toContain("_kh");
  });

  it("keyfuse OFF: rt_deps silently disabled, no rt_mix / keyfuse code", () => {
    const out = buildRuntime(SAMPLE_HEX, 42, { ...DEFAULT_RUNTIME_PROTECT, keyfuse: false, rtDeps: true }, 42, null);
    expect(allMarkers(out)).toEqual([]);
    expect(out).not.toContain("rt_mix_decrypt");
    expect(out).not.toContain("xor_bytes_512");
    expect(out).not.toContain("_kh");
    expect(out).not.toContain("_rt_tok");
  });
});

describe("rtdeps: end-to-end pipeline (pre-self-obfuscation)", () => {
  // compileVMWithRuntime 返回自混淆前的运行时源码，可检查标识符。
  // runPipeline 会对运行时模板再跑 D1-D3，标识符会被重命名。
  const SRC = 'print("hello rt_deps")';

  function compileFromSrc(src: string, seed: number, opts: Record<string, boolean>): string {
    const ast = parse(lex(src));
    return compileVMWithRuntime(ast, seed, {
      memwipe: true, antidump: true, frag: true,
      keyfuse: !opts.noKeyfuse, dynamicAntidump: true, rtDeps: !opts.noRtDeps,
    });
  }

  it("rt_deps ON: pre-obf output has rt_mix_decrypt + _rt_tok", () => {
    const rt = compileFromSrc(SRC, 42, {});
    expect(rt).toContain("rt_mix_decrypt");
    expect(rt).toContain("_rt_tok");
    expect(rt).toContain("math.floor(_rt_tok");
    expect(rt).toContain("secure_nil(_rt_tok)");
  });

  it("rt_deps OFF: pre-obf output lacks rt_mix, keyfuse intact", () => {
    const rt = compileFromSrc(SRC, 42, { noRtDeps: true });
    expect(rt).not.toContain("rt_mix_decrypt");
    expect(rt).not.toContain("_rt_tok");
    expect(rt).toContain("xor_bytes_512");
    expect(rt).toContain("_kh");
  });

  it("keyfuse OFF: no rt_mix or keyfuse code", () => {
    const rt = compileFromSrc(SRC, 42, { noKeyfuse: true });
    expect(rt).not.toContain("rt_mix_decrypt");
    expect(rt).not.toContain("xor_bytes_512");
    expect(rt).not.toContain("_rt_tok");
  });

  it("different seeds → different rt_mix ciphertext (different hexLen → different token)", () => {
    const a = compileFromSrc(SRC, 1, {});
    const b = compileFromSrc(SRC, 999, {});
    // 两者都含 rt_mix，但 token 不同 → 密文不同 → HEX_BLOB 内容不同
    expect(a).toContain("rt_mix_decrypt");
    expect(b).toContain("rt_mix_decrypt");
    expect(a).not.toBe(b);
  });

  it("full runPipeline (with self-obfuscation) doesn't crash and produces output", () => {
    const { out } = runPipeline(SRC, { seed: 42, runtime: true });
    expect(out.length).toBeGreaterThan(100);
    // 自混淆后标识符被重命名，但水印仍在
    expect(out).toContain("CUA混淆器");
  });
});
