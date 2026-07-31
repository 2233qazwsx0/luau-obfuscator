// tests/runtime-template.test.ts — Verify runtime template marker handling.
// Leaking markers = broken Lua. These tests ensure protection toggles produce
// syntactically valid marker-free output.
import { describe, it, expect } from "vitest";
import { buildRuntime } from "../src/vm/runtime-template.js";
import { DEFAULT_RUNTIME_PROTECT } from "../src/vm/memory.js";
import { deriveKeyfuseKey } from "../src/vm/keyfuse.js";

const SAMPLE_HEX = "A1B2C3D4E5F6".repeat(20);

// Region markers always end in _BEGIN__ or _END__. Plain placeholders like
// __HEX_BLOB__ / __CIPHER_KEY__ in doc comments are NOT markers and don't break
// Lua, so we only flag actual region markers that would split a string literal
// if they leaked into output.
function allMarkers(s: string): string[] {
  return (s.match(/__\w+_(?:BEGIN|END)__/g) || []) as string[];
}

describe("runtime template: dynamic anti-dump markers", () => {
  it("dynamic ON: no markers leak, anti_dump_dynamic + periodic call present", () => {
    const out = buildRuntime(SAMPLE_HEX, 42, { ...DEFAULT_RUNTIME_PROTECT, dynamicAntidump: true }, 7, null);
    expect(allMarkers(out)).toEqual([]);
    expect(out).toContain("anti_dump_dynamic");
    expect(out).toContain("__ad_cnt");
    expect(out).toContain('error("__ad")');
    // 3 dynamic checks present (timing / hook / env)
    expect(out).toContain("os.clock");
    expect(out).toContain("debug.sethook");
    expect(out).toContain("g.string");
  });

  it("dynamic OFF: no markers leak, anti_dump_dynamic absent, periodic call absent", () => {
    const out = buildRuntime(SAMPLE_HEX, 42, { ...DEFAULT_RUNTIME_PROTECT, dynamicAntidump: false }, 7, null);
    expect(allMarkers(out)).toEqual([]);
    expect(out).not.toContain("anti_dump_dynamic");
    expect(out).not.toContain("__ad_cnt");
    expect(out).not.toContain('error("__ad")');
    // Original static checks still present
    expect(out).toContain("anti_dump_check");
    expect(out).toContain("hookfunction");
  });

  it("antidump OFF: no anti-dump code at all", () => {
    const out = buildRuntime(SAMPLE_HEX, 42, { ...DEFAULT_RUNTIME_PROTECT, antidump: false, dynamicAntidump: true }, 7, null);
    expect(allMarkers(out)).toEqual([]);
    expect(out).not.toContain("anti_dump_check");
    expect(out).not.toContain("anti_dump_dynamic");
    expect(out).not.toContain("__ad_cnt");
    expect(out).not.toContain("FAKE_BLOB");
  });
});

describe("runtime template: keyfuse + dynamic combined", () => {
  it("keyfuse ON + dynamic ON: both present, no markers", () => {
    const { keyHex } = deriveKeyfuseKey(42);
    const out = buildRuntime(SAMPLE_HEX, 42, { ...DEFAULT_RUNTIME_PROTECT, keyfuse: true, dynamicAntidump: true }, 42, keyHex);
    expect(allMarkers(out)).toEqual([]);
    expect(out).toContain("xor_bytes_512");
    expect(out).toContain("anti_dump_dynamic");
    expect(out).toContain("_rf1");
  });
});

// ---- v0.12 Feature #6: Dispatch 嵌套分支树 ----

describe("runtime template: v0.12 Feature #6 dispatch nested branch tree", () => {
  // 编译一段真实 VM 字节码并取运行时模板，验证 dispatch 结构。
  const out = buildRuntime(SAMPLE_HEX, 42, DEFAULT_RUNTIME_PROTECT, 42, null);

  it("dispatch 包含 3 层 tier 注释与分支结构", () => {
    expect(out).toContain("Tier 1: hot path");
    expect(out).toContain("Tier 2: warm path");
    expect(out).toContain("Tier 3: cold path");
    expect(out).toContain("Dispatch 嵌套分支树");
  });

  it("热路径 opcode 位于 Tier 1（浅层）", () => {
    // 找到 Tier 1 段落范围
    const t1Start = out.indexOf("Tier 1: hot path");
    const t2Start = out.indexOf("Tier 2: warm path");
    expect(t1Start).toBeGreaterThan(-1);
    expect(t2Start).toBeGreaterThan(t1Start);
    const tier1 = out.slice(t1Start, t2Start);
    // 这些是最高频 opcode，必须在 Tier 1
    for (const sem of ["MOVE", "LOADK", "CALL_1RET", "CALL_RET_N", "RETURN0", "RETURN_N", "JUMP"]) {
      expect(tier1).toContain(`sem == "${sem}"`);
    }
  });

  it("算术/比较位于 Tier 2（warm）", () => {
    const t2Start = out.indexOf("Tier 2: warm path");
    const t3Start = out.indexOf("Tier 3: cold path");
    const tier2 = out.slice(t2Start, t3Start);
    for (const sem of ["ADD_RR", "SUB_RR", "EQ_RR", "ALU", "CMP"]) {
      expect(tier2).toContain(`sem == "${sem}"`);
    }
  });

  it("循环/upvalue/fused 位于 Tier 3（cold）", () => {
    const t3Start = out.indexOf("Tier 3: cold path");
    const tier3 = out.slice(t3Start);
    for (const sem of ["FORPREP", "FORLOOP", "GETUPVAL_REAL", "SETUPVAL_REAL"]) {
      expect(tier3).toContain(`sem == "${sem}"`);
    }
    // fused op 在 cold 路径报错（未支持）
    expect(tier3).toContain("FUSED_TAILCALL_VA");
  });

  it("Tier 1 入口是单个 or 链而非 40 条平铺 elseif", () => {
    // Tier 1 的入口条件应是一条 `if sem == "A" or sem == "B" or ...`，
    // 而非直接 `if sem=="A" elseif sem=="B" ...` 的长平铺链。
    const t1Start = out.indexOf("Tier 1: hot path");
    const t2Start = out.indexOf("Tier 2: warm path");
    const tier1Head = out.slice(t1Start, t2Start);
    // 入口 or 链存在
    expect(tier1Head).toMatch(/if sem == "MOVE" or sem == "LOADK"/);
    // Tier 1 内部用 elseif 细分（嵌套树第二层）
    expect(tier1Head).toContain('elseif sem == "LOADK"');
  });
});
