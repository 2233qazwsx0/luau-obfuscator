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
