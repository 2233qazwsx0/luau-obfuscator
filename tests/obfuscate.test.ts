// tests/obfuscate.test.ts — End-to-end: input → obfuscate → emit.
import { describe, it, expect } from "vitest";
import { runPipeline } from "../src/pipeline/obfuscate.js";

describe("obfuscate", () => {
  it("emits different source for the same input with two seeds", () => {
    const src = `local msg = "hello"\nprint(msg)`;
    const a = runPipeline(src, { seed: 1 }).out;
    const b = runPipeline(src, { seed: 2 }).out;
    expect(a.length).toBeGreaterThan(0);
    expect(b.length).toBeGreaterThan(0);
    // Different seeds → different cipher keys → different encrypted blobs.
    // At minimum the two outputs should not be byte-identical.
    expect(a).not.toBe(b);
  });

  it("emits the same cipher pool when given the same seed", () => {
    const src = `print("unchanging")`;
    const a = runPipeline(src, { seed: 42 });
    const b = runPipeline(src, { seed: 42 });
    expect(a.cipher.pool).toEqual(b.cipher.pool);
  });

  it("renames local variables", () => {
    const src = `local hello = 1\nprint(hello)`;
    const out = runPipeline(src, { seed: 7 }).out;
    // The original identifier 'hello' should be gone or shortened.
    expect(out.includes("hello")).toBe(false);
  });

  it("encodes strings as XOR blobs for sufficiently long ones", () => {
    const src = `print("this is a sufficiently long string to be encrypted")`;
    const out = runPipeline(src, { seed: 7 }).out;
    // The literal should be gone, the blob should be somewhere
    expect(out.includes("this is a sufficiently long string to be encrypted")).toBe(false);
    expect(out.length).toBeGreaterThan(200);
  });

  it("preserves identifiers we know to be engine-visible", () => {
    const src = `print("ok")`;
    const out = runPipeline(src, { seed: 1, noStrings: true, noNumbers: true }).out;
    expect(out).toContain("print");
  });

  it("supports minify", () => {
    const src = `local a = 1\nlocal b = 2`;
    const out = runPipeline(src, { seed: 1, minify: true }).out;
    expect(out.split("\n").filter((l) => l.trim()).length).toBeLessThanOrEqual(2);
  });

  it("handles small source without crashing", () => {
    const src = `local function f(x) return x + 1 end\nprint(f(2))`;
    const out = runPipeline(src, { seed: 1 }).out;
    expect(out.length).toBeGreaterThan(0);
  });
});