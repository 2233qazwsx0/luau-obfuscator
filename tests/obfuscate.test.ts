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

  it("v0.12 Feature #8: emits a single shared _S decryptor instead of per-string IIFEs", () => {
    // 多条加密字符串应共享一个 _S 定义，而不是每条内联一份 function(K) IIFE。
    const src = `local a="hello world one"\nlocal b="hello world two"\nlocal c="hello world three"\nprint(a,b,c)`;
    const out = runPipeline(src, { seed: 7, noFlatten: true, noDeadcode: true }).out;
    // 共享解密器只定义一次
    const sDefCount = (out.match(/local function _S\(K,H\)/g) || []).length;
    expect(sDefCount).toBe(1);
    // 不应再出现旧的内联 IIFE 头部
    expect(out).not.toContain("(function(K) return function(H)");
    // 三条字符串都应通过 _S( 调用解密
    const sCallCount = (out.match(/_S\(/g) || []).length;
    expect(sCallCount).toBeGreaterThanOrEqual(3);
  });

  it("v0.12 Feature #8: no encrypted strings → no _S helper emitted", () => {
    const src = `print("x")`; // 太短，不会被加密
    const out = runPipeline(src, { seed: 7, noNumbers: true, noFlatten: true, noDeadcode: true }).out;
    expect(out).not.toContain("local function _S");
  });

  it("v0.12 Feature #7: deadcodeRatio=0 disables D5 injection effectively", () => {
    const src = Array.from({ length: 20 }, (_, i) => `print("s${i}")`).join("\n");
    const out = runPipeline(src, { seed: 42, deadcodeRatio: 0, noFlatten: true }).out;
    expect(out).not.toContain("__d");
  });
});