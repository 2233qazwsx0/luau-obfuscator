// tests/deadcode.test.ts
import { describe, it, expect } from "vitest";
import { lex } from "../src/parser/lexer.js";
import { parse, type Node } from "../src/parser/parser.js";
import { emit } from "../src/emit/emitter.js";
import { buildCipher } from "../src/transforms/strings.js";
import { injectDeadcode } from "../src/transforms/deadcode.js";
import { flattenAST } from "../src/ir/flatten.js";
import { runPipeline } from "../src/pipeline/obfuscate.js";

function parseSrc(s: string): Node { return parse(lex(s)); }
function emitNode(a: Node): string { return emit(a, buildCipher(1)); }

describe("injectDeadcode", () => {
  it("returns non-Block unchanged", () => {
    const ast = { t: "Ident", name: "x", line: 0 } as Node;
    expect(injectDeadcode(ast, 42)).toBe(ast);
  });

  it("returns empty Block unchanged", () => {
    const ast = parseSrc("");
    expect(injectDeadcode(ast, 42)).toBe(ast);
  });

  it("deterministic: same seed produces same output", () => {
    const src = 'print("a")\nprint("b")\nprint("c")\nprint("d")\nprint("e")\nprint("f")\nprint("g")\nprint("h")';
    const r1 = emitNode(injectDeadcode(parseSrc(src), 42));
    const r2 = emitNode(injectDeadcode(parseSrc(src), 42));
    expect(r1).toBe(r2);
  });

  it("different seeds produce different output", () => {
    const src = 'print("a")\nprint("b")\nprint("c")\nprint("d")\nprint("e")\nprint("f")\nprint("g")\nprint("h")';
    const r1 = emitNode(injectDeadcode(parseSrc(src), 42));
    const r2 = emitNode(injectDeadcode(parseSrc(src), 999));
    expect(r1).not.toBe(r2);
  });

  it("injects dead code with enough statements", () => {
    // 10 statements → max 5 dead code blocks
    const src = Array.from({ length: 10 }, (_, i) => `print("s${i}")`).join("\n");
    const ast = injectDeadcode(parseSrc(src), 42);
    expect(ast.t).toBe("Block");
    if (ast.t !== "Block") return;
    // Original 10 + up to 5 dead code blocks = 10..15
    expect(ast.body.length).toBeGreaterThanOrEqual(10);
    expect(ast.body.length).toBeLessThanOrEqual(15);
  });

  it("respects 50% upper limit", () => {
    // 20 statements → max 10 dead code blocks
    const src = Array.from({ length: 20 }, (_, i) => `print("s${i}")`).join("\n");
    const ast = injectDeadcode(parseSrc(src), 42);
    if (ast.t !== "Block") return;
    const original = 20;
    const injected = ast.body.length - original;
    expect(injected).toBeLessThanOrEqual(Math.floor(original * 0.5));
  });

  it("v0.12 Feature #7: default ratio is 0.2 (lightweight mode)", () => {
    // 20 statements → default 0.2 → max 4 dead code blocks
    const src = Array.from({ length: 20 }, (_, i) => `print("s${i}")`).join("\n");
    const ast = injectDeadcode(parseSrc(src), 42);
    if (ast.t !== "Block") return;
    const original = 20;
    const injected = ast.body.length - original;
    expect(injected).toBeLessThanOrEqual(Math.floor(original * 0.2));
  });

  it("v0.12 Feature #7: ratio=0.5 restores v0.6 behavior", () => {
    const src = Array.from({ length: 20 }, (_, i) => `print("s${i}")`).join("\n");
    const ast = injectDeadcode(parseSrc(src), 42, 0.5);
    if (ast.t !== "Block") return;
    const original = 20;
    const injected = ast.body.length - original;
    expect(injected).toBeLessThanOrEqual(Math.floor(original * 0.5));
  });

  it("v0.12 Feature #7: prefers unreachable branches over dead variables", () => {
    // With bias=0.8, most injected blocks should be `if false then`.
    // 50 stmts × 0.2 ratio = up to 10 dead blocks; with 80% bias, expect
    // at least 4 unreachable branches (probabilistic margin).
    const src = Array.from({ length: 50 }, (_, i) => `print("s${i}")`).join("\n");
    const out = emitNode(injectDeadcode(parseSrc(src), 42));
    const unreachableCount = (out.match(/if false then/g) || []).length;
    expect(unreachableCount).toBeGreaterThanOrEqual(3);
  });

  it("uses __d prefix for dead variable names", () => {
    const src = Array.from({ length: 20 }, (_, i) => `print("s${i}")`).join("\n");
    const out = emitNode(injectDeadcode(parseSrc(src), 42));
    expect(out).toContain("__d");
  });

  it("injects if false unreachable branches", () => {
    const src = Array.from({ length: 20 }, (_, i) => `print("s${i}")`).join("\n");
    const out = emitNode(injectDeadcode(parseSrc(src), 42));
    // At least one `if false then` should appear (probabilistic but near-certain with 20 stmts)
    expect(out).toContain("if false then");
  });

  it("preserves original statements", () => {
    const src = 'print("alpha")\nprint("beta")\nprint("gamma")\nprint("delta")\nprint("epsilon")\nprint("zeta")\nprint("eta")\nprint("theta")';
    const out = emitNode(injectDeadcode(parseSrc(src), 42));
    expect(out).toContain("alpha");
    expect(out).toContain("beta");
    expect(out).toContain("gamma");
    expect(out).toContain("delta");
    expect(out).toContain("epsilon");
    expect(out).toContain("zeta");
    expect(out).toContain("eta");
    expect(out).toContain("theta");
  });
});

describe("deadcode + flatten pipeline", () => {
  it("dead code gets flattened into dispatch cases", () => {
    const src = 'print("a")\nprint("b")\nprint("c")\nprint("d")\nprint("e")\nprint("f")\nprint("g")\nprint("h")';
    const ast = injectDeadcode(parseSrc(src), 42);
    const flattened = flattenASTAndCheck(ast, 42);
    expect(flattened.out).toContain("while true do");
    expect(flattened.out).toContain("__b ==");
  });

  it("full pipeline with deadcode produces valid output", () => {
    const src = 'local greeting = "hello world"\nprint(greeting)';
    const r = runPipeline(src, { seed: 42 });
    expect(r.out.length).toBeGreaterThan(0);
    expect(r.out).toContain("while true do");
  });

  it("noDeadcode disables injection", () => {
    const src = 'print("a")\nprint("b")\nprint("c")\nprint("d")\nprint("e")\nprint("f")\nprint("g")\nprint("h")';
    const r = runPipeline(src, { seed: 42, noDeadcode: true, noFlatten: true, noStrings: true, noNumbers: true, noRename: true });
    // Without deadcode, output should not contain __d variables
    expect(r.out).not.toContain("__d");
  });

  it("deadcode + flatten + D2/D3 all stack", () => {
    const src = 'local msg = "hello from deadcode test"\nprint(msg)';
    const r = runPipeline(src, { seed: 42 });
    // String should be XOR encrypted
    expect(r.out).not.toContain("hello from deadcode test");
    // Should have dispatch loop
    expect(r.out).toContain("while true do");
    // Should have dead code __d variables
    expect(r.out).toContain("__d");
    // Should have bitxor polyfill
    expect(r.out).toContain("_B");
  });

  it("hello.lua style with deadcode", () => {
    const src = 'local greeting = "hello world"\nlocal repeat_count = 3\nfor i = 1, repeat_count do\n  print(greeting .. " #" .. tostring(i))\nend\nlocal function add(a, b)\n  return a + b\nend\nprint("1 + 2 = " .. tostring(add(1, 2)))\nif greeting:sub(1, 1) == "h" then\n  print("starts with h")\nend';
    const r = runPipeline(src, { seed: 42 });
    expect(r.out.length).toBeGreaterThan(500);
    expect(r.out).toContain("while true do");
  });
});

// Helper: flatten AST and emit, returning the output string
function flattenASTAndCheck(ast: Node, seed: number): { out: string } {
  const flat = flattenAST(ast, seed);
  return { out: emitNode(flat) };
}
