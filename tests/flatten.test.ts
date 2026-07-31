// tests/flatten.test.ts
import { describe, it, expect } from "vitest";
import { lex } from "../src/parser/lexer.js";
import { parse, type Node } from "../src/parser/parser.js";
import { emit } from "../src/emit/emitter.js";
import { buildCipher } from "../src/transforms/strings.js";
import { buildIR, shuffleArray } from "../src/ir/ir.js";
import { flattenAST } from "../src/ir/flatten.js";
import { runPipeline } from "../src/pipeline/obfuscate.js";
import { mulberry32 } from "../src/util/prng.js";

function parseSrc(s: string): Node { return parse(lex(s)); }
function emitNode(a: Node): string { return emit(a, buildCipher(1)); }

describe("buildIR", () => {
  it("splits 3 plain", () => {
    const ast = parseSrc('print(\"a\")\nprint(\"b\")\nprint(\"c\")');
    const blocks = buildIR(ast);
    expect(blocks.length).toBeGreaterThanOrEqual(2);
    // Each statement gets its own block, so block 0 has 1 stmt
    expect(blocks[0].stmts.length).toBe(1);
  });
  it("breaks on If", () => {
    const ast = parseSrc('print(\"before\")\nif true then print(\"yes\") end\nprint(\"after\")');
    expect(buildIR(ast).length).toBeGreaterThanOrEqual(3);
  });
  it("breaks on While", () => {
    const ast = parseSrc('local x = 1\nwhile x > 0 do x = x - 1 end\nprint(\"done\")');
    expect(buildIR(ast).length).toBeGreaterThanOrEqual(3);
  });
  it("return terminator", () => {
    const ast = parseSrc('print(\"a\")\nreturn 42');
    const blocks = buildIR(ast);
    expect(blocks.some(b => b.terminator.type === "return")).toBe(true);
  });
  it("single stmt", () => {
    expect(buildIR(parseSrc('print(\"hello\")')).length).toBeGreaterThanOrEqual(1);
  });
  it("empty program", () => {
    const blocks = buildIR(parseSrc(''));
    expect(blocks.length).toBe(1);
    expect(blocks[0].terminator.type).toBe("exit");
  });
});

describe("shuffleArray", () => {
  it("deterministic", () => { expect(shuffleArray([1,2,3,4,5], mulberry32(42))).toEqual(shuffleArray([1,2,3,4,5], mulberry32(42))); });
  it("different seeds", () => { expect(shuffleArray([1,2,3,4,5], mulberry32(1))).not.toEqual(shuffleArray([1,2,3,4,5], mulberry32(2))); });
  it("preserves elements", () => { expect(shuffleArray([10,20,30,40,50], mulberry32(100)).sort()).toEqual([10,20,30,40,50]); });
});

describe("flattenAST", () => {
  it("single stmt returns original", () => { const ast = parseSrc('print(\"hello\")'); expect(flattenAST(ast, 42)).toBe(ast); });
  it("dispatch structure", () => {
    const ast = parseSrc('print(\"a\")\nprint(\"b\")\nprint(\"c\")');
    const r = flattenAST(ast, 42);
    expect(r.t).toBe("Block");
    if (r.t !== "Block") return;
    expect(r.body.length).toBe(2);
    expect(r.body[0].t).toBe("Local");
    expect(r.body[1].t).toBe("While");
  });
  it("emits dispatch loop", () => {
    const out = emitNode(flattenAST(parseSrc('print(\"a\")\nprint(\"b\")\nprint(\"c\")'), 42));
    expect(out).toContain("while true do"); expect(out).toContain("__b =="); expect(out).toContain("break");
  });
  it("emits local __b", () => {
    expect(emitNode(flattenAST(parseSrc('print(\"a\")\nprint(\"b\")\nprint(\"c\")'), 42))).toContain("local __b =");
  });
  it("deterministic", () => {
    const src = 'print(\"a\")\nlocal x = 1\nprint(\"b\")\nif x > 0 then print(\"c\") end\nprint(\"d\")';
    expect(emitNode(flattenAST(parseSrc(src), 42))).toBe(emitNode(flattenAST(parseSrc(src), 42)));
  });
  it("different seeds diff", () => {
    const src = 'print(\"a\")\nprint(\"b\")\nprint(\"c\")\nprint(\"d\")\nprint(\"e\")';
    expect(emitNode(flattenAST(parseSrc(src), 1))).not.toBe(emitNode(flattenAST(parseSrc(src), 2)));
  });
  it("preserves stmts", () => {
    const src = 'print(\"alpha\")\nprint(\"beta\")\nprint(\"gamma\")';
    const out = emitNode(flattenAST(parseSrc(src), 42));
    expect(out).toContain("alpha"); expect(out).toContain("beta"); expect(out).toContain("gamma");
  });
  it("handles if-else", () => {
    const src = 'local x = 1\nif x > 0 then print(\"pos\") else print(\"neg\") end\nprint(\"end\")';
    const out = emitNode(flattenAST(parseSrc(src), 42));
    expect(out).toContain("while true do"); expect(out).toContain("__b ==");
  });
  it("handles while", () => {
    const src = 'local i = 0\nwhile i < 3 do i = i + 1 end\nprint(\"done\")';
    const out = emitNode(flattenAST(parseSrc(src), 42));
    expect(out).toContain("while true do"); expect(out).toContain("while");
  });
  it("handles return", () => {
    const out = emitNode(flattenAST(parseSrc('print(\"start\")\nreturn 42'), 42));
    expect(out).toContain("return");
  });
});

describe("flatten pipeline", () => {
  it("full pipeline", () => {
    const src = 'local greeting = "hello world"\nprint(greeting)';
    const r = runPipeline(src, { seed: 42 });
    expect(r.out.length).toBeGreaterThan(0);
    expect(r.out).toContain("while true do");
    // D4 dispatch var name is now scoped: __b, __b1, __b2, ... (see
    // flattenRecursive in src/ir/flatten.ts). Accept any __b<N> == pattern.
    expect(r.out).toMatch(/__b\d*\s*==/);
  });
  it("noFlatten disabled", () => {
    const src = 'print(\"a\")\nprint(\"b\")\nprint(\"c\")';
    const r = runPipeline(src, { seed: 42, noFlatten: true });
    expect(r.out).not.toContain("while true do");
  });
  it("D2/D3 after flatten", () => {
    const src = 'local msg = \"hello world from flattener\"\nprint(msg)';
    const r = runPipeline(src, { seed: 42 });
    // v0.12 Feature #8: 字符串解密器改为全局共享 `_S(K,H)`，不再每条内联
    // `function(K)` IIFE。检测加密生效的标志改为 `_S(` 调用。
    expect(r.out).not.toContain("hello world from flattener"); expect(r.out).toContain("_S(");
  });
  it("hello.lua style", () => {
    const src = 'local greeting = \"hello world\"\nlocal repeat_count = 3\nfor i = 1, repeat_count do\n  print(greeting .. \" #\" .. tostring(i))\nend\nlocal function add(a, b)\n  return a + b\nend\nprint(\"1 + 2 = \" .. tostring(add(1, 2)))\nif greeting:sub(1, 1) == \"h\" then\n  print(\"starts with h\")\nend';
    const r = runPipeline(src, { seed: 42 });
    expect(r.out.length).toBeGreaterThan(500); expect(r.out).toContain("while true do");
  });
});

