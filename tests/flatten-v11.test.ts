// tests/flatten-v11.test.ts — v0.11 递归 flatten + 不透明谓词 + 假路径 case 测试。
//
// 验证：
//   1. flattenRecursive 启用嵌套函数 flatten（函数体含 __b1 dispatch var）
//   2. 状态转移每 stride（5-10）个分支升级为 (OPAQUE_TRUE and T) or EXIT_STATE
//   3. 假路径 case（__d 垃圾 local + __b = -1）
//   4. duplicate-return 修复（return 块 case body 只有一个 return）
//   5. 端到端：复杂源码（函数 + if + return）flatten + emit 不报错
//   6. 确定性 + 不同 seed 不同输出
//   7. flattenAST（非递归）行为回归

import { describe, it, expect } from "vitest";
import { lex } from "../src/parser/lexer.js";
import { parse, type Node } from "../src/parser/parser.js";
import { emit } from "../src/emit/emitter.js";
import { buildCipher } from "../src/transforms/strings.js";
import { flattenAST, flattenRecursive } from "../src/ir/flatten.js";
import { buildIR } from "../src/ir/ir.js";
import { runPipeline } from "../src/pipeline/obfuscate.js";

function parseSrc(s: string): Node { return parse(lex(s)); }
function emitNode(a: Node): string { return emit(a, buildCipher(1)); }

// 触发递归 flatten 的函数体（>= MIN_BLOCKS_FUNC=3 个非 exit 块）。
// 4 条语句各成一个 block → 4 个非 exit 块 → 触发 flatten。
const FUNC_SRC = `local function f(x)
  local a = 1
  local b = 2
  local c = 3
  return a + b + c + x
end
print(f(10))`;

// 含 if + 早返回的函数（验证 duplicate-return 修复 + nested If 不崩）。
const FUNC_WITH_IF_SRC = `local function g(x)
  local a = 1
  if x > 0 then
    return a + x
  end
  local b = 2
  local c = 3
  return a + b + c
end
print(g(5))
print(g(-1))`;

describe("flattenRecursive: 嵌套函数 flatten", () => {
  it("函数体含 __b1 dispatch var（递归启用）", () => {
    const ast = parseSrc(FUNC_SRC);
    const out = emitNode(flattenRecursive(ast, 42));
    expect(out).toContain("__b1");
    expect(out).toContain("while true do");
  });

  it("flattenAST（非递归）函数体不含 __b1", () => {
    const ast = parseSrc(FUNC_SRC);
    const out = emitNode(flattenAST(ast, 42));
    // 非递归：只有顶层 __b（实际是 __b1，因为 flattenAST 用 DISPATCH_VAR="__b"）
    // 但函数体不会被 flatten → 函数体内无 while true do
    // 检查函数体内无 dispatch（用 while true do 出现次数判断）
    const whileCount = (out.match(/while true do/g) || []).length;
    expect(whileCount).toBe(1); // 只有顶层 1 个
  });

  it("递归 flatten 函数体有独立 while true do", () => {
    const ast = parseSrc(FUNC_SRC);
    const out = emitNode(flattenRecursive(ast, 42));
    const whileCount = (out.match(/while true do/g) || []).length;
    expect(whileCount).toBe(2); // 顶层 + 函数体
  });

  it("简单函数（< 3 块）不被 flatten", () => {
    const src = `local function tiny(a, b)\n  return a + b\nend\nprint(tiny(1, 2))`;
    const ast = parseSrc(src);
    const out = emitNode(flattenRecursive(ast, 42));
    // tiny 函数体只有 1 个 return 块 → 不 flatten → 函数体内无 while true do
    const whileCount = (out.match(/while true do/g) || []).length;
    expect(whileCount).toBe(1); // 只有顶层
  });
});

describe("flattenRecursive: 不透明谓词转移", () => {
  it("转移语句含 and/or 形式（多样化谓词）", () => {
    // v0.8: stride ∈ [5,10]，需 ≥ 10 个转移确保至少 1 个升级为不透明谓词。
    // 12 条语句 → 11 个非 exit 块 → 11 个转移 → 保证覆盖最大 stride=10。
    const src = `local a = 1\nlocal b = 2\nlocal c = 3\nlocal d = 4\nlocal e = 5\nlocal f = 6\nlocal g = 7\nlocal h = 8\nlocal i = 9\nlocal j = 10\nlocal k = 11\nlocal l = 12\nprint(a + b + c + d + e + f + g + h + i + j + k + l)`;
    const ast = parseSrc(src);
    const out = emitNode(flattenRecursive(ast, 42));
    // stride 计数器在第 stride 次调用时插入不透明谓词
    // 检查 __b 赋值行同时含 " and " 和 " or "（不透明谓词转移特征）
    const lines = out.split("\n");
    const hasOpaqueTransition = lines.some(
      (l) => /__b\d+\s*=/.test(l) && l.includes(" and ") && l.includes(" or "),
    );
    expect(hasOpaqueTransition).toBe(true);
  });

  it("不透明谓词形式多样化（5 种）", () => {
    // v0.8: stride ∈ [5,10]，用 12 条语句（11 转移）确保每 seed 至少 1 个谓词。
    const src = `local a = 1\nlocal b = 2\nlocal c = 3\nlocal d = 4\nlocal e = 5\nlocal f = 6\nlocal g = 7\nlocal h = 8\nlocal i = 9\nlocal j = 10\nlocal k = 11\nlocal l = 12\nprint(a + b + c + d + e + f + g + h + i + j + k + l)`;
    const forms = new Set<string>();
    for (const seed of [1, 7, 42, 100, 999, 2024, 12345, 67890]) {
      const ast = parseSrc(src);
      const out = emitNode(flattenRecursive(ast, seed));
      // 收集所有 == / ~= / < 形式的谓词
      const matches = out.match(/\(\s*[^()]*\s*(==|~=|<)\s*[^()]*\)/g) || [];
      for (const m of matches) forms.add(m.trim());
    }
    // 至少 2 种不同形式（5 种里至少命中 2 种）
    expect(forms.size).toBeGreaterThanOrEqual(2);
  });

  it("部分转移保持直赋值（stride 降频后大部分是直赋值）", () => {
    // v0.8: stride ∈ [5,10]，12 条语句 → 11 转移，仅 1 个升级为不透明谓词。
    // 剩余 10 个保持直赋值 `__b2 = <number>`。
    const src = `local a = 1\nlocal b = 2\nlocal c = 3\nlocal d = 4\nlocal e = 5\nlocal f = 6\nlocal g = 7\nlocal h = 8\nlocal i = 9\nlocal j = 10\nlocal k = 11\nlocal l = 12\nprint(a + b + c + d + e + f + g + h + i + j + k + l)`;
    const ast = parseSrc(src);
    const out = emitNode(flattenRecursive(ast, 42));
    // 直赋值形如 `__b2 = 123`（后面不带 and/or）
    expect(out).toMatch(/__b\d+\s*=\s*\d+\s*$/m);
  });
});

describe("flattenRecursive: 假路径 case", () => {
  it("dispatch 链含 __d 垃圾 local", () => {
    const src = `local a = 1\nlocal b = 2\nlocal c = 3\nprint(a + b + c)`;
    const ast = parseSrc(src);
    const out = emitNode(flattenRecursive(ast, 42));
    // 假路径 case body 含 __d 垃圾 local
    expect(out).toContain("local __d");
  });

  it("假路径 case 数量在 2-4 范围（每个 flatten 作用域）", () => {
    // 单个 flatten 作用域（顶层），收集 __d 声明数量
    const src = `local a = 1\nlocal b = 2\nlocal c = 3\nprint(a + b + c)`;
    const ast = parseSrc(src);
    const out = emitNode(flattenRecursive(ast, 42));
    // 假路径 case 的 __d local 数量 = 假 case 数 × (1-2 个 local/case)
    // 2-4 个假 case，每个 1-2 个 local → 2-8 个 __d local
    const dCount = (out.match(/local __d\d+/g) || []).length;
    expect(dCount).toBeGreaterThanOrEqual(2);
    expect(dCount).toBeLessThanOrEqual(8);
  });
});

describe("flattenRecursive: duplicate-return 修复", () => {
  it("return 块 case body 只有一个 return（不重复）", () => {
    // buildIR 修复后：Return 不进 currentStmts，只作 terminator
    const ast = parseSrc('print("a")\nreturn 42');
    const blocks = buildIR(ast);
    const returnBlock = blocks.find((b) => b.terminator.type === "return");
    expect(returnBlock).toBeDefined();
    if (!returnBlock) return;
    // Return 不在 stmts 里
    expect(returnBlock.stmts.some((s) => s.t === "Return")).toBe(false);
  });

  it("含 if + 早返回的函数 flatten + emit 不报错", () => {
    const ast = parseSrc(FUNC_WITH_IF_SRC);
    // 不应抛异常
    const out = emitNode(flattenRecursive(ast, 42));
    expect(out.length).toBeGreaterThan(0);
    expect(out).toContain("while true do");
  });

  it("多层嵌套函数 flatten + emit 不报错", () => {
    const src = `local function outer(x)
  local a = 1
  local b = 2
  local c = 3
  local function inner(y)
    local p = 10
    local q = 20
    local r = 30
    return p + q + r + y
  end
  return a + b + c + x + inner(x)
end
print(outer(100))`;
    const ast = parseSrc(src);
    const out = emitNode(flattenRecursive(ast, 42));
    expect(out.length).toBeGreaterThan(0);
    // 顶层 + outer + inner = 3 个 dispatch 作用域
    const whileCount = (out.match(/while true do/g) || []).length;
    expect(whileCount).toBe(3);
  });
});

describe("flattenRecursive: 确定性 + seed 差异", () => {
  it("同 seed 同输出", () => {
    const src = FUNC_SRC;
    const a = emitNode(flattenRecursive(parseSrc(src), 42));
    const b = emitNode(flattenRecursive(parseSrc(src), 42));
    expect(a).toBe(b);
  });

  it("不同 seed 不同输出", () => {
    const src = FUNC_SRC;
    const a = emitNode(flattenRecursive(parseSrc(src), 1));
    const b = emitNode(flattenRecursive(parseSrc(src), 2));
    expect(a).not.toBe(b);
  });
});

describe("flattenRecursive: pipeline 集成", () => {
  it("runPipeline 默认启用递归 flatten", () => {
    const src = FUNC_SRC;
    const r = runPipeline(src, { seed: 42 });
    expect(r.out).toContain("while true do");
    // 函数体被 flatten → 至少 2 个 while true do
    const whileCount = (r.out.match(/while true do/g) || []).length;
    expect(whileCount).toBeGreaterThanOrEqual(2);
  });

  it("noRecursiveFlatten 关闭递归（只顶层）", () => {
    const src = FUNC_SRC;
    const r = runPipeline(src, { seed: 42, recursiveFlatten: false });
    const whileCount = (r.out.match(/while true do/g) || []).length;
    expect(whileCount).toBe(1); // 只有顶层
  });

  it("noFlatten 完全关闭", () => {
    const src = FUNC_SRC;
    const r = runPipeline(src, { seed: 42, noFlatten: true });
    expect(r.out).not.toContain("while true do");
  });

  it("复杂源码端到端结构完整", () => {
    const src = `local greeting = "hello world"
local repeat_count = 3
for i = 1, repeat_count do
  print(greeting .. " #" .. tostring(i))
end
local function add(a, b)
  local c = a + b
  local d = c * 2
  local e = d - 1
  return e
end
print("add(1, 2) = " .. tostring(add(1, 2)))
if greeting:sub(1, 1) == "h" then
  print("starts with h")
end`;
    const r = runPipeline(src, { seed: 42 });
    expect(r.out.length).toBeGreaterThan(500);
    expect(r.out).toContain("while true do");
    // 函数 add 有 4 个非 exit 块 → 被 flatten
    const whileCount = (r.out.match(/while true do/g) || []).length;
    expect(whileCount).toBeGreaterThanOrEqual(2);
  });
});
