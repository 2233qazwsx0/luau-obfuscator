// tests/flatten-semantic.test.ts — v0.11 端到端语义验证。
//
// 用 fengari（纯 JS lua 5.3 VM）执行 flatten 前后的 lua 源码，比较 print 输出。
// 这是真正的语义等价验证，不是结构检查。
//
// 逻辑：
//   1. SRC（原始源码）→ fengari 执行 → expected 输出
//   2. SRC → parse → flattenRecursive(seed) → emit → flatLua → fengari 执行 → actual 输出
//   3. expect(expected) == actual
//
// 覆盖：顺序 / 函数+return / if+早返回 / for / while / 嵌套函数 / 多 seed。

import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";
import { lex } from "../src/parser/lexer.js";
import { parse, type Node } from "../src/parser/parser.js";
import { emit } from "../src/emit/emitter.js";
import { buildCipher } from "../src/transforms/strings.js";
import { flattenRecursive } from "../src/ir/flatten.js";

const require = createRequire(import.meta.url);
// fengari 无类型定义，用 any。
const fengari: any = require("fengari");

/**
 * 用 fengari 执行 lua 源码，捕获 print 输出，返回输出字符串。
 * preamble 重定义 print，把输出存到 _output 表；epilogue 返回拼接结果。
 */
function runLua(src: string): string {
  const L = fengari.lauxlib.luaL_newstate();
  fengari.lualib.luaL_openlibs(L);
  const preamble =
    'local _output = {}\n' +
    'print = function(...)\n' +
    '  local args = {...}\n' +
    '  local parts = {}\n' +
    '  for i = 1, #args do parts[i] = tostring(args[i]) end\n' +
    '  _output[#_output + 1] = table.concat(parts, "\\t")\n' +
    'end\n';
  const epilogue = '\nreturn table.concat(_output, "\\n")';
  const code = preamble + src + epilogue;
  const luaCode = fengari.to_luastring(code);
  const loadStatus = fengari.lauxlib.luaL_loadstring(L, luaCode);
  if (loadStatus !== fengari.lua.LUA_OK) {
    const err = fengari.to_jsstring(fengari.lua.lua_tolstring(L, -1));
    throw new Error("lua load error: " + err);
  }
  const callStatus = fengari.lua.lua_pcall(L, 0, 1, 0);
  if (callStatus !== fengari.lua.LUA_OK) {
    const err = fengari.to_jsstring(fengari.lua.lua_tolstring(L, -1));
    throw new Error("lua run error: " + err);
  }
  const resultBytes = fengari.lua.lua_tolstring(L, -1);
  const result = fengari.to_jsstring(resultBytes);
  return result;
}

function flattenAndEmit(src: string, seed: number): string {
  const ast: Node = parse(lex(src));
  const flat = flattenRecursive(ast, seed);
  return emit(flat, buildCipher(1));
}

// ---- 测试源码 ----
const SOURCES = {
  sequential: 'local a = 1\nlocal b = 2\nlocal c = 3\nprint(a + b + c)',
  funcReturn: 'local function f(x)\n  local a = 1\n  local b = 2\n  local c = 3\n  return a + b + c + x\nend\nprint(f(10))',
  funcEarlyReturn: 'local function g(x)\n  local a = 1\n  if x > 0 then\n    return a + x\n  end\n  local b = 2\n  local c = 3\n  return a + b + c\nend\nprint(g(5))\nprint(g(-1))',
  forLoop: 'local s = 0\nlocal t = 0\nfor i = 1, 5 do\n  s = s + i\n  t = t + s\nend\nprint(s)\nprint(t)',
  whileLoop: 'local i = 0\nlocal s = ""\nwhile i < 3 do\n  i = i + 1\n  s = s .. tostring(i)\nend\nprint(s)',
  nestedFunc: 'local function outer(x)\n  local a = 1\n  local b = 2\n  local c = 3\n  local function inner(y)\n    local p = 10\n    local q = 20\n    local r = 30\n    return p + q + r + y\n  end\n  return a + b + c + x + inner(x)\nend\nprint(outer(100))',
  ifElse: 'local x = 5\nlocal a = 1\nlocal b = 2\nlocal c = 3\nif x > 3 then\n  print(a + b)\nelse\n  print(b + c)\nend',
  stringConcat: 'local a = "hello"\nlocal b = " "\nlocal c = "world"\nlocal d = a .. b .. c\nprint(d)',
};

const SEEDS = [1, 42, 999, 12345];

describe("flatten 语义等价（fengari 端到端）", () => {
  // 先验证 fengari 本身能跑原始源码
  it("fengari 能执行原始 lua", () => {
    expect(runLua('print("hello")')).toBe("hello");
    expect(runLua('local a = 1\nlocal b = 2\nprint(a + b)')).toBe("3");
  });

  // 顺序语句
  it("sequential: flatten 前后输出一致", () => {
    const src = SOURCES.sequential;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // 函数 + return
  it("funcReturn: flatten 前后输出一致", () => {
    const src = SOURCES.funcReturn;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // if + 早返回（duplicate-return bug 修复的关键验证）
  it("funcEarlyReturn: flatten 前后输出一致", () => {
    const src = SOURCES.funcEarlyReturn;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // for 循环
  it("forLoop: flatten 前后输出一致", () => {
    const src = SOURCES.forLoop;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // while 循环
  it("whileLoop: flatten 前后输出一致", () => {
    const src = SOURCES.whileLoop;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // 嵌套函数（递归 flatten 的核心验证）
  it("nestedFunc: flatten 前后输出一致", () => {
    const src = SOURCES.nestedFunc;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // if/else
  it("ifElse: flatten 前后输出一致", () => {
    const src = SOURCES.ifElse;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // 字符串连接
  it("stringConcat: flatten 前后输出一致", () => {
    const src = SOURCES.stringConcat;
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // 不透明谓词转移的语义验证（多 seed 确保谓词形式都覆盖）
  it("不透明谓词转移不破坏语义（多 seed 全覆盖）", () => {
    // 用足够长的源码触发大量转移，确保 5 种 OPAQUE_TRUE 形式都命中
    const src = 'local a = 1\nlocal b = 2\nlocal c = 3\nlocal d = 4\nlocal e = 5\nlocal f = 6\nlocal g = 7\nlocal h = 8\nprint(a + b + c + d + e + f + g + h)';
    const expected = runLua(src);
    // 多 seed 跑，覆盖所有谓词形式
    for (const seed of [1, 7, 42, 100, 999, 2024, 12345, 67890, 55555, 3]) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });

  // 假路径 case 不影响语义（假 case 永不命中）
  it("假路径 case 不影响输出", () => {
    const src = 'local a = 1\nlocal b = 2\nlocal c = 3\nprint(a + b + c)';
    const expected = runLua(src);
    for (const seed of SEEDS) {
      const flat = flattenAndEmit(src, seed);
      const actual = runLua(flat);
      expect(actual).toBe(expected);
    }
  });
});
