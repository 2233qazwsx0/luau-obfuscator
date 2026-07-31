// tests/selective-vm.test.ts — v0.12 Feature #1 + #2: 选择性虚拟化。
//
// 覆盖：
//   1. parseVmAnnotations          — --@vm 注解预扫描（独占行 / 行尾 / 多注解）
//   2. autoIdentifyVmFunctions     — 启发式自动识别关键逻辑函数
//   3. collectFreeVariables        — upvalue 依赖检测
//   4. identifyVmFunctions         — 合并 + 安全过滤
//   5. buildSyntheticVmSource      — 合成 VM 源码结构
//   6. buildStubBody               — dispatch 桩函数体 AST
//   7. pipeline selectiveVm        — 端到端：无目标退化为普通模式 / 有目标产混合输出

import { describe, it, expect } from "vitest";
import { lex } from "../src/parser/lexer.js";
import { parse, type Node } from "../src/parser/parser.js";
import {
  parseVmAnnotations,
  autoIdentifyVmFunctions,
  collectFreeVariables,
  identifyVmFunctions,
  buildSyntheticVmSource,
  buildStubBody,
  canonicalName,
  mapNameThroughRename,
  VM_DISPATCH_NAME,
} from "../src/transforms/selective-vm.js";
import { runPipeline } from "../src/pipeline/obfuscate.js";
import { emit } from "../src/emit/emitter.js";

function astOf(src: string): Node {
  return parse(lex(src));
}

// ---- 1. parseVmAnnotations ----

describe("selective-vm: parseVmAnnotations", () => {
  it("检测独占行的 --@vm 注解，提取紧随其后的函数名", () => {
    const src = `--@vm
local function verify_key(key) return key end`;
    expect(parseVmAnnotations(src)).toEqual(new Set(["verify_key"]));
  });

  it("检测全局函数声明前的 --@vm", () => {
    const src = `print("x")
--@vm
function check() return 1 end`;
    expect(parseVmAnnotations(src)).toEqual(new Set(["check"]));
  });

  it("检测行尾注解形式：local function foo() --@vm", () => {
    const src = `local function foo() return 1 end  --@vm`;
    expect(parseVmAnnotations(src)).toEqual(new Set(["foo"]));
  });

  it("支持多个 --@vm 注解", () => {
    const src = `--@vm
local function a() end
--@vm
local function b() end
local function c() end`;
    expect(parseVmAnnotations(src)).toEqual(new Set(["a", "b"]));
  });

  it("支持点分 / 方法名", () => {
    const src = `--@vm
function obj:method() end`;
    expect(parseVmAnnotations(src)).toEqual(new Set(["obj:method"]));
  });

  it("无注解时返回空集", () => {
    expect(parseVmAnnotations("local function f() end")).toEqual(new Set());
  });

  it("忽略 --@vm 后跟非函数行", () => {
    const src = `--@vm
print("not a function")`;
    expect(parseVmAnnotations(src)).toEqual(new Set());
  });
});

// ---- 2. autoIdentifyVmFunctions ----

describe("selective-vm: autoIdentifyVmFunctions", () => {
  it("识别含 loadstring 调用的函数", () => {
    const src = `local function loader(code) return loadstring(code)() end
local function ui() print("ui") end`;
    const names = autoIdentifyVmFunctions(astOf(src));
    expect(names.has("loader")).toBe(true);
    expect(names.has("ui")).toBe(false);
  });

  it("识别含卡密关键字字符串的函数", () => {
    const src = `local function check(x) if x == "卡密错误" then return false end return true end
local function draw() print("draw") end`;
    const names = autoIdentifyVmFunctions(astOf(src));
    expect(names.has("check")).toBe(true);
    expect(names.has("draw")).toBe(false);
  });

  it("识别含白名单/校验字符串的函数", () => {
    const src = `local function whitelist(v) if v == "白名单" then return true end return false end`;
    const names = autoIdentifyVmFunctions(astOf(src));
    expect(names.has("whitelist")).toBe(true);
  });

  it("纯 UI 回调不被识别", () => {
    const src = `local function onClick() print("clicked") end
local function onEvent(e) return e.x end`;
    const names = autoIdentifyVmFunctions(astOf(src));
    expect(names.size).toBe(0);
  });
});

// ---- 3. collectFreeVariables ----

describe("selective-vm: collectFreeVariables", () => {
  it("自包含函数（仅用参数 + 内部 local）无自由变量", () => {
    const body = (astOf(`local function f(a, b)
local c = a + b
return c
end`) as any).body[0].body;
    const free = collectFreeVariables(body, ["a", "b"]);
    expect(free.size).toBe(0);
  });

  it("引用外层局部变量 → 出现自由变量", () => {
    const body = (astOf(`local function f(a)
return a + SECRET
end`) as any).body[0].body;
    const free = collectFreeVariables(body, ["a"]);
    expect(free.has("SECRET")).toBe(true);
  });

  it("已知全局（print/pairs/game）不计入自由变量", () => {
    const body = (astOf(`local function f(a)
print(a)
for k, v in pairs(t) do end
return game:GetService("x")
end`) as any).body[0].body;
    const free = collectFreeVariables(body, ["a"]);
    // t 是外层局部 → 自由变量；print/pairs/game 是已知全局，不计入
    expect(free.has("t")).toBe(true);
    expect(free.has("print")).toBe(false);
    expect(free.has("pairs")).toBe(false);
    expect(free.has("game")).toBe(false);
  });

  it("__ 前缀内部名（dispatch/deadcode）不计入自由变量", () => {
    const body = (astOf(`local function f(a)
__b = 1
return __b + a
end`) as any).body[0].body;
    const free = collectFreeVariables(body, ["a"]);
    expect(free.has("__b")).toBe(false);
  });
});

// ---- 4. identifyVmFunctions ----

describe("selective-vm: identifyVmFunctions", () => {
  it("显式 wantNames 匹配到 AST 节点 + 分配下标", () => {
    const ast = astOf(`local function a() return 1 end
local function b() return 2 end`);
    const { targets, skippedForUpvalues } = identifyVmFunctions(ast, {
      wantNames: new Set(["a"]),
      autoIdentify: false,
    });
    expect(targets.map((t) => t.name)).toEqual(["a"]);
    expect(targets[0]!.index).toBe(0);
    expect(skippedForUpvalues).toEqual([]);
  });

  it("引用 upvalue 的目标被降级（skippedForUpvalues）", () => {
    const ast = astOf(`local function a(x) return x + OUTER end`);
    const { targets, skippedForUpvalues } = identifyVmFunctions(ast, {
      wantNames: new Set(["a"]),
      autoIdentify: false,
    });
    expect(targets).toEqual([]);
    expect(skippedForUpvalues).toEqual(["a"]);
  });

  it("无 wantNames + 关闭自动识别 → 无目标", () => {
    const ast = astOf(`local function loader() return loadstring("x") end`);
    const { targets } = identifyVmFunctions(ast, { autoIdentify: false });
    expect(targets).toEqual([]);
  });

  it("无 wantNames + 自动识别 → 识别关键逻辑函数", () => {
    const ast = astOf(`local function loader(c) return loadstring(c) end
local function ui() print("ui") end`);
    const { targets } = identifyVmFunctions(ast, { autoIdentify: true });
    expect(targets.map((t) => t.name)).toEqual(["loader"]);
  });

  it("有 wantNames 时优先用 wantNames，忽略自动识别", () => {
    const ast = astOf(`local function loader(c) return loadstring(c) end
local function ui() print("ui") end`);
    const { targets } = identifyVmFunctions(ast, {
      wantNames: new Set(["ui"]),
      autoIdentify: true,
    });
    // 显式只标 ui，loader 不进 VM（即使用户没标）
    expect(targets.map((t) => t.name)).toEqual(["ui"]);
  });
});

// ---- 5. buildSyntheticVmSource ----

describe("selective-vm: buildSyntheticVmSource", () => {
  it("生成包含每个 VM 函数 + __vm_dispatch__ 注册的合成源码", () => {
    const ast = astOf(`local function a(x) return x + 1 end
local function b(y) return y * 2 end`);
    const { targets } = identifyVmFunctions(ast, {
      wantNames: new Set(["a", "b"]),
      autoIdentify: false,
    });
    const src = buildSyntheticVmSource(targets);
    expect(src).toContain("local function __vm_f0(x)");
    expect(src).toContain("local function __vm_f1(y)");
    expect(src).toContain(`function ${VM_DISPATCH_NAME}(idx, ...)`);
    expect(src).toContain("if idx == 0 then return __vm_f0(...) end");
    expect(src).toContain("if idx == 1 then return __vm_f1(...) end");
  });

  it("合成源码可被 lexer/parser 解析", () => {
    const ast = astOf(`local function a(x) return x end`);
    const { targets } = identifyVmFunctions(ast, {
      wantNames: new Set(["a"]),
      autoIdentify: false,
    });
    const src = buildSyntheticVmSource(targets);
    expect(() => parse(lex(src))).not.toThrow();
  });
});

// ---- 6. buildStubBody ----

describe("selective-vm: buildStubBody", () => {
  it("生成 return __vm_dispatch__(idx, params...) 的 Block", () => {
    const body = buildStubBody(2, ["a", "b"]);
    expect(body.t).toBe("Block");
    if (body.t !== "Block") return;
    const ret = body.body[0]!;
    expect(ret.t).toBe("Return");
    if (ret.t !== "Return") return;
    const call = ret.values[0]!;
    expect(call.t).toBe("Call");
    if (call.t !== "Call") return;
    expect(call.callee.t).toBe("Ident");
    if (call.callee.t !== "Ident") return;
    expect(call.callee.name).toBe(VM_DISPATCH_NAME);
    // 第一个参数是下标 2，其余是 a, b
    expect(call.args.length).toBe(3);
    expect(call.args[0]!.t).toBe("Number");
  });

  it("vararg 参数映射为 Vararg 节点", () => {
    const body = buildStubBody(0, ["...", "x"]);
    if (body.t !== "Block") return;
    const call = (body.body[0] as Node as any).values[0] as Node;
    if (call.t !== "Call") return;
    expect(call.args[1]!.t).toBe("Vararg");
    expect(call.args[2]!.t).toBe("Ident");
  });

  it("生成的桩函数体可被 emit 渲染", () => {
    const body = buildStubBody(1, ["a"]);
    const src = emit(body);
    expect(src).toContain(VM_DISPATCH_NAME);
  });
});

// ---- 7. mapNameThroughRename ----

describe("selective-vm: mapNameThroughRename", () => {
  it("单段名按 renameMap 映射", () => {
    const m = new Map([["verify_key", "a"]]);
    expect(mapNameThroughRename("verify_key", m)).toBe("a");
  });

  it("未在 map 中的名保持原样", () => {
    const m = new Map([["foo", "b"]]);
    expect(mapNameThroughRename("bar", m)).toBe("bar");
  });

  it("点分 / 方法名各段分别映射，分隔符保留", () => {
    const m = new Map([["obj", "x"], ["method", "y"]]);
    expect(mapNameThroughRename("obj:method", m)).toBe("x:y");
    expect(mapNameThroughRename("obj.method", m)).toBe("x.y");
  });
});

// ---- 8. pipeline 端到端 ----

describe("selective-vm: pipeline selectiveVm 端到端", () => {
  it("无 --@vm + 关闭自动识别 → 退化为普通模式（无 __vm_dispatch__）", () => {
    const src = `local function foo(a, b) return a + b end\nprint(foo(1, 2))`;
    const out = runPipeline(src, {
      seed: 7, selectiveVm: true, vmAutoIdentify: false,
      noFlatten: true, noDeadcode: true,
    }).out;
    expect(out).not.toContain(VM_DISPATCH_NAME);
    expect(out).toContain("CUA混淆器");
  });

  it("--@vm 标记的函数进 VM：输出含 __vm_dispatch__ + VM 运行时", () => {
    const src = `--@vm
local function verify_key(key)
  if key == "secret" then return true end
  return false
end
local function draw_ui()
  print("drawing")
end
print(verify_key("secret"))`;
    const out = runPipeline(src, {
      seed: 7, selectiveVm: true, vmAutoIdentify: false,
    }).out;
    // VM 运行时注册了 __vm_dispatch__
    expect(out).toContain(VM_DISPATCH_NAME);
    // 签名仍在
    expect(out).toContain("CUA混淆器");
    // VM 函数体内的敏感字符串不应明文泄露（D3 加密 + VM 字节码）
    expect(out).not.toContain("secret");
  });

  it("自动识别 loadstring 函数进 VM（无 --@vm 注解）", () => {
    const src = `local function loader(code) return loadstring(code)() end
local function ui() print("ui") end
print("ok")`;
    const out = runPipeline(src, { seed: 7, selectiveVm: true }).out;
    expect(out).toContain(VM_DISPATCH_NAME);
  });

  it("vmAutoIdentify: false 时即使含 loadstring 也不自动进 VM（无注解→普通模式）", () => {
    const src = `local function loader(code) return loadstring(code)() end\nprint("ok")`;
    const out = runPipeline(src, {
      seed: 7, selectiveVm: true, vmAutoIdentify: false,
      noFlatten: true, noDeadcode: true,
    }).out;
    expect(out).not.toContain(VM_DISPATCH_NAME);
  });

  it("引用 upvalue 的 --@vm 函数被降级，不进 VM（避免坏代码）", () => {
    // OUTER 是外层 local，verify 引用它 → upvalue 依赖 → 降级
    const src = `local OUTER = 42
--@vm
local function verify(x) return x + OUTER end
print(verify(1))`;
    const out = runPipeline(src, {
      seed: 7, selectiveVm: true, vmAutoIdentify: false,
      noFlatten: true, noDeadcode: true, noStrings: true,
    }).out;
    // 降级后走普通模式，无 VM dispatch
    expect(out).not.toContain(VM_DISPATCH_NAME);
  });

  it("selectiveVm 输出与普通（非 VM）模式输出不同（确实走了不同路径）", () => {
    const src = `--@vm
local function check(k) return k == "key" end
print(check("x"))`;
    const selective = runPipeline(src, {
      seed: 7, selectiveVm: true, vmAutoIdentify: false,
    }).out;
    const normal = runPipeline(src, { seed: 7, vmAutoIdentify: false }).out;
    expect(selective).not.toBe(normal);
    expect(selective.length).toBeGreaterThan(normal.length);
  });
});
