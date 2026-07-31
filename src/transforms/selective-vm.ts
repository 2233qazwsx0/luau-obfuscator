// src/transforms/selective-vm.ts — v0.12 Feature #1 + #2: 选择性虚拟化。
//
// 核心思路：从「全量虚拟化」转为「选择性虚拟化」。只把用户标记（--@vm）或
// 自动识别（HttpGet / loadstring / 卡密 / 白名单校验）的关键函数编译进 VM，
// 其余代码走 D1-D5 轻量混淆管线。
//
// 本模块负责「识别 + 拆分」纯逻辑，不直接接触 VM 编译器 / 运行时：
//   1. parseVmAnnotations(src)        — 预扫描源码中的 --@vm 注解，提取目标函数名
//   2. autoIdentifyVmFunctions(ast)   — 启发式扫描函数体，识别关键逻辑函数
//   3. identifyVmFunctions(src, ast)  — 合并 1+2，匹配 AST 节点 + 安全过滤
//   4. buildSyntheticVmSource(...)    — 把所有 VM 函数拼成一段可编译的合成源码
//   5. buildStubBody(idx, params)     — 生成非 VM 侧的 dispatch 桩函数体
//
// 安全过滤：引用了外层局部变量（upvalue）的函数不能独立编译进 VM（合成块里
// 拿不到那些 upvalue），自动降级为非 VM 处理，避免静默产出坏代码。
//
// 命名约定：dispatch 入口叫 __vm_dispatch__（双下划线前后缀），D1 重命名会
// 跳过这类标识符（见 src/transforms/identifier.ts），保证桩函数能正确调用到
// 运行时注册的全局 dispatcher。

import type { Node } from "../parser/parser.js";
import { emit } from "../emit/emitter.js";

/** dispatch 入口名（D1 跳过 __*__ 标识符，不会被重命名）。 */
export const VM_DISPATCH_NAME = "__vm_dispatch__";

/** Function 节点（语句 + 表达式两种变体的并集，共享 params/body）。 */
type AnyFunctionNode = Extract<Node, { t: "Function" }>;

/** 自动识别关键词（函数体命中即视为关键逻辑，优先 VM）。 */
const AUTO_IDENTIFY_IDENT = /^(?:httpget|loadstring|whitelist|verifykey|verify|auth|license|apikey|secret)$/i;
const AUTO_IDENTIFY_STR = [
  "卡密", "白名单", "校验", "verify", "whitelist", "auth", "license",
  "apikey", "secret", "password", "loadstring", "httpget",
];

// ---- 1. --@vm 注解预扫描 ----

/**
 * 预扫描源码，提取所有 `--@vm` 注解所标记的函数名（规范名）。
 *
 * 支持两种写法：
 *   (a) 注解独占一行，紧跟其后的下一个非空非注释行是函数声明：
 *         --@vm
 *         local function verify_key(key) ... end
 *   (b) 注解作为函数声明的行尾注释：
 *         local function verify_key(key) ... end  --@vm
 *
 * 规范名 = `function` 关键字后到 `(` 之前的名字串，例如 `foo` / `obj.method`
 * / `obj:method`。与 canonicalName(astNode) 完全对齐，便于和 AST 节点匹配。
 */
export function parseVmAnnotations(src: string): Set<string> {
  const names = new Set<string>();
  const lines = src.split(/\r?\n/);
  const nameRe = /(?:local\s+)?function\s+([\w.]+(?::\w+)?)/;
  for (let i = 0; i < lines.length; i++) {
    if (!/--\s*@vm\b/.test(lines[i]!)) continue;
    // (b) 同行行尾注解
    const sameLine = lines[i]!.match(nameRe);
    if (sameLine) {
      names.add(sameLine[1]!);
      continue;
    }
    // (a) 向后扫描第一个非空非注释行
    for (let j = i + 1; j < lines.length; j++) {
      const trimmed = lines[j]!.trim();
      if (trimmed === "" || trimmed.startsWith("--")) continue;
      const m = trimmed.match(/^(?:local\s+)?function\s+([\w.]+(?::\w+)?)/);
      if (m) names.add(m[1]!);
      break;
    }
  }
  return names;
}

// ---- 2. AST 函数名规范化 ----

/** 计算 AST Function 语句节点的规范名（与 parseVmAnnotations 对齐）。 */
export function canonicalName(func: Node): string | null {
  if (func.t !== "Function") return null;
  if (!("name" in func) || !func.name) return null;
  const base = func.name.parts.join(".");
  return func.name.method ? `${base}:${func.name.method}` : base;
}

// ---- 3. 函数体扫描（收集标识符 / 字符串 / 自由变量）----

interface BodyScan {
  idents: Set<string>;
  strings: Set<string>;
  declared: Set<string>;
}

/** 递归收集函数体内引用的标识符、字符串字面量，以及内部声明的局部名。 */
function scanBody(node: Node | null | undefined, out: BodyScan): void {
  if (!node) return;
  switch (node.t) {
    case "Ident":
      out.idents.add(node.name);
      return;
    case "String":
      out.strings.add(node.value);
      return;
    case "Local":
      for (const nm of node.names) out.declared.add(nm);
      if (node.values) for (const v of node.values) scanBody(v, out);
      return;
    case "For":
      out.declared.add(node.varName);
      scanBody(node.start, out);
      scanBody(node.stop, out);
      scanBody(node.step, out);
      scanBody(node.block, out);
      return;
    case "ForIn":
      for (const nm of node.names) out.declared.add(nm);
      for (const it of node.iter) scanBody(it, out);
      scanBody(node.block, out);
      return;
    case "Function":
      // 命名函数语句：函数名是外层绑定，不计入本函数体内部声明；
      // 但其参数与函数体需扫描。匿名函数表达式同理扫参数+体。
      if ("name" in node && node.name) {
        // 函数名绑定在外层作用域，这里忽略；参数是函数内局部。
      }
      for (const p of node.params) if (p !== "...") out.declared.add(p);
      scanBody(node.body, out);
      return;
  }
  // 通用子节点遍历
  walkChildren(node, (c) => scanBody(c, out));
}

/** 通用子节点遍历（仅遍历表达式 / 语句层面需要的那部分）。 */
function walkChildren(node: Node, fn: (c: Node) => void): void {
  switch (node.t) {
    case "Block":
      for (const s of node.body) fn(s);
      break;
    case "If":
      for (const b of node.branches) { fn(b.cond); fn(b.block); }
      if (node.else) fn(node.else);
      break;
    case "While": fn(node.cond); fn(node.block); break;
    case "Repeat": fn(node.block); fn(node.cond); break;
    case "Return":
      for (const v of node.values) fn(v);
      break;
    case "Call": fn(node.callee); for (const a of node.args) fn(a); break;
    case "Method": fn(node.callee); for (const a of node.args) fn(a); break;
    case "Do": fn(node.block); break;
    case "Assign":
      for (const t of node.targets) fn(t);
      for (const v of node.values) fn(v);
      break;
    case "Binop": fn(node.lhs); fn(node.rhs); break;
    case "Unop": fn(node.arg); break;
    case "Concat": for (const p of node.parts) fn(p); break;
    case "Index": fn(node.obj); fn(node.index); break;
    case "Table":
      for (const f of node.fields) { if (f.key) fn(f.key); fn(f.value); }
      break;
    case "IfExpr": fn(node.cond); fn(node.then); fn(node.else); break;
    case "Interp": for (const p of node.parts) fn(p); break;
    // Leaf / no-expr nodes: Number, Bool, Nil, String(handled above), Ident(handled above),
    // Vararg, Break, Continue, Goto, Label, TypeDecl, Empty, For(handled), ForIn(handled),
    // Local(handled), Function(handled), While(handled), Repeat(handled), Return(handled).
  }
}

/**
 * 计算函数体的「自由变量」：引用了但既不是参数、也不是函数内部 local、
 * 也不是已知全局 / 保留字 / __ 前缀的标识符。非空 → 该函数依赖外层 upvalue，
 * 不能独立编译进 VM（合成块里拿不到这些绑定），需降级为非 VM。
 */
export function collectFreeVariables(body: Node, params: string[]): Set<string> {
  const scan: BodyScan = { idents: new Set(), strings: new Set(), declared: new Set() };
  for (const p of params) if (p !== "...") scan.declared.add(p);
  scanBody(body, scan);
  const free = new Set<string>();
  for (const name of scan.idents) {
    if (scan.declared.has(name)) continue;
    if (name.startsWith("__")) continue; // __b / __d / __vm_dispatch__ 等内部名
    if (KNOWN_GLOBAL.has(name)) continue;
    if (RESERVED_LUA.has(name)) continue;
    free.add(name);
  }
  return free;
}

const RESERVED_LUA = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
  "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
  "true", "until", "while", "continue", "type", "typeof", "export", "self",
]);
const KNOWN_GLOBAL = new Set([
  "print", "warn", "error", "assert", "tostring", "tonumber", "pairs", "ipairs",
  "next", "select", "pcall", "xpcall", "setmetatable", "getmetatable", "rawget",
  "rawset", "rawequal", "rawlen", "setfenv", "getfenv", "unpack", "loadstring",
  "load", "require", "tick", "time", "wait", "game", "workspace", "script",
  "math", "string", "table", "os", "task", "Instance", "Enum", "Color3", "Vector3",
  "UDim2", "UDim", "CFrame", "Ray", "Region3", "Rect", "TweenInfo", "_G", "_ENV",
  "HttpGet", "httpget", "loadstring",
]);

// ---- 4. 自动识别 ----

/** 判断一个命名函数是否应被自动识别为 VM 候选（关键逻辑函数）。 */
export function isAutoVmCandidate(func: Node): boolean {
  if (func.t !== "Function") return false;
  if (!("name" in func) || !func.name) return false;
  const scan: BodyScan = { idents: new Set(), strings: new Set(), declared: new Set() };
  for (const p of func.params) if (p !== "...") scan.declared.add(p);
  scanBody(func.body, scan);
  for (const id of scan.idents) {
    if (AUTO_IDENTIFY_IDENT.test(id)) return true;
  }
  for (const s of scan.strings) {
    const low = s.toLowerCase();
    for (const kw of AUTO_IDENTIFY_STR) {
      if (low.includes(kw.toLowerCase())) return true;
    }
  }
  return false;
}

/** 遍历 AST，返回所有自动识别为 VM 候选的函数规范名集合。 */
export function autoIdentifyVmFunctions(ast: Node): Set<string> {
  const names = new Set<string>();
  walkNamedFunctions(ast, (fn) => {
    if (isAutoVmCandidate(fn)) {
      const nm = canonicalName(fn);
      if (nm) names.add(nm);
    }
  });
  return names;
}

// ---- 5. 识别合并 + AST 节点匹配 ----

export interface IdentifyOptions {
  /** 用户显式标记的 VM 目标函数规范名集合（已映射到 AST 当前的命名空间，
   *  即已过 D1 重命名）。无注解时传空集合 → 回退自动识别。 */
  wantNames?: Set<string>;
  /** 开启自动识别（无 --@vm 注解时按启发式挑关键逻辑函数）。默认 true。 */
  autoIdentify?: boolean;
}

export interface VmTarget {
  /** 规范名（与 canonicalName 对齐）。 */
  name: string;
  /** AST Function 语句节点。 */
  node: AnyFunctionNode;
  /** 在 VM dispatch 表中的下标（0-based）。 */
  index: number;
}

export interface IdentifyResult {
  /** 最终选定的 VM 目标（已通过 upvalue 安全过滤），按下标排序。 */
  targets: VmTarget[];
  /** 因 upvalue 依赖被降级为非 VM 的函数规范名（用于诊断 / 测试）。 */
  skippedForUpvalues: string[];
}

/**
 * 把规范名按 D1 renameMap 映射到 AST 当前的命名空间。
 *   "verify_key" → renameMap.get("verify_key") ?? "verify_key"
 *   "obj:method" → 各部分分别映射后重组（方法名 / 对象名都可能被重命名）。
 * 调用方（pipeline）在 D1 之后调用，需把 --@vm 注解里的原始名映射到重命名后的名，
 * 才能与 AST 节点的 canonicalName 匹配。
 */
export function mapNameThroughRename(name: string, renameMap: Map<string, string>): string {
  return name.split(/([.:])/).map((part) => {
    if (part === "." || part === ":") return part;
    return renameMap.get(part) ?? part;
  }).join("");
}

/**
 * 识别需要 VM 保护的目标函数。
 *   1. 合并显式标记（wantNames，已映射到 AST 命名空间）+ 自动识别结果
 *   2. 在 AST 中按规范名匹配到具体 Function 节点
 *   3. 安全过滤：跳过引用外层 upvalue 的函数（避免静默产出坏代码）
 *   4. 按源码出现顺序分配 dispatch 下标
 *
 * 注：wantNames 必须已经是 AST 当前命名空间下的名（即 D1 重命名后的）。
 * 调用方应先用 parseVmAnnotations(src) 拿到原始名，再用 mapNameThroughRename
 * 映射后传入。autoIdentify 直接在 AST 上扫描，不受重命名影响（字符串字面量与
 * loadstring 等已知全局不会被 D1 改名）。
 */
export function identifyVmFunctions(ast: Node, opts: IdentifyOptions = {}): IdentifyResult {
  const want = opts.wantNames ?? new Set<string>();
  const auto = opts.autoIdentify !== false ? autoIdentifyVmFunctions(ast) : new Set<string>();
  // 注解标记优先；无注解时回退自动识别结果。有注解则只用注解（用户显式控制）。
  const final = want.size > 0 ? want : auto;

  const targets: VmTarget[] = [];
  const skipped: string[] = [];
  if (final.size === 0) return { targets, skippedForUpvalues: skipped };

  let index = 0;
  walkNamedFunctions(ast, (fn) => {
    if (fn.t !== "Function") return;
    const nm = canonicalName(fn);
    if (!nm || !final.has(nm)) return;
    const params = fn.params.filter((p) => p !== "...");
    const free = collectFreeVariables(fn.body, params);
    if (free.size > 0) {
      // 依赖外层 upvalue，不能独立编译进 VM → 降级。
      skipped.push(nm);
      return;
    }
    targets.push({ name: nm, node: fn, index: index++ });
  });
  return { targets, skippedForUpvalues: skipped };
}

// ---- 6. 合成 VM 源码 + 桩函数体 ----

/**
 * 把所有 VM 目标函数拼成一段可编译的合成源码：
 *   local function __vm_f0(<params>) <body> end
 *   local function __vm_f1(<params>) <body> end
 *   ...
 *   function __vm_dispatch__(idx, ...)
 *     if idx == 0 then return __vm_f0(...) end
 *     if idx == 1 then return __vm_f1(...) end
 *     ...
 *   end
 *
 * 该合成源码会被整体喂给 compileVMWithRuntime，产出单一自包含 VM 运行时。
 * 运行时加载时执行主块 → 定义 __vm_f* 闭包 + 注册全局 __vm_dispatch__。
 * 非 VM 侧的桩函数通过 __vm_dispatch__(idx, ...) 转发调用，调用点无需改动。
 */
export function buildSyntheticVmSource(targets: VmTarget[]): string {
  const parts: string[] = [];
  for (const t of targets) {
    const fn = t.node;
    if (fn.t !== "Function" || !("name" in fn) || !fn.name) continue;
    const params = fn.params.join(", ");
    const bodySrc = emit(fn.body);
    parts.push(`local function __vm_f${t.index}(${params})`);
    parts.push(bodySrc);
    parts.push("end");
  }
  parts.push(`function ${VM_DISPATCH_NAME}(idx, ...)`);
  for (const t of targets) {
    parts.push(`  if idx == ${t.index} then return __vm_f${t.index}(...) end`);
  }
  parts.push("end");
  return parts.join("\n");
}

/**
 * 构造非 VM 侧的桩函数体 AST：`return __vm_dispatch__(idx, <params...>)`。
 * 替换原函数体后，调用点保持不变（函数名/参数签名不变），仅函数体变成
 * 一次 dispatch 转发。params 中的 "..." 映射为 Vararg 节点转发变长参数。
 */
export function buildStubBody(idx: number, params: string[]): Node {
  const args: Node[] = [
    { t: "Number", value: String(idx), line: 0 },
  ];
  for (const p of params) {
    if (p === "...") {
      args.push({ t: "Vararg", line: 0 });
    } else {
      args.push({ t: "Ident", name: p, line: 0 });
    }
  }
  const call: Node = {
    t: "Call",
    callee: { t: "Ident", name: VM_DISPATCH_NAME, line: 0 },
    args,
    line: 0,
  };
  return {
    t: "Block",
    line: 0,
    body: [{ t: "Return", values: [call], line: 0 }],
  };
}

// ---- AST 遍历助手 ----

/** 按源码顺序遍历所有命名 Function 语句节点（不递归进匿名函数表达式体）。 */
function walkNamedFunctions(ast: Node, fn: (n: Node) => void): void {
  const visit = (n: Node): void => {
    if (n.t === "Function" && "name" in n && n.name) {
      fn(n);
      // 仍递归进函数体，处理嵌套命名函数。
      visit(n.body);
      return;
    }
    walkChildren(n, visit);
  };
  visit(ast);
}
