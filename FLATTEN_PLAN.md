# Luau Obfuscator 完整实施记录

> 记录 v0.2 控制流平坦化（D4）以及后续 VM 字节码编译（D6）的完整实施计划与验证结果。

## 架构

```
基本模式 (D1-D5):
  lex -> rename -> parse(AST) -> D5(deadcode) -> D4(flatten) -> D2(number) -> D3(string) -> emit

VM 模式 (D6, 可选 --vm):
  lex -> rename -> parse(AST) -> D5(deadcode) -> D4(flatten) -> compileAST -> serialize -> LZW+XOR -> hex
```

- 平坦化（D4）是 AST->AST 重写，放在 parse 之后、D2/D3 之前。D2/D3 的 walk 自动覆盖所有新节点。emitter 无需改动。
- VM 模式（D6）在 parse 之后分支，跳过 D4/D2/D3/emit，直接走 `src/vm/` 编译为字节码并打包。

## 设计要点

### D4 控制流平坦化
- 只平坦化顶层 block，函数体不拆，内层 if/while/for 保持原样
- dispatch 变量 `__b`，初始值为第一个 state ID
- `while true do ... if __b == -1 then break end` 结构
- state IDs 由 mulberry32(seed) shuffle 生成，保证确定性
- 每条语句独立成块，最大化 dispatch 随机性
- 非_exit块数量 <= 1 时不平坦化（单语句不值得平化）

### VM 字节码编译 (D6)
- AST → FuncPrototype（寄存器-based bytecode）→ 二进制序列化 → LZW 压缩 → 位置相关 XOR 流加密 → Hex
- 70-op VM，opcode 别名表（0-71）增加抗分析能力
- 编译器支持：所有基础语句/表达式、循环（while/repeat/for/for-in）、break/continue、函数声明/表达式、表构造、比较运算、算术运算
- 输出为纯 hex 字符串，后续需接入 Luau 端 VM 运行时（TODO）

## 文件清单

### D4 平坦化
- [x] `src/ir/ir.ts` — Block/Terminator 类型 + buildIR + shuffleArray
- [x] `src/ir/flatten.ts` — flattenAST 主入口（含变量提升 Bug #10 修复）
- [x] `src/pipeline/obfuscate.ts` — 插入 D5 + D4 + noDeadcode/noFlatten 选项
- [x] `src/cli/obfuscate.ts` — 添加 --no-deadcode / --no-flatten / --vm
- [x] `src/transforms/deadcode.ts` — D5: 不可达分支 + 死变量注入
- [x] `src/index.ts` — 导出 injectDeadcode + compileVM
- [x] `tests/deadcode.test.ts` — D5 测试 (14个)
- [x] `tests/flatten.test.ts` — 23个测试（含变量提升回归）

### D6 VM 字节码编译
- [x] `src/vm/opcodes.ts` — 70+ opcode 定义 + 别名表（新增 MUL_RR, DIV_RR, SETTABLE, TEST_LT_RR, TEST_LE_RR）
- [x] `src/vm/constants.ts` — 常量池管理（字符串/布尔/数字，自动去重）
- [x] `src/vm/compiler.ts` — AST → FuncPrototype 编译器（寄存器分配、两遍跳转 patch、loop stack）
- [x] `src/vm/encoder.ts` — 指令 (b8,b9) 双 32-bit 编解码 + FuncPrototype 二进制序列化/反序列化
- [x] `src/vm/packer.ts` — LZW 压缩 + 位置相关 XOR 流加密 + Hex 编解码
- [x] `src/vm/pipeline.ts` — VM 模式入口：compileAST → serialize → pack → hex

## 验证结果

```
tsc --noEmit: zero errors
npm test (vitest run): 70/70 passed
  - tests/lexer.test.ts: 4 passed
  - tests/roundtrip.test.ts: 3 passed
  - tests/parser.test.ts: 19 passed
  - tests/obfuscate.test.ts: 7 passed
  - tests/flatten.test.ts: 23 passed (6 buildIR + 3 shuffleArray + 10 flattenAST + 4 pipeline)
  - tests/deadcode.test.ts: 14 passed (determinism, probability, __d prefix, flatten integration)

Luau 0.601 round-trip (基本模式, CJK strings, --seed 42):
  Input:  print("cn中国，，，。。。!-:（~）") + print("中文中文")
  Output: cn中国，，，。。。!-:（~） + 中文中文  ✓ EXIT: 0

Multi-seed E2E (hello.lua, seeds 1/7/42/100/999/2024/12345/67890):
  基本模式: All seeds produce correct output. ✓
  VM 模式:  compile→pack→unpack→deserialize round-trip 全通过 (8 seeds)
  
VM 模式示例 (print("fuck"), local yuan = 123, --seed 42):
  Hex 产物: F7FCF9F9FC0201FF... (230 bytes)
  Round-trip 解包后: 5 instructions, 3 constants (print, "fuck", 123) ✓
```

## Bug 修复记录

### Bug #9: jump target 指向自身导致无限循环 (2025-07-27)

**现象**: 混淆后的 Luau 代码在 5 秒后超时被杀（exit code 143）。

**根因**: `src/ir/ir.ts` 中 `buildIR` 的 `flush({ type: "jump", target: blockId })`
在 `default` 分支里，`blockId` 是当前 block 被 flush 后分配的新 id。
所以每个 block 的 terminator.target 指向的是**自己**，而非下一个 block。
结果是 `while true do` dispatch 循环中每个 case 执行完后跳回自身 → 无限循环。

**修复**: 将所有 `flush({ type: "jump", target: blockId })` 改为
`flush({ type: "jump", target: blockId + 1 })`，使 jump 指向下一个 block。

**验证**: 修复后 Luau 0.601 执行正确，tests 通过。

### Bug #10: 跨 dispatch case 的局部变量作用域问题 (2025-07-27)

**现象**: `hello.lua` 在启用 flatten（D4）后运行报错 `invalid 'for' limit (number expected, got nil)`。

**根因**: `flattenAST` 将顶层语句拆分成独立 dispatch case，每个 case 是独立作用域。`local a = "hello"` 在 case 0 声明，`for i = 1, b do print(a)` 在 case 3 无法访问 `a`。

**修复**: 在 `while true do` 之前预声明所有顶层 `local` 变量名。

**验证**: 修复后 hello.lua / luau-features.lua / CJK 字符串 round-trip 通过。

## 编译器修复记录 (v0.2 VM 接入)

### Compiler 操作码补齐

在接入 VM 前，compiler.ts 中多个关键运算为 placeholder，已全部修复：

| 操作 | 修复前 | 修复后 |
|------|--------|--------|
| `*` (MUL) | `ADD_RR` placeholder | `MUL_RR` |
| `/` `//` (DIV) | `MOD_RR` placeholder | `DIV_RR` |
| `==` | 错误的 TEST_EQ_K 用法 | SUB + TEST_FALSE |
| `~=` `<` `>` `<=` `>=` | 全部 nil placeholder | 基于 SUB/TEST_LT_RR 的正确实现 |
| `tbl[k] = v` (SETTABLE) | 空实现（free registers） | `Op.SETTABLE` 发射 |
| 表构造 `{}` | 空实现 | 逐字段 SETTABLE |
| `break` / `continue` | 无跳转目标 | loopStack 自动 patch |

### 新增 Op 枚举

- `MUL_RR`, `DIV_RR` — 算术乘除
- `SETTABLE` — 表字段写入
- `TEST_LT_RR`, `TEST_LE_RR` — 寄存器间比较

### Break/Continue 跳转跟踪

`CompilerFunc` 新增 `loopStack: { loopStart, breakPatches }[]`，While/Repeat/For/ForIn 四个循环统一 push/pop，break 自动 patch 到循环末尾。

## 当前限制

- VM 模式仅输出 hex 字节码，**Luau 端 VM 运行时尚未实现**（需实现 b3() 解码器 + bg() 执行循环 + LZW/N() 解码器 + aT() XOR 解密）
- `^` (power) 操作码仍用 MUL_RR placeholder，运行时需额外处理
- 部分 fused opcodes（FUSED_CALL_LOADK_LEN_SUB 等）尚未在 compiler 中使用
- `Vararg` 表达式（`...`）目前为 MOVE placeholder
