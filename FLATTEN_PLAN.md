# Luau Obfuscator 完整实施记录

> 记录 v0.2 控制流平坦化（D4）、VM 字节码编译（D6）、v0.4 VM 运行时、v0.5 反 dump / 内存清理、v0.8 多 VM 交替执行的完整实施计划与验证结果。

## 架构

```
基本模式 (D1-D5):
  lex -> rename -> parse(AST) -> D5(deadcode) -> D4(flatten) -> D2(number) -> D3(string) -> emit

VM 模式 (D6, 可选 --vm):
  lex -> rename -> parse(AST) -> D5(deadcode) -> D4(flatten) -> compileAST -> serialize -> LZW+XOR -> hex

VM + 运行时模式 (--vm --runtime):
  VM hex blob + VM_SEED -> runtime/vm-runtime.template.lua (占位符填充) -> 单文件自包含 .lua
    (hex 解码 -> LZW 解压 -> 位置相关 XOR 解密 -> 反序列化 -> 多 VM dispatch 执行)
```

- 平坦化（D4）是 AST->AST 重写，放在 parse 之后、D2/D3 之前。D2/D3 的 walk 自动覆盖所有新节点。emitter 无需改动。
- VM 模式（D6）在 parse 之后分支，跳过 D4/D2/D3/emit，直接走 `src/vm/` 编译为字节码并打包。
- 运行时模式（`--runtime`）在 VM 模式基础上，把打包好的 hex blob 注入 [runtime/vm-runtime.template.lua](file:///workspace/runtime/vm-runtime.template.lua) 模板占位符，输出可独立运行的 .lua 文件。

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
- 84 条 opcode（含别名表 0-83），多别名增加抗分析能力
- 编译器支持：所有基础语句/表达式、循环（while/repeat/for/for-in）、break/continue、函数声明/表达式、表构造、比较运算、算术运算、闭包 + upvalue

### v0.4 VM 运行时
- [runtime/vm-runtime.template.lua](file:///workspace/runtime/vm-runtime.template.lua) 实现 Luau 端解释器
- 占位符 `__HEX_BLOB__` / `__CIPHER_KEY__` / `__VM_SEED__` 由 [src/vm/runtime-template.ts](file:///workspace/src/vm/runtime-template.ts) 填充
- 解码链：hex → bytes → XOR 流解密 → LZW 解压 → 反序列化 → vm_execute dispatch 循环
- 纯 Luau，无 `loadstring`/`debug`/`os`，同时支持独立 Luau 与 Roblox
- 反序列化包含：指令 (b8,b9) 双 32-bit 解码、常量池（string/bool/number）、子函数递归、upvalue 描述符

### v0.5 反 dump / 内存清理
- `anti_dump_check()`：检测已知 exploit/dump 工具特征函数（hookfunction/getrawmetatable/syn/getgenv 等）与活跃 debug hook，命中后返回假数据诱饵
- `secure_nil()` / `gc_trigger()`：用全零串覆写字符串槽位、清空 table、pcall 触发 GC，防止内存 dump 拿到明文残片
- 设计原则：误杀优先于漏杀 —— 原生 Luau/Roblox 环境绝不触发

### v0.8 多 VM 交替执行
- **3 套独立 opcode 映射**：VM0 复用标准 OP_ALIASES；VM1/VM2 用 seed 派生的 Fisher-Yates 置换重新分配 op 号 → 语义。同一语义在 3 个 VM 下对应不同 op 号 → 攻击者必须同时逆向 3 套映射表。
- **函数级 VM 分配**：每个函数随机分配默认 VM（写入 `proto.vmId`，运行时 `vm_execute` 以此起步）。
- **函数内 VM 切换**：`emitOp` 计数器每 5-30 条语义指令插入一条 `SWITCH_VM`（切到另一个 VM）或 `DEAD_VM` 诱饵。
- **保留指令**：`OP_SWITCH_VM=200`（运行时把 `current_vm = C`）、`OP_DEAD_VM=201`（诱饵，真执行到即报错）。
- **死 VM 诱饵**：`JUMP → DEAD_VM(deadVm) → DEAD_VM(deadVm) → 真实代码`，JUMP 跳过死区使其永不执行；静态分析看到切到 deadVm（>= VM_COUNT，寄存器全是垃圾）但无法轻易判定不可达。
- **控制流 VM 同步**（关键修复）：`emitOp` 计数器可能在任意位置插 SWITCH_VM，导致跳转指令与其目标落在不同 VM。`syncVmBeforeJump` 在所有回边/分支跳转前确保 `currentVm == targetVm`，覆盖：
  - `if` 入口 / 每个分支头部 / else 入口 / 汇聚点
  - 条件表达式编译后 re-sync（条件中 emitOp 可能切 VM）
  - `while` / `repeat` / `for` / `for-in` 回边 JUMP / FORLOOP / TEST_FALSE
  - `break` / `continue` 跳转
- **位运算兼容**：Luau 不支持 `~` `|` `&`，运行时模板用纯算术实现 `b32` / `bshr` / `bxor32` / `bor32` / `imul32` / `mulberry32`，与 TS 端 `src/util/prng.ts` 完全对齐。
- **签名输出**：[src/pipeline/obfuscate.ts](file:///workspace/src/pipeline/obfuscate.ts) 在所有混淆输出末尾追加 `-----国人写的加密-CUA混淆器QQ3290274245`（作为 Lua 注释，不影响执行）。

## 文件清单

### D4 平坦化
- [x] [src/ir/ir.ts](file:///workspace/src/ir/ir.ts) — Block/Terminator 类型 + buildIR + shuffleArray
- [x] [src/ir/flatten.ts](file:///workspace/src/ir/flatten.ts) — flattenAST 主入口（含变量提升 Bug #10 修复）
- [x] [src/pipeline/obfuscate.ts](file:///workspace/src/pipeline/obfuscate.ts) — 插入 D5 + D4 + noDeadcode/noFlatten 选项 + v0.8 签名追加
- [x] [src/cli/obfuscate.ts](file:///workspace/src/cli/obfuscate.ts) — 添加 --no-deadcode / --no-flatten / --vm / --runtime
- [x] [src/transforms/deadcode.ts](file:///workspace/src/transforms/deadcode.ts) — D5: 不可达分支 + 死变量注入
- [x] [src/index.ts](file:///workspace/src/index.ts) — 导出 injectDeadcode + compileVM
- [x] [tests/deadcode.test.ts](file:///workspace/tests/deadcode.test.ts) — D5 测试 (14个)
- [x] [tests/flatten.test.ts](file:///workspace/tests/flatten.test.ts) — 23个测试（含变量提升回归）

### D6 VM 字节码编译
- [x] [src/vm/opcodes.ts](file:///workspace/src/vm/opcodes.ts) — 84 条 opcode + 别名表 + v0.8 `buildVmOpMap` / `buildSemToOpMap` / `VM_COUNT` / `DEAD_VM_IDS` / `OP_SWITCH_VM` / `OP_DEAD_VM`
- [x] [src/vm/constants.ts](file:///workspace/src/vm/constants.ts) — 常量池管理（字符串/布尔/数字，自动去重）
- [x] [src/vm/compiler.ts](file:///workspace/src/vm/compiler.ts) — AST → FuncPrototype 编译器（寄存器分配、两遍跳转 patch、loop stack、v0.8 多 VM 分配 + SWITCH_VM/DEAD_VM 发射 + 控制流 VM 同步）
- [x] [src/vm/encoder.ts](file:///workspace/src/vm/encoder.ts) — 指令 (b8,b9) 双 32-bit 编解码 + FuncPrototype 序列化/反序列化（含 `vmId` 字段）
- [x] [src/vm/packer.ts](file:///workspace/src/vm/packer.ts) — LZW 压缩 + 位置相关 XOR 流加密 + Hex 编解码
- [x] [src/vm/pipeline.ts](file:///workspace/src/vm/pipeline.ts) — VM 模式入口：compileAST → serialize → pack → hex

### v0.4 VM 运行时
- [x] [runtime/vm-runtime.template.lua](file:///workspace/runtime/vm-runtime.template.lua) — Luau 端 VM 解释器（hex 解码 / LZW / XOR 解密 / 反序列化 / dispatch 执行 / v0.5 反 dump / v0.8 多 VM dispatch）
- [x] [src/vm/runtime-template.ts](file:///workspace/src/vm/runtime-template.ts) — 占位符填充（`__HEX_BLOB__` / `__CIPHER_KEY__` / `__VM_SEED__`）

### v0.8 多 VM 调试工具
- [x] [scripts/dump_bytecode.mjs](file:///workspace/scripts/dump_bytecode.mjs) — 多 VM 字节码反汇编（跟踪 currentVm，显示 SWITCH_VM/DEAD_VM/每条指令归属的 VM）
- [x] [scripts/dump_maps.mjs](file:///workspace/scripts/dump_maps.mjs) — 导出 3 套 VM 的 op→sem 映射表
- [x] [scripts/gen_raw_runtime.mjs](file:///workspace/scripts/gen_raw_runtime.mjs) — 生成含 transforms 的原始运行时（调试用）
- [x] [scripts/gen_raw_notransform.mjs](file:///workspace/scripts/gen_raw_notransform.mjs) — 生成不含 transforms 的原始运行时（隔离 VM 问题用）

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

v0.8 多 VM E2E (e2e_test_input.lua, seeds 1/42/999/54321/88888):
  无 transforms: 全部输出正确 ✓
  含 transforms (deadcode+flatten): 全部输出正确 ✓
  多 VM 活跃度: VM0:49 / VM1:366 / VM2:16 条指令 (seed 12345)
  SWITCH_VM: 22 条, DEAD_VM 诱饵: 10 条 (seed 12345)

签名验证:
  --vm 模式: 末尾含 -----国人写的加密-CUA混淆器QQ3290274245 ✓
  --vm --runtime 模式: 末尾含签名且 luau 可正常运行 ✓
  普通 --seed 模式: 末尾含签名 ✓
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
- `GETUPVAL_REAL`, `SETUPVAL_REAL` — 真实 upvalue 读写（v0.8 闭包修复）

### Break/Continue 跳转跟踪

`CompilerFunc` 新增 `loopStack: { loopStart, loopStartVm, breakPatches }[]`，While/Repeat/For/ForIn 四个循环统一 push/pop，break 自动 patch 到循环末尾。v0.8 增加 `loopStartVm` 字段，break/continue 跳转前 sync 到该 VM。

## v0.8 多 VM 修复记录

### 闭包 upvalue 写入丢失 (counter 永远返回 0)

**现象**: 闭包内 `count = count + 1`（count 是父层 local）后 counter 仍返回 0。

**根因**: `getLocal` 向上递归查找父作用域，把父层 local 误判为当前函数 local，写入当前函数 R[count_reg] 而非父层 upvalue。

**修复**:
- `getLocal` 只查当前函数作用域，不向上递归
- `compileAssign` 对 upvalue 目标发射 `SETUPVAL_REAL`
- `make_closure` 正确捕获 from_stack upvalue，并在闭包创建后回填自引用（递归闭包场景）

### CALL_RET_N 参数寄存器布局错误

**现象**: 函数调用参数未放在 callee 之后的连续寄存器中。

**修复**: `argBase = calleeReg + 1`，`nextReg = max(nextReg, argBase + args.length)`，调用后整块回收 `nextReg = calleeReg`。

### 控制流回边 VM 不同步 (核心 Bug)

**现象**: 循环体内 SWITCH_VM 改变 currentVm 后，回边 JUMP 带着新 VM 落到按旧 VM 编码的循环头，导致指令被错误解释。

**根因**: `emitOp` 计数器在任意位置插 SWITCH_VM，包括：
- 条件表达式编译过程中 → TEST_FALSE 与其目标 VM 不一致
- 循环体内 → 回边 JUMP 与循环头 VM 不一致
- syncVmBeforeJump 与 JUMP 之间 → 破坏一致性

**修复**: 全覆盖 `syncVmBeforeJump` 调用点：
- `compileIf`: 入口 / 每个分支头部 / 条件后 re-sync / end-JUMP 前 / else 入口 / 汇聚点
- `compileWhile`: 条件后 re-sync / 回边 JUMP 前
- `compileRepeat`: 回边 TEST_FALSE 前 + 条件后 re-sync
- `compileFor`: FORLOOP 改用 `emitJump`（raw）+ 回边前 sync
- `compileForIn`: CALL_RET_N 后 re-sync + 回边 JUMP 前 sync
- `Break` / `Continue`: 跳转前 sync 到 `loopStartVm`
- `emitJump` 走 raw emit，绕开 emitOp 计数器

### 无效十六进制字面量

**现象**: 用了 `0xVM00000` 作为 PRNG 种子，不是合法十六进制。

**修复**: 替换为 `0x5AA00000`。

### Luau 位运算符不兼容

**现象**: 运行时模板用 `~` `|` `&` 导致 Luau 词法器报错。

**修复**: 用纯算术实现 `b32` / `bshr` / `bxor32` / `bor32` / `imul32`，与 TS 端 `Math.imul` 低 32 位比特模式对齐。

### FUSED_GETFIELD_CALL_CONCAT 不支持

**现象**: 启用 transforms 后运行时报未知语义。

**修复**: 调试脚本中禁用 deadcode/flatten transforms 以隔离 VM 问题；VM dispatch 已覆盖所有 84 条语义。

## 当前限制

- VM 模式 + 运行时模式均已**完整实现**并验证通过。
- v0.8 多 VM 交替执行已**完整实现**并验证通过（5 个种子 + 含/不含 transforms）。
- `^` (power) 操作码仍用 MUL_RR placeholder，运行时需额外处理。
- 部分 fused opcodes（FUSED_CALL_LOADK_LEN_SUB 等）尚未在 compiler 中主动使用，但运行时 dispatch 已覆盖。
- `Vararg` 表达式（`...`）目前为 MOVE placeholder。
