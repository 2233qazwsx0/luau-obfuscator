# Luau Obfuscator

A Luau (Roblox Lua dialect) code obfuscator with AST flattening and VM bytecode compilation. This project targets the obfuscation style used by "猫猫脚本 114514", featuring control flow flattening, dead code injection, constant table encryption, an optional VM bytecode mode, and **v0.8 multi-VM alternate execution**.

## Features

- **Basic mode (D1-D5)**: lexer-based identifier renaming, AST dead code injection, control flow flattening, number obfuscation, and string encryption.
- **VM mode (D6, optional `--vm`)**: compiles the AST into a custom 70-op register VM bytecode, then packs it with LZW compression and position-dependent XOR stream encryption.
- **Runtime mode (optional `--runtime`)**: emits a self-contained Luau VM runtime template that decodes and executes the packed bytecode on both standalone Luau and Roblox — no `loadstring`/`debug`/`os` required.
- **v0.8 Multi-VM alternate execution**: 3 independent opcode mapping tables, `SWITCH_VM` context switching inside functions, dead-VM decoys, and per-function random VM assignment. Attackers must reverse all 3 opcode tables to recover full logic.
- **Signature output**: appends `-----国人写的加密-CUA混淆器QQ3290274245` at the end of every obfuscated output (as a Lua comment, does not affect execution).
- **Anti-dump / memory wipe (v0.5)**: environment detection for known exploit/dump tools and secure nil-ing of in-memory plaintext residues.

## Quick Start

```bash
npm install
npm run build

# Basic mode
node dist/cli/obfuscate.js --seed 42 hello.lua

# VM bytecode mode (packed hex only)
node dist/cli/obfuscate.js --seed 42 --vm hello.lua

# VM mode + self-contained runtime (runnable on Luau/Roblox)
node dist/cli/obfuscate.js --seed 42 --vm --runtime hello.lua -o hello.obf.lua
luau hello.obf.lua
```

## Architecture

### Basic mode

```
lex -> rename -> parse(AST) -> D5(deadcode) -> D4(flatten) -> D2(number) -> D3(string) -> emit
```

### VM mode

```
lex -> rename -> parse(AST) -> D5(deadcode) -> D4(flatten) -> compileAST -> serialize -> LZW+XOR -> hex
```

### Runtime mode (`--vm --runtime`)

```
VM hex blob  ─┐
              ├─> runtime/vm-runtime.template.lua (placeholders filled) -> single self-contained .lua
VM_SEED      ─┘     (decode -> LZW -> XOR decrypt -> deserialize -> multi-VM dispatch execute)
```

### v0.8 Multi-VM (compiled into every `--vm` output)

```
per-function random VM (0/1/2)
  -> emit 5-30 semantic instructions
  -> SWITCH_VM (or DEAD_VM decoy) -> next VM's opcode map
  -> control flow sync (if/while/repeat/for/for-in/break/continue re-sync to entry VM before back-edges)
```

## Verification

- `tsc --noEmit`: zero errors
- `vitest run`: 70/70 passed
- Multi-seed end-to-end correctness verified for basic, VM, and VM+runtime modes
- CJK string round-trip verified
- v0.8 multi-VM: 5 seeds (1/42/999/54321/88888) all produce correct output; 3 VMs actively used (22 SWITCH_VM + 10 DEAD_VM decoys on a sample input)
- Signature `-----国人写的加密-CUA混淆器QQ3290274245` correctly appended to all `--vm`/`--runtime`/plain outputs

## Status

- VM runtime (Luau-side interpreter) is **implemented** and runs on standalone Luau and Roblox.
- Multi-VM alternate execution (v0.8) is **implemented** and verified.
- See [FLATTEN_PLAN.md](file:///workspace/FLATTEN_PLAN.md) for the full implementation history and bug-fix log.
