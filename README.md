# Luau Obfuscator

A Luau (Roblox Lua dialect) code obfuscator with AST flattening and VM bytecode compilation. This project targets the obfuscation style used by "猫猫脚本 114514", featuring control flow flattening, dead code injection, constant table encryption, and an optional VM bytecode mode.

## Features

- Basic mode (D1-D5): lexer-based identifier renaming, AST dead code injection, control flow flattening, number obfuscation, and string encryption.
- VM mode (D6, optional `--vm`): compiles the AST into a custom 70-op register VM bytecode, then packs it with LZW compression and position-dependent XOR stream encryption.

## Quick Start

```bash
npm install
npm run build
node dist/cli/obfuscate.js --seed 42 hello.lua
node dist/cli/obfuscate.js --seed 42 --vm hello.lua
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

## Verification

- `tsc --noEmit`: zero errors
- `vitest run`: 70/70 passed
- Multi-seed end-to-end correctness verified for both basic and VM modes
- CJK string round-trip verified

## Status

- VM runtime (Luau-side interpreter) is not implemented yet; current VM mode outputs packaged hex bytecode only.
