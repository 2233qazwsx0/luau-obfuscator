// Generate the raw multi-VM runtime (pre-self-obfuscation) for direct luau testing.
// Uses compiled dist/ output.
import { readFileSync, writeFileSync } from "node:fs";
import { lex } from "../dist/parser/lexer.js";
import { parse } from "../dist/parser/parser.js";
import { injectDeadcode } from "../dist/transforms/deadcode.js";
import { flattenAST } from "../dist/ir/flatten.js";
import { compileVMWithRuntime } from "../dist/vm/pipeline.js";

const src = readFileSync(process.argv[2], "utf8");
const seed = Number(process.argv[3] ?? 12345);
const outPath = process.argv[4];

let toks = lex(src);
let ast = parse(toks);
ast = injectDeadcode(ast, seed);
ast = flattenAST(ast, seed);

const rt = compileVMWithRuntime(ast, seed, { memwipe: false, antidump: false, frag: false });
writeFileSync(outPath, rt, "utf8");
console.error(`[gen] wrote ${outPath} (${rt.length} bytes)`);
