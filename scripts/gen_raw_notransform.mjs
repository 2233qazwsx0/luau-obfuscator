// Generate raw runtime WITHOUT deadcode/flatten transforms to isolate multi-VM issues.
import { readFileSync, writeFileSync } from "node:fs";
import { lex } from "../dist/parser/lexer.js";
import { parse } from "../dist/parser/parser.js";
import { compileVMWithRuntime } from "../dist/vm/pipeline.js";

const src = readFileSync(process.argv[2], "utf8");
const seed = Number(process.argv[3] ?? 12345);
const outPath = process.argv[4];

let toks = lex(src);
let ast = parse(toks);
// No deadcode/flatten — just test multi-VM execution directly.

const rt = compileVMWithRuntime(ast, seed, { memwipe: false, antidump: false, frag: false });
writeFileSync(outPath, rt, "utf8");
console.error(`[gen] wrote ${outPath} (${rt.length} bytes)`);
