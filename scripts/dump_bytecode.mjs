// Dump bytecode for the closure test to inspect VM assignment + instructions.
import { readFileSync } from "node:fs";
import { lex } from "../dist/parser/lexer.js";
import { parse } from "../dist/parser/parser.js";
import { injectDeadcode } from "../dist/transforms/deadcode.js";
import { flattenAST } from "../dist/ir/flatten.js";
import { compileAST } from "../dist/vm/compiler.js";
import { Op, OP_SWITCH_VM, OP_DEAD_VM, buildVmOpMap } from "../dist/vm/opcodes.js";

const src = readFileSync(process.argv[2], "utf8");
const seed = Number(process.argv[3] ?? 12345);
const useTransforms = process.argv[4] === "transforms";

let toks = lex(src);
let ast = parse(toks);
if (useTransforms) {
  ast = injectDeadcode(ast, seed);
  ast = flattenAST(ast, seed);
}

const proto = compileAST(ast, seed);

// Build all VM maps: maps[v] is op -> semantic string
const maps = [0,1,2].map(v => {
  const m = new Map();
  for (const [k, val] of buildVmOpMap(seed, v)) m.set(k, val);
  return m;
});

function dumpProto(p, depth = 0, name = "main") {
  const pad = "  ".repeat(depth);
  console.log(`${pad}== ${name} vmId=${p.vmId} params=${p.paramCount} upvals=${p.upvalues.length}`);
  p.upvalues.forEach((uv, i) => {
    console.log(`${pad}  upval[${i}] fromStack=${uv.fromStack} idx=${uv.index}`);
  });
  // Walk instructions tracking current VM
  let curVm = p.vmId || 0;
  p.instructions.forEach((ins, i) => {
    let sem;
    if (ins.op === OP_SWITCH_VM) {
      sem = `SWITCH_VM->VM${ins.C}`;
      curVm = ins.C;
    } else if (ins.op === OP_DEAD_VM) {
      sem = `DEAD_VM(vmId=${ins.C})`;
    } else {
      const s = maps[curVm].get(ins.op);
      sem = `VM${curVm}:${s ?? "???"}`;
    }
    console.log(`${pad}  [${i}] op=${ins.op} A=${ins.A} B=${ins.B} C=${ins.C} D=${ins.D} mode=${ins.mode}  ; ${sem}`);
  });
  p.subFunctions.forEach((s, i) => dumpProto(s, depth + 1, `sub#${i}`));
}

dumpProto(proto);
