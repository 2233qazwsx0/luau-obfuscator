// Dump VM maps from the compiler side for comparison
import { buildVmOpMap } from "../dist/vm/opcodes.js";

const seed = 12345;
for (let vm = 0; vm < 3; vm++) {
  const m = buildVmOpMap(seed, vm);
  console.log(`== VM${vm} map (op -> sem) ==`);
  const keys = Array.from(m.keys()).sort((a, b) => a - b);
  for (let i = 0; i < Math.min(10, keys.length); i++) {
    console.log(`  [${keys[i]}]=${m.get(keys[i])}`);
  }
}
