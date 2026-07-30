// src/cli/obfuscate.ts - Basic-level CLI entry (v0.1) + flatten (v0.2) + VM runtime (v0.4).
import { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { runPipeline } from "../pipeline/obfuscate.js";

const program = new Command();
program
  .name("luau-obfuscate")
  .description("Luau obfuscator (D1 identifier + D2 number + D3 string XOR + D4 flatten + VM).")
  .requiredOption("-i, --input <file>", "input .lua file")
  .option("-o, --out <file>", "output file (default: stdout)")
  .option("-s, --seed <number>", "PRNG seed for key chain (default: random)", "0")
  .option("--minify", "emit single-line output", false)
  .option("--no-rename", "disable identifier renaming")
  .option("--no-numbers", "disable bitxor number obfuscation")
  .option("--no-strings", "disable XOR string encryption")
  .option("--no-flatten", "disable control-flow flattening")
  .option("--no-deadcode", "disable dead code injection")
  .option("--vm", "VM bytecode mode: AST → bytecode → LZW+XOR → hex (experimental)")
  .option("--runtime", "wrap VM bytecode in Luau runtime template (implies --vm, v0.4)")
  .option("--no-memwipe", "disable runtime memory wiping (secure_nil + GC, v0.5)")
  .option("--no-antidump", "disable anti-dump decoy blob (v0.5)");

program.action((opts) => {
  const src = readFileSync(resolve(opts.input), "utf8");
  const seed = opts.seed && opts.seed !== "0" ? Number(opts.seed) : undefined;
  const { out } = runPipeline(src, {
    seed,
    minify: opts.minify,
    noRename: opts.rename === false,
    noNumbers: opts.numbers === false,
    noStrings: opts.strings === false,
    noFlatten: opts.flatten === false,
    noDeadcode: opts.deadcode === false,
    vm: opts.vm === true || opts.runtime === true,
    runtime: opts.runtime === true,
    noMemwipe: opts.memwipe === false,
    noAntidump: opts.antidump === false,
  });
  if (opts.out) {
    writeFileSync(resolve(opts.out), out, "utf8");
    process.stderr.write(`[ok] wrote ${opts.out} (${out.length} bytes)\n`);
  } else {
    process.stdout.write(out + "\n");
  }
});

program.parseAsync(process.argv).catch((e: Error) => {
  process.stderr.write(`[fatal] ${e.message}\n`);
  process.exit(1);
});
