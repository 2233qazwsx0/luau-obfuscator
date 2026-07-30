// src/cli/decrypt.ts — STUB for v0.1.
//
// Full decryption (per TODO.md H1-H6) lives in the H stages. For now we
// just print the cipher metadata so callers know the obfuscation key shape.
import { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
const program = new Command();
program
    .name("luau-decrypt")
    .description("Decoder (basic-level: STUB — full decoder per TODO.md H1-H6).")
    .requiredOption("-i, --input <file>", "input obfuscated .lua file")
    .option("-o, --out <file>", "output file (default: stdout)");
program.action((opts) => {
    const src = readFileSync(resolve(opts.input), "utf8");
    const out = JSON.stringify({
        version: "0.1-stub",
        notice: "Basic-mode decrypt not implemented. To recover the original strings from a basic obfuscation, re-run the obfuscator with --no-strings on the same input.",
        inputLength: src.length,
        preview: src.slice(0, 200),
    }, null, 2);
    if (opts.out)
        writeFileSync(resolve(opts.out), out, "utf8");
    else
        process.stdout.write(out + "\n");
});
program.parseAsync(process.argv).catch((e) => {
    process.stderr.write(`[fatal] ${e.message}\n`);
    process.exit(1);
});
//# sourceMappingURL=decrypt.js.map