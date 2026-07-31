// src/index.ts - Public entry point. Re-export the pipeline + transforms.
export { runPipeline, obfuscateSource } from "./pipeline/obfuscate.js";
export { lex } from "./parser/lexer.js";
export { parse } from "./parser/parser.js";
export { emit } from "./emit/emitter.js";
export { encryptString, decryptString, buildCipher, deriveStringKey, STRING_KEY_BYTES } from "./transforms/strings.js";
export { renameIdentifiers } from "./transforms/identifier.js";
export { mulberry32 } from "./util/prng.js";
export { flattenAST, flattenRecursive } from "./ir/flatten.js";
export { buildIR, shuffleArray } from "./ir/ir.js";
export { injectDeadcode, injectDeadcodeRecursive } from "./transforms/deadcode.js";
export { compileVM, compileVMWithRuntime, deriveCipherKey } from "./vm/pipeline.js";
export { buildRuntime } from "./vm/runtime-template.js";
export { deriveKeyfuseKey, xor512, genKeyfuseAssembly, computeKeyfuseKhSize } from "./vm/keyfuse.js";
export { deriveRtToken, rtTokenToNibbles, rtMixEncrypt, rtMixDecrypt } from "./vm/rtdeps.js";
//# sourceMappingURL=index.js.map