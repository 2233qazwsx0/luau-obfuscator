// src/pipeline/obfuscate.ts - End-to-end pipeline:
//   source -> lex -> parse (AST) -> D1..D5 transforms (mutate AST)
//         -> emit (re-render) -> string
//
// v0.2: D4 control-flow flattening added between parse and D2/D3.
import { lex } from "../parser/lexer.js";
import { parse } from "../parser/parser.js";
import { emit } from "../emit/emitter.js";
import { buildCipher, deriveStringKey, encryptString } from "../transforms/strings.js";
import { renameIdentifiers } from "../transforms/identifier.js";
import { mulberry32, randInt } from "../util/prng.js";
import { flattenAST, flattenRecursive } from "../ir/flatten.js";
import { injectDeadcode, injectDeadcodeRecursive } from "../transforms/deadcode.js";
import { compileVM, compileVMWithRuntime } from "../vm/pipeline.js";
/** v0.8：混淆器输出末尾的水印签名（Luau 行注释，不影响执行）。 */
const OBFUSCATOR_SIGNATURE = "\n-----国人写的加密-CUA混淆器QQ3290274245";
export function obfuscateSource(src, opts = {}) {
    return runPipeline(src, opts).out;
}
export function runPipeline(src, opts = {}) {
    const seed = opts.seed ?? ((Math.random() * 0xffffffff) >>> 0);
    const cipher = buildCipher(seed);
    // 1. Lex
    const tokens = lex(src);
    // 2. Identifier renaming (token-level - works on raw tokens before parse)
    let working = tokens;
    let renameMap = new Map();
    if (!opts.noRename) {
        const r = renameIdentifiers(working, seed);
        working = r.tokens;
        renameMap = r.map;
    }
    // 3. Parse the (renamed) tokens into AST
    let ast;
    try {
        ast = parse(working);
    }
    catch (e) {
        throw new Error(`parse error: ${e.message}`);
    }
    // 3.5. Dead code injection (D5): AST -> AST rewrite.
    // v0.6: 在 VM 编译前执行，让字节码里跑的也是含死代码的混淆版本。
    // Runs before D4 so dead code nodes get flattened into dispatch cases.
    // v0.6 F2: recursiveDeadcode 默认开启；每个作用域独立注入 + 不透明谓词包裹。
    if (!opts.noDeadcode) {
        if (opts.recursiveDeadcode !== false) {
            ast = injectDeadcodeRecursive(ast, seed);
        }
        else {
            ast = injectDeadcode(ast, seed);
        }
    }
    // 3.6. Control-flow flattening (D4): AST -> AST rewrite.
    // v0.6: 在 VM 编译前执行。攻击者解字节码后还要再逆向一层 D4 才能还原原始控制流。
    // Runs before VM compile / D2/D3 so the walk passes cover all new dispatch nodes.
    // v0.6 F1: recursiveFlatten 默认开启；每个函数作用域独立生成 dispatch。
    if (!opts.noFlatten) {
        if (opts.recursiveFlatten !== false) {
            ast = flattenRecursive(ast, seed);
        }
        else {
            ast = flattenAST(ast, seed);
        }
    }
    // If VM mode requested, branch here: compile to bytecode, skip D2/D3/emit.
    // v0.6: VM 编译器现在接收的是已经经过 D1+D5+D4 混淆的 AST，字节码内嵌混淆代码。
    if (opts.vm) {
        if (opts.runtime) {
            // v0.4: wrap bytecode in Luau runtime template → executable script
            // v0.5/v0.7: pass runtime-protection options through to the template builder.
            const rtOpts = {
                memwipe: !opts.noMemwipe,
                antidump: !opts.noAntidump,
                frag: !opts.noFrag,
                keyfuse: !opts.noKeyfuse,
                dynamicAntidump: !opts.noDynamicAntidump,
                rtDeps: !opts.noRtDeps,
            };
            const runtimeSrc = compileVMWithRuntime(ast, seed, rtOpts);
            // Self-obfuscate the runtime template through the D1-D3 pipeline only.
            // The runtime template has many complex function bodies with early returns
            // inside nested If blocks. Applying D4 (flatten) or D5 (dead code) to
            // such code can produce unbalanced if/end (see D4/D5 bugs on complex ASTs).
            // Skipping D4/D5 here is safe — the bytecode INSIDE the blob is already
            // protected by D1+D5+D4+F3+F4+F5, while the outer template wrapper only
            // handles blob loading / decoding / dispatch.
            const selfSeed = (seed ^ 0x5E1FA0) >>> 0;
            const selfResult = runPipeline(runtimeSrc, {
                seed: selfSeed,
                noRename: opts.noRename,
                noNumbers: opts.noNumbers,
                noStrings: opts.noStrings,
                noFlatten: true, // outer template: skip D4
                noDeadcode: true, // outer template: skip D5
                minify: opts.minify,
                _internal: true, // 递归自调用：签名由外层统一追加，避免重复
            });
            // v0.8：在最终可执行脚本末尾追加水印签名（顶层调用才加）。
            const out = opts._internal ? selfResult.out : selfResult.out + OBFUSCATOR_SIGNATURE;
            return { out, cipher: selfResult.cipher, nameMap: renameMap };
        }
        const vmResult = compileVM(ast, seed);
        return { out: vmResult.hex, cipher, nameMap: renameMap, vmHex: vmResult.hex };
    }
    // 4. Number obfuscation: walk AST, attach __obf meta on Number nodes
    if (!opts.noNumbers) {
        ast = walk(ast, (n) => {
            if (n.t === "Number") {
                // @ts-expect-error meta channel
                if (!n.__obf) {
                    const val = Number(n.value);
                    if (Number.isFinite(val)) {
                        const rng = mulberry32(seed ^ 0x9e3779b9);
                        const k = (randInt(rng, 0x7fffffff) | 1) >>> 0;
                        // @ts-expect-error
                        n.__obf = { kind: "bitxor", key: k, n: val };
                    }
                }
            }
            return n;
        });
    }
    // 5. String encryption: walk AST, encrypt each String node with an independent
    //    6-byte key + LCG rolling factor (v0.10). Key is attached to node meta so
    //    the emitter can inline it without consulting the cipher pool.
    if (!opts.noStrings) {
        ast = walk(ast, (n) => {
            if (n.t === "String" && n.value.length > 0) {
                // Skip identifiers / keys that are very short - many engines treat them
                // as lookups and short strings hurt decode perf without hiding much.
                const rng = mulberry32(seed ^ 0x12345678 ^ n.value.length);
                const skip = n.value.length <= 1 || (n.value.length <= 2 && rng() < 0.6);
                if (skip)
                    return n;
                // @ts-expect-error - meta channel
                if (n.__str_hex)
                    return n;
                const strId = cipher.pool.length;
                const key = deriveStringKey(seed, strId);
                const blob = encryptString(n.value, key);
                cipher.pool.push({ id: strId, hex: blob, key });
                // @ts-expect-error
                n.__str_hex = blob;
                // @ts-expect-error
                n.__str_id = strId;
                // @ts-expect-error
                n.__str_key = key;
            }
            return n;
        });
    }
    // 6. Emit
    let out = emit(ast);
    // 7. Minify (optional)
    if (opts.minify) {
        out = out.split("\n").filter((l) => l.trim() !== "").join(" ");
    }
    // 8. v0.8：顶层调用在输出末尾追加水印签名（递归自调用 _internal 不加）。
    if (!opts._internal) {
        out += OBFUSCATOR_SIGNATURE;
    }
    return { out, cipher, nameMap: renameMap };
}
// ---------- AST walker (pre-order) ----------
function walk(ast, fn) {
    const visit = (n) => {
        const u = fn(n);
        // recursively walk children in place
        switch (u.t) {
            case "Block":
                u.body = u.body.map(visit);
                break;
            case "Local":
                if (u.values)
                    u.values = u.values.map(visit);
                break;
            case "Assign":
                u.targets = u.targets.map(visit);
                u.values = u.values.map(visit);
                break;
            case "If":
                u.branches = u.branches.map((b) => ({ cond: visit(b.cond), block: visit(b.block) }));
                if (u.else)
                    u.else = visit(u.else);
                break;
            case "While":
                u.cond = visit(u.cond);
                u.block = visit(u.block);
                break;
            case "Repeat":
                u.block = visit(u.block);
                u.cond = visit(u.cond);
                break;
            case "For":
                u.start = visit(u.start);
                u.stop = visit(u.stop);
                if (u.step)
                    u.step = visit(u.step);
                u.block = visit(u.block);
                break;
            case "ForIn":
                u.iter = u.iter.map(visit);
                u.block = visit(u.block);
                break;
            case "Function":
                u.body = visit(u.body);
                break;
            case "Return":
                u.values = u.values.map(visit);
                break;
            case "Call":
                u.callee = visit(u.callee);
                u.args = u.args.map(visit);
                break;
            case "Method":
                u.callee = visit(u.callee);
                u.args = u.args.map(visit);
                break;
            case "Do":
                u.block = visit(u.block);
                break;
            case "Index":
                u.obj = visit(u.obj);
                u.index = visit(u.index);
                break;
            case "Unop":
                u.arg = visit(u.arg);
                break;
            case "Binop":
                u.lhs = visit(u.lhs);
                u.rhs = visit(u.rhs);
                break;
            case "Concat":
                u.parts = u.parts.map(visit);
                break;
            case "Table":
                u.fields = u.fields.map((f) => ({ key: f.key ? visit(f.key) : null, value: visit(f.value) }));
                break;
            // v0.1.1 new node types
            case "IfExpr":
                u.cond = visit(u.cond);
                u.then = visit(u.then);
                u.else = visit(u.else);
                break;
            case "Interp":
                u.parts = u.parts.map(visit);
                break;
            // Goto, Label, TypeDecl, Empty, Break, Continue - no child expressions
        }
        return u;
    };
    return visit(ast);
}
//# sourceMappingURL=obfuscate.js.map