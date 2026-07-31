// src/emit/emitter.ts — Render the AST back into Luau source.
//
// Important: the AST nodes carry a `meta` field written by the transforms
// pipeline (number-key on `Number` nodes, replacement blob + per-string key
// on `String`). We honor those during emission so the obfuscated form comes
// out correctly.
//
// v0.12 Feature #8: 字符串解密器全局复用。之前每条加密字符串内联一份完整
// IIFE（含 LCG 状态、循环、string.char 拼接），代码体积膨胀且每条字符串
// 重复定义闭包。现在改为：在输出顶部定义一次 `_S(K, H)` 解密函数，每条
// 字符串只发射 `_S({key}, "hex")` 调用。解密逻辑与原 IIFE 完全一致
// （6 字节 key + LCG 滚动因子），只是定义复用。
import { BIT32_POLYFILL } from "./bit32_polyfill.js";
/**
 * v0.12 Feature #8: 全局共享的字符串解密器。
 * 与 transforms/strings.ts encryptString 完全对齐：
 *   R_0 = K[1] XOR K[6]
 *   cipher[i] = (plain[i] ^ ((K[(i%6)+1] + i) & 0xff) ^ (R & 0xff)) & 0xff
 *   R_{n+1} = (R * 1664525 + 1013904223) % 2^32
 * 参数：K = 6 字节密钥数组（1-indexed Lua），H = hex 字符串。
 * 依赖：_B（bit32 polyfill，已在 BIT32_POLYFILL 中定义）。
 */
const STRING_DECRYPTOR_HELPER = [
    "local function _S(K,H)",
    "  local O=\"\"",
    "  local R=_B(K[1],K[6])",
    "  for i=1,#H,2 do",
    "    local j=(i+1)/2-1",
    "    O=O..string.char((_B(_B(tonumber(H:sub(i,i+1),16),((K[(j%6)+1]+j)%256)),(R%256)))%256)",
    "    R=(R*1664525+1013904223)%4294967296",
    "  end",
    "  return O",
    "end",
].join("\n");
export function emit(program) {
    const ctx = { indent: 0, out: [BIT32_POLYFILL], needsStringHelper: false };
    emitNode(ctx, program);
    // v0.12 Feature #8: 若有加密字符串，在 BIT32_POLYFILL 之后插入共享解密器。
    // _S 依赖 _B，必须放在 _B 定义之后；放在所有用户代码之前避免被局部覆盖。
    if (ctx.needsStringHelper) {
        ctx.out.splice(1, 0, STRING_DECRYPTOR_HELPER);
    }
    return ctx.out.join("\n");
}
function nl(ctx, n = 1) { ctx.out.push(""); void n; }
function ind(ctx) { return "    ".repeat(ctx.indent); }
function emitNode(ctx, n) {
    switch (n.t) {
        case "Block":
            for (let i = 0; i < n.body.length; i++) {
                const s = n.body[i];
                if (s.t === "Local" || s.t === "Function" || s.t === "Assign" || s.t === "If") {
                    if (i > 0)
                        nl(ctx);
                }
                emitNode(ctx, s);
            }
            return;
        case "Local": {
            const nameParts = n.names.map((nm, i) => {
                const tp = n.types[i];
                return tp ? `${nm}: ${tp}` : nm;
            });
            ctx.out.push(ind(ctx) + `local ${nameParts.join(", ")}` +
                (n.values ? ` = ${n.values.map((v) => exprToLuau(ctx, v)).join(", ")}` : ""));
            return;
        }
        case "Assign":
            ctx.out.push(ind(ctx) + n.targets.map((t) => exprToLuau(ctx, t)).join(", ") +
                ` = ${n.values.map((v) => exprToLuau(ctx, v)).join(", ")}`);
            return;
        case "If": {
            const head = `if ${exprToLuau(ctx, n.branches[0].cond)} then`;
            ctx.out.push(ind(ctx) + head);
            ctx.indent++;
            emitNode(ctx, n.branches[0].block);
            ctx.indent--;
            for (let i = 1; i < n.branches.length; i++) {
                ctx.out.push(ind(ctx) + `elseif ${exprToLuau(ctx, n.branches[i].cond)} then`);
                ctx.indent++;
                emitNode(ctx, n.branches[i].block);
                ctx.indent--;
            }
            if (n.else) {
                ctx.out.push(ind(ctx) + "else");
                ctx.indent++;
                emitNode(ctx, n.else);
                ctx.indent--;
            }
            ctx.out.push(ind(ctx) + "end");
            return;
        }
        case "While":
            ctx.out.push(ind(ctx) + `while ${exprToLuau(ctx, n.cond)} do`);
            ctx.indent++;
            emitNode(ctx, n.block);
            ctx.indent--;
            ctx.out.push(ind(ctx) + "end");
            return;
        case "Repeat":
            ctx.out.push(ind(ctx) + "repeat");
            ctx.indent++;
            emitNode(ctx, n.block);
            ctx.indent--;
            ctx.out.push(ind(ctx) + `until ${exprToLuau(ctx, n.cond)}`);
            return;
        case "For": {
            const varPart = n.varType ? `${n.varName}: ${n.varType}` : n.varName;
            ctx.out.push(ind(ctx) + `for ${varPart} = ${exprToLuau(ctx, n.start)}, ${exprToLuau(ctx, n.stop)}` +
                (n.step ? `, ${exprToLuau(ctx, n.step)}` : "") + " do");
            ctx.indent++;
            emitNode(ctx, n.block);
            ctx.indent--;
            ctx.out.push(ind(ctx) + "end");
            return;
        }
        case "ForIn": {
            const nameParts = n.names.map((nm, i) => {
                const tp = n.types[i];
                return tp ? `${nm}: ${tp}` : nm;
            });
            ctx.out.push(ind(ctx) + `for ${nameParts.join(", ")} in ${n.iter.map((i) => exprToLuau(ctx, i)).join(", ")} do`);
            ctx.indent++;
            emitNode(ctx, n.block);
            ctx.indent--;
            ctx.out.push(ind(ctx) + "end");
            return;
        }
        case "Function": {
            if ("name" in n && n.name) {
                const paramStr = n.params.map((p, i) => {
                    const tp = n.paramTypes[i];
                    return tp ? `${p}: ${tp}` : p;
                }).join(", ");
                const retStr = n.retType ? `: ${n.retType}` : "";
                const fn = `function ${n.name.parts.join(".")}${n.name.method ? ":" + n.name.method : ""}(${paramStr})${retStr}`;
                ctx.out.push(ind(ctx) + fn);
                ctx.indent++;
                emitNode(ctx, n.body);
                ctx.indent--;
                ctx.out.push(ind(ctx) + "end");
            }
            return;
        }
        case "Return":
            ctx.out.push(ind(ctx) + (n.values.length === 0 ? "return" : `return ${n.values.map((v) => exprToLuau(ctx, v)).join(", ")}`));
            return;
        case "Call":
            ctx.out.push(ind(ctx) + exprToLuau(ctx, n));
            return;
        case "Method":
            ctx.out.push(ind(ctx) + exprToLuau(ctx, n));
            return;
        case "Do":
            ctx.out.push(ind(ctx) + "do");
            ctx.indent++;
            emitNode(ctx, n.block);
            ctx.indent--;
            ctx.out.push(ind(ctx) + "end");
            return;
        case "Break":
            ctx.out.push(ind(ctx) + "break");
            return;
        case "Continue":
            ctx.out.push(ind(ctx) + "continue");
            return;
        case "Goto":
            ctx.out.push(ind(ctx) + `goto ${n.label}`);
            return;
        case "Label":
            ctx.out.push(ind(ctx) + `::${n.name}::`);
            return;
        case "TypeDecl":
            ctx.out.push(ind(ctx) + `${n.exported ? "export " : ""}type ${n.name} = ${n.body}`);
            return;
        case "Empty":
            return;
        default:
            ctx.out.push(ind(ctx) + exprToLuau(ctx, n));
            return;
    }
}
function exprToLuau(ctx, e) {
    switch (e.t) {
        case "Nil": return "nil";
        case "Bool": return e.value ? "true" : "false";
        case "Number": {
            // @ts-expect-error — meta channel for number obfuscation
            const meta = e.__obf;
            if (meta && meta.kind === "bitxor") {
                const k = meta.key;
                const inner = (Math.floor(meta.n) ^ k) >>> 0;
                return `(_B(${inner}, ${k}) + (${meta.n - ((Math.floor(meta.n) ^ k) >>> 0 ^ k)}))`;
            }
            return e.value;
        }
        case "String": {
            // @ts-expect-error — meta channel for string obfuscation
            const blob = e.__str_hex;
            // @ts-expect-error
            const key = e.__str_key;
            if (blob && key) {
                const keyLit = `{${key.join(",")}}`;
                // v0.12 Feature #8: 调用全局共享解密器 _S（定义在输出顶部），
                // 替代每条字符串内联一份完整 IIFE。解密逻辑完全一致，仅定义复用。
                // 原 IIFE 约 280 字符/条；新形式约 18 字符/条 + 一次 helper 定义。
                ctx.needsStringHelper = true;
                return `_S(${keyLit},"${blob}")`;
            }
            return JSON.stringify(e.value);
        }
        case "Ident": return e.name;
        case "Vararg": return "...";
        case "Index":
            return `${exprToLuau(ctx, e.obj)}[${exprToLuau(ctx, e.index)}]`;
        case "Unop":
            return `(${e.op} ${exprToLuau(ctx, e.arg)})`;
        case "Binop":
            return `(${exprToLuau(ctx, e.lhs)} ${e.op} ${exprToLuau(ctx, e.rhs)})`;
        case "Concat":
            return `(${e.parts.map((p) => exprToLuau(ctx, p)).join(" .. ")})`;
        case "Table": {
            const fs = e.fields.map((f) => {
                if (!f.key)
                    return exprToLuau(ctx, f.value);
                return `[${exprToLuau(ctx, f.key)}] = ${exprToLuau(ctx, f.value)}`;
            });
            return `{ ${fs.join(", ")} }`;
        }
        case "Function": {
            const params = e.params.map((p, i) => {
                const tp = e.paramTypes[i];
                return tp ? `${p}: ${tp}` : p;
            }).join(", ");
            const retStr = e.retType ? `: ${e.retType}` : "";
            const bodyCtx = { indent: ctx.indent + 1, out: [], needsStringHelper: false };
            emitNode(bodyCtx, e.body);
            // v0.12 Feature #8: 子函数体内若引用了加密字符串，标记外层 ctx 也需要 helper。
            if (bodyCtx.needsStringHelper)
                ctx.needsStringHelper = true;
            const bodyStr = bodyCtx.out.join("\n");
            const indentedBody = bodyStr.split("\n").map(l => l.length > 0 ? "    ".repeat(bodyCtx.indent > 0 ? bodyCtx.indent : ctx.indent + 1) + l : l).join("\n");
            return `function(${params})${retStr}\n${indentedBody}\n${ind(ctx)}end`;
        }
        case "IfExpr":
            return `if ${exprToLuau(ctx, e.cond)} then ${exprToLuau(ctx, e.then)} else ${exprToLuau(ctx, e.else)}`;
        case "Interp":
            return `(${e.parts.map((p) => exprToLuau(ctx, p)).join(" .. ")})`;
        case "Call":
            return `${exprToLuau(ctx, e.callee)}(${e.args.map((a) => exprToLuau(ctx, a)).join(", ")})`;
        case "Method":
            return `${exprToLuau(ctx, e.callee)}:${e.name}(${e.args.map((a) => exprToLuau(ctx, a)).join(", ")})`;
        default:
            return "<unhandled>";
    }
}
//# sourceMappingURL=emitter.js.map