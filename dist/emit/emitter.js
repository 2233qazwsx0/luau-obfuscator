// src/emit/emitter.ts — Render the AST back into Luau source.
//
// Important: the AST nodes carry a `meta` field written by the transforms
// pipeline (number-key on `Number` nodes, replacement blob on `String`).
// We honor those during emission so the obfuscated form comes out correctly.
import { BIT32_POLYFILL } from "./bit32_polyfill.js";
export function emit(program, cipher) {
    const ctx = { indent: 0, out: [BIT32_POLYFILL], cipher };
    emitNode(ctx, program);
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
            const id = e.__str_id;
            if (blob && id !== undefined) {
                const keyBytes = Array.from(Buffer.from(ctx.cipher.masterKeyHex, "hex"));
                const keyLit = `{${keyBytes.join(",")}}`;
                return `((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)(${keyLit}))("${blob}")`;
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
            const bodyCtx = { indent: ctx.indent + 1, out: [], cipher: ctx.cipher };
            emitNode(bodyCtx, e.body);
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