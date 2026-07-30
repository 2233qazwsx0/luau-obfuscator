// src/vm/runtime-template.ts — Wrap packed bytecode in a Luau runtime template.
//
// Reads runtime/vm-runtime.template.lua, substitutes placeholders, and applies
// v0.5 memory-protection marker stripping based on opts.
//
// Marker scheme (Lua long-comment delimited, keeps template valid Luau):
//   --[[__MEMWIPE_BEGIN__]]   ... --[[__MEMWIPE_END__]]      → kept if memwipe
//   --[[__ANTIDUMP_HELPERS_BEGIN__]] ... _END__              → kept if antidump
//   --[[__ANTIDUMP_BOOT_BEGIN__]]   ... _END__               → kept if antidump
// When disabled, the whole region (incl. markers) is stripped to empty.
//
// v0.4: plain substitution (no self-obfuscation yet). The runtime template
// runs as-is; the bytecode blob is already LZW+XOR protected.
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { genFakeBlob, DEFAULT_MEMWIPE } from "./memory.js";
const TEMPLATE_PATH = resolve(dirname(fileURLToPath(import.meta.url)), "../../runtime/vm-runtime.template.lua");
/** 从模板里剥离一对 marker 之间的内容（含 marker 行本身）。 */
function stripRegion(src, begin, end) {
    // 匹配 begin ... end（跨行，非贪婪），含前导空白与尾随换行一并去掉。
    const re = new RegExp(`[^\\n]*--\\[\\[${begin}\\]\\][\\s\\S]*?--\\[\\[${end}\\]\\][^\\n]*\\n?`, "g");
    return src.replace(re, "");
}
/** 保留 marker 区段但移除 marker 注释行本身（运行时不需要这些注释）。 */
function stripMarkers(src, begin, end) {
    const beginRe = new RegExp(`[^\\n]*--\\[\\[${begin}\\]\\][^\\n]*\\n?`, "g");
    const endRe = new RegExp(`[^\\n]*--\\[\\[${end}\\]\\][^\\n]*\\n?`, "g");
    return src.replace(beginRe, "").replace(endRe, "");
}
/**
 * Build the final executable Luau script by injecting the packed bytecode
 * hex blob and cipher key into the runtime template.
 *
 * @param hex       Packed hex bytecode (from compileVM().hex)
 * @param cipherKey Stream cipher key (0-255)
 * @param opts      Memory-protection options (default: both enabled)
 * @returns Final Luau source that, when executed, decodes and runs the bytecode
 */
export function buildRuntime(hex, cipherKey, opts = DEFAULT_MEMWIPE) {
    let template = readFileSync(TEMPLATE_PATH, "utf8");
    const memwipe = opts.memwipe !== false;
    const antidump = opts.antidump !== false;
    // 1. 内存清理区段：禁用时剥离整段，启用时只去掉 marker 注释行。
    if (!memwipe) {
        template = stripRegion(template, "__MEMWIPE_BEGIN__", "__MEMWIPE_END__");
    }
    else {
        template = stripMarkers(template, "__MEMWIPE_BEGIN__", "__MEMWIPE_END__");
    }
    // 2. 反 dump 区段：禁用时剥离 helper 定义 + boot 检测，启用时只去 marker。
    if (!antidump) {
        template = stripRegion(template, "__ANTIDUMP_HELPERS_BEGIN__", "__ANTIDUMP_HELPERS_END__");
        template = stripRegion(template, "__ANTIDUMP_BOOT_BEGIN__", "__ANTIDUMP_BOOT_END__");
    }
    else {
        template = stripMarkers(template, "__ANTIDUMP_HELPERS_BEGIN__", "__ANTIDUMP_HELPERS_END__");
        template = stripMarkers(template, "__ANTIDUMP_BOOT_BEGIN__", "__ANTIDUMP_BOOT_END__");
    }
    // 3. 占位符替换。
    //    hex 字符串是纯 [0-9A-F]，在 Lua 双引号字符串里安全。
    //    FAKE_BLOB：antidump 启用时生成假诱饵，禁用时填空串（FAKE_BLOB 局部不再被引用）。
    const fakeBlob = antidump ? genFakeBlob(hex.length, cipherKey ^ 0xFEEDFACE) : "";
    template = template
        .replace('"__HEX_BLOB__"', JSON.stringify(hex))
        .replace('"__FAKE_BLOB__"', JSON.stringify(fakeBlob))
        .replace(/__CIPHER_KEY__/g, String(cipherKey));
    return template;
}
//# sourceMappingURL=runtime-template.js.map