// src/vm/runtime-template.ts — Wrap packed bytecode in a Luau runtime template.
//
// Reads runtime/vm-runtime.template.lua, substitutes placeholders, and applies
// v0.5/v0.7 runtime-protection marker handling based on opts.
//
// Marker scheme (Lua long-comment delimited, keeps template valid Luau):
//   --[[__MEMWIPE_BEGIN__]]   ... --[[__MEMWIPE_END__]]      → kept if memwipe
//   --[[__ANTIDUMP_HELPERS_BEGIN__]] ... _END__              → kept if antidump
//   --[[__ANTIDUMP_BOOT_BEGIN__]]   ... _END__               → kept if antidump
//   --[[__BLOB_DEFS_BEGIN__]]  ... --[[__BLOB_DEFS_END__]]   → 碎片化/单串替换
// When disabled, the whole region (incl. markers) is stripped to empty.
//
// v0.7 碎片化：把完整 hex blob 拆成 N 个碎片（含假碎片），存入打乱顺序的表，
// 用一串顶层赋值语句按真实顺序拼接。D4 平坦化把每条拼接语句散入独立 dispatch
// case；D5 注入死代码碎片；D2 混淆拼接索引；D3 加密碎片内容。
//
// 记住我们面向的是 luau，加密后的也是 luau。

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { genFakeBlob, DEFAULT_RUNTIME_PROTECT, type RuntimeProtectOptions } from "./memory.js";
import { genKeyfuseAssembly, KEYFUSE_KEY_HEX_LEN } from "./keyfuse.js";

const TEMPLATE_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../runtime/vm-runtime.template.lua",
);

/** 从模板里剥离一对 marker 之间的内容（含 marker 行本身）。 */
function stripRegion(src: string, begin: string, end: string): string {
  const re = new RegExp(
    `[^\\n]*--\\[\\[${begin}\\]\\][\\s\\S]*?--\\[\\[${end}\\]\\][^\\n]*\\n?`,
    "g",
  );
  return src.replace(re, "");
}

/** 保留 marker 区段但移除 marker 注释行本身（运行时不需要这些注释）。 */
function stripMarkers(src: string, begin: string, end: string): string {
  const beginRe = new RegExp(`[^\\n]*--\\[\\[${begin}\\]\\][^\\n]*\\n?`, "g");
  const endRe = new RegExp(`[^\\n]*--\\[\\[${end}\\]\\][^\\n]*\\n?`, "g");
  return src.replace(beginRe, "").replace(endRe, "");
}

/** mulberry32 PRNG（内联，避免与 util 循环依赖）。 */
function mulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6D2B79F5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * 生成碎片化的 hex blob 装配代码（v0.7）。
 *
 * 把 `hex` 拆成 M 个真碎片 + K 个假碎片，混入同一张表并打乱存储顺序，
 * 然后用一串顶层赋值语句按真实装配顺序拼接出 `varName`。
 *
 * - 每条拼接语句是独立的普通语句 → buildIR 切成独立 block → D4 散入各自 dispatch case
 * - 假碎片留在表里但永不引用 → 攻击者无法区分真假
 * - 拼接索引是数字字面量 → D2 数字混淆
 * - 碎片字符串 → D3 字符串加密
 * - 装配完成后 `_frags = nil` 清空碎片表
 *
 * @param varName 目标变量名（如 HEX_BLOB）
 * @param hex     待碎片化的完整 hex 字符串
 * @param seed    PRNG 种子
 * @returns 顶层 Lua 语句序列（表定义 + 拼接赋值 + 清空）
 */
function genFragmentedAssembly(varName: string, hex: string, seed: number): string {
  const rand = mulberry32(seed);
  const hexChars = "0123456789ABCDEF";

  // 真碎片数 M：20-80，且每片 >= 8 hex 字符。
  const maxByLen = Math.max(1, Math.floor(hex.length / 8));
  const M = Math.max(1, Math.min(80, Math.min(maxByLen, 20 + Math.floor(rand() * 61))));
  // 假碎片数 K：M 的 20-40%，最少 4 个。
  const K = Math.max(4, Math.floor(M * (0.2 + rand() * 0.2)));
  const N = M + K;

  // 把 hex 切成 M 个真碎片（大致等长，余数均匀分配）。
  const realFrags: string[] = [];
  const base = Math.floor(hex.length / M);
  let rem = hex.length % M;
  let pos = 0;
  for (let i = 0; i < M; i++) {
    const len = base + (rem > 0 ? 1 : 0);
    realFrags.push(hex.slice(pos, pos + len));
    pos += len;
    if (rem > 0) rem--;
  }

  // 假碎片：随机 hex，随机长度 8-40。
  const fakeFrags: string[] = [];
  for (let i = 0; i < K; i++) {
    const flen = 8 + Math.floor(rand() * 33);
    let f = "";
    for (let j = 0; j < flen; j++) f += hexChars[Math.floor(rand() * 16)]!;
    fakeFrags.push(f);
  }

  // 存储：真+假合并后 Fisher-Yates 打乱。
  const storage: { hex: string; realOrder: number }[] = [];
  for (let i = 0; i < M; i++) storage.push({ hex: realFrags[i]!, realOrder: i });
  for (let i = 0; i < K; i++) storage.push({ hex: fakeFrags[i]!, realOrder: -1 });
  for (let i = N - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const tmp = storage[i]!;
    storage[i] = storage[j]!;
    storage[j] = tmp;
  }

  // pick[i] = 第 i 个真碎片（装配顺序）的 1-based 存储下标。
  const pick: number[] = new Array(M);
  for (let i = 0; i < N; i++) {
    if (storage[i]!.realOrder >= 0) {
      pick[storage[i]!.realOrder] = i + 1;
    }
  }

  // 生成 Lua：表字面量 + 顺序拼接赋值 + 清空。
  const tblName = `_frags_${varName}`;
  const lines: string[] = [];
  lines.push(`local ${tblName} = {`);
  for (let i = 0; i < N; i++) {
    lines.push(`  ${JSON.stringify(storage[i]!.hex)},`);
  }
  lines.push(`}`);
  lines.push(`local ${varName} = ""`);
  for (let i = 0; i < M; i++) {
    lines.push(`${varName} = ${varName} .. ${tblName}[${pick[i]}]`);
  }
  lines.push(`${tblName} = nil`);
  return lines.join("\n");
}

/**
 * Build the final executable Luau script by injecting the packed bytecode
 * hex blob and cipher key into the runtime template.
 *
 * @param hex       Packed hex bytecode (from compileVM().hex)
 * @param cipherKey Stream cipher key (0-255)
 * @param opts      运行时保护选项（默认全开）
 * @param vmSeed    v0.8 多 VM：派生 opcode 映射表的种子（与编译器同源）。
 *                  运行时用它重建 3 套 op→sem 反查表。
 * @param keyHex    v0.9 keyfuse：512 位 XOR 密钥的 128 hex 字符串。
 *                  null 表示 keyfuse 关闭（不加 XOR 外层）。需与 packer 端一致。
 * @returns Final Luau source that, when executed, decodes and runs the bytecode
 */
export function buildRuntime(
  hex: string,
  cipherKey: number,
  opts: RuntimeProtectOptions = DEFAULT_RUNTIME_PROTECT,
  vmSeed: number = 0,
  keyHex: string | null = null,
): string {
  let template = readFileSync(TEMPLATE_PATH, "utf8");
  const memwipe = opts.memwipe !== false;
  const antidump = opts.antidump !== false;
  const frag = opts.frag !== false;
  const keyfuse = opts.keyfuse !== false && keyHex !== null && keyHex.length === KEYFUSE_KEY_HEX_LEN;

  // 1. 内存清理区段：禁用时剥离整段，启用时只去掉 marker 注释行。
  if (!memwipe) {
    template = stripRegion(template, "__MEMWIPE_BEGIN__", "__MEMWIPE_END__");
  } else {
    template = stripMarkers(template, "__MEMWIPE_BEGIN__", "__MEMWIPE_END__");
  }

  // 2. 反 dump 区段：禁用时剥离 helper 定义 + boot 检测，启用时只去 marker。
  if (!antidump) {
    template = stripRegion(template, "__ANTIDUMP_HELPERS_BEGIN__", "__ANTIDUMP_HELPERS_END__");
    template = stripRegion(template, "__ANTIDUMP_BOOT_BEGIN__", "__ANTIDUMP_BOOT_END__");
  } else {
    template = stripMarkers(template, "__ANTIDUMP_HELPERS_BEGIN__", "__ANTIDUMP_HELPERS_END__");
    template = stripMarkers(template, "__ANTIDUMP_BOOT_BEGIN__", "__ANTIDUMP_BOOT_END__");
  }

  // 3. v0.9 keyfuse 区段处理（必须在 vm_boot 引用前完成）。
  //    a) xor_bytes_512 helper：keyfuse 关闭时剥离，开启时去 marker。
  //    b) __KEYFUSE_REAL__（早期段，真实融合宿主定义）：开启时替换为 realFusedCode，关闭时剥离。
  //    c) __KEYFUSE__（晚期段，装配 dispatch loop）：开启时替换为 assemblyCode，关闭时剥离。
  //    d) __KEYFUSE_XOR_STEP__（vm_boot 内 XOR 解密步）：关闭时剥离，开启时去 marker。
  //    e) __KEYFUSE_MEMWIPE__（vm_boot 内 secure_nil(KEY)）：关闭时剥离，开启时去 marker。
  //    f) __KF_JUNK1__/__KF_JUNK2__（假 VM 分支 junk 魔数）：开启→_rf1/_rf2，关闭→原始字面量。
  if (keyfuse) {
    template = stripMarkers(template, "__KEYFUSE_HELPERS_BEGIN__", "__KEYFUSE_HELPERS_END__");
    template = stripMarkers(template, "__KEYFUSE_XOR_STEP_BEGIN__", "__KEYFUSE_XOR_STEP_END__");
    template = stripMarkers(template, "__KEYFUSE_MEMWIPE_BEGIN__", "__KEYFUSE_MEMWIPE_END__");
    // 生成 keyfuse 装配代码（真实融合宿主 + dispatch loop）。
    const kf = genKeyfuseAssembly(keyHex!, vmSeed >>> 0);
    template = replaceRegion(template, "__KEYFUSE_REAL_BEGIN__", "__KEYFUSE_REAL_END__", kf.realFusedCode);
    template = replaceRegion(template, "__KEYFUSE_BEGIN__", "__KEYFUSE_END__", kf.assemblyCode);
    // 假 VM 分支 junk 魔数 → 真实融合宿主引用。
    template = template.replace(/__KF_JUNK1__/g, "_rf1");
    template = template.replace(/__KF_JUNK2__/g, "_rf2");
  } else {
    template = stripRegion(template, "__KEYFUSE_HELPERS_BEGIN__", "__KEYFUSE_HELPERS_END__");
    template = stripRegion(template, "__KEYFUSE_REAL_BEGIN__", "__KEYFUSE_REAL_END__");
    template = stripRegion(template, "__KEYFUSE_BEGIN__", "__KEYFUSE_END__");
    template = stripRegion(template, "__KEYFUSE_XOR_STEP_BEGIN__", "__KEYFUSE_XOR_STEP_END__");
    template = stripRegion(template, "__KEYFUSE_MEMWIPE_BEGIN__", "__KEYFUSE_MEMWIPE_END__");
    // 假 VM 分支 junk 魔数 → 原始字面量（与未融合行为一致）。
    template = template.replace(/__KF_JUNK1__/g, "1315423911");
    template = template.replace(/__KF_JUNK2__/g, "2654435761");
  }

  // 4. hex blob 定义区段：碎片化或单串替换。
  const fakeBlob = antidump ? genFakeBlob(hex.length, cipherKey ^ 0xFEEDFACE) : "";
  const fragSeed = (cipherKey ^ 0x7017CAFE) >>> 0;

  let blobDefs: string;
  if (frag) {
    // v0.7 碎片化：HEX_BLOB 总是碎片化；FAKE_BLOB 仅在 antidump 开启时碎片化，
    // 否则空串（antidump 关闭时 FAKE_BLOB 不会被引用，碎片化无意义）。
    const hexAsm = genFragmentedAssembly("HEX_BLOB", hex, fragSeed);
    const fakeAsm = antidump
      ? genFragmentedAssembly("FAKE_BLOB", fakeBlob, (fragSeed ^ 0xAA55) >>> 0)
      : `local FAKE_BLOB = ""`;
    blobDefs = `${hexAsm}\n${fakeAsm}`;
  } else {
    // 单串模式（原 v0.4 行为）。
    blobDefs =
      `local HEX_BLOB = ${JSON.stringify(hex)}\n` +
      `local FAKE_BLOB = ${JSON.stringify(fakeBlob)}`;
  }
  // 替换整个 __BLOB_DEFS__ 区段（含 marker）为生成的代码。
  const blobRe = new RegExp(
    `[^\\n]*--\\[\\[__BLOB_DEFS_BEGIN__\\]\\][\\s\\S]*?--\\[\\[__BLOB_DEFS_END__\\]\\][^\\n]*\\n?`,
    "g",
  );
  template = template.replace(blobRe, blobDefs + "\n");

  // 5. cipher key 替换（数字字面量）。
  template = template.replace(/__CIPHER_KEY__/g, String(cipherKey));

  // 6. v0.8 多 VM：注入 opcode 映射表种子（数字字面量，32 位）。
  //    运行时用它与编译器同源的 buildVmOpMap 算法重建 3 套 op→sem 表。
  template = template.replace(/__VM_SEED__/g, String(vmSeed >>> 0));

  return template;
}

/** 替换一对 marker 之间的内容（含 marker 行）为 replacement（保留尾换行）。 */
function replaceRegion(src: string, begin: string, end: string, replacement: string): string {
  const re = new RegExp(
    `[^\\n]*--\\[\\[${begin}\\]\\][\\s\\S]*?--\\[\\[${end}\\]\\][^\\n]*\\n?`,
    "g",
  );
  return src.replace(re, replacement + "\n");
}
