// src/vm/keyfuse.ts — 密钥深度融合 + 乱序交错存储（v0.9 keyfuse 层）。
//
// 在现有 8 位 stream cipher 外层再加一层 512 位（64 字节）随机 XOR 密钥。
// 512 位密钥拆成 128 个 nibble 碎片，每个碎片注入一个"宿主变量"——
// 一个数字同时承载正常逻辑值和密钥碎片值。宿主混合真实运行时代码
// （vm_execute 假 VM 分支的 junk 魔数）与合成诱饵逻辑。
//
// 装配逻辑手动发射 D4 风格 dispatch loop（状态机打散）+ D5 风格死分支
// 诱饵 case（结构完全相同）。因外层运行时模板自混淆走 noFlatten/noDeadcode
// 路径，D4/D5 不会作用于模板，故由本模块直接发射等价结构。
//
// 拼接索引通过 _B()（bitxor polyfill）动态计算，装配顺序由 seed 派生的
// Fisher-Yates 打乱。攻击者需完整逆向状态机才能还原碎片顺序。
//
// v0.10 rt_deps：当 rtToken != null 时，nibbles 126/127 不写入 _kh（填诱饵值），
// 改由 dispatch loop 从 _rt_tok（运行时 token）派生。token 依赖 #HEX_BLOB / #_kh，
// 两者只在碎片装配 + keyfuse 建表后才知道 → 至少一部分密钥片段必须运行时才能获得。
//
// 记住我们面向的是 luau，加密后的也是 luau。

/** mulberry32 PRNG（内联，与 src/util/prng.ts 对齐）。 */
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

/** 512 位密钥的字节数（64 字节 = 128 hex 字符 = 128 nibble 碎片）。 */
export const KEYFUSE_KEY_BYTES = 64;
export const KEYFUSE_KEY_HEX_LEN = KEYFUSE_KEY_BYTES * 2; // 128
export const KEYFUSE_NIBBLES = KEYFUSE_KEY_HEX_LEN; // 128

/**
 * 计算 _kh 宿主表的大小（128 真 + decoyCount 假）。
 * 仅依赖 decoyRate（默认 0.35），不依赖 seed / rtToken。
 * pipeline 用此值在打包前算出 rtToken（#_kh 项）。
 */
export function computeKeyfuseKhSize(decoyRate: number = 0.35): number {
  const decoyCount = Math.max(4, Math.floor(KEYFUSE_NIBBLES * decoyRate));
  return KEYFUSE_NIBBLES + decoyCount;
}

/**
 * 从 seed 派生 512 位（64 字节）XOR 密钥。确定性：同 seed 同密钥。
 * 用 mulberry32 逐字节生成，确保 0..255 均匀分布。
 */
export function deriveKeyfuseKey(seed: number): {
  keyBytes: number[];
  keyHex: string;
} {
  const rand = mulberry32((seed ^ 0x9A11FE05) >>> 0);
  const keyBytes: number[] = [];
  for (let i = 0; i < KEYFUSE_KEY_BYTES; i++) {
    keyBytes.push(Math.floor(rand() * 256));
  }
  const keyHex = keyBytes
    .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
    .join("");
  return { keyBytes, keyHex };
}

/**
 * 512 位循环 XOR 加密 / 解密（XOR 对称，同函数双向）。
 * 对二进制串逐字节与 64 字节密钥循环 XOR。
 * 与运行时 xor_bytes_512 完全对齐。
 */
export function xor512(data: string, keyBytes: number[]): string {
  const bytes = Buffer.from(data, "binary");
  const out = Buffer.alloc(bytes.length);
  const klen = keyBytes.length;
  for (let i = 0; i < bytes.length; i++) {
    out[i] = (bytes[i]! ^ keyBytes[i % klen]!) & 0xff;
  }
  return out.toString("binary");
}

// ---- 宿主变量命名 ----
// 真实融合宿主：_rf1 / _rf2，定义在模板早期（vm_execute 之前），被假 VM
// 分支的 junk 计算引用。其值 = magic_base + key_nibble，magic_base 是 16
// 的倍数（保证 % 16 == nibble）。junk 分支惰性，魔数可自由调整。
export const REAL_FUSED_NAMES = ["_rf1", "_rf2"] as const;
// 原始 junk 魔数（runtime/vm-runtime.template.lua 假 VM 分支）：
//   local junk = (ip * 1315423911 + current_vm * 2654435761) % 4294967296
// 取其 16 对齐下界作为宿主基值，+ nibble 即承载碎片。
const REAL_FUSED_BASES = [1315423904, 2654435760]; // 均为 16 的倍数

/** 宿主变量结构：一个数字同时承载业务值和碎片值。 */
interface Host {
  /** 宿主名（真实融合用 _rf1/_rf2；合成用 _h0/_h1/...）。 */
  name: string;
  /** 完整数值（业务部分 * 16 + nibble）。 */
  value: number;
  /** 该宿主承载的密钥 nibble（0..15），或 decoy 时为随机垃圾值。 */
  nibble: number;
  /** 是否为真实碎片（参与装配）。false = 假碎片（结构相同，不装配）。 */
  real: boolean;
  /** 是否为真实融合宿主（被 vm_execute 引用）。 */
  fused: boolean;
}

/** 生成单个合成宿主：随机业务值 + 指定 nibble。 */
function makeSyntheticHost(
  rand: () => number,
  name: string,
  nibble: number,
  real: boolean,
): Host {
  // 业务值：3-6 位随机整数，让整体数字看起来像正常代码常量。
  const bizDigits = 3 + Math.floor(rand() * 4); // 3..6
  const bizMax = Math.pow(10, bizDigits);
  const biz = Math.floor(rand() * bizMax);
  const value = biz * 16 + (nibble & 0xf);
  return { name, value, nibble: nibble & 0xf, real, fused: false };
}

/**
 * 生成密钥深度融合装配代码（v0.9 keyfuse）。
 *
 * 输出三段 Lua 代码：
 *   1. realFusedCode：真实融合宿主定义（_rf1/_rf2），放在模板早期。
 *   2. assemblyCode：合成宿主表 + D4 风格 dispatch loop + D5 风格死分支
 *      诱饵 case + 清理。放在模板晚期（vm_boot 之前）。
 *   3. realFusedValues：_rf1/_rf2 的数值（供 runtime-template.ts 填充占位符）。
 *
 * @param keyHex    128 hex 字符的 512 位密钥
 * @param seed      PRNG 种子（决定打乱顺序、宿主值、state ID）
 * @param decoyRate 假碎片比例（0.2-0.5）。默认 0.35。
 * @param rtToken   v0.10 rt_deps：非 null 时 nibbles 126/127 改由运行时 token 派生。
 *                  _kh 对应槽填诱饵值，dispatch loop 从 _rt_tok 读取真实 nibble。
 */
export function genKeyfuseAssembly(
  keyHex: string,
  seed: number,
  decoyRate: number = 0.35,
  rtToken: number | null = null,
): {
  realFusedCode: string;
  assemblyCode: string;
  realFusedValues: number[];
} {
  if (keyHex.length !== KEYFUSE_KEY_HEX_LEN) {
    throw new Error(
      `keyfuse: keyHex must be ${KEYFUSE_KEY_HEX_LEN} chars, got ${keyHex.length}`,
    );
  }
  const rand = mulberry32((seed ^ 0x5F051701) >>> 0);
  const nibbles: number[] = [];
  for (let i = 0; i < KEYFUSE_NIBBLES; i++) {
    nibbles.push(parseInt(keyHex[i]!, 16));
  }
  // v0.10 rt_deps：nibbles 126/127 改由 _rt_tok 派生，_kh 槽填诱饵。
  // keyHex/keyBytes 已在 pipeline 中用 rtToken 覆盖了这两位，这里只影响 _kh 表内容。
  const rtActive = rtToken != null;
  if (rtActive) {
    nibbles[126] = Math.floor(rand() * 16); // 诱饵
    nibbles[127] = Math.floor(rand() * 16); // 诱饵
  }

  // ---- 1. 构建宿主集合 ----
  // 真实融合宿主（2 个）：承载前 2 个 nibble，值 = base + nibble。
  const hosts: Host[] = [];
  for (let i = 0; i < REAL_FUSED_NAMES.length; i++) {
    const nibble = nibbles[i]!;
    hosts.push({
      name: REAL_FUSED_NAMES[i]!,
      value: REAL_FUSED_BASES[i]! + nibble,
      nibble,
      real: true,
      fused: true,
    });
  }
  // 合成真实宿主：承载 nibble[2..127]。
  for (let i = REAL_FUSED_NAMES.length; i < KEYFUSE_NIBBLES; i++) {
    hosts.push(makeSyntheticHost(rand, `_h${i}`, nibbles[i]!, true));
  }
  // 合成假碎片宿主：decoyRate 比例，随机垃圾 nibble，不装配。
  const decoyCount = Math.max(
    4,
    Math.floor(KEYFUSE_NIBBLES * decoyRate),
  );
  for (let i = 0; i < decoyCount; i++) {
    const junkNibble = Math.floor(rand() * 16);
    hosts.push(makeSyntheticHost(rand, `_d${i}`, junkNibble, false));
  }

  // ---- 2. _B() 索引混淆 + _kh 分槽 ----
  // 装配逻辑位置 i 的宿主槽位 = _B(i, _kk) + 1，其中 _kk ∈ [0,127] 保证
  // i XOR _kk ∈ [0,127]（双射）。真实碎片共 128 个，占 _kh 槽 1..128；
  // 假碎片位于槽 129..N，永不被真实位置索引（仅在不可达死分支中被引用）。
  // realHostsOrdered[i] = 承载 nibbles[i] 的真实宿主（按 nibble 顺序）。
  const realHostsOrdered: Host[] = hosts.filter((h) => h.real);
  const decoyHostIdxs: number[] = [];
  hosts.forEach((h, i) => {
    if (!h.real) decoyHostIdxs.push(i);
  });
  // 假碎片打乱（填入槽 129..N 的顺序随机）。
  for (let i = decoyHostIdxs.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const tmp = decoyHostIdxs[i]!;
    decoyHostIdxs[i] = decoyHostIdxs[j]!;
    decoyHostIdxs[j] = tmp;
  }
  // _kk：索引混淆密钥，0..127。
  const kk = Math.floor(rand() * 128);
  const totalSlots = hosts.length;
  const khValues: number[] = new Array(totalSlots + 1); // 1-based
  // 槽 (i ^ kk) + 1 放 realHostsOrdered[i] 的值（其 % 16 == nibbles[i]）。
  for (let i = 0; i < KEYFUSE_NIBBLES; i++) {
    const slot = (i ^ kk) + 1; // _B(i, kk) + 1
    khValues[slot] = realHostsOrdered[i]!.value;
  }
  // 假碎片填入槽 129..N。
  decoyHostIdxs.forEach((hIdx, pos) => {
    const slot = 128 + pos + 1;
    khValues[slot] = hosts[hIdx]!.value;
  });

  // ---- 4. D4 风格 dispatch loop ----
  // 128 个真实 case + 1 个 exit case + 假碎片死分支 case。
  // state ID 由 seed 打乱（mulberry32 生成大数，互不相同）。
  // 物理 case 顺序也打乱（elseif 链顺序不影响执行，由 __b 值匹配）。
  const numRealCases = KEYFUSE_NIBBLES; // 128
  const numDecoyCases = decoyHostIdxs.length;
  const totalCases = numRealCases + numDecoyCases;

  // 生成 state ID 池：totalCases 个真实/死分支 case + 1 个 exit。
  // 用大数让 D2 数字混淆更有意义。
  const stateIds: number[] = [];
  const usedIds = new Set<number>();
  while (stateIds.length < totalCases + 1) {
    const id = (Math.floor(rand() * 0x7fffffff) | 1) >>> 0; // 奇数，非零
    if (!usedIds.has(id)) {
      usedIds.add(id);
      stateIds.push(id);
    }
  }
  const exitId = stateIds[totalCases]!; // 最后一个作 exit
  // 真实 case i 的 state ID = stateIds[i]，下一状态 = stateIds[i+1]（i<127），
  // i==127 时下一状态 = exitId。
  // 死分支 case 的 state ID = stateIds[128..]，永不作为转移目标。

  // 物理 case 顺序打乱：把所有 case（真实 + 死分支 + exit）混排进 elseif 链。
  const caseOrder: number[] = [];
  for (let i = 0; i < totalCases + 1; i++) caseOrder.push(i); // 0..totalCases
  // caseOrder[k] = case 类型索引：< 128 真实 case i；128..127+decoy 死分支；totalCases exit
  for (let i = caseOrder.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const tmp = caseOrder[i]!;
    caseOrder[i] = caseOrder[j]!;
    caseOrder[j] = tmp;
  }

  // ---- 5. 发射 Lua 代码 ----
  const lines: string[] = [];

  // 5a. 真实融合宿主定义（早期段）。
  const realFusedValues: number[] = [];
  const rfLines: string[] = [];
  rfLines.push("-- v0.9 keyfuse: 真实融合宿主（被 vm_execute 假 VM 分支引用）。");
  rfLines.push("-- 值 = magic_base + key_nibble；修改即致 junk 计算变更 + 密钥碎片损坏。");
  for (let i = 0; i < REAL_FUSED_NAMES.length; i++) {
    const h = hosts[i]!;
    realFusedValues.push(h.value);
    rfLines.push(`local ${h.name} = ${h.value}`);
  }
  const realFusedCode = rfLines.join("\n");

  // 5b. 装配段（晚期段）。
  lines.push("-- v0.9 keyfuse: 512 位密钥深度融合装配。");
  lines.push("-- _kh 表混存真实+假碎片宿主；dispatch loop 按 _B() 动态索引打散装配。");
  // _kh 表（值已打乱）。
  lines.push(`local _kh = {`);
  for (let s = 1; s <= totalSlots; s++) {
    lines.push(`  ${khValues[s]!},`);
  }
  lines.push(`}`);
  lines.push(`local _kk = ${kk}`);
  // v0.10 rt_deps：派生运行时 token（依赖 #HEX_BLOB / #_kh，两者在此刻才已知）。
  // nibbles 126/127 由 _rt_tok 派生，而非 _kh 静态值。
  if (rtActive) {
    lines.push(
      `local _rt_tok = (#HEX_BLOB * 2654435761 + #_kh * 16777619 + 0x5F051701) % 4294967296`,
    );
  }
  lines.push(`local KEY = ""`);
  lines.push(`local __kf_b = ${stateIds[0]}`);
  lines.push(`while true do`);
  // 发射 elseif 链（按打乱后的物理顺序）。
  let firstCase = true;
  for (const caseIdx of caseOrder) {
    if (caseIdx < numRealCases) {
      // 真实 case：装配逻辑位置 caseIdx 的 nibble。
      const i = caseIdx;
      const sid = stateIds[i]!;
      const nextSid =
        i + 1 < numRealCases ? stateIds[i + 1]! : exitId;
      const branchKw = firstCase ? "if" : "elseif";
      firstCase = false;
      lines.push(`  ${branchKw} __kf_b == ${sid} then`);
      // v0.10 rt_deps：nibbles 126/127 从 _rt_tok 派生，不走 _kh。
      if (rtActive && (i === 126 || i === 127)) {
        // (token >>> 4) & 0xF → nibble 126；(token >>> 8) & 0xF → nibble 127。
        const shift = i === 126 ? 4 : 8;
        lines.push(
          `    KEY = KEY .. string.format("%X", math.floor(_rt_tok / ${1 << shift}) % 16)`,
        );
      } else {
        // _B(i, _kk) + 1 → 槽位；% 16 → nibble；string.format("%X", ...) → hex 字符。
        lines.push(
          `    KEY = KEY .. string.format("%X", _kh[_B(${i}, _kk) + 1] % 16)`,
        );
      }
      lines.push(`    __kf_b = ${nextSid}`);
    } else if (caseIdx < totalCases) {
      // 死分支 case：结构与真实 case 完全相同，但访问假碎片槽（垃圾 nibble）。
      // state ID 永不被转移目标命中 → 不可达 → KEY 不被污染。
      const decoyPos = caseIdx - numRealCases;
      const sid = stateIds[caseIdx]!;
      const fakeNext = stateIds[caseIdx]!; // 自指（不可达，无意义）
      const fakeSlot = 129 + decoyPos; // 假碎片槽
      // 用一个与真实 case 形态一致的索引表达式（不影响正确性，永不可达）。
      const fakeI = (fakeSlot - 1) ^ kk; // 反推一个 i 使 _B(i,_kk)+1 == fakeSlot
      const branchKw = firstCase ? "if" : "elseif";
      firstCase = false;
      lines.push(`  ${branchKw} __kf_b == ${sid} then`);
      lines.push(
        `    KEY = KEY .. string.format("%X", _kh[_B(${fakeI}, _kk) + 1] % 16)`,
      );
      lines.push(`    __kf_b = ${fakeNext}`);
    } else {
      // exit case。
      const branchKw = firstCase ? "if" : "elseif";
      firstCase = false;
      lines.push(`  ${branchKw} __kf_b == ${exitId} then`);
      lines.push(`    break`);
    }
  }
  lines.push(`  end`);
  lines.push(`end`);
  // 清理：用完即毁（配合 vm_boot 内 secure_nil(KEY)）。
  // 注意：_rt_tok 不在此处销毁——vm_boot 的 rt_mix_decrypt 仍需引用，
  // 由 vm_boot 内 __RT_MIX_MEMWIPE__ 段负责 secure_nil。
  lines.push(`_kh = nil`);
  lines.push(`_kk = nil`);
  lines.push(`__kf_b = nil`);

  const assemblyCode = lines.join("\n");
  return { realFusedCode, assemblyCode, realFusedValues };
}
