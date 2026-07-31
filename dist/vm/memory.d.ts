/** 运行时保护选项（由 pipeline 传入）。 */
export interface RuntimeProtectOptions {
    /** 启用即时寄存器清零 + boot 末尾 secure_nil/GC（v0.5）。 */
    memwipe?: boolean;
    /** 启用反 dump 假数据诱饵（v0.5）。 */
    antidump?: boolean;
    /** 启用 hex blob 碎片化（v0.7）：拆散为 N 碎片，D4 散入 dispatch case。 */
    frag?: boolean;
    /** 启用 512 位密钥深度融合（v0.9 keyfuse）：XOR 外层 + 碎片宿主 + 乱序装配。 */
    keyfuse?: boolean;
    /** v0.10 动态反调试：时间差 + debug hook 完整性 + 环境干净性 + vm_execute 周期性检查。 */
    dynamicAntidump?: boolean;
    /** v0.10 rt_deps：解密链插入运行时依赖层 + keyfuse 2 nibble 运行时派生。需 keyfuse 开启。 */
    rtDeps?: boolean;
}
/** 默认全开。 */
export declare const DEFAULT_RUNTIME_PROTECT: RuntimeProtectOptions;
/**
 * 生成一段假字节码 blob（hex 字符串），用于反 dump 诱饵。
 * 长度与真实 blob 接近（±20%），内容为伪随机字节，让 dump 出来看起来像真数据。
 *
 * @param realHexLen 真实 blob 的 hex 长度（字节数 ×2）
 * @param seed       PRNG 种子，保证可复现
 */
export declare function genFakeBlob(realHexLen: number, seed: number): string;
