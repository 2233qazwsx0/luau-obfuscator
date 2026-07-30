/** 内存清理选项（由 pipeline 传入）。 */
export interface MemWipeOptions {
    /** 启用即时寄存器清零 + 滑动窗口指令清理 + boot 末尾 secure_nil/GC。 */
    memwipe?: boolean;
    /** 启用反 dump 假数据诱饵（检测到调试环境时替换真实 blob）。 */
    antidump?: boolean;
}
/** 默认开启。 */
export declare const DEFAULT_MEMWIPE: MemWipeOptions;
/**
 * 生成一段假字节码 blob（hex 字符串），用于反 dump 诱饵。
 * 长度与真实 blob 接近（±20%），内容为伪随机字节，让 dump 出来看起来像真数据。
 *
 * @param realHexLen 真实 blob 的 hex 长度（字节数 ×2）
 * @param seed       PRNG 种子，保证可复现
 */
export declare function genFakeBlob(realHexLen: number, seed: number): string;
