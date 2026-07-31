/** 单条加密字符串的密钥长度（字节）。 */
export declare const STRING_KEY_BYTES = 6;
export interface StringCipher {
    /** 每条字符串的加密 blob + 独立 6 字节密钥。 */
    pool: {
        id: number;
        hex: string;
        key: number[];
    }[];
}
/** 构造空 cipher（保留 seed 参数以便调用方记录，但不再派生全局主密钥）。 */
export declare function buildCipher(_seed: number): StringCipher;
/** 由 seed + strId 派生 6 字节独立密钥。 */
export declare function deriveStringKey(seed: number, strId: number): number[];
/**
 * 用 6 字节 key + LCG 滚动因子加密单个字符串，返回 hex。
 * 与 emitter 内联的 Lua IIFE 完全对齐。
 */
export declare function encryptString(s: string, key: number[]): string;
/** 解密单个 blob（与加密对称同形）。 */
export declare function decryptString(hex: string, key: number[]): string;
