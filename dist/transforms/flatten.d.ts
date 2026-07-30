import type { Token } from "../parser/tokens.js";
/** No-op at token level. Real flatten lives in TODO E1-E6. Returns input. */
export declare function flattenBlock(tokens: Token[]): Token[];
