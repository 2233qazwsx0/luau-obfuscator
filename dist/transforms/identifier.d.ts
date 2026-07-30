import { type Token } from "../parser/tokens.js";
/** Apply D1 to a token stream. Pure: returns new Token[] and a name map. */
export declare function renameIdentifiers(tokens: Token[], seed: number): {
    tokens: Token[];
    map: Map<string, string>;
};
