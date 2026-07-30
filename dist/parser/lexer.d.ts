import { Token } from "./tokens.js";
export interface LexError {
    message: string;
    line: number;
    col: number;
    filename?: string;
}
export declare class LexException extends Error {
    err: LexError;
    constructor(err: LexError);
}
export declare function lex(src: string, filename?: string): Token[];
