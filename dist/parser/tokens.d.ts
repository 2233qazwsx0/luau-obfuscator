export declare enum TokenKind {
    IDENT = "IDENT",
    KEYWORD = "KEYWORD",
    NUMBER = "NUMBER",
    STRING = "STRING",
    OP = "OP",
    EOF = "EOF"
}
export interface Token {
    kind: TokenKind;
    value: string;
    line: number;
    col: number;
    pos: number;
}
export declare const KEYWORDS: Set<string>;
export declare const SOFT_KEYWORDS: Set<string>;
