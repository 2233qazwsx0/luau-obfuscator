// src/parser/tokens.ts — Token kinds + keyword list for Luau 0.x.

export enum TokenKind {
  IDENT = "IDENT",
  KEYWORD = "KEYWORD",
  NUMBER = "NUMBER",
  STRING = "STRING",
  OP = "OP",
  EOF = "EOF",
}

export interface Token {
  kind: TokenKind;
  value: string;
  line: number;
  col: number;
  pos: number;
}

// Luau 0.x reserved words (full set).
export const KEYWORDS: Set<string> = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
  "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
  "true", "until", "while", "continue", "export", "type", "typeof",
  // Luau-specific:
  "match",
]);

// Luau-specific soft keywords (contextual).
export const SOFT_KEYWORDS: Set<string> = new Set([
  "type", "export", "continue",
]);

// Operators / punctuation handled separately via OP tokens.