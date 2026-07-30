// src/parser/tokens.ts — Token kinds + keyword list for Luau 0.x.
export var TokenKind;
(function (TokenKind) {
    TokenKind["IDENT"] = "IDENT";
    TokenKind["KEYWORD"] = "KEYWORD";
    TokenKind["NUMBER"] = "NUMBER";
    TokenKind["STRING"] = "STRING";
    TokenKind["OP"] = "OP";
    TokenKind["EOF"] = "EOF";
})(TokenKind || (TokenKind = {}));
// Luau 0.x reserved words (full set).
export const KEYWORDS = new Set([
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while", "continue", "export", "type", "typeof",
    // Luau-specific:
    "match",
]);
// Luau-specific soft keywords (contextual).
export const SOFT_KEYWORDS = new Set([
    "type", "export", "continue",
]);
// Operators / punctuation handled separately via OP tokens.
//# sourceMappingURL=tokens.js.map