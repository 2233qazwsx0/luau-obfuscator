// src/parser/lexer.ts — Token stream for Luau 0.x.
// Lexes identifiers, keywords, strings (single-quote / double-quote / long-bracket [==[ ]==[),
// interp strings (backtick `...{expr}...`), numbers (dec/hex/oct/sci), operators,
// comments (line `--`, long `--[==[ ]==]`).
// Pure function: lex(src: string, filename?: string) => Token[].
import { TokenKind, KEYWORDS } from "./tokens.js";
export class LexException extends Error {
    err;
    constructor(err) {
        super(`[${err.filename ?? "<stdin>"}:${err.line}:${err.col}] ${err.message}`);
        this.err = err;
    }
}
export function lex(src, filename = "<stdin>") {
    const tokens = [];
    const errors = [];
    const state = {
        src,
        i: 0,
        line: 1,
        col: 1,
        tokens,
        errors,
        filename,
    };
    while (state.i < state.src.length) {
        const c = state.src[state.i];
        // whitespace
        if (c === "\n") {
            state.line++;
            state.col = 1;
            state.i++;
            continue;
        }
        if (c === " " || c === "\t" || c === "\r") {
            state.i++;
            state.col++;
            continue;
        }
        // comments
        if (c === "-" && state.src[state.i + 1] === "-") {
            lexComment(state);
            continue;
        }
        // long string [==[ ... ]==]
        if (c === "[") {
            const lb = readLongBracketLevel(state);
            if (lb !== null) {
                lexLongString(state, lb);
                continue;
            }
        }
        // single-line strings
        if (c === '"' || c === "'") {
            lexString(state, c);
            continue;
        }
        // interp strings (backtick)  `hello {name}` — Luau-specific
        if (c === "`") {
            lexInterpString(state);
            continue;
        }
        // numbers
        if (isDigit(c) || (c === "." && isDigit(state.src[state.i + 1] ?? ""))) {
            lexNumber(state);
            continue;
        }
        // identifier / keyword
        if (isIdentStart(c)) {
            lexIdent(state);
            continue;
        }
        // operators / punctuation
        lexOp(state);
    }
    if (errors.length)
        throw new LexException(errors[0]);
    // EOF token for parser convenience
    tokens.push({ kind: TokenKind.EOF, value: "", line: state.line, col: state.col, pos: state.i });
    return tokens;
}
// ---------- helpers ----------
function isDigit(c) {
    return !!c && c >= "0" && c <= "9";
}
function isHex(c) {
    return !!c && ((c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F"));
}
function isIdentStart(c) {
    return !!c && (isAlpha(c) || c === "_");
}
function isIdentCont(c) {
    return !!c && (isAlpha(c) || isDigit(c) || c === "_");
}
function isAlpha(c) {
    return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");
}
function push(state, kind, value, start) {
    state.tokens.push({
        kind, value, line: state.line, col: state.col, pos: start,
    });
}
function err(state, msg) {
    state.errors.push({ message: msg, line: state.line, col: state.col, filename: state.filename });
}
// ---------- comment ----------
function lexComment(state) {
    state.i += 2; // consume --
    // long comment --[==[ ... ]==]
    if (state.src[state.i] === "[") {
        const lb = readLongBracketLevel(state);
        if (lb !== null) {
            state.i += 2 + lb.level; // consume [==[
            const close = "]" + "=".repeat(lb.level) + "]";
            const end = state.src.indexOf(close, state.i);
            if (end === -1) {
                err(state, "unterminated long comment");
                state.i = state.src.length;
                return;
            }
            // consume body
            for (let k = state.i; k < end; k++) {
                if (state.src[k] === "\n") {
                    state.line++;
                    state.col = 1;
                }
            }
            state.i = end + close.length;
            state.col += close.length;
            return;
        }
        if (state.src[state.i + 1] === "[") {
            // --[[ ... ]]  (level 0)
            state.i += 2;
            const end = state.src.indexOf("]]", state.i);
            if (end === -1) {
                err(state, "unterminated long comment");
                state.i = state.src.length;
                return;
            }
            for (let k = state.i; k < end; k++)
                if (state.src[k] === "\n") {
                    state.line++;
                    state.col = 1;
                }
            state.i = end + 2;
            return;
        }
    }
    // line comment: -- ... \n
    while (state.i < state.src.length && state.src[state.i] !== "\n")
        state.i++;
}
// ---------- long bracket [==[ level ----------
function readLongBracketLevel(state) {
    // we are at "["
    let k = state.i + 1;
    let level = 0;
    while (state.src[k] === "=") {
        level++;
        k++;
    }
    if (state.src[k] !== "[")
        return null;
    return { level };
}
// ---------- strings ----------
function lexLongString(state, lb) {
    const start = state.i;
    state.i += 2 + lb.level; // consume [==[
    const close = "]" + "=".repeat(lb.level) + "]";
    let raw = "";
    let k = state.i;
    while (k < state.src.length) {
        if (state.src[k] === "\n") {
            state.line++;
            state.col = 1;
            k++;
            continue;
        }
        if (state.src.startsWith(close, k)) {
            raw = state.src.slice(state.i, k);
            state.i = k + close.length;
            push(state, TokenKind.STRING, raw, start);
            return;
        }
        raw += state.src[k];
        k++;
    }
    err(state, "unterminated long string");
}
function lexString(state, quote) {
    const start = state.i;
    state.i++;
    let raw = "";
    while (state.i < state.src.length) {
        const c = state.src[state.i];
        if (c === "\n") {
            // single-line string cannot contain newline (Luau does allow but we keep strict)
            err(state, "newline in single-line string");
            break;
        }
        if (c === "\\") {
            const esc = state.src[state.i + 1] ?? "";
            const mapped = decodeEscape(esc);
            if (mapped !== null) {
                raw += mapped;
                state.i += 2;
                continue;
            }
            // unknown escape — keep literal backslash + char
            raw += c + esc;
            state.i += 2;
            continue;
        }
        if (c === quote) {
            state.i++;
            push(state, TokenKind.STRING, raw, start);
            return;
        }
        raw += c;
        state.i++;
        state.col++;
    }
    err(state, "unterminated string");
}
// Luau interp (backtick) string: `hello {name}!`
// We lex the entire thing as a single STRING token with a special prefix
// marker "\x00INTERP:" so the parser knows to handle interpolation.
// The raw content preserves the original text inside the backticks (without
// the outer backticks), with escape processing for `\` sequences.
function lexInterpString(state) {
    const start = state.i;
    state.i++; // consume opening `
    let raw = "";
    let depth = 0; // brace nesting inside interpolation expressions
    while (state.i < state.src.length) {
        const c = state.src[state.i];
        if (c === "\n") {
            // interp strings can span multiple lines in Luau
            state.line++;
            state.col = 1;
            raw += c;
            state.i++;
            continue;
        }
        if (c === "\\") {
            // escape inside interp string — keep raw `\char` for parser to handle
            const esc = state.src[state.i + 1] ?? "";
            raw += c + esc;
            state.i += 2;
            continue;
        }
        if (c === "{" && depth === 0) {
            // start of interpolation expression — `{expr}`
            raw += c;
            depth = 1;
            state.i++;
            continue;
        }
        if (c === "{" && depth > 0) {
            depth++;
            raw += c;
            state.i++;
            continue;
        }
        if (c === "}" && depth > 0) {
            depth--;
            raw += c;
            state.i++;
            continue;
        }
        if (c === "`" && depth === 0) {
            state.i++;
            push(state, TokenKind.STRING, "\x00INTERP:" + raw, start);
            return;
        }
        raw += c;
        state.i++;
        state.col++;
    }
    err(state, "unterminated interp string");
}
function decodeEscape(c) {
    switch (c) {
        case "n": return "\n";
        case "t": return "\t";
        case "r": return "\r";
        case "\\": return "\\";
        case '"': return '"';
        case "'": return "'";
        case "0": return "\0";
        case "a": return "\x07";
        case "b": return "\x08";
        case "f": return "\x0c";
        case "v": return "\x0b";
        case "\n": return "\n"; // line continuation
        default:
            if (c >= "0" && c <= "9")
                return null; // numeric escape — caller handles
            return null;
    }
}
// ---------- numbers ----------
function lexNumber(state) {
    const start = state.i;
    // 0x... (hex)
    if (state.src[state.i] === "0" && (state.src[state.i + 1] === "x" || state.src[state.i + 1] === "X")) {
        state.i += 2;
        while (isHex(state.src[state.i]))
            state.i++;
        if (state.src[state.i] === ".") {
            state.i++;
            while (isHex(state.src[state.i]))
                state.i++;
        }
        if (state.src[state.i] === "p" || state.src[state.i] === "P") {
            state.i++;
            if (state.src[state.i] === "+" || state.src[state.i] === "-")
                state.i++;
            while (isDigit(state.src[state.i]))
                state.i++;
        }
        push(state, TokenKind.NUMBER, state.src.slice(start, state.i), start);
        return;
    }
    // dec / oct
    while (isDigit(state.src[state.i]))
        state.i++;
    if (state.src[state.i] === ".") {
        state.i++;
        while (isDigit(state.src[state.i]))
            state.i++;
    }
    if (state.src[state.i] === "e" || state.src[state.i] === "E") {
        state.i++;
        if (state.src[state.i] === "+" || state.src[state.i] === "-")
            state.i++;
        while (isDigit(state.src[state.i]))
            state.i++;
    }
    push(state, TokenKind.NUMBER, state.src.slice(start, state.i), start);
}
// ---------- identifier / keyword ----------
function lexIdent(state) {
    const start = state.i;
    while (isIdentCont(state.src[state.i]))
        state.i++;
    const raw = state.src.slice(start, state.i);
    if (KEYWORDS.has(raw)) {
        push(state, TokenKind.KEYWORD, raw, start);
    }
    else {
        push(state, TokenKind.IDENT, raw, start);
    }
}
// ---------- operators / punctuation ----------
//
// Greedy match against op/punct tokens. We enumerate possible sequences
// of length 1..3 in priority order. The lexer then picks the longest one
// at the current position.
const OP_TABLE = [
    // 3-char (longest)
    "...", "<<=", ">>=", "..=", "//=",
    // 2-char
    "==", "~=", "<=", ">=", "..", "::", "<<", ">>",
    "+=", "-=", "*=", "/=", "%=", "^=", "//",
    // 1-char
    "+", "-", "*", "/", "%", "^", "#", "=", "<", ">", "~",
    "(", ")", "{", "}", "[", "]", ",", ";", ".", ":",
];
const OP_MAX_LEN = 3;
function lexOp(state) {
    const start = state.i;
    let matched = "";
    for (let len = OP_MAX_LEN; len >= 1; len--) {
        const sub = state.src.substr(state.i, len);
        if (OP_TABLE.indexOf(sub) !== -1) {
            matched = sub;
            break;
        }
    }
    if (!matched) {
        err(state, `unexpected character '${state.src[state.i]}'`);
        state.i++;
        return;
    }
    push(state, TokenKind.OP, matched, start);
    state.i += matched.length;
    state.col += matched.length;
}
//# sourceMappingURL=lexer.js.map