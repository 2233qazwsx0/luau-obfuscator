// src/transforms/identifier.ts — D1: identifier renaming.
//
// Strategy:
//   - Walk the source via the existing lexer's token stream (we re-lex here
//     instead of depending on a separate parser to keep this layer standalone).
//   - Replace every non-reserved IDENT with `a0`, `a1`, ... `a9`, `b0`, ...
//     matching the format the reference script uses for *local* names.
//   - Upvalues / closures get a 2-letter scheme to mirror sample style.
//   - Globally-used reserved words (`print`, `pairs`, `game`, ... ) are NOT
//     renamed — we leave the engine's interface unchanged.
import { TokenKind } from "../parser/tokens.js";
const RESERVED_LUA = new Set([
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while", "continue", "type", "typeof", "export",
]);
// Common Roblox/Luau globals we deliberately do NOT rename (engine visibility).
const KNOWN_GLOBALS = new Set([
    "print", "warn", "error", "assert", "type", "tostring", "tonumber",
    "pairs", "ipairs", "next", "select", "pcall", "xpcall", "setmetatable",
    "getmetatable", "rawget", "rawset", "rawequal", "rawlen", "setfenv", "getfenv",
    "unpack", "loadstring", "load", "require", "tick", "time", "wait",
    "game", "workspace", "script", "math", "string", "table", "os", "task",
    "Instance", "UDim", "UDim2", "Vector3", "Color3", "Enum", "ColorSequence",
    "NumberSequence", "TweenInfo", "Rect", "Region3", "Ray", "CFrame",
]);
const SINGLE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/** Generate a stable mapping for a given seed.
 *  `avoid` is the set of identifier names that appear in the source but are
 *  NOT being renamed (declared multiple times, globals, etc.). Generated
 *  short names must not collide with these, or a renamed variable would
 *  shadow / be shadowed by an unrenamed one. */
function buildMapping(_seed, names, avoid) {
    const map = new Map();
    const SL = SINGLE.length; // 52 (a-z + A-Z)
    let idx = 0;
    for (const name of names) {
        if (RESERVED_LUA.has(name) || KNOWN_GLOBALS.has(name))
            continue;
        if (name.startsWith("__") && name.endsWith("__"))
            continue;
        // Generate a short name that doesn't collide with any unrenamed name.
        // form: a, b, ..., z, A, ..., Z, aa, ab, ..., aZ, ba, ...
        let renamed;
        do {
            if (idx < SL) {
                renamed = SINGLE[idx];
            }
            else {
                const r = idx - SL;
                renamed = SINGLE[Math.floor(r / SL) % SL] + SINGLE[r % SL];
            }
            idx++;
        } while (avoid.has(renamed) || RESERVED_LUA.has(renamed) || KNOWN_GLOBALS.has(renamed));
        map.set(name, renamed);
    }
    return map;
}
/** Heuristic: which identifier names appear to be local-declared?
 *  Simple non-scoping collector — it just scans for `local NAME`, `function NAME`,
 *  `local function NAME`, `for NAME`, and anonymous `function(` params.
 *  If two declarations share a name (which Lua's lexical scoping allows but
 *  usually avoids), we keep the original to avoid collisions.
 */
function collectCandidateIdents(tokens) {
    const declared = new Set();
    const used = new Set();
    const functionParams = new Set();
    const localDeclCounts = new Map();
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        // `local NAME[, NAME...]`  (with optional `function NAME` decl form)
        if (t.kind === TokenKind.KEYWORD && t.value === "local") {
            // local function NAME ...
            if (tokens[i + 1] && tokens[i + 1].kind === TokenKind.KEYWORD && tokens[i + 1].value === "function") {
                if (tokens[i + 2] && tokens[i + 2].kind === TokenKind.IDENT) {
                    const nm = tokens[i + 2].value;
                    localDeclCounts.set(nm, (localDeclCounts.get(nm) ?? 0) + 1);
                    declared.add(nm);
                }
                continue;
            }
            // local NAME[, NAME...]
            let j = i + 1;
            while (j < tokens.length) {
                const t2 = tokens[j];
                if (t2.kind === TokenKind.IDENT) {
                    const nm = t2.value;
                    localDeclCounts.set(nm, (localDeclCounts.get(nm) ?? 0) + 1);
                    declared.add(nm);
                    j++;
                }
                else if (t2.kind === TokenKind.OP && t2.value === ",") {
                    j++;
                }
                else
                    break;
            }
            continue;
        }
        // `function NAME[.NAME...][:METHOD] (args) ... end`  statement form
        if (t.kind === TokenKind.KEYWORD && t.value === "function") {
            // skip the `function` token of `local function NAME ...`  — that path
            // already declares NAME one line up.
            if (tokens[i - 1] && tokens[i - 1].kind === TokenKind.KEYWORD && tokens[i - 1].value === "local") {
                i++;
                continue;
            }
            const next = tokens[i + 1];
            if (next && next.kind === TokenKind.IDENT) {
                // Walk dotted segments; the last is the function's own name.
                let j = i + 1;
                while (j < tokens.length && tokens[j].kind === TokenKind.IDENT) {
                    const nm = tokens[j].value;
                    localDeclCounts.set(nm, (localDeclCounts.get(nm) ?? 0) + 1);
                    declared.add(nm);
                    j++;
                    if (tokens[j] && tokens[j].kind === TokenKind.OP && tokens[j].value === ".") {
                        j++;
                    }
                    else
                        break;
                }
                continue;
            }
            // `function (args) ... end`  anonymous expression form
            if (next && next.kind === TokenKind.OP && next.value === "(") {
                let j = i + 2;
                while (j < tokens.length && !(tokens[j].kind === TokenKind.OP && tokens[j].value === ")")) {
                    if (tokens[j].kind === TokenKind.IDENT) {
                        functionParams.add(tokens[j].value);
                    }
                    j++;
                }
                continue;
            }
        }
        // `for NAME[, NAME...] [= ... | in ...] do ... end` or `for NAME = ... do`
        if (t.kind === TokenKind.KEYWORD && t.value === "for") {
            let j = i + 1;
            while (j < tokens.length) {
                const t2 = tokens[j];
                if (t2.kind === TokenKind.IDENT) {
                    const nm = t2.value;
                    localDeclCounts.set(nm, (localDeclCounts.get(nm) ?? 0) + 1);
                    declared.add(nm);
                    j++;
                }
                else if (t2.kind === TokenKind.OP && t2.value === ",") {
                    j++;
                }
                else
                    break;
            }
            continue;
        }
        // track usage
        if (t.kind === TokenKind.IDENT)
            used.add(t.value);
    }
    // Filter out names that are declared more than once in the same file
    // (different Lua scopes would still collide under our flat-rename scheme).
    const safe = new Set();
    for (const n of declared) {
        if ((localDeclCounts.get(n) ?? 0) === 1)
            safe.add(n);
    }
    // Bug #8 fix: function parameters ARE now included in the rename candidates.
    // Each param name is added to declared with a count, so if a name is used
    // as a param in only one function, it will be renamed. If the same name
    // is used as a param in multiple functions (e.g. `f(a) ... g(a)`), the
    // count > 1 and it's excluded for safety.
    for (const n of functionParams) {
        localDeclCounts.set(n, (localDeclCounts.get(n) ?? 0) + 1);
        declared.add(n);
    }
    // Rebuild safe set with function params included
    const safeWithParams = new Set();
    for (const n of declared) {
        if ((localDeclCounts.get(n) ?? 0) === 1)
            safeWithParams.add(n);
    }
    const result = new Set([...safeWithParams].filter((n) => used.has(n)));
    if (process.env.DEBUG_IDENT) {
        // eslint-disable-next-line no-console
        console.error(`[debug] declared=${[...declared].join(',')} counts=${[...localDeclCounts.entries()].map(([k, v]) => k + '=' + v).join(',')} used=${[...used].join(',')} result=${[...result].join(',')}`);
    }
    return result;
}
/** Apply D1 to a token stream. Pure: returns new Token[] and a name map. */
export function renameIdentifiers(tokens, seed) {
    const candidates = collectCandidateIdents(tokens);
    const names = [...candidates];
    // Collect ALL ident names that appear in the source but are NOT being
    // renamed. These must be avoided when generating short names to prevent
    // a renamed variable from colliding with (shadowing / being shadowed by)
    // an unrenamed one. Example: if `p` is declared in two scopes (filtered
    // out of candidates) and `state` is renamed to `p`, the renamed `state`
    // would collide with the unrenamed `p`.
    const avoid = new Set();
    for (const t of tokens) {
        if (t.kind === TokenKind.IDENT && !candidates.has(t.value)) {
            avoid.add(t.value);
        }
    }
    const map = buildMapping(seed, names, avoid);
    // Pre-pass: collect indices of IDENT tokens that are table-constructor
    // field names. In `{ key = value }`, the IDENT `key` is a string field
    // name (syntactic sugar for `{ ["key"] = value }`), NOT a variable.
    // Renaming it would create a mismatch with dot-access (`t.key`), which
    // we also skip. We detect these by: inside `{ }` AND immediately followed
    // by a single `=` (not `==`).
    const tableFieldIndices = new Set();
    let braceDepth = 0;
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        if (t.kind === TokenKind.OP && t.value === "{") {
            braceDepth++;
        }
        else if (t.kind === TokenKind.OP && t.value === "}") {
            braceDepth--;
        }
        else if (t.kind === TokenKind.IDENT && braceDepth > 0) {
            const next = tokens[i + 1];
            if (next && next.kind === TokenKind.OP && next.value === "=") {
                tableFieldIndices.add(i);
            }
        }
    }
    const renamed = tokens.map((t, i) => {
        if (t.kind === TokenKind.IDENT && map.has(t.value)) {
            // Skip field names: an IDENT preceded by '.' or ':' is a table field
            // or method name, not a variable reference. Renaming it would break
            // the field access (the table's keys don't change).
            if (i > 0) {
                const prev = tokens[i - 1];
                if (prev.kind === TokenKind.OP && (prev.value === "." || prev.value === ":")) {
                    return t;
                }
            }
            // Skip table-constructor field names (detected in the pre-pass).
            if (tableFieldIndices.has(i)) {
                return t;
            }
            return { ...t, value: map.get(t.value) };
        }
        return t;
    });
    return { tokens: renamed, map };
}
//# sourceMappingURL=identifier.js.map