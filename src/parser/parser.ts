// src/parser/parser.ts — Recursive-descent AST builder for Luau 0.x.
//
// v0.1.1: Now covers full Luau 0.x syntax subset:
//   - goto / ::label::
//   - type annotations (transparent pass-through)
//   - type / export type declarations
//   - if-expressions (Luau-specific)
//   - interp (backtick) string lowering
//   - compound assignment (+=, -=, etc.)
//   - for-loop variable type annotations
//
// The grammar:
//   block   := stmt*
//   stmt    := local_stmt | assign_stmt | if_stmt | while_stmt
//            | repeat_stmt | for_stmt | function_stmt
//            | return_stmt | call_stmt | do_stmt | break_stmt | continue_stmt
//            | goto_stmt | label_stmt | type_decl | ';'  (empty)
//   expr    := if_expr | primary | unary | binary | call | method | index | concat
//   primary := number | string | interp | true | false | nil | ident | table | vararg | function | paren

import { type Token, TokenKind } from "./tokens.js";

export type Node =
  // statements
  | { t: "Block"; body: Node[]; line: number }
  | { t: "Local"; names: string[]; types: (string | null)[]; values: Node[] | null; line: number }
  | { t: "Assign"; targets: Node[]; values: Node[]; line: number }
  | { t: "If"; branches: { cond: Node; block: Node }[]; else?: Node; line: number }
  | { t: "While"; cond: Node; block: Node; line: number }
  | { t: "Repeat"; block: Node; cond: Node; line: number }
  | { t: "For"; varName: string; varType: string | null; start: Node; stop: Node; step: Node | null; block: Node; line: number }
  | { t: "ForIn"; names: string[]; types: (string | null)[]; iter: Node[]; block: Node; line: number }
  | { t: "Function"; name: { parts: string[]; method?: string }; params: string[]; paramTypes: (string | null)[]; retType: string | null; body: Node; isLocal?: boolean; line: number }
  | { t: "Return"; values: Node[]; line: number }
  | { t: "Call"; callee: Node; args: Node[]; line: number }
  | { t: "Method"; name: string; callee: Node; args: Node[]; line: number }
  | { t: "Do"; block: Node; line: number }
  | { t: "Break"; line: number }
  | { t: "Continue"; line: number }
  | { t: "Goto"; label: string; line: number }
  | { t: "Label"; name: string; line: number }
  | { t: "TypeDecl"; name: string; exported: boolean; body: string; line: number }
  | { t: "Empty"; line: number }
  // expressions
  | { t: "Nil"; line: number }
  | { t: "Bool"; value: boolean; line: number }
  | { t: "Number"; value: string; line: number }
  | { t: "String"; value: string; line: number }
  | { t: "Interp"; parts: Node[]; line: number }
  | { t: "IfExpr"; cond: Node; then: Node; else: Node; line: number }
  | { t: "Ident"; name: string; line: number }
  | { t: "Vararg"; line: number }
  | { t: "Index"; obj: Node; index: Node; line: number }
  | { t: "Unop"; op: string; arg: Node; line: number }
  | { t: "Binop"; op: string; lhs: Node; rhs: Node; line: number }
  | { t: "Concat"; parts: Node[]; line: number }
  | { t: "Table"; fields: { key: Node | null; value: Node }[]; line: number }
  | { t: "Function"; params: string[]; paramTypes: (string | null)[]; retType: string | null; body: Node; vararg: boolean; line: number };

interface PState { tokens: Token[]; i: number; errors: string[]; }
function peek(s: PState, off = 0): Token { return s.tokens[s.i + off]!; }
function eat(s: PState, kind: TokenKind, value?: string): Token {
  const t = s.tokens[s.i]!;
  if (t.kind !== kind || (value !== undefined && t.value !== value)) {
    const expected = value ?? kind;
    s.errors.push(`[${t.line}:${t.col}] expected ${expected}, got ${t.kind} '${t.value}'`);
    throw new Error(s.errors[s.errors.length - 1]!);
  }
  s.i++;
  return t;
}
function matchKw(s: PState, value: string): boolean {
  const t = s.tokens[s.i]!;
  return t.kind === TokenKind.KEYWORD && t.value === value;
}
function matchOp(s: PState, value: string): boolean {
  const t = s.tokens[s.i]!;
  return t.kind === TokenKind.OP && t.value === value;
}
function atEof(s: PState): boolean { return peek(s).kind === TokenKind.EOF; }

// ---- Type annotation (transparent pass-through) ----
// We don't need to understand type semantics; we just need to consume
// the annotation text and reproduce it at emit time. Returns the raw
// string representation of the type, or null if no annotation present.
function parseTypeAnnotation(s: PState): string | null {
  if (!matchOp(s, ":")) return null;
  s.i++; // consume ':'
  return parseTypeExpr(s);
}

// Parse a type expression — consume tokens that form the type annotation.
// We read until we hit a boundary: ',' ')' '=' 'do' 'then' 'end' 'in' '{' (table body)
// or EOF. We accumulate the raw source text of the type.
function parseTypeExpr(s: PState): string {
  let result = "";
  let depth = 0; // for nested <>, {}, [], ()
  const terminators = new Set([",", ")", "=", "do", "then", "end", "in", ";", "return", "break", "continue", "goto", "else", "elseif", "until",
    // Statement starters that may follow a return-type or bare local-type
    // annotation at depth 0. None of these are valid inside a Luau type
    // expression, so treating them as terminators lets a return type like
    // `(): number?` correctly stop before the body's first statement.
    // NOTE: `typeof` is intentionally excluded — `typeof(x)` is a valid type.
    "if", "while", "for", "repeat", "local", "function", "type", "export"]);
  while (!atEof(s)) {
    const t = peek(s);
    if (depth === 0 && terminators.has(t.value)) break;
    if (t.kind === TokenKind.EOF) break;
    // Track nesting
    if (t.value === "<" || t.value === "{" || t.value === "[" || t.value === "(") depth++;
    if (t.value === ">" || t.value === "}" || t.value === "]" || t.value === ")") {
      if (depth > 0) depth--;
      else break;
    }
    // Handle `|` union types
    // `?` is a postfix nullable suffix (e.g. `string?`) — attach without a
    // leading space so the emitted type stays `string?` rather than `string ?`.
    if (result.length > 0 && t.value !== "?") result += " ";
    result += t.value;
    s.i++;
  }
  return result.trim();
}

// Parse the body of a `type Name = ...` declaration. Consume until we hit
// a statement boundary at depth 0. Returns raw text.
function parseTypeBody(s: PState): string {
  let result = "";
  let depth = 0; // for {}, (), [], <>
  // Statement-starting keywords that terminate a type body at depth 0
  const stmtKeywords = new Set([
    "local", "function", "if", "while", "for", "repeat", "return",
    "do", "break", "continue", "goto", "type", "export", "end",
    "else", "elseif", "until", ";",
  ]);
  while (!atEof(s)) {
    const t = peek(s);
    if (t.kind === TokenKind.EOF) break;
    // Statement-starting keyword at depth 0 terminates the type body
    if (depth === 0 && t.kind === TokenKind.KEYWORD && stmtKeywords.has(t.value)) break;
    if (depth === 0 && t.kind === TokenKind.OP && t.value === ";") break;
    // Track nesting
    if (t.value === "{" || t.value === "[" || t.value === "(" || t.value === "<") depth++;
    if (t.value === "}" || t.value === "]" || t.value === ")" || t.value === ">") {
      if (depth > 0) depth--;
    }
    if (result.length > 0) result += " ";
    result += t.value;
    s.i++;
  }
  return result.trim();
}

// ---- Compound assignment operators ----
const COMPOUND_OPS: Set<string> = new Set(["+=", "-=", "*=", "/=", "%=", "^=", "..=", "//="]);

export function parse(tokens: Token[]): Node {
  const s: PState = { tokens, i: 0, errors: [] };
  const block = parseBlock(s, /*terminators*/ new Set(["end", "else", "elseif", "until", "EOF"]));
  if (!atEof(s)) {
    const t = peek(s);
    s.errors.push(`[${t.line}:${t.col}] unexpected trailing token '${t.value}'`);
  }
  if (s.errors.length) throw new Error(s.errors.join("\n"));
  return block;
}

function parseBlock(s: PState, terminators: Set<string>): Node {
  const body: Node[] = [];
  while (!atEof(s) && !terminators.has(peek(s).value)) {
    const stmt = parseStmt(s);
    if (stmt) body.push(stmt);
    // optional semicolon between stmts
    while (matchOp(s, ";")) s.i++;
  }
  return { t: "Block", body, line: peek(s).line };
}

function parseStmt(s: PState): Node | null {
  const t = peek(s);
  // local
  if (t.kind === TokenKind.KEYWORD && t.value === "local") {
    s.i++;
    if (matchKw(s, "function")) {
      s.i++;
      const nameTok = eat(s, TokenKind.IDENT);
      const node = parseFnDeclTail(s, nameTok.value, [nameTok.value]);
      if (node.t === "Function" && "name" in node) node.isLocal = true;
      return node;
    }
    // local NAME: Type [, NAME: Type] [= values]
    const names: string[] = [];
    const types: (string | null)[] = [];
    names.push(eat(s, TokenKind.IDENT).value);
    types.push(parseTypeAnnotation(s));
    while (matchOp(s, ",")) {
      s.i++;
      names.push(eat(s, TokenKind.IDENT).value);
      types.push(parseTypeAnnotation(s));
    }
    let values: Node[] | null = null;
    if (matchOp(s, "=")) {
      s.i++;
      values = parseExprList(s);
    }
    return { t: "Local", names, types, values, line: t.line };
  }
  // type / export type  (Luau type aliases)
  // `type Name = ...`  or  `export type Name = ...`
  // But `type(x)` / `typeof(x)` as a call expression is NOT a type alias —
  // fall through to expression-statement parsing in that case.
  if (t.kind === TokenKind.KEYWORD && (t.value === "type" || t.value === "export")) {
    let exported = false;
    if (t.value === "export") {
      s.i++;                    // consume `export`
      eat(s, TokenKind.KEYWORD, "type");
      exported = true;
    } else {
      s.i++;                    // consume `type`
      const after = peek(s);
      // `type(` → function call, not type alias. Un-eat and fall through.
      // `typeof` after `type` → also a call expression. Un-eat and fall through.
      if ((after.kind === TokenKind.OP && after.value === "(") || matchKw(s, "typeof")) {
        s.i--;                  // un-eat `type`
      } else {
        const name = eat(s, TokenKind.IDENT).value;
        eat(s, TokenKind.OP, "=");
        const body = parseTypeBody(s);
        return { t: "TypeDecl", name, exported, body, line: t.line };
      }
    }
    // For `export type Name = ...` — read name and body
    if (exported) {
      const name = eat(s, TokenKind.IDENT).value;
      eat(s, TokenKind.OP, "=");
      const body = parseTypeBody(s);
      return { t: "TypeDecl", name, exported, body, line: t.line };
    }
  }
  // goto
  if (t.kind === TokenKind.KEYWORD && t.value === "goto") {
    s.i++;
    const label = eat(s, TokenKind.IDENT).value;
    return { t: "Goto", label, line: t.line };
  }
  // ::label::
  if (t.kind === TokenKind.OP && t.value === "::") {
    s.i++; // consume `::`
    const name = eat(s, TokenKind.IDENT).value;
    eat(s, TokenKind.OP, "::");
    return { t: "Label", name, line: t.line };
  }
  // if
  if (t.kind === TokenKind.KEYWORD && t.value === "if") {
    s.i++;
    const cond = parseExpr(s);
    eat(s, TokenKind.KEYWORD, "then");
    const blk = parseBlock(s, new Set(["end", "elseif", "else"]));
    const branches: { cond: Node; block: Node }[] = [{ cond, block: blk }];
    let elseN: Node | undefined;
    while (matchKw(s, "elseif")) {
      s.i++;
      const c2 = parseExpr(s);
      eat(s, TokenKind.KEYWORD, "then");
      const b2 = parseBlock(s, new Set(["end", "elseif", "else"]));
      branches.push({ cond: c2, block: b2 });
    }
    if (matchKw(s, "else")) {
      s.i++;
      elseN = parseBlock(s, new Set(["end"]));
    }
    eat(s, TokenKind.KEYWORD, "end");
    return { t: "If", branches, else: elseN, line: t.line };
  }
  // while
  if (t.kind === TokenKind.KEYWORD && t.value === "while") {
    s.i++;
    const cond = parseExpr(s);
    eat(s, TokenKind.KEYWORD, "do");
    const blk = parseBlock(s, new Set(["end"]));
    eat(s, TokenKind.KEYWORD, "end");
    return { t: "While", cond, block: blk, line: t.line };
  }
  // repeat
  if (t.kind === TokenKind.KEYWORD && t.value === "repeat") {
    s.i++;
    const blk = parseBlock(s, new Set(["until"]));
    eat(s, TokenKind.KEYWORD, "until");
    const cond = parseExpr(s);
    return { t: "Repeat", block: blk, cond, line: t.line };
  }
  // numeric for / generic for
  if (t.kind === TokenKind.KEYWORD && t.value === "for") {
    s.i++;
    const name = eat(s, TokenKind.IDENT).value;
    // optional type annotation: `for i: T = 1, 10 do`
    const varType = parseTypeAnnotation(s);
    if (matchOp(s, "=")) {
      s.i++;
      const start = parseExpr(s);
      eat(s, TokenKind.OP, ",");
      const stop = parseExpr(s);
      let step: Node | null = null;
      if (matchOp(s, ",")) { s.i++; step = parseExpr(s); }
      eat(s, TokenKind.KEYWORD, "do");
      const blk = parseBlock(s, new Set(["end"]));
      eat(s, TokenKind.KEYWORD, "end");
      return { t: "For", varName: name, varType, start, stop, step, block: blk, line: t.line };
    } else {
      // generic for: `for k: T, v: U in pairs(t) do`
      const names: string[] = [name];
      const types: (string | null)[] = [varType];
      while (matchOp(s, ",")) {
        s.i++;
        names.push(eat(s, TokenKind.IDENT).value);
        types.push(parseTypeAnnotation(s));
      }
      eat(s, TokenKind.KEYWORD, "in");
      const iter = parseExprList(s);
      eat(s, TokenKind.KEYWORD, "do");
      const blk = parseBlock(s, new Set(["end"]));
      eat(s, TokenKind.KEYWORD, "end");
      return { t: "ForIn", names, types, iter, block: blk, line: t.line };
    }
  }
  // function
  if (t.kind === TokenKind.KEYWORD && t.value === "function") {
    s.i++;
    const head = parseFnName(s);
    if (head.method) {
      // local function obj:method(...) — actually this form doesn't exist in Lua
      // but obj.method = function(...)  is fine, covered via assign.
      s.errors.push(`[${t.line}:${t.col}] 'function name:method()' syntax not supported yet`);
      throw new Error(s.errors[s.errors.length - 1]!);
    }
    return parseFnDeclTail(s, "", head.parts);
  }
  // return
  if (t.kind === TokenKind.KEYWORD && t.value === "return") {
    s.i++;
    // Bare return (no values) when followed by a block terminator. Lua
    // requires `return` to be the last statement in its block, so the
    // following token must be one of: end / else / elseif / until / ; / EOF.
    const bare =
      matchKw(s, "end") || matchKw(s, "else") || matchKw(s, "elseif") ||
      matchKw(s, "until") || matchOp(s, ";") || atEof(s);
    const values = bare ? [] : parseExprList(s);
    return { t: "Return", values, line: t.line };
  }
  // do
  if (t.kind === TokenKind.KEYWORD && t.value === "do") {
    s.i++;
    const blk = parseBlock(s, new Set(["end"]));
    eat(s, TokenKind.KEYWORD, "end");
    return { t: "Do", block: blk, line: t.line };
  }
  // break
  if (t.kind === TokenKind.KEYWORD && t.value === "break") {
    s.i++;
    return { t: "Break", line: t.line };
  }
  // continue (Luau)
  if (t.kind === TokenKind.KEYWORD && t.value === "continue") {
    s.i++;
    return { t: "Continue", line: t.line };
  }
  // ; alone
  if (t.kind === TokenKind.OP && t.value === ";") {
    s.i++;
    return { t: "Empty", line: t.line };
  }

  // call-statement or assignment
  const first = parseExpr(s);
  // compound assignment: x += y  →  x = x + y
  const curTok = peek(s);
  if (curTok.kind === TokenKind.OP && COMPOUND_OPS.has(curTok.value)) {
    const compoundOp = curTok.value;
    s.i++; // consume the compound op
    const value = parseExpr(s);
    // Extract the binary operator from the compound op (e.g. "+=" → "+")
    const binOp = compoundOp.slice(0, -1); // remove trailing "="
    const rhs: Node = { t: "Binop", op: binOp === ".." ? ".." : binOp, lhs: first, rhs: value, line: t.line };
    return { t: "Assign", targets: [first], values: [rhs], line: t.line };
  }
  if (matchOp(s, "=") || matchOp(s, ",")) {
    const targets: Node[] = [first];
    while (matchOp(s, ",")) { s.i++; targets.push(parseExpr(s)); }
    eat(s, TokenKind.OP, "=");
    const values = parseExprList(s);
    return { t: "Assign", targets, values, line: t.line };
  }
  // call-stmt: only valid if `first` is a Call
  if (first.t === "Call" || first.t === "Method") {
    return first;
  }
  s.errors.push(`[${t.line}:${t.col}] unexpected token '${t.value}' in statement position`);
  throw new Error(s.errors[s.errors.length - 1]!);
}

function parseFnName(s: PState): { parts: string[]; method?: string } {
  const parts: string[] = [eat(s, TokenKind.IDENT).value];
  while (matchOp(s, ".")) {
    s.i++;
    parts.push(eat(s, TokenKind.IDENT).value);
  }
  return { parts };
}

function parseFnDeclTail(s: PState, _name: string, parts: string[]): Node {
  if (parts.length > 0 && matchOp(s, ":")) {
    // method def: function obj:name(...)  -- the last part is the method name
    s.i++;
    const method = eat(s, TokenKind.IDENT).value;
    eat(s, TokenKind.OP, "(");
    const { params, paramTypes } = parseParamList(s);
    eat(s, TokenKind.OP, ")");
    // Optional return type annotation
    const retType = parseTypeAnnotation(s);
    const body = parseBlock(s, new Set(["end"]));
    eat(s, TokenKind.KEYWORD, "end");
    return { t: "Function", name: { parts: parts.slice(0, -1), method }, params, paramTypes, retType, body, line: peek(s).line };
  }
  eat(s, TokenKind.OP, "(");
  const { params, paramTypes } = parseParamList(s);
  eat(s, TokenKind.OP, ")");
  // Optional return type annotation
  const retType = parseTypeAnnotation(s);
  const body = parseBlock(s, new Set(["end"]));
  eat(s, TokenKind.KEYWORD, "end");
  return { t: "Function", name: { parts }, params, paramTypes, retType, body, line: peek(s).line };
}

function parseParamList(s: PState): { params: string[]; paramTypes: (string | null)[] } {
  const ps: string[] = [];
  const ts: (string | null)[] = [];
  if (matchOp(s, ")")) return { params: ps, paramTypes: ts };
  while (true) {
    if (matchOp(s, "...")) { s.i++; ps.push("..."); ts.push(null); break; }
    ps.push(eat(s, TokenKind.IDENT).value);
    ts.push(parseTypeAnnotation(s));
    if (matchOp(s, ",")) { s.i++; continue; }
    break;
  }
  return { params: ps, paramTypes: ts };
}

function parseExprList(s: PState): Node[] {
  const out: Node[] = [parseExpr(s)];
  while (matchOp(s, ",")) { s.i++; out.push(parseExpr(s)); }
  return out;
}

function parseExpr(s: PState): Node {
  // Luau if-expression: `if cond then a else b` (or `elseif` chains)
  if (matchKw(s, "if")) {
    const line = peek(s).line;
    s.i++; // consume `if`
    const cond = parseBinopThen(s);
    eat(s, TokenKind.KEYWORD, "then");
    const thenExpr = parseExpr(s);
    // handle elseif chain: `if a then x elseif b then y else z`
    let elseExpr: Node;
    if (matchKw(s, "elseif")) {
      elseExpr = parseExpr(s); // recursively parse the elseif as a nested if-expr
    } else {
      eat(s, TokenKind.KEYWORD, "else");
      elseExpr = parseExpr(s);
    }
    return { t: "IfExpr", cond, then: thenExpr, else: elseExpr, line };
  }
  return parseConcat(s);
}

// Helper: parse expression up to `then` (for if-expr condition).
// This is just parseBinop with minPrec, since the condition is a normal
// boolean expression terminated by `then`.
function parseBinopThen(s: PState): Node {
  return parseBinop(s, 1);
}

function parseConcat(s: PState): Node {
  // minPrec = 1 means "consume any operator at any precedence" — concat itself
  // is layered on top of binop via the post-check for `..`.
  let lhs = parseBinop(s, 1);
  while (matchOp(s, "..")) {
    s.i++;
    const rhs = parseBinop(s, 1);
    if (lhs.t === "Concat") (lhs as { parts: Node[] }).parts.push(rhs);
    else lhs = { t: "Concat", parts: [lhs, rhs], line: lhs.line };
  }
  return lhs;
}

// Precedence climbing.
function parseBinop(s: PState, minPrec: number): Node {
  let lhs = parseUnary(s);
  for (;;) {
    const tok = peek(s);
    // Accept both OP tokens (e.g. +, -, *, /, ==, <, ..) and KEYWORD tokens
    // for logical operators (and, or) which are lexed as KEYWORD, not OP.
    const isBinopTok = tok.kind === TokenKind.OP ||
      (tok.kind === TokenKind.KEYWORD && (tok.value === "and" || tok.value === "or"));
    if (!isBinopTok) break;
    const prec = OP_PREC[tok.value as keyof typeof OP_PREC];
    if (prec === undefined || prec < minPrec) break;
    const op = tok.value;
    s.i++;
    const nextMin = (OP_RIGHT_ASSOC as readonly string[]).includes(op) ? prec : prec + 1;
    const rhs = parseBinop(s, nextMin);
    lhs = { t: "Binop", op, lhs, rhs, line: lhs.line };
  }
  return lhs;
}

const OP_PREC: Record<string, number> = {
  "or": 1, "and": 2,
  "==": 3, "~=": 3, "<": 3, ">": 3, "<=": 3, ">=": 3,
  "|": 4, "~": 5, "&": 6, "<<": 7, ">>": 7,
  "..": 8,
  "+": 9, "-": 9,
  "*": 10, "/": 10, "%": 10, "//": 10,
  "^": 12,
};
const OP_RIGHT_ASSOC: readonly string[] = ["^", ".."];

function parseUnary(s: PState): Node {
  if (matchOp(s, "-") || matchKw(s, "not") || matchOp(s, "#") || matchOp(s, "~")) {
    const op = peek(s).value;
    s.i++;
    const arg = parseUnary(s);
    return { t: "Unop", op, arg, line: peek(s).line };
  }
  return parsePrimary(s);
}

function parsePrimary(s: PState): Node {
  const t = peek(s);
  if (t.kind === TokenKind.NUMBER) { s.i++; return { t: "Number", value: t.value, line: t.line }; }
  if (t.kind === TokenKind.STRING) {
    s.i++;
    // Check for interp (backtick) string — lexer marks with \x00INTERP: prefix
    if (t.value.startsWith("\x00INTERP:")) {
      return parseInterpString(s, t.value.substring(9), t.line);
    }
    return { t: "String", value: t.value, line: t.line };
  }
  if (t.kind === TokenKind.KEYWORD && t.value === "true") { s.i++; return { t: "Bool", value: true, line: t.line }; }
  if (t.kind === TokenKind.KEYWORD && t.value === "false") { s.i++; return { t: "Bool", value: false, line: t.line }; }
  if (t.kind === TokenKind.KEYWORD && t.value === "nil") { s.i++; return { t: "Nil", line: t.line }; }
  if (t.kind === TokenKind.OP && t.value === "...") { s.i++; return { t: "Vararg", line: t.line }; }
  if (t.kind === TokenKind.OP && t.value === "{") {
    s.i++;
    const fields: { key: Node | null; value: Node }[] = [];
    while (!matchOp(s, "}")) {
      if (matchOp(s, "[")) {
        s.i++;
        const k = parseExpr(s);
        eat(s, TokenKind.OP, "]");
        eat(s, TokenKind.OP, "=");
        const v = parseExpr(s);
        fields.push({ key: k, value: v });
      } else if (peek(s).kind === TokenKind.IDENT && peek(s, 1).value === "=") {
        // [ident] = expr  (table field shorthand)
        const name = eat(s, TokenKind.IDENT).value;
        eat(s, TokenKind.OP, "=");
        const k: Node = { t: "String", value: name, line: peek(s).line };
        const v = parseExpr(s);
        fields.push({ key: k, value: v });
      } else {
        const v = parseExpr(s);
        fields.push({ key: null, value: v });
      }
      if (!matchOp(s, ",")) break;
      s.i++;
      if (matchOp(s, "}")) break;
    }
    eat(s, TokenKind.OP, "}");
    return { t: "Table", fields, line: t.line };
  }
  if (t.kind === TokenKind.OP && t.value === "(") {
    s.i++;
    const inner = parseExpr(s);
    eat(s, TokenKind.OP, ")");
    // A parenthesized expression can be followed by postfix operators
    // such as `:method()` or `.field` — e.g. `(a or b):method()`.
    return parsePostfix(s, inner);
  }
  if (t.kind === TokenKind.KEYWORD && t.value === "function") {
    s.i++;
    eat(s, TokenKind.OP, "(");
    const { params, paramTypes } = parseParamList(s);
    eat(s, TokenKind.OP, ")");
    // Optional return type annotation for anonymous function
    const retType = parseTypeAnnotation(s);
    const body = parseBlock(s, new Set(["end"]));
    eat(s, TokenKind.KEYWORD, "end");
    return { t: "Function", params, paramTypes, retType, body, vararg: params.includes("..."), line: t.line };
  }
  if (t.kind === TokenKind.IDENT) {
    s.i++;
    return parsePostfix(s, { t: "Ident", name: t.value, line: t.line });
  }
  // Soft keywords `type` / `typeof` used as function calls in expression
  // position (e.g. `type(x) == "string"`). Luau treats these contextually:
  // `type Name = ...` is a type alias, but `type(x)` is the global function.
  // We detect the call form by checking if the next token is `(`.
  if (t.kind === TokenKind.KEYWORD && (t.value === "type" || t.value === "typeof")) {
    const next = peek(s, 1);
    if (next.kind === TokenKind.OP && next.value === "(") {
      s.i++;
      return parsePostfix(s, { t: "Ident", name: t.value, line: t.line });
    }
  }
  s.errors.push(`[${t.line}:${t.col}] expected expression, got ${t.kind} '${t.value}'`);
  throw new Error(s.errors[s.errors.length - 1]!);
}

function parsePostfix(s: PState, base: Node): Node {
  let cur: Node = base;
  for (;;) {
    const t = peek(s);
    if (t.kind === TokenKind.OP && t.value === ".") {
      s.i++;
      const name = eat(s, TokenKind.IDENT).value;
      cur = { t: "Index", obj: cur, index: { t: "String", value: name, line: t.line }, line: cur.line };
    } else if (t.kind === TokenKind.OP && t.value === "[") {
      s.i++;
      const idx = parseExpr(s);
      eat(s, TokenKind.OP, "]");
      cur = { t: "Index", obj: cur, index: idx, line: cur.line };
    } else if (t.kind === TokenKind.OP && t.value === ":") {
      s.i++;
      const name = eat(s, TokenKind.IDENT).value;
      const next = peek(s);
      if (next.kind === TokenKind.OP && next.value === "(") {
        s.i++;
        const args = parseCallArgs(s);
        cur = { t: "Method", callee: cur, name, args, line: cur.line };
      } else if (next.kind === TokenKind.STRING) {
        s.i++;
        let arg: Node;
        if (next.value.startsWith("\x00INTERP:")) {
          arg = parseInterpString(s, next.value.substring(9), next.line);
        } else {
          arg = { t: "String", value: next.value, line: next.line };
        }
        cur = { t: "Method", callee: cur, name, args: [arg], line: cur.line };
      } else if (next.kind === TokenKind.OP && next.value === "{") {
        s.i++;
        const arg = parsePrimary(s);
        cur = { t: "Method", callee: cur, name, args: [arg], line: cur.line };
      } else {
        s.errors.push(`[${next.line}:${next.col}] expected '(', string, or '{' after method call ':', got ${next.kind} ${next.value}`);
        throw new Error(s.errors[s.errors.length - 1]!);
      }
    } else if (t.kind === TokenKind.OP && (t.value === "(" || t.value === "{" || t.value === "\"" || t.value === "'" || t.value === "`")) {
      // function call:  ident(args) | ident "str" | ident { table } | ident `str`
      if (t.value === "(") {
        s.i++;
        const args = parseCallArgs(s);
        cur = { t: "Call", callee: cur, args, line: cur.line };
      } else if (t.value === "\"" || t.value === "'") {
        // string literal as sole call arg, e.g.  print "hi"
        const arg = parsePrimary(s);
        cur = { t: "Call", callee: cur, args: [arg], line: cur.line };
      } else if (t.value === "{") {
        // table literal as sole call arg, e.g.  setmetatable(t, {__index = ...})
        const arg = parsePrimary(s);
        cur = { t: "Call", callee: cur, args: [arg], line: cur.line };
      } else break;
    } else if (t.kind === TokenKind.STRING) {
      // Luau allows `f "string"` as sugar for `f("string")`.
      // Also handles interp backtick strings (lexer marks with \x00INTERP:)
      s.i++;
      let arg: Node;
      if (t.value.startsWith("\x00INTERP:")) {
        arg = parseInterpString(s, t.value.substring(9), t.line);
      } else {
        arg = { t: "String", value: t.value, line: t.line };
      }
      cur = { t: "Call", callee: cur, args: [arg], line: cur.line };
    } else {
      break;
    }
  }
  return cur;
}

function parseCallArgs(s: PState): Node[] {
  const args: Node[] = [];
  if (matchOp(s, ")")) { s.i++; return args; }
  args.push(parseExpr(s));
  while (matchOp(s, ",")) { s.i++; args.push(parseExpr(s)); }
  eat(s, TokenKind.OP, ")");
  return args;
}

// ---- Interp (backtick) string parser ----
// The lexer gives us the raw content between backticks. We need to split
// it into literal parts and {expression} parts, then build a Concat node.
// For example:  `hello {name}!`  →  Concat["hello ", name, "!"]
//
// The expression parts are re-lexed and re-parsed as sub-expressions.
function parseInterpString(_s: PState, raw: string, line: number): Node {
  // We've already consumed the STRING token (s.i was advanced in parsePrimary).
  // The raw text is the content between the backticks.
  // We need to split the raw text into literal segments and {expr} segments.
  const parts: Node[] = [];
  let i = 0;
  let literal = "";

  while (i < raw.length) {
    if (raw[i] === "\\") {
      // Escape sequence — decode and append to literal
      const esc = raw[i + 1] ?? "";
      const decoded = decodeInterpEscape(esc);
      literal += decoded;
      i += 2;
      continue;
    }
    if (raw[i] === "{") {
      // Flush preceding literal
      if (literal.length > 0) {
        parts.push({ t: "String", value: literal, line });
        literal = "";
      }
      // Find the matching `}`
      let depth = 1;
      let j = i + 1;
      while (j < raw.length && depth > 0) {
        if (raw[j] === "{") depth++;
        if (raw[j] === "}") depth--;
        if (depth === 0) break;
        j++;
      }
      const exprText = raw.substring(i + 1, j);
      // Re-lex and parse the expression
      const innerTokens = lexInner(exprText);
      if (innerTokens.length > 0) {
        // Use parseExpr directly instead of parse() (which expects a block of
        // statements). We create a temporary PState and call parseExpr.
        const innerState: PState = { tokens: innerTokens, i: 0, errors: [] };
        const expr = parseExpr(innerState);
        parts.push(expr);
      }
      i = j + 1; // skip past `}`
      continue;
    }
    literal += raw[i]!;
    i++;
  }
  // Flush trailing literal
  if (literal.length > 0) {
    parts.push({ t: "String", value: literal, line });
  }

  // If only one part, return it directly
  if (parts.length === 1) return parts[0]!;
  // If empty, return empty string
  if (parts.length === 0) return { t: "String", value: "", line };
  // Build a Concat node
  return { t: "Concat", parts, line };
}

function decodeInterpEscape(c: string): string {
  switch (c) {
    case "n": return "\n";
    case "t": return "\t";
    case "r": return "\r";
    case "\\": return "\\";
    case "`": return "`";
    case "{": return "{";
    case "}": return "}";
    case "0": return "\0";
    default: return c; // unknown escape — keep literal
  }
}

// Re-lex a sub-expression string (import lex lazily to avoid circular dep issues)
import { lex as _lex } from "./lexer.js";
function lexInner(src: string): Token[] {
  try {
    return _lex(src);
  } catch {
    return [];
  }
}