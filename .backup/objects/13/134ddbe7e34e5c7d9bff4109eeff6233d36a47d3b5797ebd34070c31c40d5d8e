// tests/lexer.test.ts — Smoke test for the lexer.
import { describe, it, expect } from "vitest";
import { lex } from "../src/parser/lexer.js";
import { TokenKind } from "../src/parser/tokens.js";

describe("lexer", () => {
  it("tokenizes simple statements", () => {
    const tokens = lex(`local x = 1 + 2; print("hi")`);
    expect(tokens[0]!.kind).toBe(TokenKind.KEYWORD);
    expect(tokens[0]!.value).toBe("local");
    const ids = tokens.filter((t) => t.kind === TokenKind.IDENT).map((t) => t.value);
    expect(ids).toContain("x");
    expect(ids).toContain("print");
  });

  it("handles long-bracket strings", () => {
    const tokens = lex(`local s = [==[ hello\\nworld ]==]`);
    const str = tokens.find((t) => t.kind === TokenKind.STRING);
    expect(str).toBeTruthy();
    expect(str!.value).toBe(" hello\\nworld ");
  });

  it("handles hex numbers", () => {
    const tokens = lex(`local n = 0xDEADBEEF`);
    const num = tokens.find((t) => t.kind === TokenKind.NUMBER);
    expect(num!.value).toBe("0xDEADBEEF");
  });

  it("strips line comments", () => {
    const tokens = lex(`-- a comment\nlocal x = 1`);
    expect(tokens.filter((t) => t.kind === TokenKind.KEYWORD).map((t) => t.value)).toContain("local");
  });
});