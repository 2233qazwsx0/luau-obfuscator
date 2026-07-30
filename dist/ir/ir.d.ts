import type { Node } from "../parser/parser.js";
export interface Block {
    id: number;
    stmts: Node[];
    terminator: Terminator;
}
export type Terminator = {
    type: "jump";
    target: number;
} | {
    type: "branch";
    cond: Node;
    trueTarget: number;
    falseTarget: number;
} | {
    type: "loop";
    cond: Node;
    body: Node;
    exitTarget: number;
} | {
    type: "return";
    values: Node[];
} | {
    type: "exit";
};
/** Deterministic Fisher-Yates shuffle. */
export declare function shuffleArray<T>(arr: T[], rng: () => number): T[];
export declare function buildIR(ast: Node): Block[];
